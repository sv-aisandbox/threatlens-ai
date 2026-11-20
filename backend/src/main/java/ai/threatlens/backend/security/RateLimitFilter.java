package ai.threatlens.backend.security;

import ai.threatlens.backend.config.AppProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Clock;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Fixed-window, in-memory rate limit per authenticated subject. Runs after authentication so a caller cannot
 * exhaust another user's budget. Sync calls have a much smaller budget than reads. (Single instance only:
 * move to a shared store if the backend is ever scaled out.)
 */
public class RateLimitFilter extends OncePerRequestFilter {

    private static final long WINDOW_MILLIS = 60_000L;

    private record Window(long start, int count) {}

    private final ConcurrentHashMap<String, Window> windows = new ConcurrentHashMap<>();
    private final AppProperties.RateLimit limits;
    private final Clock clock;

    public RateLimitFilter(AppProperties.RateLimit limits, Clock clock) {
        this.limits = limits;
        this.clock = clock;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/api/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || "anonymousUser".equals(auth.getPrincipal())) {
            chain.doFilter(request, response); // unauthenticated requests are rejected further down the chain
            return;
        }
        boolean sync = "POST".equals(request.getMethod())
                && (request.getRequestURI().endsWith("/sync") || request.getRequestURI().equals("/api/inventory/import"));
        boolean analyst = "POST".equals(request.getMethod()) && request.getRequestURI().equals("/api/analyst/ask");
        int limit = sync ? limits.syncPerMinute() : analyst ? limits.analystPerMinute() : limits.requestsPerMinute();
        String key = (sync ? "sync:" : analyst ? "analyst:" : "api:") + auth.getName();
        long now = clock.millis();

        long retryAfterMillis = 0;
        boolean allowed = true;
        synchronized (windows) {
            if (windows.size() > 10_000) {
                windows.entrySet().removeIf(e -> now - e.getValue().start() >= WINDOW_MILLIS);
            }
            Window w = windows.get(key);
            if (w == null || now - w.start() >= WINDOW_MILLIS) {
                w = new Window(now, 0);
            }
            if (w.count() >= limit) {
                allowed = false;
                retryAfterMillis = WINDOW_MILLIS - (now - w.start());
            } else {
                w = new Window(w.start(), w.count() + 1);
            }
            windows.put(key, w);
        }
        if (!allowed) {
            response.setHeader("Retry-After", String.valueOf(Math.max(1, (retryAfterMillis + 999) / 1000)));
            Problems.write(request, response, 429, "Too Many Requests", "Rate limit exceeded. Retry later.");
            return;
        }
        chain.doFilter(request, response);
    }
}
