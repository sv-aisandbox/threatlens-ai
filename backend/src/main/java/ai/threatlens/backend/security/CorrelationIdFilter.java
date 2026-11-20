package ai.threatlens.backend.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.UUID;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/** Accepts a well-formed X-Correlation-Id or generates one; exposes it to logs, audit and the Python call. */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CorrelationIdFilter extends OncePerRequestFilter {

    private static final Logger LOG = LoggerFactory.getLogger("threatlens.access");

    public static final String HEADER = "X-Correlation-Id";
    public static final String ATTRIBUTE = "threatlens.correlationId";
    public static final String MDC_KEY = "cid";
    private static final Pattern VALID = Pattern.compile("^[A-Za-z0-9-]{8,64}$");

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String supplied = request.getHeader(HEADER);
        String cid = supplied != null && VALID.matcher(supplied).matches() ? supplied : UUID.randomUUID().toString();
        request.setAttribute(ATTRIBUTE, cid);
        response.setHeader(HEADER, cid);
        MDC.put(MDC_KEY, cid);
        try {
            chain.doFilter(request, response);
        } finally {
            // method, path (never the query string or headers) and status: no credentials can reach this line
            LOG.info("{} {} -> {}", request.getMethod(), request.getRequestURI(), response.getStatus());
            MDC.remove(MDC_KEY);
        }
    }
}
