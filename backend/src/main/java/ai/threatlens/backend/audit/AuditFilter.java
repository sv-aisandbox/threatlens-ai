package ai.threatlens.backend.audit;

import ai.threatlens.backend.security.CorrelationIdFilter;
import ai.threatlens.backend.security.CurrentUser;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.servlet.HandlerMapping;

/**
 * Records one audit row per API request, including authentication failures. It sits in the security chain just
 * before bearer-token processing and writes after the rest of the chain has produced the final status.
 * A failure to write the audit row is logged and does not turn a read into an error.
 */
public class AuditFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(AuditFilter.class);
    private static final Pattern CVE = Pattern.compile("^CVE-\\d{4}-\\d{4,}$");
    private static final Pattern SOURCE = Pattern.compile("^(nvd|kev)$");

    private final AuditRepository repository;

    public AuditFilter(AuditRepository repository) {
        this.repository = repository;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String uri = request.getRequestURI();
        return !(uri.startsWith("/api/") || uri.startsWith("/v3/api-docs"));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        try {
            chain.doFilter(request, response);
        } finally {
            write(request, response);
        }
    }

    private void write(HttpServletRequest request, HttpServletResponse response) {
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            boolean authenticated = auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getPrincipal());
            String actor = authenticated ? auth.getName() : "anonymous";
            String tenant = authenticated ? CurrentUser.tenantOf(auth) : null;
            int status = response.getStatus();
            Object pattern = request.getAttribute(HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE);
            String action = request.getMethod() + " " + (pattern != null ? pattern : "(unmatched)");
            Object cid = request.getAttribute(CorrelationIdFilter.ATTRIBUTE);
            repository.record(new AuditRepository.AuditEvent(
                    actor, tenant, action, resource(request), outcome(status), status, cid == null ? "-" : cid.toString()));
        } catch (RuntimeException e) {
            log.error("audit write failed (request still served)", e);
        }
    }

    /** Only well-formed identifiers are stored; anything else is dropped so audit rows cannot carry attacker text. */
    @SuppressWarnings("unchecked")
    private static String resource(HttpServletRequest request) {
        Object vars = request.getAttribute(HandlerMapping.URI_TEMPLATE_VARIABLES_ATTRIBUTE);
        if (vars instanceof Map<?, ?> map) {
            Object cve = ((Map<String, Object>) map).get("cveId");
            if (cve instanceof String s && CVE.matcher(s).matches()) {
                return s;
            }
            Object source = ((Map<String, Object>) map).get("sourceId");
            if (source instanceof String s && SOURCE.matcher(s).matches()) {
                return s;
            }
        }
        return null;
    }

    static String outcome(int status) {
        if (status < 400) {
            return "success";
        }
        return status == 401 || status == 403 || status == 429 ? "denied" : "error";
    }
}
