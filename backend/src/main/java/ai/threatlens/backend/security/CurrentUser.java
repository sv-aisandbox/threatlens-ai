package ai.threatlens.backend.security;

import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/**
 * The authenticated caller. Tenant and roles come from validated token claims only; nothing in the
 * request (parameters, headers, body) can change them.
 */
public record CurrentUser(String subject, String tenantId, Set<String> roles) {

    public static final String TENANT_CLAIM = "tenant_id";
    public static final Set<String> KNOWN_ROLES = Set.of("ADMIN", "SECURITY_ANALYST", "VIEWER");
    private static final Pattern TENANT = Pattern.compile("^TENANT-[A-Z0-9-]{1,40}$");

    /** Valid tenant id from the token, or null when the claim is missing or malformed. */
    public static String tenantOf(Authentication authentication) {
        if (authentication instanceof JwtAuthenticationToken jwt) {
            String tenant = jwt.getToken().getClaimAsString(TENANT_CLAIM);
            if (tenant != null && TENANT.matcher(tenant).matches()) {
                return tenant;
            }
        }
        return null;
    }

    public static CurrentUser from(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated() || !(authentication instanceof JwtAuthenticationToken)) {
            throw new AccessDeniedException("authentication required");
        }
        String tenant = tenantOf(authentication);
        if (tenant == null) {
            throw new AccessDeniedException("token carries no valid tenant");
        }
        Set<String> roles = new TreeSet<>();
        for (GrantedAuthority authority : authentication.getAuthorities()) {
            String name = authority.getAuthority();
            if (name != null && name.startsWith("ROLE_") && KNOWN_ROLES.contains(name.substring(5))) {
                roles.add(name.substring(5));
            }
        }
        if (roles.isEmpty()) {
            throw new AccessDeniedException("token carries no known role");
        }
        return new CurrentUser(authentication.getName(), tenant, Set.copyOf(roles));
    }

    public boolean isAdmin() {
        return roles.contains("ADMIN");
    }
}
