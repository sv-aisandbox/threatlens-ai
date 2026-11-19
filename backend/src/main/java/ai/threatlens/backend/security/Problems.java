package ai.threatlens.backend.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * RFC 9457 problem details for responses written outside Spring MVC (security filters). Values are escaped by
 * hand so no request data can inject JSON, and only fixed titles/details are ever used.
 */
public final class Problems {

    public static final String CONTENT_TYPE = "application/problem+json";

    private Problems() {}

    public static void write(HttpServletRequest request, HttpServletResponse response, int status, String title, String detail)
            throws IOException {
        if (response.isCommitted()) {
            return;
        }
        Object cid = request.getAttribute(CorrelationIdFilter.ATTRIBUTE);
        String body = "{\"type\":\"about:blank\",\"title\":\"" + escape(title) + "\",\"status\":" + status
                + ",\"detail\":\"" + escape(detail) + "\",\"instance\":\"" + escape(request.getRequestURI())
                + "\",\"correlationId\":\"" + escape(cid == null ? "" : cid.toString()) + "\"}";
        response.setStatus(status);
        response.setContentType(CONTENT_TYPE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.getWriter().write(body);
    }

    static String escape(String value) {
        StringBuilder sb = new StringBuilder(value.length() + 8);
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default -> {
                    if (c < 0x20 || c == 0x7f) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString();
    }
}
