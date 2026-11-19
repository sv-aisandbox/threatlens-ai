package ai.threatlens.backend.web;

import ai.threatlens.backend.client.UpstreamExceptions.ConflictException;
import ai.threatlens.backend.client.UpstreamExceptions.InventoryRejectedException;
import ai.threatlens.backend.client.UpstreamExceptions.NotFoundException;
import ai.threatlens.backend.client.UpstreamExceptions.UpstreamException;
import ai.threatlens.backend.security.CorrelationIdFilter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

/**
 * RFC 9457 problem details for every error. Details are fixed strings: no exception messages, upstream
 * bodies, stack traces or request values are ever returned.
 */
@RestControllerAdvice
public class ApiExceptionHandler extends ResponseEntityExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    private ResponseEntity<Object> problem(HttpStatus status, String title, String detail) {
        ProblemDetail pd = ProblemDetail.forStatusAndDetail(status, detail);
        pd.setTitle(title);
        pd.setProperty("correlationId", MDC.get(CorrelationIdFilter.MDC_KEY));
        return ResponseEntity.status(status).contentType(org.springframework.http.MediaType.APPLICATION_PROBLEM_JSON).body(pd);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    ResponseEntity<Object> badRequest(IllegalArgumentException e) {
        return problem(HttpStatus.BAD_REQUEST, "Bad Request", "The request is invalid.");
    }

    /** Wording lives here, not in Python: an upstream string can never become a message shown to a user. */
    private static final java.util.Map<String, String> INVENTORY_MESSAGES = java.util.Map.of(
            "not_json", "The file is not valid JSON.",
            "bad_shape", "The JSON file must be an object with an 'assets' list.",
            "tenant_mismatch", "The file names a different organization than yours.",
            "too_large", "The file is too large (limit 5 MB).",
            "not_utf8", "The file is not valid UTF-8 text.",
            "too_many_rows", "The file has too many rows (limit 20,000).",
            "bad_encoding", "The file could not be read.",
            "bad_format", "The file could not be read.");
    private static final java.util.Set<String> INVENTORY_COLUMNS =
            java.util.Set.of("asset_id", "name", "asset_type", "environment", "criticality", "internet_exposed");

    @ExceptionHandler(InventoryRejectedException.class)
    ResponseEntity<Object> inventoryRejected(InventoryRejectedException e) {
        String message;
        if ("missing_columns".equals(e.code())) {
            String names = e.details().stream().filter(INVENTORY_COLUMNS::contains).collect(java.util.stream.Collectors.joining(", "));
            message = "The CSV is missing required columns" + (names.isEmpty() ? "." : ": " + names + ".");
        } else {
            message = INVENTORY_MESSAGES.getOrDefault(e.code(), "The file could not be imported.");
        }
        String code = INVENTORY_MESSAGES.containsKey(e.code()) || "missing_columns".equals(e.code()) ? e.code() : "unknown";
        ProblemDetail pd = ProblemDetail.forStatusAndDetail(HttpStatus.valueOf(422), message);
        pd.setTitle("Inventory file rejected");
        pd.setProperty("code", code);
        pd.setProperty("correlationId", MDC.get(CorrelationIdFilter.MDC_KEY));
        return ResponseEntity.status(422).contentType(org.springframework.http.MediaType.APPLICATION_PROBLEM_JSON).body(pd);
    }

    @ExceptionHandler(NotFoundException.class)
    ResponseEntity<Object> notFound(NotFoundException e) {
        return problem(HttpStatus.NOT_FOUND, "Not Found", "The requested resource was not found.");
    }

    @ExceptionHandler(ConflictException.class)
    ResponseEntity<Object> conflict(ConflictException e) {
        return problem(HttpStatus.CONFLICT, "Conflict", "The operation conflicts with one that is already running.");
    }

    @ExceptionHandler(UpstreamException.class)
    ResponseEntity<Object> upstream(UpstreamException e) {
        HttpStatus status = switch (e.status()) {
            case 504 -> HttpStatus.GATEWAY_TIMEOUT;
            case 503 -> HttpStatus.SERVICE_UNAVAILABLE;
            default -> HttpStatus.BAD_GATEWAY;
        };
        String detail = status == HttpStatus.SERVICE_UNAVAILABLE
                ? "The analyst is currently unavailable. Try again later."
                : "The intelligence service is currently unavailable.";
        return problem(status, status.getReasonPhrase(), detail);
    }

    @ExceptionHandler(AccessDeniedException.class)
    ResponseEntity<Object> forbidden(AccessDeniedException e) {
        return problem(HttpStatus.FORBIDDEN, "Forbidden", "You do not have access to this resource.");
    }

    @ExceptionHandler(AuthenticationException.class)
    ResponseEntity<Object> unauthorized(AuthenticationException e) {
        return problem(HttpStatus.UNAUTHORIZED, "Unauthorized", "Authentication is required.");
    }

    @ExceptionHandler(Exception.class)
    ResponseEntity<Object> unexpected(Exception e) {
        log.error("unhandled error", e);
        return problem(HttpStatus.INTERNAL_SERVER_ERROR, "Internal Server Error", "An unexpected error occurred.");
    }

    /** Built-in Spring MVC problems (400 validation, 404, 405, 415...) also carry the correlation id. */
    @Override
    protected ResponseEntity<Object> handleExceptionInternal(
            Exception ex, Object body, HttpHeaders headers, HttpStatusCode statusCode, WebRequest request) {
        ResponseEntity<Object> response = super.handleExceptionInternal(ex, body, headers, statusCode, request);
        if (response != null && response.getBody() instanceof ProblemDetail pd) {
            pd.setProperty("correlationId", MDC.get(CorrelationIdFilter.MDC_KEY));
            if (statusCode.value() == 400) {
                pd.setDetail("The request is invalid.");
            }
        }
        return response;
    }
}
