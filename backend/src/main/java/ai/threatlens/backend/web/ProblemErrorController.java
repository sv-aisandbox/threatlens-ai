package ai.threatlens.backend.web;

import ai.threatlens.backend.security.CorrelationIdFilter;
import io.swagger.v3.oas.annotations.Hidden;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.boot.webmvc.error.ErrorController;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Renders errors raised by the servlet container or the request firewall (malformed or hostile paths) as
 * RFC 9457 problem details. Only the container's internal ERROR dispatch can reach this; a direct request
 * to /error is denied like any other unknown path.
 */
@Hidden
@RestController
public class ProblemErrorController implements ErrorController {

    @RequestMapping("/error")
    public ResponseEntity<ProblemDetail> error(HttpServletRequest request) {
        Object code = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
        HttpStatus status = code instanceof Integer i && HttpStatus.resolve(i) != null
                ? HttpStatus.valueOf(i) : HttpStatus.INTERNAL_SERVER_ERROR;
        ProblemDetail pd = ProblemDetail.forStatusAndDetail(status,
                status.is4xxClientError() ? "The request could not be processed." : "An unexpected error occurred.");
        pd.setTitle(status.getReasonPhrase());
        Object cid = request.getAttribute(CorrelationIdFilter.ATTRIBUTE);
        pd.setProperty("correlationId", cid == null ? null : cid.toString());
        return ResponseEntity.status(status).contentType(MediaType.APPLICATION_PROBLEM_JSON).body(pd);
    }
}
