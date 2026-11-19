package ai.threatlens.backend.client;

import ai.threatlens.backend.client.UpstreamExceptions.ConflictException;
import ai.threatlens.backend.client.UpstreamExceptions.NotFoundException;
import ai.threatlens.backend.client.UpstreamExceptions.UpstreamException;
import ai.threatlens.backend.config.AppProperties;
import ai.threatlens.backend.model.AffectedAssetsResponse;
import ai.threatlens.backend.model.AnalystAnswer;
import ai.threatlens.backend.model.SourceStatus;
import ai.threatlens.backend.model.SyncAccepted;
import ai.threatlens.backend.model.VulnerabilityDetails;
import ai.threatlens.backend.security.CorrelationIdFilter;
import ai.threatlens.backend.security.CurrentUser;
import java.net.http.HttpClient;
import java.net.http.HttpTimeoutException;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

/**
 * Calls the Python intelligence service with a fresh service JWT per request. Tenant and roles are taken from
 * the {@link CurrentUser}; this class has no way to send a tenant of its own. Timeouts are bounded and every
 * failure is mapped to a fixed outcome (upstream bodies are never logged or forwarded).
 */
@Component
public class IntelligenceClient {

    private static final Logger log = LoggerFactory.getLogger(IntelligenceClient.class);

    private final RestClient rest;
    private final RestClient analystRest;
    private final ServiceTokenIssuer tokens;

    public IntelligenceClient(AppProperties properties, ServiceTokenIssuer tokens) {
        HttpClient http = HttpClient.newBuilder().connectTimeout(properties.intelligence().connectTimeout()).build();
        JdkClientHttpRequestFactory factory = new JdkClientHttpRequestFactory(http);
        factory.setReadTimeout(properties.intelligence().readTimeout());
        this.rest = RestClient.builder().baseUrl(properties.intelligence().baseUrl()).requestFactory(factory).build();
        // Same upstream, longer read timeout: an analyst answer includes a model call and several tool calls.
        JdkClientHttpRequestFactory analystFactory = new JdkClientHttpRequestFactory(http);
        analystFactory.setReadTimeout(properties.intelligence().analystReadTimeout());
        this.analystRest = RestClient.builder().baseUrl(properties.intelligence().baseUrl()).requestFactory(analystFactory).build();
        this.tokens = tokens;
    }

    public VulnerabilityDetails vulnerability(CurrentUser user, String cveId) {
        return call(() -> rest.get()
                .uri("/internal/v1/vulnerabilities/{cve}", cveId)
                .headers(h -> authenticate(h, user))
                .retrieve()
                .onStatus(s -> s.isError(), (req, res) -> {
                    throw map(res.getStatusCode().value());
                })
                .body(VulnerabilityDetails.class));
    }

    public AffectedAssetsResponse affectedAssets(CurrentUser user, String cveId, String environment) {
        return call(() -> rest.get()
                .uri(b -> b.path("/internal/v1/vulnerabilities/{cve}/affected-assets")
                        .queryParamIfPresent("environment", Optional.ofNullable(environment))
                        .build(cveId))
                .headers(h -> authenticate(h, user))
                .retrieve()
                .onStatus(s -> s.isError(), (req, res) -> {
                    throw map(res.getStatusCode().value());
                })
                .body(AffectedAssetsResponse.class));
    }

    public List<SourceStatus> sourcesStatus(CurrentUser user) {
        return call(() -> rest.get()
                .uri("/internal/v1/sources/status")
                .headers(h -> authenticate(h, user))
                .retrieve()
                .onStatus(s -> s.isError(), (req, res) -> {
                    throw map(res.getStatusCode().value());
                })
                .body(new ParameterizedTypeReference<List<SourceStatus>>() {}));
    }

    public SyncAccepted startSync(CurrentUser user, String sourceId) {
        return call(() -> rest.post()
                .uri("/internal/v1/sources/{id}/sync", sourceId)
                .headers(h -> authenticate(h, user))
                .retrieve()
                .onStatus(s -> s.isError(), (req, res) -> {
                    throw map(res.getStatusCode().value());
                })
                .body(SyncAccepted.class));
    }

    /** Ask the analyst. Only the question is sent: tenant and roles travel in the signed service token. */
    public AnalystAnswer ask(CurrentUser user, String question) {
        return call(() -> analystRest.post()
                .uri("/internal/v1/analyst/ask")
                .headers(h -> authenticate(h, user))
                .contentType(MediaType.APPLICATION_JSON)
                .body(Map.of("question", question))
                .retrieve()
                .onStatus(s -> s.isError(), (req, res) -> {
                    throw mapAnalyst(res.getStatusCode().value());
                })
                .body(AnalystAnswer.class));
    }

    private void authenticate(HttpHeaders headers, CurrentUser user) {
        headers.setBearerAuth(tokens.issue(user));
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));
        String cid = MDC.get(CorrelationIdFilter.MDC_KEY);
        if (cid != null) {
            headers.set(CorrelationIdFilter.HEADER, cid);
        }
    }

    private static RuntimeException map(int status) {
        if (status == 404) {
            return new NotFoundException();
        }
        if (status == 409) {
            return new ConflictException();
        }
        // 401/403 here mean a configuration problem (secret mismatch), not a user problem.
        log.error("intelligence service answered HTTP {}", status);
        return new UpstreamException(502, "intelligence service error");
    }

    private static RuntimeException mapAnalyst(int status) {
        if (status == 429 || status == 503) {
            return new UpstreamException(503, "analyst busy or unavailable"); // busy or not configured
        }
        if (status == 422) {
            return new IllegalArgumentException("question rejected");
        }
        return map(status);
    }

    private static <T> T call(Supplier<T> action) {
        try {
            T result = action.get();
            if (result == null) {
                throw new UpstreamException(502, "empty response from intelligence service");
            }
            return result;
        } catch (NotFoundException | ConflictException | UpstreamException e) {
            throw e;
        } catch (ResourceAccessException e) {
            boolean timeout = rootCauseIsTimeout(e);
            log.error("intelligence service {}: {}", timeout ? "timed out" : "unreachable", e.getClass().getSimpleName());
            throw new UpstreamException(timeout ? 504 : 502, timeout ? "intelligence service timed out" : "intelligence service unreachable");
        } catch (RestClientException e) {
            log.error("intelligence service response could not be processed: {}", e.getClass().getSimpleName());
            throw new UpstreamException(502, "invalid response from intelligence service");
        }
    }

    private static boolean rootCauseIsTimeout(Throwable t) {
        for (Throwable c = t; c != null; c = c.getCause()) {
            if (c instanceof HttpTimeoutException || c instanceof java.net.SocketTimeoutException) {
                return true;
            }
            if (c.getCause() == c) {
                break;
            }
        }
        return false;
    }
}
