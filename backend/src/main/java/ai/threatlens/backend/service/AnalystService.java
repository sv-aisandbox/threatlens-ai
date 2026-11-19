package ai.threatlens.backend.service;

import ai.threatlens.backend.client.IntelligenceClient;
import ai.threatlens.backend.model.AnalystAnswer;
import ai.threatlens.backend.security.CurrentUser;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class AnalystService {

    private final IntelligenceClient client;

    public AnalystService(IntelligenceClient client) {
        this.client = client;
    }

    /** Analysts and administrators only. The tenant comes from the token, never from the question or the body. */
    @PreAuthorize("hasAnyRole('ADMIN','SECURITY_ANALYST')")
    public AnalystAnswer ask(String question) {
        CurrentUser user = CurrentUser.from(SecurityContextHolder.getContext().getAuthentication());
        return client.ask(user, question);
    }
}
