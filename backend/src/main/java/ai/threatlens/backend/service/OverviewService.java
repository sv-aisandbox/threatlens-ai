package ai.threatlens.backend.service;

import ai.threatlens.backend.client.IntelligenceClient;
import ai.threatlens.backend.model.OverviewResponse;
import ai.threatlens.backend.security.CurrentUser;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class OverviewService {

    private final IntelligenceClient client;

    public OverviewService(IntelligenceClient client) {
        this.client = client;
    }

    @PreAuthorize("hasAnyRole('ADMIN','SECURITY_ANALYST','VIEWER')")
    public OverviewResponse overview() {
        return client.overview(CurrentUser.from(SecurityContextHolder.getContext().getAuthentication()));
    }
}
