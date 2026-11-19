package ai.threatlens.backend.service;

import ai.threatlens.backend.client.IntelligenceClient;
import ai.threatlens.backend.model.SourceStatus;
import ai.threatlens.backend.model.SyncAccepted;
import ai.threatlens.backend.security.CurrentUser;
import java.util.List;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class SourceService {

    private final IntelligenceClient client;

    public SourceService(IntelligenceClient client) {
        this.client = client;
    }

    @PreAuthorize("hasAnyRole('ADMIN','SECURITY_ANALYST','VIEWER')")
    public List<SourceStatus> status() {
        return client.sourcesStatus(CurrentUser.from(SecurityContextHolder.getContext().getAuthentication()));
    }

    /** Only administrators may start a sync. */
    @PreAuthorize("hasRole('ADMIN')")
    public SyncAccepted startSync(String sourceId) {
        CurrentUser user = CurrentUser.from(SecurityContextHolder.getContext().getAuthentication());
        return client.startSync(user, Validation.sourceId(sourceId));
    }
}
