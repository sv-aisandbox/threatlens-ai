package ai.threatlens.backend.audit;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** Append-only writer for {@code audit_log}. Never receives tokens or bodies. */
@Repository
public class AuditRepository {

    private final JdbcClient jdbc;

    public AuditRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    public void record(AuditEvent e) {
        jdbc.sql("""
                        INSERT INTO audit_log (actor, tenant_id, action, resource, outcome, http_status, correlation_id)
                        VALUES (:actor, :tenant, :action, :resource, :outcome, :status, :cid)
                        """)
                .param("actor", e.actor())
                .param("tenant", e.tenantId())
                .param("action", e.action())
                .param("resource", e.resource())
                .param("outcome", e.outcome())
                .param("status", e.httpStatus())
                .param("cid", e.correlationId())
                .update();
    }

    public record AuditEvent(
            String actor, String tenantId, String action, String resource, String outcome, int httpStatus,
            String correlationId) {}
}
