package co.kubo.iam.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/**
 * Registro de auditoria append-only. Cada fila encadena el hash de la anterior, de modo que
 * alterar o borrar un registro intermedio rompe la cadena y es detectables.
 */
@Entity
@Table(name = "audit_logs")
public class AuditLog {

    @Id
    private UUID id;

    @Column(name = "tenant_id")
    private UUID tenantId;

    @Column(name = "user_id")
    private UUID userId;

    @Column(nullable = false, length = 80)
    private String action;

    @Column(length = 80)
    private String entity;

    @Column(name = "entity_id", length = 80)
    private String entityId;

    @Column(length = 60)
    private String ip;

    @Column(name = "user_agent", length = 240)
    private String userAgent;

    @Column(name = "prev_hash", length = 64)
    private String prevHash;

    @Column(nullable = false, length = 64)
    private String hash;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected AuditLog() {
        // requerido por JPA
    }

    public AuditLog(
            UUID id,
            UUID tenantId,
            UUID userId,
            String action,
            String entity,
            String entityId,
            String ip,
            String userAgent,
            String prevHash,
            String hash,
            Instant createdAt) {
        this.id = id;
        this.tenantId = tenantId;
        this.userId = userId;
        this.action = action;
        this.entity = entity;
        this.entityId = entityId;
        this.ip = ip;
        this.userAgent = userAgent;
        this.prevHash = prevHash;
        this.hash = hash;
        this.createdAt = createdAt;
    }

    public UUID getId() {
        return id;
    }

    public String getAction() {
        return action;
    }

    public String getHash() {
        return hash;
    }

    public String getPrevHash() {
        return prevHash;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public UUID getTenantId() {
        return tenantId;
    }

    public UUID getUserId() {
        return userId;
    }

    public String getEntity() {
        return entity;
    }

    public String getEntityId() {
        return entityId;
    }
}
