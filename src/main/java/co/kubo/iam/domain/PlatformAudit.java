package co.kubo.iam.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/** Registro de lo que hace el operador de plataforma (F6.4, ADR-0025). */
@Entity
@Table(name = "platform_audit")
public class PlatformAudit {

    @Id
    private UUID id;

    @Column(name = "actor_id", nullable = false)
    private UUID actorId;

    @Column(name = "actor_email", nullable = false, length = 180)
    private String actorEmail;

    @Column(nullable = false, length = 40)
    private String action;

    @Column(name = "tenant_id")
    private UUID tenantId;

    @Column(length = 300)
    private String detail;

    @Column(length = 60)
    private String ip;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected PlatformAudit() {
        // requerido por JPA
    }

    public PlatformAudit(
            UUID id,
            UUID actorId,
            String actorEmail,
            String action,
            UUID tenantId,
            String detail,
            String ip,
            Instant createdAt) {
        this.id = id;
        this.actorId = actorId;
        this.actorEmail = actorEmail;
        this.action = action;
        this.tenantId = tenantId;
        this.detail = detail;
        this.ip = ip;
        this.createdAt = createdAt;
    }

    public UUID getId() {
        return id;
    }

    public UUID getActorId() {
        return actorId;
    }

    public String getActorEmail() {
        return actorEmail;
    }

    public String getAction() {
        return action;
    }

    public UUID getTenantId() {
        return tenantId;
    }

    public String getDetail() {
        return detail;
    }

    public String getIp() {
        return ip;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
