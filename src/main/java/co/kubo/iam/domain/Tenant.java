package co.kubo.iam.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/** Negocio (tenant) que usa Kubo. En el MVP una instalacion atiende a un tenant. */
@Entity
@Table(name = "tenants")
public class Tenant {

    @Id
    private UUID id;

    @Column(nullable = false, length = 160)
    private String name;

    @Column(nullable = false, length = 80, unique = true)
    private String slug;

    @Column(nullable = false, length = 40)
    private String plan;

    /** Zona horaria IANA del negocio (ADR-0012): define su dia comercial. */
    @Column(nullable = false, length = 60)
    private String timezone;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected Tenant() {
        // requerido por JPA
    }

    public Tenant(UUID id, String name, String slug, String plan, String timezone, Instant createdAt) {
        this.id = id;
        this.name = name;
        this.slug = slug;
        this.plan = plan;
        this.timezone = timezone;
        this.createdAt = createdAt;
    }

    public UUID getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getSlug() {
        return slug;
    }

    public String getPlan() {
        return plan;
    }

    public String getTimezone() {
        return timezone;
    }

    public void setTimezone(String timezone) {
        this.timezone = timezone;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
