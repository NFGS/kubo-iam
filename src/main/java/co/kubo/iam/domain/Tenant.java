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

    /** Paquete de configuracion activo (ADR-0013, P-17): retail, servicios, etc. */
    @Column(nullable = false, length = 40)
    private String vertical;

    /** Estado comercial (ADR-0021): un negocio suspendido no inicia sesion. */
    @Column(nullable = false, length = 20)
    private String status = "ACTIVE";

    /** Fecha hasta la que esta pagado el plan (F6.2); null si es manual. */
    @Column(name = "plan_renews_at")
    private java.time.LocalDate planRenewsAt;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected Tenant() {
        // requerido por JPA
    }

    public Tenant(
            UUID id,
            String name,
            String slug,
            String plan,
            String timezone,
            String vertical,
            Instant createdAt) {
        this.id = id;
        this.name = name;
        this.slug = slug;
        this.plan = plan;
        this.timezone = timezone;
        this.vertical = vertical;
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

    /** Un pago puede cambiar de plan (F6.6): la renovacion aplica el plan pagado. */
    public void setPlan(String plan) {
        this.plan = plan;
    }

    public String getTimezone() {
        return timezone;
    }

    public void setTimezone(String timezone) {
        this.timezone = timezone;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public boolean isSuspended() {
        return "SUSPENDED".equals(status);
    }

    public java.time.LocalDate getPlanRenewsAt() {
        return planRenewsAt;
    }

    public void setPlanRenewsAt(java.time.LocalDate planRenewsAt) {
        this.planRenewsAt = planRenewsAt;
    }

    public String getVertical() {
        return vertical;
    }

    public void setVertical(String vertical) {
        this.vertical = vertical;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
