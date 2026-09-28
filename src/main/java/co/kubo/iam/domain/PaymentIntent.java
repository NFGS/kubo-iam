package co.kubo.iam.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;

/**
 * Intencion de pago (F6.6, ADR-0026).
 *
 * La renovacion del plan se deriva de un pago **pagado**: la intencion guarda el
 * plan, el ciclo, el monto y la referencia del proveedor (unica por proveedor,
 * que es la garantia de idempotencia ante webhooks repetidos).
 */
@Entity
@Table(name = "payment_intents")
public class PaymentIntent {

    @Id
    private UUID id;

    @Column(name = "tenant_id", nullable = false)
    private UUID tenantId;

    @Column(nullable = false, length = 40)
    private String plan;

    @Column(name = "cycle_months", nullable = false)
    private int cycleMonths;

    @Column(nullable = false, precision = 12, scale = 2)
    private BigDecimal amount;

    @Column(nullable = false, length = 3)
    private String currency = "COP";

    @Column(nullable = false, length = 40)
    private String provider = "manual";

    @Column(nullable = false, length = 120)
    private String reference;

    @Column(nullable = false, length = 20)
    private String status = "PENDING";

    @Column(length = 300)
    private String detail;

    @Column(name = "created_by", length = 120)
    private String createdBy;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "paid_at")
    private Instant paidAt;

    protected PaymentIntent() {
        // requerido por JPA
    }

    public PaymentIntent(
            UUID id,
            UUID tenantId,
            String plan,
            int cycleMonths,
            BigDecimal amount,
            String currency,
            String provider,
            String reference,
            String createdBy,
            Instant createdAt) {
        this.id = id;
        this.tenantId = tenantId;
        this.plan = plan;
        this.cycleMonths = cycleMonths;
        this.amount = amount;
        this.currency = currency;
        this.provider = provider;
        this.reference = reference;
        this.createdBy = createdBy;
        this.createdAt = createdAt;
    }

    public void markPaid(String detail, Instant paidAt) {
        this.status = "PAID";
        this.detail = detail;
        this.paidAt = paidAt;
    }

    public void markFailed(String detail) {
        this.status = "FAILED";
        this.detail = detail;
    }

    public UUID getId() {
        return id;
    }

    public UUID getTenantId() {
        return tenantId;
    }

    public String getPlan() {
        return plan;
    }

    public int getCycleMonths() {
        return cycleMonths;
    }

    public BigDecimal getAmount() {
        return amount;
    }

    public String getCurrency() {
        return currency;
    }

    public String getProvider() {
        return provider;
    }

    public String getReference() {
        return reference;
    }

    public String getStatus() {
        return status;
    }

    public String getDetail() {
        return detail;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getPaidAt() {
        return paidAt;
    }
}
