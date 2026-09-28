package co.kubo.iam.application;

import co.kubo.iam.domain.PaymentIntent;
import co.kubo.iam.domain.PlanPrice;
import co.kubo.iam.domain.PlatformAudit;
import co.kubo.iam.domain.Tenant;
import co.kubo.iam.domain.repository.PaymentIntentRepository;
import co.kubo.iam.domain.repository.PlanPriceRepository;
import co.kubo.iam.domain.repository.PlatformAuditRepository;
import co.kubo.iam.domain.repository.TenantRepository;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDate;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Puerto de cobro (F6.6, ADR-0026).
 *
 * Los pagos son datos: la intencion guarda plan, ciclo, monto y la referencia
 * del proveedor. La renovacion se deriva de un pago **pagado** y es idempotente
 * por referencia: un webhook repetido no extiende dos veces el plan. El cobro
 * manual (el operador registra la transferencia) usa el mismo camino, de modo
 * que la historia de pagos es una sola.
 */
@Service
public class PaymentsService {

    private static final String MONEDA = "COP";
    private static final int MAX_CICLO = 24;

    private final PaymentIntentRepository intents;
    private final PlanPriceRepository prices;
    private final TenantRepository tenants;
    private final PlatformAuditRepository platformAudit;

    public PaymentsService(
            PaymentIntentRepository intents,
            PlanPriceRepository prices,
            TenantRepository tenants,
            PlatformAuditRepository platformAudit) {
        this.intents = intents;
        this.prices = prices;
        this.tenants = tenants;
        this.platformAudit = platformAudit;
    }

    /** Precios del plan por ciclo (los datos que ve el negocio al pagar). */
    @Transactional(readOnly = true)
    public List<PlanPrice> pricesOf(String plan) {
        return prices.findByPlanAndCurrencyOrderByCycleMonthsAsc(plan, MONEDA);
    }

    /**
     * Crea la intencion de pago: el negocio la pide y el operador (o el
     * proveedor) la confirma. El monto sale del catalogo, nunca del cliente.
     */
    @Transactional
    public PaymentIntent createIntent(UUID tenantId, String plan, int cycleMonths, String provider, String createdBy) {
        if (cycleMonths < 1 || cycleMonths > MAX_CICLO) {
            throw DomainException.badRequest("INVALID_CYCLE", "El ciclo debe estar entre 1 y " + MAX_CICLO + " meses");
        }

        PlanPrice precio = prices.findByPlanAndCurrencyAndCycleMonths(plan, MONEDA, cycleMonths)
                .orElseThrow(() -> DomainException.badRequest(
                        "PLAN_PRICE_NOT_FOUND", "No hay precio para " + plan + " a " + cycleMonths + " mes(es)"));

        String referencia = provider.equals("manual")
                ? "manual-" + UUID.randomUUID()
                : "pendiente-" + UUID.randomUUID();

        return intents.save(new PaymentIntent(
                UUID.randomUUID(),
                tenantId,
                plan,
                cycleMonths,
                precio.getAmount(),
                MONEDA,
                provider,
                referencia,
                createdBy,
                Instant.now()));
    }

    /** Intenciones pendientes de confirmar (lo que ve el operador). */
    @Transactional(readOnly = true)
    public List<PaymentIntent> pending(int limite) {
        return intents.findByStatusOrderByCreatedAtAsc("PENDING", PageRequest.of(0, Math.min(Math.max(limite, 1), 100)));
    }

    @Transactional(readOnly = true)
    public List<PaymentIntent> ofTenant(UUID tenantId) {
        return intents.findByTenantIdOrderByCreatedAtDesc(tenantId, PageRequest.of(0, 50));
    }

    /**
     * Confirma un pago: marca la intencion y **extiende el plan** por su ciclo.
     *
     * Idempotente por (proveedor, referencia): si la intencion ya esta pagada se
     * devuelve sin tocar la fecha. La base tambien lo garantiza con su indice
     * unico, de modo que un webhook repetido no puede regalar un ciclo.
     */
    @Transactional
    public PaymentIntent confirmPaid(
            String provider, String reference, BigDecimal amount, String actor, String ip) {
        PaymentIntent intent = intents.findByProviderAndReference(provider, reference)
                .orElseThrow(() -> DomainException.notFound(
                        "PAYMENT_NOT_FOUND", "No hay una intencion de pago con esa referencia"));

        if ("PAID".equals(intent.getStatus())) {
            return intent;
        }

        if (amount != null && intent.getAmount().compareTo(amount) != 0) {
            throw DomainException.badRequest(
                    "AMOUNT_MISMATCH",
                    "El monto recibido (" + amount + ") no coincide con el de la intencion (" + intent.getAmount() + ")");
        }

        Tenant tenant = tenants.findById(intent.getTenantId())
                .orElseThrow(() -> DomainException.notFound("TENANT_NOT_FOUND", "El negocio no existe"));

        // La renovacion extiende desde la fecha vigente o desde hoy, la mayor:
        // pagar antes de vencer no regala meses.
        LocalDate base = tenant.getPlanRenewsAt() == null || tenant.getPlanRenewsAt().isBefore(LocalDate.now())
                ? LocalDate.now()
                : tenant.getPlanRenewsAt();

        tenant.setPlanRenewsAt(base.plusMonths(intent.getCycleMonths()));
        tenant.setPlan(intent.getPlan());
        tenants.save(tenant);

        intent.markPaid("pago de " + intent.getCycleMonths() + " mes(es) por " + actor, Instant.now());
        intents.save(intent);

        platformAudit.save(new PlatformAudit(
                UUID.randomUUID(),
                UUID.fromString("00000000-0000-0000-0000-000000000000"),
                actor,
                "PAYMENT_CONFIRMED",
                tenant.getId(),
                intent.getReference() + " hasta " + tenant.getPlanRenewsAt(),
                ip,
                Instant.now()));

        return intent;
    }

    /** Confirmacion desde el panel: el operador registra el pago de una intencion. */
    @Transactional
    public PaymentIntent confirmById(String intentId, String actor, String ip) {
        UUID id;
        try {
            id = UUID.fromString(intentId);
        } catch (IllegalArgumentException exception) {
            throw DomainException.badRequest("INVALID_ID", "El identificador no es valido");
        }

        PaymentIntent intent = intents.findById(id)
                .orElseThrow(() -> DomainException.notFound("PAYMENT_NOT_FOUND", "La intencion de pago no existe"));

        return confirmPaid(intent.getProvider(), intent.getReference(), null, actor, ip);
    }

    /**
     * Firma del webhook: HMAC-SHA256 del cuerpo crudo con el secreto compartido.
     * El proveedor firma; nosotros verificamos. Comparacion en tiempo constante.
     */
    public boolean signatureValid(String rawBody, String signature, String secret) {
        if (signature == null || signature.isBlank() || secret == null || secret.isBlank()) {
            return false;
        }

        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] esperado = mac.doFinal(rawBody.getBytes(StandardCharsets.UTF_8));

            return java.security.MessageDigest.isEqual(
                    HexFormat.of().formatHex(esperado).getBytes(StandardCharsets.UTF_8),
                    signature.trim().toLowerCase().getBytes(StandardCharsets.UTF_8));
        } catch (Exception exception) {
            throw new IllegalStateException("No fue posible verificar la firma del webhook", exception);
        }
    }
}
