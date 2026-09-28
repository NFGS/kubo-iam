package co.kubo.iam.web;

import co.kubo.iam.application.DomainException;
import co.kubo.iam.application.PaymentsService;
import co.kubo.iam.application.PlatformService;
import co.kubo.iam.application.dto.PaymentsDtos.PaymentView;
import co.kubo.iam.application.dto.PlatformDtos;
import co.kubo.iam.application.dto.PlatformDtos.PlatformAuditPage;
import co.kubo.iam.application.dto.PlatformDtos.PlatformChallenge;
import co.kubo.iam.application.dto.PlatformDtos.PlatformLoginRequest;
import co.kubo.iam.application.dto.PlatformDtos.PlatformTenant;
import co.kubo.iam.application.dto.PlatformDtos.PlatformTenantUpdate;
import co.kubo.iam.application.dto.PlatformDtos.PlatformToken;
import co.kubo.iam.application.dto.PlatformDtos.PlatformVerifyRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Reino de plataforma (F6.4, ADR-0025).
 *
 * El gateway solo enruta aqui tokens con `platform=true` e inyecta la identidad
 * del operador; un token de negocio no llega. El poder es minimo: listar
 * negocios, suspender, reactivar y registrar pagos.
 */
@RestController
@RequestMapping("/platform")
public class PlatformController {

    static final String HEADER_PLATFORM_ID = "x-platform-admin-id";
    static final String HEADER_PLATFORM_EMAIL = "x-platform-admin-email";

    private final PlatformService platformService;
    private final PaymentsService payments;

    public PlatformController(PlatformService platformService, PaymentsService payments) {
        this.platformService = platformService;
        this.payments = payments;
    }

    /**
     * Pagos pendientes de confirmar: el operador registra la transferencia.
     * El negocio aparece por nombre —el panel gestiona, no lee datos de negocio—
     * para que se sepa a quien pertenece cada pago.
     */
    @GetMapping("/payments")
    public List<Map<String, Object>> pendingPayments(
            @RequestHeader(value = HEADER_PLATFORM_ID, required = false) String actorId,
            @RequestParam(defaultValue = "50") int limit) {
        requirePlatform(actorId);

        Map<String, String> nombres = platformService.tenants().stream()
                .collect(Collectors.toMap(PlatformDtos.PlatformTenant::id, PlatformDtos.PlatformTenant::name));

        return payments.pending(limit).stream()
                .map(intent -> {
                    Map<String, Object> vista = new LinkedHashMap<String, Object>();
                    vista.put("id", intent.getId().toString());
                    vista.put("tenantName", nombres.getOrDefault(intent.getTenantId().toString(), intent.getTenantId().toString()));
                    vista.put("plan", intent.getPlan());
                    vista.put("cycleMonths", intent.getCycleMonths());
                    vista.put("amount", intent.getAmount().toPlainString());
                    vista.put("currency", intent.getCurrency());
                    vista.put("provider", intent.getProvider());
                    vista.put("reference", intent.getReference());
                    vista.put("status", intent.getStatus());
                    vista.put("createdAt", intent.getCreatedAt().toString());

                    return vista;
                })
                .toList();
    }

    /** Registra el pago de una intencion: extiende el plan por su ciclo. */
    @PostMapping("/payments/{id}/confirm")
    public PaymentView confirmPayment(
            @RequestHeader(value = HEADER_PLATFORM_ID, required = false) String actorId,
            @RequestHeader(value = HEADER_PLATFORM_EMAIL, required = false) String actorEmail,
            @PathVariable("id") String intentId,
            HttpServletRequest http) {
        requirePlatform(actorId);

        var intent = payments.confirmById(intentId, actorEmail == null ? "operador" : actorEmail, clientIp(http));

        return new PaymentView(
                intent.getId().toString(),
                intent.getPlan(),
                intent.getCycleMonths(),
                intent.getAmount().toPlainString(),
                intent.getCurrency(),
                intent.getProvider(),
                intent.getReference(),
                intent.getStatus(),
                intent.getDetail(),
                intent.getCreatedAt().toString(),
                intent.getPaidAt() == null ? null : intent.getPaidAt().toString());
    }

    /** Primer paso del acceso: correo y contrasena (siempre pide el codigo). */
    @PostMapping("/auth/login")
    public PlatformChallenge login(
            @Valid @RequestBody PlatformLoginRequest request, HttpServletRequest http) {
        return platformService.login(request, clientIp(http));
    }

    /** Segundo paso: codigo TOTP a cambio de la sesion de plataforma. */
    @PostMapping("/auth/totp")
    public PlatformToken totp(@Valid @RequestBody PlatformVerifyRequest request, HttpServletRequest http) {
        return platformService.verifyTotp(request, clientIp(http));
    }

    @GetMapping("/tenants")
    public List<PlatformTenant> tenants(@RequestHeader(value = HEADER_PLATFORM_ID, required = false) String actorId) {
        requirePlatform(actorId);

        return platformService.tenants();
    }

    /** Suspende, reactiva o registra un pago (renovacion en dias). */
    @PatchMapping("/tenants/{id}")
    public PlatformTenant updateTenant(
            @RequestHeader(value = HEADER_PLATFORM_ID, required = false) String actorId,
            @RequestHeader(value = HEADER_PLATFORM_EMAIL, required = false) String actorEmail,
            @PathVariable("id") String tenantId,
            @Valid @RequestBody PlatformTenantUpdate request,
            HttpServletRequest http) {
        requirePlatform(actorId);

        return platformService.updateTenant(actorId, actorEmail == null ? "operador" : actorEmail, tenantId, request, clientIp(http));
    }

    @GetMapping("/audit")
    public PlatformAuditPage audit(
            @RequestHeader(value = HEADER_PLATFORM_ID, required = false) String actorId,
            @RequestParam(defaultValue = "50") int limit) {
        requirePlatform(actorId);

        return platformService.audit(limit);
    }

    private void requirePlatform(String actorId) {
        if (actorId == null || actorId.isBlank()) {
            throw DomainException.forbidden("FORBIDDEN", "Se requiere una sesion de plataforma");
        }
    }

    private String clientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");

        return forwarded == null || forwarded.isBlank() ? request.getRemoteAddr() : forwarded;
    }
}
