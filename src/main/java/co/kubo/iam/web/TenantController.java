package co.kubo.iam.web;

import co.kubo.iam.application.AuthService;
import co.kubo.iam.application.PaymentsService;
import co.kubo.iam.application.dto.PaymentsDtos.PaymentList;
import co.kubo.iam.application.dto.PaymentsDtos.PaymentRequest;
import co.kubo.iam.application.dto.PaymentsDtos.PaymentView;
import co.kubo.iam.application.dto.PaymentsDtos.PriceList;
import co.kubo.iam.application.dto.PaymentsDtos.PriceView;
import co.kubo.iam.application.DomainException;
import co.kubo.iam.application.dto.AuthDtos.TenantItem;
import co.kubo.iam.application.dto.AuthDtos.UpdateTenantRequest;
import co.kubo.iam.config.InternalAuthFilter;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Perfil del negocio: zona horaria (ADR-0012) y vertical o paquete de
 * configuracion (ADR-0013, P-17).
 *
 * La zona horaria y el vertical viajan en el token de acceso; un cambio aplica
 * al siguiente inicio de sesion.
 */
@RestController
@RequestMapping("/tenants")
public class TenantController {

    private final AuthService authService;
    private final PaymentsService payments;

    public TenantController(AuthService authService, PaymentsService payments) {
        this.authService = authService;
        this.payments = payments;
    }

    @GetMapping("/me")
    public TenantItem current(@RequestHeader(InternalAuthFilter.HEADER_USER_ID) String userId) {
        return new TenantItem(authService.currentTenant(userId));
    }

    /** Catalogo de planes comerciales (ADR-0021). */
    @GetMapping("/plans")
    public java.util.List<co.kubo.iam.application.dto.AuthDtos.TenantResponse.PlanInfo> plans() {
        return authService.planes();
    }

    /** Precios del plan del negocio (F6.6): lo que cuesta pagar cada ciclo. */
    @GetMapping("/me/prices")
    public PriceList prices(@RequestHeader(InternalAuthFilter.HEADER_USER_ID) String userId) {
        var tenant = authService.currentTenant(userId);

        return new PriceList(payments.pricesOf(tenant.plan()).stream()
                .map(precio -> new PriceView(
                        precio.getPlan(),
                        precio.getCurrency(),
                        precio.getCycleMonths(),
                        precio.getAmount().toPlainString()))
                .toList());
    }

    /**
     * El negocio pide pagar su plan: se crea la intencion con el precio del
     * catalogo y el operador (o el proveedor) la confirma.
     */
    @PostMapping("/me/payments")
    public PaymentView requestPayment(
            @RequestHeader(InternalAuthFilter.HEADER_USER_ID) String userId,
            @Valid @RequestBody PaymentRequest request) {
        var tenant = authService.currentTenant(userId);
        String plan = request.plan() == null || request.plan().isBlank() ? tenant.plan() : request.plan().trim().toLowerCase(java.util.Locale.ROOT);
        int ciclo = request.cycleMonths() == null ? 1 : request.cycleMonths();

        return view(payments.createIntent(java.util.UUID.fromString(tenant.id()), plan, ciclo, "manual", tenant.name()));
    }

    /** Historia de pagos del negocio. */
    @GetMapping("/me/payments")
    public PaymentList paymentsOf(@RequestHeader(InternalAuthFilter.HEADER_USER_ID) String userId) {
        var tenant = authService.currentTenant(userId);

        return new PaymentList(payments.ofTenant(java.util.UUID.fromString(tenant.id())).stream()
                .map(TenantController::view)
                .toList());
    }

    private static PaymentView view(co.kubo.iam.domain.PaymentIntent intent) {
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

    /** Cambia la zona horaria y/o el vertical. Solo propietario o administrador. */
    @PatchMapping("/me")
    public TenantItem update(
            @RequestHeader(InternalAuthFilter.HEADER_USER_ID) String userId,
            @RequestHeader(value = InternalAuthFilter.HEADER_USER_ROLE, required = false) String role,
            @Valid @RequestBody UpdateTenantRequest request) {
        if (role == null || !(role.equals("OWNER") || role.equals("ADMIN"))) {
            throw DomainException.forbidden(
                    "FORBIDDEN", "Solo el propietario o un administrador pueden cambiar el negocio");
        }

        return new TenantItem(authService.updateTenant(userId, request));
    }
}
