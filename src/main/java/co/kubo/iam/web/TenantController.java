package co.kubo.iam.web;

import co.kubo.iam.application.AuthService;
import co.kubo.iam.application.DomainException;
import co.kubo.iam.application.dto.AuthDtos.TenantItem;
import co.kubo.iam.application.dto.AuthDtos.UpdateTenantRequest;
import co.kubo.iam.config.InternalAuthFilter;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
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

    public TenantController(AuthService authService) {
        this.authService = authService;
    }

    @GetMapping("/me")
    public TenantItem current(@RequestHeader(InternalAuthFilter.HEADER_USER_ID) String userId) {
        return new TenantItem(authService.currentTenant(userId));
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
