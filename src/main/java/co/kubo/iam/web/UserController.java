package co.kubo.iam.web;

import co.kubo.iam.application.AuthService;
import co.kubo.iam.application.AuditService;
import co.kubo.iam.application.dto.AuthDtos.AuditEntryResponse;
import co.kubo.iam.application.dto.AuthDtos.UserResponse;
import co.kubo.iam.config.InternalAuthFilter;
import java.util.List;
import org.springframework.data.domain.Page;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    private final AuthService authService;
    private final AuditService auditService;

    public UserController(AuthService authService, AuditService auditService) {
        this.authService = authService;
        this.auditService = auditService;
    }

    /** Usuarios del negocio, paginados (por defecto 20, maximo 100). */
    @GetMapping("/users")
    public Page<UserResponse> users(
            @RequestHeader(InternalAuthFilter.HEADER_USER_ID) String userId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        return authService.listUsersOfTenant(userId, page, size);
    }

    @GetMapping("/audit")
    public List<AuditEntryResponse> audit() {
        return auditService.latest().stream()
                .map(entry -> new AuditEntryResponse(
                        entry.getId().toString(),
                        entry.getAction(),
                        entry.getEntity(),
                        entry.getEntityId(),
                        entry.getHash(),
                        entry.getPrevHash(),
                        entry.getHashVersion(),
                        entry.getCreatedAt()))
                .toList();
    }

    /**
     * Comprueba que la bitacora no haya sido manipulada.
     *
     * Verifica la ventana mas reciente: que cada entrada enlace con la anterior y
     * que su hash corresponda al contenido. Devuelve `chainIntact: false` si
     * alguien edito o borro un registro.
     */
    @GetMapping("/audit/verify")
    public AuditService.AuditVerification verifyAudit() {
        return auditService.verifyLatestWindow();
    }
}
