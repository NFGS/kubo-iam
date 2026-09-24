package co.kubo.iam.web;

import co.kubo.iam.application.AuthService;
import co.kubo.iam.application.AuditService;
import co.kubo.iam.application.DomainException;
import co.kubo.iam.application.dto.AuthDtos.AuditEntryResponse;
import co.kubo.iam.application.dto.AuthDtos.CreateUserRequest;
import co.kubo.iam.application.dto.AuthDtos.UpdateUserRequest;
import co.kubo.iam.application.dto.AuthDtos.UserResponse;
import co.kubo.iam.config.InternalAuthFilter;
import jakarta.validation.Valid;
import java.util.List;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
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

    /** Crea un usuario en el negocio del actor. Solo propietario o administrador (P-20). */
    @PostMapping("/users")
    public ResponseEntity<UserResponse> createUser(
            @RequestHeader(InternalAuthFilter.HEADER_USER_ID) String userId,
            @RequestHeader(value = InternalAuthFilter.HEADER_USER_ROLE, required = false) String role,
            @Valid @RequestBody CreateUserRequest request) {
        requireAdmin(role);
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.createUser(userId, request));
    }

    /** Actualiza nombre, rol o estado de un usuario del negocio. Solo propietario o administrador. */
    @PatchMapping("/users/{id}")
    public UserResponse updateUser(
            @RequestHeader(InternalAuthFilter.HEADER_USER_ID) String userId,
            @RequestHeader(value = InternalAuthFilter.HEADER_USER_ROLE, required = false) String role,
            @PathVariable("id") String targetId,
            @Valid @RequestBody UpdateUserRequest request) {
        requireAdmin(role);
        return authService.updateUser(userId, targetId, request);
    }

    private void requireAdmin(String role) {
        if (role == null || !(role.equals("OWNER") || role.equals("ADMIN"))) {
            throw DomainException.forbidden(
                    "FORBIDDEN", "Solo el propietario o un administrador pueden gestionar usuarios");
        }
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
