package co.kubo.iam.web;

import co.kubo.iam.application.AuthService;
import co.kubo.iam.application.AuditService;
import co.kubo.iam.application.dto.AuthDtos.AuditEntryResponse;
import co.kubo.iam.application.dto.AuthDtos.UserResponse;
import co.kubo.iam.config.InternalAuthFilter;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    private final AuthService authService;
    private final AuditService auditService;

    public UserController(AuthService authService, AuditService auditService) {
        this.authService = authService;
        this.auditService = auditService;
    }

    @GetMapping("/users")
    public List<UserResponse> users(@RequestHeader(InternalAuthFilter.HEADER_USER_ID) String userId) {
        return authService.listUsersOfTenant(userId);
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
                        entry.getCreatedAt()))
                .toList();
    }
}
