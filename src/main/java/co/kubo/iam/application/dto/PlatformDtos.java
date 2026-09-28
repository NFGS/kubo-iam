package co.kubo.iam.application.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.util.List;

/** Contratos del reino de plataforma (F6.4, ADR-0025). */
public final class PlatformDtos {

    private PlatformDtos() {
    }

    public record PlatformLoginRequest(@NotBlank @Email String email, @NotBlank String password) {
    }

    public record PlatformChallenge(boolean totpRequired, String challengeToken) {
    }

    public record PlatformToken(String accessToken, String tokenType, long expiresInSeconds, String email) {
    }

    public record PlatformVerifyRequest(@NotBlank String challengeToken, @NotBlank String code) {
    }

    /** Negocio visto por el operador: identidad, plan y cupo de usuarios. */
    public record PlatformTenant(
            String id,
            String name,
            String slug,
            String plan,
            String status,
            String planRenewsAt,
            long activeUsers,
            int maxUsers,
            int maxWarehouses) {
    }

    /** Suspender, reactivar o registrar un pago (renovacion en dias). */
    public record PlatformTenantUpdate(@Size(max = 20) String status, Integer renewDays) {
    }

    public record PlatformAuditEntry(
            String actorEmail, String action, String tenantId, String detail, String createdAt) {
    }

    public record PlatformTenants(List<PlatformTenant> data) {
    }

    public record PlatformAuditPage(List<PlatformAuditEntry> data) {
    }
}
