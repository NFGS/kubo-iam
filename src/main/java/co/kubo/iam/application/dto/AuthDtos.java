package co.kubo.iam.application.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.time.Instant;

/** Contratos de entrada y salida del servicio de identidad. */
public final class AuthDtos {

    private AuthDtos() {
    }

    public record RegisterRequest(
            @NotBlank @Size(max = 160) String tenantName,
            @NotBlank @Size(max = 160) String fullName,
            @NotBlank @Email @Size(max = 180) String email,
            @NotBlank @Size(min = 8, max = 72) String password) {
    }

    public record LoginRequest(@NotBlank @Email String email, @NotBlank String password) {
    }

    public record RefreshRequest(@NotBlank String refreshToken) {
    }

    public record LogoutRequest(@NotBlank String refreshToken) {
    }

    public record ForgotPasswordRequest(@NotBlank @Email @Size(max = 180) String email) {
    }

    public record CreateUserRequest(
            @NotBlank @Size(max = 160) String fullName,
            @NotBlank @Email @Size(max = 180) String email,
            @NotBlank @Size(min = 8, max = 72) String password,
            @NotBlank String role) {
    }

    /** Actualizacion parcial: los campos ausentes conservan su valor. */
    public record UpdateUserRequest(
            @Size(max = 160) String fullName,
            String role,
            String status) {
    }

    public record ResetPasswordRequest(
            @NotBlank String token,
            @NotBlank @Size(min = 8, max = 72) String newPassword) {
    }

    public record UserResponse(
            String id,
            String email,
            String fullName,
            String role,
            String status,
            String tenantId,
            String tenantName,
            boolean totpEnabled) {
    }

    /** Resultado del acceso: sesion emitida o desafio del segundo factor (P-30). */
    public sealed interface LoginResult permits LoginResult.Tokens, LoginResult.Totp {
        record Tokens(TokenResponse response) implements LoginResult {
        }

        record Totp(TotpChallengeResponse response) implements LoginResult {
        }
    }

    public record TotpChallengeResponse(boolean totpRequired, String challengeToken) {
    }

    public record TotpSetupResponse(String secret, String otpauthUri) {
    }

    public record TotpCodeRequest(@NotBlank String code) {
    }

    public record TotpVerifyRequest(@NotBlank String challengeToken, @NotBlank String code) {
    }

    /** Cambio de perfil del negocio: zona horaria y/o vertical (ADR-0012, ADR-0013). */
    public record UpdateTenantRequest(
            @Size(max = 60) String timezone,
            @Size(max = 40) String vertical) {
    }

    public record TenantResponse(
            String id,
            String name,
            String slug,
            String plan,
            String timezone,
            String vertical) {
    }

    /** Envoltura estandar de la API: {"data": ...}, igual que el resto de servicios. */
    public record TenantItem(TenantResponse data) {
    }

    public record TokenResponse(
            String accessToken,
            String refreshToken,
            String tokenType,
            long expiresInSeconds,
            UserResponse user) {
    }

    public record HealthResponse(String status, String service, String db, Instant time) {
    }

    public record AuditEntryResponse(
            String id,
            String action,
            String entity,
            String entityId,
            String hash,
            String prevHash,
            int hashVersion,
            Instant createdAt) {
    }
}
