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
            String tenantName) {
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
