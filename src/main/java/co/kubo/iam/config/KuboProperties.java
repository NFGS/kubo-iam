package co.kubo.iam.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Propiedades de configuracion del servicio, agrupadas bajo el prefijo {@code kubo}.
 */
@ConfigurationProperties(prefix = "kubo")
public record KuboProperties(Jwt jwt, Seed seed, Auth auth, Mail mail, Totp totp) {

    public record Jwt(
            String issuer,
            String audience,
            int accessTokenMinutes,
            int refreshTokenDays,
            String privateKeyPem) {
    }

    public record Seed(
            boolean enabled,
            String adminEmail,
            String adminPassword,
            String tenantName) {
    }

    /** Politicas de autenticacion: bloqueo por intentos y vigencia del enlace de recuperacion. */
    public record Auth(int maxFailedAttempts, int lockMinutes, int resetTokenMinutes) {
    }

    /** Segundo factor TOTP (P-30): llave con la que se cifra el secreto en reposo. */
    public record Totp(String encryptionKey) {
    }

    /** Transporte de correo: `log` (buzon de demostracion) o `smtp` (servidor real). */
    public record Mail(
            String transport,
            String from,
            String resetUrlBase,
            String smtpHost,
            int smtpPort,
            String smtpUsername,
            String smtpPassword,
            boolean smtpStartTls) {
    }
}
