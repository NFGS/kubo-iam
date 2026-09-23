package co.kubo.iam.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Propiedades de configuracion del servicio, agrupadas bajo el prefijo {@code kubo}.
 */
@ConfigurationProperties(prefix = "kubo")
public record KuboProperties(Jwt jwt, Seed seed) {

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
}
