package co.kubo.iam.application;

import static org.assertj.core.api.Assertions.assertThat;

import co.kubo.iam.config.KuboProperties;
import co.kubo.iam.domain.Tenant;
import co.kubo.iam.domain.User;
import co.kubo.iam.domain.UserRole;
import co.kubo.iam.domain.UserStatus;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class TokenServiceTest {

    private TokenService tokenService;
    private User user;

    @BeforeEach
    void setUp() {
        KuboProperties properties = new KuboProperties(
                new KuboProperties.Jwt("kubo-iam", "kubo-api", 15, 7, ""),
                new KuboProperties.Seed(false, "admin@kubo.local", "Admin123!", "Tienda"),
                new KuboProperties.Auth(5, 15, 30),
                new KuboProperties.Mail("log", "no-responder@kubo.local", "http://localhost:3000/reset",
                        "", 587, "", "", true));
        tokenService = new TokenService(properties);
        tokenService.init();

        Tenant tenant = new Tenant(
                UUID.randomUUID(), "Tienda La Esquina", "tienda", "community", "America/Mexico_City", Instant.now());
        user = new User(
                UUID.randomUUID(),
                tenant,
                "admin@kubo.local",
                "hash",
                "Administrador",
                UserRole.OWNER,
                UserStatus.ACTIVE,
                Instant.now());
    }

    @Test
    @DisplayName("El access token se firma con RS256 y contiene los claims de identidad")
    void signsAccessTokenWithRs256() {
        String token = tokenService.signAccessToken(user);

        assertThat(token).isNotBlank();
        assertThat(token.split("\\.")).hasSize(3);
        assertThat(tokenService.keyId()).isNotBlank();
    }

    @Test
    @DisplayName("El token lleva la zona horaria del negocio (ADR-0012)")
    void incluyeLaZonaHorariaDelNegocio() {
        String token = tokenService.signAccessToken(user);
        String payload = new String(
                java.util.Base64.getUrlDecoder().decode(token.split("\\.")[1]),
                java.nio.charset.StandardCharsets.UTF_8);

        assertThat(payload).contains("\"tenant_timezone\":\"America/Mexico_City\"");
    }

    @Test
    @DisplayName("El JWKS expone la llave publica y no la privada")
    void publishesPublicJwksOnly() {
        String jwks = tokenService.jwks();

        assertThat(jwks).contains("\"keys\"").contains("\"kty\":\"RSA\"");
        assertThat(jwks).doesNotContain("\"d\":");
    }

    @Test
    @DisplayName("El refresh token es aleatorio y su hash es SHA-256 en hexadecimal")
    void refreshTokensAreRandomAndHashed() {
        String first = tokenService.newRefreshToken();
        String second = tokenService.newSecureToken();

        assertThat(first).isNotEqualTo(second);
        assertThat(first).doesNotContain("+", "/", "=");
        assertThat(tokenService.hashToken(first)).hasSize(64).matches("[0-9a-f]{64}");
    }
}
