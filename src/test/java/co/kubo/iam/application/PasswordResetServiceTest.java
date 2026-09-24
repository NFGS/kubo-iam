package co.kubo.iam.application;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import co.kubo.iam.config.KuboProperties;
import co.kubo.iam.domain.PasswordResetToken;
import co.kubo.iam.domain.Tenant;
import co.kubo.iam.domain.User;
import co.kubo.iam.domain.UserRole;
import co.kubo.iam.domain.UserStatus;
import co.kubo.iam.domain.repository.PasswordResetTokenRepository;
import co.kubo.iam.domain.repository.RefreshTokenRepository;
import co.kubo.iam.domain.repository.UserRepository;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

/** Reglas de la recuperacion de contrasena (P-04). */
@ExtendWith(MockitoExtension.class)
class PasswordResetServiceTest {

    @Mock
    private UserRepository users;

    @Mock
    private PasswordResetTokenRepository tokens;

    @Mock
    private RefreshTokenRepository refreshTokens;

    @Mock
    private PasswordEncoder encoder;

    @Mock
    private TokenService tokenService;

    @Mock
    private MailService mail;

    @Mock
    private AuditService audit;

    private PasswordResetService service;
    private User user;

    @BeforeEach
    void setUp() {
        KuboProperties properties = new KuboProperties(
                new KuboProperties.Jwt("kubo-iam", "kubo-api", 15, 7, ""),
                new KuboProperties.Seed(false, "admin@kubo.local", "Admin123!", "Tienda"),
                new KuboProperties.Auth(5, 15, 30),
                new KuboProperties.Mail("log", "no-responder@kubo.local", "http://localhost/recuperar",
                        "", 587, "", "", true));

        service = new PasswordResetService(
                users, tokens, refreshTokens, encoder, tokenService, mail, audit, properties);

        Tenant tenant = new Tenant(UUID.randomUUID(), "Tienda Test", "tienda-test", "community", "America/Bogota", Instant.now());
        user = new User(
                UUID.randomUUID(),
                tenant,
                "dueno@test.local",
                "hash",
                "Dueno Test",
                UserRole.OWNER,
                UserStatus.ACTIVE,
                Instant.now());
    }

    @Test
    @DisplayName("Un correo desconocido no envia nada y no revela la ausencia")
    void correoDesconocido() {
        when(users.findByEmailIgnoreCase("nadie@test.local")).thenReturn(Optional.empty());

        service.request("nadie@test.local", "127.0.0.1", "junit");

        verify(mail, never()).send(anyString(), anyString(), anyString());
        verify(tokens, never()).save(any());
    }

    @Test
    @DisplayName("Un correo registrado recibe un enlace de un solo uso")
    void correoRegistrado() {
        when(users.findByEmailIgnoreCase("dueno@test.local")).thenReturn(Optional.of(user));
        when(tokenService.newSecureToken()).thenReturn("token-plano");
        when(tokenService.hashToken("token-plano")).thenReturn("hash");

        service.request("dueno@test.local", "127.0.0.1", "junit");

        verify(tokens).deleteUnusedByUserId(user.getId());
        verify(tokens).save(any(PasswordResetToken.class));
        verify(mail).send(eq("dueno@test.local"), anyString(), anyString());
        verify(audit).record(any(), any(), eq("PASSWORD_RESET_REQUESTED"), any(), any(), any(), any());
    }

    @Test
    @DisplayName("Un token vencido o ya usado se rechaza")
    void tokenInvalido() {
        when(tokenService.hashToken("viejo")).thenReturn("hash-viejo");
        when(tokens.findByTokenHash("hash-viejo")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.reset("viejo", "NuevaClave1!", "127.0.0.1", "junit"))
                .isInstanceOf(DomainException.class)
                .extracting(exception -> ((DomainException) exception).getCode())
                .isEqualTo("INVALID_RESET_TOKEN");

        verify(users, never()).save(any());
    }

    @Test
    @DisplayName("Consumir el enlace cambia la clave, levanta el bloqueo y cierra sesiones")
    void resetCorrecto() {
        PasswordResetToken token = new PasswordResetToken(
                UUID.randomUUID(), user.getId(), "hash", Instant.now().plusSeconds(600), Instant.now());
        when(tokenService.hashToken("vigente")).thenReturn("hash");
        when(tokens.findByTokenHash("hash")).thenReturn(Optional.of(token));
        when(users.findById(user.getId())).thenReturn(Optional.of(user));
        when(encoder.encode("NuevaClave1!")).thenReturn("hash-nuevo");

        service.reset("vigente", "NuevaClave1!", "127.0.0.1", "junit");

        verify(users).save(user);
        verify(refreshTokens).revokeAllByUserId(eq(user.getId()), any());
        verify(audit).record(any(), any(), eq("PASSWORD_RESET"), any(), any(), any(), any());
        verify(tokens).save(token);
    }
}
