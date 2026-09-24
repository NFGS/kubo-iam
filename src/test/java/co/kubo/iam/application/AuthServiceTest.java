package co.kubo.iam.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import co.kubo.iam.application.dto.AuthDtos.LoginRequest;
import co.kubo.iam.application.dto.AuthDtos.TokenResponse;
import co.kubo.iam.config.KuboProperties;
import co.kubo.iam.domain.Tenant;
import co.kubo.iam.domain.User;
import co.kubo.iam.domain.UserRole;
import co.kubo.iam.domain.UserStatus;
import co.kubo.iam.domain.repository.RefreshTokenRepository;
import co.kubo.iam.domain.repository.TenantRepository;
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

/** Reglas de dominio del inicio de sesion: bloqueo, fallo y exito (P-11). */
@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository users;

    @Mock
    private TenantRepository tenants;

    @Mock
    private RefreshTokenRepository refreshTokens;

    @Mock
    private PasswordEncoder encoder;

    @Mock
    private TokenService tokenService;

    @Mock
    private AuditService audit;

    @Mock
    private SecurityIncidentService incidents;

    private AuthService service;
    private User user;

    @BeforeEach
    void setUp() {
        KuboProperties properties = new KuboProperties(
                new KuboProperties.Jwt("kubo-iam", "kubo-api", 15, 7, ""),
                new KuboProperties.Seed(false, "admin@kubo.local", "Admin123!", "Tienda"),
                new KuboProperties.Auth(5, 15, 30),
                new KuboProperties.Mail("log", "no-responder@kubo.local", "http://localhost/recuperar",
                        "", 587, "", "", true));

        service = new AuthService(users, tenants, refreshTokens, encoder, tokenService, audit, incidents, properties);

        Tenant tenant = new Tenant(UUID.randomUUID(), "Tienda Test", "tienda-test", "community", "America/Bogota", "retail", Instant.now());
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
    @DisplayName("Una cuenta bloqueada rechaza el acceso incluso con la contrasena correcta")
    void cuentaBloqueada() {
        user.setLockedUntil(Instant.now().plusSeconds(600));
        when(users.findByEmailIgnoreCase("dueno@test.local")).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> service.login(new LoginRequest("dueno@test.local", "Clave1!"), "127.0.0.1", "junit"))
                .isInstanceOf(DomainException.class)
                .extracting(exception -> ((DomainException) exception).getCode())
                .isEqualTo("ACCOUNT_LOCKED");

        verify(incidents, never()).registerLoginFailure(any(), anyString(), anyString(), anyInt(), anyInt());
        verify(audit).recordIndependent(any(), any(), eq("LOGIN_BLOCKED"), any(), any(), any(), any());
    }

    @Test
    @DisplayName("Una contrasena incorrecta registra el fallo en transaccion aparte")
    void contrasenaIncorrecta() {
        when(users.findByEmailIgnoreCase("dueno@test.local")).thenReturn(Optional.of(user));
        when(encoder.matches(anyString(), anyString())).thenReturn(false);
        when(incidents.registerLoginFailure(any(), anyString(), anyString(), anyInt(), anyInt()))
                .thenReturn(new SecurityIncidentService.LoginFailure(1, false, null));

        assertThatThrownBy(() -> service.login(new LoginRequest("dueno@test.local", "mala"), "127.0.0.1", "junit"))
                .isInstanceOf(DomainException.class)
                .extracting(exception -> ((DomainException) exception).getCode())
                .isEqualTo("INVALID_CREDENTIALS");

        verify(incidents).registerLoginFailure(eq(user.getId()), anyString(), anyString(), eq(5), eq(15));
    }

    @Test
    @DisplayName("El fallo que alcanza el limite responde ACCOUNT_LOCKED")
    void falloQueBloquea() {
        when(users.findByEmailIgnoreCase("dueno@test.local")).thenReturn(Optional.of(user));
        when(encoder.matches(anyString(), anyString())).thenReturn(false);
        when(incidents.registerLoginFailure(any(), anyString(), anyString(), anyInt(), anyInt()))
                .thenReturn(new SecurityIncidentService.LoginFailure(5, true, Instant.now().plusSeconds(900)));

        assertThatThrownBy(() -> service.login(new LoginRequest("dueno@test.local", "mala"), "127.0.0.1", "junit"))
                .isInstanceOf(DomainException.class)
                .extracting(exception -> ((DomainException) exception).getCode())
                .isEqualTo("ACCOUNT_LOCKED");
    }

    @Test
    @DisplayName("Un acceso correcto limpia el contador de intentos y emite tokens")
    void accesoCorrecto() {
        user.setFailedLoginAttempts(3);
        when(users.findByEmailIgnoreCase("dueno@test.local")).thenReturn(Optional.of(user));
        when(encoder.matches(anyString(), anyString())).thenReturn(true);
        when(tokenService.signAccessToken(user)).thenReturn("access");
        when(tokenService.newRefreshToken()).thenReturn("refresh");
        when(tokenService.hashToken("refresh")).thenReturn("hash");

        TokenResponse response =
                service.login(new LoginRequest("dueno@test.local", "Clave1!"), "127.0.0.1", "junit");

        assertThat(response.accessToken()).isEqualTo("access");
        assertThat(response.refreshToken()).isEqualTo("refresh");
        assertThat(user.getFailedLoginAttempts()).isZero();
        assertThat(user.getLockedUntil()).isNull();
        verify(audit).record(any(), any(), eq("LOGIN_SUCCEEDED"), any(), any(), any(), any());
    }

    @Test
    @DisplayName("Un usuario deshabilitado no puede ingresar")
    void usuarioDeshabilitado() {
        user.setStatus(UserStatus.DISABLED);
        when(users.findByEmailIgnoreCase("dueno@test.local")).thenReturn(Optional.of(user));
        when(encoder.matches(anyString(), anyString())).thenReturn(true);

        assertThatThrownBy(() -> service.login(new LoginRequest("dueno@test.local", "Clave1!"), "127.0.0.1", "junit"))
                .isInstanceOf(DomainException.class)
                .extracting(exception -> ((DomainException) exception).getCode())
                .isEqualTo("USER_DISABLED");
    }
}
