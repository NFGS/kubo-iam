package co.kubo.iam.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import co.kubo.iam.application.dto.AuthDtos.LogoutRequest;
import co.kubo.iam.application.dto.AuthDtos.RefreshRequest;
import co.kubo.iam.application.dto.AuthDtos.RegisterRequest;
import co.kubo.iam.application.dto.AuthDtos.TokenResponse;
import co.kubo.iam.application.dto.AuthDtos.UpdateUserRequest;
import co.kubo.iam.application.dto.AuthDtos.UserResponse;
import co.kubo.iam.config.KuboProperties;
import co.kubo.iam.domain.RefreshToken;
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
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;

/** Flujos completos de identidad: registro, rotacion, cierre y consulta. */
@ExtendWith(MockitoExtension.class)
class AuthServiceFlowsTest {

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

        Tenant tenant = new Tenant(UUID.randomUUID(), "Tienda Test", "tienda-test", "community", "America/Bogota", Instant.now());
        user = new User(
                UUID.randomUUID(), tenant, "dueno@test.local", "hash", "Dueno Test",
                UserRole.OWNER, UserStatus.ACTIVE, Instant.now());
    }

    @Test
    @DisplayName("No se puede registrar dos veces el mismo correo")
    void correoDuplicado() {
        when(users.existsByEmailIgnoreCase("dueno@test.local")).thenReturn(true);

        assertThatThrownBy(() -> service.register(
                new RegisterRequest("Otra Tienda", "Otro", "dueno@test.local", "Clave123!"), "127.0.0.1", "junit"))
                .isInstanceOf(DomainException.class)
                .extracting(exception -> ((DomainException) exception).getCode())
                .isEqualTo("EMAIL_ALREADY_EXISTS");
    }

    @Test
    @DisplayName("El registro crea negocio y propietario y emite tokens")
    void registroCorrecto() {
        when(users.existsByEmailIgnoreCase("nueva@test.local")).thenReturn(false);
        when(tenants.existsBySlug(anyString())).thenReturn(false);
        when(tenants.save(any(Tenant.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(users.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(encoder.encode("Clave123!")).thenReturn("hash");
        when(tokenService.signAccessToken(any(User.class))).thenReturn("access");
        when(tokenService.newRefreshToken()).thenReturn("refresh");
        when(tokenService.hashToken("refresh")).thenReturn("hash-refresh");

        TokenResponse response = service.register(
                new RegisterRequest("Nueva Tienda", "Dueno Nuevo", "nueva@test.local", "Clave123!"),
                "127.0.0.1", "junit");

        assertThat(response.accessToken()).isEqualTo("access");
        assertThat(response.user().role()).isEqualTo("OWNER");
        verify(audit).record(any(), any(), eq("USER_REGISTERED"), any(), any(), any(), any());
    }

    @Test
    @DisplayName("Un token de refresco desconocido se rechaza")
    void refreshDesconocido() {
        when(tokenService.hashToken("malo")).thenReturn("hash-malo");
        when(refreshTokens.findByTokenHash("hash-malo")).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.refresh(new RefreshRequest("malo"), "127.0.0.1", "junit"))
                .isInstanceOf(DomainException.class)
                .extracting(exception -> ((DomainException) exception).getCode())
                .isEqualTo("INVALID_REFRESH_TOKEN");
    }

    @Test
    @DisplayName("Un token revocado activa la respuesta a incidentes")
    void refreshReusado() {
        RefreshToken stored = new RefreshToken(
                UUID.randomUUID(), user.getId(), "hash", Instant.now().plusSeconds(600), Instant.now());
        stored.revoke(null);
        when(tokenService.hashToken("robado")).thenReturn("hash");
        when(refreshTokens.findByTokenHash("hash")).thenReturn(Optional.of(stored));

        assertThatThrownBy(() -> service.refresh(new RefreshRequest("robado"), "127.0.0.1", "junit"))
                .isInstanceOf(DomainException.class)
                .extracting(exception -> ((DomainException) exception).getCode())
                .isEqualTo("REFRESH_TOKEN_REUSED");

        verify(incidents).registerRefreshReuse(eq(user.getId()), eq(stored.getId()), anyString(), anyString());
    }

    @Test
    @DisplayName("Un token vencido se rechaza sin tocar la familia")
    void refreshVencido() {
        RefreshToken stored = new RefreshToken(
                UUID.randomUUID(), user.getId(), "hash", Instant.now().minusSeconds(60), Instant.now());
        when(tokenService.hashToken("viejo")).thenReturn("hash");
        when(refreshTokens.findByTokenHash("hash")).thenReturn(Optional.of(stored));

        assertThatThrownBy(() -> service.refresh(new RefreshRequest("viejo"), "127.0.0.1", "junit"))
                .isInstanceOf(DomainException.class)
                .extracting(exception -> ((DomainException) exception).getCode())
                .isEqualTo("REFRESH_TOKEN_EXPIRED");

        verify(incidents, never()).registerRefreshReuse(any(), any(), anyString(), anyString());
    }

    @Test
    @DisplayName("La rotacion revoca el token anterior y emite uno nuevo")
    void refreshCorrecto() {
        RefreshToken stored = new RefreshToken(
                UUID.randomUUID(), user.getId(), "hash", Instant.now().plusSeconds(600), Instant.now());
        when(tokenService.hashToken("vigente")).thenReturn("hash");
        when(refreshTokens.findByTokenHash("hash")).thenReturn(Optional.of(stored));
        when(users.findById(user.getId())).thenReturn(Optional.of(user));
        when(tokenService.signAccessToken(user)).thenReturn("access-nuevo");
        when(tokenService.newRefreshToken()).thenReturn("refresh-nuevo");
        when(tokenService.hashToken("refresh-nuevo")).thenReturn("hash-nuevo");
        when(refreshTokens.save(any(RefreshToken.class))).thenAnswer(invocation -> invocation.getArgument(0));

        TokenResponse response = service.refresh(new RefreshRequest("vigente"), "127.0.0.1", "junit");

        assertThat(response.refreshToken()).isEqualTo("refresh-nuevo");
        assertThat(stored.getRevokedAt()).isNotNull();
        verify(refreshTokens).save(stored);
        verify(audit).record(any(), any(), eq("TOKEN_REFRESHED"), any(), any(), any(), any());
    }

    @Test
    @DisplayName("Cerrar sesion revoca el token presentado")
    void cierreDeSesion() {
        RefreshToken stored = new RefreshToken(
                UUID.randomUUID(), user.getId(), "hash", Instant.now().plusSeconds(600), Instant.now());
        when(tokenService.hashToken("vigente")).thenReturn("hash");
        when(refreshTokens.findByTokenHash("hash")).thenReturn(Optional.of(stored));

        service.logout(new LogoutRequest("vigente"));

        assertThat(stored.getRevokedAt()).isNotNull();
        verify(refreshTokens).save(stored);
    }

    @Test
    @DisplayName("El listado de usuarios acota el tamano de pagina en el servidor")
    void listadoAcotado() {
        when(users.findById(user.getId())).thenReturn(Optional.of(user));
        when(users.findByTenantId(eq(user.getTenant().getId()), any(Pageable.class)))
                .thenReturn(new PageImpl<>(java.util.List.of()));

        service.listUsersOfTenant(user.getId().toString(), 0, 5000);

        verify(users).findByTenantId(user.getTenant().getId(), PageRequest.of(0, 100));
    }

    @Test
    @DisplayName("Un identificador invalido en /me se rechaza como identidad invalida")
    void meConIdentidadInvalida() {
        assertThatThrownBy(() -> service.me("no-es-uuid"))
                .isInstanceOf(DomainException.class)
                .extracting(exception -> ((DomainException) exception).getCode())
                .isEqualTo("USER_NOT_FOUND");
    }

    @Test
    @DisplayName("Un administrador no puede degradarse ni deshabilitarse a si mismo")
    void autoproteccionDelAdministrador() {
        when(users.findById(user.getId())).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> service.updateUser(
                user.getId().toString(), user.getId().toString(), new UpdateUserRequest(null, "SELLER", null)))
                .isInstanceOf(DomainException.class)
                .extracting(exception -> ((DomainException) exception).getCode())
                .isEqualTo("CANNOT_DEMOTE_SELF");

        assertThatThrownBy(() -> service.updateUser(
                user.getId().toString(), user.getId().toString(), new UpdateUserRequest(null, null, "DISABLED")))
                .isInstanceOf(DomainException.class)
                .extracting(exception -> ((DomainException) exception).getCode())
                .isEqualTo("CANNOT_DISABLE_SELF");

        verify(users, never()).save(any(User.class));
    }

    @Test
    @DisplayName("El administrador si puede ajustar su nombre o confirmar su rol")
    void autoproteccionPermiteCambiosInocuos() {
        when(users.findById(user.getId())).thenReturn(Optional.of(user));
        when(users.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        UserResponse response = service.updateUser(
                user.getId().toString(), user.getId().toString(),
                new UpdateUserRequest("Dueno Renombrado", "OWNER", "ACTIVE"));

        assertThat(response.fullName()).isEqualTo("Dueno Renombrado");
        assertThat(response.role()).isEqualTo("OWNER");
    }

    @Test
    @DisplayName("Un administrador gestiona a otro usuario sin restriccion")
    void adminGestionaAOtro() {
        User otro = new User(
                UUID.randomUUID(), user.getTenant(), "vendedor@test.local", "hash", "Vendedor",
                UserRole.SELLER, UserStatus.ACTIVE, Instant.now());
        when(users.findById(user.getId())).thenReturn(Optional.of(user));
        when(users.findById(otro.getId())).thenReturn(Optional.of(otro));
        when(users.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        UserResponse response = service.updateUser(
                user.getId().toString(), otro.getId().toString(),
                new UpdateUserRequest(null, "ADMIN", "DISABLED"));

        assertThat(response.role()).isEqualTo("ADMIN");
        assertThat(response.status()).isEqualTo("DISABLED");
        verify(audit).record(any(), any(), eq("USER_UPDATED"), any(), any(), any(), any());
    }
}
