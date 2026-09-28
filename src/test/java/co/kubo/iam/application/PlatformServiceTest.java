package co.kubo.iam.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import co.kubo.iam.application.dto.PlatformDtos.PlatformChallenge;
import co.kubo.iam.application.dto.PlatformDtos.PlatformLoginRequest;
import co.kubo.iam.application.dto.PlatformDtos.PlatformTenant;
import co.kubo.iam.application.dto.PlatformDtos.PlatformTenantUpdate;
import co.kubo.iam.application.dto.PlatformDtos.PlatformToken;
import co.kubo.iam.application.dto.PlatformDtos.PlatformVerifyRequest;
import co.kubo.iam.config.KuboProperties;
import co.kubo.iam.config.TotpSecretCipher;
import co.kubo.iam.domain.PlatformAdmin;
import co.kubo.iam.domain.PlatformAudit;
import co.kubo.iam.domain.Tenant;
import co.kubo.iam.domain.repository.PlatformAdminRepository;
import co.kubo.iam.domain.repository.PlatformAuditRepository;
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
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Reino de plataforma (F6.4, ADR-0025). El flujo positivo se prueba aqui —con
 * el secreto bajo control—; el humo cubre la separacion de reinos y el rechazo
 * del codigo invalido, que no necesitan el secreto.
 */
@ExtendWith(MockitoExtension.class)
class PlatformServiceTest {

    private static final String SECRETO = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    @Mock
    private PlatformAdminRepository admins;

    @Mock
    private PlatformAuditRepository platformAudit;

    @Mock
    private TenantRepository tenants;

    @Mock
    private UserRepository users;

    @Mock
    private PasswordEncoder encoder;

    @Mock
    private TokenService tokenService;

    @Mock
    private JdbcTemplate jdbc;

    private final TotpService totp = new TotpService();
    private TotpSecretCipher cipher;
    private PlatformService service;
    private PlatformAdmin admin;
    private Tenant tenant;

    @BeforeEach
    void setUp() {
        cipher = new TotpSecretCipher(properties());

        service = new PlatformService(
                admins, platformAudit, tenants, users, encoder, tokenService, totp, cipher, jdbc);

        admin = new PlatformAdmin(
                UUID.randomUUID(), "operador@kubo.local", "hash", cipher.encrypt(SECRETO), Instant.now());

        tenant = new Tenant(UUID.randomUUID(), "Tienda", "tienda", "community", "America/Bogota", "retail", Instant.now());
    }

    @Test
    @DisplayName("El acceso de plataforma siempre pide el codigo, nunca emite sesion directa")
    void accesoPideCodigo() {
        when(admins.findByEmailIgnoreCase("operador@kubo.local")).thenReturn(Optional.of(admin));
        when(encoder.matches(anyString(), anyString())).thenReturn(true);
        when(tokenService.signPlatformChallenge(admin)).thenReturn("desafio");

        PlatformChallenge reto = service.login(new PlatformLoginRequest("operador@kubo.local", "Clave123!"), "127.0.0.1");

        assertThat(reto.totpRequired()).isTrue();
        assertThat(reto.challengeToken()).isEqualTo("desafio");
        verify(platformAudit).save(any(PlatformAudit.class));
    }

    @Test
    @DisplayName("Una contrasena incorrecta no abre el desafio y queda auditada")
    void contrasenaIncorrecta() {
        when(admins.findByEmailIgnoreCase("operador@kubo.local")).thenReturn(Optional.of(admin));
        when(encoder.matches(anyString(), anyString())).thenReturn(false);

        assertThatThrownBy(() -> service.login(new PlatformLoginRequest("operador@kubo.local", "mala"), "127.0.0.1"))
                .isInstanceOf(DomainException.class)
                .extracting(exception -> ((DomainException) exception).getCode())
                .isEqualTo("INVALID_CREDENTIALS");

        verify(platformAudit).save(any(PlatformAudit.class));
    }

    @Test
    @DisplayName("El codigo vigente emite el token de plataforma")
    void codigoVigenteEmiteToken() {
        when(tokenService.verifyPlatformChallenge("desafio")).thenReturn(admin.getId().toString());
        when(admins.findById(admin.getId())).thenReturn(Optional.of(admin));
        when(admins.save(any(PlatformAdmin.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(tokenService.signPlatformAccessToken(admin)).thenReturn("token-plataforma");

        String codigo = totp.codeAt(SECRETO, Instant.now());
        PlatformToken token = service.verifyTotp(new PlatformVerifyRequest("desafio", codigo), "127.0.0.1");

        assertThat(token.accessToken()).isEqualTo("token-plataforma");
        assertThat(token.email()).isEqualTo("operador@kubo.local");
    }

    @Test
    @DisplayName("Rotar el segundo factor invalida el secreto viejo y entrega la URI una vez")
    void rotarSegundoFactor() {
        when(admins.findById(admin.getId())).thenReturn(Optional.of(admin));
        when(admins.save(any(PlatformAdmin.class))).thenAnswer(invocation -> invocation.getArgument(0));

        var rotacion = service.rotateTotp(admin.getId().toString(), "operador@kubo.local", "127.0.0.1");

        assertThat(rotacion.otpauthUri()).startsWith("otpauth://totp/");
        assertThat(rotacion.secret()).isNotEqualTo(SECRETO);
        assertThat(cipher.decrypt(admin.getTotpSecret())).isEqualTo(rotacion.secret());
        verify(platformAudit).save(any(PlatformAudit.class));

        // El codigo del secreto viejo ya no sirve: el segundo factor quedo rotado.
        when(tokenService.verifyPlatformChallenge("desafio")).thenReturn(admin.getId().toString());
        String viejo = totp.codeAt(SECRETO, Instant.now());
        assertThatThrownBy(() -> service.verifyTotp(new PlatformVerifyRequest("desafio", viejo), "127.0.0.1"))
                .isInstanceOf(DomainException.class)
                .extracting(exception -> ((DomainException) exception).getCode())
                .isEqualTo("INVALID_TOTP");
    }

    @Test
    @DisplayName("Suspender un negocio cambia su estado y queda auditado")
    void suspenderNegocio() {
        when(tenants.findById(tenant.getId())).thenReturn(Optional.of(tenant));
        when(tenants.save(any(Tenant.class))).thenAnswer(invocation -> invocation.getArgument(0));

        PlatformTenant vista = service.updateTenant(
                admin.getId().toString(), admin.getEmail(), tenant.getId().toString(),
                new PlatformTenantUpdate("SUSPENDED", null), "127.0.0.1");

        assertThat(vista.status()).isEqualTo("SUSPENDED");
        assertThat(tenant.getStatus()).isEqualTo("SUSPENDED");
        verify(platformAudit).save(any(PlatformAudit.class));
    }

    @Test
    @DisplayName("La renovacion extiende desde la fecha vigente y valida los dias")
    void renovacion() {
        tenant.setPlanRenewsAt(java.time.LocalDate.now().plusDays(10));
        when(tenants.findById(tenant.getId())).thenReturn(Optional.of(tenant));
        when(tenants.save(any(Tenant.class))).thenAnswer(invocation -> invocation.getArgument(0));

        PlatformTenant vista = service.updateTenant(
                admin.getId().toString(), admin.getEmail(), tenant.getId().toString(),
                new PlatformTenantUpdate(null, 30), "127.0.0.1");

        // 10 dias vigentes + 30 = 40: pagar antes de vencer no regala dias.
        assertThat(vista.planRenewsAt()).isEqualTo(java.time.LocalDate.now().plusDays(40).toString());

        assertThatThrownBy(() -> service.updateTenant(
                admin.getId().toString(), admin.getEmail(), tenant.getId().toString(),
                new PlatformTenantUpdate(null, 0), "127.0.0.1"))
                .isInstanceOf(DomainException.class)
                .extracting(exception -> ((DomainException) exception).getCode())
                .isEqualTo("INVALID_RENEW_DAYS");

        assertThatThrownBy(() -> service.updateTenant(
                admin.getId().toString(), admin.getEmail(), tenant.getId().toString(),
                new PlatformTenantUpdate("BORRADO", null), "127.0.0.1"))
                .isInstanceOf(DomainException.class)
                .extracting(exception -> ((DomainException) exception).getCode())
                .isEqualTo("INVALID_STATUS");
    }

    @Test
    @DisplayName("El listado del panel cruza negocios con la marca de sistema")
    void listadoConMarcaDeSistema() {
        when(jdbc.queryForObject(anyString(), eq(String.class))).thenReturn("on");
        when(tenants.findAll()).thenReturn(java.util.List.of(tenant));
        when(users.countByTenantIdAndStatus(tenant.getId(), co.kubo.iam.domain.UserStatus.ACTIVE)).thenReturn(3L);

        var lista = service.tenants();

        assertThat(lista).hasSize(1);
        assertThat(lista.getFirst().activeUsers()).isEqualTo(3);
        assertThat(lista.getFirst().maxUsers()).isEqualTo(5);
    }

    private KuboProperties properties() {
        return new KuboProperties(
                new KuboProperties.Jwt("kubo-iam", "kubo-api", 15, 7, ""),
                new KuboProperties.Seed(false, "admin@kubo.local", "Admin123!", "Tienda"),
                new KuboProperties.Auth(5, 15, 30),
                new KuboProperties.Mail("log", "no-responder@kubo.local", "http://localhost/reset", "", 587, "", "", true),
                new KuboProperties.Totp("a".repeat(64)));
    }
}
