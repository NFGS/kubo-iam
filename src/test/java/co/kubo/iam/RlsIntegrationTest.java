package co.kubo.iam;

import static org.assertj.core.api.Assertions.assertThat;

import co.kubo.iam.application.AuditService;
import co.kubo.iam.domain.Tenant;
import co.kubo.iam.domain.User;
import co.kubo.iam.domain.UserRole;
import co.kubo.iam.domain.UserStatus;
import co.kubo.iam.domain.repository.TenantRepository;
import co.kubo.iam.domain.repository.UserRepository;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Pruebas de integracion con PostgreSQL real (P-08).
 *
 * <p>Verifican lo que las pruebas unitarias no pueden: que las migraciones Flyway
 * (incluida la de RLS) se apliquen sobre un motor real, que el aislamiento lo
 * imponga el motor y que la cadena de auditoria se pueda verificar contra filas
 * de verdad.
 *
 * <p>La aplicacion se conecta con un rol sin superusuario: PostgreSQL exime a
 * los superusuarios de RLS y la prueba no mediria nada.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE)
@Testcontainers
class RlsIntegrationTest {

    @Container
    static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>("postgres:17-alpine").withInitScript("init-test-db.sql");

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", () -> "kubo_iam");
        registry.add("spring.datasource.password", () -> "kubo_iam_test");
        // El cifrado del secreto TOTP exige una llave real (P-30): en pruebas,
        // una fija de 64 hexadecimales.
        registry.add("kubo.totp.encryption-key", () -> "a".repeat(64));
    }

    @Autowired
    private UserRepository users;

    @Autowired
    private TenantRepository tenants;

    @Autowired
    private AuditService auditService;

    @Autowired
    private JdbcTemplate jdbc;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    @Transactional
    @DisplayName("RLS: sin contexto de negocio no hay filas; con contexto, si")
    void elAislamientoLoImponeElMotor() {
        jdbc.queryForObject("select set_config('app.system', 'on', true)", String.class);

        Instant now = Instant.now();
        Tenant tenant = tenants.saveAndFlush(
                new Tenant(UUID.randomUUID(), "Tienda Test", "tienda-test", "community", "America/Bogota", "retail", now));
        // saveAndFlush: la comprobacion siguiente usa JDBC directo y no pasa por
        // Hibernate, que de otro modo mantendria la fila sin escribir.
        users.saveAndFlush(new User(
                UUID.randomUUID(),
                tenant,
                "dueno@test.local",
                passwordEncoder.encode("ClaveTest1!"),
                "Dueno Test",
                UserRole.OWNER,
                UserStatus.ACTIVE,
                now));

        jdbc.queryForObject("select set_config('app.system', '', true)", String.class);
        Integer sinContexto = jdbc.queryForObject("select count(*) from users", Integer.class);
        assertThat(sinContexto).as("sin contexto de negocio no debe verse ninguna fila").isZero();

        jdbc.queryForObject(
                "select set_config('app.tenant_id', ?, true)", String.class, tenant.getId().toString());
        Integer conContexto = jdbc.queryForObject("select count(*) from users", Integer.class);
        assertThat(conContexto).as("con el negocio en contexto debe verse su usuario").isEqualTo(1);
    }

    @Test
    @Transactional
    @DisplayName("La cadena de auditoria se encadena y se verifica contra filas reales")
    void laCadenaDeAuditoriaSeVerifica() {
        jdbc.queryForObject("select set_config('app.system', 'on', true)", String.class);

        auditService.record(null, null, "TEST_ONE", "test", "1", "127.0.0.1", "junit");
        auditService.record(null, null, "TEST_TWO", "test", "2", "127.0.0.1", "junit");

        AuditService.AuditVerification verificacion = auditService.verifyLatestWindow();

        assertThat(verificacion.chainIntact()).isTrue();
        assertThat(verificacion.entriesChecked()).isGreaterThanOrEqualTo(2);
        assertThat(verificacion.hashVersions()).containsKey(2);
        assertThat(verificacion.unverifiableEntries()).isZero();
    }
}
