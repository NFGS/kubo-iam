package co.kubo.iam.infra;

import co.kubo.iam.application.AuditService;
import co.kubo.iam.config.KuboProperties;
import co.kubo.iam.domain.Tenant;
import co.kubo.iam.domain.User;
import co.kubo.iam.domain.UserRole;
import co.kubo.iam.domain.UserStatus;
import co.kubo.iam.domain.repository.TenantRepository;
import co.kubo.iam.domain.repository.UserRepository;
import java.time.Instant;
import java.util.Locale;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Semilla de demostracion: crea el negocio, el usuario propietario y un vendedor.
 * Solo se ejecuta si la base de datos esta vacia y {@code kubo.seed.enabled=true}.
 */
@Component
public class DataSeeder implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(DataSeeder.class);

    private final UserRepository users;
    private final TenantRepository tenants;
    private final PasswordEncoder passwordEncoder;
    private final AuditService auditService;
    private final KuboProperties properties;
    private final JdbcTemplate jdbcTemplate;

    public DataSeeder(
            UserRepository users,
            TenantRepository tenants,
            PasswordEncoder passwordEncoder,
            AuditService auditService,
            KuboProperties properties,
            JdbcTemplate jdbcTemplate) {
        this.users = users;
        this.tenants = tenants;
        this.passwordEncoder = passwordEncoder;
        this.auditService = auditService;
        this.properties = properties;
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        if (!properties.seed().enabled()) {
            return;
        }

        // La semilla es una operacion de sistema: crea el negocio y sus usuarios
        // antes de que exista una peticion con identidad. Con RLS activo, sin
        // esta marca no veria ni insertaria ninguna fila.
        jdbcTemplate.queryForObject("select set_config('app.system', 'on', true)", String.class);
        if (users.count() > 0) {
            log.info("Semilla omitida: ya existen usuarios registrados");
            return;
        }

        Instant now = Instant.now();
        Tenant tenant = tenants.save(new Tenant(
                UUID.randomUUID(), properties.seed().tenantName(), "tienda-la-esquina", "community",
                "America/Bogota", "retail", now));

        String adminEmail = properties.seed().adminEmail().toLowerCase(Locale.ROOT);
        User owner = users.save(new User(
                UUID.randomUUID(),
                tenant,
                adminEmail,
                passwordEncoder.encode(properties.seed().adminPassword()),
                "Administrador Kubo",
                UserRole.OWNER,
                UserStatus.ACTIVE,
                now));

        users.save(new User(
                UUID.randomUUID(),
                tenant,
                "vendedor@kubo.local",
                passwordEncoder.encode("Vendedor123!"),
                "Camila Vendedora",
                UserRole.SELLER,
                UserStatus.ACTIVE,
                now));

        auditService.record(
                tenant.getId(), owner.getId(), "TENANT_SEEDED", "tenant", tenant.getId().toString(), "127.0.0.1", "seed");

        log.info("Semilla creada: tenant='{}' admin='{}'", tenant.getName(), adminEmail);
    }
}
