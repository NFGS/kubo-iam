package co.kubo.iam.infra;

import co.kubo.iam.application.TotpService;
import co.kubo.iam.config.TotpSecretCipher;
import co.kubo.iam.domain.PlatformAdmin;
import co.kubo.iam.domain.repository.PlatformAdminRepository;
import java.time.Instant;
import java.util.Locale;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Primer operador de plataforma (F6.4, ADR-0025).
 *
 * Se crea con `KUBO_PLATFORM_ADMIN_EMAIL` y `KUBO_PLATFORM_ADMIN_PASSWORD`, y
 * el secreto TOTP se genera aqui: la URI `otpauth` se escribe **una sola vez**
 * en el registro del arranque para que el operador la escanee. El segundo
 * factor es obligatorio para este rol: sin el no hay sesion de plataforma.
 */
@Component
public class PlatformSeeder implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(PlatformSeeder.class);

    private final PlatformAdminRepository admins;
    private final PasswordEncoder passwordEncoder;
    private final TotpService totpService;
    private final TotpSecretCipher totpCipher;

    public PlatformSeeder(
            PlatformAdminRepository admins,
            PasswordEncoder passwordEncoder,
            TotpService totpService,
            TotpSecretCipher totpCipher) {
        this.admins = admins;
        this.passwordEncoder = passwordEncoder;
        this.totpService = totpService;
        this.totpCipher = totpCipher;
    }

    @Override
    public void run(ApplicationArguments args) {
        String email = System.getenv("KUBO_PLATFORM_ADMIN_EMAIL");
        String password = System.getenv("KUBO_PLATFORM_ADMIN_PASSWORD");

        if (email == null || email.isBlank() || password == null || password.isBlank()) {
            return;
        }

        if (admins.findByEmailIgnoreCase(email).isPresent()) {
            log.info("Operador de plataforma ya existe: {}", email);
            return;
        }

        String secreto = totpService.newSecret();

        admins.save(new PlatformAdmin(
                UUID.randomUUID(),
                email.trim().toLowerCase(Locale.ROOT),
                passwordEncoder.encode(password),
                totpCipher.encrypt(secreto),
                Instant.now()));

        // Unica vez que el secreto sale en claro: es el momento de escanearlo.
        log.info("Operador de plataforma creado: {} — escanee esta URI UNA vez: {}",
                email, totpService.otpauthUri(email, secreto));
    }
}
