package co.kubo.iam.infra;

import co.kubo.iam.application.MailService;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/**
 * Transporte de correo por defecto: no sale del servidor.
 *
 * <p>El mensaje queda en la tabla {@code mail_outbox} (buzon de demostracion) para que el
 * operador y la prueba de humo puedan verlo. En un negocio real se configura
 * {@code KUBO_MAIL_TRANSPORT=smtp} y el cuerpo deja de persistirse.
 */
@Service
@ConditionalOnProperty(name = "kubo.mail.transport", havingValue = "log", matchIfMissing = true)
public class LogMailService implements MailService {

    private static final Logger log = LoggerFactory.getLogger(LogMailService.class);

    private final JdbcTemplate jdbcTemplate;

    public LogMailService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Override
    public void send(String recipient, String subject, String body) {
        jdbcTemplate.update(
                "insert into mail_outbox (id, recipient, subject, body, transport) values (?, ?, ?, ?, 'log')",
                UUID.randomUUID(),
                recipient,
                subject,
                body);

        log.info("Correo en el buzon de demostracion para {} (asunto: {})", recipient, subject);
    }
}
