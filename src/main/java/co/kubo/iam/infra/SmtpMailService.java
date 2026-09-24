package co.kubo.iam.infra;

import co.kubo.iam.application.MailService;
import co.kubo.iam.config.KuboProperties;
import java.util.Properties;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.stereotype.Service;

/**
 * Transporte SMTP real ({@code KUBO_MAIL_TRANSPORT=smtp}).
 *
 * <p>El servidor se configura por variables de entorno. Si falta el host, el servicio falla al
 * arrancar con un mensaje claro: es mejor no arrancar que creer que se envian correos cuando
 * no es asi.
 */
@Service
@ConditionalOnProperty(name = "kubo.mail.transport", havingValue = "smtp")
public class SmtpMailService implements MailService {

    private final JavaMailSender sender;
    private final String from;

    public SmtpMailService(KuboProperties properties) {
        KuboProperties.Mail mail = properties.mail();
        if (mail.smtpHost() == null || mail.smtpHost().isBlank()) {
            throw new IllegalStateException(
                    "KUBO_MAIL_TRANSPORT=smtp exige KUBO_SMTP_HOST (y credenciales si aplica)");
        }

        JavaMailSenderImpl impl = new JavaMailSenderImpl();
        impl.setHost(mail.smtpHost());
        impl.setPort(mail.smtpPort());
        if (mail.smtpUsername() != null && !mail.smtpUsername().isBlank()) {
            impl.setUsername(mail.smtpUsername());
            impl.setPassword(mail.smtpPassword());
        }

        Properties javaMail = impl.getJavaMailProperties();
        javaMail.put("mail.smtp.auth", String.valueOf(mail.smtpUsername() != null && !mail.smtpUsername().isBlank()));
        javaMail.put("mail.smtp.starttls.enable", String.valueOf(mail.smtpStartTls()));

        this.sender = impl;
        this.from = mail.from();
    }

    @Override
    public void send(String recipient, String subject, String body) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(from);
        message.setTo(recipient);
        message.setSubject(subject);
        message.setText(body);
        sender.send(message);
    }
}
