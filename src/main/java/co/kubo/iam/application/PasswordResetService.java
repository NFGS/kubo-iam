package co.kubo.iam.application;

import co.kubo.iam.config.KuboProperties;
import co.kubo.iam.domain.PasswordResetToken;
import co.kubo.iam.domain.User;
import co.kubo.iam.domain.repository.PasswordResetTokenRepository;
import co.kubo.iam.domain.repository.RefreshTokenRepository;
import co.kubo.iam.domain.repository.UserRepository;
import java.time.Duration;
import java.time.Instant;
import java.util.Locale;
import java.util.UUID;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Recuperacion de contrasena (P-04).
 *
 * <p>Dos pasos: solicitar el enlace (por correo) y consumirlo una sola vez. El token se guarda
 * hasheado, vence en minutos y al usarse revoca todas las sesiones del usuario. La solicitud
 * responde igual exista o no la cuenta: no se puede usar para enumerar usuarios.
 */
@Service
public class PasswordResetService {

    private final UserRepository users;
    private final PasswordResetTokenRepository tokens;
    private final RefreshTokenRepository refreshTokens;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;
    private final MailService mailService;
    private final AuditService auditService;
    private final KuboProperties properties;

    public PasswordResetService(
            UserRepository users,
            PasswordResetTokenRepository tokens,
            RefreshTokenRepository refreshTokens,
            PasswordEncoder passwordEncoder,
            TokenService tokenService,
            MailService mailService,
            AuditService auditService,
            KuboProperties properties) {
        this.users = users;
        this.tokens = tokens;
        this.refreshTokens = refreshTokens;
        this.passwordEncoder = passwordEncoder;
        this.tokenService = tokenService;
        this.mailService = mailService;
        this.auditService = auditService;
        this.properties = properties;
    }

    /** Genera el enlace y lo envia. Nunca revela si el correo existe. */
    @Transactional
    public void request(String rawEmail, String ip, String userAgent) {
        String email = rawEmail.trim().toLowerCase(Locale.ROOT);
        users.findByEmailIgnoreCase(email).ifPresent(user -> sendResetLink(user, ip, userAgent));
    }

    /** Consume el token y cambia la contrasena. El token es de un solo uso. */
    @Transactional
    public void reset(String rawToken, String newPassword, String ip, String userAgent) {
        Instant now = Instant.now();

        PasswordResetToken token = tokens.findByTokenHash(tokenService.hashToken(rawToken))
                .filter(candidate -> candidate.getUsedAt() == null)
                .filter(candidate -> candidate.getExpiresAt().isAfter(now))
                .orElseThrow(() -> DomainException.badRequest(
                        "INVALID_RESET_TOKEN", "El enlace no es valido o ya expiro"));

        User user = users.findById(token.getUserId())
                .orElseThrow(() -> DomainException.badRequest(
                        "INVALID_RESET_TOKEN", "El enlace no es valido o ya expiro"));

        user.setPasswordHash(passwordEncoder.encode(newPassword));
        // Recuperar la contrasena tambien levanta el bloqueo por intentos fallidos.
        user.setFailedLoginAttempts(0);
        user.setLockedUntil(null);
        users.save(user);

        token.markUsed(now);
        tokens.save(token);

        // Cambiar la contrasena cierra todas las sesiones: un token robado deja de servir.
        refreshTokens.revokeAllByUserId(user.getId(), now);

        auditService.record(
                user.getTenant().getId(),
                user.getId(),
                "PASSWORD_RESET",
                "user",
                user.getId().toString(),
                ip,
                userAgent);
    }

    private void sendResetLink(User user, String ip, String userAgent) {
        tokens.deleteUnusedByUserId(user.getId());

        String rawToken = tokenService.newSecureToken();
        Instant now = Instant.now();

        tokens.save(new PasswordResetToken(
                UUID.randomUUID(),
                user.getId(),
                tokenService.hashToken(rawToken),
                now.plus(Duration.ofMinutes(properties.auth().resetTokenMinutes())),
                now));

        String link = properties.mail().resetUrlBase() + "?token=" + rawToken;
        String body = """
                Hola %s:

                Recibimos una solicitud para restablecer tu contrasena de Kubo.
                Abre este enlace (vence en %d minutos y solo puede usarse una vez):

                %s

                Si no solicitaste el cambio, ignora este mensaje: tu contrasena sigue igual.
                """.formatted(user.getFullName(), properties.auth().resetTokenMinutes(), link);

        mailService.send(user.getEmail(), "Restablece tu contrasena de Kubo", body);

        auditService.record(
                user.getTenant().getId(),
                user.getId(),
                "PASSWORD_RESET_REQUESTED",
                "user",
                user.getId().toString(),
                ip,
                userAgent);
    }
}
