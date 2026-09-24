package co.kubo.iam.application;

import co.kubo.iam.domain.User;
import co.kubo.iam.domain.repository.RefreshTokenRepository;
import co.kubo.iam.domain.repository.UserRepository;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Respuesta a incidentes de seguridad que debe persistir aunque la peticion falle.
 *
 * <p>Cuando se detecta la reutilizacion de un token de refresco (senal de robo), hay que
 * cerrar todas las sesiones del usuario y dejar constancia. Ese camino termina lanzando una
 * excepcion, de modo que si ambas cosas se hicieran en la transaccion de la peticion, la
 * revocacion y el registro se revertirian: la respuesta de seguridad no ocurriria.
 *
 * <p>Por eso este servicio abre su propia transaccion. No participa de la transaccion
 * original y, al no existir en ella ningun bloqueo de la cadena de auditoria, tampoco puede
 * producirse un bloqueo mutuo.
 *
 * <p>La misma leccion aplica al contador de intentos fallidos (P-11): si se incrementara en
 * la transaccion del login, la excepcion de credenciales invalidas lo borraria y el bloqueo
 * por fuerza bruta nunca se activaria.
 */
@Service
public class SecurityIncidentService {

    private final RefreshTokenRepository refreshTokens;
    private final UserRepository users;
    private final AuditService auditService;
    private final JdbcTemplate jdbcTemplate;

    public SecurityIncidentService(
            RefreshTokenRepository refreshTokens,
            UserRepository users,
            AuditService auditService,
            JdbcTemplate jdbcTemplate) {
        this.refreshTokens = refreshTokens;
        this.users = users;
        this.auditService = auditService;
        this.jdbcTemplate = jdbcTemplate;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void registerRefreshReuse(UUID userId, UUID tokenId, String ip, String userAgent) {
        markSystemContext();
        refreshTokens.revokeAllByUserId(userId, Instant.now());
        auditService.record(
                null,
                userId,
                "REFRESH_REUSE_DETECTED",
                "refresh_token",
                tokenId.toString(),
                ip,
                userAgent);
    }

    /**
     * Incrementa el contador de intentos fallidos y bloquea la cuenta al alcanzar el limite.
     *
     * <p>Ocurre en una transaccion independiente porque el login terminara en excepcion: el
     * contador debe sobrevivir a ese rollback. El bloqueo se levanta solo con un acceso
     * correcto, con una recuperacion de contrasena o al vencer el plazo.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public LoginFailure registerLoginFailure(
            UUID userId, String ip, String userAgent, int maxAttempts, int lockMinutes) {
        markSystemContext();
        User user = users.findById(userId)
                .orElseThrow(() -> DomainException.notFound("USER_NOT_FOUND", "Usuario no encontrado"));

        int attempts = user.getFailedLoginAttempts() + 1;
        boolean locked = attempts >= maxAttempts;

        user.setFailedLoginAttempts(attempts);
        if (locked) {
            user.setLockedUntil(Instant.now().plus(Duration.ofMinutes(lockMinutes)));
        }
        users.save(user);

        auditService.record(
                user.getTenant().getId(),
                user.getId(),
                "LOGIN_FAILED",
                "user",
                user.getId().toString(),
                ip,
                userAgent);

        if (locked) {
            auditService.record(
                    user.getTenant().getId(),
                    user.getId(),
                    "ACCOUNT_LOCKED",
                    "user",
                    user.getId().toString(),
                    ip,
                    userAgent);
        }

        return new LoginFailure(attempts, locked, user.getLockedUntil());
    }

    /**
     * La transaccion REQUIRES_NEW corre en otra conexion y no hereda el contexto de RLS que el
     * interceptor fijo en la transaccion exterior. Sin esta marca, las consultas no verian
     * ninguna fila y —peor— la revocacion de la familia de tokens actualizaria cero filas en
     * silencio: el sistema detectaria el robo y no cerraria nada.
     */
    private void markSystemContext() {
        jdbcTemplate.queryForObject("select set_config('app.system', 'on', true)", String.class);
    }

    /** Resultado de registrar un intento fallido. */
    public record LoginFailure(int attempts, boolean locked, Instant lockedUntil) {
    }
}
