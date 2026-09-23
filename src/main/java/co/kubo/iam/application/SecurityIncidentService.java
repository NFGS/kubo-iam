package co.kubo.iam.application;

import co.kubo.iam.domain.repository.RefreshTokenRepository;
import java.time.Instant;
import java.util.UUID;
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
 */
@Service
public class SecurityIncidentService {

    private final RefreshTokenRepository refreshTokens;
    private final AuditService auditService;

    public SecurityIncidentService(RefreshTokenRepository refreshTokens, AuditService auditService) {
        this.refreshTokens = refreshTokens;
        this.auditService = auditService;
    }

    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void registerRefreshReuse(UUID userId, UUID tokenId, String ip, String userAgent) {
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
}
