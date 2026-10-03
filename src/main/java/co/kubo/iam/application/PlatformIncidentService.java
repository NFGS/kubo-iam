package co.kubo.iam.application;

import co.kubo.iam.domain.PlatformAdmin;
import co.kubo.iam.domain.PlatformAudit;
import co.kubo.iam.domain.repository.PlatformAdminRepository;
import co.kubo.iam.domain.repository.PlatformAuditRepository;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Incidentes del reino de plataforma (ADR-0025).
 *
 * <p>El contador de intentos fallidos debe sobrevivir al rollback de la peticion que termina
 * en excepcion: sin una transaccion independiente, el bloqueo por fuerza bruta nunca se
 * activaria. Es la misma leccion de P-11 en los negocios, aplicada al operador.
 *
 * <p>La auditoria de plataforma no esta bajo RLS (tabla de la plataforma, no de un negocio),
 * de modo que esta transaccion no necesita la marca de sistema.
 */
@Service
public class PlatformIncidentService {

    private final PlatformAdminRepository admins;
    private final PlatformAuditRepository audit;

    public PlatformIncidentService(PlatformAdminRepository admins, PlatformAuditRepository audit) {
        this.admins = admins;
        this.audit = audit;
    }

    /** Incrementa el contador y bloquea al alcanzar el limite. */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public Failure registerFailure(
            UUID adminId, String action, String ip, int maxAttempts, int lockMinutes) {
        PlatformAdmin admin = admins.findById(adminId)
                .orElseThrow(() -> DomainException.notFound("ADMIN_NOT_FOUND", "El operador no existe"));

        int attempts = admin.getFailedLoginAttempts() + 1;
        boolean locked = attempts >= maxAttempts;

        admin.setFailedLoginAttempts(attempts);
        if (locked) {
            admin.setLockedUntil(Instant.now().plus(Duration.ofMinutes(lockMinutes)));
        }
        admins.save(admin);

        record(admin, action, ip);
        if (locked) {
            record(admin, "ACCOUNT_LOCKED", ip);
        }

        return new Failure(attempts, locked, admin.getLockedUntil());
    }

    private void record(PlatformAdmin admin, String action, String ip) {
        audit.save(new PlatformAudit(
                UUID.randomUUID(),
                admin.getId(),
                admin.getEmail(),
                action,
                null,
                null,
                ip,
                Instant.now()));
    }

    /** Resultado de registrar un intento fallido. */
    public record Failure(int attempts, boolean locked, Instant lockedUntil) {
    }
}
