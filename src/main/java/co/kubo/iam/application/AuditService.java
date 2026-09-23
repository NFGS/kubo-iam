package co.kubo.iam.application;

import co.kubo.iam.domain.AuditLog;
import co.kubo.iam.domain.repository.AuditLogRepository;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Bitacora de auditoria con cadena de hash.
 *
 * <p>Cada entrada incluye el hash de la anterior. Verificar la cadena permite detectar
 * manipulaciones posteriores de la base de datos.
 *
 * <p><b>Serializacion:</b> la lectura del ultimo hash y la insercion del nuevo deben ser
 * atomicas. Sin un bloqueo, dos peticiones concurrentes leerian el mismo hash anterior y la
 * cadena quedaria partida (dos entradas apuntando al mismo predecesor), lo que romperia la
 * deteccion de manipulacion. Se usa un <i>advisory lock</i> de transaccion de PostgreSQL:
 * se libera solo al terminar la transaccion y no bloquea ninguna tabla.
 */
@Service
public class AuditService {

    /** Identificador arbitrario y estable de la cadena de auditoria. */
    private static final long CHAIN_LOCK_KEY = 0x4B55424FL; // "KUBO"

    private final AuditLogRepository repository;
    private final JdbcTemplate jdbcTemplate;

    public AuditService(AuditLogRepository repository, JdbcTemplate jdbcTemplate) {
        this.repository = repository;
        this.jdbcTemplate = jdbcTemplate;
    }

    @Transactional
    public void record(
            UUID tenantId,
            UUID userId,
            String action,
            String entity,
            String entityId,
            String ip,
            String userAgent) {
        // `pg_advisory_xact_lock` devuelve void, asi que se envuelve en una
        // consulta que si devuelve una fila: mapear void a un tipo Java falla.
        jdbcTemplate.queryForObject(
                "select 1 from (select pg_advisory_xact_lock(?)) as bloqueo",
                Integer.class,
                CHAIN_LOCK_KEY);

        Instant now = Instant.now();
        String previous = repository.findTopByOrderByCreatedAtDesc()
                .map(AuditLog::getHash)
                .orElse("GENESIS");
        String hash = chainHash(previous, action, entityId, now);
        repository.save(new AuditLog(
                UUID.randomUUID(),
                tenantId,
                userId,
                action,
                entity,
                entityId,
                truncate(ip, 60),
                truncate(userAgent, 240),
                previous,
                hash,
                now));
    }

    public List<AuditLog> latest() {
        return repository.findTop50ByOrderByCreatedAtDesc();
    }

    /**
     * Verifica que cada entrada encadene con la anterior.
     *
     * @param entriesOldestFirst entradas ordenadas de la mas antigua a la mas reciente
     */
    public boolean verifyChain(List<AuditLog> entriesOldestFirst) {
        String expected = "GENESIS";
        for (AuditLog entry : entriesOldestFirst) {
            if (!expected.equals(entry.getPrevHash())) {
                return false;
            }
            expected = entry.getHash();
        }
        return true;
    }

    private String chainHash(String previous, String action, String entityId, Instant timestamp) {
        try {
            String payload = String.join("|",
                    previous,
                    action,
                    entityId == null ? "" : entityId,
                    timestamp.toString());
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(payload.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception exception) {
            throw new IllegalStateException("No fue posible calcular el hash de auditoria", exception);
        }
    }

    private String truncate(String value, int max) {
        if (value == null) {
            return null;
        }
        return value.length() <= max ? value : value.substring(0, max);
    }
}
