package co.kubo.iam.application;

import co.kubo.iam.domain.AuditLog;
import co.kubo.iam.domain.repository.AuditLogRepository;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
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

        // Se trunca a microsegundos porque es la precision de PostgreSQL: si se
        // guardara con nanosegundos, el valor leido de vuelta seria distinto y la
        // verificacion de la cadena fallaria siempre.
        Instant now = Instant.now().truncatedTo(ChronoUnit.MICROS);
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
     * Registra un evento que <b>debe sobrevivir</b> al fallo de la operacion.
     *
     * <p>Cuando un inicio de sesion falla, el servicio lanza una excepcion y su transaccion se
     * revierte: si la auditoria se escribiera en esa misma transaccion, el intento fallido
     * desapareceria de la bitacora — justo el evento que interesa para una investigacion. Esta
     * variante abre su propia transaccion, de modo que el registro queda aunque la operacion
     * de negocio falle.
     *
     * <p>Se usa solo en rutas de fallo: en las rutas exitosas la auditoria debe ser parte de la
     * misma transaccion, para que no existan registros de acciones que finalmente no ocurrieron.
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void recordIndependent(
            UUID tenantId,
            UUID userId,
            String action,
            String entity,
            String entityId,
            String ip,
            String userAgent) {
        record(tenantId, userId, action, entity, entityId, ip, userAgent);
    }

    /**
     * Verifica la integridad de una ventana de la bitacora.
     *
     * <p>Para cada entrada comprueba dos cosas: que enlace con la anterior (nadie borro ni
     * inserto un registro en medio) y que su hash corresponda al contenido (nadie edito la
     * accion ni el identificador). Una edicion parcial rompe la verificacion; para falsificar
     * la bitacora completa habria que recalcular toda la cadena.
     *
     * @param entriesOldestFirst entradas ordenadas de la mas antigua a la mas reciente
     */
    public boolean verifyChain(List<AuditLog> entriesOldestFirst) {
        for (int index = 0; index < entriesOldestFirst.size(); index++) {
            AuditLog entry = entriesOldestFirst.get(index);

            if (index > 0) {
                AuditLog previous = entriesOldestFirst.get(index - 1);
                if (!previous.getHash().equals(entry.getPrevHash())) {
                    return false;
                }
            }

            String expected = chainHash(
                    entry.getPrevHash(), entry.getAction(), entry.getEntityId(), entry.getCreatedAt());
            if (!expected.equals(entry.getHash())) {
                return false;
            }
        }
        return true;
    }

    /**
     * Verifica la ventana mas reciente de la bitacora.
     *
     * <p>Se limita a las ultimas entradas porque recorrer una bitacora de millones de filas en
     * una peticion HTTP no es razonable; la verificacion completa es un trabajo por lotes.
     * El resultado incluye el hash de la entrada mas antigua de la ventana para poder
     * encadenarlo con una verificacion anterior.
     */
    @Transactional(readOnly = true)
    public AuditVerification verifyLatestWindow() {
        List<AuditLog> oldestFirst = new ArrayList<>(repository.findTop50ByOrderByCreatedAtDesc());
        Collections.reverse(oldestFirst);

        return new AuditVerification(
                oldestFirst.size(),
                verifyChain(oldestFirst),
                oldestFirst.isEmpty() ? null : oldestFirst.get(0).getHash(),
                oldestFirst.isEmpty() ? null : oldestFirst.get(oldestFirst.size() - 1).getHash(),
                Instant.now().truncatedTo(ChronoUnit.MICROS));
    }

    /** Resultado de verificar la cadena de auditoria. */
    public record AuditVerification(
            int entriesChecked,
            boolean chainIntact,
            String oldestHash,
            String newestHash,
            Instant checkedAt) {
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
