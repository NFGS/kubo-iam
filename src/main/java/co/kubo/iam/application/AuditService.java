package co.kubo.iam.application;

import co.kubo.iam.domain.AuditLog;
import co.kubo.iam.domain.repository.AuditLogRepository;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
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
 *
 * <p><b>Algoritmo versionado (P-23):</b> el hash de cada fila declara su version. La version 2
 * es la vigente; las filas historicas (version 1, calculadas con nanosegundos) se verifican
 * solo por enlace y se reportan aparte.
 *
 * <p><b>Contexto de sistema:</b> la cadena es global (cruza negocios), de modo que este
 * servicio opera con la marca {@code app.system} activada. Con RLS habilitado, esa marca es
 * la que permite leer el ultimo hash de la cadena completa sin exponer datos de negocio.
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
        markSystemContext();

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
        String hash = AuditHash.compute(previous, action, entityId, now);

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
                AuditHash.CURRENT_VERSION,
                now));
    }

    @Transactional(readOnly = true)
    public List<AuditLog> latest() {
        markSystemContext();
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
     * Verifica la ventana mas reciente de la bitacora.
     *
     * <p>Para cada entrada comprueba dos cosas: que enlace con la anterior (nadie borro ni
     * inserto un registro en medio) y — si su version lo permite — que su hash corresponda al
     * contenido (nadie edito la accion ni el identificador). Las entradas de la version 1 no
     * son verificables por contenido y se informan aparte en {@code unverifiableEntries}.
     *
     * <p>Se limita a las ultimas entradas porque recorrer una bitacora de millones de filas en
     * una peticion HTTP no es razonable; la verificacion completa es un trabajo por lotes.
     * El resultado incluye el hash de la entrada mas antigua de la ventana para poder
     * encadenarlo con una verificacion anterior.
     */
    @Transactional(readOnly = true)
    public AuditVerification verifyLatestWindow() {
        markSystemContext();

        List<AuditLog> oldestFirst = new ArrayList<>(repository.findTop50ByOrderByCreatedAtDesc());
        Collections.reverse(oldestFirst);

        Map<Integer, Integer> versions = new TreeMap<>();
        int unverifiable = 0;
        boolean chainIntact = true;

        for (int index = 0; index < oldestFirst.size(); index++) {
            AuditLog entry = oldestFirst.get(index);
            versions.merge(entry.getHashVersion(), 1, Integer::sum);

            if (index > 0 && !oldestFirst.get(index - 1).getHash().equals(entry.getPrevHash())) {
                chainIntact = false;
            }

            if (AuditHash.verifiableByContent(entry.getHashVersion())) {
                String expected = AuditHash.compute(
                        entry.getPrevHash(), entry.getAction(), entry.getEntityId(), entry.getCreatedAt());
                if (!expected.equals(entry.getHash())) {
                    chainIntact = false;
                }
            } else {
                unverifiable++;
            }
        }

        return new AuditVerification(
                oldestFirst.size(),
                chainIntact,
                oldestFirst.isEmpty() ? null : oldestFirst.get(0).getHash(),
                oldestFirst.isEmpty() ? null : oldestFirst.get(oldestFirst.size() - 1).getHash(),
                Instant.now().truncatedTo(ChronoUnit.MICROS),
                versions,
                unverifiable);
    }

    /**
     * Resultado de verificar la cadena de auditoria.
     *
     * @param hashVersions cuantas entradas hay de cada version del algoritmo
     * @param unverifiableEntries entradas historicas que solo se pueden verificar por enlace
     */
    public record AuditVerification(
            int entriesChecked,
            boolean chainIntact,
            String oldestHash,
            String newestHash,
            Instant checkedAt,
            Map<Integer, Integer> hashVersions,
            int unverifiableEntries) {
    }

    /**
     * Marca la transaccion como operacion de sistema: la cadena de auditoria es global y su
     * lectura/escritura no puede quedar restringida a un negocio.
     */
    private void markSystemContext() {
        jdbcTemplate.execute("SET LOCAL app.system = 'on'");
    }

    private String truncate(String value, int max) {
        if (value == null) {
            return null;
        }
        return value.length() <= max ? value : value.substring(0, max);
    }
}
