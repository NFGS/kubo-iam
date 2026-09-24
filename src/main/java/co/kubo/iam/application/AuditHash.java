package co.kubo.iam.application;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;

/**
 * Algoritmo de hash de la cadena de auditoria, <b>versionado</b>.
 *
 * <p>Un cambio de algoritmo no puede dejar el historico sin verificar: cada fila declara con que
 * version se calculo su hash y el verificador aplica la regla correspondiente.
 *
 * <ul>
 *   <li><b>Version 1 (historica)</b>: se calculaba con el instante en nanosegundos, pero la
 *       columna solo guarda microsegundos, de modo que el hash no se puede recomputar. Estas
 *       filas se verifican <i>solo por enlace</i> (que encadenen con la anterior) y se reportan
 *       como no verificables por contenido.
 *   <li><b>Version 2 (vigente)</b>: el instante se trunca a microsegundos antes de calcular el
 *       hash, que es exactamente lo que devuelve la base de datos. La verificacion por contenido
 *       funciona.
 * </ul>
 */
public final class AuditHash {

    /** Version vigente del algoritmo. */
    public static final int CURRENT_VERSION = 2;

    private AuditHash() {
    }

    /** Indica si la version permite recomputar el hash a partir del contenido guardado. */
    public static boolean verifiableByContent(int version) {
        return version >= 2;
    }

    /**
     * Calcula el hash de una entrada con el algoritmo vigente (version 2).
     *
     * <p>El instante se trunca a microsegundos aqui dentro —la precision real de PostgreSQL—
     * para que el algoritmo sea autosuficiente: si dependiera de que el llamador truncara,
     * cualquier olvido produciria hashes imposibles de verificar.
     */
    public static String compute(String previous, String action, String entityId, Instant timestamp) {
        try {
            String payload = String.join(
                    "|",
                    previous,
                    action,
                    entityId == null ? "" : entityId,
                    timestamp.truncatedTo(ChronoUnit.MICROS).toString());
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(payload.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception exception) {
            throw new IllegalStateException("No fue posible calcular el hash de auditoria", exception);
        }
    }
}
