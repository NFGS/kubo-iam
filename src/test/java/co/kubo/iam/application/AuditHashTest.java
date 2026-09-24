package co.kubo.iam.application;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import org.junit.jupiter.api.Test;

/**
 * Pruebas del algoritmo versionado de la cadena de auditoria (P-23).
 *
 * <p>Lo importante: el hash es determinista para el mismo contenido, cambia si cambia
 * cualquier campo y la version vigente es verificable por contenido.
 */
class AuditHashTest {

    private final Instant timestamp = Instant.parse("2026-09-23T12:00:00.123456Z");

    @Test
    void elHashEsDeterministaParaElMismoContenido() {
        String first = AuditHash.compute("GENESIS", "LOGIN_SUCCEEDED", "user-1", timestamp);
        String second = AuditHash.compute("GENESIS", "LOGIN_SUCCEEDED", "user-1", timestamp);

        assertThat(first).isEqualTo(second).hasSize(64);
    }

    @Test
    void cambiarLaAccionOElEnlaceCambiaElHash() {
        String base = AuditHash.compute("GENESIS", "LOGIN_SUCCEEDED", "user-1", timestamp);

        assertThat(AuditHash.compute("GENESIS", "LOGIN_FAILED", "user-1", timestamp))
                .isNotEqualTo(base);
        assertThat(AuditHash.compute("OTRO", "LOGIN_SUCCEEDED", "user-1", timestamp))
                .isNotEqualTo(base);
        assertThat(AuditHash.compute("GENESIS", "LOGIN_SUCCEEDED", null, timestamp))
                .isNotEqualTo(base);
    }

    @Test
    void elInstanteSeTruncaAMicrosegundosAntesDeHashear() {
        Instant conNanosegundos = timestamp.plusNanos(987);
        Instant truncado = conNanosegundos.truncatedTo(ChronoUnit.MICROS);

        assertThat(AuditHash.compute("GENESIS", "LOGIN_SUCCEEDED", "user-1", conNanosegundos))
                .isEqualTo(AuditHash.compute("GENESIS", "LOGIN_SUCCEEDED", "user-1", truncado));
    }

    @Test
    void laVersionVigenteEsVerificableYLaHistoricaNo() {
        assertThat(AuditHash.verifiableByContent(AuditHash.CURRENT_VERSION)).isTrue();
        assertThat(AuditHash.verifiableByContent(1)).isFalse();
        assertThat(AuditHash.CURRENT_VERSION).isEqualTo(2);
    }
}
