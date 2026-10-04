package co.kubo.iam.application;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class NitDvTest {

    @Test
    @DisplayName("El DV coincide con el algoritmo oficial (casos reales)")
    void casosConocidos() {
        // Bancolombia 890903938-8, verificado con el algoritmo de la DIAN.
        assertThat(NitDv.calcular("890903938")).isEqualTo("8");
        assertThat(NitDv.calcular("900123456")).isEqualTo("8");
    }

    @Test
    @DisplayName("Un NIT no numerico o vacio no tiene DV")
    void entradasInvalidas() {
        assertThat(NitDv.calcular(null)).isNull();
        assertThat(NitDv.calcular("")).isNull();
        assertThat(NitDv.calcular("900-123")).isNull();
        assertThat(NitDv.calcular("ABC")).isNull();
    }
}
