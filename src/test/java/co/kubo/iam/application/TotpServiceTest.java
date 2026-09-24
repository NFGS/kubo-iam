package co.kubo.iam.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import co.kubo.iam.config.KuboProperties;
import co.kubo.iam.config.TotpSecretCipher;
import java.time.Instant;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Segundo factor TOTP (P-30). Los vectores vienen del RFC 6238 (apendice B,
 * SHA-1) para no probar la implementacion contra si misma.
 */
class TotpServiceTest {

    private static final String RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    private final TotpService totp = new TotpService();

    @Test
    @DisplayName("Los codigos coinciden con los vectores del RFC 6238")
    void vectoresDelRfc() {
        assertThat(totp.codeAt(RFC_SECRET, Instant.ofEpochSecond(59))).isEqualTo("287082");
        assertThat(totp.codeAt(RFC_SECRET, Instant.ofEpochSecond(1111111109))).isEqualTo("081804");
        assertThat(totp.codeAt(RFC_SECRET, Instant.ofEpochSecond(1234567890))).isEqualTo("005924");
    }

    @Test
    @DisplayName("La verificacion tolera un paso de desfase y nada mas")
    void ventanaDeTolerancia() {
        Instant ahora = Instant.ofEpochSecond(1111111111);
        String codigo = totp.codeAt(RFC_SECRET, ahora);

        assertThat(totp.verify(RFC_SECRET, codigo, ahora.plusSeconds(30))).isTrue();
        assertThat(totp.verify(RFC_SECRET, codigo, ahora.minusSeconds(30))).isTrue();
        assertThat(totp.verify(RFC_SECRET, codigo, ahora.plusSeconds(90))).isFalse();
        assertThat(totp.verify(RFC_SECRET, "000000", ahora)).isFalse();
        assertThat(totp.verify(RFC_SECRET, "no-es-codigo", ahora)).isFalse();
        assertThat(totp.verify(null, codigo, ahora)).isFalse();
    }

    @Test
    @DisplayName("Un secreto con caracteres invalidos no produce codigo")
    void secretoInvalido() {
        assertThatThrownBy(() -> totp.codeAt("SECRETO-INVALIDO-1", Instant.now()))
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    @DisplayName("El secreto y la URI son los que espera la aplicacion autenticadora")
    void secretoYUri() {
        String secreto = totp.newSecret();

        assertThat(secreto).hasSize(32).matches("[A-Z2-7]+");
        assertThat(totp.otpauthUri("admin@kubo.local", secreto))
                .startsWith("otpauth://totp/")
                .contains("secret=" + secreto)
                .contains("issuer=Kubo")
                .contains("digits=6");
    }

    @Test
    @DisplayName("El secreto se cifra en reposo y la llave marcador se rechaza")
    void cifradoDelSecreto() {
        KuboProperties properties = propertiesCon("a".repeat(64));
        TotpSecretCipher cipher = new TotpSecretCipher(properties);

        String cifrado = cipher.encrypt("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");

        assertThat(cifrado).doesNotContain("GEZDGNBVGY3TQOJQ");
        assertThat(cipher.decrypt(cifrado)).isEqualTo("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assertThat(cipher.decrypt(null)).isNull();
        assertThat(cipher.encrypt(null)).isNull();

        assertThatThrownBy(() -> new TotpSecretCipher(propertiesCon("0".repeat(64))))
                .isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new TotpSecretCipher(propertiesCon("")))
                .isInstanceOf(IllegalStateException.class);
    }

    private KuboProperties propertiesCon(String clave) {
        return new KuboProperties(
                new KuboProperties.Jwt("kubo-iam", "kubo-api", 15, 7, ""),
                new KuboProperties.Seed(false, "admin@kubo.local", "Admin123!", "Tienda"),
                new KuboProperties.Auth(5, 15, 30),
                new KuboProperties.Mail("log", "no-responder@kubo.local", "http://localhost/reset", "", 587, "", "", true),
                new KuboProperties.Totp(clave));
    }
}
