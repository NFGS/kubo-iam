package co.kubo.iam.application;

import java.net.URLEncoder;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Instant;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.stereotype.Service;

/**
 * Segundo factor TOTP (RFC 6238, P-30).
 *
 * Sin dependencias externas: HMAC-SHA1, 6 digitos y ventana de 30 segundos, que
 * es lo que entienden Google Authenticator, Authy y 1Password.
 *
 * La verificacion acepta **un paso antes y uno despues** para tolerar el
 * desfase de reloj del telefono, y no mas: cada paso extra multiplica las
 * oportunidades de un atacante con un codigo observado.
 */
@Service
public class TotpService {

    private static final String ALGORITHM = "HmacSHA1";
    private static final int SECRET_BYTES = 20;
    private static final int DIGITS = 6;
    private static final long PERIOD_SECONDS = 30;
    private static final int WINDOW_STEPS = 1;
    private static final String BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    private final SecureRandom random = new SecureRandom();

    /** Secreto nuevo en Base32 (sin relleno), como lo esperan las aplicaciones. */
    public String newSecret() {
        byte[] bytes = new byte[SECRET_BYTES];
        random.nextBytes(bytes);
        return base32Encode(bytes);
    }

    /** URI que la aplicacion autenticadora entiende (y que el QR representa). */
    public String otpauthUri(String email, String secret) {
        String label = URLEncoder.encode("Kubo:" + email, StandardCharsets.UTF_8);
        return "otpauth://totp/"
                + label
                + "?secret="
                + secret
                + "&issuer=Kubo&algorithm=SHA1&digits="
                + DIGITS
                + "&period="
                + PERIOD_SECONDS;
    }

    /** Codigo vigente en un instante dado (para pruebas y diagnostico). */
    public String codeAt(String secret, Instant instant) {
        long counter = instant.getEpochSecond() / PERIOD_SECONDS;
        byte[] hash = hmac(secret, counter);
        int offset = hash[hash.length - 1] & 0x0F;
        int binary = ((hash[offset] & 0x7F) << 24)
                | ((hash[offset + 1] & 0xFF) << 16)
                | ((hash[offset + 2] & 0xFF) << 8)
                | (hash[offset + 3] & 0xFF);
        int code = binary % (int) Math.pow(10, DIGITS);
        return String.format("%0" + DIGITS + "d", code);
    }

    /** Verifica el codigo en la ventana tolerada, en tiempo constante. */
    public boolean verify(String secret, String code, Instant now) {
        if (secret == null || code == null || !code.matches("\\d{6}")) {
            return false;
        }

        for (int step = -WINDOW_STEPS; step <= WINDOW_STEPS; step++) {
            Instant candidate = now.plusSeconds(step * PERIOD_SECONDS);
            if (constantTimeEquals(codeAt(secret, candidate), code)) {
                return true;
            }
        }
        return false;
    }

    private byte[] hmac(String secret, long counter) {
        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(new SecretKeySpec(base32Decode(secret), ALGORITHM));
            return mac.doFinal(ByteBuffer.allocate(Long.BYTES).putLong(counter).array());
        } catch (Exception exception) {
            throw new IllegalStateException("No fue posible calcular el codigo TOTP", exception);
        }
    }

    private boolean constantTimeEquals(String expected, String candidate) {
        if (expected.length() != candidate.length()) {
            return false;
        }
        int difference = 0;
        for (int index = 0; index < expected.length(); index++) {
            difference |= expected.charAt(index) ^ candidate.charAt(index);
        }
        return difference == 0;
    }

    // Base32 (RFC 4648) sin dependencias: solo lo que necesita el TOTP.

    private String base32Encode(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        int buffer = 0;
        int bitsLeft = 0;

        for (byte value : bytes) {
            buffer = (buffer << 8) | (value & 0xFF);
            bitsLeft += 8;
            while (bitsLeft >= 5) {
                result.append(BASE32_ALPHABET.charAt((buffer >> (bitsLeft - 5)) & 0x1F));
                bitsLeft -= 5;
            }
        }
        if (bitsLeft > 0) {
            result.append(BASE32_ALPHABET.charAt((buffer << (5 - bitsLeft)) & 0x1F));
        }
        return result.toString();
    }

    private byte[] base32Decode(String encoded) {
        String normalized = encoded.trim().replace("=", "").toUpperCase();
        int buffer = 0;
        int bitsLeft = 0;
        java.io.ByteArrayOutputStream output = new java.io.ByteArrayOutputStream();

        for (char character : normalized.toCharArray()) {
            int index = BASE32_ALPHABET.indexOf(character);
            if (index < 0) {
                throw new IllegalArgumentException("Secreto TOTP invalido");
            }
            buffer = (buffer << 5) | index;
            bitsLeft += 5;
            if (bitsLeft >= 8) {
                output.write((buffer >> (bitsLeft - 8)) & 0xFF);
                bitsLeft -= 8;
            }
        }
        return output.toByteArray();
    }
}
