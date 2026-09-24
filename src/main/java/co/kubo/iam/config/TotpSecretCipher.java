package co.kubo.iam.config;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.stereotype.Component;

/**
 * Cifrado del secreto TOTP en reposo (ADR-0015).
 *
 * El secreto es la llave para generar codigos validos: si la base de datos se
 * filtra, un secreto en claro convierte el segundo factor en decorativo. Se
 * cifra con AES-256-GCM (confidencialidad y deteccion de manipulacion) usando
 * una llave de configuracion que no vive en la base.
 *
 * Formato almacenado: base64( iv (12 bytes) | tag (16 bytes) | ciphertext ).
 */
@Component
public class TotpSecretCipher {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int IV_LENGTH = 12;
    private static final int TAG_LENGTH_BITS = 128;
    private static final int KEY_LENGTH_BYTES = 32;
    private static final String PLACEHOLDER_KEY = "0".repeat(64);

    private final SecureRandom random = new SecureRandom();
    private final byte[] key;

    public TotpSecretCipher(KuboProperties properties) {
        String configured = properties.totp().encryptionKey();
        this.key = parseKey(configured);
    }

    public String encrypt(String plaintext) {
        if (plaintext == null || plaintext.isBlank()) {
            return null;
        }
        try {
            byte[] iv = new byte[IV_LENGTH];
            random.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_LENGTH_BITS, iv));
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            byte[] payload = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, payload, 0, iv.length);
            System.arraycopy(ciphertext, 0, payload, iv.length, ciphertext.length);
            return Base64.getEncoder().encodeToString(payload);
        } catch (Exception exception) {
            throw new IllegalStateException("No fue posible cifrar el secreto TOTP", exception);
        }
    }

    public String decrypt(String payload) {
        if (payload == null || payload.isBlank()) {
            return null;
        }
        try {
            byte[] decoded = Base64.getDecoder().decode(payload);
            byte[] iv = java.util.Arrays.copyOfRange(decoded, 0, IV_LENGTH);
            byte[] ciphertext = java.util.Arrays.copyOfRange(decoded, IV_LENGTH, decoded.length);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_LENGTH_BITS, iv));
            return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
        } catch (Exception exception) {
            throw new IllegalStateException("No fue posible descifrar el secreto TOTP", exception);
        }
    }

    private byte[] parseKey(String configured) {
        if (configured == null || configured.isBlank() || PLACEHOLDER_KEY.equals(configured)) {
            throw new IllegalStateException(
                    "KUBO_TOTP_ENCRYPTION_KEY es obligatoria (64 hexadecimales): sin ella el segundo factor no protege nada");
        }

        byte[] parsed = hexToBytes(configured.trim());
        if (parsed.length != KEY_LENGTH_BYTES) {
            throw new IllegalStateException("KUBO_TOTP_ENCRYPTION_KEY debe tener 64 digitos hexadecimales");
        }
        return parsed;
    }

    private byte[] hexToBytes(String hex) {
        byte[] bytes = new byte[hex.length() / 2];
        for (int index = 0; index < bytes.length; index++) {
            bytes[index] = (byte) Integer.parseInt(hex.substring(index * 2, index * 2 + 2), 16);
        }
        return bytes;
    }
}
