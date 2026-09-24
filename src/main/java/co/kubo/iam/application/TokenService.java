package co.kubo.iam.application;

import co.kubo.iam.config.KuboProperties;
import co.kubo.iam.domain.User;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.annotation.PostConstruct;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HexFormat;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Emision y firma de tokens.
 *
 * <p>Los access tokens se firman con RSA (RS256) y se publican como JWKS, de modo que el API
 * Gateway verifica la firma con la llave publica y nunca conoce la llave privada. Los refresh
 * tokens son valores aleatorios de 384 bits que solo se guardan como hash SHA-256.
 */
@Service
public class TokenService {

    private static final Logger log = LoggerFactory.getLogger(TokenService.class);
    private static final int REFRESH_TOKEN_BYTES = 48;

    private final KuboProperties properties;
    private final SecureRandom random = new SecureRandom();
    private RSAKey rsaKey;
    private JWSSigner signer;

    public TokenService(KuboProperties properties) {
        this.properties = properties;
    }

    @PostConstruct
    public void init() {
        if (rsaKey != null) {
            return;
        }
        try {
            String pem = properties.jwt().privateKeyPem();
            if (pem != null && !pem.isBlank()) {
                rsaKey = fromPem(pem);
                log.info("JWT: llave RSA cargada desde KUBO_JWT_PRIVATE_KEY (kid={})", rsaKey.getKeyID());
            } else {
                rsaKey = new RSAKeyGenerator(2048).keyID("kubo-dev-ephemeral").generate();
                log.warn(
                        "JWT: llave RSA EFIMERA generada en memoria. Configure KUBO_JWT_PRIVATE_KEY "
                                + "en produccion para que los tokens sobrevivan reinicios.");
            }
            signer = new RSASSASigner(rsaKey);
        } catch (Exception exception) {
            throw new IllegalStateException("No fue posible inicializar la llave de firma JWT", exception);
        }
    }

    public String signAccessToken(User user) {
        try {
            Instant now = Instant.now();
            Instant expiration =
                    now.plus(Duration.ofMinutes(properties.jwt().accessTokenMinutes()));
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject(user.getId().toString())
                    .issuer(properties.jwt().issuer())
                    .audience(properties.jwt().audience())
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(expiration))
                    .jwtID(UUID.randomUUID().toString())
                    .claim("typ", "access")
                    .claim("email", user.getEmail())
                    .claim("name", user.getFullName())
                    .claim("role", user.getRole().name())
                    .claim("tenant_id", user.getTenant().getId().toString())
                    .claim("tenant", user.getTenant().getName())
                    // Zona horaria del negocio (ADR-0012): el gateway la
                    // propaga al ERP para que su dia comercial sea el correcto.
                    .claim("tenant_timezone", user.getTenant().getTimezone())
                    // Paquete de configuracion activo (ADR-0013, P-17).
                    .claim("tenant_vertical", user.getTenant().getVertical())
                    .build();

            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256)
                            .keyID(rsaKey.getKeyID())
                            .type(JOSEObjectType.JWT)
                            .build(),
                    claims);
            jwt.sign(signer);
            return jwt.serialize();
        } catch (Exception exception) {
            throw new IllegalStateException("No fue posible firmar el access token", exception);
        }
    }

    /**
     * Desafio del segundo factor (P-30): token firmado de 5 minutos con tipo
     * propio. El gateway solo acepta `typ=access`, de modo que este token no
     * sirve como credencial de API.
     */
    public String signTotpChallenge(User user) {
        try {
            Instant now = Instant.now();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject(user.getId().toString())
                    .issuer(properties.jwt().issuer())
                    .audience(properties.jwt().audience())
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plus(Duration.ofMinutes(5))))
                    .jwtID(UUID.randomUUID().toString())
                    .claim("typ", "totp")
                    .build();

            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256)
                            .keyID(rsaKey.getKeyID())
                            .type(JOSEObjectType.JWT)
                            .build(),
                    claims);
            jwt.sign(signer);
            return jwt.serialize();
        } catch (Exception exception) {
            throw new IllegalStateException("No fue posible firmar el desafio de segundo factor", exception);
        }
    }

    /** Devuelve el id del usuario del desafio, o lanza si no es valido. */
    public String verifyTotpChallenge(String token) {
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            JWSVerifier verifier = new RSASSAVerifier(rsaKey.toRSAPublicKey());

            if (!jwt.verify(verifier)
                    || !"totp".equals(jwt.getJWTClaimsSet().getStringClaim("typ"))
                    || !properties.jwt().issuer().equals(jwt.getJWTClaimsSet().getIssuer())
                    || jwt.getJWTClaimsSet().getExpirationTime().before(new Date())) {
                throw new IllegalArgumentException("desafio invalido");
            }

            return jwt.getJWTClaimsSet().getSubject();
        } catch (Exception exception) {
            throw DomainException.unauthorized(
                    "INVALID_CHALLENGE", "El desafio de verificacion no es valido o expiro");
        }
    }

    public String newRefreshToken() {
        return newSecureToken();
    }

    /** Valor aleatorio de 384 bits para cualquier credencial opaca (refresh o recuperacion). */
    public String newSecureToken() {
        byte[] bytes = new byte[REFRESH_TOKEN_BYTES];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public String hashToken(String rawToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(rawToken.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception exception) {
            throw new IllegalStateException("No fue posible calcular el hash del token", exception);
        }
    }

    /** Documento JWKS publico que consume el API Gateway. */
    public String jwks() {
        return new JWKSet(rsaKey.toPublicJWK()).toString();
    }

    public String keyId() {
        return rsaKey.getKeyID();
    }

    private RSAKey fromPem(String pem) throws Exception {
        String normalized = pem.replace("\\n", "\n");
        String base64 = normalized
                .replaceAll("-----BEGIN [A-Z ]+-----", "")
                .replaceAll("-----END [A-Z ]+-----", "")
                .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(base64);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPrivateCrtKey privateKey =
                (RSAPrivateCrtKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(der));
        RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(
                new RSAPublicKeySpec(privateKey.getModulus(), privateKey.getPublicExponent()));

        RSAKey key = new RSAKey.Builder(publicKey).privateKey(privateKey).build();
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(key.computeThumbprint().toString())
                .build();
    }
}
