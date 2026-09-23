package co.kubo.iam.application;

import co.kubo.iam.application.dto.AuthDtos.LoginRequest;
import co.kubo.iam.application.dto.AuthDtos.LogoutRequest;
import co.kubo.iam.application.dto.AuthDtos.RefreshRequest;
import co.kubo.iam.application.dto.AuthDtos.RegisterRequest;
import co.kubo.iam.application.dto.AuthDtos.TokenResponse;
import co.kubo.iam.application.dto.AuthDtos.UserResponse;
import co.kubo.iam.config.KuboProperties;
import co.kubo.iam.domain.RefreshToken;
import co.kubo.iam.domain.Tenant;
import co.kubo.iam.domain.User;
import co.kubo.iam.domain.UserRole;
import co.kubo.iam.domain.UserStatus;
import co.kubo.iam.domain.repository.RefreshTokenRepository;
import co.kubo.iam.domain.repository.TenantRepository;
import co.kubo.iam.domain.repository.UserRepository;
import java.text.Normalizer;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Casos de uso de identidad: registro, inicio de sesion, rotacion de tokens y consulta. */
@Service
public class AuthService {

    private final UserRepository users;
    private final TenantRepository tenants;
    private final RefreshTokenRepository refreshTokens;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;
    private final AuditService auditService;
    private final KuboProperties properties;

    public AuthService(
            UserRepository users,
            TenantRepository tenants,
            RefreshTokenRepository refreshTokens,
            PasswordEncoder passwordEncoder,
            TokenService tokenService,
            AuditService auditService,
            KuboProperties properties) {
        this.users = users;
        this.tenants = tenants;
        this.refreshTokens = refreshTokens;
        this.passwordEncoder = passwordEncoder;
        this.tokenService = tokenService;
        this.auditService = auditService;
        this.properties = properties;
    }

    @Transactional
    public TokenResponse register(RegisterRequest request, String ip, String userAgent) {
        String email = request.email().trim().toLowerCase(Locale.ROOT);
        if (users.existsByEmailIgnoreCase(email)) {
            throw DomainException.conflict("EMAIL_ALREADY_EXISTS", "El correo ya esta registrado");
        }

        Instant now = Instant.now();
        Tenant tenant = tenants.save(new Tenant(
                UUID.randomUUID(),
                request.tenantName().trim(),
                uniqueSlug(request.tenantName()),
                "community",
                now));

        User user = users.save(new User(
                UUID.randomUUID(),
                tenant,
                email,
                passwordEncoder.encode(request.password()),
                request.fullName().trim(),
                UserRole.OWNER,
                UserStatus.ACTIVE,
                now));

        auditService.record(
                tenant.getId(), user.getId(), "USER_REGISTERED", "user", user.getId().toString(), ip, userAgent);

        return issueTokens(user);
    }

    @Transactional
    public TokenResponse login(LoginRequest request, String ip, String userAgent) {
        String email = request.email().trim().toLowerCase(Locale.ROOT);
        User user = users.findByEmailIgnoreCase(email)
                .orElseThrow(() -> DomainException.unauthorized(
                        "INVALID_CREDENTIALS", "Correo o contrasena incorrectos"));

        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            auditService.record(
                    user.getTenant().getId(), user.getId(), "LOGIN_FAILED", "user", user.getId().toString(), ip, userAgent);
            throw DomainException.unauthorized(
                    "INVALID_CREDENTIALS", "Correo o contrasena incorrectos");
        }

        if (user.getStatus() != UserStatus.ACTIVE) {
            throw DomainException.unauthorized("USER_DISABLED", "El usuario esta deshabilitado");
        }

        user.setLastLoginAt(Instant.now());
        users.save(user);
        auditService.record(
                user.getTenant().getId(), user.getId(), "LOGIN_SUCCEEDED", "user", user.getId().toString(), ip, userAgent);

        return issueTokens(user);
    }

    @Transactional
    public TokenResponse refresh(RefreshRequest request, String ip, String userAgent) {
        String hash = tokenService.hashToken(request.refreshToken());
        RefreshToken stored = refreshTokens.findByTokenHash(hash)
                .orElseThrow(() -> DomainException.unauthorized(
                        "INVALID_REFRESH_TOKEN", "El token de refresco no es valido"));

        if (stored.getRevokedAt() != null) {
            // Reutilizacion de un token ya rotado: se invalida la familia completa.
            refreshTokens.revokeAllByUserId(stored.getUserId(), Instant.now());
            auditService.record(
                    null, stored.getUserId(), "REFRESH_REUSE_DETECTED", "refresh_token", stored.getId().toString(), ip, userAgent);
            throw DomainException.unauthorized(
                    "REFRESH_TOKEN_REUSED", "Se detecto reutilizacion de un token; sesiones cerradas");
        }

        if (stored.getExpiresAt().isBefore(Instant.now())) {
            throw DomainException.unauthorized("REFRESH_TOKEN_EXPIRED", "El token de refresco expiro");
        }

        User user = users.findById(stored.getUserId())
                .orElseThrow(() -> DomainException.unauthorized(
                        "INVALID_REFRESH_TOKEN", "El token de refresco no es valido"));

        String accessToken = tokenService.signAccessToken(user);
        String rawRefresh = tokenService.newRefreshToken();
        RefreshToken replacement = refreshTokens.save(new RefreshToken(
                UUID.randomUUID(),
                user.getId(),
                tokenService.hashToken(rawRefresh),
                Instant.now().plus(Duration.ofDays(properties.jwt().refreshTokenDays())),
                Instant.now()));
        stored.revoke(replacement.getId());
        refreshTokens.save(stored);

        auditService.record(
                user.getTenant().getId(), user.getId(), "TOKEN_REFRESHED", "user", user.getId().toString(), ip, userAgent);

        return new TokenResponse(
                accessToken,
                rawRefresh,
                "Bearer",
                properties.jwt().accessTokenMinutes() * 60L,
                toResponse(user));
    }

    @Transactional
    public void logout(LogoutRequest request) {
        refreshTokens.findByTokenHash(tokenService.hashToken(request.refreshToken()))
                .ifPresent(token -> {
                    token.revoke(null);
                    refreshTokens.save(token);
                });
    }

    @Transactional(readOnly = true)
    public UserResponse me(String userId) {
        User user = users.findById(parseUuid(userId, "USER_NOT_FOUND"))
                .orElseThrow(() -> DomainException.notFound("USER_NOT_FOUND", "Usuario no encontrado"));
        return toResponse(user);
    }

    @Transactional(readOnly = true)
    public Page<UserResponse> listUsersOfTenant(String userId, int page, int size) {
        User user = users.findById(parseUuid(userId, "USER_NOT_FOUND"))
                .orElseThrow(() -> DomainException.notFound("USER_NOT_FOUND", "Usuario no encontrado"));

        // El tamano de pagina se acota en el servidor: un cliente no puede pedir
        // la tabla completa ni forzar una consulta desmedida.
        int safeSize = Math.min(Math.max(size, 1), 100);
        int safePage = Math.max(page, 0);

        return users.findByTenantId(user.getTenant().getId(), PageRequest.of(safePage, safeSize))
                .map(this::toResponse);
    }

    private TokenResponse issueTokens(User user) {
        String accessToken = tokenService.signAccessToken(user);
        String rawRefresh = tokenService.newRefreshToken();
        refreshTokens.save(new RefreshToken(
                UUID.randomUUID(),
                user.getId(),
                tokenService.hashToken(rawRefresh),
                Instant.now().plus(Duration.ofDays(properties.jwt().refreshTokenDays())),
                Instant.now()));

        return new TokenResponse(
                accessToken,
                rawRefresh,
                "Bearer",
                properties.jwt().accessTokenMinutes() * 60L,
                toResponse(user));
    }

    private UserResponse toResponse(User user) {
        return new UserResponse(
                user.getId().toString(),
                user.getEmail(),
                user.getFullName(),
                user.getRole().name(),
                user.getTenant().getId().toString(),
                user.getTenant().getName());
    }

    private UUID parseUuid(String value, String errorCode) {
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException exception) {
            throw DomainException.unauthorized(errorCode, "Identidad invalida");
        }
    }

    private String uniqueSlug(String name) {
        String base = Normalizer.normalize(name, Normalizer.Form.NFD)
                .replaceAll("\\p{M}", "")
                .toLowerCase(Locale.ROOT)
                .replaceAll("[^a-z0-9]+", "-")
                .replaceAll("(^-+|-+$)", "");
        if (base.isBlank()) {
            base = "negocio";
        }
        if (base.length() > 60) {
            base = base.substring(0, 60);
        }
        String candidate = base;
        int suffix = 1;
        while (tenants.existsBySlug(candidate)) {
            candidate = base + "-" + suffix++;
        }
        return candidate;
    }
}
