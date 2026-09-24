package co.kubo.iam.application;

import co.kubo.iam.application.dto.AuthDtos.CreateUserRequest;
import co.kubo.iam.application.dto.AuthDtos.LoginRequest;
import co.kubo.iam.application.dto.AuthDtos.LogoutRequest;
import co.kubo.iam.application.dto.AuthDtos.UpdateUserRequest;
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
    private final SecurityIncidentService securityIncidents;
    private final KuboProperties properties;

    public AuthService(
            UserRepository users,
            TenantRepository tenants,
            RefreshTokenRepository refreshTokens,
            PasswordEncoder passwordEncoder,
            TokenService tokenService,
            AuditService auditService,
            SecurityIncidentService securityIncidents,
            KuboProperties properties) {
        this.users = users;
        this.tenants = tenants;
        this.refreshTokens = refreshTokens;
        this.passwordEncoder = passwordEncoder;
        this.tokenService = tokenService;
        this.auditService = auditService;
        this.securityIncidents = securityIncidents;
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

        if (user.getLockedUntil() != null && user.getLockedUntil().isAfter(Instant.now())) {
            auditService.recordIndependent(
                    user.getTenant().getId(), user.getId(), "LOGIN_BLOCKED", "user", user.getId().toString(), ip, userAgent);
            throw DomainException.unauthorized(
                    "ACCOUNT_LOCKED", "La cuenta esta bloqueada temporalmente por intentos fallidos");
        }

        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            // En transaccion aparte: el contador y el bloqueo deben sobrevivir al
            // rollback de este login, que termina en excepcion.
            SecurityIncidentService.LoginFailure failure = securityIncidents.registerLoginFailure(
                    user.getId(),
                    ip,
                    userAgent,
                    properties.auth().maxFailedAttempts(),
                    properties.auth().lockMinutes());

            if (failure.locked()) {
                throw DomainException.unauthorized(
                        "ACCOUNT_LOCKED", "La cuenta quedo bloqueada temporalmente por intentos fallidos");
            }
            throw DomainException.unauthorized(
                    "INVALID_CREDENTIALS", "Correo o contrasena incorrectos");
        }

        if (user.getStatus() != UserStatus.ACTIVE) {
            throw DomainException.unauthorized("USER_DISABLED", "El usuario esta deshabilitado");
        }

        // Acceso correcto: se limpia el contador de intentos y cualquier bloqueo vigente.
        user.setLastLoginAt(Instant.now());
        user.setFailedLoginAttempts(0);
        user.setLockedUntil(null);
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
            // Reutilizacion de un token ya rotado: se invalida la familia completa y
            // se deja constancia. Ambas cosas en una transaccion independiente, porque
            // este camino termina en excepcion y de otro modo se revertirian.
            securityIncidents.registerRefreshReuse(
                    stored.getUserId(), stored.getId(), ip, userAgent);
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

    /**
     * Crea un usuario dentro del negocio del actor (P-20).
     *
     * <p>El correo se comprueba primero dentro del negocio (la consulta corre con el contexto de
     * RLS del tenant) y, ademas, el indice unico global lo garantiza en el motor: si otro negocio
     * ya lo usa, la violacion se traduce a 409.
     */
    @Transactional
    public UserResponse createUser(String actorId, CreateUserRequest request) {
        User actor = users.findById(parseUuid(actorId, "USER_NOT_FOUND"))
                .orElseThrow(() -> DomainException.notFound("USER_NOT_FOUND", "Usuario no encontrado"));

        String email = request.email().trim().toLowerCase(Locale.ROOT);
        if (users.existsByEmailIgnoreCase(email)) {
            throw DomainException.conflict("EMAIL_ALREADY_EXISTS", "El correo ya esta registrado");
        }

        User user = users.save(new User(
                UUID.randomUUID(),
                actor.getTenant(),
                email,
                passwordEncoder.encode(request.password()),
                request.fullName().trim(),
                parseRole(request.role()),
                UserStatus.ACTIVE,
                Instant.now()));

        auditService.record(
                actor.getTenant().getId(), user.getId(), "USER_CREATED", "user", user.getId().toString(), null, null);

        return toResponse(user);
    }

    /** Actualiza nombre, rol o estado de un usuario del mismo negocio (P-20). */
    @Transactional
    public UserResponse updateUser(String actorId, String targetId, UpdateUserRequest request) {
        User actor = users.findById(parseUuid(actorId, "USER_NOT_FOUND"))
                .orElseThrow(() -> DomainException.notFound("USER_NOT_FOUND", "Usuario no encontrado"));

        User target = users.findById(parseUuid(targetId, "USER_NOT_FOUND"))
                .orElseThrow(() -> DomainException.notFound("USER_NOT_FOUND", "Usuario no encontrado"));

        if (request.fullName() != null && !request.fullName().isBlank()) {
            target.setFullName(request.fullName().trim());
        }
        if (request.role() != null && !request.role().isBlank()) {
            target.setRole(parseRole(request.role()));
        }
        if (request.status() != null && !request.status().isBlank()) {
            target.setStatus(parseStatus(request.status()));
        }

        users.save(target);
        auditService.record(
                actor.getTenant().getId(), target.getId(), "USER_UPDATED", "user", target.getId().toString(), null, null);

        return toResponse(target);
    }

    private UserRole parseRole(String value) {
        try {
            return UserRole.valueOf(value.trim().toUpperCase(Locale.ROOT));
        } catch (Exception exception) {
            throw DomainException.badRequest("INVALID_ROLE", "El rol indicado no es valido");
        }
    }

    private UserStatus parseStatus(String value) {
        try {
            return UserStatus.valueOf(value.trim().toUpperCase(Locale.ROOT));
        } catch (Exception exception) {
            throw DomainException.badRequest("INVALID_STATUS", "El estado indicado no es valido");
        }
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
                user.getStatus().name(),
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
