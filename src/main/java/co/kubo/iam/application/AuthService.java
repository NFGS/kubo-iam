package co.kubo.iam.application;

import co.kubo.iam.application.dto.AuthDtos.CreateUserRequest;
import co.kubo.iam.application.dto.AuthDtos.LoginRequest;
import co.kubo.iam.application.dto.AuthDtos.LoginResult;
import co.kubo.iam.application.dto.AuthDtos.TotpChallengeResponse;
import co.kubo.iam.application.dto.AuthDtos.TotpSetupResponse;
import co.kubo.iam.application.dto.AuthDtos.TotpVerifyRequest;
import co.kubo.iam.application.dto.AuthDtos.LogoutRequest;
import co.kubo.iam.application.dto.AuthDtos.UpdateUserRequest;
import co.kubo.iam.application.dto.AuthDtos.RefreshRequest;
import co.kubo.iam.application.dto.AuthDtos.RegisterRequest;
import co.kubo.iam.application.dto.AuthDtos.TenantResponse;
import co.kubo.iam.application.dto.AuthDtos.TokenResponse;
import co.kubo.iam.application.dto.AuthDtos.UpdateTenantRequest;
import co.kubo.iam.application.dto.AuthDtos.UserResponse;
import co.kubo.iam.config.KuboProperties;
import co.kubo.iam.config.TotpSecretCipher;
import co.kubo.iam.domain.Plan;
import co.kubo.iam.domain.RefreshToken;
import co.kubo.iam.domain.Tenant;
import co.kubo.iam.domain.User;
import co.kubo.iam.domain.UserRole;
import co.kubo.iam.domain.UserStatus;
import co.kubo.iam.domain.repository.RefreshTokenRepository;
import co.kubo.iam.domain.repository.TenantRepository;
import co.kubo.iam.domain.repository.UserRepository;
import java.text.Normalizer;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Set;
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
    private final TotpService totpService;
    private final TotpSecretCipher totpCipher;
    private final KuboProperties properties;

    public AuthService(
            UserRepository users,
            TenantRepository tenants,
            RefreshTokenRepository refreshTokens,
            PasswordEncoder passwordEncoder,
            TokenService tokenService,
            AuditService auditService,
            SecurityIncidentService securityIncidents,
            KuboProperties properties,
            TotpService totpService,
            TotpSecretCipher totpCipher) {
        this.users = users;
        this.tenants = tenants;
        this.refreshTokens = refreshTokens;
        this.passwordEncoder = passwordEncoder;
        this.tokenService = tokenService;
        this.auditService = auditService;
        this.securityIncidents = securityIncidents;
        this.totpService = totpService;
        this.totpCipher = totpCipher;
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
                // Zona horaria por defecto del negocio nuevo (ADR-0012).
                "America/Bogota",
                "retail",
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
    public LoginResult login(LoginRequest request, String ip, String userAgent) {
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

        // Negocio suspendido (ADR-0021): la contrasena es correcta, pero la
        // relacion comercial no; sus datos siguen intactos y exportables.
        if (user.getTenant().isSuspended()) {
            auditService.record(
                    user.getTenant().getId(), user.getId(), "TENANT_SUSPENDED", "tenant",
                    user.getTenant().getId().toString(), ip, userAgent);
            throw DomainException.forbidden(
                    "TENANT_SUSPENDED", "El negocio esta suspendido; contacte al operador");
        }

        // Con el segundo factor activo, la contrasena correcta solo abre el
        // desafio: la sesion se emite cuando el codigo TOTP es valido (P-30).
        if (user.isTotpEnabled()) {
            auditService.record(
                    user.getTenant().getId(), user.getId(), "TOTP_CHALLENGED", "user", user.getId().toString(), ip, userAgent);
            return new LoginResult.Totp(
                    new TotpChallengeResponse(true, tokenService.signTotpChallenge(user)));
        }

        return new LoginResult.Tokens(completeLogin(user, ip, userAgent));
    }

    /** Cierre comun de un acceso correcto (con o sin segundo factor). */
    private TokenResponse completeLogin(User user, String ip, String userAgent) {
        user.setLastLoginAt(Instant.now());
        user.setFailedLoginAttempts(0);
        user.setLockedUntil(null);
        users.save(user);
        auditService.record(
                user.getTenant().getId(), user.getId(), "LOGIN_SUCCEEDED", "user", user.getId().toString(), ip, userAgent);

        return issueTokens(user);
    }

    /** Genera (o regenera) el secreto TOTP; queda pendiente de confirmar. */
    public TotpSetupResponse totpSetup(String actorId) {
        User user = requireUser(actorId);
        String secret = totpService.newSecret();

        user.setTotpSecret(totpCipher.encrypt(secret));
        user.setTotpEnabled(false);
        users.save(user);

        return new TotpSetupResponse(secret, totpService.otpauthUri(user.getEmail(), secret));
    }

    /** Activa el segundo factor: el primer codigo demuestra que el secreto quedo bien. */
    public UserResponse totpEnable(String actorId, String code) {
        User user = requireUser(actorId);

        if (user.getTotpSecret() == null) {
            throw DomainException.badRequest(
                    "TOTP_NOT_SETUP", "Primero genera el secreto del segundo factor");
        }

        if (!totpService.verify(totpCipher.decrypt(user.getTotpSecret()), code, Instant.now())) {
            throw DomainException.unauthorized("INVALID_TOTP", "El codigo de verificacion no es valido");
        }

        user.setTotpEnabled(true);
        users.save(user);
        auditService.record(
                user.getTenant().getId(), user.getId(), "TOTP_ENABLED", "user", user.getId().toString(), null, null);

        return toResponse(user);
    }

    /** Desactiva el segundo factor; exige un codigo vigente. */
    public UserResponse totpDisable(String actorId, String code) {
        User user = requireUser(actorId);

        if (!user.isTotpEnabled()) {
            throw DomainException.badRequest("TOTP_NOT_ENABLED", "El segundo factor no esta activo");
        }

        if (!totpService.verify(totpCipher.decrypt(user.getTotpSecret()), code, Instant.now())) {
            throw DomainException.unauthorized("INVALID_TOTP", "El codigo de verificacion no es valido");
        }

        user.setTotpEnabled(false);
        user.setTotpSecret(null);
        users.save(user);
        auditService.record(
                user.getTenant().getId(), user.getId(), "TOTP_DISABLED", "user", user.getId().toString(), null, null);

        return toResponse(user);
    }

    /** Segundo paso del acceso: valida el desafio y el codigo, y emite la sesion. */
    public TokenResponse verifyTotp(TotpVerifyRequest request, String ip, String userAgent) {
        String userId = tokenService.verifyTotpChallenge(request.challengeToken());
        User user = users.findById(parseUuid(userId, "INVALID_CHALLENGE"))
                .orElseThrow(() -> DomainException.unauthorized(
                        "INVALID_CHALLENGE", "El desafio de verificacion no es valido"));

        if (user.getLockedUntil() != null && user.getLockedUntil().isAfter(Instant.now())) {
            auditService.recordIndependent(
                    user.getTenant().getId(), user.getId(), "LOGIN_BLOCKED", "user", user.getId().toString(), ip, userAgent);
            throw DomainException.unauthorized(
                    "ACCOUNT_LOCKED", "La cuenta esta bloqueada temporalmente por intentos fallidos");
        }

        if (!user.isTotpEnabled()
                || !totpService.verify(totpCipher.decrypt(user.getTotpSecret()), request.code(), Instant.now())) {
            // El codigo de seis digitos no puede ser la puerta sin freno de la
            // fuerza bruta: comparte el contador y el bloqueo de la contrasena
            // (P-11), en una transaccion que sobrevive al rechazo.
            SecurityIncidentService.LoginFailure failure = securityIncidents.registerLoginFailure(
                    user.getId(), ip, userAgent,
                    properties.auth().maxFailedAttempts(), properties.auth().lockMinutes());

            if (failure.locked()) {
                throw DomainException.unauthorized(
                        "ACCOUNT_LOCKED", "La cuenta quedo bloqueada temporalmente por intentos fallidos");
            }
            throw DomainException.unauthorized("INVALID_TOTP", "El codigo de verificacion no es valido");
        }

        return completeLogin(user, ip, userAgent);
    }

    private User requireUser(String actorId) {
        return users.findById(parseUuid(actorId, "USER_NOT_FOUND"))
                .orElseThrow(() -> DomainException.notFound("USER_NOT_FOUND", "Usuario no encontrado"));
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

        // Renovar no es un camino lateral: la sesion no sobrevive a la
        // deshabilitacion del usuario ni a la suspension del negocio (ADR-0021).
        if (user.getStatus() != UserStatus.ACTIVE) {
            throw DomainException.unauthorized("USER_DISABLED", "El usuario esta deshabilitado");
        }

        if (user.getTenant().isSuspended()) {
            auditService.recordIndependent(
                    user.getTenant().getId(), user.getId(), "TENANT_SUSPENDED", "tenant",
                    user.getTenant().getId().toString(), ip, userAgent);
            throw DomainException.forbidden(
                    "TENANT_SUSPENDED", "El negocio esta suspendido; contacte al operador");
        }

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

        // Cupo del plan (ADR-0021): se avisa con el limite y el uso, nunca
        // borrando datos. Los deshabilitados no ocupan asiento.
        Plan plan = Plan.byCodeOrDefault(actor.getTenant().getPlan());
        long activos = users.countByTenantIdAndStatus(actor.getTenant().getId(), UserStatus.ACTIVE);

        if (activos >= plan.maxUsers()) {
            throw DomainException.conflict(
                    "PLAN_LIMIT_REACHED",
                    "El plan " + plan.code() + " permite " + plan.maxUsers()
                            + " usuarios activos y el negocio ya tiene " + activos);
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

        // Un administrador no puede quitarse a si mismo el rol ni deshabilitarse:
        // dejaria al negocio sin quien gestione usuarios y sin ruta de recuperacion
        // dentro del producto. Otro administrador si puede hacerlo.
        boolean isSelf = target.getId().equals(actor.getId());

        if (isSelf && request.role() != null && !request.role().isBlank()) {
            UserRole requested = parseRole(request.role());
            boolean keepsAdmin = requested == UserRole.OWNER || requested == UserRole.ADMIN;
            if (!keepsAdmin) {
                throw DomainException.conflict(
                        "CANNOT_DEMOTE_SELF", "No puedes quitarte a ti mismo el rol de administrador");
            }
        }

        if (isSelf && request.status() != null && !request.status().isBlank()) {
            UserStatus requested = parseStatus(request.status());
            if (requested != UserStatus.ACTIVE) {
                throw DomainException.conflict("CANNOT_DISABLE_SELF", "No puedes deshabilitar tu propio usuario");
            }
        }

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

    /** Paquetes de configuracion que el ERP sabe aplicar (contrato ADR-0013). */
    private static final Set<String> VERTICALES = Set.of("retail", "servicios", "restaurantes", "agro");

    /** Regimenes tributarios que acepta la facturacion electronica. */
    private static final Set<String> REGIMENES =
            Set.of("RESPONSABLE_IVA", "NO_RESPONSABLE_IVA", "SIMPLE");

    public TenantResponse currentTenant(String actorId) {
        User actor = users.findById(parseUuid(actorId, "USER_NOT_FOUND"))
                .orElseThrow(() -> DomainException.notFound("USER_NOT_FOUND", "Usuario no encontrado"));

        return toTenantResponse(actor.getTenant());
    }

    public TenantResponse updateTenant(String actorId, UpdateTenantRequest request) {
        User actor = users.findById(parseUuid(actorId, "USER_NOT_FOUND"))
                .orElseThrow(() -> DomainException.notFound("USER_NOT_FOUND", "Usuario no encontrado"));
        Tenant tenant = actor.getTenant();

        if (request.timezone() != null && !request.timezone().isBlank()) {
            String timezone = request.timezone().trim();
            if (!timezoneValida(timezone)) {
                throw DomainException.badRequest(
                        "INVALID_TIMEZONE", "La zona horaria indicada no es valida");
            }
            tenant.setTimezone(timezone);
        }

        if (request.vertical() != null && !request.vertical().isBlank()) {
            String vertical = request.vertical().trim().toLowerCase(Locale.ROOT);
            if (!VERTICALES.contains(vertical)) {
                throw DomainException.badRequest("INVALID_VERTICAL", "El vertical indicado no es valido");
            }
            tenant.setVertical(vertical);
        }

        // Datos fiscales (DIAN): el DV del NIT se calcula aqui para que quede
        // consistente sin que el negocio tenga que conocerlo.
        if (request.taxId() != null && !request.taxId().isBlank()) {
            String taxId = request.taxId().trim();
            String dv = NitDv.calcular(taxId);
            if (dv == null) {
                throw DomainException.badRequest("INVALID_TAX_ID", "El NIT debe ser numerico");
            }
            tenant.setTaxId(taxId);
            tenant.setTaxIdDv(dv);
        }

        if (request.fiscalAddress() != null && !request.fiscalAddress().isBlank()) {
            tenant.setFiscalAddress(request.fiscalAddress().trim());
        }

        if (request.taxRegime() != null && !request.taxRegime().isBlank()) {
            String regimen = request.taxRegime().trim().toUpperCase(Locale.ROOT);
            if (!REGIMENES.contains(regimen)) {
                throw DomainException.badRequest(
                        "INVALID_TAX_REGIME", "El regimen tributario indicado no es valido");
            }
            tenant.setTaxRegime(regimen);
        }

        if (request.invoiceResolution() != null && !request.invoiceResolution().isBlank()) {
            tenant.setInvoiceResolution(request.invoiceResolution().trim());
        }

        if (request.invoicePrefix() != null && !request.invoicePrefix().isBlank()) {
            String prefijo = request.invoicePrefix().trim().toUpperCase(Locale.ROOT);
            if (!prefijo.matches("[A-Z0-9]{1,6}")) {
                throw DomainException.badRequest(
                        "INVALID_INVOICE_PREFIX", "El prefijo debe ser alfanumerico de 1 a 6 caracteres");
            }
            tenant.setInvoicePrefix(prefijo);
        }

        tenants.save(tenant);
        auditService.record(
                tenant.getId(), actor.getId(), "TENANT_UPDATED", "tenant", tenant.getId().toString(), null, null);

        return toTenantResponse(tenant);
    }

    private boolean timezoneValida(String timezone) {
        try {
            ZoneId.of(timezone);
            return true;
        } catch (DateTimeException exception) {
            return false;
        }
    }

    private TenantResponse toTenantResponse(Tenant tenant) {
        Plan plan = Plan.byCodeOrDefault(tenant.getPlan());

        return new TenantResponse(
                tenant.getId().toString(),
                tenant.getName(),
                tenant.getSlug(),
                tenant.getPlan(),
                tenant.getTimezone(),
                tenant.getVertical(),
                tenant.getStatus(),
                plan.maxUsers(),
                plan.maxWarehouses(),
                users.countByTenantIdAndStatus(tenant.getId(), UserStatus.ACTIVE),
                tenant.getPlanRenewsAt() == null ? null : tenant.getPlanRenewsAt().toString(),
                tenant.getTaxId(),
                tenant.getTaxIdDv(),
                tenant.getFiscalAddress(),
                tenant.getTaxRegime(),
                tenant.getInvoiceResolution(),
                tenant.getInvoicePrefix());
    }

    /** Catalogo de planes para la interfaz (ADR-0021). */
    public List<TenantResponse.PlanInfo> planes() {
        return Arrays.stream(Plan.values())
                .map(plan -> new TenantResponse.PlanInfo(plan.code(), plan.maxUsers(), plan.maxWarehouses()))
                .toList();
    }

    private UserResponse toResponse(User user) {
        return new UserResponse(
                user.getId().toString(),
                user.getEmail(),
                user.getFullName(),
                user.getRole().name(),
                user.getStatus().name(),
                user.getTenant().getId().toString(),
                user.getTenant().getName(),
                user.isTotpEnabled());
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
