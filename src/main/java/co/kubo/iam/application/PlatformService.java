package co.kubo.iam.application;

import co.kubo.iam.application.dto.PlatformDtos.PlatformAuditEntry;
import co.kubo.iam.application.dto.PlatformDtos.PlatformAuditPage;
import co.kubo.iam.application.dto.PlatformDtos.PlatformChallenge;
import co.kubo.iam.application.dto.PlatformDtos.PlatformLoginRequest;
import co.kubo.iam.application.dto.PlatformDtos.PlatformTenant;
import co.kubo.iam.application.dto.PlatformDtos.PlatformTenantUpdate;
import co.kubo.iam.application.dto.PlatformDtos.PlatformToken;
import co.kubo.iam.application.dto.PlatformDtos.PlatformTotpRotation;
import co.kubo.iam.application.dto.PlatformDtos.PlatformVerifyRequest;
import co.kubo.iam.config.TotpSecretCipher;
import co.kubo.iam.domain.Plan;
import co.kubo.iam.domain.PlatformAdmin;
import co.kubo.iam.domain.PlatformAudit;
import co.kubo.iam.domain.Tenant;
import co.kubo.iam.domain.UserStatus;
import co.kubo.iam.domain.repository.PlatformAdminRepository;
import co.kubo.iam.domain.repository.PlatformAuditRepository;
import co.kubo.iam.domain.repository.TenantRepository;
import co.kubo.iam.domain.repository.UserRepository;
import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import org.springframework.data.domain.PageRequest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Operacion de la plataforma (F6.4, ADR-0025).
 *
 * El poder es minimo por diseno: listar negocios, suspender, reactivar y
 * registrar pagos. **Nunca** lee datos de negocio (ventas, clientes,
 * documentos): para eso esta el dueno. Cada accion queda en su propia auditoria.
 */
@Service
public class PlatformService {

    private static final Set<String> ESTADOS = Set.of("ACTIVE", "SUSPENDED");
    private static final int MAX_RENEW_DAYS = 365;

    private final PlatformAdminRepository admins;
    private final PlatformAuditRepository platformAudit;
    private final TenantRepository tenants;
    private final UserRepository users;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;
    private final TotpService totpService;
    private final TotpSecretCipher totpCipher;
    private final JdbcTemplate jdbc;

    public PlatformService(
            PlatformAdminRepository admins,
            PlatformAuditRepository platformAudit,
            TenantRepository tenants,
            UserRepository users,
            PasswordEncoder passwordEncoder,
            TokenService tokenService,
            TotpService totpService,
            TotpSecretCipher totpCipher,
            JdbcTemplate jdbc) {
        this.admins = admins;
        this.platformAudit = platformAudit;
        this.tenants = tenants;
        this.users = users;
        this.passwordEncoder = passwordEncoder;
        this.tokenService = tokenService;
        this.totpService = totpService;
        this.totpCipher = totpCipher;
        this.jdbc = jdbc;
    }

    /**
     * Primer paso: correo y contrasena. **Siempre** pide el codigo: el segundo
     * factor es obligatorio para este rol (ADR-0025), no una opcion.
     */
    @Transactional
    public PlatformChallenge login(PlatformLoginRequest request, String ip) {
        PlatformAdmin admin = admins.findByEmailIgnoreCase(request.email().trim().toLowerCase(Locale.ROOT))
                .orElseThrow(() -> DomainException.unauthorized(
                        "INVALID_CREDENTIALS", "Correo o contrasena incorrectos"));

        if (!"ACTIVE".equals(admin.getStatus())) {
            throw DomainException.unauthorized("ADMIN_DISABLED", "El operador esta deshabilitado");
        }

        if (!passwordEncoder.matches(request.password(), admin.getPasswordHash())) {
            record(admin, "LOGIN_FAILED", null, "contrasena incorrecta", ip);
            throw DomainException.unauthorized("INVALID_CREDENTIALS", "Correo o contrasena incorrectos");
        }

        record(admin, "LOGIN_CHALLENGED", null, null, ip);

        return new PlatformChallenge(true, tokenService.signPlatformChallenge(admin));
    }

    /** Segundo paso: codigo TOTP a cambio de la sesion de plataforma. */
    @Transactional
    public PlatformToken verifyTotp(PlatformVerifyRequest request, String ip) {
        UUID adminId = UUID.fromString(tokenService.verifyPlatformChallenge(request.challengeToken()));
        PlatformAdmin admin = admins.findById(adminId)
                .orElseThrow(() -> DomainException.unauthorized(
                        "INVALID_CHALLENGE", "El desafio de verificacion no es valido"));

        if (!totpService.verify(totpCipher.decrypt(admin.getTotpSecret()), request.code(), Instant.now())) {
            record(admin, "TOTP_FAILED", null, null, ip);
            throw DomainException.unauthorized("INVALID_TOTP", "El codigo de verificacion no es valido");
        }

        admin.setLastLoginAt(Instant.now());
        admins.save(admin);
        record(admin, "LOGIN_SUCCEEDED", null, null, ip);

        return new PlatformToken(
                tokenService.signPlatformAccessToken(admin),
                "Bearer",
                Instant.now().getEpochSecond() + 900,
                admin.getEmail());
    }

    /**
     * Rota el segundo factor del operador (F6.6): el secreto viejo deja de
     * servir en el acto y la URI nueva se entrega **una sola vez**. Exige una
     * sesion de plataforma valida (el token), es decir, haber pasado el codigo.
     */
    @Transactional
    public PlatformTotpRotation rotateTotp(String adminId, String actorEmail, String ip) {
        UUID id;
        try {
            id = UUID.fromString(adminId);
        } catch (IllegalArgumentException exception) {
            throw DomainException.badRequest("INVALID_ID", "El identificador no es valido");
        }

        PlatformAdmin admin = admins.findById(id)
                .orElseThrow(() -> DomainException.notFound("ADMIN_NOT_FOUND", "El operador no existe"));

        String secreto = totpService.newSecret();
        admin.setTotpSecret(totpCipher.encrypt(secreto));
        admins.save(admin);

        platformAudit.save(new PlatformAudit(
                UUID.randomUUID(),
                admin.getId(),
                actorEmail == null || actorEmail.isBlank() ? admin.getEmail() : actorEmail,
                "TOTP_ROTATED",
                null,
                "segundo factor rotado",
                ip,
                Instant.now()));

        // Unica vez que el secreto nuevo sale en claro.
        return new PlatformTotpRotation(totpService.otpauthUri(admin.getEmail(), secreto), secreto);
    }

    /** Negocios con su plan, estado y cupo de usuarios (datos de identidad). */
    @Transactional(readOnly = true)
    public List<PlatformTenant> tenants() {
        // La marca de sistema permite contar usuarios de todos los negocios:
        // `users` tiene RLS y sin ella la cuenta seria cero.
        jdbc.queryForObject("select set_config('app.system', 'on', true)", String.class);

        return tenants.findAll().stream()
                .map(tenant -> {
                    Plan plan = Plan.byCodeOrDefault(tenant.getPlan());
                    long activos = users.countByTenantIdAndStatus(tenant.getId(), UserStatus.ACTIVE);

                    return new PlatformTenant(
                            tenant.getId().toString(),
                            tenant.getName(),
                            tenant.getSlug(),
                            tenant.getPlan(),
                            tenant.getStatus(),
                            tenant.getPlanRenewsAt() == null ? null : tenant.getPlanRenewsAt().toString(),
                            activos,
                            plan.maxUsers(),
                            plan.maxWarehouses());
                })
                .toList();
    }

    /** Suspende, reactiva o registra un pago (renovacion en dias). */
    @Transactional
    public PlatformTenant updateTenant(
            String actorId, String actorEmail, String tenantId, PlatformTenantUpdate request, String ip) {
        Tenant tenant = tenants.findById(parseUuid(tenantId))
                .orElseThrow(() -> DomainException.notFound("TENANT_NOT_FOUND", "El negocio no existe"));

        if (request.status() != null && !request.status().isBlank()) {
            String estado = request.status().trim().toUpperCase(Locale.ROOT);

            if (!ESTADOS.contains(estado)) {
                throw DomainException.badRequest("INVALID_STATUS", "El estado indicado no es valido");
            }

            tenant.setStatus(estado);
            record(actorId, actorEmail, "TENANT_" + estado, tenant.getId(), null, ip);
        }

        if (request.renewDays() != null) {
            if (request.renewDays() < 1 || request.renewDays() > MAX_RENEW_DAYS) {
                throw DomainException.badRequest(
                        "INVALID_RENEW_DAYS", "Los dias de renovacion deben estar entre 1 y " + MAX_RENEW_DAYS);
            }

            // Igual que la herramienta del operador: se extiende desde la fecha
            // vigente o desde hoy, la que sea mayor; pagar antes no regala dias.
            LocalDate base = tenant.getPlanRenewsAt() == null || tenant.getPlanRenewsAt().isBefore(LocalDate.now())
                    ? LocalDate.now()
                    : tenant.getPlanRenewsAt();

            tenant.setPlanRenewsAt(base.plusDays(request.renewDays()));
            record(actorId, actorEmail, "TENANT_RENEWED", tenant.getId(),
                    "hasta " + tenant.getPlanRenewsAt(), ip);
        }

        tenants.save(tenant);

        Plan plan = Plan.byCodeOrDefault(tenant.getPlan());

        return new PlatformTenant(
                tenant.getId().toString(),
                tenant.getName(),
                tenant.getSlug(),
                tenant.getPlan(),
                tenant.getStatus(),
                tenant.getPlanRenewsAt() == null ? null : tenant.getPlanRenewsAt().toString(),
                users.countByTenantIdAndStatus(tenant.getId(), UserStatus.ACTIVE),
                plan.maxUsers(),
                plan.maxWarehouses());
    }

    @Transactional(readOnly = true)
    public PlatformAuditPage audit(int limite) {
        int tamano = Math.min(Math.max(limite, 1), 100);

        List<PlatformAuditEntry> entradas = platformAudit
                .findAllByOrderByCreatedAtDesc(PageRequest.of(0, tamano))
                .stream()
                .map(entrada -> new PlatformAuditEntry(
                        entrada.getActorEmail(),
                        entrada.getAction(),
                        entrada.getTenantId() == null ? null : entrada.getTenantId().toString(),
                        entrada.getDetail(),
                        entrada.getCreatedAt().toString()))
                .toList();

        return new PlatformAuditPage(entradas);
    }

    private void record(PlatformAdmin admin, String action, UUID tenantId, String detail, String ip) {
        record(admin.getId().toString(), admin.getEmail(), action, tenantId, detail, ip);
    }

    private void record(String actorId, String actorEmail, String action, UUID tenantId, String detail, String ip) {
        platformAudit.save(new co.kubo.iam.domain.PlatformAudit(
                UUID.randomUUID(),
                parseUuid(actorId),
                actorEmail,
                action,
                tenantId,
                detail,
                ip,
                Instant.now()));
    }

    private UUID parseUuid(String value) {
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException exception) {
            throw DomainException.badRequest("INVALID_ID", "El identificador no es valido");
        }
    }
}
