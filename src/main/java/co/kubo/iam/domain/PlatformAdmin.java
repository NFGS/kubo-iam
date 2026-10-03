package co.kubo.iam.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/**
 * Operador de la plataforma (F6.4, ADR-0025).
 *
 * Separado de {@link User}: no pertenece a ningun negocio y su poder es el
 * minimo (listar negocios, suspender, reactivar y renovar), con segundo factor
 * obligatorio y auditoria propia.
 */
@Entity
@Table(name = "platform_admins")
public class PlatformAdmin {

    @Id
    private UUID id;

    @Column(nullable = false, length = 180, unique = true)
    private String email;

    @Column(name = "password_hash", nullable = false, length = 120)
    private String passwordHash;

    /** Secreto TOTP cifrado: el segundo factor es obligatorio para este rol. */
    @Column(name = "totp_secret", nullable = false, length = 200)
    private String totpSecret;

    @Column(nullable = false, length = 20)
    private String status = "ACTIVE";

    @Column(name = "last_login_at")
    private Instant lastLoginAt;

    /** Contador de intentos fallidos (contrasena o TOTP): alimenta el bloqueo. */
    @Column(name = "failed_login_attempts", nullable = false)
    private int failedLoginAttempts = 0;

    @Column(name = "locked_until")
    private Instant lockedUntil;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected PlatformAdmin() {
        // requerido por JPA
    }

    public PlatformAdmin(
            UUID id, String email, String passwordHash, String totpSecret, Instant createdAt) {
        this.id = id;
        this.email = email;
        this.passwordHash = passwordHash;
        this.totpSecret = totpSecret;
        this.createdAt = createdAt;
    }

    public UUID getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public String getTotpSecret() {
        return totpSecret;
    }

    public String getStatus() {
        return status;
    }

    /** Rotacion del segundo factor: reemplaza el secreto cifrado (F6.6). */
    public void setTotpSecret(String totpSecret) {
        this.totpSecret = totpSecret;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public Instant getLastLoginAt() {
        return lastLoginAt;
    }

    public void setLastLoginAt(Instant lastLoginAt) {
        this.lastLoginAt = lastLoginAt;
    }

    public int getFailedLoginAttempts() {
        return failedLoginAttempts;
    }

    public void setFailedLoginAttempts(int failedLoginAttempts) {
        this.failedLoginAttempts = failedLoginAttempts;
    }

    public Instant getLockedUntil() {
        return lockedUntil;
    }

    public void setLockedUntil(Instant lockedUntil) {
        this.lockedUntil = lockedUntil;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
