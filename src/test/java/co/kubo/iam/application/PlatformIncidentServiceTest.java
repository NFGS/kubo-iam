package co.kubo.iam.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import co.kubo.iam.domain.PlatformAdmin;
import co.kubo.iam.domain.PlatformAudit;
import co.kubo.iam.domain.repository.PlatformAdminRepository;
import co.kubo.iam.domain.repository.PlatformAuditRepository;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Bloqueo por intentos fallidos del operador (P-11 en el reino de plataforma).
 * La transaccion independiente es lo que permite que el contador sobreviva al
 * rechazo; aqui se prueba la logica de incremento y bloqueo.
 */
@ExtendWith(MockitoExtension.class)
class PlatformIncidentServiceTest {

    @Mock
    private PlatformAdminRepository admins;

    @Mock
    private PlatformAuditRepository audit;

    private PlatformIncidentService service;
    private PlatformAdmin admin;

    @BeforeEach
    void setUp() {
        service = new PlatformIncidentService(admins, audit);
        admin = new PlatformAdmin(
                UUID.randomUUID(), "operador@kubo.local", "hash", "secreto", Instant.now());
    }

    @Test
    @DisplayName("Los intentos fallidos incrementan y bloquean al alcanzar el limite")
    void bloqueoAlLimite() {
        when(admins.findById(admin.getId())).thenReturn(Optional.of(admin));
        when(admins.save(any(PlatformAdmin.class))).thenAnswer(invocation -> invocation.getArgument(0));

        PlatformIncidentService.Failure primero =
                service.registerFailure(admin.getId(), "LOGIN_FAILED", "127.0.0.1", 3, 15);
        PlatformIncidentService.Failure segundo =
                service.registerFailure(admin.getId(), "LOGIN_FAILED", "127.0.0.1", 3, 15);
        PlatformIncidentService.Failure tercero =
                service.registerFailure(admin.getId(), "TOTP_FAILED", "127.0.0.1", 3, 15);

        assertThat(primero.locked()).isFalse();
        assertThat(segundo.locked()).isFalse();
        assertThat(tercero.locked()).isTrue();
        assertThat(admin.getFailedLoginAttempts()).isEqualTo(3);
        assertThat(admin.getLockedUntil()).isAfter(Instant.now());
        // Tres intentos + el evento de bloqueo.
        verify(audit, times(4)).save(any(PlatformAudit.class));
    }
}
