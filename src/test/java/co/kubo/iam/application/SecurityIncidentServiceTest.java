package co.kubo.iam.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import co.kubo.iam.domain.Tenant;
import co.kubo.iam.domain.User;
import co.kubo.iam.domain.UserRole;
import co.kubo.iam.domain.UserStatus;
import co.kubo.iam.domain.repository.RefreshTokenRepository;
import co.kubo.iam.domain.repository.UserRepository;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;

/** Respuesta a incidentes: revocacion de familia y contador de intentos (P-11). */
@ExtendWith(MockitoExtension.class)
class SecurityIncidentServiceTest {

    @Mock
    private RefreshTokenRepository refreshTokens;

    @Mock
    private UserRepository users;

    @Mock
    private AuditService audit;

    @Mock
    private JdbcTemplate jdbc;

    private SecurityIncidentService service;
    private User user;

    @BeforeEach
    void setUp() {
        service = new SecurityIncidentService(refreshTokens, users, audit, jdbc);
        Tenant tenant = new Tenant(UUID.randomUUID(), "Tienda Test", "tienda-test", "community", "America/Bogota", "retail", Instant.now());
        user = new User(
                UUID.randomUUID(), tenant, "dueno@test.local", "hash", "Dueno Test",
                UserRole.OWNER, UserStatus.ACTIVE, Instant.now());
    }

    @Test
    @DisplayName("El reuso de un token revoca la familia completa y lo audita")
    void reusoRevocaLaFamilia() {
        UUID tokenId = UUID.randomUUID();

        service.registerRefreshReuse(user.getId(), tokenId, "127.0.0.1", "junit");

        verify(refreshTokens).revokeAllByUserId(eq(user.getId()), any());
        verify(audit).record(eq(null), eq(user.getId()), eq("REFRESH_REUSE_DETECTED"),
                eq("refresh_token"), eq(tokenId.toString()), anyString(), anyString());
    }

    @Test
    @DisplayName("Un fallo por debajo del limite suma al contador sin bloquear")
    void falloPorDebajoDelLimite() {
        when(users.findById(user.getId())).thenReturn(Optional.of(user));

        SecurityIncidentService.LoginFailure failure =
                service.registerLoginFailure(user.getId(), "127.0.0.1", "junit", 5, 15);

        assertThat(failure.attempts()).isEqualTo(1);
        assertThat(failure.locked()).isFalse();
        assertThat(user.getFailedLoginAttempts()).isEqualTo(1);
        assertThat(user.getLockedUntil()).isNull();
        verify(audit).record(any(), any(), eq("LOGIN_FAILED"), any(), any(), any(), any());
    }

    @Test
    @DisplayName("Al alcanzar el limite la cuenta queda bloqueada y auditada")
    void falloQueBloquea() {
        user.setFailedLoginAttempts(4);
        when(users.findById(user.getId())).thenReturn(Optional.of(user));

        SecurityIncidentService.LoginFailure failure =
                service.registerLoginFailure(user.getId(), "127.0.0.1", "junit", 5, 15);

        assertThat(failure.locked()).isTrue();
        assertThat(user.getLockedUntil()).isAfter(Instant.now());
        verify(audit).record(any(), any(), eq("ACCOUNT_LOCKED"), any(), any(), any(), any());
    }

    @Test
    @DisplayName("Un usuario inexistente no puede registrar el fallo")
    void usuarioInexistente() {
        when(users.findById(user.getId())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.registerLoginFailure(user.getId(), "127.0.0.1", "junit", 5, 15))
                .isInstanceOf(DomainException.class);
    }
}
