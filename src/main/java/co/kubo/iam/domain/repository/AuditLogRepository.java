package co.kubo.iam.domain.repository;

import co.kubo.iam.domain.AuditLog;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuditLogRepository extends JpaRepository<AuditLog, UUID> {

    Optional<AuditLog> findTopByOrderByCreatedAtDesc();

    List<AuditLog> findTop50ByOrderByCreatedAtDesc();

    long countByTenantId(UUID tenantId);
}
