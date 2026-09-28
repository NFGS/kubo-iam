package co.kubo.iam.domain.repository;

import co.kubo.iam.domain.PlatformAudit;
import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PlatformAuditRepository extends JpaRepository<PlatformAudit, UUID> {

    List<PlatformAudit> findAllByOrderByCreatedAtDesc(Pageable pageable);
}
