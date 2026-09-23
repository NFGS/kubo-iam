package co.kubo.iam.domain.repository;

import co.kubo.iam.domain.User;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, UUID> {

    Optional<User> findByEmailIgnoreCase(String email);

    boolean existsByEmailIgnoreCase(String email);

    List<User> findByTenantIdOrderByCreatedAtAsc(UUID tenantId);

    long countByTenantId(UUID tenantId);
}
