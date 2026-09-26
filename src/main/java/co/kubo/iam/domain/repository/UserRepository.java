package co.kubo.iam.domain.repository;

import co.kubo.iam.domain.User;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, UUID> {

    Optional<User> findByEmailIgnoreCase(String email);

    boolean existsByEmailIgnoreCase(String email);

    List<User> findByTenantIdOrderByCreatedAtAsc(UUID tenantId);

    /** Listado paginado: un negocio puede tener cientos de usuarios. */
    Page<User> findByTenantId(UUID tenantId, Pageable pageable);

    long countByTenantId(UUID tenantId);

    /** Cupo del plan: los usuarios deshabilitados no ocupan asiento (ADR-0021). */
    long countByTenantIdAndStatus(UUID tenantId, co.kubo.iam.domain.UserStatus status);
}
