package co.kubo.iam.domain.repository;

import co.kubo.iam.domain.PaymentIntent;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PaymentIntentRepository extends JpaRepository<PaymentIntent, UUID> {

    Optional<PaymentIntent> findByProviderAndReference(String provider, String reference);

    List<PaymentIntent> findByStatusOrderByCreatedAtAsc(String status, Pageable pageable);

    List<PaymentIntent> findByTenantIdOrderByCreatedAtDesc(UUID tenantId, Pageable pageable);
}
