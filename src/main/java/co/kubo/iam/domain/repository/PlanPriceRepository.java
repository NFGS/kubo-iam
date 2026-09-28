package co.kubo.iam.domain.repository;

import co.kubo.iam.domain.PlanPrice;
import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PlanPriceRepository extends JpaRepository<PlanPrice, PlanPrice.Key> {

    Optional<PlanPrice> findByPlanAndCurrencyAndCycleMonths(String plan, String currency, int cycleMonths);

    List<PlanPrice> findByPlanAndCurrencyOrderByCycleMonthsAsc(String plan, String currency);
}
