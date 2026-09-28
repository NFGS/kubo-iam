package co.kubo.iam.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.IdClass;
import jakarta.persistence.Table;
import java.io.Serializable;
import java.math.BigDecimal;
import java.util.Objects;

/** Precio de un plan por moneda y ciclo (F6.6, ADR-0026): datos, no codigo. */
@Entity
@Table(name = "plan_prices")
@IdClass(PlanPrice.Key.class)
public class PlanPrice {

    @Id
    @Column(nullable = false, length = 40)
    private String plan;

    @Id
    @Column(nullable = false, length = 3)
    private String currency;

    @Id
    @Column(name = "cycle_months", nullable = false)
    private int cycleMonths;

    @Column(nullable = false, precision = 12, scale = 2)
    private BigDecimal amount;

    protected PlanPrice() {
        // requerido por JPA
    }

    public String getPlan() {
        return plan;
    }

    public String getCurrency() {
        return currency;
    }

    public int getCycleMonths() {
        return cycleMonths;
    }

    public BigDecimal getAmount() {
        return amount;
    }

    /** Clave compuesta (plan, moneda, ciclo). */
    public static class Key implements Serializable {
        private String plan;
        private String currency;
        private int cycleMonths;

        public Key() {
        }

        @Override
        public boolean equals(Object otro) {
            if (this == otro) {
                return true;
            }
            if (!(otro instanceof Key key)) {
                return false;
            }
            return cycleMonths == key.cycleMonths
                    && Objects.equals(plan, key.plan)
                    && Objects.equals(currency, key.currency);
        }

        @Override
        public int hashCode() {
            return Objects.hash(plan, currency, cycleMonths);
        }
    }
}
