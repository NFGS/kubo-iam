package co.kubo.iam.application.dto;

import jakarta.validation.constraints.Size;
import java.util.List;

/** Contratos del puerto de cobro (F6.6, ADR-0026). */
public final class PaymentsDtos {

    private PaymentsDtos() {
    }

    /** El negocio pide pagar su plan: plan y ciclo (1 a 24 meses). */
    public record PaymentRequest(@Size(max = 40) String plan, Integer cycleMonths) {
    }

    public record PaymentView(
            String id,
            String plan,
            int cycleMonths,
            String amount,
            String currency,
            String provider,
            String reference,
            String status,
            String detail,
            String createdAt,
            String paidAt) {
    }

    public record PaymentList(List<PaymentView> data) {
    }

    public record PriceView(String plan, String currency, int cycleMonths, String amount) {
    }

    public record PriceList(List<PriceView> data) {
    }

    /** Lo que el proveedor envia al webhook: referencia, monto y estado. */
    public record WebhookEvent(String reference, java.math.BigDecimal amount, String status) {
    }
}
