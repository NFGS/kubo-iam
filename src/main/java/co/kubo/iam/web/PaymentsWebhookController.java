package co.kubo.iam.web;

import co.kubo.iam.application.DomainException;
import co.kubo.iam.application.PaymentsService;
import co.kubo.iam.application.dto.PaymentsDtos.WebhookEvent;
import tools.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Webhook del proveedor de pagos (F6.6, ADR-0026).
 *
 * Es publico (lo llama el proveedor, no el panel) y por eso exige **firma
 * HMAC-SHA256** del cuerpo crudo con el secreto compartido. Los webhooks son la
 * fuente de verdad del cobro, y el servicio los aplica de forma idempotente por
 * la referencia del proveedor: un reintento no extiende dos veces el plan.
 */
@RestController
@RequestMapping("/webhooks/payments")
public class PaymentsWebhookController {

    private static final String HEADER_FIRMA = "X-Kubo-Signature";

    private final PaymentsService payments;
    private final ObjectMapper json;
    private final String webhookSecret;

    public PaymentsWebhookController(
            PaymentsService payments,
            ObjectMapper json,
            @Value("${kubo.payments.webhook-secret:}") String webhookSecret) {
        this.payments = payments;
        this.json = json;
        this.webhookSecret = webhookSecret;
    }

    @PostMapping("/{provider}")
    public ResponseEntity<Map<String, String>> receive(
            @PathVariable("provider") String provider,
            @RequestHeader(value = HEADER_FIRMA, required = false) String signature,
            @RequestBody String rawBody,
            HttpServletRequest http) {

        if (!payments.signatureValid(rawBody, signature, webhookSecret)) {
            throw DomainException.unauthorized("INVALID_SIGNATURE", "La firma del webhook no es valida");
        }

        WebhookEvent evento;
        try {
            evento = json.readValue(rawBody, WebhookEvent.class);
        } catch (Exception exception) {
            throw DomainException.badRequest("INVALID_PAYLOAD", "El webhook no trae un evento valido");
        }

        if (evento.reference() == null || evento.reference().isBlank()) {
            throw DomainException.badRequest("INVALID_PAYLOAD", "El webhook no trae referencia de pago");
        }

        // El proveedor habla de APPROVED/PAID; lo demas (declinado, expirado)
        // no toca el plan: el estado del pago queda en la intencion.
        if ("APPROVED".equalsIgnoreCase(evento.status()) || "PAID".equalsIgnoreCase(evento.status())) {
            payments.confirmPaid(provider, evento.reference(), evento.amount(), "webhook:" + provider, clientIp(http));
        }

        return ResponseEntity.ok(Map.of("recibido", "ok"));
    }

    private static String clientIp(HttpServletRequest request) {
        String reenviada = request.getHeader("X-Forwarded-For");

        return reenviada == null || reenviada.isBlank()
                ? request.getRemoteAddr()
                : reenviada.split(",")[0].trim();
    }
}
