package co.kubo.iam.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import co.kubo.iam.domain.PaymentIntent;
import co.kubo.iam.domain.PlanPrice;
import co.kubo.iam.domain.PlatformAudit;
import co.kubo.iam.domain.Tenant;
import co.kubo.iam.domain.repository.PaymentIntentRepository;
import co.kubo.iam.domain.repository.PlanPriceRepository;
import co.kubo.iam.domain.repository.PlatformAuditRepository;
import co.kubo.iam.domain.repository.TenantRepository;
import java.lang.reflect.Field;
import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Puerto de cobro (F6.6, ADR-0026): la renovacion se deriva de un pago pagado,
 * el monto sale del catalogo y un webhook repetido NO extiende dos veces.
 */
@ExtendWith(MockitoExtension.class)
class PaymentsServiceTest {

    @Mock
    private PaymentIntentRepository intents;

    @Mock
    private PlanPriceRepository prices;

    @Mock
    private TenantRepository tenants;

    @Mock
    private PlatformAuditRepository platformAudit;

    private PaymentsService service;

    @BeforeEach
    void setUp() {
        service = new PaymentsService(intents, prices, tenants, platformAudit);
    }

    @Test
    @DisplayName("la intencion toma el monto del catalogo, nunca del cliente")
    void createIntentUsaElPrecioDelCatalogo() {
        when(prices.findByPlanAndCurrencyAndCycleMonths("pro", "COP", 12)).thenReturn(Optional.of(precio("pro", 12, "490000")));
        when(intents.save(any(PaymentIntent.class))).thenAnswer(invocacion -> invocacion.getArgument(0));

        PaymentIntent intent = service.createIntent(UUID.randomUUID(), "pro", 12, "manual", "Tienda La Esquina");

        assertThat(intent.getAmount()).isEqualByComparingTo("490000");
        assertThat(intent.getCycleMonths()).isEqualTo(12);
        assertThat(intent.getStatus()).isEqualTo("PENDING");
        assertThat(intent.getProvider()).isEqualTo("manual");
    }

    @Test
    @DisplayName("un ciclo sin precio no se puede cobrar")
    void createIntentSinPrecioFalla() {
        when(prices.findByPlanAndCurrencyAndCycleMonths("pro", "COP", 7)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.createIntent(UUID.randomUUID(), "pro", 7, "manual", "x"))
                .isInstanceOf(DomainException.class)
                .hasMessageContaining("No hay precio");
    }

    @Test
    @DisplayName("confirmar el pago extiende el plan por el ciclo pagado")
    void confirmarExtiendeElPlan() {
        UUID tenantId = UUID.randomUUID();
        Tenant tenant = tenantConRenovacion(tenantId, LocalDate.now().minusDays(2));
        PaymentIntent intent = intentPendiente(tenantId, "pro", 1, "49000", "manual", "manual-1");

        when(intents.findByProviderAndReference("manual", "manual-1")).thenReturn(Optional.of(intent));
        when(tenants.findById(tenantId)).thenReturn(Optional.of(tenant));
        when(tenants.save(any(Tenant.class))).thenAnswer(invocacion -> invocacion.getArgument(0));

        PaymentIntent pagado = service.confirmPaid("manual", "manual-1", null, "operador@kubo.local", "127.0.0.1");

        assertThat(pagado.getStatus()).isEqualTo("PAID");
        // La base vencida arranca hoy: un mes desde hoy, no desde la fecha vieja.
        assertThat(tenant.getPlanRenewsAt()).isEqualTo(LocalDate.now().plusMonths(1));
        verify(platformAudit).save(any(PlatformAudit.class));
    }

    @Test
    @DisplayName("pagar antes de vencer extiende desde la fecha vigente (no regala meses)")
    void pagarAntesDeVencerExtiendeDesdeLaVigente() {
        UUID tenantId = UUID.randomUUID();
        LocalDate vigente = LocalDate.now().plusDays(10);
        Tenant tenant = tenantConRenovacion(tenantId, vigente);
        PaymentIntent intent = intentPendiente(tenantId, "pro", 3, "147000", "manual", "manual-2");

        when(intents.findByProviderAndReference("manual", "manual-2")).thenReturn(Optional.of(intent));
        when(tenants.findById(tenantId)).thenReturn(Optional.of(tenant));
        when(tenants.save(any(Tenant.class))).thenAnswer(invocacion -> invocacion.getArgument(0));

        service.confirmPaid("manual", "manual-2", null, "operador@kubo.local", null);

        assertThat(tenant.getPlanRenewsAt()).isEqualTo(vigente.plusMonths(3));
    }

    @Test
    @DisplayName("un webhook repetido no extiende dos veces (idempotencia por referencia)")
    void webhookRepetidoNoExtiendeDosVeces() {
        UUID tenantId = UUID.randomUUID();
        PaymentIntent intent = intentPendiente(tenantId, "pro", 1, "49000", "wompi", "wompi-777");
        intent.markPaid("pago previo", Instant.now());

        when(intents.findByProviderAndReference("wompi", "wompi-777")).thenReturn(Optional.of(intent));

        PaymentIntent repetido = service.confirmPaid("wompi", "wompi-777", null, "webhook:wompi", null);

        assertThat(repetido.getStatus()).isEqualTo("PAID");
        // No se toca el negocio: el plan ya se extendio con el primer webhook.
        verify(tenants, never()).save(any(Tenant.class));
    }

    @Test
    @DisplayName("un monto que no coincide con la intencion se rechaza")
    void montoDistintoSeRechaza() {
        PaymentIntent intent = intentPendiente(UUID.randomUUID(), "pro", 1, "49000", "wompi", "wompi-888");

        when(intents.findByProviderAndReference("wompi", "wompi-888")).thenReturn(Optional.of(intent));

        assertThatThrownBy(() -> service.confirmPaid("wompi", "wompi-888", new BigDecimal("1000"), "webhook:wompi", null))
                .isInstanceOf(DomainException.class)
                .hasMessageContaining("no coincide");
        verify(tenants, never()).save(any(Tenant.class));
    }

    @Test
    @DisplayName("la firma del webhook: solo pasa el cuerpo firmado con el secreto")
    void firmaDelWebhook() throws Exception {
        String cuerpo = "{\"reference\":\"wompi-1\",\"amount\":49000,\"status\":\"APPROVED\"}";
        String firma = firmar(cuerpo, "secreto-de-prueba");

        assertThat(service.signatureValid(cuerpo, firma, "secreto-de-prueba")).isTrue();
        assertThat(service.signatureValid(cuerpo, firma, "otro-secreto")).isFalse();
        assertThat(service.signatureValid(cuerpo, null, "secreto-de-prueba")).isFalse();
        assertThat(service.signatureValid(cuerpo + " ", firma, "secreto-de-prueba")).isFalse();
        assertThat(service.signatureValid(cuerpo, firma, "")).isFalse();
    }

    @Test
    @DisplayName("el catalogo de precios se consulta por plan")
    void preciosDelPlan() {
        when(prices.findByPlanAndCurrencyOrderByCycleMonthsAsc("pro", "COP"))
                .thenReturn(java.util.List.of(precio("pro", 1, "49000"), precio("pro", 12, "490000")));

        assertThat(service.pricesOf("pro")).hasSize(2);
    }

    @Test
    @DisplayName("un ciclo fuera de rango se rechaza antes de tocar el catalogo")
    void cicloFueraDeRango() {
        assertThatThrownBy(() -> service.createIntent(UUID.randomUUID(), "pro", 0, "manual", "x"))
                .isInstanceOf(DomainException.class)
                .hasMessageContaining("entre 1 y 24");
        assertThatThrownBy(() -> service.createIntent(UUID.randomUUID(), "pro", 25, "manual", "x"))
                .isInstanceOf(DomainException.class)
                .hasMessageContaining("entre 1 y 24");
        verify(intents, never()).save(any(PaymentIntent.class));
    }

    @Test
    @DisplayName("un proveedor real arranca con referencia propia (el webhook la traera)")
    void referenciaDeProveedor() {
        when(prices.findByPlanAndCurrencyAndCycleMonths("pro", "COP", 1)).thenReturn(Optional.of(precio("pro", 1, "49000")));
        when(intents.save(any(PaymentIntent.class))).thenAnswer(invocacion -> invocacion.getArgument(0));

        PaymentIntent intent = service.createIntent(UUID.randomUUID(), "pro", 1, "wompi", "Tienda");

        assertThat(intent.getProvider()).isEqualTo("wompi");
        assertThat(intent.getReference()).startsWith("pendiente-");
    }

    @Test
    @DisplayName("las listas de pagos: pendientes para el operador, historia por negocio")
    void listasDePagos() {
        UUID tenantId = UUID.randomUUID();
        when(intents.findByStatusOrderByCreatedAtAsc(org.mockito.ArgumentMatchers.eq("PENDING"), any()))
                .thenReturn(java.util.List.of(intentPendiente(tenantId, "pro", 1, "49000", "manual", "manual-9")));
        when(intents.findByTenantIdOrderByCreatedAtDesc(org.mockito.ArgumentMatchers.eq(tenantId), any()))
                .thenReturn(java.util.List.of(intentPendiente(tenantId, "pro", 1, "49000", "manual", "manual-9")));

        assertThat(service.pending(50)).hasSize(1);
        assertThat(service.ofTenant(tenantId)).hasSize(1);
    }

    @Test
    @DisplayName("confirmar desde el panel: id invalido, intencion inexistente y camino feliz")
    void confirmarDesdeElPanel() {
        assertThatThrownBy(() -> service.confirmById("no-es-uuid", "operador", null))
                .isInstanceOf(DomainException.class)
                .hasMessageContaining("identificador");

        UUID id = UUID.randomUUID();
        when(intents.findById(id)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.confirmById(id.toString(), "operador", null))
                .isInstanceOf(DomainException.class)
                .hasMessageContaining("no existe");

        UUID tenantId = UUID.randomUUID();
        Tenant tenant = tenantConRenovacion(tenantId, LocalDate.now());
        PaymentIntent intent = intentPendiente(tenantId, "pro", 1, "49000", "manual", "manual-10");
        when(intents.findById(id)).thenReturn(Optional.of(intent));
        when(intents.findByProviderAndReference("manual", "manual-10")).thenReturn(Optional.of(intent));
        when(tenants.findById(tenantId)).thenReturn(Optional.of(tenant));
        when(tenants.save(any(Tenant.class))).thenAnswer(invocacion -> invocacion.getArgument(0));

        assertThat(service.confirmById(id.toString(), "operador@kubo.local", "10.0.0.1").getStatus()).isEqualTo("PAID");
    }

    @Test
    @DisplayName("confirmar una referencia desconocida o un negocio inexistente falla claro")
    void confirmarReferenciaDesconocida() {
        when(intents.findByProviderAndReference("wompi", "nada")).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.confirmPaid("wompi", "nada", null, "webhook:wompi", null))
                .isInstanceOf(DomainException.class)
                .hasMessageContaining("referencia");

        UUID tenantId = UUID.randomUUID();
        PaymentIntent intent = intentPendiente(tenantId, "pro", 1, "49000", "wompi", "wompi-1");
        when(intents.findByProviderAndReference("wompi", "wompi-1")).thenReturn(Optional.of(intent));
        when(tenants.findById(tenantId)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.confirmPaid("wompi", "wompi-1", null, "webhook:wompi", null))
                .isInstanceOf(DomainException.class)
                .hasMessageContaining("negocio no existe");
    }

    @Test
    @DisplayName("una intencion fallida conserva su detalle y la clave compuesta del precio es estable")
    void detalleYClaveCompuesta() throws Exception {
        PaymentIntent intent = intentPendiente(UUID.randomUUID(), "pro", 1, "49000", "wompi", "wompi-2");
        intent.markFailed("tarjeta rechazada");
        assertThat(intent.getStatus()).isEqualTo("FAILED");
        assertThat(intent.getDetail()).isEqualTo("tarjeta rechazada");

        PlanPrice precio = precio("pro", 1, "49000");
        var claveA = new PlanPrice.Key();
        var claveB = new PlanPrice.Key();
        assertThat(claveA).isEqualTo(claveB).hasSameHashCodeAs(claveB);
        assertThat(claveA.equals(claveA)).isTrue();
        assertThat(claveA.equals(null)).isFalse();
        assertThat(claveA.equals("otra")).isFalse();
        assertThat(precio.getPlan()).isEqualTo("pro");
        assertThat(precio.getCurrency()).isEqualTo("COP");
        assertThat(precio.getCycleMonths()).isEqualTo(1);
        assertThat(precio.getAmount()).isEqualByComparingTo("49000");
        assertThat(intent.getCurrency()).isEqualTo("COP");
        assertThat(intent.getPaidAt()).isNull();
        assertThat(intent.getCreatedAt()).isNotNull();
    }

    private static String firmar(String cuerpo, String secreto) throws Exception {
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        mac.init(new javax.crypto.spec.SecretKeySpec(secreto.getBytes(java.nio.charset.StandardCharsets.UTF_8), "HmacSHA256"));

        return java.util.HexFormat.of().formatHex(mac.doFinal(cuerpo.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
    }

    private static PlanPrice precio(String plan, int ciclo, String monto) {
        return precioConReflexion(plan, ciclo, new BigDecimal(monto));
    }

    private static PlanPrice precioConReflexion(String plan, int ciclo, BigDecimal monto) {
        try {
            var constructor = PlanPrice.class.getDeclaredConstructor();
            constructor.setAccessible(true);
            PlanPrice precio = constructor.newInstance();
            campo(precio, "plan", plan);
            campo(precio, "currency", "COP");
            campo(precio, "cycleMonths", ciclo);
            campo(precio, "amount", monto);

            return precio;
        } catch (Exception exception) {
            throw new IllegalStateException(exception);
        }
    }

    private static PaymentIntent intentPendiente(
            UUID tenantId, String plan, int ciclo, String monto, String proveedor, String referencia) {
        return new PaymentIntent(
                UUID.randomUUID(), tenantId, plan, ciclo, new BigDecimal(monto), "COP", proveedor, referencia, "x", Instant.now());
    }

    private static Tenant tenantConRenovacion(UUID tenantId, LocalDate renovacion) {
        try {
            Tenant tenant = new Tenant(
                    tenantId, "Tienda", "tienda", "pro", "America/Bogota", "retail", Instant.now());
            tenant.setPlanRenewsAt(renovacion);

            return tenant;
        } catch (Exception exception) {
            throw new IllegalStateException(exception);
        }
    }

    private static void campo(Object objeto, String nombre, Object valor) throws Exception {
        Field field = objeto.getClass().getDeclaredField(nombre);
        field.setAccessible(true);
        field.set(objeto, valor);
    }
}
