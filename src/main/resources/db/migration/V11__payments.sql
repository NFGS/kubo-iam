-- ---------------------------------------------------------------------------
-- Puerto de cobro (F6.6, ADR-0026).
--
-- Los pagos son datos: cada intencion guarda negocio, plan, ciclo, monto y
-- estado, y la renovacion del plan se deriva del pago PAGADO. La referencia del
-- proveedor es unica por proveedor: un webhook repetido (los proveedores
-- reintentan) NO extiende dos veces el plan.
--
-- Los precios son datos del plan (moneda y ciclo), no codigo: cambiar una
-- tarifa es un UPDATE, no un despliegue.
-- ---------------------------------------------------------------------------

CREATE TABLE plan_prices (
    plan         varchar(40)   NOT NULL,
    currency     varchar(3)    NOT NULL DEFAULT 'COP',
    cycle_months integer       NOT NULL,
    amount       numeric(12, 2) NOT NULL,
    created_at   timestamptz   NOT NULL DEFAULT now(),
    PRIMARY KEY (plan, currency, cycle_months),
    CONSTRAINT ck_plan_prices_ciclo CHECK (cycle_months BETWEEN 1 AND 24),
    CONSTRAINT ck_plan_prices_monto CHECK (amount >= 0)
);

INSERT INTO plan_prices (plan, currency, cycle_months, amount) VALUES
    ('community', 'COP', 1, 0),
    ('pro', 'COP', 1, 49000),
    ('pro', 'COP', 12, 490000);

CREATE TABLE payment_intents (
    id           uuid PRIMARY KEY,
    tenant_id    uuid          NOT NULL,
    plan         varchar(40)   NOT NULL,
    cycle_months integer       NOT NULL,
    amount       numeric(12, 2) NOT NULL,
    currency     varchar(3)    NOT NULL DEFAULT 'COP',
    -- manual: el operador registra el pago; un proveedor real usa su nombre.
    provider     varchar(40)   NOT NULL DEFAULT 'manual',
    reference    varchar(120)  NOT NULL,
    status       varchar(20)   NOT NULL DEFAULT 'PENDING',
    detail       varchar(300),
    created_by   varchar(120),
    created_at   timestamptz   NOT NULL DEFAULT now(),
    paid_at      timestamptz,
    CONSTRAINT uq_payment_intents_referencia UNIQUE (provider, reference),
    CONSTRAINT ck_payment_intents_estado CHECK (status IN ('PENDING', 'PAID', 'FAILED', 'EXPIRED'))
);

CREATE INDEX idx_payment_intents_tenant ON payment_intents (tenant_id, created_at DESC);
CREATE INDEX idx_payment_intents_pendientes ON payment_intents (status) WHERE status = 'PENDING';
