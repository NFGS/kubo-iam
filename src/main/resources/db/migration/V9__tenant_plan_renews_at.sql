-- ---------------------------------------------------------------------------
-- Renovacion del plan (F6.2, ADR-0021).
--
-- El cobro es manual en este mercado (transferencia o Nequi): el operador
-- registra el pago renovando la fecha desde su herramienta. La fecha es el
-- recordatorio operativo; el corte del servicio sigue siendo explicito
-- (suspender), nunca automatico: la mora no puede sorprender a un negocio en
-- plena jornada sin aviso.
-- ---------------------------------------------------------------------------

ALTER TABLE tenants
    ADD COLUMN plan_renews_at date;
