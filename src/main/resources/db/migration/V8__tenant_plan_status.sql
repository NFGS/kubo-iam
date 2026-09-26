-- ---------------------------------------------------------------------------
-- Estado comercial del negocio (P-27, ADR-0021).
--
-- `plan` ya existia; falta el estado: un negocio suspendido (mora, abuso) no
-- puede iniciar sesion, pero sus datos quedan intactos y exportables. La
-- suspension no puede convertirse en rehen de los datos.
-- ---------------------------------------------------------------------------

ALTER TABLE tenants
    ADD COLUMN status varchar(20) NOT NULL DEFAULT 'ACTIVE';

ALTER TABLE tenants
    ADD CONSTRAINT ck_tenants_status CHECK (status IN ('ACTIVE', 'SUSPENDED'));

-- Los planes vigentes se validan en la aplicacion (catalogo compartido con el
-- ERP, como los verticales): la base no debe frenar un plan nuevo.
ALTER TABLE tenants
    ADD CONSTRAINT ck_tenants_plan_no_vacio CHECK (btrim(plan) <> '');
