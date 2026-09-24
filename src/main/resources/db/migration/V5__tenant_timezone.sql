-- ---------------------------------------------------------------------------
-- Zona horaria del negocio (ADR-0012).
--
-- El dia comercial, los reportes y el comprobante deben usar la hora del
-- negocio: un cierre a las 21:00 en Bogota no puede caer en el dia siguiente
-- porque el servidor piense en UTC. El valor viaja en el token de acceso y el
-- gateway lo propaga como cabecera a los servicios.
-- ---------------------------------------------------------------------------

ALTER TABLE tenants
    ADD COLUMN timezone varchar(60) NOT NULL DEFAULT 'America/Bogota';

-- Un valor vacio romperia el calculo del dia comercial en el ERP; se detiene en
-- la puerta. La validez contra la base de zonas (tzdata) se comprueba al usarla.
ALTER TABLE tenants
    ADD CONSTRAINT ck_tenants_timezone_no_vacia CHECK (btrim(timezone) <> '');
