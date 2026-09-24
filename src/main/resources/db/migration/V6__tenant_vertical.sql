-- ---------------------------------------------------------------------------
-- Vertical del negocio (ADR-0013, P-17).
--
-- El vertical activa un paquete de configuracion (terminologia, impuesto por
-- defecto, comportamiento del punto de venta) sin tocar el nucleo. El catalogo
-- de paquetes vive en el ERP; aqui se guarda cual tiene activo el negocio.
-- ---------------------------------------------------------------------------

ALTER TABLE tenants
    ADD COLUMN vertical varchar(40) NOT NULL DEFAULT 'retail';

-- Un valor vacio dejaria al ERP sin paquete que aplicar; se detiene en la
-- puerta. El conjunto valido lo valida la aplicacion (es un contrato con el ERP).
ALTER TABLE tenants
    ADD CONSTRAINT ck_tenants_vertical_no_vacia CHECK (btrim(vertical) <> '');
