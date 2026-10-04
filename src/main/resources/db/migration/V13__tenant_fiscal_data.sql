-- ---------------------------------------------------------------------------
-- Datos fiscales del emisor (facturacion electronica DIAN).
--
-- El proveedor tecnologico los necesita para emitir: NIT y su digito de
-- verificacion, direccion fiscal, regimen tributario y la resolucion/prefijo
-- de facturacion. Son datos del negocio: viven en `tenants` y viajan en el
-- token como el resto de la configuracion (zona horaria, vertical, plan).
-- ---------------------------------------------------------------------------
ALTER TABLE tenants
    ADD COLUMN tax_id varchar(20),
    ADD COLUMN tax_id_dv varchar(1),
    ADD COLUMN fiscal_address varchar(200),
    ADD COLUMN tax_regime varchar(30),
    ADD COLUMN invoice_resolution varchar(60),
    ADD COLUMN invoice_prefix varchar(6);
