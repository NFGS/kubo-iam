-- ---------------------------------------------------------------------------
-- Kubo IAM — Row Level Security
--
-- Este script quedo superado por la migracion Flyway
-- `src/main/resources/db/migration/V3__enable_rls.sql`, que se aplica sola al
-- arrancar el servicio (KUBO_RUN_MIGRATIONS / Flyway habilitado).
--
-- Se conserva como referencia de las politicas vigentes y para inspeccion
-- manual. NO ejecutarlo a mano salvo en una base que no use Flyway: aplicarlo
-- dos veces recrea las politicas (el script hace DROP POLICY IF EXISTS, asi que
-- es idempotente).
--
-- Requisito de operacion: cada transaccion fija su contexto con
--     select set_config('app.tenant_id', '<uuid del negocio>', true);
-- o, para operaciones de sistema (autenticacion, cadena de auditoria, semilla):
--     select set_config('app.system', 'on', true);
-- El interceptor `TenantRlsFilter` lo hace automaticamente por peticion.
-- ---------------------------------------------------------------------------

\i src/main/resources/db/migration/V3__enable_rls.sql
