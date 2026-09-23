-- ---------------------------------------------------------------------------
-- Kubo — Row Level Security (listo para activar en la fase 2)
--
-- El aislamiento por negocio ya se aplica en la capa de aplicacion (todas las
-- consultas filtran por tenant_id). Este script agrega la segunda barrera a
-- nivel de motor: aunque una consulta olvidara el filtro, PostgreSQL no
-- devolveria filas de otro tenant.
--
-- Requisito para activarlo: cada transaccion debe ejecutar
--     SET LOCAL app.tenant_id = '<uuid del negocio>';
-- mediante un interceptor. Sin esa variable las consultas no devuelven filas.
--
-- Uso:
--   psql "postgres://kubo_iam@localhost:5433/kubo_iam" -f db/rls/enable-rls.sql
-- ---------------------------------------------------------------------------

ALTER TABLE users          ENABLE ROW LEVEL SECURITY;
ALTER TABLE refresh_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs     ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS users_tenant_isolation ON users;
CREATE POLICY users_tenant_isolation ON users
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

DROP POLICY IF EXISTS refresh_tokens_tenant_isolation ON refresh_tokens;
CREATE POLICY refresh_tokens_tenant_isolation ON refresh_tokens
    USING (user_id IN (
        SELECT id FROM users
        WHERE tenant_id = current_setting('app.tenant_id', true)::uuid
    ));

DROP POLICY IF EXISTS audit_logs_tenant_isolation ON audit_logs;
CREATE POLICY audit_logs_tenant_isolation ON audit_logs
    USING (tenant_id = current_setting('app.tenant_id', true)::uuid);

-- El rol de la aplicacion no debe poder saltarse las politicas.
ALTER TABLE users          FORCE ROW LEVEL SECURITY;
ALTER TABLE refresh_tokens FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_logs     FORCE ROW LEVEL SECURITY;
