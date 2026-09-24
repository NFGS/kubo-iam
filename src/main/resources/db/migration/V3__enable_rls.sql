-- ---------------------------------------------------------------------------
-- Kubo IAM - Row Level Security (P-02)
--
-- A partir de aqui el aislamiento entre negocios lo impone el motor, no la
-- disciplina del codigo. Cada peticion abre una transaccion y fija:
--   * `app.tenant_id` cuando llega identidad verificada (rutas de negocio), o
--   * `app.system` cuando la operacion es de sistema (autenticacion, cadena de
--     auditoria global, semilla). La identidad necesita leer usuarios por correo
--     antes de conocer el negocio, y la cadena de auditoria cruza negocios por
--     diseno; ambas son operaciones de sistema, no de negocio.
--
-- `tenants` queda sin RLS a proposito: el registro debe comprobar la unicidad
-- global del slug. `mail_outbox` es un buzon de demostracion: solo el sistema
-- escribe y lee en el.
--
-- FORCE es imprescindible: el rol kubo_iam es dueno de las tablas y, sin FORCE,
-- PostgreSQL lo eximiria de las politicas.
-- ---------------------------------------------------------------------------

-- Usuarios -------------------------------------------------------------------
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS users_tenant_isolation ON users;
CREATE POLICY users_tenant_isolation ON users
    USING (
        tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
        OR current_setting('app.system', true) = 'on'
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
        OR current_setting('app.system', true) = 'on'
    );

-- Tokens de refresco ---------------------------------------------------------
ALTER TABLE refresh_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE refresh_tokens FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS refresh_tokens_tenant_isolation ON refresh_tokens;
CREATE POLICY refresh_tokens_tenant_isolation ON refresh_tokens
    USING (
        current_setting('app.system', true) = 'on'
        OR user_id IN (
            SELECT id FROM users
            WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
        )
    )
    WITH CHECK (
        current_setting('app.system', true) = 'on'
        OR user_id IN (
            SELECT id FROM users
            WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
        )
    );

-- Bitacora de auditoria ------------------------------------------------------
-- La cadena es global: el servicio de auditoria opera como sistema.
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS audit_logs_tenant_isolation ON audit_logs;
CREATE POLICY audit_logs_tenant_isolation ON audit_logs
    USING (
        current_setting('app.system', true) = 'on'
        OR tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
    )
    WITH CHECK (
        current_setting('app.system', true) = 'on'
        OR tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
    );

-- Recuperacion de contrasena -------------------------------------------------
ALTER TABLE password_reset_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE password_reset_tokens FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS password_reset_tokens_tenant_isolation ON password_reset_tokens;
CREATE POLICY password_reset_tokens_tenant_isolation ON password_reset_tokens
    USING (
        current_setting('app.system', true) = 'on'
        OR user_id IN (
            SELECT id FROM users
            WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
        )
    )
    WITH CHECK (
        current_setting('app.system', true) = 'on'
        OR user_id IN (
            SELECT id FROM users
            WHERE tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid
        )
    );

-- Buzon de correo de demostracion --------------------------------------------
ALTER TABLE mail_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE mail_outbox FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS mail_outbox_system_only ON mail_outbox;
CREATE POLICY mail_outbox_system_only ON mail_outbox
    USING (current_setting('app.system', true) = 'on')
    WITH CHECK (current_setting('app.system', true) = 'on');
