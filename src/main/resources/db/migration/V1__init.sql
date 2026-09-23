-- ---------------------------------------------------------------------------
-- Kubo IAM - esquema inicial
-- ---------------------------------------------------------------------------

CREATE TABLE tenants (
    id         uuid PRIMARY KEY,
    name       varchar(160) NOT NULL,
    slug       varchar(80)  NOT NULL,
    plan       varchar(40)  NOT NULL DEFAULT 'community',
    created_at timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT uq_tenants_slug UNIQUE (slug)
);

CREATE TABLE users (
    id            uuid PRIMARY KEY,
    tenant_id     uuid         NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    email         varchar(180) NOT NULL,
    password_hash varchar(120) NOT NULL,
    full_name     varchar(160) NOT NULL,
    role          varchar(40)  NOT NULL,
    status        varchar(30)  NOT NULL DEFAULT 'ACTIVE',
    last_login_at timestamptz,
    created_at    timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT uq_users_tenant_email UNIQUE (tenant_id, email)
);

CREATE TABLE refresh_tokens (
    id          uuid PRIMARY KEY,
    user_id     uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash  varchar(64) NOT NULL,
    expires_at  timestamptz NOT NULL,
    revoked_at  timestamptz,
    replaced_by uuid,
    created_at  timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_refresh_tokens_hash UNIQUE (token_hash)
);

CREATE TABLE audit_logs (
    id         uuid PRIMARY KEY,
    tenant_id  uuid,
    user_id    uuid,
    action     varchar(80)  NOT NULL,
    entity     varchar(80),
    entity_id  varchar(80),
    ip         varchar(60),
    user_agent varchar(240),
    prev_hash  varchar(64),
    hash       varchar(64) NOT NULL,
    created_at timestamptz  NOT NULL DEFAULT now()
);

CREATE INDEX idx_users_tenant        ON users (tenant_id);
CREATE INDEX idx_users_email         ON users (email);
CREATE INDEX idx_refresh_user        ON refresh_tokens (user_id);
CREATE INDEX idx_refresh_expires     ON refresh_tokens (expires_at);
CREATE INDEX idx_audit_tenant_date   ON audit_logs (tenant_id, created_at DESC);
CREATE INDEX idx_audit_action        ON audit_logs (action);

COMMENT ON TABLE audit_logs IS
  'Bitacora append-only con cadena de hash: cada registro encadena el hash del anterior.';
COMMENT ON TABLE refresh_tokens IS
  'Solo se almacena el SHA-256 del token de refresco, nunca el valor en claro.';
COMMENT ON COLUMN users.password_hash IS
  'Hash BCrypt (coste 10). La contrasena jamas se persiste en claro.';
