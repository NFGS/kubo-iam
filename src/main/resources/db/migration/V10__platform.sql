-- ---------------------------------------------------------------------------
-- Rol de plataforma (F6.4, ADR-0025).
--
-- El operador de la plataforma NO es un usuario de negocio: vive en su propia
-- tabla, con su propio segundo factor (obligatorio) y su propia auditoria. Un
-- usuario de negocio no puede tener poder de plataforma, y un administrador de
-- plataforma no puede entrar a un negocio como si fuera su dueno.
--
-- Estas tablas no llevan RLS por negocio: son de la plataforma y no contienen
-- datos de negocio (solo quien opera y que hizo).
-- ---------------------------------------------------------------------------

CREATE TABLE platform_admins (
    id            uuid PRIMARY KEY,
    email         varchar(180) NOT NULL,
    password_hash varchar(120) NOT NULL,
    -- Cifrado con la misma llave que el TOTP de los usuarios (KUBO_TOTP_ENCRYPTION_KEY).
    totp_secret   varchar(200) NOT NULL,
    status        varchar(20)  NOT NULL DEFAULT 'ACTIVE',
    last_login_at timestamptz,
    created_at    timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT uq_platform_admins_email UNIQUE (email),
    CONSTRAINT ck_platform_admins_status CHECK (status IN ('ACTIVE', 'DISABLED'))
);

CREATE TABLE platform_audit (
    id          uuid PRIMARY KEY,
    actor_id    uuid         NOT NULL,
    actor_email varchar(180) NOT NULL,
    action      varchar(40)  NOT NULL,
    tenant_id   uuid,
    detail      varchar(300),
    ip          varchar(60),
    created_at  timestamptz  NOT NULL DEFAULT now()
);

CREATE INDEX idx_platform_audit_created ON platform_audit (created_at DESC);
