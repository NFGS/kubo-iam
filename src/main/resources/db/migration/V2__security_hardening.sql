-- ---------------------------------------------------------------------------
-- Kubo IAM - endurecimiento de seguridad (fase 1)
--
--   * P-23: version del algoritmo de hash de la cadena de auditoria.
--   * P-11: bloqueo de cuenta tras N intentos fallidos.
--   * P-04: recuperacion de contrasena con token de un solo uso.
--   * Buzon de correo de demostracion (transporte `log`).
-- ---------------------------------------------------------------------------

-- P-23 ---------------------------------------------------------------------
-- Las filas anteriores a la correccion A-08 se hashearon con nanosegundos y no
-- son verificables por contenido; la version permite identificarlas y tratarlas
-- como solo verificables por enlace. La version 2 es el algoritmo vigente
-- (instante truncado a microsegundos, la precision real de PostgreSQL).
ALTER TABLE audit_logs ADD COLUMN hash_version smallint NOT NULL DEFAULT 2;

-- P-11 ---------------------------------------------------------------------
ALTER TABLE users ADD COLUMN failed_login_attempts integer NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN locked_until timestamptz;

-- P-04 ---------------------------------------------------------------------
-- Solo se guarda el SHA-256 del token: quien lea la base no puede usarlo.
CREATE TABLE password_reset_tokens (
    id         uuid PRIMARY KEY,
    user_id    uuid        NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash varchar(64) NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at    timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT uq_password_reset_hash UNIQUE (token_hash)
);

CREATE INDEX idx_password_reset_user ON password_reset_tokens (user_id);

-- Buzon de demostracion ------------------------------------------------------
-- Con `KUBO_MAIL_TRANSPORT=log` (por defecto) el correo no sale del servidor:
-- se guarda aqui para que la prueba de humo y el operador puedan verlo. Con
-- `smtp` el cuerpo NO se persiste (columna en NULL) y sale por el servidor real.
CREATE TABLE mail_outbox (
    id         uuid PRIMARY KEY,
    recipient  varchar(180) NOT NULL,
    subject    varchar(200) NOT NULL,
    body       text,
    transport  varchar(20)  NOT NULL,
    created_at timestamptz  NOT NULL DEFAULT now()
);

CREATE INDEX idx_mail_outbox_created ON mail_outbox (created_at DESC);

COMMENT ON COLUMN audit_logs.hash_version IS
  'Version del algoritmo de hash: 2 = vigente; 1 = historico no verificable por contenido.';
COMMENT ON TABLE mail_outbox IS
  'Buzon de correo de demostracion (transporte log). En produccion el cuerpo no se persiste.';
COMMENT ON TABLE password_reset_tokens IS
  'Tokens de recuperacion de contrasena: solo su SHA-256, un solo uso y con expiracion.';
