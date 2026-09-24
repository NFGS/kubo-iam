-- ---------------------------------------------------------------------------
-- Segundo factor del propietario (P-30, ADR-0015).
--
-- El secreto TOTP se guarda CIFRADO (AES-256-GCM): una copia de la base no
-- debe permitir generar codigos validos. `totp_enabled` separa el secreto
-- generado (aun sin confirmar) del segundo factor activo.
-- ---------------------------------------------------------------------------

ALTER TABLE users
    ADD COLUMN totp_secret varchar(200),
    ADD COLUMN totp_enabled boolean NOT NULL DEFAULT false;

-- Un usuario con el segundo factor activo siempre tiene secreto.
ALTER TABLE users
    ADD CONSTRAINT ck_users_totp_secret CHECK (NOT totp_enabled OR totp_secret IS NOT NULL);
