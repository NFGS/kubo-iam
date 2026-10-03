-- ---------------------------------------------------------------------------
-- P-11 en el reino de plataforma (ADR-0025).
--
-- El segundo factor obligatorio no puede ser la puerta sin freno de la fuerza
-- bruta: el contador y el bloqueo son los mismos que usan los usuarios del
-- negocio. Los operadores existentes arrancan en cero.
-- ---------------------------------------------------------------------------
ALTER TABLE platform_admins
    ADD COLUMN failed_login_attempts integer NOT NULL DEFAULT 0,
    ADD COLUMN locked_until timestamptz;
