-- Rol de aplicacion sin privilegios de superusuario.
--
-- Testcontainers crea el contenedor con un superusuario, y PostgreSQL exime a
-- los superusuarios de RLS incluso con FORCE: la prueba no mediria nada. La
-- aplicacion se conecta con este rol, igual que en produccion.
CREATE ROLE kubo_iam LOGIN PASSWORD 'kubo_iam_test' NOSUPERUSER NOCREATEDB NOCREATEROLE;
GRANT ALL ON SCHEMA public TO kubo_iam;
ALTER DATABASE test OWNER TO kubo_iam;
