-- ---------------------------------------------------------------------------
-- Correo unico GLOBAL (P-20)
--
-- El login busca al usuario por correo antes de conocer el negocio, de modo que
-- el correo debe ser unico en toda la tabla y no solo por negocio. Con RLS, una
-- comprobacion hecha desde la aplicacion solo ve el negocio actual: el indice es
-- la garantia del motor. El servicio traduce la violacion a un 409.
-- ---------------------------------------------------------------------------

CREATE UNIQUE INDEX uq_users_email_global ON users (lower(email));

COMMENT ON INDEX uq_users_email_global IS
  'El correo identifica al usuario en el login (global): unico en toda la tabla.';
