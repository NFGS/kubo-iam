# kubo-iam

Servicio de identidad, tenants, roles y auditoría de Kubo.

| Campo | Valor |
| --- | --- |
| Stack | Java 21 · Spring Boot 4.1 · Spring Security · Spring Data JPA · Flyway |
| Base de datos | PostgreSQL 17 (`kubo_iam`) |
| Puerto | 8081 (contenedor) · 9081 (host) |
| Ruta base | `/api/v1` |

## Responsabilidades

- Registro de negocios (tenants) y usuarios.
- Inicio de sesión y emisión de **JWT RS256** con par de llaves RSA.
- Publicación del **JWKS** que consume el API Gateway para verificar firmas.
- Rotación de *refresh tokens* con detección de reutilización.
- Bitácora de auditoría **append-only con cadena de hash**.
- Hash de contraseñas con **BCrypt** (coste 10).

## Endpoints

| Método | Ruta | Descripción | Auth |
| --- | --- | --- | --- |
| POST | `/api/v1/auth/register` | Crea negocio + usuario propietario | Público |
| POST | `/api/v1/auth/login` | Inicia sesión | Público |
| POST | `/api/v1/auth/refresh` | Rota el refresh token | Público |
| POST | `/api/v1/auth/logout` | Revoca el refresh token | Público |
| GET | `/api/v1/auth/me` | Perfil del usuario autenticado | `X-User-Id` |
| GET | `/api/v1/auth/.well-known/jwks.json` | Llave pública RSA (JWKS) | Público |
| GET | `/api/v1/users` | Usuarios del negocio | `X-User-Id` |
| GET | `/api/v1/audit` | Últimos 50 eventos de auditoría | `X-User-Id` |
| GET | `/api/v1/health` | Estado del servicio y de la base | Público |

## Modelo de seguridad

1. La contraseña se almacena como hash BCrypt; nunca viaja ni se guarda en claro.
2. El access token vive 15 minutos y se firma con RSA (RS256).
3. El refresh token es un valor aleatorio de 384 bits; solo se persiste su SHA-256.
4. Al rotar, el token anterior se marca como revocado. Si vuelve a usarse, se revocan
   todos los tokens vigentes del usuario (detección de robo de token).
5. La auditoría encadena hashes: alterar un registro intermedio rompe la cadena.

## Ejecución local

```bash
# Base de datos (desde kubo-infra)
docker compose up -d postgres

# Servicio
mvn spring-boot:run
```

Variables de entorno relevantes (ver `.env.example`):

| Variable | Uso |
| --- | --- |
| `SPRING_DATASOURCE_URL` | Cadena JDBC de `kubo_iam` |
| `KUBO_JWT_PRIVATE_KEY` | Llave RSA en PEM. Vacía ⇒ par efímero (solo desarrollo) |
| `KUBO_SEED_ENABLED` | Crea negocio y usuarios de demostración |
| `KUBO_ADMIN_EMAIL` / `KUBO_ADMIN_PASSWORD` | Credenciales sembradas |

## Pruebas

```bash
mvn test
```

## Notas de arquitectura

- **Capa de dominio** (`domain`): entidades y repositorios, sin dependencias de framework HTTP.
- **Capa de aplicación** (`application`): casos de uso y servicios de token/auditoría.
- **Capa de presentación** (`web`): controladores REST y manejo global de errores.
- **Infraestructura** (`infra`): semilla de datos.
- El aislamiento por tenant se aplica en la capa de aplicación (toda consulta filtra por
  `tenant_id`). El script `db/rls/enable-rls.sql` deja lista la política de *row level
  security* para activarla en la siguiente fase, cuando exista el interceptor de transacción
  que fija `app.tenant_id`.
