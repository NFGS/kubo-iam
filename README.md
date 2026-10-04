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
- **Bloqueo de cuenta** tras N intentos fallidos (5 por defecto, 15 minutos);
  también cubre los códigos TOTP inválidos y al operador de plataforma.
- **Segundo factor TOTP** del propietario y del operador, con el secreto cifrado
  en reposo y desafío `typ=totp` que el gateway no acepta como token de acceso.
- **Recuperación de contraseña** con enlace de un solo uso (transporte `log` para
  demostración o `smtp` real).
- **Planes comerciales** (cupos y suspensión), **cobro** con intención de pago y
  webhook firmado, y **reino de plataforma** separado del negocio (ADR-0021,
  ADR-0025 y ADR-0026).
- **Datos fiscales del negocio** (NIT con DV calculado, dirección, régimen,
  resolución y prefijo) que viajan en el token para la facturación electrónica.
- Bitácora de auditoría **append-only con cadena de hash versionada**.
- **RLS activo**: cada petición fija `app.tenant_id` (o la marca de sistema) y el
  motor garantiza el aislamiento entre negocios.
- Hash de contraseñas con **BCrypt** (coste 10).

## Endpoints

| Método | Ruta | Descripción | Auth |
| --- | --- | --- | --- |
| POST | `/api/v1/auth/register` | Crea negocio + usuario propietario | Público |
| POST | `/api/v1/auth/login` | Inicia sesión | Público |
| POST | `/api/v1/auth/refresh` | Rota el refresh token | Público |
| POST | `/api/v1/auth/logout` | Revoca el refresh token | Público |
| POST | `/api/v1/auth/forgot-password` | Envía el enlace de recuperación (siempre 204) | Público |
| POST | `/api/v1/auth/reset-password` | Consume el enlace y cambia la contraseña | Público |
| GET | `/api/v1/auth/me` | Perfil del usuario autenticado | `X-User-Id` |
| POST | `/api/v1/auth/totp/setup` · `/enable` · `/disable` | Ciclo del segundo factor del usuario | `X-User-Id` |
| POST | `/api/v1/auth/totp/verify` | Cambia el desafío TOTP por la sesión | Público |
| GET | `/api/v1/auth/.well-known/jwks.json` | Llave pública RSA (JWKS) | Público |
| GET/PATCH | `/api/v1/tenants/me` | Perfil del negocio (vertical, zona horaria, plan y datos fiscales) | `X-User-Id` |
| GET | `/api/v1/tenants/plans` · `/tenants/me/prices` | Catálogo de planes y precios | `X-User-Id` |
| POST | `/api/v1/tenants/me/payments` | Intención de pago del plan | `X-User-Id` |
| POST | `/api/v1/webhooks/payments/{proveedor}` | Confirmación firmada (HMAC-SHA256) | Firma |
| POST | `/api/v1/platform/auth/login` · `/auth/totp` | Acceso del operador (TOTP obligatorio) | Público |
| GET | `/api/v1/platform/tenants` · `/audit` · `/payments` | Panel del operador | `X-Platform-Admin-Id` |
| PATCH | `/api/v1/platform/tenants/{id}` | Suspender, reactivar o renovar | `X-Platform-Admin-Id` |
| POST | `/api/v1/platform/payments/{id}/confirm` | Registrar un pago pendiente | `X-Platform-Admin-Id` |
| POST | `/api/v1/platform/totp/rotate` | Rotar el segundo factor del operador | `X-Platform-Admin-Id` |
| GET | `/api/v1/users` | Usuarios del negocio | `X-User-Id` |
| GET | `/api/v1/audit` | Últimos 50 eventos de auditoría | `X-User-Id` |
| GET | `/api/v1/health` | Estado del servicio y de la base | Público |

## Modelo de seguridad

1. La contraseña se almacena como hash BCrypt; nunca viaja ni se guarda en claro.
2. El access token vive 15 minutos y se firma con RSA (RS256).
3. El refresh token es un valor aleatorio de 384 bits; solo se persiste su SHA-256.
4. Al rotar, el token anterior se marca como revocado. Si vuelve a usarse, se revocan
   todos los tokens vigentes del usuario (detección de robo de token).
5. La auditoría encadena hashes **versionados** (`hash_version`): alterar un
   registro intermedio rompe la cadena y el verificador reporta qué versiones
   pudo comprobar por contenido.
6. Tras 5 intentos fallidos la cuenta se bloquea 15 minutos; el contador vive en
   una transacción independiente para que el rollback del login no lo borre.
7. El enlace de recuperación se guarda **hasheado**, vence en 30 minutos, es de un
   solo uso y al consumirse revoca todas las sesiones.
8. El refresh token no llega al navegador: el gateway lo deja en cookie `httpOnly`.
9. Renovar una sesión **revalida** el estado del usuario y la suspensión del
   negocio: suspender corta también las sesiones vivas al siguiente refresco.
10. El código TOTP fallido alimenta el mismo contador de bloqueo que la
    contraseña; el operador de plataforma tiene su propio contador (V12).

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
# Unitarias + integración con PostgreSQL real (Testcontainers) + cobertura
mvn verify
```

Hoy: **79 pruebas** (0 fallos) y **85.2 %** de cobertura en `application` y
`domain`, con gate JaCoCo de 80 %.

## Notas de arquitectura

- **Capa de dominio** (`domain`): entidades y repositorios, sin dependencias de framework HTTP.
- **Capa de aplicación** (`application`): casos de uso y servicios de token/auditoría.
- **Capa de presentación** (`web`): controladores REST y manejo global de errores.
- **Infraestructura** (`infra`): semilla de datos y transportes de correo.
- **Aislamiento en dos capas**: toda consulta filtra por `tenant_id` y además RLS
  está activo con `FORCE` (migración `V3__enable_rls.sql`). El `TenantRlsFilter`
  fija `app.tenant_id` por petición; las operaciones de identidad (login por
  correo, rotación, cadena de auditoría global, semilla) usan la marca
  `app.system`. Ver `kubo-docs/adr/ADR-0010-rls-activo.md`.

## Observabilidad y calidad (Fase 2)

- **Trazas OpenTelemetry**: `spring-boot-starter-opentelemetry` exporta al
  collector (`OTEL_EXPORTER_OTLP_ENDPOINT`); sin collector el servicio arranca
  igual y no exporta métricas (solo trazas).
- **Pruebas de integración**: `RlsIntegrationTest` levanta PostgreSQL con
  Testcontainers, aplica las migraciones Flyway y verifica RLS y la cadena de
  auditoría contra un motor real (rol sin superusuario, como en producción).
- **Cobertura**: JaCoCo con gate de **80 %** en `co.kubo.iam.application` y
  `co.kubo.iam.domain` (`mvn verify`); hoy 85.2 %.
