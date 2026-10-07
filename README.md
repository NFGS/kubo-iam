# kubo-iam
[!\[CI](https://github.com/NFGS/kubo-iam/actions/workflows/ci.yml/badge.svg)\]([https://github.com/NFGS/kubo-iam/actions/workflows/ci.yml](https://github.com/NFGS/kubo-iam/actions/workflows/ci.yml))
> Parte del proyecto **Kubo** — [kubo-workspace](https://github.com/NFGS/kubo-workspace) (ERP + CRM autoalojable para PYMES).
Servicio de identidad, tenants, roles y auditoría de Kubo.
<table header-row="true">
<tr>
<td>Campo</td>
<td>Valor</td>
</tr>
<tr>
<td>Stack</td>
<td>Java 21 · Spring Boot 4.1 · Spring Security · Spring Data JPA · Flyway</td>
</tr>
<tr>
<td>Base de datos</td>
<td>PostgreSQL 17 (`kubo_iam`)</td>
</tr>
<tr>
<td>Puerto</td>
<td>8081 (contenedor) · 9081 (host)</td>
</tr>
<tr>
<td>Ruta base</td>
<td>`/api/v1`</td>
</tr>
</table>
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
<table header-row="true">
<tr>
<td>Método</td>
<td>Ruta</td>
<td>Descripción</td>
<td>Auth</td>
</tr>
<tr>
<td>POST</td>
<td>`/api/v1/auth/register`</td>
<td>Crea negocio + usuario propietario</td>
<td>Público</td>
</tr>
<tr>
<td>POST</td>
<td>`/api/v1/auth/login`</td>
<td>Inicia sesión</td>
<td>Público</td>
</tr>
<tr>
<td>POST</td>
<td>`/api/v1/auth/refresh`</td>
<td>Rota el refresh token</td>
<td>Público</td>
</tr>
<tr>
<td>POST</td>
<td>`/api/v1/auth/logout`</td>
<td>Revoca el refresh token</td>
<td>Público</td>
</tr>
<tr>
<td>POST</td>
<td>`/api/v1/auth/forgot-password`</td>
<td>Envía el enlace de recuperación (siempre 204)</td>
<td>Público</td>
</tr>
<tr>
<td>POST</td>
<td>`/api/v1/auth/reset-password`</td>
<td>Consume el enlace y cambia la contraseña</td>
<td>Público</td>
</tr>
<tr>
<td>GET</td>
<td>`/api/v1/auth/me`</td>
<td>Perfil del usuario autenticado</td>
<td>`X-User-Id`</td>
</tr>
<tr>
<td>POST</td>
<td>`/api/v1/auth/totp/setup` · `/enable` · `/disable`</td>
<td>Ciclo del segundo factor del usuario</td>
<td>`X-User-Id`</td>
</tr>
<tr>
<td>POST</td>
<td>`/api/v1/auth/totp/verify`</td>
<td>Cambia el desafío TOTP por la sesión</td>
<td>Público</td>
</tr>
<tr>
<td>GET</td>
<td>`/api/v1/auth/.well-known/jwks.json`</td>
<td>Llave pública RSA (JWKS)</td>
<td>Público</td>
</tr>
<tr>
<td>GET/PATCH</td>
<td>`/api/v1/tenants/me`</td>
<td>Perfil del negocio (vertical, zona horaria, plan y datos fiscales)</td>
<td>`X-User-Id`</td>
</tr>
<tr>
<td>GET</td>
<td>`/api/v1/tenants/plans` · `/tenants/me/prices`</td>
<td>Catálogo de planes y precios</td>
<td>`X-User-Id`</td>
</tr>
<tr>
<td>POST</td>
<td>`/api/v1/tenants/me/payments`</td>
<td>Intención de pago del plan</td>
<td>`X-User-Id`</td>
</tr>
<tr>
<td>POST</td>
<td>`/api/v1/webhooks/payments/{proveedor}`</td>
<td>Confirmación firmada (HMAC-SHA256)</td>
<td>Firma</td>
</tr>
<tr>
<td>POST</td>
<td>`/api/v1/platform/auth/login` · `/auth/totp`</td>
<td>Acceso del operador (TOTP obligatorio)</td>
<td>Público</td>
</tr>
<tr>
<td>GET</td>
<td>`/api/v1/platform/tenants` · `/audit` · `/payments`</td>
<td>Panel del operador</td>
<td>`X-Platform-Admin-Id`</td>
</tr>
<tr>
<td>PATCH</td>
<td>`/api/v1/platform/tenants/{id}`</td>
<td>Suspender, reactivar o renovar</td>
<td>`X-Platform-Admin-Id`</td>
</tr>
<tr>
<td>POST</td>
<td>`/api/v1/platform/payments/{id}/confirm`</td>
<td>Registrar un pago pendiente</td>
<td>`X-Platform-Admin-Id`</td>
</tr>
<tr>
<td>POST</td>
<td>`/api/v1/platform/totp/rotate`</td>
<td>Rotar el segundo factor del operador</td>
<td>`X-Platform-Admin-Id`</td>
</tr>
<tr>
<td>GET</td>
<td>`/api/v1/users`</td>
<td>Usuarios del negocio</td>
<td>`X-User-Id`</td>
</tr>
<tr>
<td>GET</td>
<td>`/api/v1/audit`</td>
<td>Últimos 50 eventos de auditoría</td>
<td>`X-User-Id`</td>
</tr>
<tr>
<td>GET</td>
<td>`/api/v1/health`</td>
<td>Estado del servicio y de la base</td>
<td>Público</td>
</tr>
</table>
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
<table header-row="true">
<tr>
<td>Variable</td>
<td>Uso</td>
</tr>
<tr>
<td>`SPRING_DATASOURCE_URL`</td>
<td>Cadena JDBC de `kubo_iam`</td>
</tr>
<tr>
<td>`KUBO_JWT_PRIVATE_KEY`</td>
<td>Llave RSA en PEM. Vacía ⇒ par efímero (solo desarrollo)</td>
</tr>
<tr>
<td>`KUBO_SEED_ENABLED`</td>
<td>Crea negocio y usuarios de demostración</td>
</tr>
<tr>
<td>`KUBO_ADMIN_EMAIL` / `KUBO_ADMIN_PASSWORD`</td>
<td>Credenciales sembradas</td>
</tr>
</table>
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
