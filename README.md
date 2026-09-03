# Registro del Foro de Ciberseguridad 2026

Aplicación web para solicitar, aprobar y controlar el acceso al Foro de Ciberseguridad de ACLUVAQ.

## Funcionalidades

- Registro rápido con validación de correo corporativo o educativo.
- Revisión administrativa y clasificación por empresa, puesto e influencia.
- Emisión de boleto móvil únicamente después de la aprobación.
- QR firmado mediante HMAC, sin datos personales dentro del código.
- Escáner web con cámara del teléfono y captura manual de respaldo.
- Registro de asistencia, detección de reingresos y conteo de ausentes.
- Persistencia en Cloudflare D1.

## Variables de producción

- `ADMIN_KEY`: clave de acceso al panel administrativo completo.
- `SCANNER_KEY`: clave que autoriza **únicamente** el endpoint `/api/checkin` (control de acceso/escáner). Debe ser **diferente de `ADMIN_KEY`** para que el personal de puerta no reciba la credencial de administración total. Se envía en el encabezado `x-scanner-key`. El endpoint también acepta `ADMIN_KEY` (vía `x-admin-key`) para que un administrador pueda escanear, pero `SCANNER_KEY` no otorga ningún otro acceso.
- `TICKET_SECRET`: secreto aleatorio de alta entropía para firmar los boletos.
- `RESEND_API_KEY`: llave privada de la cuenta de Resend.
- `EMAIL_FROM`: remitente verificado, por ejemplo `Foro ACLUVAQ <foro@dominio.org>`.

Los secretos no deben incluirse en el repositorio. La validación institucional rechaza dominios personales conocidos; no sustituye una verificación de propiedad mediante correo de confirmación.

Los envíos se registran en `email_deliveries`. Si Resend no está configurado o presenta una interrupción, la solicitud se conserva y el administrador puede reenviar posteriormente el boleto.

## Migraciones de base de datos (D1)

El esquema se define como migraciones SQL incrementales y numeradas en `.openai/drizzle/` (`0000`, `0001`, …). El binding de la base es `DB` y el código accede mediante `env.DB`. Las migraciones son idempotentes (`CREATE TABLE IF NOT EXISTS` / `CREATE INDEX IF NOT EXISTS`), por lo que reaplicarlas no destruye datos.

**Este repositorio no contiene un workflow de CI/CD que aplique las migraciones automáticamente.** No hay `.github/workflows` ni un `wrangler.toml` versionado que ejecute las migraciones. La aplicación de cada archivo `.sql` debe realizarse de forma explícita al desplegar, con uno de estos mecanismos:

- **Plataforma de hosting (OpenAI Apps):** `scripts/build.js` copia `.openai/drizzle/` dentro del bundle publicado. La aplicación de esas migraciones depende del proceso de despliegue de la plataforma y no puede verificarse desde este repositorio; confírmalo en el panel de la plataforma después de publicar.
- **Wrangler (método verificable y recomendado como respaldo):** aplica los archivos directamente contra D1. Sustituye `<D1_DATABASE>` por el nombre real de tu base:

  ```bash
  # DEV / entorno local o remoto de desarrollo
  wrangler d1 execute <D1_DATABASE> --file=.openai/drizzle/0003_rate_limits.sql

  # PROD
  wrangler d1 execute <D1_DATABASE> --remote --env production --file=.openai/drizzle/0003_rate_limits.sql
  ```

  Aplica en orden cualquier migración pendiente que aún no exista en el entorno. Para verificar que la tabla quedó creada:

  ```bash
  wrangler d1 execute <D1_DATABASE> --command "SELECT name FROM sqlite_master WHERE type='table' AND name='rate_limits';"
  ```

La migración `0003_rate_limits.sql` (tabla `rate_limits`) es requerida por el rate limiting. El código **falla en abierto** si la tabla no existe (no bloquea a los usuarios), por lo que el despliegue del código no se rompe aunque la migración aún no se haya aplicado; sin embargo, el rate limiting no protege de verdad hasta aplicarla.

## Rutas

- `/`: solicitud de registro y consulta de estado.
- `/admin`: revisión y aprobación de solicitudes.
- `/scanner`: control de acceso mediante cámara.
- `/ticket`: boleto digital firmado.

## Desarrollo

```bash
node scripts/vendor-qrcode.cjs
node scripts/build.js
node --check dist/server/index.js
```

El generador QR incorporado deriva de *QRCode for JavaScript* de Kazuhiko Arase, distribuido bajo licencia MIT.
