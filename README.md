# Registro del Foro de Ciberseguridad ACLUVAQ 2026

Aplicación Cloudflare Worker + D1 para registro, aprobación, boleto QR firmado,
notificaciones con Resend, control de acceso, asistencia y exportación CSV.

## Rutas

- `/`: registro público y consulta de estado.
- `/embed`: formulario compacto para un iframe del micrositio ACLUVAQ.
- `/admin`: administración, configuración, CSV y respaldo manual.
- `/scanner`: lector QR para iPhone, iPad, Android y navegadores modernos.
- `/ticket`: boleto móvil firmado mediante HMAC.

```html
<iframe
  src="https://foro-ciberseguridad-registro.cbasulto.chatgpt.site/embed"
  width="100%"
  height="1100"
  frameborder="0"
  loading="lazy">
</iframe>
```

`frame-ancestors` permite incrustar `/embed` desde `acluvaq.com.mx` y sus
subdominios. Ajusta `htmlHeaders()` cuando se defina otro dominio.

## Datos y migraciones

Cloudflare D1 es la fuente operativa. Las migraciones incrementales viven en
`.openai/drizzle/` e incluyen registros, asistencia, entregas de correo,
configuración, país, consentimiento, auditoría y rate limiting. No edites
migraciones ya aplicadas; agrega una nueva.

## Variables de entorno

- `ADMIN_KEY`: acceso administrativo de emergencia; no se guarda en el navegador.
- `SCANNER_KEY`: clave independiente y limitada al escáner; nunca debe ser igual
  a `ADMIN_KEY`.
- `TICKET_SECRET`: secreto aleatorio de alta entropía para HMAC.
- `RESEND_API_KEY`: llave privada de Resend.
- `EMAIL_FROM`: remitente verificado.
- `TURNSTILE_SITE_KEY` y `TURNSTILE_SECRET_KEY`: protección antiabuso. Si no se
  configuran, el widget no se presenta.
- `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`, `AWS_S3_BUCKET`:
  respaldo manual a S3.
- `AWS_S3_PREFIX`: opcional; por defecto `acluvaq-foro-2026/backups`.
- `AWS_KMS_KEY_ID`: opcional; fuerza SSE-KMS con esa llave. Sin ella, cada PUT
  solicita cifrado SSE-S3 (`AES256`).

Las credenciales AWS deben permitir únicamente `s3:PutObject` en el bucket y
prefijo de respaldos. Nunca guardes secretos en Git, frontend, logs o README.
Activa además Block Public Access, una política TLS-only y lifecycle en el bucket.

## Configuración administrativa

Las opciones se conservan en D1 y se aplican inmediatamente:

- correos empresariales/institucionales;
- teléfono internacional estricto (7–15 dígitos);
- registro público habilitado/deshabilitado.

Configura `privacy_notice_url` en `application_settings` cuando ACLUVAQ entregue
la URL definitiva. No se incluye una dirección inventada. La versión aceptada y
los consentimientos necesarios/adicionales quedan registrados por solicitud.

## Seguridad

- Folios y boletos usan 128 bits aleatorios.
- Comparación de claves en tiempo constante.
- Rate limiting persistente en D1 para registro, consulta, acceso administrativo
  y check-in.
- Turnstile opcional con verificación backend.
- SQL de edición con sentencias explícitas y valores enlazados.
- Scanner separado de administración y respuestas con datos mínimos.
- Auditoría de cambios, borrados, aprobaciones, exportaciones y check-in.
- CSP, HSTS, `nosniff`, aislamiento de origen, política de referencia y permisos
  de cámara restringidos.
- El QR no contiene datos personales y se valida mediante HMAC.

## Usuarios y roles

El panel permite crear usuarios individuales con contraseña PBKDF2-SHA256 y
sesiones revocables de ocho horas en cookies `HttpOnly`, `Secure` y
`SameSite=Strict`. Los usuarios no se eliminan: se desactivan y sus sesiones se
revocan.

- `admin`: registros, configuración, usuarios, CSV, respaldos y scanner.
- `approver`: consulta solicitudes y cambia su estado; el backend bloquea
  configuración, exportación, edición y usuarios.
- `scanner`: únicamente estadísticas agregadas y check-in con datos mínimos.

Para el arranque, entra con `ADMIN_KEY`, crea al primer administrador en
**Usuarios** y después utiliza cuentas individuales. Conserva la clave de
emergencia fuera de la operación cotidiana.

Además de las defensas del Worker, configura Cloudflare Access con MFA para
`/admin` y `/scanner`, y reglas WAF/Rate Limiting para `/api/status`,
`/api/admin/*` y `/api/checkin`. La protección perimetral no se configura desde
este repositorio.

## DEV y PROD

DEV y PROD no deben compartir D1, secretos, claves, usuarios, `TICKET_SECRET` ni
credenciales AWS. Flujo recomendado:

`Work → GitHub → DEV → validación → PROD`

## Desarrollo

```bash
npm install
node --check worker/index.js
node scripts/build.js
node --check dist/server/index.js
```

El generador QR deriva de *QRCode for JavaScript* (Kazuhiko Arase, MIT). El
fallback de lectura para Safari utiliza `jsQR` (Apache-2.0).
