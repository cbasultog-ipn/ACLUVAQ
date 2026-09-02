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

- `ADMIN_KEY`: clave de acceso al panel y al escáner.
- `TICKET_SECRET`: secreto aleatorio de alta entropía para firmar los boletos.

Los secretos no deben incluirse en el repositorio. La validación institucional rechaza dominios personales conocidos; no sustituye una verificación de propiedad mediante correo de confirmación.

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
