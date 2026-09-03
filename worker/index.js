import { qrSvg } from "./qrcode.js";
const JSQR_SOURCE = "__JSQR_SOURCE__";
const FORUM_BANNER = "__FORUM_BANNER__";
const ACLUVAQ_LOGO = "__ACLUVAQ_LOGO__";
const EVENT = {
  title: "2do. Foro de Ciberseguridad ACLUVAQ 2026",
  theme: "IA y Ciberseguridad · Organizaciones resilientes",
  date: "4 de noviembre de 2026",
  time: "9:00–13:30 h",
};
const PUBLIC_ORIGIN = "https://registro.thehwconsulting.com";
const PERSONAL = new Set([
  "gmail.com",
  "googlemail.com",
  "hotmail.com",
  "hotmail.com.mx",
  "outlook.com",
  "live.com",
  "msn.com",
  "yahoo.com",
  "yahoo.com.mx",
  "icloud.com",
  "me.com",
  "aol.com",
  "proton.me",
  "protonmail.com",
  "gmx.com",
  "mail.com",
  "yandex.com",
  "hey.com",
  "zoho.com",
]);
const COUNTRY_CODES =
    "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW".split(
      " ",
    ),
  regionNames = new Intl.DisplayNames(["es"], { type: "region" }),
  COUNTRIES = COUNTRY_CODES.map((code) => regionNames.of(code))
    .filter(Boolean)
    .sort((a, b) => a.localeCompare(b, "es")),
  COUNTRY_SET = new Set(COUNTRIES);
const enc = new TextEncoder(),
  esc = (s = "") =>
    String(s).replace(
      /[&<>"']/g,
      (c) =>
        ({
          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          '"': "&quot;",
          "'": "&#39;",
        })[c],
    );
const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "strict-transport-security": "max-age=31536000; includeSubDomains",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
    },
  });
const csvCell = (value) =>
  `"${(/^[=+\-@\t\r]/.test(String(value ?? "")) ? "'" : "") + String(value ?? "").replace(/"/g, '""')}"`;
const countryOptionsHtml = () =>
  '<option value="">Selecciona un país</option>' +
  COUNTRIES.map(
    (country) => `<option value="${esc(country)}">${esc(country)}</option>`,
  ).join("");
function code(p = "SOL") {
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  return `${p}-${Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("").toUpperCase()}`;
}
function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const aa = enc.encode(a), bb = enc.encode(b), maxBytes = 256;
  let diff = aa.length ^ bb.length;
  diff |= aa.length > maxBytes ? 1 : 0;
  diff |= bb.length > maxBytes ? 1 : 0;
  for (let i = 0; i < maxBytes; i++)
    diff |= (aa[i] ?? 0) ^ (bb[i] ?? 0);
  return diff === 0;
}
const adminOK = (req, env) =>
    !!env.ADMIN_KEY && timingSafeEqual(req.headers.get("x-admin-key") || "", env.ADMIN_KEY),
  scannerOK = (req, env) => {
    const scanner = req.headers.get("x-scanner-key") || "";
    return (!!env.SCANNER_KEY && timingSafeEqual(scanner, env.SCANNER_KEY)) ||
      adminOK(req, env);
  };
const b64url = (bytes) =>
  btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
function fromB64url(s) {
  try {
    return Uint8Array.from(
      atob(
        s.replace(/-/g, "+").replace(/_/g, "/") +
          "===".slice((s.length + 3) % 4),
      ),
      (c) => c.charCodeAt(0),
    );
  } catch {
    return null;
  }
}
function cookieValue(req, name) {
  const match = (req.headers.get("cookie") || "").match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  return match ? decodeURIComponent(match[1]) : "";
}
async function passwordHash(password, salt = crypto.getRandomValues(new Uint8Array(16)), iterations = 100000) {
  const passwordBytes = enc.encode(password);
  const passwordBuffer = passwordBytes.buffer.slice(
    passwordBytes.byteOffset,
    passwordBytes.byteOffset + passwordBytes.byteLength,
  );
  const saltBuffer = salt.buffer.slice(
    salt.byteOffset,
    salt.byteOffset + salt.byteLength,
  );
  const key = await crypto.subtle.importKey("raw", passwordBuffer, "PBKDF2", false, ["deriveBits"]);
  const hash = new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: saltBuffer, iterations }, key, 256));
  return `pbkdf2-sha256.${iterations}.${b64url(salt)}.${b64url(hash)}`;
}
async function verifyPassword(password, stored) {
  const [kind, count, salt64] = String(stored || "").split(".");
  if (kind !== "pbkdf2-sha256") return false;
  const salt = fromB64url(salt64), expected = await passwordHash(password, salt, Number(count));
  return timingSafeEqual(expected, stored);
}
function temporaryPassword() {
  return "Tmp9!" + b64url(crypto.getRandomValues(new Uint8Array(15)));
}
async function sendSystemUserInvite(env, user, temporaryPasswordValue, origin) {
  if (!env.RESEND_API_KEY || !env.EMAIL_FROM)
    return { status: "failed", error: "Servicio de correo pendiente de configuración" };
  try {
    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        authorization: "Bearer " + env.RESEND_API_KEY,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        from: env.EMAIL_FROM,
        to: [user.email],
        subject: "Tu acceso administrativo | " + EVENT.title,
        html: emailFrame(
          user.name,
          "Tu cuenta está lista",
          `<p>Se creó una cuenta para que ingreses a la plataforma del evento.</p><p><b>Usuario:</b> ${esc(user.email)}<br><b>Contraseña temporal:</b> <span style="font-family:monospace">${esc(temporaryPasswordValue)}</span><br><b>Rol:</b> ${esc(user.role)}</p><p style="margin:26px 0"><a href="${esc(origin)}/admin" style="background:#087fce;color:white;text-decoration:none;padding:14px 20px;border-radius:9px;font-weight:bold">Ingresar a la plataforma</a></p><p>Por seguridad, deberás definir una contraseña nueva inmediatamente después de iniciar sesión. No compartas estas credenciales.</p>`,
        ),
      }),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.message || "Error del proveedor de correo");
    return { status: "sent", error: null };
  } catch (error) {
    return { status: "failed", error: String(error?.message || error).slice(0, 400) };
  }
}
async function getActor(req, env) {
  if (adminOK(req, env)) return { id: null, name: "Clave de emergencia", role: "admin", actor: "admin_key" };
  const scannerHeader = req.headers.get("x-scanner-key") || "";
  if (!!env.SCANNER_KEY && timingSafeEqual(scannerHeader, env.SCANNER_KEY))
    return { id: null, name: "Equipo de acceso", role: "scanner", actor: "scanner_key" };
  const token = cookieValue(req, "foro_session");
  if (!token) return null;
  const tokenHash = await sha256Hex(token);
  return await env.DB.prepare("SELECT u.id,u.name,u.email,u.role,u.must_change_password,u.name || ' <' || u.email || '>' AS actor FROM user_sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.revoked_at IS NULL AND s.expires_at>CURRENT_TIMESTAMP AND u.active=1").bind(tokenHash).first();
}
function safeExternalUrl(value) {
  try {
    const parsed = new URL(String(value || ""));
    return parsed.protocol === "https:" ? parsed.href : "";
  } catch {
    return "";
  }
}
function mutationOriginOK(req) {
  if (!cookieValue(req, "foro_session")) return true;
  const origin = req.headers.get("origin") || "";
  return origin === PUBLIC_ORIGIN || origin === new URL(req.url).origin;
}
async function roleOK(req, env, roles) {
  const actor = await getActor(req, env);
  return actor && !actor.must_change_password && roles.includes(actor.role) ? actor : null;
}
async function ticketToken(ticket, env) {
  const data = enc.encode(ticket),
    key = await crypto.subtle.importKey(
      "raw",
      enc.encode(env.TICKET_SECRET),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    ),
    sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, data));
  return b64url(data) + "." + b64url(sig);
}
async function verifyToken(token, env) {
  const [a, b] = String(token || "").split("."),
    data = fromB64url(a),
    sig = fromB64url(b);
  if (!data || !sig || !env.TICKET_SECRET) return null;
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(env.TICKET_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"],
  );
  return (await crypto.subtle.verify("HMAC", key, sig, data))
    ? new TextDecoder().decode(data)
    : null;
}
async function workEmailRequired(env) {
  const row = await env.DB.prepare(
    "SELECT setting_value FROM application_settings WHERE setting_key='require_work_email'",
  ).first();
  return !row || row.setting_value !== "false";
}
async function phoneValidationRequired(env) {
  const row = await env.DB.prepare(
    "SELECT setting_value FROM application_settings WHERE setting_key='validate_phone'",
  ).first();
  return !row || row.setting_value !== "false";
}
async function setting(env, key, fallback = "") {
  const row = await env.DB.prepare(
    "SELECT setting_value FROM application_settings WHERE setting_key=?",
  ).bind(key).first();
  return row ? row.setting_value : fallback;
}
async function rateLimit(req, env, scope, maxHits, windowSeconds) {
  const ip = req.headers.get("cf-connecting-ip") || "unknown";
  const now = Math.floor(Date.now() / 1000), bucket = `${scope}:${ip}`;
  const row = await env.DB.prepare("SELECT hits,window_started_at FROM rate_limits WHERE bucket=?").bind(bucket).first();
  if (!row || now - row.window_started_at >= windowSeconds) {
    await env.DB.prepare("INSERT INTO rate_limits(bucket,hits,window_started_at) VALUES(?,1,?) ON CONFLICT(bucket) DO UPDATE SET hits=1,window_started_at=excluded.window_started_at").bind(bucket, now).run();
    return true;
  }
  if (row.hits >= maxHits) return false;
  await env.DB.prepare("UPDATE rate_limits SET hits=hits+1 WHERE bucket=?").bind(bucket).run();
  return true;
}
async function audit(req, env, action, registrationId = null, details = "", actor = null) {
  if (!actor) actor = (await getActor(req, env))?.actor || "unknown";
  await env.DB.prepare("INSERT INTO admin_audit_log(actor,action,registration_id,details,ip_address) VALUES(?,?,?,?,?)")
    .bind(actor, action, registrationId, String(details || "").slice(0, 1000), req.headers.get("cf-connecting-ip") || null).run();
}
async function verifyTurnstile(req, env, token) {
  if (!env.TURNSTILE_SECRET_KEY) return true;
  if (!token) return false;
  const body = new FormData();
  body.set("secret", env.TURNSTILE_SECRET_KEY);
  body.set("response", token);
  body.set("remoteip", req.headers.get("cf-connecting-ip") || "");
  const response = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body });
  const result = await response.json().catch(() => ({}));
  return result.success === true;
}
async function sha256Hex(value) {
  const data = typeof value === "string" ? enc.encode(value) : value;
  return Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", data)), (b) => b.toString(16).padStart(2, "0")).join("");
}
async function hmac(key, value) {
  const raw = typeof key === "string" ? enc.encode(key) : key;
  const cryptoKey = await crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, enc.encode(value)));
}
async function uploadS3Backup(env, payload) {
  const required = ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_REGION", "AWS_S3_BUCKET"];
  if (required.some((key) => !env[key])) throw new Error("Falta configurar el respaldo S3.");
  const now = new Date(), stamp = now.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z"), shortDate = stamp.slice(0, 8);
  const prefix = String(env.AWS_S3_PREFIX || "acluvaq-foro-2026/backups").replace(/^\/+|\/+$/g, "");
  const key = `${prefix}/${now.toISOString().slice(0, 10)}/registrations-${stamp.replace("T", "-").replace("Z", "")}.json`;
  const path = "/" + key.split("/").map(encodeURIComponent).join("/"), host = `${env.AWS_S3_BUCKET}.s3.${env.AWS_REGION}.amazonaws.com`, body = JSON.stringify(payload, null, 2), bodyHash = await sha256Hex(body);
  const encryption = env.AWS_KMS_KEY_ID ? "aws:kms" : "AES256";
  const kmsCanonical = env.AWS_KMS_KEY_ID ? `x-amz-server-side-encryption-aws-kms-key-id:${env.AWS_KMS_KEY_ID}\n` : "";
  const canonicalHeaders = `host:${host}\nx-amz-content-sha256:${bodyHash}\nx-amz-date:${stamp}\nx-amz-server-side-encryption:${encryption}\n${kmsCanonical}`;
  const signedHeaders = "host;x-amz-content-sha256;x-amz-date;x-amz-server-side-encryption" + (env.AWS_KMS_KEY_ID ? ";x-amz-server-side-encryption-aws-kms-key-id" : "");
  const canonicalRequest = `PUT\n${path}\n\n${canonicalHeaders}\n${signedHeaders}\n${bodyHash}`;
  const scope = `${shortDate}/${env.AWS_REGION}/s3/aws4_request`, stringToSign = `AWS4-HMAC-SHA256\n${stamp}\n${scope}\n${await sha256Hex(canonicalRequest)}`;
  const kDate = await hmac("AWS4" + env.AWS_SECRET_ACCESS_KEY, shortDate), kRegion = await hmac(kDate, env.AWS_REGION), kService = await hmac(kRegion, "s3"), kSigning = await hmac(kService, "aws4_request"), signature = Array.from(await hmac(kSigning, stringToSign), (b) => b.toString(16).padStart(2, "0")).join("");
  const headers = { "content-type": "application/json", "x-amz-content-sha256": bodyHash, "x-amz-date": stamp, "x-amz-server-side-encryption": encryption, authorization: `AWS4-HMAC-SHA256 Credential=${env.AWS_ACCESS_KEY_ID}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}` };
  if (env.AWS_KMS_KEY_ID) headers["x-amz-server-side-encryption-aws-kms-key-id"] = env.AWS_KMS_KEY_ID;
  const response = await fetch(`https://${host}${path}`, { method: "PUT", headers, body });
  if (!response.ok) throw new Error(`S3 respondió ${response.status}.`);
  return key;
}
function validPhone(phone, validate = true) {
  const value = String(phone || "");
  if (!value) return { ok: true };
  if (validate && !/^\d{7,15}$/.test(value))
    return {
      ok: false,
      error:
        "El teléfono debe contener entre 7 y 15 dígitos, sin espacios ni caracteres especiales.",
    };
  return { ok: true };
}
function validCountry(country) {
  return COUNTRY_SET.has(String(country || "").trim());
}
function registrationFieldsWithinLimits(data) {
  const limits = { first_name: 100, last_name: 100, email: 254, phone: 15, country: 100, company: 160, member_company: 160, job_title: 120, job_level: 80, influence: 32, club_member: 16, interest: 400 };
  return Object.entries(limits).every(([field, max]) => String(data?.[field] || "").length <= max);
}
function validWorkEmail(email, requireWorkEmail = true) {
  const m = String(email || "")
    .trim()
    .toLowerCase()
    .match(
      /^[a-z0-9.!#$%&'*+/=?^_`{|}~-]+@([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)$/i,
    );
  if (!m)
    return { ok: false, error: "Ingresa un correo con estructura válida." };
  const personal = PERSONAL.has(m[1]);
  if (requireWorkEmail && personal)
    return {
      ok: false,
      error:
        "Usa el correo de tu empresa o institución educativa; no se aceptan correos personales.",
    };
  return {
    ok: true,
    domain: m[1],
    type: personal
      ? "personal"
      : /(\.edu(\.|$)|\.ac\.|\.edu\.mx$)/.test(m[1])
        ? "educativo"
        : "corporativo",
  };
}
function emailFrame(name, title, body) {
  return `<!doctype html><html><body style="margin:0;background:#f4f8fb;font:16px Arial,sans-serif;color:#0b1728"><div style="max-width:600px;margin:auto;padding:28px 18px"><div style="background:#08243e;color:white;padding:20px;border-radius:14px 14px 0 0"><img src="${PUBLIC_ORIGIN}/assets/acluvaq-logo.png" width="150" alt="ACLUVAQ" style="display:block;width:150px;max-width:48%;height:auto;margin:0 0 14px"><b>${EVENT.title}</b><br><span style="color:#bcd1e3;font-size:13px">${EVENT.date} · ${EVENT.time}</span></div><div style="background:white;padding:28px;border:1px solid #d7e2eb;border-top:0;border-radius:0 0 14px 14px"><p>Hola, ${esc(name)}:</p><h1 style="font-size:24px">${title}</h1>${body}<div style="margin-top:28px;padding:14px;background:#f5f9fc;border-radius:9px;font-size:13px;line-height:1.55;color:#465b70"><b>Correo automático — no responder</b><br>Este buzón no es monitoreado. No es necesario responder ni enviar mensajes a <b>foro@thehwconsulting.com</b>.<br><br>Para no perder futuras actualizaciones, agrega <b>Foro ACLUVAQ &lt;foro@thehwconsulting.com&gt;</b> a tus remitentes seguros y verifica que no esté en SPAM ni bloqueado.</div><p style="font-size:12px;color:#617284;margin-top:20px">Mensaje automático relacionado exclusivamente con tu participación en el ${EVENT.title}.</p></div><p style="font-size:12px;line-height:1.6;color:#617284;text-align:center;margin:18px 12px 0">Plataforma tecnológica provista para ACLUVAQ por <b>The Hysteresis Way Consulting Group</b> © 2026<br><a href="mailto:info@thehwconsulting.com" style="color:#087fce">info@thehwconsulting.com</a></p></div></body></html>`;
}
async function sendAndLog(env, row, type, subject, html) {
  let status = "failed",
    providerId = null,
    error = null;
  try {
    if (!env.RESEND_API_KEY || !env.EMAIL_FROM)
      throw new Error("Servicio de correo pendiente de configuración");
    const r = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
          authorization: "Bearer " + env.RESEND_API_KEY,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          from: env.EMAIL_FROM,
          to: [row.email],
          subject,
          html,
        }),
      }),
      j = await r.json();
    if (!r.ok) throw new Error(j.message || "Error del proveedor");
    status = "sent";
    providerId = j.id || null;
  } catch (e) {
    error = String(e.message || e).slice(0, 400);
  }
  await env.DB.prepare(
    "INSERT INTO email_deliveries (registration_id,message_type,recipient,status,provider_id,error_message) VALUES (?,?,?,?,?,?)",
  )
    .bind(row.id, type, row.email, status, providerId, error)
    .run();
  return { status, error };
}
async function sendReviewEmail(env, row, origin = PUBLIC_ORIGIN) {
  const statusUrl = origin + "/?folio=" + encodeURIComponent(row.request_code) + "#consultar";
  return sendAndLog(
    env,
    row,
    "solicitud",
    "Recibimos tu solicitud | " + EVENT.title,
    emailFrame(
      row.first_name,
      "Tu solicitud está en revisión",
      `<p>Recibimos correctamente tu solicitud. El comité revisará la disponibilidad y el perfil registrado antes de confirmar tu participación.</p><p><b>Folio:</b> ${esc(row.request_code)}</p><p style="margin:26px 0"><a href="${statusUrl}" style="background:#087fce;color:white;text-decoration:none;padding:14px 20px;border-radius:9px;font-weight:bold">Consultar estado de mi solicitud</a></p><p>Este folio no es un boleto. Espera nuestro correo de confirmación antes de acudir al evento.</p>`,
    ),
  );
}
async function sendTicketEmail(env, row, origin) {
  const token = await ticketToken(row.ticket_code, env),
    ticketUrl = origin + "/ticket?token=" + encodeURIComponent(token);
  return sendAndLog(
    env,
    row,
    "boleto",
    "Tu acceso fue aprobado | " + EVENT.title,
    emailFrame(
      row.first_name,
      "Tu participación fue confirmada",
      `<p>Tu solicitud fue aprobada. Abre tu boleto digital y presenta el código QR desde tu celular en el acceso.</p><p style="margin:26px 0"><a href="${ticketUrl}" style="background:#087fce;color:white;text-decoration:none;padding:14px 20px;border-radius:9px;font-weight:bold">Abrir boleto digital</a></p><p><b>Boleto:</b> ${esc(row.ticket_code)}</p><p style="font-size:13px;color:#617284">Es personal, intransferible y válido únicamente para este foro; no concede acceso a otros eventos de ACLUVAQ.</p><div style="margin-top:24px;padding:16px;background:#fff6df;border-radius:10px"><b>¿Cambió tu agenda?</b><p style="margin:6px 0 14px">El cupo es limitado. Si ya no puedes acompañarnos, cancela tu participación para que otra persona pueda ocupar tu lugar.</p><a href="${ticketUrl}#cancelar" style="color:#a72c3b;font-weight:bold">Cancelar mi participación</a></div>`,
    ),
  );
}
async function sendStatusEmail(env, row, status, previous) {
  if (status === "aprobado") return sendTicketEmail(env, row, row.origin);
  const copy =
    status === "lista_espera"
      ? {
          subject:
            "Actualización: lista de espera | " + EVENT.title,
          title: "Tu solicitud está en lista de espera",
          text: "Por el momento no podemos confirmar tu acceso. Conservaremos tu solicitud activa y te avisaremos por correo si se libera un lugar.",
        }
      : status === "rechazado"
        ? {
            subject:
              "Actualización de tu registro | " + EVENT.title,
            title:
              previous === "aprobado"
                ? "Tu participación fue cancelada"
                : "Tu solicitud no fue aprobada",
            text:
              previous === "aprobado"
                ? "Tu acceso y boleto para este evento han sido cancelados. El código QR anterior ya no es válido."
                : "Después de revisar la solicitud, en esta ocasión no fue posible confirmar tu participación.",
          }
        : {
            subject:
              "Actualización: solicitud en revisión | " + EVENT.title,
            title: "Tu solicitud está en revisión",
            text: "Tu registro permanece en revisión. Te enviaremos otra actualización cuando el comité determine el resultado.",
          };
  return sendAndLog(
    env,
    row,
    "estado_" + status,
    copy.subject,
    emailFrame(
      row.first_name,
      copy.title,
      `<p>${copy.text}</p><p><b>Folio:</b> ${esc(row.request_code)}</p>`,
    ),
  );
}
async function sendDataUpdateEmail(env, row) {
  return sendAndLog(
    env,
    row,
    "datos_actualizados",
    "Tus datos fueron actualizados | " + EVENT.title,
    emailFrame(
      row.first_name,
      "Actualizamos los datos de tu registro",
      `<p>El equipo organizador realizó una corrección en la información de tu registro.</p><p><b>Folio:</b> ${esc(row.request_code)}</p><p>Si no reconoces este cambio, solicita una revisión a través de los canales oficiales de ACLUVAQ.</p>`,
    ),
  );
}
const css = `:root{--ink:#0b1728;--navy:#08243e;--blue:#087fce;--cyan:#19c3d5;--paper:#f4f8fb;--line:#d7e2eb;--muted:#617284;--ok:#087a55;--warn:#a85d00;--bad:#a72c3b}*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:16px/1.45 Inter,ui-sans-serif,system-ui,-apple-system,sans-serif}button,input,select,textarea{font:inherit}button{cursor:pointer}.shell{min-height:100vh}.top{background:var(--navy);color:white;padding:17px 24px}.topin{max-width:1160px;margin:auto;display:flex;align-items:center;justify-content:space-between;gap:16px}.brand{display:flex;align-items:center;gap:12px;font-weight:760}.mark{width:38px;height:38px;border:2px solid var(--cyan);border-radius:50%;display:grid;place-items:center;color:var(--cyan);font-weight:900}.meta{font-size:.82rem;color:#bcd1e3}.wrap{max-width:1160px;margin:auto;padding:28px 20px 56px}.grid{display:grid;grid-template-columns:minmax(0,1.25fr) minmax(280px,.75fr);gap:28px;align-items:start}.card{background:white;border:1px solid var(--line);border-radius:18px;box-shadow:0 10px 32px #0b28440d}.formcard{padding:28px}.side{padding:24px;position:sticky;top:20px}.eyebrow{font-size:.78rem;letter-spacing:.12em;text-transform:uppercase;color:var(--blue);font-weight:800}.h1{font-size:clamp(1.65rem,4vw,2.5rem);line-height:1.08;margin:8px 0 10px;letter-spacing:-.035em}.lead{color:var(--muted);margin:0 0 24px}.notice{background:#eaf7fb;border-left:4px solid var(--cyan);padding:13px 15px;border-radius:8px;margin-bottom:24px;font-size:.93rem}.section{border:0;padding:0;margin:0 0 22px}.section legend{font-weight:780;margin-bottom:12px}.fields{display:grid;grid-template-columns:1fr 1fr;gap:15px}.full{grid-column:1/-1}label{display:block;font-size:.87rem;font-weight:700;margin-bottom:6px}input,select,textarea{width:100%;min-height:46px;border:1px solid #bdccd8;border-radius:9px;background:white;padding:10px 12px;color:var(--ink)}input:focus,select:focus,textarea:focus{outline:3px solid #11a7dc2b;border-color:var(--blue)}textarea{min-height:76px;resize:vertical}.radios{display:flex;gap:9px;flex-wrap:wrap}.radio{border:1px solid #bdccd8;border-radius:9px;padding:10px 13px;display:flex;gap:8px;align-items:center;font-weight:600}.radio input,.check input{width:auto;min-height:0}.check{display:flex;gap:10px;align-items:flex-start;font-size:.84rem;color:var(--muted)}.check input{margin-top:4px}.primary{border:0;background:linear-gradient(135deg,var(--blue),#075ca5);color:white;border-radius:10px;padding:13px 18px;font-weight:800;box-shadow:0 6px 14px #087fce35}.ghost{border:1px solid var(--line);background:white;color:var(--navy);border-radius:9px;padding:9px 12px;font-weight:700}.side h2{font-size:1.15rem;margin:0 0 15px}.fact{display:flex;gap:12px;padding:13px 0;border-bottom:1px solid var(--line)}.fact:last-child{border:0}.ico{color:var(--blue);font-weight:900}.small{font-size:.82rem;color:var(--muted)}.statusbox{padding:18px;background:#f8fbfd;border-radius:12px;margin-top:18px}.success{text-align:center;padding:34px 12px}.badge{display:inline-flex;padding:5px 9px;border-radius:99px;font-size:.75rem;font-weight:800}.pendiente{background:#fff1d8;color:var(--warn)}.aprobado,.asistio{background:#dff7ed;color:var(--ok)}.rechazado{background:#fde5e8;color:var(--bad)}.lista_espera{background:#e8eefc;color:#3556a5}.dashhead{display:flex;justify-content:space-between;gap:16px;align-items:end;margin-bottom:20px}.stats{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:18px}.stat{padding:17px}.stat b{display:block;font-size:1.65rem}.metric-panel{padding:20px;margin-bottom:18px}.metric-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}.metric{background:#f7fafc;border:1px solid var(--line);border-radius:12px;padding:15px}.metric strong{display:block;font-size:1.45rem;margin-top:3px}.metric-bar{height:8px;background:#dce8f0;border-radius:99px;overflow:hidden;margin-top:10px}.metric-bar span{display:block;height:100%;background:linear-gradient(90deg,var(--blue),var(--cyan));border-radius:inherit}.metric-lists{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-top:18px}.metric-row{display:grid;grid-template-columns:minmax(110px,1fr) 2fr 42px;gap:10px;align-items:center;margin:9px 0;font-size:.86rem}.audit-table td{font-size:.84rem}.audit-action{font-weight:750;color:var(--navy)}.toolbar{display:flex;gap:10px;padding:14px;margin-bottom:14px}.toolbar input{flex:1}.tablewrap{overflow:auto}.table{width:100%;border-collapse:collapse;background:white}.table th,.table td{text-align:left;padding:13px 12px;border-bottom:1px solid var(--line);vertical-align:top}.table th{font-size:.74rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}.person{font-weight:780}.score{display:inline-grid;place-items:center;width:34px;height:34px;border-radius:50%;background:#e8f5fb;color:#075a91;font-weight:900}.actions{display:flex;gap:6px;flex-wrap:wrap}.approve{background:var(--ok);color:white;border:0}.wait{background:#fff5df;color:#875000;border:0}.reject{background:#fff;border:1px solid #e5aeb5;color:var(--bad)}.actions button{padding:7px 9px;border-radius:7px;font-size:.78rem;font-weight:750}.empty{padding:40px;text-align:center;color:var(--muted)}.login{max-width:430px;margin:60px auto;padding:28px}.ticket{max-width:520px;margin:30px auto;padding:28px;border-top:7px solid var(--cyan)}.tickethead{display:flex;justify-content:space-between;gap:15px}.ticketcode{font:800 1.2rem ui-monospace,monospace;letter-spacing:.06em}.qr{width:min(72vw,260px);margin:22px auto}.qr svg{display:block;width:100%;height:auto}.terms{font-size:.8rem;color:var(--muted);border-top:1px solid var(--line);padding-top:16px;margin-top:20px}.scanner{max-width:620px;margin:28px auto;padding:22px}.camera{background:#071624;border-radius:14px;overflow:hidden;aspect-ratio:4/3;display:grid;place-items:center;color:white;position:relative}.camera video{width:100%;height:100%;object-fit:cover}.finder{position:absolute;width:62%;aspect-ratio:1;border:3px solid var(--cyan);border-radius:18px;box-shadow:0 0 0 999px #00101f66}.scanresult{padding:18px;border-radius:12px;margin-top:14px}.scanresult.ok{background:#dff7ed;color:#07583d}.scanresult.bad{background:#fde5e8;color:#81212e}.hidden{display:none!important}@media(max-width:900px){.metric-grid{grid-template-columns:1fr 1fr}}@media(max-width:780px){.grid{grid-template-columns:1fr}.side{position:static;order:-1}.fields{grid-template-columns:1fr}.full{grid-column:auto}.stats{grid-template-columns:1fr 1fr}.metric-lists{grid-template-columns:1fr}.topin{align-items:flex-start}.meta{display:none}.formcard{padding:20px}.dashhead{align-items:flex-start;flex-direction:column}.ticket{margin:12px}.toolbar{flex-direction:column}}`;
const uxCss = `.toast-stack{position:fixed;right:18px;bottom:18px;z-index:1000;display:grid;gap:10px;width:min(390px,calc(100vw - 36px))}.toast{display:grid;grid-template-columns:40px 1fr auto;gap:12px;align-items:start;background:#fff;border:1px solid var(--line);border-left:5px solid var(--blue);border-radius:14px;padding:14px;box-shadow:0 18px 46px #06192c33;animation:toast-in .22s ease-out}.toast.success{border-left-color:var(--ok)}.toast.error{border-left-color:var(--bad)}.toast.warning{border-left-color:var(--warn)}.toast-icon{width:36px;height:36px;border-radius:50%;display:grid;place-items:center;background:#e8f5fb;color:var(--blue);font-weight:900}.toast.success .toast-icon{background:#dff7ed;color:var(--ok)}.toast.error .toast-icon{background:#fde5e8;color:var(--bad)}.toast.warning .toast-icon{background:#fff1d8;color:var(--warn)}.toast b{display:block;margin-bottom:2px}.toast p{margin:0;color:var(--muted);font-size:.9rem}.toast-close{border:0;background:transparent;color:var(--muted);font-size:1.25rem;line-height:1;padding:2px}.ux-dialog{width:min(470px,calc(100vw - 28px));border:0;border-radius:18px;padding:0;box-shadow:0 24px 80px #00152b66}.ux-dialog::backdrop{background:#06192c99;backdrop-filter:blur(3px)}.ux-dialog-body{padding:24px}.ux-dialog-head{display:flex;gap:13px;align-items:flex-start;margin-bottom:14px}.ux-dialog-head .toast-icon{flex:0 0 auto}.ux-dialog h2{font-size:1.25rem;line-height:1.2;margin:2px 0 5px}.ux-dialog p{margin:0;color:var(--muted)}.ux-dialog-actions{display:flex;justify-content:flex-end;gap:9px;margin-top:20px}.danger-btn{border:0;background:var(--bad);color:#fff;border-radius:9px;padding:10px 14px;font-weight:800}@keyframes toast-in{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}@media(max-width:780px){.toast-stack{right:12px;bottom:12px;width:calc(100vw - 24px)}}`;
const brandCss = `.brand-logo{display:block;width:132px;height:auto}.event-banner{display:block;width:100%;aspect-ratio:1.82/1;object-fit:cover;border-radius:14px;margin-bottom:20px}.ticket-logo{display:block;width:min(230px,58vw);height:auto;margin:0 auto 18px}.top .brand-logo{width:120px}.embed .top,.embed .side{display:none}.embed .wrap{padding:0;max-width:820px}.embed .grid{display:block}.embed .formcard{border:0;border-radius:0;box-shadow:none}@media(max-width:780px){.top .brand-logo{width:98px}.event-banner{margin-bottom:15px}}`;
const uxJS = `const UX_TITLES={success:'Listo',error:'No pudimos completar la acción',warning:'Atención',info:'Información'};
function toast(message,type='info',title=''){const stack=document.querySelector('#toastStack'),item=document.createElement('div'),icons={success:'✓',error:'!',warning:'!',info:'i'};item.className='toast '+type;item.setAttribute('role',type==='error'?'alert':'status');item.innerHTML='<span class="toast-icon">'+icons[type]+'</span><div><b></b><p></p></div><button class="toast-close" aria-label="Cerrar">×</button>';item.querySelector('b').textContent=title||UX_TITLES[type];item.querySelector('p').textContent=message;item.querySelector('button').onclick=()=>item.remove();stack.append(item);setTimeout(()=>item.remove(),type==='error'?7000:4500)}
function uxConfirm(title,message,{danger=false,confirmText='Confirmar'}={}){return new Promise(resolve=>{const d=document.createElement('dialog');d.className='ux-dialog';d.innerHTML='<div class="ux-dialog-body"><div class="ux-dialog-head"><span class="toast-icon">'+(danger?'!':'?')+'</span><div><h2></h2><p></p></div></div><div class="ux-dialog-actions"><button class="ghost" value="cancel">Cancelar</button><button class="'+(danger?'danger-btn':'primary')+'" value="ok"></button></div></div>';d.querySelector('h2').textContent=title;d.querySelector('p').textContent=message;d.querySelector('[value=ok]').textContent=confirmText;document.body.append(d);const done=v=>{d.close();d.remove();resolve(v)};d.querySelector('[value=cancel]').onclick=()=>done(false);d.querySelector('[value=ok]').onclick=()=>done(true);d.oncancel=e=>{e.preventDefault();done(false)};d.showModal()})}
function uxPrompt(title,label){return new Promise(resolve=>{const d=document.createElement('dialog');d.className='ux-dialog';d.innerHTML='<form class="ux-dialog-body"><div class="ux-dialog-head"><span class="toast-icon">i</span><div><h2></h2><p></p></div></div><label>Nota interna <span class="small">(opcional)</span></label><textarea maxlength="500" placeholder="Agrega contexto para el equipo organizador"></textarea><div class="ux-dialog-actions"><button type="button" class="ghost">Cancelar</button><button type="submit" class="primary">Continuar</button></div></form>';d.querySelector('h2').textContent=title;d.querySelector('p').textContent=label;document.body.append(d);const done=v=>{d.close();d.remove();resolve(v)};d.querySelector('button[type=button]').onclick=()=>done(null);d.querySelector('form').onsubmit=e=>{e.preventDefault();done(d.querySelector('textarea').value.trim())};d.oncancel=e=>{e.preventDefault();done(null)};d.showModal();d.querySelector('textarea').focus()})}`;
function page(body, title = EVENT.title) {
  return `<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title><meta name="description" content="Registro del ${EVENT.title}"><style>${css}${uxCss}${brandCss}</style></head><body><div class="shell"><header class="top"><div class="topin"><div class="brand"><img class="brand-logo" src="/assets/acluvaq-logo.png" alt="ACLUVAQ"><div>${EVENT.title}<div class="meta">${EVENT.theme}</div></div></div><div class="meta">${EVENT.date} · ${EVENT.time}</div></div></header>${body}<footer style="max-width:1180px;margin:16px auto 0;padding:24px 20px 32px;text-align:center;color:#617284;font-size:.82rem;line-height:1.6;border-top:1px solid #d7e2eb">Plataforma tecnológica provista para ACLUVAQ por <b>The Hysteresis Way Consulting Group</b> © 2026<br><a href="mailto:info@thehwconsulting.com" style="color:#087fce;font-weight:700;text-decoration:none">info@thehwconsulting.com</a></footer></div><div id="toastStack" class="toast-stack" aria-live="polite"></div><script>${uxJS}</script></body></html>`;
}
function htmlHeaders(embed = false) {
  const ancestors = embed ? "'self' https://acluvaq.com.mx https://*.acluvaq.com.mx" : "'none'";
  return {
    "content-type": "text/html; charset=utf-8",
    "content-security-policy": `default-src 'self'; script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; frame-ancestors ${ancestors}; base-uri 'none'; form-action 'self'`,
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=(self), microphone=(), geolocation=()",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "cross-origin-resource-policy": "same-origin",
    ...(embed ? {} : { "cross-origin-opener-policy": "same-origin", "x-frame-options": "DENY" }),
    "cache-control": "no-store",
  };
}
function registerPage(requireWorkEmail, validatePhone, privacyUrl = "", turnstileSiteKey = "") {
  const emailLabel = requireWorkEmail
      ? "Correo de empresa o institución *"
      : "Correo electrónico *",
    emailHelp = requireWorkEmail
      ? "Estudiantes y académicos: usa el correo de tu universidad. No se aceptan cuentas personales."
      : "Se aceptan correos empresariales, institucionales y personales.",
    phoneAttrs = validatePhone
      ? ' inputmode="numeric" pattern="[0-9]{7,15}" minlength="7" maxlength="15"'
      : "",
    phoneHelp = validatePhone
      ? '<div class="small">Entre 7 y 15 dígitos. Escribe solo números, sin +, espacios, guiones ni paréntesis.</div>'
      : "",
    privacyLink = privacyUrl
      ? ` Consulta el <a href="${esc(privacyUrl)}" target="_blank" rel="noopener">Aviso de Privacidad de ACLUVAQ</a>.`
      : "",
    turnstile = turnstileSiteKey
      ? `<div class="cf-turnstile" data-sitekey="${esc(turnstileSiteKey)}" data-theme="light" style="margin-top:18px"></div><script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>`
      : "";
  return page(
    `<main class="wrap"><div class="grid"><section class="card formcard"><img class="event-banner" src="/assets/foro-banner.png" alt="2do. Foro de Ciberseguridad ACLUVAQ 2026: IA, nueva frontera de la ciberseguridad"><div class="eyebrow">Solicitud de acceso</div><h1 class="h1">Regístrate en menos de 2 minutos</h1><p class="lead">El comité revisará tu solicitud antes de asignar el boleto.</p><div class="notice"><strong>Importante:</strong> el registro no confirma tu acceso. Recibirás un folio para consultar el resultado.</div><form id="reg"><fieldset class="section"><legend>Datos del participante</legend><div class="fields"><div><label for="first">Nombre *</label><input id="first" name="first_name" autocomplete="given-name" required></div><div><label for="last">Apellidos *</label><input id="last" name="last_name" autocomplete="family-name" required></div><div><label for="email">${emailLabel}</label><input id="email" name="email" type="email" autocomplete="email" required><div class="small">${emailHelp}</div></div><div><label for="phone">Teléfono</label><input id="phone" name="phone" type="tel" autocomplete="tel"></div></div></fieldset><fieldset class="section"><legend>Perfil profesional</legend><div class="fields"><div class="full"><label for="company">Empresa u organización *</label><input id="company" name="company" required></div><div class="full"><label>¿Tu empresa es socia de ACLUVAQ? *</label><div class="radios"><label class="radio"><input type="radio" name="club_member" value="si" required> Sí</label><label class="radio"><input type="radio" name="club_member" value="no"> No</label><label class="radio"><input type="radio" name="club_member" value="no_se"> No estoy seguro</label></div></div><div><label for="job">Puesto *</label><input id="job" name="job_title" required></div><div><label for="level">Nivel del puesto *</label><select id="level" name="job_level" required><option value="">Selecciona</option><option>Alta dirección / Consejo</option><option>Dirección</option><option>Gerencia</option><option>Jefatura / Coordinación</option><option>Especialista / Consultoría</option><option>Académico / Estudiante</option><option>Otro</option></select></div><div class="full"><label for="influence">Participación en decisiones de tecnología o ciberseguridad *</label><select id="influence" name="influence" required><option value="">Selecciona</option><option value="decisor">Decido o autorizo inversiones</option><option value="influenciador">Evalúo y recomiendo soluciones</option><option value="usuario">Participo como usuario o especialista</option><option value="interesado">Busco aprender sobre el tema</option></select></div><div class="full"><label for="interest">¿Qué esperas obtener del foro? <span class="small">(opcional)</span></label><textarea id="interest" name="interest" maxlength="400"></textarea></div></div></fieldset><div class="notice" style="background:#f5f9fc"><label class="check"><input type="checkbox" name="necessary_consent" value="true" required><span><b>Tratamiento necesario de datos *</b><br>Autorizo el uso de mis datos para gestionar mi solicitud, comunicaciones operativas, boleto QR y control de acceso de este Foro.${privacyLink}</span></label><label class="check" style="margin-top:14px"><input type="checkbox" name="additional_comms_consent" value="true"><span><b>Comunicaciones futuras (opcional)</b><br>Deseo recibir invitaciones a futuros eventos y comunicaciones institucionales de ACLUVAQ.</span></label></div>${turnstile}<div style="margin-top:20px"><button class="primary" type="submit">Enviar solicitud</button></div></form><div id="result"></div></section><aside class="card side"><h2>Tu registro, paso a paso</h2><div class="fact"><span class="ico">01</span><div><b>Envía tu solicitud</b><div class="small">Datos básicos y perfil profesional.</div></div></div><div class="fact"><span class="ico">02</span><div><b>Revisión del comité</b><div class="small">Se valida disponibilidad y perfil.</div></div></div><div class="fact"><span class="ico">03</span><div><b>Acceso con QR</b><div class="small">Solo solicitudes aprobadas reciben boleto.</div></div></div><div class="statusbox"><b>¿Ya te registraste?</b><p class="small">Consulta con tu folio y correo.</p><button class="ghost" id="checkBtn">Consultar estado</button></div></aside></div></main><script>${clientJS}${statusPostUpgradeJS}</script>`,
  );
}
const clientJS = `const q=s=>document.querySelector(s);q('#reg').addEventListener('submit',async e=>{e.preventDefault();const b=e.submitter;b.disabled=true;b.textContent='Validando…';const data=Object.fromEntries(new FormData(e.target));try{const r=await fetch('/api/register',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(data)}),j=await r.json();if(!r.ok)throw Error(j.error);q('#result').innerHTML='<div class="success"><span class="badge pendiente">En revisión</span><h2>Solicitud recibida</h2><p>Guarda este folio:</p><div class="ticketcode">'+j.request_code+'</div><p class="small">No es un boleto ni confirma tu acceso.</p></div>';q('#reg').classList.add('hidden')}catch(x){toast(x.message||'No pudimos enviar tu solicitud.','error');b.disabled=false;b.textContent='Enviar solicitud'}});q('#checkBtn').onclick=()=>{const d=document.createElement('dialog');d.className='ux-dialog';d.innerHTML='<form class="ux-dialog-body"><div class="eyebrow">Consulta de solicitud</div><h2 style="margin:5px 0 6px">Revisa el estado de tu registro</h2><p class="small" style="margin-bottom:18px">Ingresa exactamente el folio y correo utilizados al registrarte.</p><label>Folio de solicitud</label><input name="folio" placeholder="Ej. SOL-2026-…" required><label style="margin-top:13px">Correo electrónico</label><input name="email" type="email" autocomplete="email" required><div id="statusResult"></div><div class="ux-dialog-actions"><button type="button" class="ghost">Cancelar</button><button type="submit" class="primary">Consultar estado</button></div></form>';document.body.append(d);const close=()=>{d.close();d.remove()};d.querySelector('button[type=button]').onclick=close;d.oncancel=e=>{e.preventDefault();close()};d.querySelector('form').onsubmit=async e=>{e.preventDefault();const b=e.submitter,folio=e.currentTarget.elements.folio.value.trim(),email=e.currentTarget.elements.email.value.trim();b.disabled=true;b.textContent='Consultando…';const r=await fetch('/api/status?folio='+encodeURIComponent(folio)+'&email='+encodeURIComponent(email)),j=await r.json();b.disabled=false;b.textContent='Consultar estado';const box=d.querySelector('#statusResult');if(!r.ok){box.innerHTML='<div class="scanresult bad"><b>No encontramos la solicitud</b><br>'+String(j.error||'Verifica el folio y el correo e intenta nuevamente.')+'</div>';return}const labels={pendiente:'Pendiente de revisión',aprobado:'Solicitud aprobada',lista_espera:'En lista de espera',rechazado:'Solicitud no aprobada'},kind=j.status==='aprobado'?'ok':j.status==='rechazado'?'bad':'';box.innerHTML='<div class="scanresult '+kind+'"><b>'+labels[j.status]+'</b><br><span class="small">Folio '+folio+'</span>'+(j.ticket_url?'<div style="margin-top:12px"><a class="primary" style="display:inline-block;text-decoration:none" href="'+j.ticket_url+'">Abrir boleto digital</a></div>':'')+'</div>'};d.showModal();d.querySelector('[name=folio]').focus()};`;
const statusPostUpgradeJS = `const nativeFetch=window.fetch.bind(window);window.fetch=(resource,options={})=>{if(typeof resource==='string'&&resource.startsWith('/api/status?')){const u=new URL(resource,location.origin);return nativeFetch('/api/status',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({folio:u.searchParams.get('folio')||'',email:u.searchParams.get('email')||''})})}return nativeFetch(resource,options)};`;
function enhancedRegisterPage(requireWorkEmail, validatePhone, privacyUrl = "", turnstileSiteKey = "") {
  const phoneInput =
      '<input id="phone" name="phone" type="tel" autocomplete="tel">',
    enhancedPhone = `<input id="phone" name="phone" type="tel" autocomplete="tel"${validatePhone ? ' inputmode="numeric" pattern="[0-9]{7,15}" minlength="7" maxlength="15"' : ""}>${validatePhone ? '<div class="small">Entre 7 y 15 dígitos. Escribe solo números, sin +, espacios, guiones ni paréntesis.</div>' : ""}`,
    countryField = `<div><label for="country">País *</label><select id="country" name="country" autocomplete="country-name" required>${countryOptionsHtml()}</select></div>`;
  const deliveryNotice = '<div class="notice" style="background:#fff8e8;border-left-color:#e1a323"><strong>Asegura la recepción de tus mensajes:</strong> agrega <b>Foro ACLUVAQ &lt;foro@thehwconsulting.com&gt;</b> a tus remitentes seguros y verifica que no esté en SPAM ni bloqueado. Es una cuenta automática no monitoreada; no envíes respuestas a esa dirección.</div>';
  const directStatusJS = `<script>const requestedFolio=new URLSearchParams(location.search).get('folio');if(requestedFolio){document.querySelector('#checkBtn').click();const field=document.querySelector('dialog [name=folio]');if(field){field.value=requestedFolio;document.querySelector('dialog [name=email]').focus()}}</script>`;
  return registerPage(requireWorkEmail, validatePhone, privacyUrl, turnstileSiteKey)
    .replace(phoneInput, enhancedPhone)
    .replace(enhancedPhone + "</div>", enhancedPhone + "</div>" + countryField)
    .replace('<form id="reg">', deliveryNotice + '<form id="reg">')
    .replace("</body>", directStatusJS + "</body>");
}
function adminPage() {
  return page(
    `<main class="wrap"><section id="login" class="card login"><div class="eyebrow">Administración</div><h1 class="h1">Control del evento</h1><label for="key">Clave administrativa</label><input id="key" type="password"><button id="enter" class="primary" style="margin-top:14px">Ingresar</button></section><section id="dash" class="hidden"><div class="dashhead"><div><div class="eyebrow">Panel administrativo</div><h1 class="h1">Solicitudes y asistencia</h1></div><div class="actions"><button class="ghost" id="exportCsv">Exportar CSV</button><a class="primary" href="/scanner" style="text-decoration:none">Escanear accesos</a><button class="ghost" id="exit">Cerrar sesión</button></div></div><div class="card" style="padding:18px 20px;margin-bottom:18px"><div style="display:flex;align-items:center;justify-content:space-between;gap:20px;flex-wrap:wrap"><div><b>Solo correos empresariales o institucionales</b><div class="small" id="emailPolicyHelp">Cargando configuración…</div></div><label class="radio" style="margin:0;cursor:pointer"><input id="emailPolicy" type="checkbox" role="switch"> <span id="emailPolicyState">Activada</span></label></div></div><div class="stats" id="stats"></div><section class="card metric-panel"><div class="eyebrow">Dashboard del evento</div><h2 style="margin:5px 0 16px">Indicadores ejecutivos</h2><div id="eventMetrics"></div></section><div class="card toolbar"><input id="search" placeholder="Buscar participante, empresa o puesto"><select id="filter"><option value="">Todos los estados</option><option value="pendiente">Pendientes</option><option value="aprobado">Aprobados</option><option value="lista_espera">Lista de espera</option><option value="rechazado">Rechazados</option></select></div><div class="card tablewrap"><table class="table"><thead><tr><th>Participante</th><th>Organización / perfil</th><th>Socio</th><th>Influencia</th><th>Estado</th><th>Acción</th></tr></thead><tbody id="rows"></tbody></table><div id="empty" class="empty hidden">No hay solicitudes que coincidan.</div></div></section></main><script>${adminJS}</script>`,
    "Administración | " + EVENT.title,
  );
}
const adminJS = `
const sessionStorage={getItem:()=>'',setItem:()=>{},removeItem:()=>{}};
let KEY='',ALL=[];
const q=s=>document.querySelector(s),e=s=>String(s||'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function load(){const headers={'x-admin-key':KEY},[r,s,p,g]=await Promise.all([fetch('/api/admin/registrations',{headers}),fetch('/api/admin/settings/email-policy',{headers}),fetch('/api/admin/settings/phone-policy',{headers}),fetch('/api/admin/settings/public-registration',{headers})]);if(!r.ok||!s.ok||!p.ok||!g.ok){sessionStorage.removeItem('foro_admin');return toast('Verifica la clave administrativa e intenta nuevamente.','error','Acceso no autorizado')}ALL=await r.json();const policy=await s.json(),phonePolicy=await p.json(),publicPolicy=await g.json();installPhonePolicy();installPublicPolicy();q('#emailPolicy').checked=policy.require_work_email;showEmailPolicy(policy.require_work_email);q('#phonePolicy').checked=phonePolicy.validate_phone;showPhonePolicy(phonePolicy.validate_phone);q('#publicPolicy').checked=publicPolicy.public_registration_enabled;showPublicPolicy(publicPolicy.public_registration_enabled);q('#login').classList.add('hidden');q('#dash').classList.remove('hidden');render()}
function showEmailPolicy(active){q('#emailPolicyState').textContent=active?'Activada':'Desactivada';q('#emailPolicyHelp').textContent=active?'Los nuevos registros deben usar correo de empresa, universidad o institución.':'Los nuevos registros también pueden usar Gmail, Outlook, Yahoo y otras cuentas personales.'}
async function saveEmailPolicy(){const box=q('#emailPolicy'),active=box.checked;box.disabled=true;try{const r=await fetch('/api/admin/settings/email-policy',{method:'PATCH',headers:{'content-type':'application/json','x-admin-key':KEY},body:JSON.stringify({require_work_email:active})}),j=await r.json();if(!r.ok)throw Error(j.error||'No se pudo guardar');showEmailPolicy(j.require_work_email);toast('La restricción de correo quedó '+(j.require_work_email?'activada.':'desactivada.'),'success','Configuración actualizada')}catch(err){box.checked=!active;showEmailPolicy(!active);toast(err.message,'error')}finally{box.disabled=false}}
function installPhonePolicy(){if(q('#phonePolicy'))return;const card=q('#emailPolicy').closest('.card'),row=document.createElement('div');row.style.cssText='display:flex;align-items:center;justify-content:space-between;gap:20px;flex-wrap:wrap;border-top:1px solid var(--line);margin-top:16px;padding-top:16px';row.innerHTML='<div><b>Validar teléfono internacional</b><div class="small" id="phonePolicyHelp">Cargando configuración…</div></div><label class="radio" style="margin:0;cursor:pointer"><input id="phonePolicy" type="checkbox" role="switch"> <span id="phonePolicyState">Activada</span></label>';card.append(row);q('#phonePolicy').onchange=savePhonePolicy;installCountryFields()}
function showPhonePolicy(active){q('#phonePolicyState').textContent=active?'Activada':'Desactivada';q('#phonePolicyHelp').textContent=active?'Si se captura un teléfono, debe tener entre 7 y 15 números, sin +, espacios ni caracteres especiales.':'El formato del teléfono no será restringido en nuevos registros.';document.querySelectorAll('.phone-guide').forEach(x=>x.textContent=active?'Entre 7 y 15 dígitos. Solo números, sin +, espacios, guiones ni paréntesis.':'La validación del teléfono está desactivada.')}
function installPublicPolicy(){if(q('#publicPolicy'))return;const card=q('#emailPolicy').closest('.card'),row=document.createElement('div');row.style.cssText='display:flex;align-items:center;justify-content:space-between;gap:20px;flex-wrap:wrap;border-top:1px solid var(--line);margin-top:16px;padding-top:16px';row.innerHTML='<div><b>Registro público habilitado</b><div class="small" id="publicPolicyHelp"></div></div><label class="radio" style="margin:0;cursor:pointer"><input id="publicPolicy" type="checkbox" role="switch"> <span id="publicPolicyState">Activado</span></label>';card.append(row);q('#publicPolicy').onchange=savePublicPolicy}
function showPublicPolicy(active){q('#publicPolicyState').textContent=active?'Activado':'Desactivado';q('#publicPolicyHelp').textContent=active?'El formulario acepta nuevas solicitudes.':'El formulario público está cerrado; la administración conserva acceso.'}
async function savePublicPolicy(){const box=q('#publicPolicy'),active=box.checked;box.disabled=true;try{const r=await fetch('/api/admin/settings/public-registration',{method:'PATCH',headers:{'content-type':'application/json','x-admin-key':KEY},body:JSON.stringify({public_registration_enabled:active})}),j=await r.json();if(!r.ok)throw Error(j.error||'No se pudo guardar');showPublicPolicy(j.public_registration_enabled);toast('El registro público quedó '+(j.public_registration_enabled?'habilitado.':'deshabilitado.'),'success','Configuración actualizada')}catch(err){box.checked=!active;showPublicPolicy(!active);toast(err.message,'error')}finally{box.disabled=false}}
function installCountryFields(){for(const form of [q('#editForm')]){if(!form||form.elements.country)continue;const phone=form.elements.phone.closest('div'),guide=document.createElement('div');guide.className='small phone-guide';phone.append(guide);const field=document.createElement('div');field.innerHTML='<label>País *</label><select name="country" autocomplete="country-name" required>${countryOptionsHtml()}</select>';phone.after(field)}}
async function savePhonePolicy(){const box=q('#phonePolicy'),active=box.checked;box.disabled=true;try{const r=await fetch('/api/admin/settings/phone-policy',{method:'PATCH',headers:{'content-type':'application/json','x-admin-key':KEY},body:JSON.stringify({validate_phone:active})}),j=await r.json();if(!r.ok)throw Error(j.error||'No se pudo guardar');showPhonePolicy(j.validate_phone);toast('La validación telefónica quedó '+(j.validate_phone?'activada.':'desactivada.'),'success','Configuración actualizada')}catch(err){box.checked=!active;showPhonePolicy(!active);toast(err.message,'error')}finally{box.disabled=false}}
async function exportCsv(){const r=await fetch('/api/admin/registrations.csv',{headers:{'x-admin-key':KEY}});if(!r.ok){const j=await r.json().catch(()=>({}));return toast(j.error||'No se pudo exportar el reporte.','error')}const blob=await r.blob(),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download='registros-foro-ciberseguridad-2026.csv';document.body.append(a);a.click();a.remove();URL.revokeObjectURL(url);toast('El reporte CSV se descargó correctamente.','success','Reporte generado')}
function percentage(value,total){return total?Math.round(value*100/total):0}
function topGroups(key,limit=5){const counts={};for(const row of ALL){const value=String(row[key]||'Sin especificar').trim()||'Sin especificar';counts[value]=(counts[value]||0)+1}return Object.entries(counts).sort((a,b)=>b[1]-a[1]||a[0].localeCompare(b[0],'es')).slice(0,limit)}
function metricList(title,items,total){return '<div><b>'+e(title)+'</b>'+(items.length?items.map(([label,value])=>'<div class="metric-row"><span title="'+e(label)+'">'+e(label)+'</span><div class="metric-bar"><span style="width:'+percentage(value,total)+'%"></span></div><b>'+value+'</b></div>').join(''):'<p class="small">Sin datos disponibles.</p>')+'</div>'}
function renderDashboard(){const total=ALL.length,approved=ALL.filter(x=>x.status==='aprobado').length,attended=ALL.filter(x=>x.checked_in_at).length,members=ALL.filter(x=>x.club_member==='si').length,decisionProfiles=ALL.filter(x=>['decisor','influenciador'].includes(x.influence)).length,approvalRate=percentage(approved,total),attendanceRate=percentage(attended,approved),memberRate=percentage(members,total),decisionRate=percentage(decisionProfiles,total);q('#eventMetrics').innerHTML='<div class="metric-grid">'+[['Tasa de aprobación',approvalRate+'%',approved+' de '+total],['Asistencia confirmada',attendanceRate+'%',attended+' de '+approved+' aprobados'],['Socios ACLUVAQ',memberRate+'%',members+' registros'],['Decisores e influenciadores',decisionRate+'%',decisionProfiles+' perfiles']].map(x=>'<div class="metric"><span class="small">'+x[0]+'</span><strong>'+x[1]+'</strong><div class="small">'+x[2]+'</div><div class="metric-bar"><span style="width:'+parseInt(x[1],10)+'%"></span></div></div>').join('')+'</div><div class="metric-lists">'+metricList('Países con más registros',topGroups('country'),total)+metricList('Organizaciones con más registros',topGroups('company'),total)+'</div>'}
function render(){const f=q('#filter').value,s=q('#search').value.toLowerCase(),a=ALL.filter(x=>(!f||x.status===f)&&(!s||(x.first_name+' '+x.last_name+' '+x.company+' '+x.job_title).toLowerCase().includes(s))),count=k=>ALL.filter(x=>x.status===k).length,att=ALL.filter(x=>x.checked_in_at).length;q('#stats').innerHTML=[['Total',ALL.length],['Pendientes',count('pendiente')],['Aprobados',count('aprobado')],['Asistieron',att],['Ausentes',Math.max(0,count('aprobado')-att)]].map(x=>'<div class="card stat"><span class="small">'+x[0]+'</span><b>'+x[1]+'</b></div>').join('');renderDashboard();q('#rows').innerHTML=a.map(x=>'<tr><td><div class="person">'+e(x.first_name)+' '+e(x.last_name)+'</div><div class="small">'+e(x.email)+'</div></td><td>'+e(x.company)+'<div class="small">'+e(x.job_title)+' · '+e(x.job_level)+'</div></td><td>'+(x.club_member==='si'?'<b style="color:var(--ok)">Sí</b>':e(x.club_member.replace('_',' ')))+'</td><td><span class="score">'+x.score+'</span></td><td><span class="badge '+(x.checked_in_at?'asistio':x.status)+'">'+(x.checked_in_at?'Asistió':e(x.status.replace('_',' ')))+'</span>'+(x.ticket_code?'<div class="small">'+e(x.ticket_code)+'</div>':'')+'</td><td><div class="actions">'+(x.status!=='aprobado'?'<button class="approve" onclick="setStatus('+x.id+',\\'aprobado\\')">Aprobar</button>':'')+(x.status==='aprobado'?'<button class="ghost" onclick="resend('+x.id+')">Reenviar boleto</button>':'')+'<button class="ghost" onclick="editField('+x.id+')">Editar</button><button class="reject" onclick="removeRecord('+x.id+')">Eliminar</button><button class="wait" onclick="setStatus('+x.id+',\\'lista_espera\\')">Espera</button><button class="reject" onclick="setStatus('+x.id+',\\'rechazado\\')">Rechazar</button></div></td></tr>').join('');q('#empty').classList.toggle('hidden',a.length>0)}
async function setStatus(id,status){const labels={aprobado:'aprobar',lista_espera:'enviar a lista de espera',rechazado:'rechazar'},notes=await uxPrompt('Confirmar cambio de estado','Vas a '+(labels[status]||'actualizar')+' esta solicitud. El participante recibirá una notificación por correo.');if(notes===null)return;const r=await fetch('/api/admin/registrations/'+id,{method:'PATCH',headers:{'content-type':'application/json','x-admin-key':KEY},body:JSON.stringify({status,notes})}),j=await r.json();if(!r.ok)return toast(j.error||'No se pudo actualizar.','error');if(j.email_status==='failed')toast('El estado se guardó, pero el correo no pudo enviarse: '+(j.email_error||'revisa la configuración.'),'warning','Cambio guardado con advertencia');else toast('El estado cambió a '+status.replace('_',' ')+'. El participante fue notificado.','success','Estado actualizado');await load()}
async function resend(id){if(!await uxConfirm('Reenviar boleto','Se enviará nuevamente el boleto a la dirección registrada.',{confirmText:'Reenviar boleto'}))return;const r=await fetch('/api/admin/registrations/'+id+'/resend',{method:'POST',headers:{'x-admin-key':KEY}}),j=await r.json();toast(r.ok?'El boleto fue reenviado correctamente.':j.error||'No se pudo reenviar.',r.ok?'success':'error',r.ok?'Boleto enviado':'Error de envío')}
let EDIT_ID=null;
function editField(id){const x=ALL.find(v=>v.id===id);if(!x)return toast('Actualiza la lista e intenta nuevamente.','error','Registro no encontrado');EDIT_ID=id;const f=q('#editForm');['first_name','last_name','email','phone','country','company','job_title','job_level','influence','club_member','interest'].forEach(k=>f.elements[k].value=x[k]||'');q('#editTitle').textContent='Editar a '+x.first_name+' '+x.last_name;q('#editDialog').showModal()}
async function saveEdit(ev){ev.preventDefault();const f=ev.currentTarget,b=q('#saveEdit'),changes=Object.fromEntries(new FormData(f));b.disabled=true;b.textContent='Guardando…';try{const r=await fetch('/api/admin/registrations/'+EDIT_ID,{method:'PUT',headers:{'content-type':'application/json','x-admin-key':KEY},body:JSON.stringify({changes})}),j=await r.json();if(!r.ok)throw Error(j.error||'No se pudo modificar');q('#editDialog').close();toast(j.email_status==='failed'?'Los cambios se guardaron, pero el correo no pudo enviarse: '+(j.email_error||'revisa la configuración.'):'Los datos fueron guardados y el participante recibió la actualización.',j.email_status==='failed'?'warning':'success',j.email_status==='failed'?'Cambios guardados con advertencia':'Registro actualizado');await load()}catch(err){toast(err.message,'error')}finally{b.disabled=false;b.textContent='Guardar cambios'}}
async function removeRecord(id){const x=ALL.find(v=>v.id===id);if(!await uxConfirm('Eliminar registro definitivamente','Se eliminará el registro de '+x.first_name+' '+x.last_name+' y su historial de correos. Esta acción no se puede deshacer.',{danger:true,confirmText:'Sí, eliminar'}))return;const r=await fetch('/api/admin/registrations/'+id,{method:'DELETE',headers:{'x-admin-key':KEY}}),j=await r.json();if(!r.ok)return toast(j.error||'No se pudo eliminar.','error');toast('El registro y su historial de correos fueron eliminados.','success','Registro eliminado');await load()}
function manualRecord(){let d=q('#newDialog');if(!d){d=q('#editDialog').cloneNode(true);d.id='newDialog';const f=d.querySelector('form');f.id='newForm';d.querySelector('#editTitle').id='newTitle';d.querySelector('#newTitle').textContent='Nuevo registro manual';d.querySelector('#closeEdit').id='closeNew';d.querySelector('#cancelEdit').id='cancelNew';d.querySelector('#saveEdit').id='saveNew';d.querySelector('#saveNew').textContent='Crear registro';f.lastElementChild.insertAdjacentHTML('beforebegin','<label class="check" style="margin-top:18px;padding:14px;background:#eaf7fb;border-radius:10px"><input type="checkbox" name="verified" value="true"><span><b>Registro verificado y aprobado</b><br><span class="small">Generará el boleto QR y lo enviará inmediatamente al correo registrado.</span></span></label>');document.body.append(d);f.onsubmit=saveNew;d.querySelector('#closeNew').onclick=d.querySelector('#cancelNew').onclick=()=>d.close()}q('#newForm').reset();d.showModal()}
async function saveNew(ev){ev.preventDefault();const f=ev.currentTarget,b=q('#saveNew'),data=Object.fromEntries(new FormData(f));data.verified=!!f.elements.verified.checked;b.disabled=true;b.textContent='Creando…';try{const r=await fetch('/api/admin/registrations',{method:'POST',headers:{'content-type':'application/json','x-admin-key':KEY},body:JSON.stringify(data)}),j=await r.json();if(!r.ok)throw Error(j.error||'No se pudo crear el registro');q('#newDialog').close();const detail='Folio: '+j.request_code+(j.ticket_code?' · Boleto: '+j.ticket_code:'');toast(detail+(j.email_status==='failed'?' El correo no pudo enviarse; puedes reintentarlo desde el panel.':''),j.email_status==='failed'?'warning':'success',j.email_status==='failed'?'Registro creado con advertencia':'Registro creado');await load()}catch(err){toast(err.message,'error')}finally{b.disabled=false;b.textContent='Crear registro'}}
const dialog=document.createElement('dialog');dialog.id='editDialog';dialog.style.cssText='width:min(760px,94vw);max-height:90vh;border:0;border-radius:16px;padding:0;box-shadow:0 20px 70px #00152b55';dialog.innerHTML='<form id="editForm" style="padding:24px" method="dialog"><div style="display:flex;justify-content:space-between;gap:16px;align-items:start"><div><div class="eyebrow">Corrección de datos</div><h2 id="editTitle" style="margin:5px 0 18px">Editar registro</h2></div><button type="button" class="ghost" id="closeEdit">Cerrar</button></div><div class="fields"><div><label>Nombre *</label><input name="first_name" required></div><div><label>Apellidos *</label><input name="last_name" required></div><div><label>Correo electrónico *</label><input name="email" type="email" required></div><div><label>Teléfono</label><input name="phone" type="tel"></div><div class="full"><label>Empresa u organización *</label><input name="company" required></div><div><label>Puesto *</label><input name="job_title" required></div><div><label>Nivel del puesto *</label><select name="job_level" required><option>Alta dirección / Consejo</option><option>Dirección</option><option>Gerencia</option><option>Jefatura / Coordinación</option><option>Especialista / Consultoría</option><option>Académico / Estudiante</option><option>Otro</option></select></div><div><label>Influencia *</label><select name="influence" required><option value="decisor">Decide o autoriza inversiones</option><option value="influenciador">Evalúa y recomienda</option><option value="usuario">Usuario o especialista</option><option value="interesado">Interesado en aprender</option></select></div><div><label>¿Empresa socia? *</label><select name="club_member" required><option value="si">Sí</option><option value="no">No</option><option value="no_se">No está seguro</option></select></div><div class="full"><label>Interés o expectativa</label><textarea name="interest" maxlength="400"></textarea></div></div><div style="display:flex;justify-content:flex-end;gap:10px;margin-top:20px"><button type="button" class="ghost" id="cancelEdit">Cancelar</button><button type="submit" class="primary" id="saveEdit">Guardar cambios</button></div></form>';document.body.append(dialog);q('#editForm').onsubmit=saveEdit;q('#closeEdit').onclick=q('#cancelEdit').onclick=()=>dialog.close();const add=document.createElement('button');add.className='primary';add.textContent='Nuevo registro';add.onclick=manualRecord;q('#dash .dashhead .actions').prepend(add);q('#enter').onclick=()=>{KEY=q('#key').value;sessionStorage.setItem('foro_admin',KEY);load()};q('#exit').onclick=()=>{sessionStorage.removeItem('foro_admin');location.reload()};q('#emailPolicy').onchange=saveEmailPolicy;q('#exportCsv').onclick=exportCsv;q('#search').oninput=render;q('#filter').onchange=render;if(KEY)load();
const backup=document.createElement('button');backup.className='ghost';backup.textContent='Generar respaldo';backup.onclick=async()=>{backup.disabled=true;backup.textContent='Generando…';try{const r=await fetch('/api/admin/backup',{method:'POST',headers:{'x-admin-key':KEY}}),j=await r.json();toast(r.ok?'Se respaldaron '+j.records+' registros en S3.':j.error||'No se pudo generar el respaldo.',r.ok?'success':'error',r.ok?'Respaldo generado':'Error de respaldo')}finally{backup.disabled=false;backup.textContent='Generar respaldo'}};q('#exportCsv').after(backup);
async function forcePasswordChange(){const d=document.createElement('dialog');d.className='ux-dialog';d.innerHTML='<form class="ux-dialog-body"><div class="eyebrow">Protege tu cuenta</div><h2>Crea una nueva contraseña</h2><p class="small">La contraseña temporal solo funciona para este primer acceso. Elige una nueva de al menos 12 caracteres.</p><label>Nueva contraseña</label><input name="password" type="password" minlength="12" required autocomplete="new-password"><label style="margin-top:12px">Confirmar contraseña</label><input name="confirm" type="password" minlength="12" required autocomplete="new-password"><div class="ux-dialog-actions"><button class="primary" type="submit">Guardar y continuar</button></div></form>';document.body.append(d);d.oncancel=ev=>ev.preventDefault();d.querySelector('form').onsubmit=async ev=>{ev.preventDefault();const f=ev.currentTarget;if(f.password.value!==f.confirm.value)return toast('Las contraseñas no coinciden.','error');const r=await fetch('/api/auth/change-password',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({new_password:f.password.value})}),j=await r.json();if(!r.ok)return toast(j.error||'No se pudo actualizar la contraseña.','error');d.close();d.remove();toast('Tu nueva contraseña quedó guardada.','success','Contraseña actualizada')};d.showModal();await new Promise(resolve=>d.addEventListener('close',resolve,{once:true}))}
const keyLabel=q('#key').previousElementSibling;keyLabel.textContent='Clave administrativa de emergencia';const emailField=document.createElement('div');emailField.innerHTML='<label>Correo de usuario</label><input id="loginEmail" type="email" autocomplete="username"><label style="margin-top:12px">Contraseña</label><input id="loginPassword" type="password" autocomplete="current-password"><div class="small" style="margin:12px 0">O utiliza la clave de emergencia:</div>';keyLabel.before(emailField);q('#enter').onclick=async()=>{const email=q('#loginEmail').value.trim(),password=q('#loginPassword').value;if(email&&password){const r=await fetch('/api/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email,password})}),j=await r.json();if(!r.ok)return toast(j.error||'No se pudo iniciar sesión.','error');KEY='';sessionStorage.removeItem('foro_admin');if(j.must_change_password)await forcePasswordChange();await load();return}KEY=q('#key').value;sessionStorage.setItem('foro_admin',KEY);load()};q('#exit').onclick=async()=>{await fetch('/api/auth/logout',{method:'POST'});sessionStorage.removeItem('foro_admin');location.reload()};
async function usersDialog(){const r=await fetch('/api/admin/users',{headers:{'x-admin-key':KEY}}),users=await r.json();if(!r.ok)return toast(users.error||'No tienes permiso para administrar usuarios.','error');const d=document.createElement('dialog');d.className='ux-dialog';d.style.width='min(760px,calc(100vw - 28px))';d.innerHTML='<div class="ux-dialog-body"><div class="eyebrow">Seguridad y acceso</div><h2>Usuarios del sistema</h2><div id="userRows"></div><form id="userForm" class="fields" style="margin-top:18px"><div><label>Nombre</label><input name="name" required></div><div><label>Correo</label><input name="email" type="email" required></div><div><label>Contraseña inicial</label><input name="password" type="password" minlength="12" required></div><div><label>Rol</label><select name="role"><option value="admin">Administrador</option><option value="approver">Aprobador</option><option value="scanner">Scanner</option></select></div><div class="full ux-dialog-actions"><button type="button" class="ghost">Cerrar</button><button type="submit" class="primary">Crear usuario</button></div></form></div>';const renderUsers=()=>d.querySelector('#userRows').innerHTML=users.map(u=>'<div class="fact"><div style="flex:1"><b>'+e(u.name)+'</b><div class="small">'+e(u.email)+' · '+e(u.role)+' · '+(u.active?'Activo':'Desactivado')+'</div></div><button class="ghost" data-id="'+u.id+'" data-active="'+u.active+'">'+(u.active?'Desactivar':'Activar')+'</button></div>').join('');renderUsers();d.querySelector('button[type=button]').onclick=()=>{d.close();d.remove()};d.querySelector('#userRows').onclick=async ev=>{const b=ev.target.closest('[data-id]');if(!b)return;const response=await fetch('/api/admin/users/'+b.dataset.id,{method:'PATCH',headers:{'content-type':'application/json','x-admin-key':KEY},body:JSON.stringify({active:b.dataset.active!=='1'})});if(response.ok){const u=users.find(x=>String(x.id)===b.dataset.id);u.active=u.active?0:1;renderUsers()}};d.querySelector('#userForm').onsubmit=async ev=>{ev.preventDefault();const data=Object.fromEntries(new FormData(ev.currentTarget)),response=await fetch('/api/admin/users',{method:'POST',headers:{'content-type':'application/json','x-admin-key':KEY},body:JSON.stringify(data)}),j=await response.json();if(!response.ok)return toast(j.error||'No se pudo crear el usuario.','error');d.close();d.remove();toast('El usuario fue creado correctamente.','success','Usuario creado')};document.body.append(d);d.showModal()}
usersDialog=async function(){const r=await fetch('/api/admin/users',{headers:{'x-admin-key':KEY}}),users=await r.json();if(!r.ok)return toast(users.error||'No tienes permiso para administrar usuarios.','error');const d=document.createElement('dialog');d.className='ux-dialog';d.style.width='min(760px,calc(100vw - 28px))';d.innerHTML='<div class="ux-dialog-body"><div class="eyebrow">Seguridad y acceso</div><h2>Usuarios del sistema</h2><div id="userRows"></div><form id="userForm" class="fields" style="margin-top:18px"><div><label>Nombre</label><input name="name" required></div><div><label>Correo</label><input name="email" type="email" required></div><div><label>Rol</label><select name="role"><option value="admin">Administrador</option><option value="approver">Aprobador</option><option value="scanner">Scanner</option></select></div><div id="scannerPasswordBox" class="hidden"><label>Contraseña fija del scanner</label><input name="password" type="password" minlength="12" autocomplete="new-password"><div class="small">Mínimo 12 caracteres. No se enviará por correo.</div></div><div id="temporaryNotice" class="full statusbox"><b>Acceso temporal automático</b><div class="small">El sistema generará una contraseña temporal y la enviará por correo. El usuario deberá cambiarla en su primer acceso.</div></div><div class="full ux-dialog-actions"><button type="button" class="ghost">Cerrar</button><button type="submit" class="primary">Crear usuario</button></div></form></div>';const draw=()=>d.querySelector('#userRows').innerHTML=users.map(u=>'<div class="fact"><div style="flex:1"><b>'+e(u.name)+'</b><div class="small">'+e(u.email)+' · '+e(u.role)+' · '+(u.active?'Activo':'Desactivado')+'</div></div><button class="ghost" data-id="'+u.id+'" data-active="'+u.active+'">'+(u.active?'Desactivar':'Activar')+'</button></div>').join('');draw();const role=d.querySelector('[name=role]'),box=d.querySelector('#scannerPasswordBox'),notice=d.querySelector('#temporaryNotice'),password=d.querySelector('[name=password]');role.onchange=()=>{const fixed=role.value==='scanner';box.classList.toggle('hidden',!fixed);notice.classList.toggle('hidden',fixed);password.required=fixed};role.onchange();d.querySelector('button[type=button]').onclick=()=>{d.close();d.remove()};d.querySelector('#userRows').onclick=async ev=>{const b=ev.target.closest('[data-id]');if(!b)return;const response=await fetch('/api/admin/users/'+b.dataset.id,{method:'PATCH',headers:{'content-type':'application/json','x-admin-key':KEY},body:JSON.stringify({active:b.dataset.active!=='1'})});if(response.ok){const u=users.find(x=>String(x.id)===b.dataset.id);u.active=u.active?0:1;draw()}};d.querySelector('#userForm').onsubmit=async ev=>{ev.preventDefault();const f=ev.currentTarget,data=Object.fromEntries(new FormData(f)),button=f.querySelector('[type=submit]');button.disabled=true;button.textContent='Creando…';const response=await fetch('/api/admin/users',{method:'POST',headers:{'content-type':'application/json','x-admin-key':KEY},body:JSON.stringify(data)}),j=await response.json();button.disabled=false;button.textContent='Crear usuario';if(!response.ok)return toast(j.error||'No se pudo crear el usuario.','error');d.close();d.remove();if(j.email_status==='failed'&&j.temporary_password)return toast('El correo no pudo enviarse. Contraseña temporal: '+j.temporary_password,'warning','Guarda esta contraseña');toast(data.role==='scanner'?'La cuenta de scanner quedó creada con contraseña fija.':'Se envió al usuario su contraseña temporal y la liga de acceso.','success','Usuario creado')};document.body.append(d);d.showModal()};
const usersButton=document.createElement('button');usersButton.className='ghost';usersButton.textContent='Usuarios';usersButton.onclick=usersDialog;backup.after(usersButton);
const AUDIT_LABELS={'auth.login':'Inicio de sesión','auth.logout':'Cierre de sesión','user.create':'Usuario creado','user.activate':'Usuario activado','user.deactivate':'Usuario desactivado','settings.require_work_email':'Política de correo modificada','settings.validate_phone':'Validación telefónica modificada','settings.public_registration':'Registro público modificado','registrations.export_csv':'Reporte CSV exportado','backup.s3':'Respaldo generado','backup.s3_failed':'Error de respaldo','registration.create_manual':'Registro manual creado','ticket.resend':'Boleto reenviado','registration.update':'Registro editado','registration.delete':'Registro eliminado','registration.aprobado':'Solicitud aprobada','registration.lista_espera':'Solicitud en espera','registration.rechazado':'Solicitud rechazada','checkin':'Asistencia registrada'};
function auditLabel(action){return ({'auth.password_changed':'Contraseña actualizada','registration.cancelled_by_participant':'Participación cancelada'})[action]||AUDIT_LABELS[action]||String(action||'').replaceAll('.',' · ').replaceAll('_',' ')}
async function auditDialog(){const d=document.createElement('dialog');d.className='ux-dialog';d.style.width='min(1080px,calc(100vw - 28px))';d.innerHTML='<div class="ux-dialog-body"><div class="dashhead" style="align-items:start;margin-bottom:14px"><div><div class="eyebrow">Trazabilidad</div><h2 style="margin:5px 0">Registro de auditoría</h2><p class="small">Actividad administrativa y operativa más reciente.</p></div><button type="button" class="ghost" id="closeAudit">Cerrar</button></div><div class="toolbar" style="padding:0"><input id="auditSearch" placeholder="Buscar usuario, acción, folio o detalle"><button class="ghost" id="auditRefresh">Actualizar</button></div><div class="tablewrap" style="max-height:58vh"><table class="table audit-table"><thead><tr><th>Fecha y hora</th><th>Usuario</th><th>Acción</th><th>Registro</th><th>Detalle</th><th>IP</th></tr></thead><tbody id="auditRows"></tbody></table><div id="auditEmpty" class="empty hidden">No hay actividad que coincida.</div></div><div class="ux-dialog-actions"><span class="small" id="auditCount" style="margin-right:auto"></span><button class="ghost" id="auditMore">Ver más</button></div></div>';document.body.append(d);let items=[],offset=0,total=0;const draw=()=>{const term=d.querySelector('#auditSearch').value.toLowerCase(),rows=items.filter(x=>(x.actor+' '+x.action+' '+(x.registration_id||'')+' '+(x.details||'')+' '+(x.ip_address||'')).toLowerCase().includes(term));d.querySelector('#auditRows').innerHTML=rows.map(x=>'<tr><td>'+e(x.created_at)+'</td><td><b>'+e(x.actor)+'</b></td><td><span class="audit-action">'+e(auditLabel(x.action))+'</span></td><td>'+(x.registration_id?'#'+x.registration_id:'—')+'</td><td>'+e(x.details||'—')+'</td><td>'+e(x.ip_address||'—')+'</td></tr>').join('');d.querySelector('#auditEmpty').classList.toggle('hidden',rows.length>0);d.querySelector('#auditCount').textContent=items.length+' de '+total+' movimientos';d.querySelector('#auditMore').classList.toggle('hidden',items.length>=total)};const loadAudit=async(reset=false)=>{if(reset){offset=0;items=[]}const r=await fetch('/api/admin/audit?limit=100&offset='+offset,{headers:{'x-admin-key':KEY}}),j=await r.json();if(!r.ok){d.remove();return toast(j.error||'No se pudo consultar la auditoría.','error')}items=items.concat(j.items);offset=items.length;total=j.total;draw()};d.querySelector('#closeAudit').onclick=()=>{d.close();d.remove()};d.querySelector('#auditRefresh').onclick=()=>loadAudit(true);d.querySelector('#auditMore').onclick=()=>loadAudit(false);d.querySelector('#auditSearch').oninput=draw;d.oncancel=ev=>{ev.preventDefault();d.close();d.remove()};d.showModal();await loadAudit(true)}
const auditButton=document.createElement('button');auditButton.className='ghost';auditButton.textContent='Auditoría';auditButton.onclick=auditDialog;usersButton.after(auditButton);
`;
function ticketPage(row, token) {
  return page(
    `<main class="wrap"><article class="card ticket"><img class="ticket-logo" src="/assets/acluvaq-logo.png" alt="ACLUVAQ"><div class="tickethead"><div><div class="eyebrow">Boleto digital</div><h1 style="margin:6px 0">${EVENT.title}</h1></div><span id="ticketStatus" class="badge aprobado">Confirmado</span></div><p><b>${esc(row.first_name)} ${esc(row.last_name)}</b><br><span class="small">${esc(row.company)} · ${esc(row.job_title)}</span></p><div class="qr">${qrSvg(token)}</div><div style="text-align:center"><div class="ticketcode">${esc(row.ticket_code)}</div><p class="small">Presenta este QR en la entrada. No compartas esta pantalla.</p></div><div class="fact"><span class="ico">FECHA</span><div><b>${EVENT.date}</b><div class="small">${EVENT.time}</div></div></div><div id="cancelar" class="statusbox" style="margin-top:18px"><b>¿Cambió tu agenda?</b><p class="small">El cupo es limitado. Si ya no puedes acompañarnos, cancela tu participación para que otra persona pueda ocupar tu lugar.</p><button id="cancelParticipation" class="reject" type="button">Cancelar mi participación</button></div><div class="terms"><b>Términos y condiciones</b><br>Este boleto es personal, intransferible y válido exclusivamente para el ${EVENT.title} del 4 de noviembre de 2026. No concede acceso a ningún otro evento, actividad o beneficio de ACLUVAQ. Está sujeto a validación de identidad, aforo y escaneo único. La organización podrá negar el acceso por uso indebido, duplicación o alteración.</div></article></main><script>${ticketCancellationJS(token)}</script>`,
    "Boleto | " + EVENT.title,
  );
}
function ticketCancellationJS(token) {
  return `document.querySelector('#cancelParticipation').onclick=async()=>{if(!await uxConfirm('Cancelar participación','Tu boleto quedará invalidado y tu lugar se liberará para otra persona. Esta acción no se puede deshacer desde esta pantalla.',{danger:true,confirmText:'Sí, cancelar mi lugar'}))return;const b=document.querySelector('#cancelParticipation');b.disabled=true;b.textContent='Cancelando…';try{const r=await fetch('/api/cancel',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({token:${JSON.stringify(token)}})}),j=await r.json();if(!r.ok)throw Error(j.error||'No fue posible cancelar.');document.querySelector('.qr').innerHTML='<div style="padding:42px 16px;color:#a72c3b;font-weight:800">BOLETO INVALIDADO</div>';document.querySelector('#ticketStatus').className='badge rechazado';document.querySelector('#ticketStatus').textContent='Cancelado';document.querySelector('#cancelar').innerHTML='<b>Tu participación fue cancelada</b><p class="small">Tu lugar quedó liberado y este boleto ya no permite el acceso.</p>';toast('Tu participación se canceló correctamente.','success','Cancelación confirmada')}catch(err){toast(err.message,'error','No fue posible cancelar');b.disabled=false;b.textContent='Cancelar mi participación'}};`;
}
function scannerPage() {
  return page(
    `<main class="wrap"><section id="login" class="card login"><div class="eyebrow">Control de acceso</div><h1 class="h1">Escáner de boletos</h1><label for="key">Clave de escáner</label><input id="key" type="password" autocomplete="current-password"><button id="enter" class="primary" style="margin-top:14px">Activar escáner</button></section><section id="scan" class="card scanner hidden"><div class="dashhead"><div><div class="eyebrow">Acceso al evento</div><h1 class="h1">Escanear QR</h1></div></div><div id="scanStats" class="statusbox" style="margin:0 0 14px;text-align:center"><b style="font-size:1.55rem">Cargando asistencia…</b></div><div class="camera"><video id="video" playsinline muted></video><canvas id="qrCanvas" class="hidden"></canvas><div class="finder"></div><span id="cammsg">Inicia la cámara</span></div><button id="start" class="primary" style="width:100%;margin-top:14px">Usar cámara</button><div id="result"></div><div class="statusbox"><b>Captura manual</b><p class="small">Úsala si la cámara no puede leer el QR.</p><div style="display:flex;gap:8px"><input id="manual" placeholder="Código CYB26-…"><button id="manualBtn" class="ghost">Registrar</button></div></div></section></main><script src="/assets/jsqr.js"></script><script>${scannerJS}</script><script>${scannerEnhancementJS}</script>`,
    "Escáner | " + EVENT.title,
  );
}
const scannerJS = `let KEY='',busy=false,detector,scanMode='';const q=s=>document.querySelector(s),headers=()=>KEY?{'x-scanner-key':KEY}:{};function open(){q('#login').classList.add('hidden');q('#scan').classList.remove('hidden');loadStats()}async function loadStats(){const r=await fetch('/api/scanner/stats',{headers:headers()}),j=await r.json();if(!r.ok)return;const box=q('#scanStats');box.replaceChildren();const title=document.createElement('b');title.style.fontSize='1.55rem';title.textContent=j.checked_in+' personas han ingresado';const detail=document.createElement('div');detail.textContent=j.checked_in+' de '+j.approved+' asistentes aprobados — '+j.attendance_percentage+'%';const pending=document.createElement('div');pending.className='small';pending.textContent=j.pending_arrival+' pendientes de llegada · '+j.total_registrations+' solicitudes totales';box.append(title,detail,pending)}q('#manualBtn').onclick=()=>send({ticket_code:q('#manual').value.trim()});q('#start').onclick=async()=>{try{if(!navigator.mediaDevices||!navigator.mediaDevices.getUserMedia)throw Error('Safari no permitió usar la cámara. Revisa el permiso de cámara para este sitio.');if('BarcodeDetector'in window){detector=new BarcodeDetector({formats:['qr_code']});scanMode='native'}else if(window.jsQR){scanMode='canvas'}else throw Error('No fue posible iniciar el lector QR. Recarga la página e intenta nuevamente.');const stream=await navigator.mediaDevices.getUserMedia({video:{facingMode:{ideal:'environment'},width:{ideal:1280},height:{ideal:720}},audio:false});q('#video').srcObject=stream;await q('#video').play();q('#cammsg').classList.add('hidden');q('#start').textContent='Cámara activa';q('#start').disabled=true;tick()}catch(err){toast(err.message||'No pudimos abrir la cámara.','error','No pudimos abrir la cámara')}};async function tick(){if(!busy)try{if(scanMode==='native'){const codes=await detector.detect(q('#video'));if(codes[0])send({token:codes[0].rawValue})}else if(scanMode==='canvas'&&q('#video').readyState>=2){const v=q('#video'),c=q('#qrCanvas'),max=720,scale=Math.min(1,max/v.videoWidth);c.width=Math.max(1,Math.round(v.videoWidth*scale));c.height=Math.max(1,Math.round(v.videoHeight*scale));const ctx=c.getContext('2d',{willReadFrequently:true});ctx.drawImage(v,0,0,c.width,c.height);const img=ctx.getImageData(0,0,c.width,c.height),code=window.jsQR(img.data,img.width,img.height,{inversionAttempts:'dontInvert'});if(code&&code.data)send({token:code.data})}}catch{}requestAnimationFrame(tick)}const keyLabel=q('#key').previousElementSibling,userFields=document.createElement('div');userFields.innerHTML='<label>Correo de usuario</label><input id="scannerEmail" type="email" autocomplete="username"><label style="margin-top:12px">Contraseña</label><input id="scannerPassword" type="password" autocomplete="current-password"><div class="small" style="margin:12px 0">O utiliza la clave exclusiva de escáner:</div>';keyLabel.before(userFields);q('#enter').onclick=async()=>{const email=q('#scannerEmail').value.trim(),password=q('#scannerPassword').value;if(email&&password){const login=await fetch('/api/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email,password})}),j=await login.json();if(!login.ok||!['scanner','admin'].includes(j.role))return toast('La cuenta no tiene permiso de escáner.','error','Acceso no autorizado');KEY='';open();return}KEY=q('#key').value;const r=await fetch('/api/scanner/stats',{headers:headers()});if(!r.ok){KEY='';return toast('Verifica la clave de escáner e intenta nuevamente.','error','Acceso no autorizado')}open()};`;
const scannerEnhancementJS = `async function send(body){if(busy)return;busy=true;let d;try{const r=await fetch('/api/checkin',{method:'POST',headers:{'content-type':'application/json',...headers()},body:JSON.stringify(body)}),j=await r.json(),state=j.result_state||(r.ok?'valid':'invalid'),cfg={valid:{color:'#087a55',icon:'✓',title:'Acceso autorizado'},invalid:{color:'#a72c3b',icon:'!',title:'Boleto no válido'},reentry:{color:'#6f42a8',icon:'↻',title:'Reingreso detectado'},status_changed:{color:'#d89a00',icon:'!',title:'Estado del boleto cambió'}}[state]||{color:'#a72c3b',icon:'!',title:'No fue posible validar'};d=document.createElement('dialog');d.style.cssText='border:0;border-radius:24px;padding:0;width:min(520px,calc(100vw - 28px));box-shadow:0 24px 80px #00172f66;color:#07172a';const wrap=document.createElement('div');wrap.style.cssText='border-top:12px solid '+cfg.color+';padding:32px;text-align:center';const icon=document.createElement('div');icon.style.cssText='width:74px;height:74px;border-radius:50%;margin:0 auto 18px;display:grid;place-items:center;background:'+cfg.color+'18;color:'+cfg.color+';font-size:42px;font-weight:900';icon.textContent=cfg.icon;const eyebrow=document.createElement('div');eyebrow.className='eyebrow';eyebrow.style.color=cfg.color;eyebrow.textContent='Resultado del escaneo';const heading=document.createElement('h2');heading.style.margin='8px 0';heading.textContent=cfg.title;const name=document.createElement('div');name.style.cssText='font-size:1.25rem;font-weight:800';name.textContent=j.name||'Participante no identificado';wrap.append(icon,eyebrow,heading,name);if(j.company){const company=document.createElement('div');company.className='small';company.style.marginTop='5px';company.textContent=j.company;wrap.append(company)}const status=document.createElement('div');status.style.cssText='margin:18px 0;padding:12px;border-radius:10px;background:#f3f6f9';const label=document.createElement('b');label.textContent='Estatus: ';status.append(label,document.createTextNode(state==='valid'?'Aprobado · ingreso registrado':state==='reentry'?'Aprobado · ya había ingresado':state==='status_changed'?String(j.ticket_status||'No aprobado').replace('_',' '):j.error||'Inexistente o alterado'));wrap.append(status);if(state==='invalid'){const ack=document.createElement('button');ack.id='scanAck';ack.className='primary';ack.style.background=cfg.color;ack.textContent='Entendido, cerrar';wrap.append(ack)}else{const note=document.createElement('div');note.className='small';note.textContent='Esta confirmación se cerrará automáticamente.';wrap.append(note)}d.append(wrap);document.body.append(d);d.showModal();const close=()=>{if(!d)return;d.close();d.remove();d=null;setTimeout(()=>busy=false,900)};if(state==='invalid')d.querySelector('#scanAck').onclick=close;else setTimeout(close,3600);if(state==='valid')loadStats();if(navigator.vibrate)navigator.vibrate(state==='valid'?100:[100,80,100])}catch{if(d){d.remove();d=null}toast('No se pudo validar el boleto.','error');setTimeout(()=>busy=false,1800)}};`;
async function api(req, env, url) {
  if (["POST", "PUT", "PATCH", "DELETE"].includes(req.method)) {
    const declaredLength = Number(req.headers.get("content-length") || 0);
    if (Number.isFinite(declaredLength) && declaredLength > 32768)
      return json({ error: "La solicitud excede el tamaño permitido." }, 413);
    if (!mutationOriginOK(req)) return json({ error: "Origen no autorizado." }, 403);
  }
  if (url.pathname === "/api/auth/login" && req.method === "POST") {
    if (!(await rateLimit(req, env, "login", 5, 900))) return json({ error: "Demasiados intentos. Espera 15 minutos." }, 429);
    const d = await req.json().catch(() => null), email = String(d?.email || "").trim().toLowerCase(), password = String(d?.password || "");
    if (!d || password.length < 1 || password.length > 128)
      return json({ error: "Correo o contraseña incorrectos." }, 401);
    const user = await env.DB.prepare("SELECT * FROM users WHERE email=? AND active=1").bind(email).first();
    if (!user || !(await verifyPassword(password, user.password_hash))) {
      await audit(req, env, "auth.login_failed", null, "Cuenta o credencial inválida", email || "anonymous");
      return json({ error: "Correo o contraseña incorrectos." }, 401);
    }
    const token = b64url(crypto.getRandomValues(new Uint8Array(32))), tokenHash = await sha256Hex(token);
    await env.DB.batch([
      env.DB.prepare("INSERT INTO user_sessions(user_id,token_hash,expires_at) VALUES(?,?,datetime('now','+8 hours'))").bind(user.id, tokenHash),
      env.DB.prepare("UPDATE users SET last_login_at=CURRENT_TIMESTAMP WHERE id=?").bind(user.id),
    ]);
    await audit(req, env, "auth.login", null, user.email, user.email);
    return new Response(JSON.stringify({ ok: true, name: user.name, role: user.role, must_change_password: !!user.must_change_password }), { headers: { "content-type": "application/json", "set-cookie": `foro_session=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`, "cache-control": "no-store" } });
  }
  if (url.pathname === "/api/auth/logout" && req.method === "POST") {
    const token = cookieValue(req, "foro_session");
    if (token) {
      const actor = await getActor(req, env);
      if (actor) await audit(req, env, "auth.logout", null, actor.email || actor.name, actor.actor);
      await env.DB.prepare("UPDATE user_sessions SET revoked_at=CURRENT_TIMESTAMP WHERE token_hash=?").bind(await sha256Hex(token)).run();
    }
    return new Response(JSON.stringify({ ok: true }), { headers: { "content-type": "application/json", "set-cookie": "foro_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0", "cache-control": "no-store" } });
  }
  if (url.pathname === "/api/auth/me" && req.method === "GET") {
    const actor = await getActor(req, env);
    return actor ? json({ name: actor.name, email: actor.email || null, role: actor.role, must_change_password: !!actor.must_change_password }) : json({ error: "No autorizado" }, 401);
  }
  if (url.pathname === "/api/auth/change-password" && req.method === "POST") {
    const actor = await getActor(req, env);
    if (!actor?.id) return json({ error: "No autorizado" }, 401);
    const d = await req.json().catch(() => null);
    if (!d || String(d.new_password || "").length < 12 || String(d.new_password || "").length > 128)
      return json({ error: "La nueva contraseña debe tener entre 12 y 128 caracteres." }, 400);
    const tokenHash = await sha256Hex(cookieValue(req, "foro_session"));
    await env.DB.batch([
      env.DB.prepare("UPDATE users SET password_hash=?,must_change_password=0,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(await passwordHash(String(d.new_password)), actor.id),
      env.DB.prepare("UPDATE user_sessions SET revoked_at=CURRENT_TIMESTAMP WHERE user_id=? AND token_hash<>? AND revoked_at IS NULL").bind(actor.id, tokenHash),
    ]);
    await audit(req, env, "auth.password_changed", null, actor.email, actor.actor);
    return json({ ok: true });
  }
  let apiActor = null;
  if (url.pathname.startsWith("/api/admin/")) {
    const approverRoute = (url.pathname === "/api/admin/registrations" && req.method === "GET") || (/^\/api\/admin\/registrations\/\d+$/.test(url.pathname) && req.method === "PATCH") || (url.pathname.startsWith("/api/admin/settings/") && req.method === "GET");
    apiActor = await roleOK(req, env, approverRoute ? ["admin", "approver"] : ["admin"]);
  }
  if (url.pathname.startsWith("/api/admin/") && !apiActor) {
    if (!(await rateLimit(req, env, "admin_auth", 5, 900)))
      return json({ error: "Acceso bloqueado temporalmente por demasiados intentos." }, 429);
    return json({ error: "No autorizado" }, 401);
  }
  if (url.pathname === "/api/admin/audit" && req.method === "GET") {
    const limit = Math.min(200, Math.max(1, Number.parseInt(url.searchParams.get("limit") || "100", 10) || 100));
    const offset = Math.max(0, Number.parseInt(url.searchParams.get("offset") || "0", 10) || 0);
    const [countRow, page] = await Promise.all([
      env.DB.prepare("SELECT COUNT(*) AS total FROM admin_audit_log").first(),
      env.DB.prepare("SELECT id,actor,action,registration_id,details,ip_address,created_at FROM admin_audit_log ORDER BY id DESC LIMIT ? OFFSET ?").bind(limit, offset).all(),
    ]);
    return json({ items: page.results, total: Number(countRow?.total || 0), limit, offset });
  }
  if (url.pathname === "/api/admin/users" && req.method === "GET") {
    const { results } = await env.DB.prepare("SELECT id,name,email,role,active,created_at,updated_at,last_login_at FROM users ORDER BY name").all();
    return json(results);
  }
  if (url.pathname === "/api/admin/users" && req.method === "POST") {
    const d = await req.json().catch(() => null);
    if (!d || !d.name || !d.email || !["admin", "approver", "scanner"].includes(d.role))
      return json({ error: "Completa nombre, correo y rol." }, 400);
    const fixedScannerPassword = d.role === "scanner" ? String(d.password || "") : "";
    if (String(d.name).trim().length > 120 || String(d.email).trim().length > 254 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(d.email).trim()))
      return json({ error: "Verifica el nombre y el formato del correo electrónico." }, 400);
    if (d.role === "scanner" && (fixedScannerPassword.length < 12 || fixedScannerPassword.length > 128))
      return json({ error: "La contraseña fija del escáner debe tener entre 12 y 128 caracteres." }, 400);
    const email = String(d.email).trim().toLowerCase();
    const generatedPassword = d.role === "scanner" ? null : temporaryPassword();
    const initialPassword = fixedScannerPassword || generatedPassword;
    try {
      const hash = await passwordHash(initialPassword);
      const result = await env.DB.prepare("INSERT INTO users(name,email,password_hash,role,must_change_password) VALUES(?,?,?,?,?)")
        .bind(String(d.name).trim(), email, hash, d.role, d.role === "scanner" ? 0 : 1)
        .run();
      let mail = { status: "not_required", error: null };
      if (generatedPassword)
        mail = await sendSystemUserInvite(env, { name: String(d.name).trim(), email, role: d.role }, generatedPassword, PUBLIC_ORIGIN);
      await audit(req, env, "user.create", null, `${email}:${d.role}:email_${mail.status}`);
      return json({ ok: true, id: result.meta?.last_row_id ?? null, email_status: mail.status, email_error: mail.error, temporary_password: mail.status === "failed" ? generatedPassword : null }, 201);
    } catch (error) {
      console.error("user.create failed", error);
      if (/unique|constraint/i.test(String(error?.message || error)))
        return json({ error: "Ya existe un usuario registrado con ese correo electrónico." }, 409);
      return json({ error: "No fue posible crear el usuario. Intenta nuevamente." }, 500);
    }
  }
  const userMatch = url.pathname.match(/^\/api\/admin\/users\/(\d+)$/);
  if (userMatch && req.method === "PATCH") {
    const d = await req.json().catch(() => null);
    if (!d || typeof d.active !== "boolean") return json({ error: "Estado inválido." }, 400);
    await env.DB.prepare("UPDATE users SET active=?,updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(d.active ? 1 : 0, +userMatch[1]).run();
    if (!d.active) await env.DB.prepare("UPDATE user_sessions SET revoked_at=CURRENT_TIMESTAMP WHERE user_id=? AND revoked_at IS NULL").bind(+userMatch[1]).run();
    await audit(req, env, d.active ? "user.activate" : "user.deactivate", null, String(userMatch[1]));
    return json({ ok: true });
  }
  if (url.pathname === "/api/register" && req.method === "POST") {
    if ((await setting(env, "public_registration_enabled", "true")) !== "true")
      return json({ error: "El registro público está cerrado temporalmente." }, 403);
    if (!(await rateLimit(req, env, "register", 8, 900)))
      return json({ error: "Se alcanzó el límite de registros. Intenta nuevamente más tarde." }, 429);
    const d = await req.json().catch(() => null),
      required = [
        "first_name",
        "last_name",
        "email",
        "country",
        "company",
        "club_member",
        "job_title",
        "job_level",
        "influence",
      ];
    if (!d || required.some((k) => !String(d[k] || "").trim()))
      return json({ error: "Completa todos los campos obligatorios." }, 400);
    if (!registrationFieldsWithinLimits(d))
      return json({ error: "Uno o más campos exceden la longitud permitida." }, 400);
    if (d.necessary_consent !== "true")
      return json({ error: "Debes aceptar el tratamiento necesario de datos para gestionar tu participación." }, 400);
    if (!(await verifyTurnstile(req, env, d["cf-turnstile-response"])))
      return json({ error: "No pudimos verificar que eres una persona. Actualiza la página e intenta nuevamente." }, 400);
    if (!validCountry(d.country))
      return json({ error: "Selecciona un país válido de la lista." }, 400);
    const check = validWorkEmail(d.email, await workEmailRequired(env));
    if (!check.ok) return json({ error: check.error }, 400);
    const phoneCheck = validPhone(
      d.phone,
      await phoneValidationRequired(env),
    );
    if (!phoneCheck.ok) return json({ error: phoneCheck.error }, 400);
    const email = d.email.trim().toLowerCase(),
      exists = await env.DB.prepare(
        "SELECT request_code FROM registrations WHERE lower(trim(email))=?",
      )
        .bind(email)
        .first();
    if (exists)
      return json(
        { error: "Ya existe una solicitud asociada a este correo. Revisa el mensaje de confirmación recibido o usa la opción de consultar estado." },
        409,
      );
    const request_code = code("SOL");
    await env.DB.prepare(
      "INSERT INTO registrations (request_code,first_name,last_name,email,phone,country,company,club_member,member_company,job_title,job_level,influence,interest,email_domain,email_type,necessary_consent_at,privacy_notice_version,additional_comms_consent) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP,?,?)",
    )
      .bind(
        request_code,
        d.first_name.trim(),
        d.last_name.trim(),
        email,
        (d.phone || "").trim(),
        d.country.trim(),
        d.company.trim(),
        d.club_member,
        (d.member_company || "").trim(),
        d.job_title.trim(),
        d.job_level,
        d.influence,
        (d.interest || "").trim(),
        check.domain,
        check.type,
        await setting(env, "privacy_notice_version", "2026-09"),
        d.additional_comms_consent === "true" ? 1 : 0,
      )
      .run();
    const row = await env.DB.prepare(
        "SELECT id,first_name,email,request_code FROM registrations WHERE request_code=?",
      )
        .bind(request_code)
        .first(),
      mail = await sendReviewEmail(env, row);
    return json({ request_code, email_status: mail.status }, 201);
  }
  if (url.pathname === "/api/status" && ["GET", "POST"].includes(req.method)) {
    if (!(await rateLimit(req, env, "status", 12, 300)))
      return json({ error: "Demasiadas consultas. Espera unos minutos antes de volver a intentar." }, 429);
    const statusInput = req.method === "POST" ? await req.json().catch(() => ({})) : Object.fromEntries(url.searchParams),
      folio = String(statusInput.folio || "").trim().toUpperCase(),
      email = String(statusInput.email || "").trim().toLowerCase(),
      row = await env.DB.prepare(
        "SELECT status,ticket_code,country FROM registrations WHERE upper(trim(request_code))=? AND lower(trim(email))=?",
      )
        .bind(folio, email)
        .first();
    if (!row)
      return json(
        {
          error:
            "No encontramos la solicitud. Verifica que el folio y el correo coincidan exactamente con los del registro.",
        },
        404,
      );
    if (row.status === "aprobado" && row.ticket_code)
      row.ticket_url =
        "/ticket?token=" +
        encodeURIComponent(await ticketToken(row.ticket_code, env));
    return json(row);
  }
  if (
    url.pathname === "/api/admin/settings/email-policy" &&
    req.method === "GET"
  ) {
    return json({ require_work_email: await workEmailRequired(env) });
  }
  if (
    url.pathname === "/api/admin/settings/email-policy" &&
    req.method === "PATCH"
  ) {
    const d = await req.json().catch(() => null);
    if (!d || typeof d.require_work_email !== "boolean")
      return json({ error: "Configuración inválida." }, 400);
    await env.DB.prepare(
      "INSERT INTO application_settings (setting_key,setting_value,updated_at) VALUES ('require_work_email',?,CURRENT_TIMESTAMP) ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value,updated_at=CURRENT_TIMESTAMP",
    )
      .bind(String(d.require_work_email))
      .run();
    await audit(req, env, "settings.require_work_email", null, String(d.require_work_email));
    return json({ require_work_email: d.require_work_email });
  }
  if (
    url.pathname === "/api/admin/settings/phone-policy" &&
    req.method === "GET"
  ) {
    return json({ validate_phone: await phoneValidationRequired(env) });
  }
  if (
    url.pathname === "/api/admin/settings/phone-policy" &&
    req.method === "PATCH"
  ) {
    const d = await req.json().catch(() => null);
    if (!d || typeof d.validate_phone !== "boolean")
      return json({ error: "Configuración inválida." }, 400);
    await env.DB.prepare(
      "INSERT INTO application_settings (setting_key,setting_value,updated_at) VALUES ('validate_phone',?,CURRENT_TIMESTAMP) ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value,updated_at=CURRENT_TIMESTAMP",
    )
      .bind(String(d.validate_phone))
      .run();
    await audit(req, env, "settings.validate_phone", null, String(d.validate_phone));
    return json({ validate_phone: d.validate_phone });
  }
  if (url.pathname === "/api/admin/settings/public-registration" && req.method === "GET")
    return json({ public_registration_enabled: (await setting(env, "public_registration_enabled", "true")) === "true" });
  if (url.pathname === "/api/admin/settings/public-registration" && req.method === "PATCH") {
    const d = await req.json().catch(() => null);
    if (!d || typeof d.public_registration_enabled !== "boolean")
      return json({ error: "Configuración inválida." }, 400);
    await env.DB.prepare("INSERT INTO application_settings(setting_key,setting_value,updated_at) VALUES('public_registration_enabled',?,CURRENT_TIMESTAMP) ON CONFLICT(setting_key) DO UPDATE SET setting_value=excluded.setting_value,updated_at=CURRENT_TIMESTAMP")
      .bind(String(d.public_registration_enabled)).run();
    await audit(req, env, "settings.public_registration", null, String(d.public_registration_enabled));
    return json({ public_registration_enabled: d.public_registration_enabled });
  }
  if (
    url.pathname === "/api/admin/registrations.csv" &&
    req.method === "GET"
  ) {
    const { results } = await env.DB.prepare(
      "SELECT request_code,first_name,last_name,email,phone,country,company,club_member,member_company,job_title,job_level,influence,interest,email_domain,email_type,status,admin_notes,ticket_code,created_at,reviewed_at,necessary_consent_at,privacy_notice_version,additional_comms_consent,checked_in_at,checked_in_by FROM registrations ORDER BY created_at ASC",
    ).all();
    const headers = [
      "Folio",
      "Nombre",
      "Apellidos",
      "Correo",
      "Teléfono",
      "País",
      "Empresa u organización",
      "Socio ACLUVAQ",
      "Empresa socia",
      "Puesto",
      "Nivel del puesto",
      "Influencia",
      "Interés o expectativa",
      "Dominio del correo",
      "Tipo de correo",
      "Estado",
      "Notas administrativas",
      "Boleto",
      "Fecha de registro",
      "Fecha de revisión",
      "Consentimiento necesario",
      "Versión aviso de privacidad",
      "Comunicaciones adicionales",
      "Asistió",
      "Fecha de asistencia",
      "Registrado por",
    ];
    const keys = [
      "request_code",
      "first_name",
      "last_name",
      "email",
      "phone",
      "country",
      "company",
      "club_member",
      "member_company",
      "job_title",
      "job_level",
      "influence",
      "interest",
      "email_domain",
      "email_type",
      "status",
      "admin_notes",
      "ticket_code",
      "created_at",
      "reviewed_at",
      "necessary_consent_at",
      "privacy_notice_version",
      "additional_comms_consent",
    ];
    const lines = [
      headers.map(csvCell).join(","),
      ...results.map((row) =>
        [
          ...keys.map((key) => row[key]),
          row.checked_in_at ? "Sí" : "No",
          row.checked_in_at,
          row.checked_in_by,
        ]
          .map(csvCell)
          .join(","),
      ),
    ];
    await audit(req, env, "registrations.export_csv", null, `${results.length} registros`);
    return new Response("\uFEFF" + lines.join("\r\n"), {
      headers: {
        "content-type": "text/csv; charset=utf-8",
        "content-disposition":
          'attachment; filename="registros-foro-ciberseguridad-2026.csv"',
        "cache-control": "no-store",
      },
    });
  }
  if (url.pathname === "/api/admin/backup" && req.method === "POST") {
    const { results } = await env.DB.prepare("SELECT * FROM registrations ORDER BY created_at ASC").all();
    try {
      const key = await uploadS3Backup(env, { event: EVENT.title, generated_at: new Date().toISOString(), records: results });
      await audit(req, env, "backup.s3", null, key);
      return json({ ok: true, key, records: results.length });
    } catch (error) {
      await audit(req, env, "backup.s3_failed", null, error.message);
      return json({ error: error.message }, 502);
    }
  }
  if (url.pathname === "/api/admin/registrations" && req.method === "GET") {
    const statement = apiActor.role === "approver"
      ? env.DB.prepare("SELECT id,request_code,first_name,last_name,company,club_member,job_title,job_level,influence,interest,status,created_at,reviewed_at,checked_in_at, CASE job_level WHEN 'Alta dirección / Consejo' THEN 4 WHEN 'Dirección' THEN 3 WHEN 'Gerencia' THEN 2 ELSE 1 END + CASE influence WHEN 'decisor' THEN 4 WHEN 'influenciador' THEN 3 WHEN 'usuario' THEN 1 ELSE 0 END + CASE club_member WHEN 'si' THEN 2 ELSE 0 END AS score FROM registrations ORDER BY CASE status WHEN 'pendiente' THEN 0 ELSE 1 END, score DESC, created_at ASC")
      : env.DB.prepare("SELECT *, CASE job_level WHEN 'Alta dirección / Consejo' THEN 4 WHEN 'Dirección' THEN 3 WHEN 'Gerencia' THEN 2 ELSE 1 END + CASE influence WHEN 'decisor' THEN 4 WHEN 'influenciador' THEN 3 WHEN 'usuario' THEN 1 ELSE 0 END + CASE club_member WHEN 'si' THEN 2 ELSE 0 END AS score FROM registrations ORDER BY CASE status WHEN 'pendiente' THEN 0 ELSE 1 END, score DESC, created_at ASC");
    const { results } = await statement.all();
    return json(results);
  }
  if (url.pathname === "/api/admin/registrations" && req.method === "POST") {
    const d = await req.json().catch(() => null),
      required = [
        "first_name",
        "last_name",
        "email",
        "country",
        "company",
        "job_title",
        "job_level",
        "influence",
        "club_member",
      ];
    if (!d || required.some((k) => !String(d[k] || "").trim()))
      return json({ error: "Completa todos los campos obligatorios." }, 400);
    if (!registrationFieldsWithinLimits(d))
      return json({ error: "Uno o más campos exceden la longitud permitida." }, 400);
    if (!validCountry(d.country))
      return json({ error: "Selecciona un país válido de la lista." }, 400);
    if (
      !["decisor", "influenciador", "usuario", "interesado"].includes(
        d.influence,
      )
    )
      return json({ error: "Influencia inválida." }, 400);
    if (!["si", "no", "no_se"].includes(d.club_member))
      return json({ error: "La condición de socio es inválida." }, 400);
    const check = validWorkEmail(d.email, await workEmailRequired(env));
    if (!check.ok) return json({ error: check.error }, 400);
    const phoneCheck = validPhone(
      d.phone,
      await phoneValidationRequired(env),
    );
    if (!phoneCheck.ok) return json({ error: phoneCheck.error }, 400);
    const email = d.email.trim().toLowerCase(),
      exists = await env.DB.prepare(
        "SELECT request_code FROM registrations WHERE lower(trim(email))=?",
      )
        .bind(email)
        .first();
    if (exists)
      return json(
        { error: `Este correo ya tiene una solicitud: ${exists.request_code}` },
        409,
      );
    const status = d.verified === true ? "aprobado" : "pendiente",
      request_code = code("SOL"),
      ticket_code = status === "aprobado" ? code("CYB26") : null;
    await env.DB.prepare(
      "INSERT INTO registrations (request_code,first_name,last_name,email,phone,country,company,club_member,job_title,job_level,influence,interest,email_domain,email_type,status,ticket_code,reviewed_at,admin_notes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,CASE WHEN ?='aprobado' THEN CURRENT_TIMESTAMP ELSE NULL END,?)",
    )
      .bind(
        request_code,
        d.first_name.trim(),
        d.last_name.trim(),
        email,
        (d.phone || "").trim(),
        d.country.trim(),
        d.company.trim(),
        d.club_member,
        d.job_title.trim(),
        d.job_level.trim(),
        d.influence,
        (d.interest || "").trim(),
        check.domain,
        check.type,
        status,
        ticket_code,
        status,
        "Registro creado manualmente por el administrador",
      )
      .run();
    const row = await env.DB.prepare(
      "SELECT id,first_name,email,request_code,ticket_code,status FROM registrations WHERE request_code=?",
    )
      .bind(request_code)
      .first();
    const mail =
      status === "aprobado"
        ? await sendTicketEmail(env, row, PUBLIC_ORIGIN)
        : await sendReviewEmail(env, row);
    await audit(req, env, "registration.create_manual", row.id, status);
    return json(
      {
        ok: true,
        request_code,
        ticket_code,
        email_status: mail.status,
        email_error: mail.error,
      },
      201,
    );
  }
  const resendMatch = url.pathname.match(
    /^\/api\/admin\/registrations\/(\d+)\/resend$/,
  );
  if (resendMatch && req.method === "POST") {
    const row = await env.DB.prepare(
      "SELECT id,first_name,email,request_code,ticket_code,status FROM registrations WHERE id=?",
    )
      .bind(+resendMatch[1])
      .first();
    if (!row || row.status !== "aprobado" || !row.ticket_code)
      return json(
        { error: "La solicitud no está aprobada o no tiene boleto." },
        400,
      );
    const mail = await sendTicketEmail(env, row, PUBLIC_ORIGIN);
    await audit(req, env, "ticket.resend", row.id, mail.status);
    return mail.status === "sent"
      ? json({ ok: true })
      : json({ error: mail.error || "No se pudo enviar el correo." }, 502);
  }
  const match = url.pathname.match(/^\/api\/admin\/registrations\/(\d+)$/);
  if (match && req.method === "PUT") {
    const d = await req.json(),
      fields = new Set([
        "first_name",
        "last_name",
        "email",
        "phone",
        "country",
        "company",
        "job_title",
        "job_level",
        "influence",
        "club_member",
        "interest",
      ]),
      changes =
        d.changes && typeof d.changes === "object"
          ? d.changes
          : { [d.field]: d.value },
      entries = Object.entries(changes).filter(([k]) => fields.has(k));
    if (!entries.length)
      return json({ error: "No se recibieron campos editables." }, 400);
    if (!registrationFieldsWithinLimits(changes))
      return json({ error: "Uno o más campos exceden la longitud permitida." }, 400);
    const required = new Set([
      "first_name",
      "last_name",
      "email",
      "country",
      "company",
      "job_title",
      "job_level",
      "influence",
      "club_member",
    ]);
    for (const [k, v] of entries)
      if (required.has(k) && !String(v || "").trim())
        return json(
          { error: "Los campos obligatorios no pueden quedar vacíos." },
          400,
        );
    if (
      changes.influence &&
      !["decisor", "influenciador", "usuario", "interesado"].includes(
        changes.influence,
      )
    )
      return json({ error: "Influencia inválida." }, 400);
    if (
      changes.club_member &&
      !["si", "no", "no_se"].includes(changes.club_member)
    )
      return json({ error: "La condición de socio es inválida." }, 400);
    if (changes.country !== undefined && !validCountry(changes.country))
      return json({ error: "Selecciona un país válido de la lista." }, 400);
    if (changes.phone !== undefined) {
      const phoneCheck = validPhone(
        changes.phone,
        await phoneValidationRequired(env),
      );
      if (!phoneCheck.ok) return json({ error: phoneCheck.error }, 400);
    }
    const statements = [];
    if (changes.email !== undefined) {
      const check = validWorkEmail(
        changes.email,
        await workEmailRequired(env),
      );
      if (!check.ok) return json({ error: check.error }, 400);
      changes.email = String(changes.email).trim().toLowerCase();
      const duplicate = await env.DB.prepare(
        "SELECT id FROM registrations WHERE lower(trim(email))=? AND id<>?",
      )
        .bind(changes.email, +match[1])
        .first();
      if (duplicate)
        return json(
          { error: "Ese correo ya pertenece a otra solicitud." },
          409,
        );
      statements.push(
        env.DB.prepare(
          "UPDATE registrations SET email_domain=?,email_type=? WHERE id=?",
        ).bind(check.domain, check.type, +match[1]),
      );
    }
    const updateSql = {
      first_name: "UPDATE registrations SET first_name=? WHERE id=?",
      last_name: "UPDATE registrations SET last_name=? WHERE id=?",
      email: "UPDATE registrations SET email=? WHERE id=?",
      phone: "UPDATE registrations SET phone=? WHERE id=?",
      country: "UPDATE registrations SET country=? WHERE id=?",
      company: "UPDATE registrations SET company=? WHERE id=?",
      job_title: "UPDATE registrations SET job_title=? WHERE id=?",
      job_level: "UPDATE registrations SET job_level=? WHERE id=?",
      influence: "UPDATE registrations SET influence=? WHERE id=?",
      club_member: "UPDATE registrations SET club_member=? WHERE id=?",
      interest: "UPDATE registrations SET interest=? WHERE id=?",
    };
    for (const [field, raw] of entries)
      statements.push(env.DB.prepare(updateSql[field]).bind(String(changes[field] ?? raw).trim(), +match[1]));
    await env.DB.batch(statements);
    const row = await env.DB.prepare(
        "SELECT id,first_name,email,request_code FROM registrations WHERE id=?",
      )
        .bind(+match[1])
        .first(),
      mail = await sendDataUpdateEmail(env, row);
    await audit(req, env, "registration.update", +match[1], entries.map(([k]) => k).join(","));
    return json({
      ok: true,
      updated: entries.map(([k]) => k),
      email_status: mail.status,
      email_error: mail.error,
    });
  }
  if (match && req.method === "DELETE") {
    const exists = await env.DB.prepare(
      "SELECT id FROM registrations WHERE id=?",
    )
      .bind(+match[1])
      .first();
    if (!exists) return json({ error: "Registro no encontrado." }, 404);
    await env.DB.batch([
      env.DB.prepare(
        "DELETE FROM email_deliveries WHERE registration_id=?",
      ).bind(+match[1]),
      env.DB.prepare("DELETE FROM registrations WHERE id=?").bind(+match[1]),
    ]);
    await audit(req, env, "registration.delete", +match[1], "Registro e historial de correos eliminados");
    return json({ ok: true });
  }
  if (match && req.method === "PATCH") {
    const d = await req.json();
    if (!["aprobado", "lista_espera", "rechazado"].includes(d.status))
      return json({ error: "Estado inválido" }, 400);
    const current = await env.DB.prepare(
      "SELECT id,first_name,email,request_code,ticket_code,status FROM registrations WHERE id=?",
    )
      .bind(+match[1])
      .first();
    if (!current) return json({ error: "No encontrado" }, 404);
    const ticket =
      d.status === "aprobado" ? current.ticket_code || code("CYB26") : current.ticket_code;
    await env.DB.prepare(
      "UPDATE registrations SET status=?,admin_notes=?,ticket_code=?,reviewed_at=CURRENT_TIMESTAMP WHERE id=?",
    )
      .bind(d.status, d.notes || "", ticket, +match[1])
      .run();
    await audit(req, env, `registration.${d.status}`, +match[1], d.notes || "");
    let mail = { status: "not_required", error: null };
    if (current.status !== d.status)
      mail = await sendStatusEmail(
        env,
        { ...current, ticket_code: ticket, origin: PUBLIC_ORIGIN },
        d.status,
        current.status,
      );
    return json({
      ok: true,
      ticket_code: ticket,
      email_status: mail.status,
      email_error: mail.error,
    });
  }
  if (url.pathname === "/api/cancel" && req.method === "POST") {
    if (!(await rateLimit(req, env, "cancel", 6, 900)))
      return json({ error: "Demasiados intentos. Espera unos minutos." }, 429);
    const d = await req.json().catch(() => null);
    const ticket = await verifyToken(d?.token, env);
    if (!ticket) return json({ error: "El enlace de cancelación no es válido." }, 400);
    const row = await env.DB.prepare("SELECT id,first_name,email,request_code,ticket_code,status FROM registrations WHERE ticket_code=?").bind(ticket).first();
    if (!row) return json({ error: "No encontramos este boleto." }, 404);
    if (row.status !== "aprobado")
      return json({ error: row.status === "rechazado" ? "Esta participación ya está cancelada." : "Este boleto ya no se encuentra aprobado." }, 409);
    const cancelled = await env.DB.prepare("UPDATE registrations SET status='rechazado',admin_notes='Cancelado por el participante',reviewed_at=CURRENT_TIMESTAMP WHERE id=? AND status='aprobado'").bind(row.id).run();
    if (!Number(cancelled.meta?.changes || cancelled.meta?.rows_written || 0))
      return json({ error: "La participación ya fue actualizada por otra operación." }, 409);
    const actor = `participante:${row.email}`;
    await audit(req, env, "registration.cancelled_by_participant", row.id, "Lugar liberado por el participante", actor);
    const mail = await sendStatusEmail(env, { ...row, origin: PUBLIC_ORIGIN }, "rechazado", "aprobado");
    return json({ ok: true, email_status: mail.status, email_error: mail.error });
  }
  if (url.pathname === "/api/scanner/stats" && req.method === "GET") {
    if (!(await roleOK(req, env, ["admin", "scanner"]))) return json({ error: "No autorizado" }, 401);
    const row = await env.DB.prepare("SELECT COUNT(*) AS total_registrations,SUM(CASE WHEN status='aprobado' THEN 1 ELSE 0 END) AS approved,SUM(CASE WHEN status='aprobado' AND checked_in_at IS NOT NULL THEN 1 ELSE 0 END) AS checked_in FROM registrations").first();
    const approved = Number(row.approved || 0), checkedIn = Number(row.checked_in || 0);
    return json({ total_registrations: Number(row.total_registrations || 0), approved, checked_in: checkedIn, pending_arrival: Math.max(0, approved - checkedIn), attendance_percentage: approved ? Number((checkedIn / approved * 100).toFixed(1)) : 0 });
  }
  if (url.pathname === "/api/checkin" && req.method === "POST") {
    if (!(await rateLimit(req, env, "checkin", 60, 300)))
      return json({ error: "Demasiados intentos de lectura. Espera un momento." }, 429);
    const scannerActor = await roleOK(req, env, ["admin", "scanner"]);
    if (!scannerActor)
      return json({ error: "Clave de escáner incorrecta." }, 401);
    const d = await req.json(),
      ticket = d.token
        ? await verifyToken(d.token, env)
        : String(d.ticket_code || "").toUpperCase();
    if (!ticket) return json({ result_state: "invalid", error: "QR inválido o alterado." }, 400);
    const row = await env.DB.prepare(
      "SELECT id,first_name,last_name,company,status,checked_in_at FROM registrations WHERE ticket_code=?",
    )
      .bind(ticket)
      .first();
    if (!row)
      return json({ result_state: "invalid", error: "El boleto no existe o no es válido." }, 404);
    if (row.status !== "aprobado")
      return json({ result_state: "status_changed", name: row.first_name + " " + row.last_name, company: row.company, ticket_status: row.status, error: "El boleto ya no está aprobado." }, 409);
    if (row.checked_in_at)
      return json({
        result_state: "reentry",
        already: true,
        name: row.first_name + " " + row.last_name,
        company: row.company,
        checked_in_at: row.checked_in_at,
      });
    // TODO: sustituir este valor por un identificador de operador incluido en
    // el body únicamente cuando pueda verificarse contra una sesión autenticada.
    const by = scannerActor.actor || "equipo_acceso";
    const update = await env.DB.prepare(
      "UPDATE registrations SET checked_in_at=CURRENT_TIMESTAMP,checked_in_by=? WHERE id=? AND checked_in_at IS NULL",
    )
      .bind(by, row.id)
      .run();
    if (!Number(update.meta?.changes || update.meta?.rows_written || 0)) {
      const existing = await env.DB.prepare("SELECT checked_in_at FROM registrations WHERE id=?").bind(row.id).first();
      return json({ result_state: "reentry", already: true, name: row.first_name + " " + row.last_name, company: row.company, checked_in_at: existing?.checked_in_at || null });
    }
    await audit(req, env, "checkin", row.id, "Acceso registrado", by);
    const done = await env.DB.prepare(
      "SELECT checked_in_at FROM registrations WHERE id=?",
    )
      .bind(row.id)
      .first();
    return json({
      result_state: "valid",
      already: false,
      name: row.first_name + " " + row.last_name,
      company: row.company,
      checked_in_at: done.checked_in_at,
    });
  }
  return json({ error: "No encontrado" }, 404);
}
export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    try {
      if (url.pathname === "/assets/jsqr.js")
        return new Response(JSQR_SOURCE, {
          headers: {
            "content-type": "application/javascript; charset=utf-8",
            "cache-control": "public, max-age=31536000, immutable",
          },
        });
      if (url.pathname === "/assets/foro-banner.png" || url.pathname === "/assets/acluvaq-logo.png") {
        const data = url.pathname.includes("foro-banner") ? FORUM_BANNER : ACLUVAQ_LOGO;
        return new Response(Uint8Array.from(atob(data), (c) => c.charCodeAt(0)), {
          headers: { "content-type": "image/png", "cache-control": "public, max-age=31536000, immutable", "x-content-type-options": "nosniff" },
        });
      }
      if (url.pathname.startsWith("/api/")) return await api(req, env, url);
      if (url.pathname === "/admin")
        return new Response(adminPage(), {
          headers: htmlHeaders(),
        });
      if (url.pathname === "/scanner")
        return new Response(scannerPage(), {
          headers: htmlHeaders(),
        });
      if (url.pathname === "/ticket") {
        const ticket = await verifyToken(url.searchParams.get("token"), env);
        if (!ticket)
          return new Response(
            page(
              '<main class="wrap"><div class="card login"><h1>Boleto inválido</h1><p>Este enlace no es válido o fue alterado.</p></div></main>',
            ),
            {
              status: 400,
              headers: htmlHeaders(),
            },
          );
        const row = await env.DB.prepare(
          "SELECT first_name,last_name,company,job_title,ticket_code FROM registrations WHERE ticket_code=? AND status='aprobado'",
        )
          .bind(ticket)
          .first();
        return row
          ? new Response(ticketPage(row, url.searchParams.get("token")), {
              headers: htmlHeaders(),
            })
          : new Response("Boleto no disponible", { status: 404 });
      }
      if (url.pathname === "/" || url.pathname === "/embed") {
        const registrationEnabled = (await setting(env, "public_registration_enabled", "true")) === "true";
        if (!registrationEnabled)
          return new Response(page('<main class="wrap"><div class="card login"><div class="eyebrow">Registro temporalmente cerrado</div><h1>Las solicitudes no están disponibles</h1><p>La administración habilitará nuevamente el formulario cuando corresponda.</p></div></main>'), { status: 503, headers: htmlHeaders(url.pathname === "/embed") });
        const requireWorkEmail = await workEmailRequired(env),
          validatePhone = await phoneValidationRequired(env),
          privacyUrl = safeExternalUrl(await setting(env, "privacy_notice_url", "")),
          html = enhancedRegisterPage(requireWorkEmail, validatePhone, privacyUrl, env.TURNSTILE_SITE_KEY || "");
        return new Response(url.pathname === "/embed" ? html.replace("<body>", '<body class="embed">') : html, { headers: htmlHeaders(url.pathname === "/embed") });
      }
      return new Response("No encontrado", { status: 404 });
    } catch (e) {
      console.error("Unhandled request error", url.pathname, e);
      return json({ error: "Ocurrió un error inesperado." }, 500);
    }
  },
};
