import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const source = await readFile(new URL("../worker/index.js", import.meta.url), "utf8");

test("scanner renders API-controlled participant data with textContent", () => {
  assert.match(source, /name\.textContent=j\.name/);
  assert.match(source, /company\.textContent=j\.company/);
  assert.doesNotMatch(source, /innerHTML=.*j\.(?:name|company|ticket_status)/);
});

test("scanner key cannot impersonate the emergency administrator", () => {
  assert.doesNotMatch(source, /timingSafeEqual\(scannerHeader, env\.ADMIN_KEY\)/);
  assert.doesNotMatch(source, /timingSafeEqual\(scanner, env\.ADMIN_KEY\)/);
});

test("shared keys are not restored from browser storage", () => {
  assert.doesNotMatch(source, /sessionStorage\.getItem\(['"]foro_(?:admin|scanner)/);
});

test("CSV export neutralizes spreadsheet formula prefixes", () => {
  assert.match(source, /\/\^\[=\+\\-@\\t\\r\]\//);
});

test("public duplicate response does not disclose an existing folio", () => {
  assert.match(source, /Ya existe una solicitud asociada a este correo/);
  const publicRoute = source.slice(source.indexOf('url.pathname === "/api/register"'), source.indexOf('url.pathname === "/api/status"'));
  assert.doesNotMatch(publicRoute, /exists\.request_code/);
});

test("security headers and canonical origin controls are present", () => {
  assert.match(source, /strict-transport-security/);
  assert.match(source, /function mutationOriginOK/);
  assert.match(source, /safeExternalUrl/);
});
