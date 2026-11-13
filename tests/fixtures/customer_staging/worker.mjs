// Controlled synthetic acceptance target for the Heel customer journey.
//
// A standalone Cloudflare Worker with no bindings, storage, outbound fetch, redirect or
// dependency. It serves one ownership-proof file, two plan-gated export routes (an ordinary
// markerless one and a canary-bound one), one authentication-gated canary read route, one
// health route and its own static OpenAPI inventory. All data is static and fake. Nothing
// here is Heel product code.
//
// Operator configuration (never request-controlled):
//   HEEL_TARGET_MODE       var:    vulnerable | patched | error_envelope
//   HEEL_TARGET_REVISION   var:    7-40 lowercase hex characters (optional, reported only)
//   HEEL_VERIFY_TOKEN      secret: the ownership token issued by Heel (printable ASCII)
//   HEEL_FREE_TOKEN_SHA256 secret: lowercase hex SHA-256 of the free canary bearer token
//   HEEL_PRO_TOKEN_SHA256  secret: lowercase hex SHA-256 of the pro canary bearer token
// Missing, malformed or equal digests, or an unknown mode, fail closed with 503.

// The one approved synthetic canary fixture id (tests/plan_differential_support.py MARKER).
// Heel's paired runner learns a marker only from a route fixture binding, so the canary
// export lives at /api/exports/{id} and is served only for this exact id; that body carries
// it in the top-level protected_canary field. It is public and not a secret.
export const CANARY_ID = "heel-canary-export-0001";
// Ordinary export at /api/export: the same fake payload as tests/plan_differential_support.py
// EXPORT, with no marker (97 bytes, unchanged from the original 47ab432 fixture).
const EXPORT = Object.freeze({
  account_id: "acct_canary",
  format: "csv",
  rows: [{ id: "row_1", amount_cents: 1200 }],
  total: 1,
});
// Canary export at /api/exports/heel-canary-export-0001: the same payload plus the marker.
const CANARY_EXPORT = Object.freeze({ ...EXPORT, protected_canary: CANARY_ID });
// The one approved synthetic authentication-read fixture id, served only at
// /api/auth-records/heel-canary-auth-0001. Public, fake and not a secret.
export const AUTH_CANARY_ID = "heel-canary-auth-0001";
// Fake protected record. Its marker is in the top-level protected_canary field only.
const AUTH_RECORD = Object.freeze({
  record_id: "rec_canary",
  account_id: "acct_canary",
  display_name: "Synthetic Record",
  protected_canary: AUTH_CANARY_ID,
});
const AUTH_ROUTE = "/api/auth-records/{id}";
// Served verbatim at /openapi.json; byte-for-byte equal to openapi.json beside this file.
// Two export paths and one record path; each id route has an ordinary path parameter only.
// No marker value, example, plan, finding, privilege or extension annotation.
const OPENAPI = JSON.stringify({
  openapi: "3.1.0",
  info: { title: "Heel controlled staging target API", version: "1.3.0" },
  paths: {
    "/api/export": {
      get: { operationId: "getAccountExport", responses: { 200: { description: "ok" } } },
      head: { operationId: "headAccountExport", responses: { 200: { description: "ok" } } },
    },
    "/api/exports/{id}": {
      parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
      get: { operationId: "getExport", responses: { 200: { description: "ok" } } },
      head: { operationId: "headExport", responses: { 200: { description: "ok" } } },
    },
    "/api/auth-records/{id}": {
      parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
      get: { operationId: "getAuthRecord", responses: { 200: { description: "ok" } } },
      head: { operationId: "headAuthRecord", responses: { 200: { description: "ok" } } },
    },
  },
}, null, 2) + "\n";
// The same recognized denial envelope as tests/plan_differential_support.py DENIAL_ENVELOPE.
const DENIAL_ENVELOPE = Object.freeze({ error: "upgrade required" });

export const MODES = Object.freeze(["vulnerable", "patched", "error_envelope"]);
// Exact concrete paths only: any other export id is an unknown path (404, never reflected).
export const ROUTES = Object.freeze({
  "/.well-known/heel-verify.txt": "/.well-known/heel-verify.txt",
  "/api/export": "/api/export",
  [`/api/exports/${CANARY_ID}`]: "/api/exports/{id}",
  [`/api/auth-records/${AUTH_CANARY_ID}`]: AUTH_ROUTE,
  "/healthz": "/healthz",
  "/openapi.json": "/openapi.json",
});
const ALLOWED_METHODS = new Set(["GET", "HEAD"]);
const DIGEST = /^[0-9a-f]{64}$/;
const REVISION = /^[0-9a-f]{7,40}$/;
// RFC 6750 b64token, bounded.
const BEARER = /^Bearer ([A-Za-z0-9\-._~+/]{1,512}=*)$/;
const encoder = new TextEncoder();

function configString(env, name) {
  const value = env == null ? undefined : env[name];
  return typeof value === "string" ? value : null;
}

function verifyToken(env) {
  const value = configString(env, "HEEL_VERIFY_TOKEN");
  if (value === null || value.length < 16 || value.length > 512) return null;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 33 || code > 126) return null;
  }
  return value;
}

function exportConfig(env) {
  const mode = configString(env, "HEEL_TARGET_MODE");
  const free = configString(env, "HEEL_FREE_TOKEN_SHA256");
  const pro = configString(env, "HEEL_PRO_TOKEN_SHA256");
  if (!MODES.includes(mode) || !DIGEST.test(free ?? "") || !DIGEST.test(pro ?? "") || free === pro) {
    return null;
  }
  return { mode, free, pro };
}

function reportedMode(env) {
  const mode = configString(env, "HEEL_TARGET_MODE");
  return MODES.includes(mode) ? mode : "invalid";
}

function sameDigest(left, right) {
  let difference = left.length ^ right.length;
  for (let index = 0; index < 64; index += 1) {
    difference |= (left.charCodeAt(index) | 0) ^ (right.charCodeAt(index) | 0);
  }
  return difference === 0;
}

async function sha256Hex(bytes) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

// Returns free | pro | none | malformed | unknown. The token never leaves this function.
async function role(request, config) {
  const header = request.headers.get("authorization");
  if (header === null) return "none";
  const match = BEARER.exec(header);
  if (match === null) return "malformed";
  const presented = await sha256Hex(encoder.encode(match[1]));
  const isFree = sameDigest(presented, config.free);
  const isPro = sameDigest(presented, config.pro);
  return isFree ? "free" : isPro ? "pro" : "unknown";
}

function json(status, value) {
  return { status, type: "application/json", body: encoder.encode(JSON.stringify(value)) };
}

// Both export routes share the same auth and modes; only the served payload differs.
function exportResponse(route, mode, plan) {
  if (plan === "pro" || mode === "vulnerable") return json(200, route === "/api/export" ? EXPORT : CANARY_EXPORT);
  if (mode === "patched") return { status: 403, type: null, body: new Uint8Array(0) };
  return json(403, DENIAL_ENVELOPE);
}

// Authentication read: any configured identity (free or pro) is the positive control and
// always gets the record. Only a request with NO Authorization header depends on the mode.
// A malformed or unknown credential is refused with the 401 envelope in every mode.
function authRecordResponse(mode, caller) {
  if (caller === "free" || caller === "pro") return json(200, AUTH_RECORD);
  if (caller === "none" && mode === "vulnerable") return json(200, AUTH_RECORD);
  if (caller === "none" && mode === "patched") {
    return { status: 401, type: null, body: new Uint8Array(0), authenticate: true };
  }
  return { ...json(401, { error: "unauthenticated" }), authenticate: true };
}

async function decide(request, env, method, route) {
  if (route === "/healthz") {
    const revision = configString(env, "HEEL_TARGET_REVISION");
    return {
      role: "-",
      ...json(200, {
        status: "ok",
        mode: reportedMode(env),
        revision: REVISION.test(revision ?? "") ? revision : "unknown",
        ownership_configured: verifyToken(env) !== null,
        export_configured: exportConfig(env) !== null,
      }),
    };
  }
  if (route === "/openapi.json") {
    return { role: "-", status: 200, type: "application/json", body: encoder.encode(OPENAPI) };
  }
  if (route === "/.well-known/heel-verify.txt") {
    const token = verifyToken(env);
    if (token === null) return { role: "-", ...json(503, { error: "target not configured" }) };
    return { role: "-", status: 200, type: "text/plain; charset=utf-8", body: encoder.encode(token + "\n") };
  }
  const config = exportConfig(env);
  if (config === null) return { role: "-", ...json(503, { error: "target not configured" }) };
  const plan = await role(request, config);
  if (route === AUTH_ROUTE) return { role: plan, ...authRecordResponse(config.mode, plan) };
  if (plan !== "free" && plan !== "pro") {
    return { role: plan, ...json(401, { error: "unauthenticated" }), authenticate: true };
  }
  return { role: plan, ...exportResponse(route, config.mode, plan) };
}

async function handle(request, env) {
  const method = request.method;
  const pathname = new URL(request.url).pathname;
  const route = Object.hasOwn(ROUTES, pathname) ? ROUTES[pathname] : null;
  let outcome;
  if (route === null) {
    outcome = { role: "-", ...json(404, { error: "not found" }) };
  } else if (!ALLOWED_METHODS.has(method)) {
    outcome = { role: "-", ...json(405, { error: "method not allowed" }), allow: true };
  } else {
    outcome = await decide(request, env, method, route);
  }
  const headers = new Headers({
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "content-length": String(outcome.body.byteLength),
  });
  if (outcome.type !== null) headers.set("content-type", outcome.type);
  if (outcome.allow) headers.set("allow", "GET, HEAD");
  if (outcome.authenticate) headers.set("www-authenticate", "Bearer");
  const sent = method === "HEAD" ? new Uint8Array(0) : outcome.body;
  // Bounded receipt: generated id and allowlisted labels only, never a header, query or body.
  console.log(JSON.stringify({
    receipt: crypto.randomUUID(),
    method: ALLOWED_METHODS.has(method) ? method : "OTHER",
    route: route ?? "unknown",
    role: outcome.role,
    status: outcome.status,
    mode: reportedMode(env),
    body_sha256: await sha256Hex(sent),
  }));
  return new Response(method === "HEAD" ? null : outcome.body, { status: outcome.status, headers });
}

export default {
  async fetch(request, env) {
    try {
      return await handle(request, env);
    } catch {
      return new Response(null, { status: 500, headers: { "cache-control": "no-store", "content-length": "0" } });
    }
  },
};
