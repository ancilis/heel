// SPDX-License-Identifier: LicenseRef-Heel-Commercial

/** Cloudflare Worker entry point for Heel Cloud. */
import { handleImageOptimization, DEFAULT_DEVICE_SIZES, DEFAULT_IMAGE_SIZES } from "vinext/server/image-optimization";
import handler from "vinext/server/app-router-entry";

interface AssetFetcher {
  fetch(request: Request): Promise<Response>;
}

interface PrivateControlPlaneFetcher {
  fetch(request: Request): Promise<Response>;
}

declare class FixedLengthStream extends TransformStream<Uint8Array, Uint8Array> {
  constructor(expectedLength: number);
}

interface Env {
  ASSETS: AssetFetcher;
  CONTROL_PLANE?: PrivateControlPlaneFetcher;
  CONTROL_PLANE_EDGE_SECRET?: string;
  PUBLIC_ORIGIN?: string;
  IMAGES: {
    input(stream: ReadableStream): {
      transform(options: Record<string, unknown>): {
        output(options: { format: string; quality: number }): Promise<{ response(): Response }>;
      };
    };
  };
}

interface ExecutionContext {
  waitUntil(promise: Promise<unknown>): void;
  passThroughOnException(): void;
}

const RESPONSE_HEADERS = Object.freeze({
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Permissions-Policy": "accelerometer=(), camera=(), display-capture=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()",
  "Referrer-Policy": "no-referrer",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
});

const CONTROL_PLANE_PREFIX = "/api/control-plane";
const CONTROL_PLANE_ORIGIN = "https://heel-control-plane.internal";
const SIGNUP_ROUTE = "/v1/signup";
const LOGIN_ROUTE = "/v1/login";
const LOGOUT_ROUTE = "/v1/logout";
const ME_ROUTE = "/v1/me";
const DEVICE_START_ROUTE = "/v1/device/start";
const DEVICE_VERIFY_ROUTE = "/v1/device/verify";
const DEVICE_POLL_ROUTE = "/v1/device/poll";
const DEVICE_TOKEN_ROUTE = "/v1/device/token";
const DEVICE_REFRESH_ROUTE = "/v1/device/refresh";
const DEVICE_REVOKE_ROUTE = "/v1/device/revoke";
const PUBLIC_DEVICE_ROUTES = new Set([
  DEVICE_START_ROUTE,
  DEVICE_POLL_ROUTE,
  DEVICE_TOKEN_ROUTE,
  DEVICE_REFRESH_ROUTE,
  DEVICE_REVOKE_ROUTE,
]);
const WORKSPACE_REF = "ws_[0-9a-f]{16}";
const PROJECT_REF = "prj_[0-9a-f]{32}";
const SYNCED_REVIEW_REF = "synrev_[0-9a-f]{32}";
const PROJECTS_ROUTE = new RegExp(`^/v1/workspaces/${WORKSPACE_REF}/projects$`);
const PROJECT_KEY_ROUTE = new RegExp(
  `^/v1/workspaces/${WORKSPACE_REF}/projects/${PROJECT_REF}/namespace-key$`,
);
const FINDINGS_APPROVAL_ROUTE = new RegExp(
  `^/v1/workspaces/${WORKSPACE_REF}/projects/${PROJECT_REF}/findings-sync/approve$`,
);
const FINDINGS_SYNC_ROUTE = new RegExp(
  `^/v1/workspaces/${WORKSPACE_REF}/projects/${PROJECT_REF}/findings-sync$`,
);
const REVIEWS_ROUTE = new RegExp(
  `^/v1/workspaces/${WORKSPACE_REF}/projects/${PROJECT_REF}/reviews$`,
);
const REVIEW_DETAIL_ROUTE = new RegExp(
  `^/v1/workspaces/${WORKSPACE_REF}/projects/${PROJECT_REF}/reviews/${SYNCED_REVIEW_REF}$`,
);
const ENVIRONMENT_REF = "env_[0-9a-f]{32}";
const CANARY_RUN_REF = "crun_[0-9a-f]{32}";
const RUNNER_CONTEXT_REF = "rcb_[0-9a-f]{32}";
const RUNNER_CONTEXT_BINDINGS_ROUTE = new RegExp(`^/v1/workspaces/${WORKSPACE_REF}/projects/${PROJECT_REF}/runner-context-bindings$`);
const RUNNER_CONTEXT_REVOKE_ROUTE = new RegExp(`^/v1/workspaces/${WORKSPACE_REF}/projects/${PROJECT_REF}/runner-context-bindings/${RUNNER_CONTEXT_REF}/revoke$`);
const CANARY_APPROVAL_PROJECTION_ROUTE = new RegExp(
  `^/v1/workspaces/${WORKSPACE_REF}/projects/${PROJECT_REF}/canary-approval-projections$`,
);
const CANARY_APPROVAL_REQUESTS_ROUTE = new RegExp(
  `^/v1/workspaces/${WORKSPACE_REF}/projects/${PROJECT_REF}/canary-approval-requests$`,
);
const CANARY_RUN_ROUTE = new RegExp(
  `^/v1/workspaces/${WORKSPACE_REF}/projects/${PROJECT_REF}/canary-runs/${CANARY_RUN_REF}$`,
);
const CANARY_RUN_EVENTS_ROUTE = new RegExp(
  `^/v1/workspaces/${WORKSPACE_REF}/projects/${PROJECT_REF}/canary-runs/${CANARY_RUN_REF}/events$`,
);
const CANARY_RUN_APPROVE_ROUTE = new RegExp(
  `^/v1/workspaces/${WORKSPACE_REF}/projects/${PROJECT_REF}/canary-runs/${CANARY_RUN_REF}/approve$`,
);
const CANARY_RUN_STOP_ROUTE = new RegExp(
  `^/v1/workspaces/${WORKSPACE_REF}/projects/${PROJECT_REF}/canary-runs/${CANARY_RUN_REF}/stop$`,
);
const CANARY_DISCLOSURE_PERMIT_ROUTE = new RegExp(
  `^/v1/workspaces/${WORKSPACE_REF}/projects/${PROJECT_REF}/canary-runs/${CANARY_RUN_REF}/disclosure-permits$`,
);
const CANARY_DISCLOSURE_LOCAL_ROUTE = new RegExp(
  `^/v1/workspaces/${WORKSPACE_REF}/projects/${PROJECT_REF}/canary-runs/${CANARY_RUN_REF}/disclosure-local-only$`,
);
const CANARY_FINDINGS_ROUTE = new RegExp(
  `^/v1/workspaces/${WORKSPACE_REF}/projects/${PROJECT_REF}/canary-runs/${CANARY_RUN_REF}/findings$`,
);
const ENVIRONMENTS_ROUTE = new RegExp(
  `^/v1/workspaces/${WORKSPACE_REF}/projects/${PROJECT_REF}/environments$`,
);
const ENVIRONMENT_CHECK_ROUTE = new RegExp(
  `^/v1/workspaces/${WORKSPACE_REF}/projects/${PROJECT_REF}/environments/${ENVIRONMENT_REF}/check$`,
);
const ENVIRONMENT_REVOKE_ROUTE = new RegExp(
  `^/v1/workspaces/${WORKSPACE_REF}/projects/${PROJECT_REF}/environments/${ENVIRONMENT_REF}/revoke$`,
);
const MAX_CONTROL_PLANE_BODY_BYTES = 256 * 1024;
const MAX_DEVICE_BODY_BYTES = 8 * 1024;
const MAX_CANARY_PROJECTION_BODY_BYTES = 64 * 1024;
const MAX_CANARY_HUMAN_BODY_BYTES = 16 * 1024;
const MAX_RUNNER_CLAIM_BODY_BYTES = 256;
const MAX_RUNNER_CONTROL_BODY_BYTES = 36 * 1024;
const MAX_RUNNER_CONTEXT_LIST_BODY_BYTES = 128;
const MAX_RUNNER_CONTEXT_CLAIM_BODY_BYTES = 256;
const MAX_RUNNER_CONTEXT_SUBMIT_BODY_BYTES = 69632;
const MAX_RUNNER_RESULT_PROJECTION_BODY_BYTES = 272 * 1024;
const MAX_RUNNER_RESYNC_BODY_BYTES = 2 * 1024;
const MAX_RUNNER_PAIRING_BODY_BYTES = 16 * 1024;
const API_KEY_AUTHORIZATION = /^Bearer heel_sk_[A-Za-z0-9_-]+$/;
const DEVICE_AUTHORIZATION = /^Bearer heel_at_[A-Za-z0-9_-]{43}$/;
const SESSION_TOKEN = /^[A-Za-z0-9_-]+$/;
const IDEMPOTENCY_KEY = /^fs1-[0-9a-f]{64}$/;
const CANARY_IDEMPOTENCY_KEY = /^ca1-[0-9a-f]{64}$/;
const CONTROL_GENERATION = /^(?:0|[1-9][0-9]{0,19})$/;
const RUNNER_NEXT_NONCE = /^[A-Za-z0-9+/]{43}=$/;
const RUNNER_PAIRING_EXCHANGE = "/v1/runner-pairings/exchange";
const RUNNER_PAIRING_ACTIVATE = /^\/v1\/runner-pairings\/pending_[0-9a-f]{32}\/(?:activate|activation-abort)$/;
const RUNNER_PAIRING_MANAGE = new RegExp(`^/v1/workspaces/${WORKSPACE_REF}/runner-pairings(?:/pending_[0-9a-f]{32}(?:/approve)?)?$`);
const RUNNER_ROTATION_START = new RegExp(`^/v1/workspaces/${WORKSPACE_REF}/runners/[A-Za-z0-9_-]{1,128}/rotate$`);
const RUNNER_ROTATION_APPROVE = new RegExp(`^/v1/workspaces/${WORKSPACE_REF}/runners/[A-Za-z0-9_-]{1,128}/rotations/rotation_[0-9a-f]{32}/approve$`);
const RUNNER_REVOKE = new RegExp(`^/v1/workspaces/${WORKSPACE_REF}/runners/[A-Za-z0-9_-]{1,128}$`);
const RUNNER_ROTATION_PUBLIC = /^\/v1\/runner-rotations\/rotation_[0-9a-f]{32}\/(?:activate|poll|activation-abort)$/;
const RUNNER_CONTROL = new RegExp(`^/v1/workspaces/${WORKSPACE_REF}/runners/[A-Za-z0-9_-]{1,128}(?:/claim|/runs/[A-Za-z0-9_-]{1,128}/(?:heartbeat|progress|result|stop-ack))$`);
const RUNNER_CONTEXT_CONTROL = new RegExp(`^/v1/workspaces/${WORKSPACE_REF}/runners/[A-Za-z0-9_-]{1,128}/contexts(?:/list|/${RUNNER_CONTEXT_REF}/(?:claim|approval-projections))$`);
const RUNNER_RESULT_PROJECTION = new RegExp(`^/v1/workspaces/${WORKSPACE_REF}/runners/[A-Za-z0-9_-]{1,128}/runs/${CANARY_RUN_REF}/result-projection$`);
const RUNNER_RESYNC = new RegExp(`^/v1/workspaces/${WORKSPACE_REF}/runners/[A-Za-z0-9_-]{1,128}/resync/(?:start|complete)$`);
const RUNNER_HEADERS = ["X-Heel-Runner-Id", "X-Heel-Runner-Key-Id", "X-Heel-Runner-Timestamp-Ms", "X-Heel-Runner-Nonce", "X-Heel-Runner-Sequence", "X-Heel-Runner-Signature"];
const RUNNER_RESYNC_HEADERS = ["X-Heel-Runner-Id", "X-Heel-Runner-Key-Id", "X-Heel-Runner-Timestamp-Ms", "X-Heel-Runner-Signature"];

function isHumanCanaryRoute(method: string, upstreamPath: string): boolean {
  if (RUNNER_CONTEXT_BINDINGS_ROUTE.test(upstreamPath)) return method === "GET" || method === "POST";
  if (RUNNER_CONTEXT_REVOKE_ROUTE.test(upstreamPath)) return method === "POST";
  if (CANARY_APPROVAL_PROJECTION_ROUTE.test(upstreamPath)) return method === "POST";
  if (CANARY_APPROVAL_REQUESTS_ROUTE.test(upstreamPath)) return method === "GET";
  if (CANARY_RUN_ROUTE.test(upstreamPath)) return method === "GET";
  if (CANARY_RUN_EVENTS_ROUTE.test(upstreamPath)) return method === "GET";
  if (CANARY_RUN_APPROVE_ROUTE.test(upstreamPath)) return method === "POST";
  if (CANARY_RUN_STOP_ROUTE.test(upstreamPath)) return method === "POST";
  if (CANARY_DISCLOSURE_PERMIT_ROUTE.test(upstreamPath)) return method === "POST";
  if (CANARY_DISCLOSURE_LOCAL_ROUTE.test(upstreamPath)) return method === "POST";
  return CANARY_FINDINGS_ROUTE.test(upstreamPath) && method === "GET";
}

function isHumanEnvironmentRoute(method: string, upstreamPath: string): boolean {
  if (ENVIRONMENTS_ROUTE.test(upstreamPath)) return method === "GET" || method === "POST";
  return method === "POST"
    && (ENVIRONMENT_CHECK_ROUTE.test(upstreamPath) || ENVIRONMENT_REVOKE_ROUTE.test(upstreamPath));
}

function contentSecurityPolicy(nonce: string): string {
  return [
    "default-src 'self'",
    "base-uri 'none'",
    "connect-src 'self'",
    "font-src 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "img-src 'self' data:",
    "object-src 'none'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic' 'wasm-unsafe-eval'`,
    `style-src 'self' 'nonce-${nonce}'`,
    "worker-src 'self'",
  ].join("; ");
}

function withSecurityHeaders(response: Response, csp: string, noStore = false): Response {
  const headers = new Headers(response.headers);
  headers.set("Content-Security-Policy", csp);
  for (const [name, value] of Object.entries(RESPONSE_HEADERS)) headers.set(name, value);
  if (noStore) headers.set("Cache-Control", "no-store");
  return new Response(response.body, {
    headers,
    status: response.status,
    statusText: response.statusText,
  });
}

class InvalidControlPlaneRequest extends Error {}

function singletonHeader(source: Headers, name: string): string | null {
  // Cloudflare Headers preserves duplicate fields through getAll.  The web-test
  // implementation merges them, for which a comma is invalid for every runner
  // proof field and therefore remains fail-closed.
  const cloudflare = source as Headers & { getAll?: (header: string) => string[] };
  if (typeof cloudflare.getAll === "function") {
    const values = cloudflare.getAll(name);
    return values.length === 1 ? values[0] : null;
  }
  const value = source.get(name);
  return value === null || value.includes(",") ? null : value;
}

function controlPlaneCredentials(source: Headers): Headers {
  const headers = new Headers();
  const authorization = source.get("Authorization")?.trim() ?? "";
  if (
    authorization !== ""
    && !API_KEY_AUTHORIZATION.test(authorization)
    && !DEVICE_AUTHORIZATION.test(authorization)
  ) {
    throw new InvalidControlPlaneRequest();
  }
  const sessions = (source.get("Cookie") ?? "")
    .split(";")
    .map((part) => {
      const candidate = part.trim();
      const separator = candidate.indexOf("=");
      return separator === -1
        ? { name: candidate, value: "" }
        : { name: candidate.slice(0, separator), value: candidate.slice(separator + 1) };
    })
    .filter(({ name, value }) => name === "__Host-heel_session" && value !== "")
    .map(({ value }) => value);
  if (
    sessions.length > 1
    || (sessions.length === 1 && !SESSION_TOKEN.test(sessions[0]))
    || (authorization !== "" && sessions.length !== 0)
  ) throw new InvalidControlPlaneRequest();
  if (authorization !== "") headers.set("Authorization", authorization);
  if (sessions.length === 1) headers.set("Cookie", `heel_session=${sessions[0]}`);
  return headers;
}

function controlPlaneRequestHeaders(
  source: Headers,
  method: string,
  upstreamPath: string,
  configuredPublicOrigin: string | undefined,
  edgeClientKey: string | undefined,
  edgeAuthSecret: string,
): { headers: Headers; contentLength: number } {
  let headers: Headers;
  const runnerResultProjection = RUNNER_RESULT_PROJECTION.test(upstreamPath);
  const runnerContextControl = RUNNER_CONTEXT_CONTROL.test(upstreamPath);
  const runnerControl = RUNNER_CONTROL.test(upstreamPath) || runnerContextControl || runnerResultProjection;
  const runnerResync = RUNNER_RESYNC.test(upstreamPath);
  const humanCanary = isHumanCanaryRoute(method, upstreamPath);
  const humanEnvironment = isHumanEnvironmentRoute(method, upstreamPath);
  const runnerPairingPublic = upstreamPath === RUNNER_PAIRING_EXCHANGE || RUNNER_PAIRING_ACTIVATE.test(upstreamPath) || RUNNER_ROTATION_PUBLIC.test(upstreamPath);
  const runnerPairingHuman = RUNNER_PAIRING_MANAGE.test(upstreamPath) || RUNNER_ROTATION_START.test(upstreamPath) || RUNNER_ROTATION_APPROVE.test(upstreamPath) || RUNNER_REVOKE.test(upstreamPath);
  if (runnerControl) {
    // Runner proof headers are an isolated protocol: a caller cannot nominate a
    // hop-by-hop/header-smuggling field or impersonate an edge-derived origin.
    if (method !== "POST" || source.has("Authorization") || source.has("Cookie")
      || source.has("Connection") || source.has("TE") || source.has("Transfer-Encoding")
      || source.has("Content-Encoding") || source.has("X-Heel-Internal-Origin")) throw new InvalidControlPlaneRequest();
    headers = new Headers();
    for (const name of RUNNER_HEADERS) {
      const value = singletonHeader(source, name);
      if (value === null) throw new InvalidControlPlaneRequest();
      headers.set(name, value);
    }
  } else if (runnerResync) {
    if (method !== "POST" || source.has("Authorization") || source.has("Cookie")
      || source.has("X-Heel-Runner-Nonce") || source.has("X-Heel-Runner-Sequence")) throw new InvalidControlPlaneRequest();
    headers = new Headers();
    for (const name of RUNNER_RESYNC_HEADERS) {
      const value = singletonHeader(source, name);
      if (value === null) throw new InvalidControlPlaneRequest();
      headers.set(name, value);
    }
  } else if (runnerPairingPublic) {
    if (method !== "POST" || source.has("Authorization") || source.has("Cookie")) throw new InvalidControlPlaneRequest();
    headers = new Headers();
  } else if (humanCanary || humanEnvironment) {
    if (source.has("Authorization")) throw new InvalidControlPlaneRequest();
    headers = controlPlaneCredentials(source);
    if (!headers.has("Cookie") || headers.has("Authorization")) throw new InvalidControlPlaneRequest();
    if (CANARY_APPROVAL_REQUESTS_ROUTE.test(upstreamPath) && (source.has("Transfer-Encoding") || source.has("TE") || source.has("Content-Encoding") || source.has("Content-Length"))) {
      throw new InvalidControlPlaneRequest();
    }
    if (method === "POST") {
      const origin = source.get("Origin") ?? "";
      if (origin !== configuredPublicOrigin || source.get("Sec-Fetch-Site") !== "same-origin") {
        throw new InvalidControlPlaneRequest();
      }
      headers.set("X-Heel-Internal-Origin", "same-origin");
      headers.set("Origin", origin);
    }
  } else if (runnerPairingHuman) {
    const origin = source.get("Origin") ?? "";
    if (origin !== configuredPublicOrigin || source.get("Sec-Fetch-Site") !== "same-origin") throw new InvalidControlPlaneRequest();
    headers = controlPlaneCredentials(source);
    if (!headers.has("Cookie") || headers.has("Authorization")) throw new InvalidControlPlaneRequest();
    headers.set("X-Heel-Internal-Origin", "same-origin");
    headers.set("Origin", origin);
  } else
  if (
    upstreamPath === SIGNUP_ROUTE
    || upstreamPath === LOGIN_ROUTE
    || PUBLIC_DEVICE_ROUTES.has(upstreamPath)
  ) {
    // Anonymous endpoints never receive ambient browser or machine credentials.
    headers = new Headers();
  } else if (upstreamPath === DEVICE_VERIFY_ROUTE) {
    const origin = source.get("Origin") ?? "";
    const fetchSite = source.get("Sec-Fetch-Site") ?? "";
    let expectedOrigin = "";
    try {
      const parsed = new URL(configuredPublicOrigin ?? "");
      if (
        configuredPublicOrigin !== parsed.origin
        || (parsed.protocol !== "https:" && parsed.hostname !== "127.0.0.1" && parsed.hostname !== "localhost")
      ) throw new Error("invalid public origin");
      expectedOrigin = parsed.origin;
    } catch {
      throw new InvalidControlPlaneRequest();
    }
    if (origin !== expectedOrigin || fetchSite !== "same-origin") {
      throw new InvalidControlPlaneRequest();
    }
    headers = controlPlaneCredentials(source);
    if (!headers.has("Cookie") || headers.has("Authorization")) {
      throw new InvalidControlPlaneRequest();
    }
    // Derived by the edge after the browser-origin and credential checks above. Caller input
    // with this name is never copied because every upstream header is allowlisted from scratch.
    headers.set("X-Heel-Internal-Origin", "same-origin");
    headers.set("Origin", expectedOrigin);
  } else {
    headers = controlPlaneCredentials(source);
  }
  headers.set("X-Heel-Edge-Auth", edgeAuthSecret);
  if (method !== "POST") return { headers, contentLength: 0 };
  if (source.has("Transfer-Encoding")) throw new InvalidControlPlaneRequest();

  const contentType = source.get("Content-Type")?.trim().toLowerCase() ?? "";
  if (contentType.split(";", 1)[0] !== "application/json" || contentType.includes(",")) {
    throw new InvalidControlPlaneRequest();
  }
  const contentEncoding = source.get("Content-Encoding")?.trim().toLowerCase() ?? "identity";
  if (contentEncoding !== "identity") throw new InvalidControlPlaneRequest();
  const declaredLength = source.get("Content-Length") ?? "";
  if (!/^(?:0|[1-9][0-9]*)$/.test(declaredLength) || declaredLength.length > 6) {
    throw new InvalidControlPlaneRequest();
  }
  const contentLength = Number(declaredLength);
  const maximum = runnerControl
    ? runnerResultProjection
      ? MAX_RUNNER_RESULT_PROJECTION_BODY_BYTES
      : (upstreamPath.endsWith("/contexts/list") ? MAX_RUNNER_CONTEXT_LIST_BODY_BYTES
        : (runnerContextControl && upstreamPath.endsWith("/claim") ? MAX_RUNNER_CONTEXT_CLAIM_BODY_BYTES
          : (upstreamPath.endsWith("/approval-projections") ? MAX_RUNNER_CONTEXT_SUBMIT_BODY_BYTES
            : (upstreamPath.endsWith("/claim") ? MAX_RUNNER_CLAIM_BODY_BYTES : MAX_RUNNER_CONTROL_BODY_BYTES))))
    : runnerResync
      ? MAX_RUNNER_RESYNC_BODY_BYTES
      : (runnerPairingPublic || runnerPairingHuman)
        ? MAX_RUNNER_PAIRING_BODY_BYTES
        : CANARY_APPROVAL_PROJECTION_ROUTE.test(upstreamPath)
          ? MAX_CANARY_PROJECTION_BODY_BYTES
          : humanCanary || humanEnvironment
            ? (RUNNER_CONTEXT_BINDINGS_ROUTE.test(upstreamPath) ? 2 * 1024
              : (RUNNER_CONTEXT_REVOKE_ROUTE.test(upstreamPath) ? 256 : MAX_CANARY_HUMAN_BODY_BYTES))
        : upstreamPath.startsWith("/v1/device/")
          ? MAX_DEVICE_BODY_BYTES
          : MAX_CONTROL_PLANE_BODY_BYTES;
  if (!Number.isSafeInteger(contentLength) || contentLength > maximum) {
    throw new InvalidControlPlaneRequest();
  }

  headers.set("Content-Type", "application/json");
  headers.set("Content-Encoding", "identity");
  headers.set("Content-Length", declaredLength);
  if (upstreamPath === DEVICE_START_ROUTE || upstreamPath === SIGNUP_ROUTE) {
    if (edgeClientKey === undefined || !/^[0-9a-f]{64}$/.test(edgeClientKey)) {
      throw new InvalidControlPlaneRequest();
    }
    headers.set("X-Heel-Client-Key", edgeClientKey);
  }
  if (FINDINGS_SYNC_ROUTE.test(upstreamPath)) {
    const idempotencyKey = source.get("Idempotency-Key")?.trim() ?? "";
    if (!IDEMPOTENCY_KEY.test(idempotencyKey)) throw new InvalidControlPlaneRequest();
    headers.set("Idempotency-Key", idempotencyKey);
  }
  if (CANARY_RUN_APPROVE_ROUTE.test(upstreamPath)) {
    const idempotencyKey = singletonHeader(source, "Idempotency-Key")?.trim() ?? "";
    if (!CANARY_IDEMPOTENCY_KEY.test(idempotencyKey)) throw new InvalidControlPlaneRequest();
    headers.set("Idempotency-Key", idempotencyKey);
  }
  if (CANARY_RUN_APPROVE_ROUTE.test(upstreamPath) || CANARY_RUN_STOP_ROUTE.test(upstreamPath)) {
    const controlGeneration = singletonHeader(source, "If-Heel-Control-Generation")?.trim() ?? "";
    if (!CONTROL_GENERATION.test(controlGeneration)) throw new InvalidControlPlaneRequest();
    headers.set("If-Heel-Control-Generation", controlGeneration);
  }
  return { headers, contentLength };
}

function controlPlaneResponse(response: Response, csp: string, upstreamPath = ""): Response {
  const headers = new Headers();
  for (const name of ["Content-Type", "Content-Length", "Retry-After"]) {
    const value = response.headers.get(name);
    if (value !== null) headers.set(name, value);
  }
  if (RUNNER_CONTROL.test(upstreamPath) || RUNNER_CONTEXT_CONTROL.test(upstreamPath) || RUNNER_RESULT_PROJECTION.test(upstreamPath)) {
    const nextNonce = response.headers.get("X-Heel-Runner-Next-Nonce");
    if (nextNonce !== null) {
      if (!RUNNER_NEXT_NONCE.test(nextNonce)) throw new Error("invalid runner nonce response");
      headers.set("X-Heel-Runner-Next-Nonce", nextNonce);
    }
  }
  if (response.status >= 200 && response.status <= 299) {
    const setCookie = response.headers.get("Set-Cookie");
    if (upstreamPath === SIGNUP_ROUTE || upstreamPath === LOGIN_ROUTE) {
      const match = setCookie?.match(
        /^heel_session=([A-Za-z0-9_-]+); HttpOnly; SameSite=Lax; Path=\/$/,
      );
      if (match === undefined || match === null) throw new Error("invalid session response");
      headers.set(
        "Set-Cookie",
        `__Host-heel_session=${match[1]}; HttpOnly; SameSite=Lax; Path=/; Secure`,
      );
    } else if (upstreamPath === LOGOUT_ROUTE) {
      if (setCookie !== "heel_session=; Max-Age=0; Path=/") {
        throw new Error("invalid session response");
      }
      headers.set(
        "Set-Cookie",
        "__Host-heel_session=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax; Secure",
      );
    }
  }
  return withSecurityHeaders(new Response(response.body, {
    headers,
    status: response.status,
    statusText: response.statusText,
  }), csp, true);
}

function proxyError(status: number, error: string, csp: string): Response {
  return controlPlaneResponse(new Response(JSON.stringify({ error }), {
    headers: { "Content-Type": "application/json" },
    status,
  }), csp);
}

function controlPlaneRoute(method: string, pathname: string): string | null {
  if (pathname !== CONTROL_PLANE_PREFIX && !pathname.startsWith(`${CONTROL_PLANE_PREFIX}/`)) {
    return null;
  }
  const upstreamPath = pathname.slice(CONTROL_PLANE_PREFIX.length);
  if ((upstreamPath === SIGNUP_ROUTE || upstreamPath === LOGIN_ROUTE || upstreamPath === LOGOUT_ROUTE)
    && method === "POST") return upstreamPath;
  if (upstreamPath === ME_ROUTE && method === "GET") return upstreamPath;
  if (
    (PUBLIC_DEVICE_ROUTES.has(upstreamPath) || upstreamPath === DEVICE_VERIFY_ROUTE)
    && method === "POST"
  ) return upstreamPath;
  if ((upstreamPath === RUNNER_PAIRING_EXCHANGE || RUNNER_PAIRING_ACTIVATE.test(upstreamPath) || RUNNER_ROTATION_PUBLIC.test(upstreamPath)) && method === "POST") return upstreamPath;
  if (RUNNER_PAIRING_MANAGE.test(upstreamPath) && (method === "GET" || method === "POST" || method === "DELETE")) return upstreamPath;
  if ((RUNNER_ROTATION_START.test(upstreamPath) || RUNNER_ROTATION_APPROVE.test(upstreamPath)) && method === "POST") return upstreamPath;
  if (RUNNER_REVOKE.test(upstreamPath) && method === "DELETE") return upstreamPath;
  if ((RUNNER_CONTROL.test(upstreamPath) || RUNNER_CONTEXT_CONTROL.test(upstreamPath) || RUNNER_RESULT_PROJECTION.test(upstreamPath) || RUNNER_RESYNC.test(upstreamPath)) && method === "POST") return upstreamPath;
  if (isHumanCanaryRoute(method, upstreamPath) || isHumanEnvironmentRoute(method, upstreamPath)) return upstreamPath;
  if (PROJECTS_ROUTE.test(upstreamPath) && (method === "GET" || method === "POST")) {
    return upstreamPath;
  }
  if (PROJECT_KEY_ROUTE.test(upstreamPath) && method === "GET") return upstreamPath;
  if (FINDINGS_APPROVAL_ROUTE.test(upstreamPath) && method === "POST") return upstreamPath;
  if (FINDINGS_SYNC_ROUTE.test(upstreamPath) && method === "POST") return upstreamPath;
  if (REVIEWS_ROUTE.test(upstreamPath) && method === "GET") return upstreamPath;
  if (REVIEW_DETAIL_ROUTE.test(upstreamPath) && method === "GET") return upstreamPath;
  return "";
}

async function proxyControlPlane(
  request: Request,
  env: Env,
  csp: string,
  upstreamPath: string,
): Promise<Response> {
  if (env.CONTROL_PLANE === undefined) {
    return proxyError(503, "control plane unavailable", csp);
  }
  const edgeAuthSecret = env.CONTROL_PLANE_EDGE_SECRET?.trim() ?? "";
  if (!/^[A-Za-z0-9_-]{43,86}$/.test(edgeAuthSecret)) {
    return proxyError(503, "control plane unavailable", csp);
  }
  let edgeClientKey: string | undefined;
  if (upstreamPath === DEVICE_START_ROUTE || upstreamPath === SIGNUP_ROUTE) {
    const requestUrl = new URL(request.url);
    let clientAddress = request.headers.get("CF-Connecting-IP")?.trim() ?? "";
    if (
      clientAddress === ""
      && (requestUrl.hostname === "127.0.0.1" || requestUrl.hostname === "localhost")
    ) clientAddress = "127.0.0.1";
    if (!/^[0-9A-Fa-f:.]{2,64}$/.test(clientAddress)) {
      return proxyError(400, "invalid control plane request", csp);
    }
    const rateLimitKey = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(edgeAuthSecret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const digest = await crypto.subtle.sign(
      "HMAC",
      rateLimitKey,
      new TextEncoder().encode(`heel-client-rate-limit\0${upstreamPath}\0${clientAddress}`),
    );
    edgeClientKey = Array.from(new Uint8Array(digest), (byte) =>
      byte.toString(16).padStart(2, "0")
    ).join("");
  }
  let requestContract;
  try {
    requestContract = controlPlaneRequestHeaders(
      request.headers,
      request.method,
      upstreamPath,
      env.PUBLIC_ORIGIN,
      edgeClientKey,
      edgeAuthSecret,
    );
  } catch (error) {
    if (error instanceof InvalidControlPlaneRequest) {
      return proxyError(400, "invalid control plane request", csp);
    }
    throw error;
  }
  const upstreamUrl = new URL(upstreamPath, CONTROL_PLANE_ORIGIN);
  const init: RequestInit & { duplex?: "half" } = {
    headers: requestContract.headers,
    method: request.method,
    redirect: "manual",
  };
  if (request.method === "POST") {
    if (requestContract.contentLength !== 0 && request.body === null) {
      return proxyError(400, "invalid control plane request", csp);
    }
    try {
      init.body = requestContract.contentLength === 0
        ? new Uint8Array()
        : request.body!.pipeThrough(new FixedLengthStream(requestContract.contentLength));
      init.duplex = "half";
    } catch {
      return proxyError(502, "control plane request failed", csp);
    }
  }
  try {
    const response = await env.CONTROL_PLANE.fetch(new Request(upstreamUrl, init));
    if (response.status >= 300 && response.status <= 399) {
      return proxyError(502, "control plane request failed", csp);
    }
    if (CANARY_APPROVAL_REQUESTS_ROUTE.test(upstreamPath) && response.status >= 200 && response.status <= 299) {
      const declared = singletonHeader(response.headers, "Content-Length");
      if (declared === null || !/^(?:0|[1-9][0-9]*)$/.test(declared) || Number(declared) > 69632) {
        return proxyError(502, "control plane request failed", csp);
      }
      const body = new Uint8Array(await response.arrayBuffer());
      if (body.byteLength !== Number(declared)) return proxyError(502, "control plane request failed", csp);
      return controlPlaneResponse(new Response(body, { status: response.status, statusText: response.statusText, headers: response.headers }), csp, upstreamPath);
    }
    return controlPlaneResponse(response, csp, upstreamPath);
  } catch {
    return proxyError(502, "control plane request failed", csp);
  }
}

// Image security config. SVG sources with .svg extension auto-skip the
// optimization endpoint on the client side (served directly, no proxy).
// To route SVGs through the optimizer (with security headers), set
// dangerouslyAllowSVG: true in next.config.js and uncomment below:
// const imageConfig: ImageConfig = { dangerouslyAllowSVG: true };

const worker = {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const nonce = crypto.randomUUID().replaceAll("-", "");
    const csp = contentSecurityPolicy(nonce);
    const trustedOrigin = new URL(request.url).origin;
    const requestUrl = new URL(request.url);
    const upstreamPath = controlPlaneRoute(request.method, requestUrl.pathname);
    if (upstreamPath === "") return proxyError(404, "not found", csp);
    if (upstreamPath !== null) {
      if (requestUrl.search !== "") return proxyError(400, "invalid control plane request", csp);
      return proxyControlPlane(request, env, csp, upstreamPath);
    }
    const requestHeaders = new Headers(request.headers);
    // Vinext/Next reads the request CSP nonce and applies it to framework scripts.
    requestHeaders.set("Content-Security-Policy", csp);
    // This private header is derived here and overwritten on every request. App
    // metadata must never reconstruct public URLs from caller-controlled Host or
    // forwarding headers.
    requestHeaders.set("x-heel-internal-origin", trustedOrigin);
    const securedRequest = new Request(request, { headers: requestHeaders });
    const url = new URL(securedRequest.url);

    if (url.pathname === "/_vinext/image") {
      const allowedWidths = [...DEFAULT_DEVICE_SIZES, ...DEFAULT_IMAGE_SIZES];
      const response = await handleImageOptimization(securedRequest, {
        fetchAsset: (path) => env.ASSETS.fetch(new Request(new URL(path, securedRequest.url))),
        transformImage: async (body, { width, format, quality }) => {
          const result = await env.IMAGES.input(body).transform(width > 0 ? { width } : {}).output({ format, quality });
          return result.response();
        },
      }, allowedWidths);
      return withSecurityHeaders(response, csp);
    }

    return withSecurityHeaders(
      await handler.fetch(securedRequest, env, ctx),
      csp,
      url.pathname === "/device",
    );
  },
};

export default worker;
