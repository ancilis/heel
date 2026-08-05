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
const MAX_CONTROL_PLANE_BODY_BYTES = 256 * 1024;
const API_KEY_AUTHORIZATION = /^Bearer heel_sk_[A-Za-z0-9_-]+$/;
const SESSION_TOKEN = /^[A-Za-z0-9_-]+$/;
const IDEMPOTENCY_KEY = /^fs1-[0-9a-f]{64}$/;

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

function controlPlaneCredentials(source: Headers): Headers {
  const headers = new Headers();
  const authorization = source.get("Authorization")?.trim() ?? "";
  if (authorization !== "" && !API_KEY_AUTHORIZATION.test(authorization)) {
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
    .filter(({ name, value }) => name === "heel_session" && value !== "")
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
): { headers: Headers; contentLength: number } {
  const headers = upstreamPath === SIGNUP_ROUTE || upstreamPath === LOGIN_ROUTE
    ? new Headers()
    : controlPlaneCredentials(source);
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
  if (!Number.isSafeInteger(contentLength) || contentLength > MAX_CONTROL_PLANE_BODY_BYTES) {
    throw new InvalidControlPlaneRequest();
  }

  headers.set("Content-Type", "application/json");
  headers.set("Content-Encoding", "identity");
  headers.set("Content-Length", declaredLength);
  if (FINDINGS_SYNC_ROUTE.test(upstreamPath)) {
    const idempotencyKey = source.get("Idempotency-Key")?.trim() ?? "";
    if (!IDEMPOTENCY_KEY.test(idempotencyKey)) throw new InvalidControlPlaneRequest();
    headers.set("Idempotency-Key", idempotencyKey);
  }
  return { headers, contentLength };
}

function controlPlaneResponse(response: Response, csp: string, upstreamPath = ""): Response {
  const headers = new Headers();
  for (const name of ["Content-Type", "Content-Length", "Retry-After"]) {
    const value = response.headers.get(name);
    if (value !== null) headers.set(name, value);
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
        `heel_session=${match[1]}; HttpOnly; SameSite=Lax; Path=/; Secure`,
      );
    } else if (upstreamPath === LOGOUT_ROUTE) {
      if (setCookie !== "heel_session=; Max-Age=0; Path=/") {
        throw new Error("invalid session response");
      }
      headers.set(
        "Set-Cookie",
        "heel_session=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax; Secure",
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
  let requestContract;
  try {
    requestContract = controlPlaneRequestHeaders(request.headers, request.method, upstreamPath);
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

    return withSecurityHeaders(await handler.fetch(securedRequest, env, ctx), csp);
  },
};

export default worker;
