// SPDX-License-Identifier: LicenseRef-Heel-Commercial

/** Cloudflare Worker entry point for Heel Cloud. */
import { handleImageOptimization, DEFAULT_DEVICE_SIZES, DEFAULT_IMAGE_SIZES } from "vinext/server/image-optimization";
import handler from "vinext/server/app-router-entry";

interface AssetFetcher {
  fetch(request: Request): Promise<Response>;
}

interface Env {
  ASSETS: AssetFetcher;
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

function withSecurityHeaders(response: Response, csp: string): Response {
  const headers = new Headers(response.headers);
  headers.set("Content-Security-Policy", csp);
  for (const [name, value] of Object.entries(RESPONSE_HEADERS)) headers.set(name, value);
  return new Response(response.body, {
    headers,
    status: response.status,
    statusText: response.statusText,
  });
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
