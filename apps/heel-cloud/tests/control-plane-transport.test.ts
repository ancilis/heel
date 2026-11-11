// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import { beforeAll, describe, expect, it, vi } from "vitest";

vi.mock("vinext/server/image-optimization", () => ({
  handleImageOptimization: vi.fn(), DEFAULT_DEVICE_SIZES: [], DEFAULT_IMAGE_SIZES: [],
}));
vi.mock("vinext/server/app-router-entry", () => ({ default: { fetch: vi.fn() } }));

import worker from "../worker/index";

// The operator-selected private upstream transport, seen through the Worker. Reserved example/test
// names are syntax fixtures, not owned domains.
const origin = "https://heel.example";
const edge = "a".repeat(43);
const context = { waitUntil() {}, passThroughOnException() {} };
const MISSING = Symbol("missing");
// Caller-controlled names that must never nominate the upstream scheme or host.
const destinationNoise = {
  Host: "attacker.invalid",
  Forwarded: "for=192.0.2.1;host=attacker.invalid;proto=http",
  "X-Forwarded-Host": "attacker.invalid",
  "X-Forwarded-Proto": "http",
  "X-Forwarded-Port": "8080",
  "X-Forwarded-Scheme": "http",
};

beforeAll(() => {
  class LengthStream extends TransformStream<Uint8Array, Uint8Array> {
    constructor(length: number) { void length; super(); }
  }
  (globalThis as typeof globalThis & { FixedLengthStream: typeof LengthStream }).FixedLengthStream = LengthStream;
});

function upstream(request: Request): Response {
  const pathname = new URL(request.url).pathname;
  return new Response("{}", {
    headers: {
      "Content-Type": "application/json",
      ...(pathname === "/v1/login" ? { "Set-Cookie": "heel_session=private; HttpOnly; SameSite=Lax; Path=/" } : {}),
    },
  });
}

function environment(transport: unknown, fetcher: ReturnType<typeof vi.fn>) {
  return {
    ASSETS: { fetch: vi.fn(async () => new Response("asset")) },
    IMAGES: { input: () => { throw new Error("image transform is not used by the control-plane route"); } },
    CONTROL_PLANE: { fetch: fetcher },
    CONTROL_PLANE_EDGE_SECRET: edge,
    PUBLIC_ORIGIN: origin,
    ...(transport === MISSING ? {} : { CONTROL_PLANE_TRANSPORT: transport }),
  } as never;
}

const routes = [
  { method: "GET", path: "/v1/me", headers: { Cookie: "__Host-heel_session=private" } },
  { method: "POST", path: "/v1/login", headers: {}, body: "{}" },
  {
    method: "POST", path: "/v1/device/verify", body: "{}",
    headers: { Cookie: "__Host-heel_session=private", Origin: origin, "Sec-Fetch-Site": "same-origin" },
  },
] as const;

function incoming(route: (typeof routes)[number], extra: Record<string, string> = {}): Request {
  const body = "body" in route ? route.body : undefined;
  return new Request(`${origin}/api/control-plane${route.path}`, {
    method: route.method,
    headers: {
      ...route.headers,
      ...(body === undefined ? {} : { "Content-Type": "application/json", "Content-Length": String(body.length) }),
      ...extra,
    },
    body,
  });
}

async function forward(transport: unknown, route: (typeof routes)[number], extra: Record<string, string> = {}) {
  const fetcher = vi.fn(async (request: Request) => upstream(request));
  const response = await worker.fetch(incoming(route, extra), environment(transport, fetcher), context);
  return { response, fetcher };
}

describe("private upstream transport through the Worker", () => {
  it("keeps the canonical HTTPS URL by default and for explicit https", async () => {
    for (const transport of [MISSING, undefined, "https"]) {
      for (const route of routes) {
        const { response, fetcher } = await forward(transport, route);
        expect(response.status, `${String(transport)} ${route.path}`).toBe(200);
        expect(fetcher).toHaveBeenCalledTimes(1);
        expect((fetcher.mock.calls[0][0] as Request).url).toBe(`${origin}${route.path}`);
      }
    }
  });

  it("calls the fixed binding at the HTTP port for explicit private HTTP; headers and cookies stay HTTPS", async () => {
    for (const route of routes) {
      const secure = await forward("https", route);
      const plain = await forward("http", route);
      expect(plain.response.status, route.path).toBe(200);
      expect(plain.fetcher).toHaveBeenCalledTimes(1);
      const sent = plain.fetcher.mock.calls[0][0] as Request;
      const reference = secure.fetcher.mock.calls[0][0] as Request;
      expect(sent.url, route.path).toBe(`http://heel.example${route.path}`);
      expect(new URL(sent.url).port, route.path).toBe("");
      // Only the scheme differs: method, redirect mode and every forwarded header are identical.
      expect(sent.method).toBe(reference.method);
      expect(sent.redirect).toBe("manual");
      expect([...sent.headers]).toEqual([...reference.headers]);
      for (const [name, value] of sent.headers) expect(value, name).not.toContain("http://");
      const forwardedOrigin = sent.headers.get("Origin");
      if (forwardedOrigin !== null) expect(forwardedOrigin, route.path).toBe(origin);
      expect(plain.response.headers.get("set-cookie")).toBe(secure.response.headers.get("set-cookie"));
    }
    const login = await forward("http", routes[1]);
    const cookie = login.response.headers.get("set-cookie") ?? "";
    expect(cookie.startsWith("__Host-heel_session=")).toBe(true);
    expect(cookie).toMatch(/;\s*Secure/i);
  });

  it("does not let caller scheme, host or forwarding headers choose the transport or host", async () => {
    for (const [transport, scheme] of [[MISSING, "https"], ["https", "https"], ["http", "http"]] as const) {
      const { response, fetcher } = await forward(transport, routes[0], destinationNoise);
      expect(response.status, String(transport)).toBe(200);
      expect((fetcher.mock.calls[0][0] as Request).url).toBe(`${scheme}://heel.example/v1/me`);
    }
  });

  it("answers the fixed 503 without calling the binding for every malformed transport", async () => {
    for (const transport of [
      null, "", " ", "HTTP", "Https", " http", "http ", "http:", "https:", "http://", "tcp", "8080",
      0, true, {}, ["http"], new String("http"),
    ]) {
      for (const route of routes) {
        const { response, fetcher } = await forward(transport, route);
        expect(response.status, `${String(transport)} ${route.path}`).toBe(503);
        expect(await response.text()).toBe('{"error":"control plane unavailable"}');
        expect(fetcher).not.toHaveBeenCalled();
      }
    }
  });
});
