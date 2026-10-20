// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import { afterEach, beforeAll, beforeEach, describe, expect, it, vi, type MockInstance } from "vitest";

vi.mock("vinext/server/image-optimization", () => ({
  handleImageOptimization: vi.fn(), DEFAULT_DEVICE_SIZES: [], DEFAULT_IMAGE_SIZES: [],
}));
vi.mock("vinext/server/app-router-entry", () => ({ default: { fetch: vi.fn() } }));

import handler from "vinext/server/app-router-entry";
import { handleImageOptimization } from "vinext/server/image-optimization";
import { deploymentConfig } from "../build/deployment-config";
import worker from "../worker/index";

// The canonical control-plane destination is the configured PUBLIC_ORIGIN, reached only through
// the private CONTROL_PLANE binding. Reserved example/test names are syntax fixtures, not owned domains.
const CONFIGURED_ORIGINS = ["https://heel.example", "https://control-two.heel.test"];
const REQUEST_BASES = ["https://request-host.invalid", "http://127.0.0.1:8787"];
const workspace = "ws_0123456789abcdef";
const project = `prj_${"a".repeat(32)}`;
const review = `synrev_${"b".repeat(32)}`;
const runner = "runr_0123456789abcdef0123456789abcdef";
const run = `crun_${"c".repeat(32)}`;
const environment = `env_${"d".repeat(32)}`;
const binding = `rcb_${"e".repeat(32)}`;
const pairing = `pending_${"f".repeat(32)}`;
const rotation = `rotation_${"9".repeat(32)}`;
const edge = "a".repeat(43);
const context = { waitUntil() {}, passThroughOnException() {} };
const MISSING = Symbol("missing");
const runnerProof = {
  "X-Heel-Runner-Id": runner, "X-Heel-Runner-Key-Id": "key", "X-Heel-Runner-Timestamp-Ms": "1",
  "X-Heel-Runner-Nonce": "nonce", "X-Heel-Runner-Sequence": "1", "X-Heel-Runner-Signature": "sig",
};
const resyncProof = {
  "X-Heel-Runner-Id": runner, "X-Heel-Runner-Key-Id": "key", "X-Heel-Runner-Timestamp-Ms": "1",
  "X-Heel-Runner-Signature": "sig",
};
const session = { Cookie: "__Host-heel_session=private" };
// Caller-controlled names that must never nominate the upstream destination.
const destinationNoise = {
  Host: "attacker.invalid",
  Forwarded: "for=192.0.2.1;host=attacker.invalid;proto=https",
  "X-Forwarded-Host": "attacker.invalid",
  "X-Forwarded-Proto": "http",
  "X-Forwarded-Port": "444",
};

interface RouteCase {
  label: string;
  method: "GET" | "POST";
  path: string;
  headers: Record<string, string>;
  body?: string;
  human?: boolean;
  runnerProtocol?: boolean;
}

function routeCases(origin: string): RouteCase[] {
  const browser = { ...session, Origin: origin, "Sec-Fetch-Site": "same-origin" };
  return [
    { label: "account signup", method: "POST", path: "/v1/signup", headers: { "CF-Connecting-IP": "203.0.113.4" }, body: "{}" },
    { label: "account login", method: "POST", path: "/v1/login", headers: {}, body: "{}" },
    { label: "account me", method: "GET", path: "/v1/me", headers: session },
    { label: "account logout", method: "POST", path: "/v1/logout", headers: session, body: "{}" },
    { label: "device start", method: "POST", path: "/v1/device/start", headers: { "CF-Connecting-IP": "203.0.113.4" }, body: "{}" },
    ...["poll", "token", "refresh", "revoke"].map((route): RouteCase => (
      { label: `device ${route}`, method: "POST", path: `/v1/device/${route}`, headers: {}, body: "{}" }
    )),
    { label: "device verify", method: "POST", path: "/v1/device/verify", headers: browser, body: "{}", human: true },
    { label: "findings projects list", method: "GET", path: `/v1/workspaces/${workspace}/projects`, headers: session },
    { label: "findings projects create", method: "POST", path: `/v1/workspaces/${workspace}/projects`, headers: { Authorization: "Bearer heel_sk_private" }, body: "{}" },
    { label: "findings namespace key", method: "GET", path: `/v1/workspaces/${workspace}/projects/${project}/namespace-key`, headers: session },
    { label: "findings approve", method: "POST", path: `/v1/workspaces/${workspace}/projects/${project}/findings-sync/approve`, headers: session, body: "{}" },
    { label: "findings sync", method: "POST", path: `/v1/workspaces/${workspace}/projects/${project}/findings-sync`, headers: { ...session, "Idempotency-Key": `fs1-${"0".repeat(64)}` }, body: "{}" },
    { label: "findings reviews", method: "GET", path: `/v1/workspaces/${workspace}/projects/${project}/reviews`, headers: session },
    { label: "findings review detail", method: "GET", path: `/v1/workspaces/${workspace}/projects/${project}/reviews/${review}`, headers: session },
    { label: "runner pairing exchange", method: "POST", path: "/v1/runner-pairings/exchange", headers: {}, body: "{}" },
    { label: "runner pairing activate", method: "POST", path: `/v1/runner-pairings/${pairing}/activate`, headers: {}, body: "{}" },
    { label: "runner rotation poll", method: "POST", path: `/v1/runner-rotations/${rotation}/poll`, headers: {}, body: "{}" },
    { label: "runner pairing manage", method: "GET", path: `/v1/workspaces/${workspace}/runner-pairings`, headers: browser, human: true },
    { label: "runner rotation start", method: "POST", path: `/v1/workspaces/${workspace}/runners/${runner}/rotate`, headers: browser, body: "{}", human: true },
    { label: "runner revoke", method: "POST", path: `/v1/workspaces/${workspace}/runners/${runner}/revoke`, headers: browser, body: "{}", human: true },
    { label: "runner claim", method: "POST", path: `/v1/workspaces/${workspace}/runners/${runner}/claim`, headers: runnerProof, body: "{}", runnerProtocol: true },
    { label: "runner heartbeat", method: "POST", path: `/v1/workspaces/${workspace}/runners/${runner}/runs/${run}/heartbeat`, headers: runnerProof, body: "{}", runnerProtocol: true },
    { label: "runner context list", method: "POST", path: `/v1/workspaces/${workspace}/runners/${runner}/contexts/list`, headers: runnerProof, body: "{}", runnerProtocol: true },
    { label: "runner context claim", method: "POST", path: `/v1/workspaces/${workspace}/runners/${runner}/contexts/${binding}/claim`, headers: runnerProof, body: "{}", runnerProtocol: true },
    { label: "runner result projection", method: "POST", path: `/v1/workspaces/${workspace}/runners/${runner}/runs/${run}/result-projection`, headers: runnerProof, body: "{}", runnerProtocol: true },
    { label: "runner resync", method: "POST", path: `/v1/workspaces/${workspace}/runners/${runner}/resync/start`, headers: resyncProof, body: "{}", runnerProtocol: true },
    { label: "canary run", method: "GET", path: `/v1/workspaces/${workspace}/projects/${project}/canary-runs/${run}`, headers: session },
    { label: "canary approve", method: "POST", path: `/v1/workspaces/${workspace}/projects/${project}/canary-runs/${run}/approve`, headers: { ...browser, "Idempotency-Key": `ca1-${"1".repeat(64)}`, "If-Heel-Control-Generation": "3" }, body: "{}", human: true },
    { label: "runner context bindings", method: "POST", path: `/v1/workspaces/${workspace}/projects/${project}/runner-context-bindings`, headers: browser, body: "{}", human: true },
    { label: "environments list", method: "GET", path: `/v1/workspaces/${workspace}/projects/${project}/environments`, headers: session },
    { label: "environment check", method: "POST", path: `/v1/workspaces/${workspace}/projects/${project}/environments/${environment}/check`, headers: browser, body: "{}", human: true },
  ];
}

function upstreamResponse(request: Request): Response {
  const pathname = new URL(request.url).pathname;
  const setCookie = pathname === "/v1/logout"
    ? "heel_session=; Max-Age=0; Path=/"
    : pathname === "/v1/signup" || pathname === "/v1/login"
      ? "heel_session=private; HttpOnly; SameSite=Lax; Path=/"
      : null;
  return new Response("{}", {
    headers: { "Content-Type": "application/json", ...(setCookie === null ? {} : { "Set-Cookie": setCookie }) },
  });
}

function bindingSpy(respond: (request: Request) => Response | Promise<Response> = upstreamResponse) {
  return vi.fn(async (request: Request) => respond(request));
}

function workerEnv(publicOrigin: unknown, fetcher?: ReturnType<typeof bindingSpy>, secret: unknown = edge) {
  return {
    ASSETS: { fetch: assetFetch },
    IMAGES: { input: () => { throw new Error("image transform is not used by the control-plane route"); } },
    ...(fetcher === undefined ? {} : { CONTROL_PLANE: { fetch: fetcher } }),
    ...(secret === MISSING ? {} : { CONTROL_PLANE_EDGE_SECRET: secret }),
    ...(publicOrigin === undefined ? {} : { PUBLIC_ORIGIN: publicOrigin }),
  } as never;
}

function incoming(base: string, route: RouteCase, extra: Record<string, string> = {}, query = ""): Request {
  const headers: Record<string, string> = { ...route.headers, ...extra };
  if (route.body !== undefined) {
    headers["Content-Type"] = "application/json";
    headers["Content-Length"] = String(new TextEncoder().encode(route.body).byteLength);
  }
  return new Request(`${base}/api/control-plane${route.path}${query}`, {
    method: route.method, headers, body: route.body,
  });
}

// Honest FixedLengthStream seam: it enforces the declared length, unlike a pass-through shim.
class EnforcedLengthStream extends TransformStream<Uint8Array, Uint8Array> {
  constructor(expected: number) {
    let received = 0;
    super({
      transform(chunk, controller) {
        received += chunk.byteLength;
        if (received > expected) throw new TypeError("body exceeds the declared length");
        controller.enqueue(chunk);
      },
      flush() {
        if (received !== expected) throw new TypeError("body is shorter than the declared length");
      },
    });
  }
}

const assetFetch = vi.fn(async () => new Response("asset", { status: 404 }));
let globalFetch: MockInstance<typeof fetch>;

beforeAll(() => {
  (globalThis as typeof globalThis & { FixedLengthStream: typeof EnforcedLengthStream }).FixedLengthStream = EnforcedLengthStream;
});

beforeEach(() => {
  globalFetch = vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
    throw new Error("public fetch must never carry control-plane traffic");
  });
  assetFetch.mockClear();
  vi.mocked(handler.fetch).mockReset();
});

afterEach(() => {
  globalFetch.mockRestore();
});

function expectNoFallback() {
  expect(globalFetch).not.toHaveBeenCalled();
  expect(assetFetch).not.toHaveBeenCalled();
  expect(handler.fetch).not.toHaveBeenCalled();
}

const REFUSED_ORIGINS: unknown[] = [
  undefined, "", " https://heel.example", "https://heel.example ", "HTTPS://heel.example", "https://Heel.example",
  "http://heel.example", "http://127.0.0.1:8787", "http://localhost:8787", "https://heel.example/", "https://heel.example/v1",
  "https://heel.example?", "https://heel.example#", "https://user@heel.example", "https://heel.example:443",
  "https://heel.example:8443", "https://127.0.0.1", "https://0x7f000001", "https://[::1]", "https://heel",
  "https://heel.example.", "https://heel_ingress.example", "https://-heel.example", "https://heel%2eexample",
  "https://hëel.example", "https://localhost", "https://heel.localhost", "https://heel.local",
  "https://heel-control-plane.internal", "https://cp.heel.internal", 443,
];

describe("canonical control-plane binding destination", () => {
  it("sends every route family to the configured origin over the private binding only", async () => {
    for (const origin of CONFIGURED_ORIGINS) {
      for (const base of REQUEST_BASES) {
        const fetcher = bindingSpy();
        const routes = routeCases(origin);
        for (const route of routes) {
          // Runner proof is an isolated protocol that already refuses X-Heel-Internal-Origin.
          const noise: Record<string, string> = route.runnerProtocol
            ? { ...destinationNoise }
            : { ...destinationNoise, "X-Heel-Internal-Origin": "https://attacker.invalid" };
          if (!route.human) noise.Origin = "https://attacker.invalid";
          const response = await worker.fetch(incoming(base, route, noise), workerEnv(origin, fetcher), context);
          expect(response.status, `${origin} ${base} ${route.label}`).toBe(200);
        }
        expect(fetcher).toHaveBeenCalledTimes(routes.length);
        for (const [index, route] of routes.entries()) {
          const upstream = fetcher.mock.calls[index][0];
          expect(upstream.url, route.label).toBe(`${origin}${route.path}`);
          expect(new URL(upstream.url).origin, route.label).toBe(origin);
          expect(upstream.method, route.label).toBe(route.method);
          expect(upstream.redirect, route.label).toBe("manual");
          expect(upstream.headers.get("x-heel-edge-auth"), route.label).toBe(edge);
          for (const name of ["host", "forwarded", "x-forwarded-host", "x-forwarded-proto", "x-forwarded-port"]) {
            expect(upstream.headers.get(name), `${route.label} ${name}`).toBeNull();
          }
          expect(upstream.headers.get("origin"), route.label).toBe(route.human ? origin : null);
          expect(upstream.headers.get("x-heel-internal-origin"), route.label).toBe(route.human ? "same-origin" : null);
          expect(await upstream.text(), route.label).toBe(route.body ?? "");
        }
        expectNoFallback();
      }
    }
  });

  it("keeps human Origin checks on the configured origin, not the request origin", async () => {
    const origin = CONFIGURED_ORIGINS[0];
    const fetcher = bindingSpy();
    const humanRoutes = routeCases(origin).filter((route) => route.human);
    for (const route of humanRoutes) {
      for (const headers of [
        { Origin: "https://request-host.invalid" },
        { Origin: CONFIGURED_ORIGINS[1] },
        { Origin: "https://heel-control-plane.internal" },
        { "Sec-Fetch-Site": "cross-site" },
      ] as Array<Record<string, string>>) {
        const response = await worker.fetch(
          incoming("https://request-host.invalid", route, headers), workerEnv(origin, fetcher), context,
        );
        expect(response.status, `${route.label} ${JSON.stringify(headers)}`).toBe(400);
      }
    }
    expect(fetcher).not.toHaveBeenCalled();
    expectNoFallback();
  });

  it("refuses a caller query instead of carrying it to the configured origin", async () => {
    const fetcher = bindingSpy();
    const route = routeCases(CONFIGURED_ORIGINS[0]).find(({ label }) => label === "account me")!;
    for (const query of ["?host=attacker.invalid", "?url=https%3A%2F%2Fattacker.invalid", "?a"]) {
      const response = await worker.fetch(
        incoming("https://request-host.invalid", route, {}, query), workerEnv(CONFIGURED_ORIGINS[0], fetcher), context,
      );
      expect(response.status, query).toBe(400);
    }
    expect(fetcher).not.toHaveBeenCalled();
    expectNoFallback();
  });

  it("fails closed with a fixed 503 before any fetch when the configured origin is missing or refused", async () => {
    for (const refused of REFUSED_ORIGINS) {
      const fetcher = bindingSpy();
      const routes = routeCases(typeof refused === "string" ? refused : "").filter((route) => (
        ["account login", "device verify", "findings sync", "runner claim", "runner revoke", "canary approve"].includes(route.label)
      ));
      for (const route of routes) {
        const response = await worker.fetch(incoming("https://heel.example", route), workerEnv(refused, fetcher), context);
        expect(response.status, `${JSON.stringify(refused)} ${route.label}`).toBe(503);
        expect(await response.json()).toEqual({ error: "control plane unavailable" });
        expect(response.headers.get("cache-control")).toBe("no-store");
        expect(response.headers.get("location")).toBeNull();
      }
      expect(fetcher, JSON.stringify(refused)).not.toHaveBeenCalled();
    }
    expectNoFallback();
  });

  it("fails closed with a fixed 503 when the private binding or edge secret is absent or invalid", async () => {
    const origin = CONFIGURED_ORIGINS[0];
    const route = routeCases(origin).find(({ label }) => label === "runner claim")!;
    const fetcher = bindingSpy();
    for (const env of [
      workerEnv(origin),
      workerEnv(origin, fetcher, MISSING),
      workerEnv(origin, fetcher, ""),
      workerEnv(origin, fetcher, "short"),
      workerEnv(origin, fetcher, `${edge}=`),
    ]) {
      const response = await worker.fetch(incoming("https://heel.example", route), env, context);
      expect(response.status).toBe(503);
      expect(await response.json()).toEqual({ error: "control plane unavailable" });
    }
    expect(fetcher).not.toHaveBeenCalled();
    // Local review mode emits no private service capability at all.
    expect(deploymentConfig({ HEEL_DEPLOYMENT_MODE: "local_review", HEEL_PUBLIC_ORIGIN: origin }, "build").vpc_services).toEqual([]);
    expectNoFallback();
  });

  it("fails closed with the fixed 503 and no call for out-of-shape secret or binding configuration", async () => {
    const origin = CONFIGURED_ORIGINS[0];
    const routes = routeCases(origin).filter((route) => (
      ["account me", "device verify", "findings sync", "runner claim"].includes(route.label)
    ));
    const fetcher = bindingSpy();
    const malformed: Array<[string, Record<string, unknown>]> = [
      ...([["number", 43], ["boolean", true], ["object", {}], ["array", [edge]], ["null", null], ["String object", new String(edge)]] as const)
        .map(([label, value]): [string, Record<string, unknown>] => [`secret ${label}`, { CONTROL_PLANE: { fetch: fetcher }, CONTROL_PLANE_EDGE_SECRET: value }]),
      ...([["null", null], ["empty object", {}], ["missing fetch", { fetch: undefined }], ["non-callable fetch", { fetch: 43 }], ["number", 43]] as const)
        .map(([label, value]): [string, Record<string, unknown>] => [`binding ${label}`, { CONTROL_PLANE: value, CONTROL_PLANE_EDGE_SECRET: edge }]),
    ];
    for (const [label, configuration] of malformed) {
      for (const route of routes) {
        const environment = {
          ASSETS: { fetch: assetFetch },
          IMAGES: { input: () => { throw new Error("image transform is not used by the control-plane route"); } },
          PUBLIC_ORIGIN: origin,
          ...configuration,
        } as never;
        const response = await worker.fetch(incoming("https://heel.example", route), environment, context);
        expect(response.status, `${label} ${route.label}`).toBe(503);
        expect(await response.text(), `${label} ${route.label}`).toBe('{"error":"control plane unavailable"}');
        expect(response.headers.get("cache-control")).toBe("no-store");
        expect(response.headers.get("x-content-type-options")).toBe("nosniff");
        expect(response.headers.get("location")).toBeNull();
      }
    }
    expect(fetcher).not.toHaveBeenCalled();
    expectNoFallback();
    // The same routes with a valid binding are attempted exactly once each: unavailable configuration
    // stays distinct from an attempted private request.
    for (const route of routes) {
      const response = await worker.fetch(incoming("https://heel.example", route), workerEnv(origin, fetcher), context);
      expect(response.status, route.label).toBe(200);
    }
    expect(fetcher).toHaveBeenCalledTimes(routes.length);
    expectNoFallback();
  });

  it("refuses upstream redirects and errors without following them or falling back", async () => {
    const origin = CONFIGURED_ORIGINS[0];
    const route = routeCases(origin).find(({ label }) => label === "findings reviews")!;
    for (const status of [301, 302, 303, 307, 308]) {
      const fetcher = bindingSpy(() => new Response("private-redirect-marker", {
        status, headers: { Location: `${origin}/v1/elsewhere` },
      }));
      const response = await worker.fetch(incoming("https://heel.example", route), workerEnv(origin, fetcher), context);
      expect(response.status, String(status)).toBe(502);
      expect(response.headers.get("location")).toBeNull();
      expect(await response.text()).not.toContain("private-redirect-marker");
      expect(fetcher).toHaveBeenCalledTimes(1);
      expect(fetcher.mock.calls[0][0].url).toBe(`${origin}${route.path}`);
    }
    const failing = bindingSpy(() => { throw new Error("private-upstream-marker"); });
    const failed = await worker.fetch(incoming("https://heel.example", route), workerEnv(origin, failing), context);
    expect(failed.status).toBe(502);
    expect(await failed.text()).not.toContain("private-upstream-marker");
    expect(failing).toHaveBeenCalledTimes(1);
    expectNoFallback();
  });

  it("enforces the declared request length through FixedLengthStream on the binding request", async () => {
    const origin = CONFIGURED_ORIGINS[0];
    const route = routeCases(origin).find(({ label }) => label === "runner claim")!;
    const received: string[] = [];
    const fetcher = bindingSpy(async (request) => {
      received.push(new TextDecoder().decode(await request.arrayBuffer()));
      return upstreamResponse(request);
    });
    const exact = await worker.fetch(incoming("https://heel.example", route), workerEnv(origin, fetcher), context);
    expect(exact.status).toBe(200);
    expect(received).toEqual(["{}"]);
    for (const [declared, body] of [["3", "{}"], ["2", "{} "], ["1", "{}"]]) {
      const response = await worker.fetch(new Request(`https://heel.example/api/control-plane${route.path}`, {
        method: "POST", body, headers: { ...runnerProof, "Content-Type": "application/json", "Content-Length": declared },
      }), workerEnv(origin, fetcher), context);
      expect(response.status, `${declared} ${JSON.stringify(body)}`).toBe(502);
    }
    expect(received).toEqual(["{}"]);
    expect(fetcher).toHaveBeenCalledTimes(4);
    for (const call of fetcher.mock.calls) expect(call[0].url).toBe(`${origin}${route.path}`);
    expectNoFallback();
  });

  it("leaves ordinary page requests on request-URL metadata whatever the configured origin", async () => {
    for (const publicOrigin of [CONFIGURED_ORIGINS[0], "https://heel-control-plane.internal", undefined]) {
      const fetcher = bindingSpy();
      vi.mocked(handler.fetch).mockReset().mockResolvedValue(new Response("page"));
      const response = await worker.fetch(new Request("https://request-host.invalid/runner", {
        headers: { "X-Heel-Internal-Origin": "https://attacker.invalid", "X-Forwarded-Host": "attacker.invalid" },
      }), workerEnv(publicOrigin, fetcher), context);
      expect(response.status).toBe(200);
      expect(handler.fetch).toHaveBeenCalledTimes(1);
      const forwarded = vi.mocked(handler.fetch).mock.calls[0][0] as Request;
      expect(forwarded.headers.get("x-heel-internal-origin")).toBe("https://request-host.invalid");
      expect(fetcher).not.toHaveBeenCalled();
      expect(globalFetch).not.toHaveBeenCalled();
    }
  });

  // H0X E2: the composed Worker carries length authority and sink identity for every route family.
  it("refuses a declared-length mismatch with 502 for every POST route family", async () => {
    const origin = CONFIGURED_ORIGINS[0];
    const posts = routeCases(origin).filter((route) => route.method === "POST");
    for (const [declared, body] of [["3", "{}"], ["1", "{}"]]) {
      for (const route of posts) {
        const reads: string[] = [];
        const fetcher = bindingSpy(async (request) => {
          try {
            await request.arrayBuffer();
          } catch (error) {
            reads.push((error as Error).name);
            throw error;
          }
          reads.push("read");
          return upstreamResponse(request);
        });
        const headers: Record<string, string> = { ...route.headers, "Content-Type": "application/json", "Content-Length": declared };
        const response = await worker.fetch(new Request(`https://heel.example/api/control-plane${route.path}`, {
          method: "POST", headers, body,
        }), workerEnv(origin, fetcher), context);
        expect(response.status, `${route.label} declared ${declared}`).toBe(502);
        expect(fetcher, route.label).toHaveBeenCalledTimes(1);
        expect(fetcher.mock.calls[0][0].url, route.label).toBe(`${origin}${route.path}`);
        expect(reads, route.label).toEqual(["TypeError"]);
      }
    }
    expectNoFallback();
  });

  it("reaches only the private binding, once, for each route on its own", async () => {
    for (const origin of CONFIGURED_ORIGINS) {
      for (const route of routeCases(origin)) {
        const fetcher = bindingSpy();
        assetFetch.mockClear();
        vi.mocked(handler.fetch).mockClear();
        globalFetch.mockClear();
        const response = await worker.fetch(incoming("https://request-host.invalid", route), workerEnv(origin, fetcher), context);
        const label = `${origin} ${route.label}`;
        expect(response.status, label).toBe(200);
        expect(fetcher, label).toHaveBeenCalledTimes(1);
        expect(fetcher.mock.calls[0][0].url, label).toBe(`${origin}${route.path}`);
        expect(assetFetch, label).not.toHaveBeenCalled();
        expect(handler.fetch, label).not.toHaveBeenCalled();
        expect(globalFetch, label).not.toHaveBeenCalled();
      }
    }
  });

  it("keeps page and image requests on the page handler and assets only", async () => {
    const origin = CONFIGURED_ORIGINS[0];
    const fetcher = bindingSpy();
    vi.mocked(handler.fetch).mockReset().mockResolvedValue(new Response("page"));
    const page = await worker.fetch(new Request("https://request-host.invalid/dashboard"), workerEnv(origin, fetcher), context);
    expect(page.status).toBe(200);
    expect(handler.fetch).toHaveBeenCalledTimes(1);
    expect(assetFetch).not.toHaveBeenCalled();

    vi.mocked(handler.fetch).mockReset();
    vi.mocked(handleImageOptimization).mockImplementation((async (
      _request: Request, options: { fetchAsset: (path: string) => Promise<Response> },
    ) => options.fetchAsset("/_next/static/media/probe.png")) as never);
    const image = await worker.fetch(
      new Request("https://request-host.invalid/_vinext/image?url=%2Fprobe.png&w=64&q=75"), workerEnv(origin, fetcher), context,
    );
    expect(image.status).toBe(404);
    expect(assetFetch).toHaveBeenCalledTimes(1);
    expect(handler.fetch).not.toHaveBeenCalled();
    expect(fetcher).not.toHaveBeenCalled();
    expect(globalFetch).not.toHaveBeenCalled();
    vi.mocked(handleImageOptimization).mockReset();
  });
});
