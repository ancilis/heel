// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import { afterEach, beforeAll, beforeEach, describe, expect, it, vi, type MockInstance } from "vitest";

import { dispatchControlPlane, type ControlPlaneDispatchInput } from "../worker/control-plane-dispatch";

// Explicit-input tests for the one private control-plane sink. Reserved example/test names are
// syntax fixtures, not owned domains.
const CONFIGURED_ORIGINS = ["https://heel.example", "https://control-two.heel.test"];
const edge = "a".repeat(43);
const workspace = "ws_0123456789abcdef";
const project = `prj_${"a".repeat(32)}`;
const review = `synrev_${"b".repeat(32)}`;
const runner = "runr_0123456789abcdef0123456789abcdef";
const run = `crun_${"c".repeat(32)}`;
const environment = `env_${"d".repeat(32)}`;
const binding = `rcb_${"e".repeat(32)}`;
const pairing = `pending_${"f".repeat(32)}`;
const rotation = `rotation_${"9".repeat(32)}`;

// Every allowlisted route family, as the Worker's route contract passes it to the module.
const ROUTES: Array<{ method: "GET" | "POST"; path: string }> = [
  { method: "POST", path: "/v1/signup" },
  { method: "POST", path: "/v1/login" },
  { method: "GET", path: "/v1/me" },
  { method: "POST", path: "/v1/logout" },
  ...["start", "poll", "token", "refresh", "revoke", "verify"].map((route) => ({ method: "POST" as const, path: `/v1/device/${route}` })),
  { method: "GET", path: `/v1/workspaces/${workspace}/projects` },
  { method: "POST", path: `/v1/workspaces/${workspace}/projects` },
  { method: "GET", path: `/v1/workspaces/${workspace}/projects/${project}/namespace-key` },
  { method: "POST", path: `/v1/workspaces/${workspace}/projects/${project}/findings-sync/approve` },
  { method: "POST", path: `/v1/workspaces/${workspace}/projects/${project}/findings-sync` },
  { method: "GET", path: `/v1/workspaces/${workspace}/projects/${project}/reviews` },
  { method: "GET", path: `/v1/workspaces/${workspace}/projects/${project}/reviews/${review}` },
  { method: "POST", path: "/v1/runner-pairings/exchange" },
  { method: "POST", path: `/v1/runner-pairings/${pairing}/activate` },
  { method: "POST", path: `/v1/runner-rotations/${rotation}/poll` },
  { method: "GET", path: `/v1/workspaces/${workspace}/runner-pairings` },
  { method: "POST", path: `/v1/workspaces/${workspace}/runners/${runner}/rotate` },
  { method: "POST", path: `/v1/workspaces/${workspace}/runners/${runner}/revoke` },
  { method: "POST", path: `/v1/workspaces/${workspace}/runners/${runner}/claim` },
  { method: "POST", path: `/v1/workspaces/${workspace}/runners/${runner}/runs/${run}/heartbeat` },
  { method: "POST", path: `/v1/workspaces/${workspace}/runners/${runner}/contexts/list` },
  { method: "POST", path: `/v1/workspaces/${workspace}/runners/${runner}/contexts/${binding}/claim` },
  { method: "POST", path: `/v1/workspaces/${workspace}/runners/${runner}/runs/${run}/result-projection` },
  { method: "POST", path: `/v1/workspaces/${workspace}/runners/${runner}/resync/start` },
  { method: "GET", path: `/v1/workspaces/${workspace}/projects/${project}/canary-runs/${run}` },
  { method: "POST", path: `/v1/workspaces/${workspace}/projects/${project}/canary-runs/${run}/approve` },
  { method: "POST", path: `/v1/workspaces/${workspace}/projects/${project}/runner-context-bindings` },
  { method: "GET", path: `/v1/workspaces/${workspace}/projects/${project}/environments` },
  { method: "POST", path: `/v1/workspaces/${workspace}/projects/${project}/environments/${environment}/check` },
  { method: "POST", path: `/v1/workspaces/${workspace}/projects/${project}/environments/${environment}/challenge` },
  { method: "POST", path: `/v1/workspaces/${workspace}/projects/${project}/environments/${environment}/challenge/rotate` },
];

const REFUSED_ORIGINS: unknown[] = [
  undefined, null, "", " https://heel.example", "https://heel.example ", "HTTPS://heel.example", "https://Heel.example",
  "http://heel.example", "http://127.0.0.1:8787", "http://localhost:8787", "https://heel.example/", "https://heel.example/v1",
  "https://heel.example?", "https://heel.example#", "https://user@heel.example", "https://heel.example:443",
  "https://heel.example:8443", "https://127.0.0.1", "https://0x7f000001", "https://[::1]", "https://heel",
  "https://heel.example.", "https://heel_ingress.example", "https://-heel.example", "https://heel%2eexample",
  "https://hëel.example", "https://localhost", "https://heel.localhost", "https://heel.local",
  "https://heel-control-plane.internal", "https://cp.heel.internal", 443, {}, ["https://heel.example"],
  new String("https://heel.example"),
];

const MALFORMED_BINDINGS: Array<[string, unknown]> = [
  ["missing", undefined], ["null", null], ["empty object", {}], ["missing fetch", { fetch: undefined }],
  ["non-callable fetch", { fetch: 43 }], ["number", 43], ["boolean", false], ["array", []], ["string", "binding"],
];

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

interface Observed {
  url: string;
  method: string;
  redirect: string;
  headers: Array<[string, string]>;
  body: string | { rejected: string };
  receiverIsBinding: boolean;
}

// The binding spy reads every forwarded body, so a framing failure surfaces as a body-read rejection.
function bindingSpy(respond: (upstream: Request) => Response = () => new Response("{}", { status: 200 })) {
  const observed: Observed[] = [];
  const target = {
    fetch: vi.fn(async function (this: unknown, upstream: Request) {
      const record: Observed = {
        url: upstream.url,
        method: upstream.method,
        redirect: upstream.redirect,
        headers: [...upstream.headers].sort(([a], [b]) => a.localeCompare(b)),
        body: "",
        receiverIsBinding: this === target,
      };
      observed.push(record);
      try {
        record.body = new TextDecoder().decode(await upstream.arrayBuffer());
      } catch (error) {
        record.body = { rejected: (error as Error).name };
        throw error;
      }
      return respond(upstream);
    }),
  };
  return { target, observed };
}

function headers(): Headers {
  return new Headers({ "X-Heel-Edge-Auth": edge, "Content-Type": "application/json", "Content-Length": "2", Cookie: "heel_session=private" });
}

function body(text: string): ReadableStream<Uint8Array> {
  return new Response(text).body!;
}

function input(overrides: Omit<Partial<ControlPlaneDispatchInput>, "binding"> & { binding: unknown }): ControlPlaneDispatchInput {
  return {
    publicOrigin: CONFIGURED_ORIGINS[0],
    upstreamPath: "/v1/me",
    method: "GET",
    headers: headers(),
    contentLength: 0,
    body: null,
    ...overrides,
  } as ControlPlaneDispatchInput;
}

let globalFetch: MockInstance<typeof fetch>;

beforeAll(() => {
  (globalThis as typeof globalThis & { FixedLengthStream?: typeof EnforcedLengthStream }).FixedLengthStream = EnforcedLengthStream;
});

beforeEach(() => {
  globalFetch = vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
    throw new Error("public fetch must never carry control-plane traffic");
  });
});

afterEach(() => {
  expect(globalFetch).not.toHaveBeenCalled();
  globalFetch.mockRestore();
  (globalThis as typeof globalThis & { FixedLengthStream?: typeof EnforcedLengthStream }).FixedLengthStream = EnforcedLengthStream;
});

describe("control-plane dispatch module (explicit inputs only)", () => {
  it("returns unavailable without any call for every malformed binding shape", async () => {
    for (const [label, malformed] of MALFORMED_BINDINGS) {
      const outcome = await dispatchControlPlane(input({ binding: malformed }));
      expect(outcome, label).toEqual({ kind: "unavailable" });
    }
  });

  it("returns unavailable without any call for every refused configured origin", async () => {
    for (const refused of REFUSED_ORIGINS) {
      const spy = bindingSpy();
      for (const route of [ROUTES[2], ROUTES[1]]) {
        const outcome = await dispatchControlPlane(input({
          binding: spy.target, publicOrigin: refused, upstreamPath: route.path, method: route.method,
          contentLength: route.method === "POST" ? 2 : 0, body: route.method === "POST" ? body("{}") : null,
        }));
        expect(outcome, `${String(refused)} ${route.path}`).toEqual({ kind: "unavailable" });
      }
      expect(spy.target.fetch, String(refused)).not.toHaveBeenCalled();
    }
  });

  it("sends every route to the validated configured origin over the binding exactly once", async () => {
    for (const origin of CONFIGURED_ORIGINS) {
      for (const route of ROUTES) {
        const spy = bindingSpy();
        const sent = headers();
        const expectedHeaders = [...sent].sort(([a], [b]) => a.localeCompare(b));
        const outcome = await dispatchControlPlane(input({
          binding: spy.target, publicOrigin: origin, upstreamPath: route.path, method: route.method, headers: sent,
          contentLength: route.method === "POST" ? 2 : 0, body: route.method === "POST" ? body("{}") : null,
        }));
        expect(outcome.kind, route.path).toBe("response");
        expect(spy.target.fetch, route.path).toHaveBeenCalledTimes(1);
        expect(spy.observed, route.path).toEqual([{
          url: `${origin}${route.path}`,
          method: route.method,
          redirect: "manual",
          headers: expectedHeaders,
          body: route.method === "POST" ? "{}" : "",
          receiverIsBinding: true,
        }]);
      }
    }
  });

  it("returns the upstream response object itself for a non-redirect status", async () => {
    for (const status of [200, 201, 204, 400, 401, 403, 404, 409, 429, 500, 503]) {
      const upstream = new Response(null, { status });
      const outcome = await dispatchControlPlane(input({ binding: { fetch: async () => upstream } }));
      expect(outcome, String(status)).toEqual({ kind: "response", response: upstream });
    }
  });

  it("frames POST bodies to the declared length so a mismatch fails at the binding", async () => {
    for (const [declared, text] of [[3, "{}"], [2, "{} "], [1, "{}"], [2, ""]] as const) {
      const spy = bindingSpy();
      const outcome = await dispatchControlPlane(input({
        binding: spy.target, upstreamPath: "/v1/login", method: "POST", contentLength: declared, body: body(text),
      }));
      expect(outcome, `${declared} ${JSON.stringify(text)}`).toEqual({ kind: "failed" });
      expect(spy.target.fetch).toHaveBeenCalledTimes(1);
      expect(spy.observed[0].body).toEqual({ rejected: "TypeError" });
    }
  });

  it("refuses a declared body that is absent and sends an empty body for a zero length", async () => {
    const spy = bindingSpy();
    const missing = await dispatchControlPlane(input({
      binding: spy.target, upstreamPath: "/v1/login", method: "POST", contentLength: 2, body: null,
    }));
    expect(missing).toEqual({ kind: "invalid" });
    expect(spy.target.fetch).not.toHaveBeenCalled();
    for (const empty of [null, body("ignored")]) {
      const outcome = await dispatchControlPlane(input({
        binding: spy.target, upstreamPath: "/v1/login", method: "POST", contentLength: 0, body: empty,
      }));
      expect(outcome.kind).toBe("response");
    }
    expect(spy.observed.map((call) => call.body)).toEqual(["", ""]);
  });

  it("fails without calling the binding when the framing stream cannot be built", async () => {
    const spy = bindingSpy();
    delete (globalThis as typeof globalThis & { FixedLengthStream?: unknown }).FixedLengthStream;
    const outcome = await dispatchControlPlane(input({
      binding: spy.target, upstreamPath: "/v1/login", method: "POST", contentLength: 2, body: body("{}"),
    }));
    expect(outcome).toEqual({ kind: "failed" });
    expect(spy.target.fetch).not.toHaveBeenCalled();
  });

  it("refuses every upstream redirect and does not return its response", async () => {
    for (const status of [300, 301, 302, 303, 304, 305, 307, 308, 399]) {
      const spy = bindingSpy(() => new Response("private-redirect-marker", {
        status, headers: { Location: "https://attacker.invalid/" },
      }));
      const outcome = await dispatchControlPlane(input({ binding: spy.target }));
      expect(outcome, String(status)).toEqual({ kind: "failed" });
      expect(spy.target.fetch).toHaveBeenCalledTimes(1);
      expect(spy.observed[0].redirect).toBe("manual");
    }
  });

  it("maps a throwing binding to failed", async () => {
    const spy = bindingSpy(() => { throw new Error("private-upstream-marker"); });
    const outcome = await dispatchControlPlane(input({ binding: spy.target }));
    expect(outcome).toEqual({ kind: "failed" });
    expect(spy.target.fetch).toHaveBeenCalledTimes(1);
  });
});
