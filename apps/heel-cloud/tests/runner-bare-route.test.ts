// SPDX-License-Identifier: LicenseRef-Heel-Commercial

// The released rc2 runner transport addresses the runner-protocol machine routes as
// `POST /v1/...` on the dashboard origin (heel/runner/control_transport.py `_PATH`). The
// Worker must treat that spelling exactly like `/api/control-plane/v1/...` for those
// machine routes only; every human/session route keeps the browser prefix.

import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const { appFetch } = vi.hoisted(() => ({ appFetch: vi.fn() }));

vi.mock("vinext/server/image-optimization", () => ({
  handleImageOptimization: vi.fn(), DEFAULT_DEVICE_SIZES: [], DEFAULT_IMAGE_SIZES: [],
}));
vi.mock("vinext/server/app-router-entry", () => ({ default: { fetch: appFetch } }));

import worker from "../worker/index";

const PREFIX = "/api/control-plane";
const workspace = "ws_0123456789abcdef";
const runner = "runr_0123456789abcdef0123456789abcdef";
const pairing = `pending_${"a".repeat(32)}`;
const rotation = `rotation_${"b".repeat(32)}`;
const binding = "rcb_0123456789abcdef0123456789abcdef";
const run = `crun_${"c".repeat(32)}`;
const edge = "a".repeat(43);
const context = { waitUntil() {}, passThroughOnException() {} };
const nextNonce = `${"N".repeat(43)}=`;

const runnerProof = {
  "X-Heel-Runner-Id": runner, "X-Heel-Runner-Key-Id": "key", "X-Heel-Runner-Timestamp-Ms": "1",
  "X-Heel-Runner-Nonce": "nonce", "X-Heel-Runner-Sequence": "1", "X-Heel-Runner-Signature": "sig",
};
const resyncProof = {
  "X-Heel-Runner-Id": runner, "X-Heel-Runner-Key-Id": "key", "X-Heel-Runner-Timestamp-Ms": "1",
  "X-Heel-Runner-Signature": "sig",
};
const runnerBase = `/v1/workspaces/${workspace}/runners/${runner}`;

type Family = { name: string; path: string; headers: Record<string, string>; cap: number };

// One entry per accepted machine-route spelling: exchange, pairing activate/activation-abort,
// rotation public, RUNNER_CONTROL, RUNNER_CONTEXT_CONTROL, RUNNER_RESULT_PROJECTION,
// RUNNER_RESYNC and RUNNER_INACTIVE_CLAIM_ATTESTATION.
const MACHINE_ROUTES: Family[] = [
  { name: "pairing exchange", path: "/v1/runner-pairings/exchange", headers: {}, cap: 16 * 1024 },
  { name: "pairing activate", path: `/v1/runner-pairings/${pairing}/activate`, headers: {}, cap: 16 * 1024 },
  { name: "pairing activation-abort", path: `/v1/runner-pairings/${pairing}/activation-abort`, headers: {}, cap: 16 * 1024 },
  { name: "rotation activate", path: `/v1/runner-rotations/${rotation}/activate`, headers: {}, cap: 16 * 1024 },
  { name: "rotation poll", path: `/v1/runner-rotations/${rotation}/poll`, headers: {}, cap: 16 * 1024 },
  { name: "rotation activation-abort", path: `/v1/runner-rotations/${rotation}/activation-abort`, headers: {}, cap: 16 * 1024 },
  { name: "control claim", path: `${runnerBase}/claim`, headers: runnerProof, cap: 256 },
  { name: "control heartbeat", path: `${runnerBase}/runs/${run}/heartbeat`, headers: runnerProof, cap: 36 * 1024 },
  { name: "control progress", path: `${runnerBase}/runs/${run}/progress`, headers: runnerProof, cap: 36 * 1024 },
  { name: "control result", path: `${runnerBase}/runs/${run}/result`, headers: runnerProof, cap: 36 * 1024 },
  { name: "control stop-ack", path: `${runnerBase}/runs/${run}/stop-ack`, headers: runnerProof, cap: 36 * 1024 },
  { name: "context list", path: `${runnerBase}/contexts/list`, headers: runnerProof, cap: 128 },
  { name: "context claim", path: `${runnerBase}/contexts/${binding}/claim`, headers: runnerProof, cap: 256 },
  { name: "context approval-projections", path: `${runnerBase}/contexts/${binding}/approval-projections`, headers: runnerProof, cap: 69632 },
  { name: "result projection", path: `${runnerBase}/runs/${run}/result-projection`, headers: runnerProof, cap: 272 * 1024 },
  { name: "resync start", path: `${runnerBase}/resync/start`, headers: resyncProof, cap: 2 * 1024 },
  { name: "resync complete", path: `${runnerBase}/resync/complete`, headers: resyncProof, cap: 2 * 1024 },
  { name: "inactive-claim attestation", path: `${runnerBase}/runs/${run}/inactive-claim-attestation`, headers: resyncProof, cap: 2 * 1024 },
];

beforeAll(() => {
  class LengthStream extends TransformStream<Uint8Array, Uint8Array> {
    constructor(length: number) { void length; super(); }
  }
  (globalThis as typeof globalThis & { FixedLengthStream: typeof LengthStream }).FixedLengthStream = LengthStream;
});

beforeEach(() => {
  appFetch.mockReset();
  appFetch.mockImplementation(async () => new Response("<html>app</html>", { status: 404, headers: { "Content-Type": "text/html" } }));
});

function upstreamOk() {
  return vi.fn().mockImplementation(async () => new Response('{"ok":true}', {
    status: 201,
    headers: { "Content-Type": "application/json", "X-Heel-Runner-Next-Nonce": nextNonce, "Set-Cookie": "x=y", "X-Other": "dropped" },
  }));
}

function env(fetcher: ReturnType<typeof vi.fn>) {
  return { CONTROL_PLANE: { fetch: fetcher }, CONTROL_PLANE_EDGE_SECRET: edge, PUBLIC_ORIGIN: "https://heel.example" } as never;
}

function post(path: string, headers: Record<string, string>, body = '{"k":"v"}', search = "") {
  return new Request(`https://heel.example${path}${search}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Content-Length": String(new TextEncoder().encode(body).byteLength), ...headers },
    body,
  });
}

async function observe(request: Request) {
  appFetch.mockClear();
  const fetcher = upstreamOk();
  const response = await worker.fetch(request, env(fetcher), context);
  const responseHeaders = [...response.headers.entries()].filter(([name]) => name !== "content-security-policy");
  const upstream = fetcher.mock.calls.length === 1 ? fetcher.mock.calls[0][0] as Request : null;
  return {
    status: response.status,
    body: await response.text(),
    responseHeaders,
    calls: fetcher.mock.calls.length,
    appCalls: appFetch.mock.calls.length,
    upstream: upstream === null ? null : {
      method: upstream.method,
      url: upstream.url,
      headers: [...upstream.headers.entries()].sort(),
      body: await upstream.text(),
    },
  };
}

describe("bare /v1 runner machine routes (rc2 runner transport)", () => {
  for (const family of MACHINE_ROUTES) {
    it(`${family.name}: bare spelling is equivalent to the prefixed route`, async () => {
      const prefixed = await observe(post(`${PREFIX}${family.path}`, family.headers));
      const bare = await observe(post(family.path, family.headers));
      expect(prefixed.calls).toBe(1);
      expect(prefixed.upstream?.url).toBe(`https://heel.example${family.path}`);
      expect(bare).toEqual(prefixed);
      expect(bare.appCalls).toBe(0);
    });

    it(`${family.name}: bare spelling keeps the identical header, body-cap, query and method contract`, async () => {
      const variants: Array<[string, (path: string) => Request]> = [
        ["oversized body", (path) => post(path, family.headers, "x".repeat(family.cap + 1))],
        ["at cap", (path) => post(path, family.headers, "x".repeat(family.cap))],
        ["query string", (path) => post(path, family.headers, "{}", "?a=1")],
        ["cookie", (path) => post(path, { ...family.headers, Cookie: "__Host-heel_session=abc" })],
        ["authorization", (path) => post(path, { ...family.headers, Authorization: "Bearer heel_sk_abc" })],
        ["text body", (path) => post(path, { ...family.headers, "Content-Type": "text/plain" })],
        ["gzip body", (path) => post(path, { ...family.headers, "Content-Encoding": "gzip" })],
        ["GET", (path) => new Request(`https://heel.example${path}`, { method: "GET", headers: family.headers })],
        ["DELETE", (path) => new Request(`https://heel.example${path}`, { method: "DELETE", headers: family.headers })],
        ["PUT", (path) => new Request(`https://heel.example${path}`, { method: "PUT", headers: { ...family.headers, "Content-Type": "application/json", "Content-Length": "2" }, body: "{}" })],
        ["near match", (path) => post(`${path}-extra`, family.headers)],
      ];
      if (Object.keys(family.headers).length > 0) {
        for (const missing of Object.keys(family.headers)) {
          variants.push([`missing ${missing}`, (path) => {
            const headers = { ...family.headers };
            delete headers[missing as keyof typeof headers];
            return post(path, headers);
          }]);
        }
      }
      for (const [label, build] of variants) {
        const prefixed = await observe(build(`${PREFIX}${family.path}`));
        const bare = await observe(build(family.path));
        if (label === "near match") {
          // Prefixed near misses are a closed Worker 404; the bare near miss is not a
          // control-plane route at all and reaches neither the private binding nor a proxy.
          expect(prefixed.status, label).toBe(404);
          expect(prefixed.calls, label).toBe(0);
          expect(bare.calls, label).toBe(0);
          expect(bare.status, label).toBe(404);
          continue;
        }
        expect(bare, label).toEqual(prefixed);
        if (label !== "at cap") {
          expect(bare.calls, label).toBe(0);
          expect([400, 404], label).toContain(bare.status);
        }
        expect(bare.appCalls, label).toBe(0);
      }
    });
  }
});

describe("bare /v1 human, session and unknown routes are not aliased", () => {
  const browser = { Origin: "https://heel.example", "Sec-Fetch-Site": "same-origin", Cookie: "__Host-heel_session=abc" };
  const human: Array<[string, string]> = [
    ["POST", "/v1/signup"], ["POST", "/v1/login"], ["POST", "/v1/logout"], ["GET", "/v1/me"],
    ["POST", "/v1/device/start"], ["POST", "/v1/device/verify"], ["POST", "/v1/device/poll"],
    ["POST", "/v1/device/token"], ["POST", "/v1/device/refresh"], ["POST", "/v1/device/revoke"],
    ["GET", `/v1/workspaces/${workspace}/runner-pairings`],
    ["POST", `/v1/workspaces/${workspace}/runner-pairings`],
    ["POST", `/v1/workspaces/${workspace}/runner-pairings/${pairing}/approve`],
    ["DELETE", `/v1/workspaces/${workspace}/runner-pairings/${pairing}`],
    ["POST", `/v1/workspaces/${workspace}/runners/${runner}/rotate`],
    ["POST", `/v1/workspaces/${workspace}/runners/${runner}/rotations/${rotation}/approve`],
    ["POST", `/v1/workspaces/${workspace}/runners/${runner}/revoke`],
    ["GET", `/v1/workspaces/${workspace}/projects`],
    ["POST", `/v1/workspaces/${workspace}/projects`],
  ];
  const unknown = [
    "/v1", "/v1/", "/v1/runner-pairings", "/v1/runner-pairings/exchange/", "/v1//runner-pairings/exchange",
    "/v1/RUNNER-PAIRINGS/exchange", "/v1/runner-pairings%2Fexchange", "/v1/runner-pairings/exchange-extra",
    `/v1/runner-pairings/pending_${"a".repeat(31)}/activate`, `/v1/runner-rotations/${rotation}/approve`,
    `${runnerBase}`, `${runnerBase}/runs/${run}/unknown`, `${runnerBase}/resync/abort`,
    "/v2/runner-pairings/exchange", "/v1/anything",
  ];

  it("leaves bare human/session routes to the app (404) and never calls the private binding", async () => {
    for (const [method, path] of human) {
      const init: RequestInit = { method, headers: { ...browser } };
      if (method === "POST") {
        init.headers = { ...browser, "Content-Type": "application/json", "Content-Length": "2" };
        init.body = "{}";
      }
      appFetch.mockClear();
      const fetcher = upstreamOk();
      const response = await worker.fetch(new Request(`https://heel.example${path}`, init), env(fetcher), context);
      expect(response.status, `${method} ${path}`).toBe(404);
      expect(response.headers.get("content-type"), `${method} ${path}`).toBe("text/html");
      expect(fetcher, `${method} ${path}`).not.toHaveBeenCalled();
      expect(appFetch, `${method} ${path}`).toHaveBeenCalledTimes(1);
    }
  });

  it("leaves malformed and unknown bare /v1 paths to the app and never calls the private binding", async () => {
    for (const path of unknown) {
      for (const method of ["POST", "GET"]) {
        appFetch.mockClear();
        const fetcher = upstreamOk();
        const request = method === "POST"
          ? post(path, runnerProof)
          : new Request(`https://heel.example${path}`, { method, headers: runnerProof });
        const response = await worker.fetch(request, env(fetcher), context);
        expect(response.status, `${method} ${path}`).toBe(404);
        expect(fetcher, `${method} ${path}`).not.toHaveBeenCalled();
        expect(appFetch, `${method} ${path}`).toHaveBeenCalledTimes(1);
      }
    }
  });
});
