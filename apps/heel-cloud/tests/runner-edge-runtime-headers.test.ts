// SPDX-License-Identifier: LicenseRef-Heel-Commercial

// The deployed edge differs from Node's fetch in two ways that refused the paired rc2 runner's
// first signed call (`POST …/contexts/list` → 400 "invalid control plane request"):
// 1. Cloudflare hands the Worker every request with `Connection: Keep-Alive` (any client value is
//    overwritten), and the runner-proof family refused any Connection field.
// 2. workerd's non-standard `Headers.getAll` throws a TypeError for every name except Set-Cookie,
//    and `singletonHeader` called it for runner proof fields, Idempotency-Key,
//    If-Heel-Control-Generation and the approval queue's response Content-Length.
// These tests reproduce both runtime facts in Node: the edge header is added to the request, and
// `Headers.prototype.getAll` is given workerd's exact behaviour for the duration of each test.
// tests/test_runner_worker_wire.py proves the same journey in workerd itself.

import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const { appFetch } = vi.hoisted(() => ({ appFetch: vi.fn() }));

vi.mock("vinext/server/image-optimization", () => ({
  handleImageOptimization: vi.fn(), DEFAULT_DEVICE_SIZES: [], DEFAULT_IMAGE_SIZES: [],
}));
vi.mock("vinext/server/app-router-entry", () => ({ default: { fetch: appFetch } }));

import worker from "../worker/index";

const origin = "https://heel.example";
const workspace = "ws_0123456789abcdef";
const runner = "runr_0123456789abcdef0123456789abcdef";
const binding = "rcb_0123456789abcdef0123456789abcdef";
const project = `prj_${"1".repeat(32)}`;
const run = `crun_${"c".repeat(32)}`;
const edge = "a".repeat(43);
const context = { waitUntil() {}, passThroughOnException() {} };
const nextNonce = `${"N".repeat(43)}=`;
const runnerBase = `/v1/workspaces/${workspace}/runners/${runner}`;
const ownerBase = `/api/control-plane/v1/workspaces/${workspace}/projects/${project}`;
const refused = { status: 400, body: '{"error":"invalid control plane request"}', calls: 0 };

const proof = {
  "X-Heel-Runner-Id": runner, "X-Heel-Runner-Key-Id": "k_a885ad48a10280e5",
  "X-Heel-Runner-Timestamp-Ms": "1794380875291", "X-Heel-Runner-Nonce": nextNonce,
  "X-Heel-Runner-Sequence": "1", "X-Heel-Runner-Signature": `${"S".repeat(86)}==`,
};

// Every runner-proof frame of the first scan, at its exact rc2 spelling and per-route cap.
const FRAMES: Array<{ name: string; path: string; body: string; cap: number }> = [
  { name: "context list", path: `${runnerBase}/contexts/list`, body: '{"schema_version":"heel.runner-context-list.v1"}', cap: 128 },
  { name: "context claim", path: `${runnerBase}/contexts/${binding}/claim`, body: "{}", cap: 256 },
  { name: "projection submit", path: `${runnerBase}/contexts/${binding}/approval-projections`, body: "{}", cap: 69632 },
  { name: "lease claim", path: `${runnerBase}/claim`, body: "{}", cap: 256 },
  { name: "heartbeat", path: `${runnerBase}/runs/${run}/heartbeat`, body: "{}", cap: 36 * 1024 },
  { name: "progress", path: `${runnerBase}/runs/${run}/progress`, body: "{}", cap: 36 * 1024 },
  { name: "result", path: `${runnerBase}/runs/${run}/result`, body: "{}", cap: 36 * 1024 },
  { name: "result projection", path: `${runnerBase}/runs/${run}/result-projection`, body: "{}", cap: 272 * 1024 },
];

type GetAll = (name: string) => string[];
const headersPrototype = Headers.prototype as Headers & { getAll?: GetAll };
let originalGetAll: GetAll | undefined;

beforeAll(() => {
  class LengthStream extends TransformStream<Uint8Array, Uint8Array> {
    constructor(length: number) { void length; super(); }
  }
  (globalThis as typeof globalThis & { FixedLengthStream: typeof LengthStream }).FixedLengthStream = LengthStream;
});

beforeEach(() => {
  appFetch.mockReset();
  originalGetAll = headersPrototype.getAll;
  // workerd: "getAll() can only be used with the header name \"Set-Cookie\"."
  headersPrototype.getAll = function getAll(this: Headers, name: string): string[] {
    if (name.toLowerCase() !== "set-cookie") {
      throw new TypeError('getAll() can only be used with the header name "Set-Cookie".');
    }
    return this.getSetCookie();
  };
});

afterEach(() => {
  if (originalGetAll === undefined) delete headersPrototype.getAll;
  else headersPrototype.getAll = originalGetAll;
});

function upstream(status = 200, body = '{"ok":true}') {
  return vi.fn().mockImplementation(async () => new Response(body, {
    status,
    headers: {
      "Content-Type": "application/json", "Content-Length": String(new TextEncoder().encode(body).byteLength),
      "X-Heel-Runner-Next-Nonce": nextNonce,
    },
  }));
}

function env(fetcher: ReturnType<typeof vi.fn>) {
  return { CONTROL_PLANE: { fetch: fetcher }, CONTROL_PLANE_EDGE_SECRET: edge, PUBLIC_ORIGIN: origin } as never;
}

/** The request as the Worker receives it from Cloudflare's edge: `Connection: Keep-Alive` added. */
function edgeRequest(path: string, init: { method?: string; headers?: Record<string, string>; body?: string }) {
  const headers: Record<string, string> = { Host: "heel.example", Accept: "application/json", Connection: "Keep-Alive", ...init.headers };
  if (init.body !== undefined) {
    headers["Content-Type"] ??= "application/json";
    headers["Content-Length"] ??= String(new TextEncoder().encode(init.body).byteLength);
  }
  return new Request(`${origin}${path}`, { method: init.method ?? "POST", headers, body: init.body });
}

async function observe(request: Request, fetcher = upstream()) {
  const response = await worker.fetch(request, env(fetcher), context);
  const forwarded = fetcher.mock.calls.length === 1 ? fetcher.mock.calls[0][0] as Request : null;
  return {
    status: response.status,
    body: await response.text(),
    calls: fetcher.mock.calls.length,
    nonce: response.headers.get("X-Heel-Runner-Next-Nonce"),
    upstreamHeaders: forwarded === null ? null : [...forwarded.headers.keys()].sort(),
    upstreamBody: forwarded === null ? null : await forwarded.text(),
  };
}

const { "X-Heel-Runner-Nonce": _nonce, ...withoutNonce } = proof;
void _nonce;

const pick = ({ status, body, calls }: { status: number; body: string; calls: number }) => ({ status, body, calls });

describe("runner frames as the deployed edge delivers them", () => {
  for (const frame of FRAMES) {
    it(`${frame.name}: an edge-shaped signed request reaches the control plane unchanged`, async () => {
      const seen = await observe(edgeRequest(frame.path, { headers: proof, body: frame.body }));
      expect(pick(seen)).toEqual({ status: 200, body: '{"ok":true}', calls: 1 });
      expect(seen.nonce).toBe(nextNonce);
      expect(seen.upstreamBody).toBe(frame.body);
      // Hop-by-hop Connection is never forwarded: the upstream set is rebuilt from scratch.
      expect(seen.upstreamHeaders).toEqual([
        "content-encoding", "content-length", "content-type", "x-heel-edge-auth",
        "x-heel-runner-id", "x-heel-runner-key-id", "x-heel-runner-nonce", "x-heel-runner-sequence",
        "x-heel-runner-signature", "x-heel-runner-timestamp-ms",
      ]);
    });

    it(`${frame.name}: smuggling, duplicated proof, credentials and oversize bodies stay refused`, async () => {
      const variants: Array<[string, Request]> = [
        ["Connection close", edgeRequest(frame.path, { headers: { ...proof, Connection: "close" }, body: frame.body })],
        ["Connection nominating a proof field", edgeRequest(frame.path, { headers: { ...proof, Connection: "Keep-Alive, X-Heel-Runner-Id" }, body: frame.body })],
        ["TE", edgeRequest(frame.path, { headers: { ...proof, TE: "trailers" }, body: frame.body })],
        ["duplicated signature", edgeRequest(frame.path, { headers: { ...proof, "X-Heel-Runner-Signature": `${proof["X-Heel-Runner-Signature"]}, other` }, body: frame.body })],
        ["missing nonce", edgeRequest(frame.path, { headers: withoutNonce, body: frame.body })],
        ["session cookie", edgeRequest(frame.path, { headers: { ...proof, Cookie: "__Host-heel_session=abc" }, body: frame.body })],
        ["bearer", edgeRequest(frame.path, { headers: { ...proof, Authorization: "Bearer heel_sk_abc" }, body: frame.body })],
        ["edge-derived origin", edgeRequest(frame.path, { headers: { ...proof, "X-Heel-Internal-Origin": "same-origin" }, body: frame.body })],
        ["over the route cap", edgeRequest(frame.path, { headers: proof, body: "x".repeat(frame.cap + 1) })],
      ];
      for (const [name, request] of variants) {
        expect([name, pick(await observe(request))]).toEqual([name, refused]);
      }
    });
  }

  it("a wrong workspace or runner spelling is not a runner route at all", async () => {
    for (const path of [
      `/v1/workspaces/ws_0123456789ABCDEF/runners/${runner}/contexts/list`,
      `/v1/workspaces/${workspace}/runners/${runner}/contexts/list/extra`,
      `/v1/workspaces/${workspace}/runners/${"r".repeat(129)}/contexts/list`,
    ]) {
      appFetch.mockClear();
      appFetch.mockImplementation(async () => new Response("app", { status: 404 }));
      const seen = await observe(edgeRequest(path, { headers: proof, body: "{}" }));
      expect(seen.calls).toBe(0);
      expect(seen.status).toBe(404);
    }
  });
});

describe("owner approval frames as the deployed edge delivers them", () => {
  const owner = {
    Cookie: "__Host-heel_session=session-token", Origin: origin, "Sec-Fetch-Site": "same-origin",
  };

  it("the browser approval carries its idempotency key and generation to the control plane", async () => {
    const body = '{"schema_version":"heel.canary-execution-approval.v1"}';
    const seen = await observe(edgeRequest(`${ownerBase}/canary-runs/${run}/approve`, {
      headers: { ...owner, "Idempotency-Key": `ca1-${"f".repeat(64)}`, "If-Heel-Control-Generation": "0" }, body,
    }));
    expect(pick(seen)).toEqual({ status: 200, body: '{"ok":true}', calls: 1 });
    expect(seen.upstreamHeaders).toContain("idempotency-key");
    expect(seen.upstreamHeaders).toContain("if-heel-control-generation");
    expect(seen.upstreamHeaders).not.toContain("connection");
    const variants: Array<Record<string, string>> = [
      { "Idempotency-Key": `ca1-${"f".repeat(64)}, ca1-${"e".repeat(64)}`, "If-Heel-Control-Generation": "0" },
      { "Idempotency-Key": `ca1-${"f".repeat(64)}`, "If-Heel-Control-Generation": "0, 1" },
      { "If-Heel-Control-Generation": "0" },
    ];
    for (const extra of variants) {
      expect(pick(await observe(edgeRequest(`${ownerBase}/canary-runs/${run}/approve`, { headers: { ...owner, ...extra }, body }))))
        .toEqual(refused);
    }
  });

  it("the approval queue read keeps its exact response framing check", async () => {
    const queue = '{"requests":[],"has_more":false}';
    const seen = await observe(edgeRequest(`${ownerBase}/canary-approval-requests`, { method: "GET", headers: owner }), upstream(200, queue));
    expect(pick(seen)).toEqual({ status: 200, body: queue, calls: 1 });
    const lying = vi.fn().mockImplementation(async () => new Response(queue, {
      status: 200, headers: { "Content-Type": "application/json", "Content-Length": "999999" },
    }));
    expect(pick(await observe(edgeRequest(`${ownerBase}/canary-approval-requests`, { method: "GET", headers: owner }), lying)))
      .toEqual({ status: 502, body: '{"error":"control plane request failed"}', calls: 1 });
  });
});
