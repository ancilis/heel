// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import { beforeAll, describe, expect, it, vi } from "vitest";

vi.mock("vinext/server/image-optimization", () => ({
  handleImageOptimization: vi.fn(), DEFAULT_DEVICE_SIZES: [], DEFAULT_IMAGE_SIZES: [],
}));
vi.mock("vinext/server/app-router-entry", () => ({ default: { fetch: vi.fn() } }));

import worker from "../worker/index";

const workspace = "ws_0123456789abcdef";
const runner = "runr_0123456789abcdef0123456789abcdef";
const edge = "a".repeat(43);

beforeAll(() => {
  class LengthStream extends TransformStream<Uint8Array, Uint8Array> {
    constructor(_: number) { super(); }
  }
  (globalThis as typeof globalThis & { FixedLengthStream: typeof LengthStream }).FixedLengthStream = LengthStream;
});

function env(fetcher = vi.fn().mockResolvedValue(new Response("{}", { headers: { "Content-Type": "application/json" } }))) {
  return { CONTROL_PLANE: { fetch: fetcher }, CONTROL_PLANE_EDGE_SECRET: edge, PUBLIC_ORIGIN: "https://heel.example" } as never;
}

function request(path: string, headers: Record<string, string>, body = "{}") {
  return new Request(`https://heel.example${path}`, { method: "POST", headers: { "Content-Type": "application/json", "Content-Length": String(new TextEncoder().encode(body).byteLength), ...headers }, body });
}

describe("runner edge routes", () => {
  it("isolates exact context routes on the existing claim proof headers and caps", async () => {
    const binding = "rcb_0123456789abcdef0123456789abcdef";
    const headers = { "X-Heel-Runner-Id": runner, "X-Heel-Runner-Key-Id": "key", "X-Heel-Runner-Timestamp-Ms": "1", "X-Heel-Runner-Nonce": "nonce", "X-Heel-Runner-Sequence": "1", "X-Heel-Runner-Signature": "sig" };
    const fetcher = vi.fn().mockResolvedValue(new Response("{}", { headers: { "Content-Type": "application/json" } }));
    const listed = await worker.fetch(request(`/api/control-plane/v1/workspaces/${workspace}/runners/${runner}/contexts/list`, headers), env(fetcher), { waitUntil() {}, passThroughOnException() {} });
    expect(listed.status).toBe(200);
    const upstream = fetcher.mock.calls[0][0] as Request;
    expect([...upstream.headers.keys()].sort()).toEqual(["content-encoding", "content-length", "content-type", "x-heel-edge-auth", "x-heel-runner-id", "x-heel-runner-key-id", "x-heel-runner-nonce", "x-heel-runner-sequence", "x-heel-runner-signature", "x-heel-runner-timestamp-ms"]);
    const oversized = request(`/api/control-plane/v1/workspaces/${workspace}/runners/${runner}/contexts/${binding}/claim`, headers, "x".repeat(257));
    expect((await worker.fetch(oversized, env(fetcher), { waitUntil() {}, passThroughOnException() {} })).status).toBe(400);
  });
  it("forwards only the resync proof header subset and raw body", async () => {
    const fetcher = vi.fn().mockResolvedValue(new Response("{}", { headers: { "Content-Type": "application/json" } }));
    const response = await worker.fetch(request(
      `/api/control-plane/v1/workspaces/${workspace}/runners/${runner}/resync/start`,
      { "X-Heel-Runner-Id": runner, "X-Heel-Runner-Key-Id": "key", "X-Heel-Runner-Timestamp-Ms": "1", "X-Heel-Runner-Signature": "sig", "Cookie": "__Host-heel_session=x", "Authorization": "Bearer heel_at_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
    ), env(fetcher), { waitUntil() {}, passThroughOnException() {} });
    expect(response.status).toBe(400);
    expect(fetcher).not.toHaveBeenCalled();

    const accepted = await worker.fetch(request(
      `/api/control-plane/v1/workspaces/${workspace}/runners/${runner}/resync/start`,
      { "X-Heel-Runner-Id": runner, "X-Heel-Runner-Key-Id": "key", "X-Heel-Runner-Timestamp-Ms": "1", "X-Heel-Runner-Signature": "sig" },
    ), env(fetcher), { waitUntil() {}, passThroughOnException() {} });
    expect(accepted.status).toBe(200);
    const upstream = fetcher.mock.calls[0][0] as Request;
    expect([...upstream.headers.keys()].sort()).toEqual([
      "content-encoding", "content-length", "content-type", "x-heel-edge-auth",
      "x-heel-runner-id", "x-heel-runner-key-id", "x-heel-runner-signature", "x-heel-runner-timestamp-ms",
    ]);
    expect(await upstream.text()).toBe("{}");
  });

  it("rejects nonce headers on resync and per-family oversized bodies before upstream", async () => {
    const fetcher = vi.fn();
    const resync = request(`/api/control-plane/v1/workspaces/${workspace}/runners/${runner}/resync/complete`, {
      "X-Heel-Runner-Id": runner, "X-Heel-Runner-Key-Id": "key", "X-Heel-Runner-Timestamp-Ms": "1", "X-Heel-Runner-Signature": "sig", "X-Heel-Runner-Nonce": "forbidden",
    });
    expect((await worker.fetch(resync, env(fetcher), { waitUntil() {}, passThroughOnException() {} })).status).toBe(400);
    const claim = request(`/api/control-plane/v1/workspaces/${workspace}/runners/${runner}/claim`, {
      "X-Heel-Runner-Id": runner, "X-Heel-Runner-Key-Id": "key", "X-Heel-Runner-Timestamp-Ms": "1", "X-Heel-Runner-Nonce": "nonce", "X-Heel-Runner-Sequence": "1", "X-Heel-Runner-Signature": "sig",
    }, "x".repeat(257));
    expect((await worker.fetch(claim, env(fetcher), { waitUntil() {}, passThroughOnException() {} })).status).toBe(400);
    expect(fetcher).not.toHaveBeenCalled();
  });
});
