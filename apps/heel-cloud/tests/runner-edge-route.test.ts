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
    constructor(length: number) { void length; super(); }
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
  it("forwards exact unauthenticated pairing and rotation activation-abort routes", async () => {
    const pairing = `pending_${"a".repeat(32)}`;
    const rotation = `rotation_${"b".repeat(32)}`;
    const fetcher = vi.fn().mockResolvedValue(new Response("{}", { headers: { "Content-Type": "application/json" } }));
    const context = { waitUntil() {}, passThroughOnException() {} };
    const paths = [
      `/api/control-plane/v1/runner-pairings/${pairing}/activation-abort`,
      `/api/control-plane/v1/runner-rotations/${rotation}/activation-abort`,
    ];

    for (const path of paths) {
      const response = await worker.fetch(request(path, {}), env(fetcher), context);
      expect(response.status).toBe(200);
    }

    expect(fetcher).toHaveBeenCalledTimes(paths.length);
    for (const [index, path] of paths.entries()) {
      const upstream = fetcher.mock.calls[index][0] as Request;
      expect(upstream.url).toBe(`https://heel.example${path.replace("/api/control-plane", "")}`);
      expect([...upstream.headers.keys()].sort()).toEqual([
        "content-encoding", "content-length", "content-type", "x-heel-edge-auth",
      ]);
    }
  });

  it("rejects activation-abort near matches and methods before the private binding", async () => {
    const pairing = `pending_${"a".repeat(32)}`;
    const rotation = `rotation_${"b".repeat(32)}`;
    const fetcher = vi.fn();
    const context = { waitUntil() {}, passThroughOnException() {} };
    const rejected = [
      new Request(`https://heel.example/api/control-plane/v1/runner-pairings/${pairing}/activation-abort`, { method: "GET" }),
      new Request(`https://heel.example/api/control-plane/v1/runner-rotations/${rotation}/activation-abort`, { method: "GET" }),
      request(`/api/control-plane/v1/runner-pairings/${pairing}/activation-abort-extra`, {}),
      request(`/api/control-plane/v1/runner-rotations/${rotation}/activation-abort/extra`, {}),
    ];

    for (const candidate of rejected) {
      expect((await worker.fetch(candidate, env(fetcher), context)).status).toBe(404);
    }
    expect(fetcher).not.toHaveBeenCalled();
  });

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

  it("forwards the reasoned runner revoke as a same-origin cookie POST with its exact body", async () => {
    const fetcher = vi.fn().mockResolvedValue(new Response("{}", { headers: { "Content-Type": "application/json" } }));
    const body = '{"schema_version":"heel.runner-revoke.v1","reason_code":"human_revocation"}';
    const response = await worker.fetch(request(`/api/control-plane/v1/workspaces/${workspace}/runners/${runner}/revoke`, {
      Origin: "https://heel.example", "Sec-Fetch-Site": "same-origin", Cookie: "__Host-heel_session=abc",
      "X-Heel-Internal-Origin": "caller-forged", "X-Heel-Edge-Auth": "caller-forged",
    }, body), env(fetcher), { waitUntil() {}, passThroughOnException() {} });
    expect(response.status).toBe(200);
    expect(fetcher).toHaveBeenCalledTimes(1);
    const upstream = fetcher.mock.calls[0][0] as Request;
    expect(upstream.method).toBe("POST");
    expect(upstream.url).toBe(`https://heel.example/v1/workspaces/${workspace}/runners/${runner}/revoke`);
    expect([...upstream.headers.keys()].sort()).toEqual([
      "content-encoding", "content-length", "content-type", "cookie", "origin", "x-heel-edge-auth", "x-heel-internal-origin",
    ]);
    expect(upstream.headers.get("X-Heel-Internal-Origin")).toBe("same-origin");
    expect(upstream.headers.get("X-Heel-Edge-Auth")).toBe(edge);
    expect(upstream.headers.get("Origin")).toBe("https://heel.example");
    expect(upstream.headers.get("Content-Length")).toBe(String(body.length));
    expect(await upstream.text()).toBe(body);
  });

  it("rejects the retired DELETE, other methods, cross-origin, non-cookie and oversized runner revokes before upstream", async () => {
    const fetcher = vi.fn();
    const context = { waitUntil() {}, passThroughOnException() {} };
    const retired = `https://heel.example/api/control-plane/v1/workspaces/${workspace}/runners/${runner}`;
    const path = `/api/control-plane/v1/workspaces/${workspace}/runners/${runner}/revoke`;
    const browser = { Origin: "https://heel.example", "Sec-Fetch-Site": "same-origin", Cookie: "__Host-heel_session=abc" };
    const body = '{"schema_version":"heel.runner-revoke.v1","reason_code":"human_revocation"}';
    for (const candidate of [
      new Request(retired, { method: "DELETE", headers: browser }),
      new Request(`https://heel.example${path}`, { method: "DELETE", headers: browser }),
      new Request(`https://heel.example${path}`, { method: "GET", headers: browser }),
      new Request(`https://heel.example${path}`, { method: "PUT", headers: { ...browser, "Content-Type": "application/json" }, body }),
      request(`${path}/extra`, browser, body),
      request(`/api/control-plane/v1/workspaces/${workspace}/runners/${runner}/revoked`, browser, body),
    ]) {
      expect((await worker.fetch(candidate, env(fetcher), context)).status).toBe(404);
    }
    const noOrigin = { "Sec-Fetch-Site": browser["Sec-Fetch-Site"], Cookie: browser.Cookie };
    const noFetchSite = { Origin: browser.Origin, Cookie: browser.Cookie };
    const noCookie = { Origin: browser.Origin, "Sec-Fetch-Site": browser["Sec-Fetch-Site"] };
    for (const [headers, payload] of [
      [{ ...browser, Origin: "https://evil.example" }, body],
      [noOrigin, body],
      [noFetchSite, body],
      [{ ...browser, "Sec-Fetch-Site": "cross-site" }, body],
      [{ ...browser, "Sec-Fetch-Site": "same-site" }, body],
      [noCookie, body],
      [{ ...noCookie, Authorization: "Bearer heel_sk_abc" }, body],
      [{ ...browser, Authorization: "Bearer heel_sk_abc" }, body],
      [{ ...browser, "Content-Type": "text/plain" }, body],
      [{ ...browser, "Content-Encoding": "gzip" }, body],
      [{ ...browser, "Content-Length": "1000000" }, body],
      [browser, "x".repeat(16 * 1024 + 1)],
    ] as Array<[Record<string, string>, string]>) {
      expect((await worker.fetch(request(path, headers, payload), env(fetcher), context)).status).toBe(400);
    }
    expect(fetcher).not.toHaveBeenCalled();
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
