// SPDX-License-Identifier: LicenseRef-Heel-Commercial

// The deployed rc5 and rc6 sites served the published 1.3.0rc5 and 1.3.0rc6 Agent wheels and source
// archives at /downloads/<name>. The current /downloads/ files are the next release only, so exactly
// those four names redirect to the immutable v1.3.0rc5 or v1.3.0rc6 GitHub release assets, whose bytes
// equal what the sites served. Every other path, method or query is left to the app, and no other file
// is aliased.

import { readFileSync, readdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { join, resolve } from "node:path";

import { beforeEach, describe, expect, it, vi } from "vitest";

const { appFetch } = vi.hoisted(() => ({ appFetch: vi.fn() }));

vi.mock("vinext/server/image-optimization", () => ({
  handleImageOptimization: vi.fn(), DEFAULT_DEVICE_SIZES: [], DEFAULT_IMAGE_SIZES: [],
}));
vi.mock("vinext/server/app-router-entry", () => ({ default: { fetch: appFetch } }));

import worker from "../worker/index";

const ORIGIN = "https://heel.example";
const RELEASE = {
  rc5: "https://github.com/ancilis/heel/releases/download/v1.3.0rc5/",
  rc6: "https://github.com/ancilis/heel/releases/download/v1.3.0rc6/",
} as const;
const LEGACY = {
  "heel_sim-1.3.0rc5-py3-none-any.whl": "a7c7293be3e30f1c3fb6fd968ab16c2845ebaae34d4fe3bcb2ddfd54855aa226",
  "heel_sim-1.3.0rc5.tar.gz": "3cd3cbc9aa84381f58703c13cc0f446fa8fc8fe57d395283cdc422ff3ded579e",
  "heel_sim-1.3.0rc6-py3-none-any.whl": "40b7cc7a4a1364cb412d820727c69b8474e17dc587d49c52fee9fcda137166b0",
  "heel_sim-1.3.0rc6.tar.gz": "7087bcad6cdd73838aedeeb70c7f214816222cb3f052f969a0c93c29421b5fe9",
} as const;
const release = (name: string) => (name.includes("1.3.0rc6") ? RELEASE.rc6 : RELEASE.rc5);
const context = { waitUntil() {}, passThroughOnException() {} };
const env = { ASSETS: { fetch: vi.fn() }, IMAGES: {}, CONTROL_PLANE: { fetch: vi.fn() } } as never;
const fixture = (name: string) => resolve(process.cwd(),
  `../../tests/fixtures/runner_preview_${name.includes("1.3.0rc6") ? "rc6" : "rc5"}/artifacts`);

const call = (path: string, method = "GET") =>
  worker.fetch(new Request(`${ORIGIN}${path}`, { method }), env, context as never);

describe("published rc5 and rc6 download links", () => {
  beforeEach(() => {
    appFetch.mockReset();
    appFetch.mockResolvedValue(new Response("app", { status: 404 }));
  });

  it("redirects exactly the four rc5 and rc6 file names to their immutable release assets", async () => {
    for (const name of Object.keys(LEGACY)) {
      for (const method of ["GET", "HEAD"]) {
        const response = await call(`/downloads/${name}`, method);
        expect(response.status).toBe(308);
        expect(response.headers.get("location")).toBe(`${release(name)}${name}`);
        expect(response.headers.get("x-content-type-options")).toBe("nosniff");
      }
    }
    expect(appFetch).not.toHaveBeenCalled();
  });

  it("leaves every other path, method, query and the current index to the app", async () => {
    for (const [path, method] of [
      ["/downloads/heel_sim-1.3.0rc5-py3-none-any.whl", "POST"],
      ["/downloads/heel_sim-1.3.0rc5-py3-none-any.whl?x=1", "GET"],
      ["/downloads/heel_sim-1.3.0rc4-py3-none-any.whl", "GET"],
      ["/downloads/heel_sim-1.3.0rc5-py3-none-any.whl.sig", "GET"],
      ["/downloads/heel_sim-1.3.0rc6-py3-none-any.whl?x=1", "GET"],
      ["/downloads/heel_sim-1.3.0rc6.tar.gz", "PUT"],
      ["/downloads/heel_sim-1.3.0rc7-py3-none-any.whl", "GET"],
      ["/downloads/HEEL_SIM-1.3.0RC5.TAR.GZ", "GET"],
      ["/downloads/heel-open-core-manifest.json", "GET"],
      ["/heel-runtime/heel_browser-1.3.0rc5-py3-none-any.whl", "GET"],
      ["/heel-runtime/heel_browser-1.3.0rc6-py3-none-any.whl", "GET"],
    ] as const) {
      const response = await call(path, method);
      expect(response.status, `${method} ${path}`).not.toBe(308);
      expect(response.headers.get("location"), path).toBeNull();
    }
  });

  it("names targets whose published bytes are the historical rc5 and rc6 fixtures, and serves neither itself", () => {
    for (const [name, digest] of Object.entries(LEGACY)) {
      const bytes = readFileSync(join(fixture(name), name));
      expect(createHash("sha256").update(bytes).digest("hex")).toBe(digest);
    }
    const current = readdirSync(resolve(process.cwd(), "public/downloads")).sort();
    expect(current.some((name) => name.includes("1.3.0rc5") || name.includes("1.3.0rc6"))).toBe(false);
    const source = readFileSync(resolve(process.cwd(), "worker/index.ts"), "utf8");
    expect(source.match(/\/downloads\/heel_sim-[^"`]*/g)).toEqual([
      "/downloads/heel_sim-1.3.0rc5-py3-none-any.whl",
      "/downloads/heel_sim-1.3.0rc5.tar.gz",
      "/downloads/heel_sim-1.3.0rc6-py3-none-any.whl",
      "/downloads/heel_sim-1.3.0rc6.tar.gz",
    ]);
  });
});
