// SPDX-License-Identifier: LicenseRef-Heel-Commercial

// The deployed rc5 site served the published 1.3.0rc5 Agent wheel and source archive at
// /downloads/<name>. The current /downloads/ files are the next release only, so exactly those two
// names redirect to the immutable v1.3.0rc5 GitHub release assets, whose bytes equal what the site
// served. Every other path, method or query is left to the app, and no other file is aliased.

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
const RELEASE = "https://github.com/ancilis/heel/releases/download/v1.3.0rc5/";
const LEGACY = {
  "heel_sim-1.3.0rc5-py3-none-any.whl": "a7c7293be3e30f1c3fb6fd968ab16c2845ebaae34d4fe3bcb2ddfd54855aa226",
  "heel_sim-1.3.0rc5.tar.gz": "3cd3cbc9aa84381f58703c13cc0f446fa8fc8fe57d395283cdc422ff3ded579e",
} as const;
const context = { waitUntil() {}, passThroughOnException() {} };
const env = { ASSETS: { fetch: vi.fn() }, IMAGES: {}, CONTROL_PLANE: { fetch: vi.fn() } } as never;
const fixture = resolve(process.cwd(), "../../tests/fixtures/runner_preview_rc5/artifacts");

const call = (path: string, method = "GET") =>
  worker.fetch(new Request(`${ORIGIN}${path}`, { method }), env, context as never);

describe("published rc5 download links", () => {
  beforeEach(() => {
    appFetch.mockReset();
    appFetch.mockResolvedValue(new Response("app", { status: 404 }));
  });

  it("redirects exactly the two rc5 file names to their immutable release assets", async () => {
    for (const name of Object.keys(LEGACY)) {
      for (const method of ["GET", "HEAD"]) {
        const response = await call(`/downloads/${name}`, method);
        expect(response.status).toBe(308);
        expect(response.headers.get("location")).toBe(`${RELEASE}${name}`);
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
      ["/downloads/HEEL_SIM-1.3.0RC5.TAR.GZ", "GET"],
      ["/downloads/heel-open-core-manifest.json", "GET"],
      ["/heel-runtime/heel_browser-1.3.0rc5-py3-none-any.whl", "GET"],
    ] as const) {
      const response = await call(path, method);
      expect(response.status, `${method} ${path}`).not.toBe(308);
      expect(response.headers.get("location"), path).toBeNull();
    }
  });

  it("names targets whose published bytes are the historical rc5 fixture, and serves no rc5 file itself", () => {
    for (const [name, digest] of Object.entries(LEGACY)) {
      const bytes = readFileSync(join(fixture, name));
      expect(createHash("sha256").update(bytes).digest("hex")).toBe(digest);
    }
    const current = readdirSync(resolve(process.cwd(), "public/downloads")).sort();
    expect(current.some((name) => name.includes("1.3.0rc5"))).toBe(false);
    const source = readFileSync(resolve(process.cwd(), "worker/index.ts"), "utf8");
    expect(source.match(/\/downloads\/heel_sim-[^"`]*/g)).toEqual([
      "/downloads/heel_sim-1.3.0rc5-py3-none-any.whl",
      "/downloads/heel_sim-1.3.0rc5.tar.gz",
    ]);
  });
});
