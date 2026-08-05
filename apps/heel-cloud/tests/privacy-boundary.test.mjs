// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";


const appRoot = new URL("../", import.meta.url);


async function source(path) {
  return readFile(new URL(path, appRoot), "utf8");
}


test("keeps customer source in the worker message path and out of durable or network sinks", async () => {
  const [client, localReviews, presentation, reviewContract, browserWorker] = await Promise.all([
    source("lib/browser-review-client.ts"),
    source("lib/local-reviews.ts"),
    source("lib/review-presentation.ts"),
    source("lib/review-v1.ts"),
    source("workers/heel-review.worker.ts"),
  ]);
  const allCustomerBoundarySource = [client, localReviews, presentation, reviewContract, browserWorker].join("\n");

  assert.doesNotMatch(allCustomerBoundarySource, /\blocalStorage\b|\bsessionStorage\b|\bcaches\s*\.|\bCacheStorage\b/);
  assert.doesNotMatch(allCustomerBoundarySource, /navigator\.sendBeacon|analytics|telemetry|error[-_ ]report/i);
  assert.doesNotMatch(allCustomerBoundarySource, /["']use server["']|server action/i);
  assert.doesNotMatch(allCustomerBoundarySource, /\bconsole\s*\./);
  assert.doesNotMatch(allCustomerBoundarySource, /https?:\/\//i);

  assert.doesNotMatch(client, /\bfetch\s*\(|XMLHttpRequest|WebSocket|EventSource|indexedDB|\bcaches\b/);
  assert.doesNotMatch(localReviews, /\bfetch\s*\(|XMLHttpRequest|WebSocket|EventSource|\bURL\b/);
  assert.doesNotMatch(localReviews, /\b(source|answers_json)\s*:/);
  assert.match(localReviews, /sync_state:\s*["']local_only["']/);

  assert.match(client, /postMessage\(JSON\.stringify\(/);
  assert.match(browserWorker, /typeof event\.data !== ["']string["']/);
  assert.match(browserWorker, /postMessage\(JSON\.stringify\(/);
  assert.doesNotMatch(browserWorker, /postMessage\(\s*source|fetch\([^)]*source|send\([^)]*source/i);
});


test("pins worker boot to same-origin runtime assets and revokes ambient network/package APIs", async () => {
  const worker = await source("workers/heel-review.worker.ts");

  assert.match(worker, /["']\/heel-runtime\/pyodide\.mjs["']/);
  assert.match(worker, /["']\/heel-runtime\/runtime-manifest\.json["']/);
  assert.match(worker, /crypto\.subtle\.digest\(["']SHA-256["']/);
  assert.match(worker, /wheel\.sha256/);
  assert.match(worker, /wheel\.size/);
  assert.match(worker, /unpackArchive/);
  assert.match(worker, /loadPackage/);
  assert.match(worker, /loadPackagesFromImports/);
  for (const capability of ["fetch", "XMLHttpRequest", "WebSocket", "EventSource"]) {
    assert.match(worker, new RegExp(`guard.*${capability}|${capability}.*guard`, "is"));
  }
  assert.match(worker, /MAX_BROWSER_RESULT_BYTES/);
  assert.doesNotMatch(worker, /https?:\/\/|unpkg|jsdelivr|pypi\.org|["']micropip["']|\/api\/review/i);
});


test("attaches a strict CSP and browser security headers to app and image responses", async () => {
  const worker = await source("worker/index.ts");

  assert.match(worker, /Content-Security-Policy/);
  for (const directive of [
    "default-src 'self'",
    "base-uri 'none'",
    "connect-src 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "object-src 'none'",
    "script-src 'self'",
    "worker-src 'self'",
    "'wasm-unsafe-eval'",
  ]) {
    assert.match(worker, new RegExp(directive.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
  assert.match(worker, /Referrer-Policy[^\n]+no-referrer/);
  assert.match(worker, /X-Content-Type-Options[^\n]+nosniff/);
  assert.match(worker, /X-Frame-Options[^\n]+DENY/);
  assert.match(worker, /Permissions-Policy/);
  assert.match(worker, /handleImageOptimization/);
  assert.match(worker, /withSecurityHeaders/);
  assert.doesNotMatch(worker, /connect-src[^;\n]*(https?:|\*)/);
  assert.doesNotMatch(worker, /worker-src[^;\n]*(https?:|\*)/);
});
