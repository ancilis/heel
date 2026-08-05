// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { lstat, readFile, readdir } from "node:fs/promises";
import { extname, join, relative } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";


const appRoot = fileURLToPath(new URL("../", import.meta.url));
const distRoot = join(appRoot, "dist");
const clientRoot = join(distRoot, "client");
const runtimeRoot = join(clientRoot, "heel-runtime");
const serverRoot = join(distRoot, "server");
const wheelName = "heel_browser-1.1.0-py3-none-any.whl";


function sha256(payload) {
  return createHash("sha256").update(payload).digest("hex");
}


async function filesUnder(root) {
  const files = [];
  async function visit(directory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isDirectory()) await visit(path);
      else files.push(path);
    }
  }
  await visit(root);
  return files.sort();
}


async function json(path) {
  return JSON.parse(await readFile(path, "utf8"));
}


async function firstPartyBrowserSources() {
  const manifest = await json(join(clientRoot, ".vite/manifest.json"));
  const workspace = manifest["components/review/ReviewWorkspace.tsx"]?.file;
  assert.equal(typeof workspace, "string", "production client manifest omits ReviewWorkspace");
  const workerFiles = (await readdir(join(clientRoot, "assets")))
    .filter((name) => /^heel-review\.worker-[A-Za-z0-9_-]+\.js$/.test(name));
  assert.equal(workerFiles.length, 1, "production build must contain one browser review worker");
  const paths = [join(clientRoot, workspace), join(clientRoot, "assets", workerFiles[0])];
  return {
    paths,
    source: (await Promise.all(paths.map((path) => readFile(path, "utf8")))).join("\n"),
    worker: await readFile(paths[1], "utf8"),
  };
}


test("ships the exact integrity-pinned wheel and Pyodide runtime behind same-origin paths", async () => {
  const [runtimeManifest, builtEngineManifest, committedManifest, runtimeFiles, firstParty] = await Promise.all([
    json(join(runtimeRoot, "runtime-manifest.json")),
    json(join(runtimeRoot, "heel-browser-manifest.json")),
    json(join(appRoot, "browser-engine/manifest.json")),
    readdir(runtimeRoot),
    firstPartyBrowserSources(),
  ]);

  assert.equal(runtimeManifest.schema_version, "heel.browser-runtime-manifest.v1");
  assert.equal(runtimeManifest.pyodide.version, "314.0.3");
  assert.deepEqual(runtimeManifest.heel, committedManifest);
  assert.deepEqual(builtEngineManifest, committedManifest);
  const expectedRuntimeFiles = [
    ...Object.keys(runtimeManifest.pyodide.assets),
    ...Object.values(runtimeManifest.notices).map((notice) => notice.filename),
    "heel-browser-manifest.json",
    "runtime-manifest.json",
    committedManifest.wheel.filename,
  ].sort();
  assert.deepEqual(runtimeFiles.sort(), expectedRuntimeFiles);

  for (const [name, expected] of Object.entries(runtimeManifest.pyodide.assets)) {
    const payload = await readFile(join(runtimeRoot, name));
    assert.equal(payload.byteLength, expected.size, `${name} size`);
    assert.equal(sha256(payload), expected.sha256, `${name} digest`);
  }
  for (const expected of Object.values(runtimeManifest.notices)) {
    const payload = await readFile(join(runtimeRoot, expected.filename));
    assert.equal(payload.byteLength, expected.size, `${expected.filename} size`);
    assert.equal(sha256(payload), expected.sha256, `${expected.filename} digest`);
  }
  const builtWheel = await readFile(join(runtimeRoot, wheelName));
  const committedWheel = await readFile(join(appRoot, "browser-engine", wheelName));
  assert.deepEqual(builtWheel, committedWheel);
  assert.equal(builtWheel.byteLength, committedManifest.wheel.size);
  assert.equal(sha256(builtWheel), committedManifest.wheel.sha256);

  assert.match(firstParty.worker, /\/heel-runtime\/runtime-manifest\.json/);
  assert.ok(firstParty.worker.includes(wheelName));
  assert.match(firstParty.worker, /\/heel-runtime\/pyodide\.mjs/);
  assert.match(firstParty.worker, /credentials:\s*[`"']same-origin[`"']/);
  assert.match(firstParty.worker, /redirect:\s*[`"']error[`"']/);
  assert.match(firstParty.worker, /\.origin\s*!==\s*[^;]+\.location\.origin/);
  assert.doesNotMatch(
    firstParty.source,
    /https?:\/\/(?:cdn\.jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare\.com|esm\.sh|pypi\.org|files\.pythonhosted\.org)/i,
  );
});


test("production executables exclude remote review, telemetry, native control-plane, maps, env, and credentials", async () => {
  const [artifactFiles, firstParty, builtWheel, serverEntry, serverExternals] = await Promise.all([
    filesUnder(distRoot),
    firstPartyBrowserSources(),
    readFile(join(runtimeRoot, wheelName)),
    readFile(join(serverRoot, "index.js"), "utf8"),
    json(join(serverRoot, "vinext-externals.json")),
  ]);
  const relativeFiles = artifactFiles.map((path) => relative(distRoot, path).replaceAll("\\", "/"));

  for (const path of artifactFiles) {
    const status = await lstat(path);
    assert.equal(status.isSymbolicLink(), false, `${relative(distRoot, path)} is a symlink`);
  }
  assert.equal(relativeFiles.some((path) => extname(path) === ".map"), false, "source map shipped");
  assert.equal(
    relativeFiles.some((path) => /(?:^|\/)\.env(?:\.|$)|\.(?:pem|key|p12|pfx)$/i.test(path)),
    false,
    "environment or credential file shipped",
  );
  assert.equal(
    relativeFiles.some((path) => /(?:^|\/)(?:tests?|fixtures?)(?:\/|$)/i.test(path)),
    false,
    "test or fixture tree shipped",
  );

  assert.deepEqual(serverExternals, [], "production worker has an unexpected external package");
  assert.doesNotMatch(
    `${firstParty.source}\n${serverEntry}`,
    /["'`]\/(?:api\/)?reviews?(?:\/|[?"'`])/i,
  );
  assert.doesNotMatch(
    firstParty.source,
    /(?:@sentry|sentry\.init|posthog|datadog|newrelic|rollbar|bugsnag|segment\.io|mixpanel|amplitude)/i,
  );
  assert.doesNotMatch(firstParty.source, /micropip\.(?:install|list)|pypi\.org|files\.pythonhosted\.org/i);

  const wheelText = builtWheel.toString("utf8");
  const executableText = `${firstParty.source}\n${serverEntry}\n${wheelText}`;
  const formerBrand = "arc" + "eo";
  assert.equal(executableText.toLowerCase().includes(formerBrand), false);
  for (const forbidden of [
    "heel.saas",
    "heel/mcp_server.py",
    "heel/rest.py",
    "heel/runner.py",
    "from .mcp_server",
    "from .rest",
    "from .runner",
  ]) assert.equal(wheelText.includes(forbidden), false, `${forbidden} shipped in browser wheel`);

  for (const credential of [
    /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
    /\bAKIA[0-9A-Z]{16}\b/,
    /\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b/,
    /\bgh[pousr]_[A-Za-z0-9]{20,}\b/,
    /\bxox[baprs]-[A-Za-z0-9-]{12,}\b/,
    /\bBearer\s+eyJ[A-Za-z0-9_-]{12,}\./,
  ]) assert.doesNotMatch(executableText, credential);
});


test("production worker exposes strict headers, host-derived social metadata, and no persistence bindings", async () => {
  const [workerConfig, hostingConfig, socialCard] = await Promise.all([
    json(join(serverRoot, "wrangler.json")),
    json(join(distRoot, ".openai/hosting.json")),
    readFile(join(clientRoot, "og.png")),
  ]);
  assert.deepEqual(hostingConfig, { d1: null, r2: null });
  assert.deepEqual(workerConfig.vars, {});
  for (const field of [
    "d1_databases",
    "r2_buckets",
    "kv_namespaces",
    "durable_objects",
    "queues",
    "services",
    "analytics_engine_datasets",
    "hyperdrive",
    "workflows",
    "secrets_store_secrets",
    "vectorize",
  ]) {
    const value = workerConfig[field];
    if (field === "durable_objects" || field === "queues") {
      assert.ok(value && Object.values(value).every((entries) => Array.isArray(entries) && entries.length === 0), field);
    } else {
      assert.deepEqual(value, [], field);
    }
  }

  assert.equal(socialCard.subarray(0, 8).toString("hex"), "89504e470d0a1a0a");
  assert.equal(socialCard.readUInt32BE(16), 1200);
  assert.equal(socialCard.readUInt32BE(20), 630);

  const artifact = await import(pathToFileURL(join(serverRoot, "index.js")).href + `?artifact=${Date.now()}`);
  const environment = {
    ASSETS: { fetch: async () => new Response("not found", { status: 404 }) },
    IMAGES: { input: () => { throw new Error("image transform is not used for the page"); } },
  };
  const context = { waitUntil() {}, passThroughOnException() {} };
  const response = await artifact.default.fetch(
    new Request("https://edge.heel.invalid/", {
      headers: {
        host: "edge.heel.invalid",
        "x-forwarded-host": "attacker.invalid",
        "x-forwarded-proto": "https",
      },
    }),
    environment,
    context,
  );
  assert.equal(response.status, 200);
  const csp = response.headers.get("content-security-policy");
  assert.ok(csp);
  for (const directive of [
    "default-src 'self'",
    "base-uri 'none'",
    "connect-src 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "object-src 'none'",
    "worker-src 'self'",
  ]) assert.ok(csp.includes(directive), directive);
  assert.match(csp, /script-src 'self' 'nonce-[0-9a-f]{32}' 'strict-dynamic' 'wasm-unsafe-eval'/);
  assert.equal(response.headers.get("cross-origin-opener-policy"), "same-origin");
  assert.equal(response.headers.get("cross-origin-resource-policy"), "same-origin");
  assert.equal(response.headers.get("referrer-policy"), "no-referrer");
  assert.equal(response.headers.get("strict-transport-security"), "max-age=31536000; includeSubDomains");
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  assert.equal(response.headers.get("x-frame-options"), "DENY");
  assert.match(response.headers.get("permissions-policy"), /camera=\(\)/);
  assert.match(response.headers.get("permissions-policy"), /payment=\(\)/);

  const html = await response.text();
  assert.match(html, /<meta property="og:image" content="https:\/\/edge\.heel\.invalid\/og\.png"\/>/);
  assert.match(html, /<meta property="og:image:width" content="1200"\/>/);
  assert.match(html, /<meta property="og:image:height" content="630"\/>/);
  assert.match(html, /<meta name="twitter:image" content="https:\/\/edge\.heel\.invalid\/og\.png"\/>/);
  assert.doesNotMatch(html, /https:\/\/attacker\.invalid\/og\.png/);

  const fallbackResponse = await artifact.default.fetch(
    new Request("https://fallback-origin.invalid/", {
      headers: {
        "x-forwarded-host": "fallback.heel.example",
        "x-forwarded-proto": "https",
      },
    }),
    environment,
    context,
  );
  assert.equal(fallbackResponse.status, 200);
  assert.match(
    await fallbackResponse.text(),
    /<meta property="og:image" content="https:\/\/fallback\.heel\.example\/og\.png"\/>/,
  );
});
