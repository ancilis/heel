// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { lstat, readFile, readdir } from "node:fs/promises";
import { extname, join, relative } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";
import { inflateRawSync } from "node:zlib";


const appRoot = fileURLToPath(new URL("../", import.meta.url));
const distRoot = join(appRoot, "dist");
const clientRoot = join(distRoot, "client");
const runtimeRoot = join(clientRoot, "heel-runtime");
const serverRoot = join(distRoot, "server");
const wheelName = "heel_browser-1.1.0-py3-none-any.whl";
const internalOriginHeader = "x-heel-internal-origin";
const scannedTextExtensions = new Set([".css", ".html", ".js", ".json", ".mjs", ".txt"]);
const executableExtensions = new Set([".js", ".mjs"]);
const generatedPrerenderFiles = [
  "server/ssr/vinext-server.json",
  "server/vinext-server.json",
];


function sha256(payload) {
  return createHash("sha256").update(payload).digest("hex");
}


async function filesUnder(root, label = relative(distRoot, root) || "deployment root") {
  const rootStatus = await lstat(root);
  assert.equal(rootStatus.isSymbolicLink(), false, `${label} is a symlink`);
  assert.equal(rootStatus.isDirectory(), true, `${label} is not a directory`);
  const files = [];
  async function visit(directory) {
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      const status = await lstat(path);
      const artifactPath = relative(distRoot, path).replaceAll("\\", "/");
      assert.equal(status.isSymbolicLink(), false, `${artifactPath} is a symlink`);
      if (status.isDirectory()) await visit(path);
      else {
        assert.equal(status.isFile(), true, `${artifactPath} is not a regular file`);
        files.push(path);
      }
    }
  }
  await visit(root);
  return files.sort();
}


async function json(path) {
  return JSON.parse(await readFile(path, "utf8"));
}


function decodeUtf8(payload, label) {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(payload);
  } catch {
    assert.fail(`${label} is not valid UTF-8`);
  }
}


function zipMembers(archive) {
  const minimumEndRecord = 22;
  let endRecord = -1;
  for (let offset = archive.byteLength - minimumEndRecord; offset >= 0; offset -= 1) {
    if (archive.readUInt32LE(offset) === 0x06054b50) {
      endRecord = offset;
      break;
    }
  }
  assert.notEqual(endRecord, -1, "wheel has no ZIP end record");
  assert.equal(archive.readUInt16LE(endRecord + 4), 0, "multi-disk wheel");
  assert.equal(archive.readUInt16LE(endRecord + 6), 0, "multi-disk wheel");
  const entryCount = archive.readUInt16LE(endRecord + 10);
  let cursor = archive.readUInt32LE(endRecord + 16);
  const members = new Map();

  for (let index = 0; index < entryCount; index += 1) {
    assert.equal(archive.readUInt32LE(cursor), 0x02014b50, `wheel central entry ${index}`);
    const flags = archive.readUInt16LE(cursor + 8);
    const compression = archive.readUInt16LE(cursor + 10);
    const compressedSize = archive.readUInt32LE(cursor + 20);
    const uncompressedSize = archive.readUInt32LE(cursor + 24);
    const nameLength = archive.readUInt16LE(cursor + 28);
    const extraLength = archive.readUInt16LE(cursor + 30);
    const commentLength = archive.readUInt16LE(cursor + 32);
    const localOffset = archive.readUInt32LE(cursor + 42);
    const name = decodeUtf8(archive.subarray(cursor + 46, cursor + 46 + nameLength), `wheel member ${index}`);
    assert.equal(flags & 1, 0, `${name} is encrypted`);
    assert.ok(name && !name.startsWith("/") && !name.split("/").includes(".."), `${name} is unsafe`);
    assert.equal(members.has(name), false, `${name} is duplicated`);
    assert.equal(archive.readUInt32LE(localOffset), 0x04034b50, `${name} local header`);
    const localNameLength = archive.readUInt16LE(localOffset + 26);
    const localExtraLength = archive.readUInt16LE(localOffset + 28);
    const dataOffset = localOffset + 30 + localNameLength + localExtraLength;
    const compressed = archive.subarray(dataOffset, dataOffset + compressedSize);
    const payload = compression === 0
      ? compressed
      : compression === 8
        ? inflateRawSync(compressed)
        : assert.fail(`${name} uses unsupported ZIP compression ${compression}`);
    assert.equal(payload.byteLength, uncompressedSize, `${name} uncompressed size`);
    if (!name.endsWith("/")) members.set(name, payload);
    cursor += 46 + nameLength + extraLength + commentLength;
  }
  assert.equal(members.size > 0, true, "wheel has no file members");
  return members;
}


async function deploymentInventory() {
  const files = await filesUnder(distRoot);
  const records = await Promise.all(files.map(async (path) => {
    const artifactPath = relative(distRoot, path).replaceAll("\\", "/");
    const extension = extname(path).toLowerCase();
    const payload = await readFile(path);
    return {
      artifactPath,
      extension,
      path,
      payload,
      text: scannedTextExtensions.has(extension) ? decodeUtf8(payload, artifactPath) : null,
    };
  }));
  return { files, records };
}


function assertNoCredentials(source, label) {
  for (const credential of [
    /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
    /\bAKIA[0-9A-Z]{16}\b/,
    /\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b/,
    /\bgh[pousr]_[A-Za-z0-9]{20,}\b/,
    /\bxox[baprs]-[A-Za-z0-9-]{12,}\b/,
    /\bBearer\s+eyJ[A-Za-z0-9_-]{12,}\./,
  ]) assert.doesNotMatch(source, credential, label);
}


function parseCsp(value) {
  const directives = new Map();
  for (const section of value.split(";")) {
    const tokens = section.trim().split(/\s+/).filter(Boolean);
    if (tokens.length === 0) continue;
    assert.equal(directives.has(tokens[0]), false, `duplicate CSP directive ${tokens[0]}`);
    directives.set(tokens[0], tokens.slice(1));
  }
  return directives;
}


function assertEmptyCapability(value, label) {
  if (Array.isArray(value)) {
    assert.deepEqual(value, [], `${label} bindings`);
    return;
  }
  assert.ok(value && typeof value === "object", `${label} must be an object or array`);
  for (const entries of Object.values(value)) {
    assert.ok(Array.isArray(entries), `${label} has a non-array binding collection`);
    assert.deepEqual(entries, [], `${label} bindings`);
  }
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


test("ships the transformed integrity-pinned wheel and Pyodide runtime behind same-origin paths", async () => {
  const [
    runtimeManifest,
    builtEngineManifest,
    committedManifest,
    runtimeFiles,
    firstParty,
    builtPyodide,
  ] = await Promise.all([
    json(join(runtimeRoot, "runtime-manifest.json")),
    json(join(runtimeRoot, "heel-browser-manifest.json")),
    json(join(appRoot, "browser-engine/manifest.json")),
    readdir(runtimeRoot),
    firstPartyBrowserSources(),
    readFile(join(runtimeRoot, "pyodide.mjs")),
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
  assert.equal(builtPyodide.byteLength, runtimeManifest.pyodide.assets["pyodide.mjs"].size);
  assert.equal(sha256(builtPyodide), runtimeManifest.pyodide.assets["pyodide.mjs"].sha256);
  const builtPyodideSource = decodeUtf8(builtPyodide, "heel-runtime/pyodide.mjs");
  assert.match(builtPyodideSource, /["']\/heel-runtime\/["']/);
  assert.doesNotMatch(builtPyodideSource, /cdn\.jsdelivr\.net|sourceMappingURL=/i);
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


test("recursively scans every deployed executable, text manifest, and wheel member", async () => {
  const [{ records }, builtWheel, serverExternals] = await Promise.all([
    deploymentInventory(),
    readFile(join(runtimeRoot, wheelName)),
    json(join(serverRoot, "vinext-externals.json")),
  ]);
  const relativeFiles = records.map(({ artifactPath }) => artifactPath);
  const executableRecords = records.filter(({ extension }) => executableExtensions.has(extension));
  const textRecords = records.filter(({ text }) => text !== null);
  assert.ok(executableRecords.length > 3, "deployment scan did not cover generated executables");

  assert.equal(relativeFiles.some((path) => /\.map$/i.test(path)), false, "source map shipped");
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
  const formerBrand = "arc" + "eo";
  const prerenderRecords = [];
  for (const record of textRecords) {
    const label = record.artifactPath;
    assert.doesNotMatch(record.text, /(?:\/\/[#@]|\/\*#)\s*sourceMappingURL=/i, label);
    assert.doesNotMatch(
      record.text,
      /https?:\/\/(?:cdn\.jsdelivr\.net|unpkg\.com|cdnjs\.cloudflare\.com|esm\.sh|pypi\.org|files\.pythonhosted\.org)/i,
      label,
    );
    assert.doesNotMatch(record.text, /["'`]\/(?:api\/)?reviews?(?:\/|[?"'`])/i, label);
    assert.doesNotMatch(
      record.text,
      /(?:from\s*["']@sentry\/|import\s*\(\s*["']@sentry\/|require\s*\(\s*["']@sentry\/|sentry\.init\s*\(|posthog\.(?:init|capture)\s*\(|datadogRum\.|newrelic\.start|rollbar\.init|bugsnag\.start|segment\.io\/v1|mixpanel\.init\s*\(|amplitude\.init\s*\()/i,
      label,
    );
    assert.equal(record.text.toLowerCase().includes(formerBrand), false, `${label} contains former brand`);
    assertNoCredentials(record.text, label);
    if (record.text.includes("prerenderSecret")) prerenderRecords.push(record);
  }

  assert.deepEqual(
    prerenderRecords.map(({ artifactPath }) => artifactPath).sort(),
    generatedPrerenderFiles,
    "generated prerender secret appeared outside its classified manifests",
  );
  const generatedSecrets = new Set();
  for (const record of prerenderRecords) {
    const manifest = JSON.parse(record.text);
    assert.deepEqual(Object.keys(manifest), ["prerenderSecret"], record.artifactPath);
    assert.match(manifest.prerenderSecret, /^[0-9a-f]{64}$/, record.artifactPath);
    generatedSecrets.add(manifest.prerenderSecret);
  }
  assert.equal(generatedSecrets.size, 1, "generated prerender manifests disagree");

  const members = zipMembers(builtWheel);
  const wheelSources = [];
  for (const [name, payload] of members) {
    const source = decodeUtf8(payload, `wheel:${name}`);
    wheelSources.push(source);
    assert.equal(source.toLowerCase().includes(formerBrand), false, `wheel:${name} contains former brand`);
    assertNoCredentials(source, `wheel:${name}`);
  }
  const wheelText = wheelSources.join("\n");
  for (const forbidden of [
    "heel.saas",
    "heel/mcp_server.py",
    "heel/rest.py",
    "heel/runner.py",
    "from .mcp_server",
    "from .rest",
    "from .runner",
  ]) assert.equal(wheelText.includes(forbidden), false, `${forbidden} shipped in browser wheel`);
});


test("production worker exposes exact headers, request-URL metadata, and no unapproved bindings", async () => {
  const [workerConfig, hostingConfig, socialCard] = await Promise.all([
    json(join(serverRoot, "wrangler.json")),
    json(join(distRoot, ".openai/hosting.json")),
    readFile(join(clientRoot, "og.png")),
  ]);
  assert.deepEqual(hostingConfig, { d1: null, r2: null });
  assert.deepEqual(workerConfig.vars, {});
  assert.deepEqual(workerConfig.assets, { directory: "../client" });
  assert.deepEqual(workerConfig.observability, { enabled: false });
  const requiredEmptyCapabilities = [
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
    "ai_search_namespaces",
    "ai_search",
    "artifacts",
    "worker_loaders",
    "pipelines",
    "vpc_services",
    "vpc_networks",
    "send_email",
    "mtls_certificates",
    "dispatch_namespaces",
  ];
  for (const field of requiredEmptyCapabilities) {
    assert.ok(Object.hasOwn(workerConfig, field), `${field} is absent from the deployment manifest`);
    assertEmptyCapability(workerConfig[field], field);
  }
  const approvedConfiguration = new Set([
    "topLevelName",
    "dev",
    "name",
    "compatibility_date",
    "compatibility_flags",
    "legacy_env",
    "main",
    "jsx_factory",
    "jsx_fragment",
    "rules",
    "build",
    "no_bundle",
    "assets",
    "observability",
    "python_modules",
    "vars",
  ]);
  for (const [field, value] of Object.entries(workerConfig)) {
    if (!approvedConfiguration.has(field)) assertEmptyCapability(value, field);
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
    new Request("https://request-url.heel.invalid/", {
      headers: {
        host: "host-attacker.invalid",
        "x-forwarded-host": "forwarded-attacker.invalid",
        "x-forwarded-proto": "http",
        [internalOriginHeader]: "https://internal-attacker.invalid",
      },
    }),
    environment,
    context,
  );
  assert.equal(response.status, 200);
  const csp = response.headers.get("content-security-policy");
  assert.ok(csp);
  const directives = parseCsp(csp);
  const nonce = directives.get("script-src")?.[1];
  assert.match(nonce ?? "", /^'nonce-[0-9a-f]{32}'$/);
  assert.deepEqual([...directives], [
    ["default-src", ["'self'"]],
    ["base-uri", ["'none'"]],
    ["connect-src", ["'self'"]],
    ["font-src", ["'self'"]],
    ["form-action", ["'self'"]],
    ["frame-ancestors", ["'none'"]],
    ["img-src", ["'self'", "data:"]],
    ["object-src", ["'none'"]],
    ["script-src", ["'self'", nonce, "'strict-dynamic'", "'wasm-unsafe-eval'"]],
    ["style-src", ["'self'", nonce]],
    ["worker-src", ["'self'"]],
  ]);
  assert.equal(response.headers.get("cross-origin-opener-policy"), "same-origin");
  assert.equal(response.headers.get("cross-origin-resource-policy"), "same-origin");
  assert.equal(response.headers.get("referrer-policy"), "no-referrer");
  assert.equal(response.headers.get("strict-transport-security"), "max-age=31536000; includeSubDomains");
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  assert.equal(response.headers.get("x-frame-options"), "DENY");
  assert.match(response.headers.get("permissions-policy"), /camera=\(\)/);
  assert.match(response.headers.get("permissions-policy"), /payment=\(\)/);

  const html = await response.text();
  assert.match(html, /<meta property="og:image" content="https:\/\/request-url\.heel\.invalid\/og\.png"\/>/);
  assert.match(html, /<meta property="og:image:width" content="1200"\/>/);
  assert.match(html, /<meta property="og:image:height" content="630"\/>/);
  assert.match(html, /<meta name="twitter:image" content="https:\/\/request-url\.heel\.invalid\/og\.png"\/>/);
  assert.doesNotMatch(html, /https:\/\/(?:host-|forwarded-|internal-)attacker\.invalid\/og\.png/);

  const localResponse = await artifact.default.fetch(
    new Request("http://127.0.0.1:8787/", {
      headers: {
        host: "production-attacker.invalid",
        "x-forwarded-host": "forwarded-attacker.invalid",
        "x-forwarded-proto": "https",
      },
    }),
    environment,
    context,
  );
  assert.equal(localResponse.status, 200);
  assert.match(
    await localResponse.text(),
    /<meta property="og:image" content="http:\/\/127\.0\.0\.1:8787\/og\.png"\/>/,
  );
});
