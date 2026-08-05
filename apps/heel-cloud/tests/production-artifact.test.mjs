// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { cp, lstat, mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { extname, join, relative } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";
import { gunzipSync, inflateRawSync } from "node:zlib";

import { validateReleaseDownloads } from "../scripts/prepare-runtime.mjs";


const appRoot = fileURLToPath(new URL("../", import.meta.url));
const distRoot = join(appRoot, "dist");
const clientRoot = join(distRoot, "client");
const runtimeRoot = join(clientRoot, "heel-runtime");
const downloadsRoot = join(clientRoot, "downloads");
const serverRoot = join(distRoot, "server");
const wheelName = "heel_browser-1.1.0-py3-none-any.whl";
const agentWheelName = "heel_sim-1.1.0-py3-none-any.whl";
const agentSourceName = "heel_sim-1.1.0.tar.gz";
const agentManifestName = "heel-open-core-manifest.json";
const expectedDownloadNames = [agentManifestName, agentWheelName, agentSourceName];
const internalOriginHeader = "x-heel-internal-origin";
const scannedTextExtensions = new Set([".css", ".html", ".js", ".json", ".mjs", ".txt"]);
const executableExtensions = new Set([".js", ".mjs"]);
const generatedPrerenderFiles = [
  "server/ssr/vinext-server.json",
  "server/vinext-server.json",
];
const maxReleaseArchiveBytes = 32 * 1024 * 1024;
const maxReleaseMemberBytes = 4 * 1024 * 1024;
const maxReleaseMembers = 128;
const maxReleaseExpandedBytes = 24 * 1024 * 1024;
const forbiddenReleasePrefixes = [
  "apps/",
  "deploy/",
  "docs/saas/",
  "docs/superpowers/",
  "heel/saas/",
  "tests/",
  "web/",
];
const allowedReleaseExtensions = new Set([".in", ".json", ".md", ".py", ".toml", ".txt"]);
const allowedExtensionlessNames = new Set(["DCO", "LICENSE", "METADATA", "NOTICE", "PKG-INFO", "RECORD", "WHEEL"]);


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


function assertSafeArchivePath(name, label) {
  assert.ok(name && !name.startsWith("/") && !name.includes("\\"), `${label} has an unsafe path`);
  assert.equal(name.includes("\0"), false, `${label} contains NUL`);
  const parts = name.split("/");
  assert.equal(parts.some((part) => part === "" || part === "." || part === ".."), false, `${label} traverses directories`);
}


function zipMembers(archive, label = "wheel") {
  assert.ok(archive.byteLength <= maxReleaseArchiveBytes, `${label} exceeds the archive size limit`);
  const minimumEndRecord = 22;
  let endRecord = -1;
  for (let offset = archive.byteLength - minimumEndRecord; offset >= 0; offset -= 1) {
    if (archive.readUInt32LE(offset) === 0x06054b50) {
      endRecord = offset;
      break;
    }
  }
  assert.notEqual(endRecord, -1, `${label} has no ZIP end record`);
  assert.equal(archive.readUInt16LE(endRecord + 4), 0, `${label} is multi-disk`);
  assert.equal(archive.readUInt16LE(endRecord + 6), 0, `${label} is multi-disk`);
  const entryCount = archive.readUInt16LE(endRecord + 10);
  assert.ok(entryCount > 0 && entryCount <= maxReleaseMembers, `${label} has an invalid member count`);
  let cursor = archive.readUInt32LE(endRecord + 16);
  const members = new Map();
  let expandedBytes = 0;

  for (let index = 0; index < entryCount; index += 1) {
    assert.equal(archive.readUInt32LE(cursor), 0x02014b50, `${label} central entry ${index}`);
    const creatorSystem = archive.readUInt16LE(cursor + 4) >> 8;
    const flags = archive.readUInt16LE(cursor + 8);
    const compression = archive.readUInt16LE(cursor + 10);
    const compressedSize = archive.readUInt32LE(cursor + 20);
    const uncompressedSize = archive.readUInt32LE(cursor + 24);
    const nameLength = archive.readUInt16LE(cursor + 28);
    const extraLength = archive.readUInt16LE(cursor + 30);
    const commentLength = archive.readUInt16LE(cursor + 32);
    const externalAttributes = archive.readUInt32LE(cursor + 38);
    const localOffset = archive.readUInt32LE(cursor + 42);
    const name = decodeUtf8(archive.subarray(cursor + 46, cursor + 46 + nameLength), `${label} member ${index}`);
    assert.equal(flags & 1, 0, `${name} is encrypted`);
    assertSafeArchivePath(name.replace(/\/$/, ""), `${label}:${name}`);
    assert.equal(members.has(name), false, `${name} is duplicated`);
    if (creatorSystem === 3) {
      const fileType = (externalAttributes >>> 16) & 0o170000;
      assert.notEqual(fileType, 0o120000, `${name} is a symbolic link`);
      assert.ok(fileType === 0 || fileType === 0o100000 || fileType === 0o040000, `${name} is not a regular file`);
    }
    assert.ok(uncompressedSize <= maxReleaseMemberBytes, `${name} exceeds the member size limit`);
    expandedBytes += uncompressedSize;
    assert.ok(expandedBytes <= maxReleaseExpandedBytes, `${label} exceeds the expanded size limit`);
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


function parseTarNumber(field, label) {
  const text = field.toString("ascii").replace(/\0.*$/s, "").trim();
  assert.match(text, /^[0-7]+$/, `${label} is not an octal TAR number`);
  return Number.parseInt(text, 8);
}


function tarMembers(archive, label = "source archive") {
  assert.ok(archive.byteLength <= maxReleaseArchiveBytes, `${label} exceeds the archive size limit`);
  const payload = gunzipSync(archive, { maxOutputLength: maxReleaseExpandedBytes + 1024 });
  const members = [];
  const names = new Set();
  let cursor = 0;
  let expandedBytes = 0;
  while (cursor + 512 <= payload.byteLength) {
    const header = payload.subarray(cursor, cursor + 512);
    if (header.every((byte) => byte === 0)) break;
    assert.ok(members.length < maxReleaseMembers, `${label} exceeds the member count limit`);
    assert.equal(header.subarray(257, 263).toString("ascii"), "ustar\0", `${label} member is not USTAR`);
    const name = decodeUtf8(header.subarray(0, 100), `${label} member name`).replace(/\0.*$/s, "");
    const prefix = decodeUtf8(header.subarray(345, 500), `${label} member prefix`).replace(/\0.*$/s, "");
    const fullName = prefix ? `${prefix}/${name}` : name;
    assertSafeArchivePath(fullName, `${label}:${fullName}`);
    assert.equal(names.has(fullName), false, `${fullName} is duplicated`);
    names.add(fullName);
    const type = header[156] === 0 ? "0" : String.fromCharCode(header[156]);
    assert.equal(type, "0", `${fullName} is not a regular file`);
    const size = parseTarNumber(header.subarray(124, 136), `${fullName} size`);
    assert.ok(size <= maxReleaseMemberBytes, `${fullName} exceeds the member size limit`);
    expandedBytes += size;
    assert.ok(expandedBytes <= maxReleaseExpandedBytes, `${label} exceeds the expanded size limit`);
    const start = cursor + 512;
    const end = start + size;
    assert.ok(end <= payload.byteLength, `${fullName} is truncated`);
    members.push({ name: fullName, payload: payload.subarray(start, end), type });
    cursor = start + Math.ceil(size / 512) * 512;
  }
  assert.ok(members.length > 0, `${label} has no file members`);
  return members;
}


function classifyReleaseMembers(records, { label, rootPrefix = "" }) {
  assert.ok(records.length > 0 && records.length <= maxReleaseMembers, `${label} has an invalid member count`);
  const names = new Set();
  let expandedBytes = 0;
  for (const record of records) {
    assertSafeArchivePath(record.name, `${label}:${record.name}`);
    assert.equal(names.has(record.name), false, `${label}:${record.name} is duplicated`);
    names.add(record.name);
    assert.equal(record.type ?? "0", "0", `${label}:${record.name} is not a regular file`);
    assert.ok(record.payload.byteLength <= maxReleaseMemberBytes, `${label}:${record.name} exceeds the member size limit`);
    expandedBytes += record.payload.byteLength;
    assert.ok(expandedBytes <= maxReleaseExpandedBytes, `${label} exceeds the expanded size limit`);

    assert.ok(!rootPrefix || record.name.startsWith(rootPrefix), `${label}:${record.name} escapes its release root`);
    const releasePath = rootPrefix ? record.name.slice(rootPrefix.length) : record.name;
    assertSafeArchivePath(releasePath, `${label}:${record.name}`);
    for (const prefix of forbiddenReleasePrefixes) {
      assert.equal(releasePath.startsWith(prefix), false, `${label}:${record.name} crosses the commercial boundary`);
    }
    const basename = releasePath.split("/").at(-1);
    const extension = extname(basename).toLowerCase();
    assert.ok(
      allowedReleaseExtensions.has(extension) || allowedExtensionlessNames.has(basename),
      `${label}:${record.name} has an unexpected extension`,
    );
    assert.notEqual(extension, ".map", `${label}:${record.name} is a source map`);
    const source = decodeUtf8(record.payload, `${label}:${record.name}`);
    if (releasePath === "MANIFEST.in") {
      assert.equal(source.match(/LICENSE-COMMERCIAL/g)?.length, 1, `${label}:${record.name}`);
      assert.doesNotMatch(source, /LicenseRef-Heel-Commercial/, `${label}:${record.name}`);
    } else {
      assert.doesNotMatch(source, /LicenseRef-Heel-Commercial|LICENSE-COMMERCIAL/, `${label}:${record.name}`);
    }
    assert.doesNotMatch(source, /(?:\/\/[#@]|\/\*#)\s*sourceMappingURL=/i, `${label}:${record.name}`);
    assertNoCredentials(source, `${label}:${record.name}`);
  }
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
    /\b(?:api[_-]?key|secret|token)\s*[:=]\s*["'][A-Za-z0-9+/=_-]{24,}["']/i,
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


test("ships exactly the classified, digest-pinned Heel Agent downloads", async () => {
  const names = (await readdir(downloadsRoot)).sort();
  assert.deepEqual(names, expectedDownloadNames);

  const manifestPayload = await readFile(join(downloadsRoot, agentManifestName));
  const manifest = JSON.parse(decodeUtf8(manifestPayload, `downloads/${agentManifestName}`));
  assert.deepEqual(Object.keys(manifest).sort(), ["artifacts", "schema_version", "version"]);
  assert.equal(manifest.schema_version, "heel.open-core-artifacts.v1");
  assert.equal(manifest.version, "1.1.0");
  assert.deepEqual(manifest.artifacts.map(({ name }) => name).sort(), [agentWheelName, agentSourceName]);

  const artifacts = new Map();
  for (const expected of manifest.artifacts) {
    assert.deepEqual(Object.keys(expected).sort(), ["name", "sha256", "size"]);
    assert.match(expected.sha256, /^[0-9a-f]{64}$/);
    assert.ok(Number.isSafeInteger(expected.size) && expected.size > 0 && expected.size <= maxReleaseArchiveBytes);
    const payload = await readFile(join(downloadsRoot, expected.name));
    assert.equal(payload.byteLength, expected.size, `${expected.name} size`);
    assert.equal(sha256(payload), expected.sha256, `${expected.name} digest`);
    artifacts.set(expected.name, payload);
  }

  const wheelRecords = [...zipMembers(artifacts.get(agentWheelName), "Heel Agent wheel")]
    .map(([name, payload]) => ({ name, payload, type: "0" }));
  classifyReleaseMembers(wheelRecords, { label: "Heel Agent wheel" });
  const sourceRecords = tarMembers(artifacts.get(agentSourceName), "Heel Agent source archive");
  classifyReleaseMembers(sourceRecords, {
    label: "Heel Agent source archive",
    rootPrefix: "heel_sim-1.1.0/",
  });
});


test("release member classification rejects private paths and hostile archive shapes", () => {
  const safeWheel = { name: "heel/model.py", payload: Buffer.from("VALUE = 1\n"), type: "0" };
  const safeSource = {
    name: "heel_sim-1.1.0/heel/model.py",
    payload: Buffer.from("VALUE = 1\n"),
    type: "0",
  };
  const mutations = [
    {
      label: "wheel commercial module",
      records: [safeWheel, { ...safeWheel, name: "heel/saas/auth.py" }],
      options: { label: "mutated wheel" },
      message: /commercial boundary/,
    },
    {
      label: "source private documentation",
      records: [safeSource, { ...safeSource, name: "heel_sim-1.1.0/docs/saas/PRODUCT.md" }],
      options: { label: "mutated source", rootPrefix: "heel_sim-1.1.0/" },
      message: /commercial boundary/,
    },
    {
      label: "duplicate",
      records: [safeWheel, { ...safeWheel }],
      options: { label: "mutated wheel" },
      message: /duplicated/,
    },
    {
      label: "traversal",
      records: [safeWheel, { ...safeWheel, name: "heel/../saas/auth.py" }],
      options: { label: "mutated wheel" },
      message: /traverses directories/,
    },
    {
      label: "symlink",
      records: [safeWheel, { ...safeWheel, name: "heel/link.py", type: "2" }],
      options: { label: "mutated wheel" },
      message: /not a regular file/,
    },
    {
      label: "device",
      records: [safeSource, { ...safeSource, name: "heel_sim-1.1.0/heel/device.py", type: "3" }],
      options: { label: "mutated source", rootPrefix: "heel_sim-1.1.0/" },
      message: /not a regular file/,
    },
    {
      label: "credential",
      records: [{ ...safeWheel, payload: Buffer.from("TOKEN = 'ghp_12345678901234567890'\n") }],
      options: { label: "mutated wheel" },
      message: /mutated wheel/,
    },
    {
      label: "source map directive",
      records: [{ ...safeWheel, payload: Buffer.from("//# sourceMappingURL=private.map\n") }],
      options: { label: "mutated wheel" },
      message: /mutated wheel/,
    },
    {
      label: "unexpected extension",
      records: [safeSource, { ...safeSource, name: "heel_sim-1.1.0/private.pem" }],
      options: { label: "mutated source", rootPrefix: "heel_sim-1.1.0/" },
      message: /unexpected extension/,
    },
  ];
  for (const mutation of mutations) {
    assert.throws(
      () => classifyReleaseMembers(mutation.records, mutation.options),
      mutation.message,
      mutation.label,
    );
  }
});


test("runtime preparation validates committed downloads without rewriting them", async (context) => {
  const sourceRoot = join(appRoot, "public/downloads");
  const validRoot = await mkdtemp(join(appRoot, ".heel-valid-downloads-"));
  const unexpectedRoot = await mkdtemp(join(appRoot, ".heel-unexpected-downloads-"));
  const corruptRoot = await mkdtemp(join(appRoot, ".heel-corrupt-downloads-"));
  const symlinkRoot = await mkdtemp(join(appRoot, ".heel-symlink-downloads-"));
  context.after(async () => {
    await Promise.all([validRoot, unexpectedRoot, corruptRoot, symlinkRoot].map((root) => rm(root, { recursive: true, force: true })));
  });
  await Promise.all([validRoot, unexpectedRoot, corruptRoot, symlinkRoot].map((root) => cp(sourceRoot, root, { recursive: true })));

  const before = await Promise.all(expectedDownloadNames.map((name) => readFile(join(validRoot, name))));
  await validateReleaseDownloads(validRoot);
  const after = await Promise.all(expectedDownloadNames.map((name) => readFile(join(validRoot, name))));
  assert.deepEqual(after, before, "download validation rewrote committed release bytes");

  await writeFile(join(unexpectedRoot, "private.pem"), "not a release artifact\n");
  await assert.rejects(validateReleaseDownloads(unexpectedRoot), /unexpected release download/);

  await writeFile(join(corruptRoot, agentWheelName), "corrupt\n");
  await assert.rejects(validateReleaseDownloads(corruptRoot), /size mismatch|digest mismatch/);

  await rm(join(symlinkRoot, agentSourceName));
  await symlink(join(sourceRoot, agentSourceName), join(symlinkRoot, agentSourceName));
  await assert.rejects(validateReleaseDownloads(symlinkRoot), /symbolic link/);
});


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
