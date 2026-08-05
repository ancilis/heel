// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { cp, lstat, mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { extname, join, relative } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";
import { deflateRawSync, gunzipSync, gzipSync, inflateRawSync } from "node:zlib";

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


function crc32(payload) {
  let crc = 0xffffffff;
  for (const byte of payload) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) {
      crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}


function syntheticZip(records) {
  const localRecords = [];
  const centralRecords = [];
  let localOffset = 0;
  for (const record of records) {
    const name = Buffer.from(record.name, "utf8");
    const payload = record.payload ?? Buffer.alloc(0);
    const compression = record.compression ?? 8;
    const compressed = compression === 0 ? payload : deflateRawSync(payload);
    const checksum = crc32(payload);
    const declaredSize = record.declaredSize ?? payload.byteLength;
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 6);
    local.writeUInt16LE(compression, 8);
    local.writeUInt32LE(checksum, 14);
    local.writeUInt32LE(compressed.byteLength, 18);
    local.writeUInt32LE(declaredSize, 22);
    local.writeUInt16LE(name.byteLength, 26);
    localRecords.push(local, name, compressed);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE((3 << 8) | 20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0, 8);
    central.writeUInt16LE(compression, 10);
    central.writeUInt32LE(checksum, 16);
    central.writeUInt32LE(compressed.byteLength, 20);
    central.writeUInt32LE(declaredSize, 24);
    central.writeUInt16LE(name.byteLength, 28);
    central.writeUInt32LE(((record.mode ?? 0o100644) << 16) >>> 0, 38);
    central.writeUInt32LE(localOffset, 42);
    centralRecords.push(central, name);
    localOffset += local.byteLength + name.byteLength + compressed.byteLength;
  }
  const localPayload = Buffer.concat(localRecords);
  const centralPayload = Buffer.concat(centralRecords);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(records.length, 8);
  end.writeUInt16LE(records.length, 10);
  end.writeUInt32LE(centralPayload.byteLength, 12);
  end.writeUInt32LE(localPayload.byteLength, 16);
  return Buffer.concat([localPayload, centralPayload, end]);
}


function writeTarOctal(header, offset, length, value) {
  const encoded = value.toString(8).padStart(length - 1, "0") + "\0";
  header.write(encoded, offset, length, "ascii");
}


function syntheticTar(records) {
  const chunks = [];
  for (const record of records) {
    const payload = record.payload ?? Buffer.alloc(0);
    const header = Buffer.alloc(512);
    header.write(record.name, 0, 100, "utf8");
    writeTarOctal(header, 100, 8, 0o644);
    writeTarOctal(header, 108, 8, 0);
    writeTarOctal(header, 116, 8, 0);
    writeTarOctal(header, 124, 12, payload.byteLength);
    writeTarOctal(header, 136, 12, 0);
    header.fill(0x20, 148, 156);
    header[156] = (record.type ?? "0").charCodeAt(0);
    header.write("ustar\0", 257, 6, "ascii");
    header.write("00", 263, 2, "ascii");
    const checksum = header.reduce((total, byte) => total + byte, 0);
    header.write(checksum.toString(8).padStart(6, "0"), 148, 6, "ascii");
    header[154] = 0;
    header[155] = 0x20;
    chunks.push(header, payload, Buffer.alloc((512 - (payload.byteLength % 512)) % 512));
  }
  return gzipSync(Buffer.concat([...chunks, Buffer.alloc(1024)]), { mtime: 0 });
}


function findZipEndRecord(archive) {
  for (let offset = archive.byteLength - 22; offset >= 0; offset -= 1) {
    if (archive.readUInt32LE(offset) === 0x06054b50) return offset;
  }
  assert.fail("ZIP end record is absent");
}


function zipCentralEntries(archive) {
  const endOffset = findZipEndRecord(archive);
  const count = archive.readUInt16LE(endOffset + 10);
  const centralOffset = archive.readUInt32LE(endOffset + 16);
  const entries = [];
  let cursor = centralOffset;
  for (let index = 0; index < count; index += 1) {
    const nameLength = archive.readUInt16LE(cursor + 28);
    const extraLength = archive.readUInt16LE(cursor + 30);
    const commentLength = archive.readUInt16LE(cursor + 32);
    entries.push({
      centralOffset: cursor,
      localOffset: archive.readUInt32LE(cursor + 42),
    });
    cursor += 46 + nameLength + extraLength + commentLength;
  }
  return { centralOffset, endOffset, entries };
}


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
      const commentLength = archive.readUInt16LE(offset + 20);
      if (offset + minimumEndRecord + commentLength === archive.byteLength) {
        endRecord = offset;
        break;
      }
    }
  }
  assert.notEqual(endRecord, -1, `${label} has no structurally final ZIP end record or has trailing data`);
  assert.equal(archive.readUInt16LE(endRecord + 20), 0, `${label} must not contain an end-record comment`);
  assert.equal(archive.readUInt16LE(endRecord + 4), 0, `${label} is multi-disk`);
  assert.equal(archive.readUInt16LE(endRecord + 6), 0, `${label} is multi-disk`);
  const diskEntryCount = archive.readUInt16LE(endRecord + 8);
  const entryCount = archive.readUInt16LE(endRecord + 10);
  const centralSize = archive.readUInt32LE(endRecord + 12);
  const centralOffset = archive.readUInt32LE(endRecord + 16);
  assert.notEqual(diskEntryCount, 0xffff, `${label} uses unsupported ZIP64 metadata`);
  assert.notEqual(entryCount, 0xffff, `${label} uses unsupported ZIP64 metadata`);
  assert.notEqual(centralSize, 0xffffffff, `${label} uses unsupported ZIP64 metadata`);
  assert.notEqual(centralOffset, 0xffffffff, `${label} uses unsupported ZIP64 metadata`);
  assert.equal(diskEntryCount, entryCount, `${label} entry counts disagree`);
  assert.ok(entryCount > 0 && entryCount <= maxReleaseMembers, `${label} has an invalid member count`);
  assert.ok(centralOffset <= endRecord && centralSize <= endRecord - centralOffset, `${label} central directory is out of bounds`);
  const centralEnd = centralOffset + centralSize;
  assert.equal(centralEnd, endRecord, `${label} central directory does not end at its end record`);
  let cursor = centralOffset;
  const members = new Map();
  const seenNames = new Set();
  const localSpans = [];
  let expandedBytes = 0;

  for (let index = 0; index < entryCount; index += 1) {
    assert.ok(cursor <= centralEnd - 46, `${label} central directory entry ${index} is out of bounds`);
    assert.equal(archive.readUInt32LE(cursor), 0x02014b50, `${label} central entry ${index}`);
    const creatorSystem = archive.readUInt16LE(cursor + 4) >> 8;
    const flags = archive.readUInt16LE(cursor + 8);
    const compression = archive.readUInt16LE(cursor + 10);
    const checksum = archive.readUInt32LE(cursor + 16);
    const compressedSize = archive.readUInt32LE(cursor + 20);
    const uncompressedSize = archive.readUInt32LE(cursor + 24);
    const nameLength = archive.readUInt16LE(cursor + 28);
    const extraLength = archive.readUInt16LE(cursor + 30);
    const commentLength = archive.readUInt16LE(cursor + 32);
    const externalAttributes = archive.readUInt32LE(cursor + 38);
    const localOffset = archive.readUInt32LE(cursor + 42);
    const centralEntryEnd = cursor + 46 + nameLength + extraLength + commentLength;
    assert.ok(centralEntryEnd <= centralEnd, `${label} central entry ${index} is out of bounds`);
    const name = decodeUtf8(archive.subarray(cursor + 46, cursor + 46 + nameLength), `${label} member ${index}`);
    assert.equal(flags & 1, 0, `${name} is encrypted`);
    assert.equal(flags & 0x0008, 0, `${name} uses an unsupported data descriptor`);
    assert.equal(name.endsWith("/"), false, `${name} is a directory, not a regular file`);
    assertSafeArchivePath(name, `${label}:${name}`);
    assert.equal(seenNames.has(name), false, `${name} is duplicated`);
    seenNames.add(name);
    if (creatorSystem === 3) {
      const fileType = (externalAttributes >>> 16) & 0o170000;
      assert.notEqual(fileType, 0o120000, `${name} is a symbolic link`);
      assert.ok(fileType === 0 || fileType === 0o100000, `${name} is not a regular file`);
    }
    assert.ok(uncompressedSize <= maxReleaseMemberBytes, `${name} exceeds the member size limit`);
    expandedBytes += uncompressedSize;
    assert.ok(expandedBytes <= maxReleaseExpandedBytes, `${label} exceeds the expanded size limit`);
    assert.ok(localOffset <= centralOffset - 30, `${name} local header is out of bounds`);
    assert.equal(archive.readUInt32LE(localOffset), 0x04034b50, `${name} local header`);
    const localFlags = archive.readUInt16LE(localOffset + 6);
    const localCompression = archive.readUInt16LE(localOffset + 8);
    const localChecksum = archive.readUInt32LE(localOffset + 14);
    const localCompressedSize = archive.readUInt32LE(localOffset + 18);
    const localUncompressedSize = archive.readUInt32LE(localOffset + 22);
    const localNameLength = archive.readUInt16LE(localOffset + 26);
    const localExtraLength = archive.readUInt16LE(localOffset + 28);
    const localHeaderEnd = localOffset + 30 + localNameLength + localExtraLength;
    assert.ok(localHeaderEnd <= centralOffset, `${name} local header is out of bounds`);
    const localName = decodeUtf8(
      archive.subarray(localOffset + 30, localOffset + 30 + localNameLength),
      `${label}:${name} local name`,
    );
    assert.equal(localFlags, flags, `${name} local and central flags disagree`);
    assert.equal(localCompression, compression, `${name} local and central compression disagree`);
    assert.equal(localChecksum, checksum, `${name} local and central CRC disagree`);
    assert.equal(localCompressedSize, compressedSize, `${name} local and central compressed sizes disagree`);
    assert.equal(localUncompressedSize, uncompressedSize, `${name} local and central uncompressed sizes disagree`);
    assert.equal(localName, name, `${name} local and central names disagree`);
    const dataOffset = localOffset + 30 + localNameLength + localExtraLength;
    assert.ok(compressedSize <= centralOffset - dataOffset, `${name} compressed data is out of bounds`);
    const compressed = archive.subarray(dataOffset, dataOffset + compressedSize);
    localSpans.push({ end: dataOffset + compressedSize, name, start: localOffset });
    let payload;
    if (compression === 0) payload = compressed;
    else if (compression === 8) {
      try {
        payload = inflateRawSync(compressed, { maxOutputLength: Math.max(1, uncompressedSize) });
      } catch {
        assert.fail(`${name} exceeded its bounded decompression or member size limit`);
      }
    } else assert.fail(`${name} uses unsupported ZIP compression ${compression}`);
    assert.equal(payload.byteLength, uncompressedSize, `${name} uncompressed size`);
    assert.equal(crc32(payload), checksum, `${name} CRC mismatch`);
    members.set(name, payload);
    cursor = centralEntryEnd;
  }
  assert.equal(cursor, centralEnd, `${label} central directory has hidden entries or disagrees with its entry count`);
  assert.equal(members.size, entryCount, `${label} did not consume every central entry`);
  localSpans.sort((left, right) => left.start - right.start);
  let coveredUntil = 0;
  for (const span of localSpans) {
    assert.equal(
      span.start,
      coveredUntil,
      span.start < coveredUntil
        ? `${label}:${span.name} overlaps another local record`
        : `${label}:${span.name} leaves an unreferenced prefix or gap`,
    );
    coveredUntil = span.end;
  }
  assert.equal(coveredUntil, centralOffset, `${label} leaves an unreferenced gap before its central directory`);
  return members;
}


function parseTarNumber(field, label) {
  const text = field.toString("ascii").replace(/\0.*$/s, "").trim();
  assert.match(text, /^[0-7]+$/, `${label} is not an octal TAR number`);
  return Number.parseInt(text, 8);
}


function tarMembers(archive, label = "source archive") {
  assert.ok(archive.byteLength <= maxReleaseArchiveBytes, `${label} exceeds the archive size limit`);
  const maximumTarBytes = maxReleaseExpandedBytes + maxReleaseMembers * 1023 + 1024;
  const payload = gunzipSync(archive, { maxOutputLength: maximumTarBytes });
  assert.equal(payload.byteLength % 512, 0, `${label} has a partial TAR block`);
  const members = [];
  const names = new Set();
  let cursor = 0;
  let expandedBytes = 0;
  let terminated = false;
  while (cursor + 512 <= payload.byteLength) {
    const header = payload.subarray(cursor, cursor + 512);
    if (header.every((byte) => byte === 0)) {
      const terminator = payload.subarray(cursor, cursor + 1024);
      assert.equal(terminator.byteLength, 1024, `${label} termination requires two zero blocks`);
      assert.equal(terminator.every((byte) => byte === 0), true, `${label} termination contains trailing data`);
      assert.equal(cursor + 1024, payload.byteLength, `${label} has trailing data after its canonical termination`);
      terminated = true;
      break;
    }
    assert.ok(members.length < maxReleaseMembers, `${label} exceeds the member count limit`);
    assert.equal(header.subarray(257, 263).toString("ascii"), "ustar\0", `${label} member is not USTAR`);
    const expectedChecksum = parseTarNumber(header.subarray(148, 156), `${label} member checksum`);
    let actualChecksum = 0;
    for (let index = 0; index < header.byteLength; index += 1) {
      actualChecksum += index >= 148 && index < 156 ? 0x20 : header[index];
    }
    assert.equal(actualChecksum, expectedChecksum, `${label} member checksum mismatch`);
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
    const paddedEnd = start + Math.ceil(size / 512) * 512;
    assert.ok(paddedEnd <= payload.byteLength, `${fullName} padding is truncated`);
    assert.equal(payload.subarray(end, paddedEnd).every((byte) => byte === 0), true, `${fullName} has nonzero padding`);
    members.push({ name: fullName, payload: payload.subarray(start, end), type });
    cursor = paddedEnd;
  }
  assert.equal(terminated, true, `${label} has no canonical two-zero-block termination`);
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


test("ZIP scanner rejects malformed end records, hidden entries, metadata disagreement, and bombs", async () => {
  const wheel = await readFile(join(appRoot, "public/downloads", agentWheelName));
  const endOffset = findZipEndRecord(wheel);
  const centralOffset = wheel.readUInt32LE(endOffset + 16);
  const firstNameLength = wheel.readUInt16LE(centralOffset + 28);
  const firstExtraLength = wheel.readUInt16LE(centralOffset + 30);
  const firstCommentLength = wheel.readUInt16LE(centralOffset + 32);
  const firstCentralLength = 46 + firstNameLength + firstExtraLength + firstCommentLength;
  const firstLocalOffset = wheel.readUInt32LE(centralOffset + 42);

  const trailing = Buffer.concat([wheel, Buffer.from("trailing")]);
  assert.throws(() => zipMembers(trailing, "trailing wheel"), /end record|trailing/i);

  const badComment = Buffer.from(wheel);
  badComment.writeUInt16LE(1, endOffset + 20);
  assert.throws(() => zipMembers(badComment, "bad-comment wheel"), /comment|end record/i);

  const badCentralSize = Buffer.from(wheel);
  badCentralSize.writeUInt32LE(wheel.readUInt32LE(endOffset + 12) + 1, endOffset + 12);
  assert.throws(() => zipMembers(badCentralSize, "bad-central-size wheel"), /central directory/i);

  const zip64Sentinel = Buffer.from(wheel);
  zip64Sentinel.writeUInt32LE(0xffffffff, endOffset + 12);
  assert.throws(() => zipMembers(zip64Sentinel, "ZIP64 wheel"), /ZIP64/i);

  const hiddenEntry = wheel.subarray(centralOffset, centralOffset + firstCentralLength);
  const hiddenCentral = Buffer.concat([wheel.subarray(0, endOffset), hiddenEntry, wheel.subarray(endOffset)]);
  const hiddenEnd = endOffset + hiddenEntry.byteLength;
  hiddenCentral.writeUInt32LE(wheel.readUInt32LE(endOffset + 12) + hiddenEntry.byteLength, hiddenEnd + 12);
  assert.throws(() => zipMembers(hiddenCentral, "hidden-central-entry wheel"), /central directory|entry count/i);

  const localMethodMismatch = Buffer.from(wheel);
  localMethodMismatch.writeUInt16LE(wheel.readUInt16LE(centralOffset + 10) === 8 ? 0 : 8, firstLocalOffset + 8);
  assert.throws(() => zipMembers(localMethodMismatch, "local-method wheel"), /compression|local header/i);

  const badCrc = Buffer.from(wheel);
  badCrc.writeUInt32LE(0, centralOffset + 16);
  badCrc.writeUInt32LE(0, firstLocalOffset + 14);
  assert.throws(() => zipMembers(badCrc, "bad-CRC wheel"), /CRC/i);

  const outOfBounds = Buffer.from(wheel);
  outOfBounds.writeUInt32LE(outOfBounds.byteLength + 1, endOffset + 16);
  assert.throws(() => zipMembers(outOfBounds, "out-of-bounds wheel"), /bounds|central directory/i);

  const directory = syntheticZip([
    { name: "heel/model.py", payload: Buffer.from("VALUE = 1\n") },
    { name: "heel/private/", mode: 0o040755, payload: Buffer.alloc(0), compression: 0 },
  ]);
  assert.throws(() => zipMembers(directory, "directory wheel"), /regular file|directory/i);

  const bomb = syntheticZip([{
    name: "heel/bomb.py",
    payload: Buffer.alloc(maxReleaseMemberBytes + 1),
    declaredSize: 1,
  }]);
  assert.throws(() => zipMembers(bomb, "compressed bomb wheel"), /member size limit|decompression/i);
});


test("ZIP scanner rejects comments and every unreferenced byte before the central directory", async () => {
  const wheel = await readFile(join(appRoot, "public/downloads", agentWheelName));
  const original = zipCentralEntries(wheel);

  const comment = Buffer.from("private-comment");
  const commented = Buffer.concat([wheel, comment]);
  commented.writeUInt16LE(comment.byteLength, original.endOffset + 20);
  assert.throws(() => zipMembers(commented, "commented wheel"), /comment/i);

  const prefix = Buffer.from("private-prefix");
  const prefixed = Buffer.concat([prefix, wheel]);
  const prefixedEnd = original.endOffset + prefix.byteLength;
  prefixed.writeUInt32LE(original.centralOffset + prefix.byteLength, prefixedEnd + 16);
  for (const entry of original.entries) {
    prefixed.writeUInt32LE(
      entry.localOffset + prefix.byteLength,
      entry.centralOffset + prefix.byteLength + 42,
    );
  }
  assert.throws(() => zipMembers(prefixed, "prefixed wheel"), /prefix|gap|unreferenced/i);

  const gap = Buffer.from("private-gap");
  const gapped = Buffer.concat([
    wheel.subarray(0, original.centralOffset),
    gap,
    wheel.subarray(original.centralOffset),
  ]);
  const gappedEnd = original.endOffset + gap.byteLength;
  gapped.writeUInt32LE(original.centralOffset + gap.byteLength, gappedEnd + 16);
  assert.throws(() => zipMembers(gapped, "gapped wheel"), /gap|unreferenced/i);
});


test("TAR scanner rejects corrupt checksums, padding, termination, and private members", () => {
  const valid = syntheticTar([{ name: "heel_sim-1.1.0/heel/model.py", payload: Buffer.from("VALUE = 1\n") }]);
  const raw = gunzipSync(valid);

  const badChecksum = Buffer.from(raw);
  badChecksum[0] ^= 1;
  assert.throws(() => tarMembers(gzipSync(badChecksum), "bad-checksum source"), /checksum/i);

  const size = Number.parseInt(raw.subarray(124, 136).toString("ascii").replace(/\0.*$/s, "").trim(), 8);
  const badPadding = Buffer.from(raw);
  badPadding[512 + size] = 1;
  assert.throws(() => tarMembers(gzipSync(badPadding), "bad-padding source"), /padding/i);

  const firstEndBlock = 512 + Math.ceil(size / 512) * 512;
  const singleEndBlock = gzipSync(raw.subarray(0, firstEndBlock + 512));
  assert.throws(() => tarMembers(singleEndBlock, "single-end-block source"), /two zero blocks|termination/i);

  const trailingPayload = Buffer.from(raw);
  trailingPayload[trailingPayload.byteLength - 1] = 1;
  assert.throws(() => tarMembers(gzipSync(trailingPayload), "trailing-data source"), /trailing|termination/i);

  const privateSource = syntheticTar([
    { name: "heel_sim-1.1.0/heel/model.py", payload: Buffer.from("VALUE = 1\n") },
    { name: "heel_sim-1.1.0/docs/saas/PRODUCT.md", payload: Buffer.from("private\n") },
  ]);
  assert.throws(
    () => classifyReleaseMembers(tarMembers(privateSource), {
      label: "mutated source",
      rootPrefix: "heel_sim-1.1.0/",
    }),
    /commercial boundary/,
  );
});


test("TAR decompression budget includes bounded headers and padding", () => {
  const records = Array.from({ length: 6 }, (_, index) => ({
    name: `heel_sim-1.1.0/heel/payload_${index}.py`,
    payload: Buffer.alloc(maxReleaseMemberBytes),
  }));
  assert.equal(tarMembers(syntheticTar(records), "limit source").length, records.length);
});


test("ZIP member classification rejects an actual private-member archive", () => {
  const privateWheel = syntheticZip([
    { name: "heel/model.py", payload: Buffer.from("VALUE = 1\n") },
    { name: "heel/saas/auth.py", payload: Buffer.from("private = True\n") },
  ]);
  const records = [...zipMembers(privateWheel, "mutated wheel")]
    .map(([name, payload]) => ({ name, payload, type: "0" }));
  assert.throws(() => classifyReleaseMembers(records, { label: "mutated wheel" }), /commercial boundary/);
});


test("release reads are descriptor-bound and no-follow", async () => {
  const source = await readFile(join(appRoot, "scripts/prepare-runtime.mjs"), "utf8");
  assert.match(source, /O_NOFOLLOW/);
  assert.match(source, /handle\.stat\(/);
  assert.match(source, /handle\.read\(/);
});


test("ships exactly the classified, digest-pinned Heel Agent downloads", async () => {
  const names = (await readdir(downloadsRoot)).sort();
  assert.deepEqual(names, expectedDownloadNames);

  const manifestPayload = await readFile(join(downloadsRoot, agentManifestName));
  const manifest = JSON.parse(decodeUtf8(manifestPayload, `downloads/${agentManifestName}`));
  assert.deepEqual(Object.keys(manifest).sort(), ["artifacts", "schema_version", "version"]);
  assert.equal(manifest.schema_version, "heel.open-core-artifacts.v1");
  assert.equal(manifest.version, "1.1.0");
  assert.deepEqual(manifest.artifacts.map(({ name }) => name), [agentWheelName, agentSourceName]);
  await validateReleaseDownloads(downloadsRoot);

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
  const reversedRoot = await mkdtemp(join(appRoot, ".heel-reversed-downloads-"));
  context.after(async () => {
    await Promise.all([validRoot, unexpectedRoot, corruptRoot, symlinkRoot, reversedRoot]
      .map((root) => rm(root, { recursive: true, force: true })));
  });
  await Promise.all([validRoot, unexpectedRoot, corruptRoot, symlinkRoot, reversedRoot]
    .map((root) => cp(sourceRoot, root, { recursive: true })));

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

  const reversedManifest = JSON.parse(await readFile(join(reversedRoot, agentManifestName), "utf8"));
  reversedManifest.artifacts.reverse();
  await writeFile(join(reversedRoot, agentManifestName), JSON.stringify(reversedManifest) + "\n");
  await assert.rejects(validateReleaseDownloads(reversedRoot), /order|exact artifacts/);
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
