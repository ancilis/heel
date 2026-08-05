// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import { createHash, randomBytes } from "node:crypto";
import { lstat, mkdir, open, readFile, readdir, rename, rm } from "node:fs/promises";
import { dirname, join, parse, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";


const scriptPath = fileURLToPath(import.meta.url);
const defaultAppRoot = resolve(dirname(scriptPath), "..");
const PYODIDE_VERSION = "314.0.3";
const PYODIDE_HOMEPAGE = "https://github.com/pyodide/pyodide";
const PYODIDE_SOURCE = "https://github.com/pyodide/pyodide/tree/ac57031be7564f864d061cb37c5c152e59f83ad4";
const CPYTHON_VERSION = "3.14.2";
const CPYTHON_SOURCE = "https://github.com/python/cpython/tree/df793163d5821791d4e7caf88885a2c11a107986";
const WHEEL_NAME = "heel_browser-1.1.0-py3-none-any.whl";
const RELEASE_WHEEL_NAME = "heel_sim-1.1.0-py3-none-any.whl";
const RELEASE_SOURCE_NAME = "heel_sim-1.1.0.tar.gz";
const RELEASE_MANIFEST_NAME = "heel-open-core-manifest.json";
const RELEASE_DOWNLOAD_NAMES = Object.freeze([
  RELEASE_MANIFEST_NAME,
  RELEASE_WHEEL_NAME,
  RELEASE_SOURCE_NAME,
]);
const MAX_RELEASE_ARCHIVE_BYTES = 32 * 1024 * 1024;
const MAX_RELEASE_MANIFEST_BYTES = 16 * 1024;
const PYODIDE_CDN_FALLBACK = "`https://cdn.jsdelivr.net/pyodide/v${U}/full/`";
const SAME_ORIGIN_PYODIDE_FALLBACK = '"/heel-runtime/"';
const PYODIDE_SOURCE_MAP_DIRECTIVE = "\n//# sourceMappingURL=pyodide.mjs.map";
const THIRD_PARTY_LICENSES = Object.freeze({
  "LICENSE.CPYTHON-PSF-2.0.txt": Object.freeze({
    size: 13804,
    sha256: "b0e25a78cffb43f4d92de8b61ccfa1f1f98ecbc22330b54b5251e7b6ba010231",
  }),
  "LICENSE.PYODIDE-MPL-2.0.txt": Object.freeze({
    size: 15648,
    sha256: "5eba353fe5076ac3432177f8ab1cf75e3afcd0584251e37c3bfead5f447d040e",
  }),
});
const PYODIDE_ASSETS = Object.freeze({
  "pyodide.asm.mjs": Object.freeze({ size: 1249447, sha256: "1a9775427ef6e8abaa7db88ece0515422d1886915ae5c9093776410c865dfd8d" }),
  "pyodide.asm.wasm": Object.freeze({ size: 9596462, sha256: "e7f8fac36f8bf11085309cbc5c829b3ec3057c18bf1d73b05a6741612d63cdbf" }),
  "pyodide-lock.json": Object.freeze({ size: 113804, sha256: "c963d22858f6bcb8f41586a2142f03905ab370c88ea22a86a2736e95fac2a8f3" }),
  "pyodide.mjs": Object.freeze({ size: 17880, sha256: "5cfc46f5dcbaf2a16f26e2363f441873eb424762609cc03db00d6a2ace4d00e5" }),
  "python_stdlib.zip": Object.freeze({ size: 2545106, sha256: "444c770dfd75a32097fc0a7d5c1413fd3140601f49c3a1f2e9af0376fcd124b4" }),
});


function sha256(payload) {
  return createHash("sha256").update(payload).digest("hex");
}


function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}


async function readRegular(path, label) {
  await assertNoSymlinkComponents(path, label);
  const status = await lstat(path);
  if (status.isSymbolicLink()) throw new Error(`${label} must not be a symbolic link`);
  if (!status.isFile()) throw new Error(`${label} must be a regular file`);
  return readFile(path);
}


async function readBoundedRegular(path, label, maximumBytes) {
  await assertNoSymlinkComponents(path, label);
  const status = await lstat(path);
  if (status.isSymbolicLink()) throw new Error(`${label} must not be a symbolic link`);
  if (!status.isFile()) throw new Error(`${label} must be a regular file`);
  if (!Number.isSafeInteger(status.size) || status.size <= 0 || status.size > maximumBytes) {
    throw new Error(`${label} has an invalid size`);
  }
  return readFile(path);
}


async function assertNoSymlinkComponents(path, label, { allowMissing = false } = {}) {
  const absolute = resolve(path);
  const root = parse(absolute).root;
  let current = root;
  for (const component of relative(root, absolute).split(sep).filter(Boolean)) {
    current = join(current, component);
    try {
      const status = await lstat(current);
      if (status.isSymbolicLink()) throw new Error(`${label} contains a symbolic link: ${current}`);
    } catch (error) {
      if (allowMissing && error?.code === "ENOENT") continue;
      throw error;
    }
  }
  return absolute;
}


async function validateDirectoryRoot(path, label) {
  await assertNoSymlinkComponents(path, label);
  const status = await lstat(path);
  if (!status.isDirectory()) throw new Error(`${label} must be a directory`);
}


function assertExactObject(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} has unexpected fields`);
  }
}


function assertIntegrity(payload, expected, label) {
  if (payload.byteLength !== expected.size) throw new Error(`${label} size mismatch`);
  if (sha256(payload) !== expected.sha256) throw new Error(`${label} digest mismatch`);
}


export async function validateReleaseDownloads(downloadsRoot) {
  const root = resolve(downloadsRoot);
  await validateDirectoryRoot(root, "release downloads");
  const entries = await readdir(root, { withFileTypes: true });
  const actualNames = entries.map(({ name }) => name).sort();
  if (
    actualNames.length !== RELEASE_DOWNLOAD_NAMES.length
    || actualNames.some((name, index) => name !== RELEASE_DOWNLOAD_NAMES[index])
  ) {
    const unexpected = actualNames.find((name) => !RELEASE_DOWNLOAD_NAMES.includes(name));
    throw new Error(unexpected ? `unexpected release download: ${unexpected}` : "release downloads are incomplete");
  }
  for (const entry of entries) {
    const path = join(root, entry.name);
    await assertNoSymlinkComponents(path, `release download ${entry.name}`);
    if (entry.isSymbolicLink()) throw new Error(`release download ${entry.name} must not be a symbolic link`);
    if (!entry.isFile()) throw new Error(`release download ${entry.name} must be a regular file`);
  }

  const manifestBytes = await readBoundedRegular(
    join(root, RELEASE_MANIFEST_NAME),
    "release manifest",
    MAX_RELEASE_MANIFEST_BYTES,
  );
  let manifest;
  try {
    manifest = JSON.parse(manifestBytes.toString("utf8"));
  } catch {
    throw new Error("release manifest is invalid JSON");
  }
  if (manifestBytes.toString("utf8") !== canonicalJson(manifest) + "\n") {
    throw new Error("release manifest is not canonical JSON");
  }
  assertExactObject(manifest, ["artifacts", "schema_version", "version"], "release manifest");
  if (
    manifest.schema_version !== "heel.open-core-artifacts.v1"
    || manifest.version !== "1.1.0"
    || !Array.isArray(manifest.artifacts)
    || manifest.artifacts.length !== 2
  ) {
    throw new Error("release manifest contains unpinned values");
  }

  const expectedArtifactNames = [RELEASE_WHEEL_NAME, RELEASE_SOURCE_NAME];
  const artifactNames = [];
  for (const artifact of manifest.artifacts) {
    assertExactObject(artifact, ["name", "sha256", "size"], "release artifact");
    if (
      !expectedArtifactNames.includes(artifact.name)
      || artifactNames.includes(artifact.name)
      || !Number.isSafeInteger(artifact.size)
      || artifact.size <= 0
      || artifact.size > MAX_RELEASE_ARCHIVE_BYTES
      || !/^[0-9a-f]{64}$/.test(artifact.sha256)
    ) {
      throw new Error("release artifact contains unpinned values");
    }
    artifactNames.push(artifact.name);
    const payload = await readBoundedRegular(
      join(root, artifact.name),
      `release artifact ${artifact.name}`,
      MAX_RELEASE_ARCHIVE_BYTES,
    );
    assertIntegrity(payload, artifact, `release artifact ${artifact.name}`);
  }
  artifactNames.sort();
  if (artifactNames.some((name, index) => name !== expectedArtifactNames[index])) {
    throw new Error("release manifest does not list the exact artifacts");
  }
  return manifest;
}


function replaceExactlyOnce(source, expected, replacement, label) {
  const parts = source.split(expected);
  if (parts.length !== 2) {
    throw new Error(`${label} replacement count must be exactly one`);
  }
  return parts.join(replacement);
}


function transformPyodideModule(payload) {
  let source = payload.toString("utf8");
  source = replaceExactlyOnce(
    source,
    PYODIDE_CDN_FALLBACK,
    SAME_ORIGIN_PYODIDE_FALLBACK,
    "Pyodide CDN fallback",
  );
  source = replaceExactlyOnce(
    source,
    PYODIDE_SOURCE_MAP_DIRECTIVE,
    "",
    "Pyodide source map directive",
  );
  return Buffer.from(source, "utf8");
}


async function validatePyodide(pyodideRoot) {
  const packageBytes = await readRegular(join(pyodideRoot, "package.json"), "Pyodide package metadata");
  let packageJson;
  try {
    packageJson = JSON.parse(packageBytes.toString("utf8"));
  } catch {
    throw new Error("Pyodide package metadata is invalid JSON");
  }
  if (packageJson.name !== "pyodide" || packageJson.version !== PYODIDE_VERSION) {
    throw new Error(`Pyodide package version must be ${PYODIDE_VERSION}`);
  }
  if (packageJson.license !== "MPL-2.0" || packageJson.homepage !== PYODIDE_HOMEPAGE) {
    throw new Error("Pyodide package license or source metadata is unpinned");
  }

  const assets = {};
  for (const [name, expected] of Object.entries(PYODIDE_ASSETS)) {
    const payload = await readRegular(join(pyodideRoot, name), `Pyodide asset ${name}`);
    assertIntegrity(payload, expected, `Pyodide asset ${name}`);
    assets[name] = payload;
  }
  return assets;
}


async function validateHeelEngine(engineRoot) {
  const manifestBytes = await readRegular(join(engineRoot, "manifest.json"), "Heel engine manifest");
  let manifest;
  try {
    manifest = JSON.parse(manifestBytes.toString("utf8"));
  } catch {
    throw new Error("Heel engine manifest is invalid JSON");
  }
  if (manifestBytes.toString("utf8") !== canonicalJson(manifest) + "\n") {
    throw new Error("Heel engine manifest is not canonical JSON");
  }
  assertExactObject(manifest, ["engine_version", "schema_version", "wheel"], "Heel engine manifest");
  assertExactObject(manifest.wheel, ["filename", "sha256", "size"], "Heel engine wheel manifest");
  if (
    manifest.schema_version !== "heel.browser-engine-manifest.v1"
    || manifest.engine_version !== "1.1.0"
    || manifest.wheel.filename !== WHEEL_NAME
    || !Number.isSafeInteger(manifest.wheel.size)
    || !/^[0-9a-f]{64}$/.test(manifest.wheel.sha256)
  ) {
    throw new Error("Heel engine manifest contains unpinned values");
  }
  const wheel = await readRegular(join(engineRoot, WHEEL_NAME), "Heel browser wheel");
  assertIntegrity(wheel, manifest.wheel, "Heel browser wheel");
  return { manifest, manifestBytes, wheel };
}


async function validateLegalAssets(legalRoot) {
  const assets = {};
  for (const [name, expected] of Object.entries(THIRD_PARTY_LICENSES)) {
    const payload = await readRegular(join(legalRoot, name), `third-party license ${name}`);
    assertIntegrity(payload, expected, `third-party license ${name}`);
    assets[name] = payload;
  }
  return assets;
}


async function validateOutputDirectory(outputRoot, expectedNames) {
  await assertNoSymlinkComponents(outputRoot, "runtime output", { allowMissing: true });
  try {
    const status = await lstat(outputRoot);
    if (status.isSymbolicLink()) throw new Error("runtime output must not be a symbolic link");
    if (!status.isDirectory()) throw new Error("runtime output must be a directory");
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
    await mkdir(outputRoot, { recursive: true, mode: 0o755 });
  }
  await validateDirectoryRoot(outputRoot, "runtime output");
  const entries = await readdir(outputRoot, { withFileTypes: true });
  for (const entry of entries) {
    if (!expectedNames.has(entry.name)) throw new Error(`unexpected runtime path: ${entry.name}`);
    await assertNoSymlinkComponents(join(outputRoot, entry.name), `runtime path ${entry.name}`);
    if (entry.isSymbolicLink()) throw new Error(`runtime path must not be a symbolic link: ${entry.name}`);
    if (!entry.isFile()) throw new Error(`runtime path must be a regular file: ${entry.name}`);
  }
}


async function writeAtomic(outputRoot, name, payload) {
  await validateDirectoryRoot(outputRoot, "runtime output");
  const destination = await assertNoSymlinkComponents(
    join(outputRoot, name),
    `runtime path ${name}`,
    { allowMissing: true },
  );
  const temporary = join(outputRoot, `.prepare-${randomBytes(12).toString("hex")}`);
  let handle;
  try {
    handle = await open(temporary, "wx", 0o644);
    await handle.writeFile(payload);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await validateDirectoryRoot(outputRoot, "runtime output");
    await assertNoSymlinkComponents(temporary, "runtime temporary artifact");
    await assertNoSymlinkComponents(destination, `runtime path ${name}`, { allowMissing: true });
    await rename(temporary, destination);
  } finally {
    if (handle) await handle.close();
    let cleanupIsSafe = true;
    try {
      await assertNoSymlinkComponents(temporary, "runtime temporary artifact", { allowMissing: true });
    } catch {
      cleanupIsSafe = false;
    }
    if (cleanupIsSafe) await rm(temporary, { force: true });
  }
}


export async function prepareRuntime(options = {}) {
  const appRoot = options.appRoot ? resolve(options.appRoot) : defaultAppRoot;
  const pyodideRoot = options.pyodideRoot
    ? resolve(options.pyodideRoot)
    : join(appRoot, "node_modules/pyodide");
  const engineRoot = options.engineRoot
    ? resolve(options.engineRoot)
    : join(appRoot, "browser-engine");
  const legalRoot = options.legalRoot
    ? resolve(options.legalRoot)
    : join(appRoot, "legal/third-party");
  const downloadsRoot = options.downloadsRoot
    ? resolve(options.downloadsRoot)
    : join(appRoot, "public/downloads");
  const outputRoot = options.outputRoot
    ? resolve(options.outputRoot)
    : join(appRoot, "public/heel-runtime");
  await Promise.all([
    validateDirectoryRoot(appRoot, "application root"),
    validateDirectoryRoot(pyodideRoot, "Pyodide root"),
    validateDirectoryRoot(engineRoot, "Heel engine root"),
    validateDirectoryRoot(legalRoot, "third-party legal root"),
    validateReleaseDownloads(downloadsRoot),
  ]);
  const [pyodideAssets, heel, legalAssets] = await Promise.all([
    validatePyodide(pyodideRoot),
    validateHeelEngine(engineRoot),
    validateLegalAssets(legalRoot),
  ]);
  const preparedPyodideAssets = {
    ...pyodideAssets,
    "pyodide.mjs": transformPyodideModule(pyodideAssets["pyodide.mjs"]),
  };

  const pyodideLicense = legalAssets["LICENSE.PYODIDE-MPL-2.0.txt"];
  const cpythonLicense = legalAssets["LICENSE.CPYTHON-PSF-2.0.txt"];
  const notice = Buffer.from(
    `Third-party runtime notice\n\nPyodide ${PYODIDE_VERSION}\nLicense: Mozilla Public License 2.0 (MPL-2.0)\nSource: ${PYODIDE_SOURCE}\n\nCPython ${CPYTHON_VERSION}\nLicense: Python Software Foundation License Version 2 (PSF-2.0)\nSource: ${CPYTHON_SOURCE}\n\nPyodide and CPython are distributed separately from the Apache-2.0 Heel browser wheel.\n`,
    "utf8",
  );
  const noticeFiles = {
    cpython: {
      filename: "LICENSE.CPYTHON-PSF-2.0.txt",
      sha256: sha256(cpythonLicense),
      size: cpythonLicense.byteLength,
    },
    pyodide: {
      filename: "LICENSE.PYODIDE-MPL-2.0.txt",
      sha256: sha256(pyodideLicense),
      size: pyodideLicense.byteLength,
    },
    third_party: {
      filename: "THIRD_PARTY_NOTICES.txt",
      sha256: sha256(notice),
      size: notice.byteLength,
    },
  };
  const runtimeManifest = {
    cpython: {
      license: "PSF-2.0",
      source: CPYTHON_SOURCE,
      version: CPYTHON_VERSION,
    },
    heel: heel.manifest,
    notices: noticeFiles,
    pyodide: {
      assets: Object.fromEntries(Object.entries(preparedPyodideAssets).map(([name, payload]) => [name, {
        sha256: sha256(payload),
        size: payload.byteLength,
      }])),
      license: "MPL-2.0",
      source: PYODIDE_SOURCE,
      version: PYODIDE_VERSION,
    },
    schema_version: "heel.browser-runtime-manifest.v1",
  };
  const outputPayloads = {
    ...preparedPyodideAssets,
    "LICENSE.CPYTHON-PSF-2.0.txt": cpythonLicense,
    "LICENSE.PYODIDE-MPL-2.0.txt": pyodideLicense,
    "THIRD_PARTY_NOTICES.txt": notice,
    "heel-browser-manifest.json": heel.manifestBytes,
    "runtime-manifest.json": Buffer.from(canonicalJson(runtimeManifest) + "\n", "utf8"),
    [WHEEL_NAME]: heel.wheel,
  };
  await validateOutputDirectory(outputRoot, new Set(Object.keys(outputPayloads)));
  for (const name of Object.keys(outputPayloads).sort()) {
    await writeAtomic(outputRoot, name, outputPayloads[name]);
  }
  return runtimeManifest;
}


if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  try {
    await prepareRuntime();
    process.stdout.write("prepared pinned local Heel/Pyodide runtime\n");
  } catch (error) {
    process.stderr.write(`runtime preparation failed: ${error instanceof Error ? error.message : "unknown error"}\n`);
    process.exitCode = 1;
  }
}
