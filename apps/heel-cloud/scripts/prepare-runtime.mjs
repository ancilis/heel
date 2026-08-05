// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import { createHash, randomBytes } from "node:crypto";
import { lstat, mkdir, open, readFile, readdir, rename, rm } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";


const scriptPath = fileURLToPath(import.meta.url);
const defaultAppRoot = resolve(dirname(scriptPath), "..");
const PYODIDE_VERSION = "314.0.3";
const PYODIDE_HOMEPAGE = "https://github.com/pyodide/pyodide";
const PYODIDE_SOURCE = "https://github.com/pyodide/pyodide/tree/ac57031be7564f864d061cb37c5c152e59f83ad4";
const CPYTHON_VERSION = "3.14.2";
const CPYTHON_SOURCE = "https://github.com/python/cpython/tree/df793163d5821791d4e7caf88885a2c11a107986";
const WHEEL_NAME = "heel_browser-1.1.0-py3-none-any.whl";
const PYODIDE_ASSETS = Object.freeze({
  "pyodide.asm.mjs": Object.freeze({ size: 1249447, sha256: "1a9775427ef6e8abaa7db88ece0515422d1886915ae5c9093776410c865dfd8d" }),
  "pyodide.asm.wasm": Object.freeze({ size: 9596462, sha256: "e7f8fac36f8bf11085309cbc5c829b3ec3057c18bf1d73b05a6741612d63cdbf" }),
  "pyodide-lock.json": Object.freeze({ size: 113804, sha256: "c963d22858f6bcb8f41586a2142f03905ab370c88ea22a86a2736e95fac2a8f3" }),
  "pyodide.mjs": Object.freeze({ size: 17880, sha256: "5cfc46f5dcbaf2a16f26e2363f441873eb424762609cc03db00d6a2ace4d00e5" }),
  "python_stdlib.zip": Object.freeze({ size: 2545106, sha256: "444c770dfd75a32097fc0a7d5c1413fd3140601f49c3a1f2e9af0376fcd124b4" }),
});
const MPL_GZIP_BASE64 = "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";
const CPYTHON_LICENSE_GZIP_BASE64 = "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";


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
  const status = await lstat(path);
  if (status.isSymbolicLink()) throw new Error(`${label} must not be a symbolic link`);
  if (!status.isFile()) throw new Error(`${label} must be a regular file`);
  return readFile(path);
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


async function validateOutputDirectory(outputRoot, expectedNames) {
  try {
    const status = await lstat(outputRoot);
    if (status.isSymbolicLink()) throw new Error("runtime output must not be a symbolic link");
    if (!status.isDirectory()) throw new Error("runtime output must be a directory");
  } catch (error) {
    if (error?.code !== "ENOENT") throw error;
    await mkdir(outputRoot, { recursive: true, mode: 0o755 });
  }
  const entries = await readdir(outputRoot, { withFileTypes: true });
  for (const entry of entries) {
    if (!expectedNames.has(entry.name)) throw new Error(`unexpected runtime path: ${entry.name}`);
    if (entry.isSymbolicLink()) throw new Error(`runtime path must not be a symbolic link: ${entry.name}`);
    if (!entry.isFile()) throw new Error(`runtime path must be a regular file: ${entry.name}`);
  }
}


async function writeAtomic(outputRoot, name, payload) {
  const temporary = join(outputRoot, `.prepare-${randomBytes(12).toString("hex")}`);
  let handle;
  try {
    handle = await open(temporary, "wx", 0o644);
    await handle.writeFile(payload);
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(temporary, join(outputRoot, name));
  } finally {
    if (handle) await handle.close();
    await rm(temporary, { force: true });
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
  const outputRoot = options.outputRoot
    ? resolve(options.outputRoot)
    : join(appRoot, "public/heel-runtime");
  const [pyodideAssets, heel] = await Promise.all([
    validatePyodide(pyodideRoot),
    validateHeelEngine(engineRoot),
  ]);

  const pyodideLicense = gunzipSync(Buffer.from(MPL_GZIP_BASE64, "base64"));
  const cpythonLicense = gunzipSync(Buffer.from(CPYTHON_LICENSE_GZIP_BASE64, "base64"));
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
      assets: Object.fromEntries(Object.entries(PYODIDE_ASSETS).map(([name, value]) => [name, value])),
      license: "MPL-2.0",
      source: PYODIDE_SOURCE,
      version: PYODIDE_VERSION,
    },
    schema_version: "heel.browser-runtime-manifest.v1",
  };
  const outputPayloads = {
    ...pyodideAssets,
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
