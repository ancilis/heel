// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { copyFile, mkdtemp, mkdir, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";


const appRoot = fileURLToPath(new URL("../", import.meta.url));
const repositoryRoot = resolve(appRoot, "../..");
const prepareScript = join(appRoot, "scripts/prepare-runtime.mjs");
const runtimeRoot = join(appRoot, "public/heel-runtime");
const engineRoot = join(appRoot, "browser-engine");
const wheelName = "heel_browser-1.1.0-py3-none-any.whl";
const pyodideSource = "https://github.com/pyodide/pyodide/tree/ac57031be7564f864d061cb37c5c152e59f83ad4";
const cpythonSource = "https://github.com/python/cpython/tree/df793163d5821791d4e7caf88885a2c11a107986";
const licenseFiles = {
  cpython: {
    filename: "LICENSE.CPYTHON-PSF-2.0.txt",
    sha256: "b0e25a78cffb43f4d92de8b61ccfa1f1f98ecbc22330b54b5251e7b6ba010231",
    size: 13804,
  },
  pyodide: {
    filename: "LICENSE.PYODIDE-MPL-2.0.txt",
    sha256: "5eba353fe5076ac3432177f8ab1cf75e3afcd0584251e37c3bfead5f447d040e",
    size: 15648,
  },
};
const pyodideAssets = {
  "pyodide.asm.mjs": [1249447, "1a9775427ef6e8abaa7db88ece0515422d1886915ae5c9093776410c865dfd8d"],
  "pyodide.asm.wasm": [9596462, "e7f8fac36f8bf11085309cbc5c829b3ec3057c18bf1d73b05a6741612d63cdbf"],
  "pyodide-lock.json": [113804, "c963d22858f6bcb8f41586a2142f03905ab370c88ea22a86a2736e95fac2a8f3"],
  "pyodide.mjs": [17880, "5cfc46f5dcbaf2a16f26e2363f441873eb424762609cc03db00d6a2ace4d00e5"],
  "python_stdlib.zip": [2545106, "444c770dfd75a32097fc0a7d5c1413fd3140601f49c3a1f2e9af0376fcd124b4"],
};
const expectedRuntimeFiles = [
  "LICENSE.PYODIDE-MPL-2.0.txt",
  "LICENSE.CPYTHON-PSF-2.0.txt",
  "THIRD_PARTY_NOTICES.txt",
  "heel-browser-manifest.json",
  "pyodide.asm.mjs",
  "pyodide.asm.wasm",
  "pyodide-lock.json",
  "pyodide.mjs",
  "python_stdlib.zip",
  "runtime-manifest.json",
  wheelName,
].sort();


function prepareRuntime() {
  return spawnSync(process.execPath, [prepareScript], {
    cwd: appRoot,
    encoding: "utf8",
    timeout: 30_000,
  });
}


async function importPrepareModule() {
  return import(pathToFileURL(prepareScript).href + `?test=${Date.now()}`);
}


function sha256(payload) {
  return createHash("sha256").update(payload).digest("hex");
}


test("prepares only integrity-pinned local engine and Pyodide runtime assets", async () => {
  const prepared = prepareRuntime();
  assert.equal(prepared.status, 0, prepared.stderr);
  assert.deepEqual((await readdir(runtimeRoot)).sort(), expectedRuntimeFiles);

  const [
    runtimeManifest,
    engineManifest,
    notice,
    pyodideLicense,
    cpythonLicense,
    packageJson,
    gitignore,
  ] = await Promise.all([
    readFile(join(runtimeRoot, "runtime-manifest.json"), "utf8").then(JSON.parse),
    readFile(join(engineRoot, "manifest.json"), "utf8").then(JSON.parse),
    readFile(join(runtimeRoot, "THIRD_PARTY_NOTICES.txt"), "utf8"),
    readFile(join(runtimeRoot, "LICENSE.PYODIDE-MPL-2.0.txt")),
    readFile(join(runtimeRoot, "LICENSE.CPYTHON-PSF-2.0.txt")),
    readFile(join(appRoot, "package.json"), "utf8").then(JSON.parse),
    readFile(join(appRoot, ".gitignore"), "utf8"),
  ]);

  assert.equal(runtimeManifest.schema_version, "heel.browser-runtime-manifest.v1");
  assert.equal(runtimeManifest.pyodide.version, "314.0.3");
  assert.equal(runtimeManifest.pyodide.license, "MPL-2.0");
  assert.equal(runtimeManifest.pyodide.source, pyodideSource);
  assert.deepEqual(runtimeManifest.cpython, {
    license: "PSF-2.0",
    source: cpythonSource,
    version: "3.14.2",
  });
  assert.deepEqual(
    Object.fromEntries(Object.entries(runtimeManifest.pyodide.assets).map(([name, value]) => [
      name,
      [value.size, value.sha256],
    ])),
    pyodideAssets,
  );
  assert.deepEqual(runtimeManifest.heel, engineManifest);
  assert.deepEqual(Object.keys(runtimeManifest.notices).sort(), ["cpython", "pyodide", "third_party"]);
  assert.deepEqual(runtimeManifest.notices.cpython, licenseFiles.cpython);
  assert.deepEqual(runtimeManifest.notices.pyodide, licenseFiles.pyodide);
  assert.equal(sha256(cpythonLicense), licenseFiles.cpython.sha256);
  assert.equal(sha256(pyodideLicense), licenseFiles.pyodide.sha256);
  assert.match(notice, /Pyodide 314\.0\.3/);
  assert.match(notice, /Mozilla Public License 2\.0/);
  assert.ok(notice.includes(pyodideSource));
  assert.match(notice, /CPython 3\.14\.2/);
  assert.match(notice, /Python Software Foundation License Version 2/);
  assert.ok(notice.includes(cpythonSource));
  assert.match(pyodideLicense.toString("utf8"), /Mozilla Public License Version 2\.0/);
  assert.match(pyodideLicense.toString("utf8"), /1\. Definitions/);
  assert.match(pyodideLicense.toString("utf8"), /Exhibit B/);
  assert.ok(pyodideLicense.length > 14_000, "full MPL-2.0 text must be distributed");
  assert.match(cpythonLicense.toString("utf8"), /PYTHON SOFTWARE FOUNDATION LICENSE VERSION 2/);
  assert.match(cpythonLicense.toString("utf8"), /BEOPEN\.COM LICENSE AGREEMENT FOR PYTHON 2\.0/);
  assert.match(cpythonLicense.toString("utf8"), /CNRI LICENSE AGREEMENT FOR PYTHON 1\.6\.1/);
  assert.ok(cpythonLicense.length > 13_000, "full CPython license history must be distributed");
  assert.equal(packageJson.scripts.predev, "node scripts/prepare-runtime.mjs");
  assert.equal(packageJson.scripts.prebuild, "node scripts/prepare-runtime.mjs");
  assert.equal(
    packageJson.scripts.lint,
    "eslint . --ignore-pattern dist --ignore-pattern .next --ignore-pattern public/heel-runtime",
  );
  assert.match(gitignore, /^\/public\/heel-runtime\/$/m);
});


test("runtime preparation rejects tampering, symlinks, unpinned versions, and unexpected output", async () => {
  const { prepareRuntime: prepare } = await importPrepareModule();
  const temporary = await mkdtemp(join(tmpdir(), "heel-runtime-security-"));
  try {
    const tamperedEngine = join(temporary, "tampered-engine");
    await mkdir(tamperedEngine);
    await copyFile(join(engineRoot, "manifest.json"), join(tamperedEngine, "manifest.json"));
    await copyFile(join(engineRoot, wheelName), join(tamperedEngine, wheelName));
    await writeFile(join(tamperedEngine, wheelName), "tampered", { flag: "a" });
    await assert.rejects(
      prepare({ engineRoot: tamperedEngine, outputRoot: join(temporary, "tampered-output") }),
      /digest|size/i,
    );

    const wrongVersion = join(temporary, "wrong-version");
    await mkdir(wrongVersion);
    await writeFile(join(wrongVersion, "package.json"), JSON.stringify({
      name: "pyodide",
      version: "0.0.0",
      license: "MPL-2.0",
      homepage: "https://github.com/pyodide/pyodide",
    }));
    await assert.rejects(
      prepare({ pyodideRoot: wrongVersion, outputRoot: join(temporary, "wrong-output") }),
      /version/i,
    );

    const symlinkPackage = join(temporary, "symlink-package");
    await mkdir(symlinkPackage);
    await copyFile(join(appRoot, "node_modules/pyodide/package.json"), join(symlinkPackage, "package.json"));
    await symlink(
      join(appRoot, "node_modules/pyodide/pyodide.asm.mjs"),
      join(symlinkPackage, "pyodide.asm.mjs"),
    );
    await assert.rejects(
      prepare({ pyodideRoot: symlinkPackage, outputRoot: join(temporary, "symlink-output") }),
      /symbolic link/i,
    );

    const digestPackage = join(temporary, "digest-package");
    await mkdir(digestPackage);
    await copyFile(join(appRoot, "node_modules/pyodide/package.json"), join(digestPackage, "package.json"));
    await writeFile(join(digestPackage, "pyodide.asm.mjs"), "wrong bytes");
    await assert.rejects(
      prepare({ pyodideRoot: digestPackage, outputRoot: join(temporary, "digest-output") }),
      /digest|size/i,
    );

    const prepared = prepareRuntime();
    assert.equal(prepared.status, 0, prepared.stderr);
    const unexpected = join(runtimeRoot, "unexpected.js");
    await writeFile(unexpected, "unexpected");
    await assert.rejects(prepare(), /unexpected runtime path/i);
    await rm(unexpected);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
});


test("executes the real local wheel in Pyodide with outbound network disabled", async () => {
  const prepared = prepareRuntime();
  assert.equal(prepared.status, 0, prepared.stderr);
  const sample = await readFile(join(repositoryRoot, "tests/fixtures/openapi/saas_api.json"), "utf8");
  const native = spawnSync(
    process.env.PYTHON ?? "python3",
    ["-c", "import sys; from heel.browser_review import review_openapi_json; sys.stdout.write(review_openapi_json(sys.stdin.read()))"],
    { cwd: repositoryRoot, input: sample, encoding: "utf8", timeout: 30_000 },
  );
  assert.equal(native.status, 0, native.stderr);

  let networkAttempts = 0;
  const denyNetwork = () => {
    networkAttempts += 1;
    throw new Error("outbound network disabled for browser-engine test");
  };
  const patches = [
    [http, "get"], [http, "request"], [https, "get"], [https, "request"],
    [net, "connect"], [net, "createConnection"],
  ];
  const originals = patches.map(([owner, name]) => [owner, name, owner[name]]);
  const originalFetch = globalThis.fetch;
  for (const [owner, name] of patches) owner[name] = denyNetwork;
  globalThis.fetch = denyNetwork;
  assert.throws(() => http.get("http://127.0.0.1/"), /outbound network disabled/);
  networkAttempts = 0;

  try {
    const runtimeModule = await import(pathToFileURL(join(runtimeRoot, "pyodide.mjs")).href);
    assert.equal(runtimeModule.version, "314.0.3");
    const pyodide = await runtimeModule.loadPyodide({
      indexURL: runtimeRoot,
      lockFileURL: join(runtimeRoot, "pyodide-lock.json"),
    });
    const wheel = await readFile(join(runtimeRoot, wheelName));
    const sitePackages = pyodide.runPython("import sysconfig; sysconfig.get_paths()['purelib']");
    pyodide.unpackArchive(new Uint8Array(wheel), "wheel", { extractDir: sitePackages });
    pyodide.globals.set("heel_source", sample);
    const actual = pyodide.runPython(
      "from heel.browser_review import review_openapi_json\nreview_openapi_json(heel_source)",
    );
    const cpythonVersion = pyodide.runPython(
      "import sys\n'.'.join(str(part) for part in sys.version_info[:3])",
    );
    pyodide.globals.delete("heel_source");

    assert.equal(actual, native.stdout);
    assert.equal(cpythonVersion, "3.14.2");
    const envelope = JSON.parse(actual);
    assert.equal(envelope.schema_version, "heel.review.v1");
    assert.equal(envelope.execution_mode, "browser_local");
    assert.ok(envelope.summary.findings > 0);
    assert.ok(envelope.recommended_controls.length > 0);
    assert.equal(networkAttempts, 0, "engine attempted outbound network access");
  } finally {
    for (const [owner, name, original] of originals) owner[name] = original;
    globalThis.fetch = originalFetch;
  }
});
