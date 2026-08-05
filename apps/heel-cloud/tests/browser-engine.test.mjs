// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import dgram from "node:dgram";
import dns from "node:dns";
import dnsPromises from "node:dns/promises";
import { copyFile, mkdtemp, mkdir, readFile, readdir, realpath, rm, symlink, writeFile } from "node:fs/promises";
import http from "node:http";
import http2 from "node:http2";
import https from "node:https";
import { registerHooks, syncBuiltinESMExports } from "node:module";
import net from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";
import tls from "node:tls";


const appRoot = fileURLToPath(new URL("../", import.meta.url));
const confinementSymbolKey = "heel.browser-engine.test.network-confinement";
const networkDeniedMessage = "outbound network disabled for browser-engine test";
const repositoryRoot = resolve(appRoot, "../..");
const prepareScript = join(appRoot, "scripts/prepare-runtime.mjs");
const runtimeRoot = join(appRoot, "public/heel-runtime");
const engineRoot = join(appRoot, "browser-engine");
const legalRoot = join(appRoot, "legal/third-party");
const permissionRunner = join(appRoot, "tests/browser-engine-permission-runner.mjs");
const wheelName = "heel_browser-1.1.1-py3-none-any.whl";
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
const upstreamPyodideAssets = {
  "pyodide.asm.mjs": [1249447, "1a9775427ef6e8abaa7db88ece0515422d1886915ae5c9093776410c865dfd8d"],
  "pyodide.asm.wasm": [9596462, "e7f8fac36f8bf11085309cbc5c829b3ec3057c18bf1d73b05a6741612d63cdbf"],
  "pyodide-lock.json": [113804, "c963d22858f6bcb8f41586a2142f03905ab370c88ea22a86a2736e95fac2a8f3"],
  "pyodide.mjs": [17880, "5cfc46f5dcbaf2a16f26e2363f441873eb424762609cc03db00d6a2ace4d00e5"],
  "python_stdlib.zip": [2545106, "444c770dfd75a32097fc0a7d5c1413fd3140601f49c3a1f2e9af0376fcd124b4"],
};
const upstreamCdnFallback = "`https://cdn.jsdelivr.net/pyodide/v${U}/full/`";
const sameOriginCdnFallback = '"/heel-runtime/"';
const upstreamSourceMapDirective = "//# sourceMappingURL=pyodide.mjs.map";
const preparedPyodideAsset = [17813, "be311e4c0ef3d22edd4fee1309a69cc6571e9980e80c40a113776cb225de355e"];
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


function expectedPreparedPyodide(upstream) {
  const source = upstream.toString("utf8");
  assert.equal(source.split(upstreamCdnFallback).length - 1, 1, "upstream CDN fallback count");
  assert.equal(source.split(upstreamSourceMapDirective).length - 1, 1, "upstream map directive count");
  return Buffer.from(
    source
      .replace(upstreamCdnFallback, sameOriginCdnFallback)
      .replace(`\n${upstreamSourceMapDirective}`, ""),
    "utf8",
  );
}


function deniedModuleUrl(moduleName) {
  const common = `
const state = globalThis[Symbol.for(${JSON.stringify(confinementSymbolKey)})];
if (!state) throw new Error("Heel network confinement is unavailable");
const deny = (label) => function deniedOutboundMechanism(...args) {
  return state.deny(label, args);
};
export const __heelNetworkDenied = true;
export const __heelConfinementToken = state.token;
`;
  const source = moduleName === "ws"
    ? `${common}
export const WebSocket = deny("module:ws.WebSocket");
export const WebSocketServer = deny("module:ws.WebSocketServer");
export const Server = WebSocketServer;
export const Receiver = deny("module:ws.Receiver");
export const Sender = deny("module:ws.Sender");
export const createWebSocketStream = deny("module:ws.createWebSocketStream");
export default WebSocket;
`
    : `${common}
export const fetch = deny("module:undici.fetch");
export const request = deny("module:undici.request");
export const stream = deny("module:undici.stream");
export const pipeline = deny("module:undici.pipeline");
export const connect = deny("module:undici.connect");
export const WebSocket = deny("module:undici.WebSocket");
export const EventSource = deny("module:undici.EventSource");
export const Client = deny("module:undici.Client");
export const Pool = deny("module:undici.Pool");
export const Agent = deny("module:undici.Agent");
export const ProxyAgent = deny("module:undici.ProxyAgent");
export default { fetch, request, stream, pipeline, connect, WebSocket, EventSource, Client, Pool, Agent, ProxyAgent };
`;
  return `data:text/javascript,${encodeURIComponent(source)}`;
}


function installNetworkConfinement() {
  assert.equal(typeof registerHooks, "function", "Node must support synchronous module confinement hooks");
  const attempts = [];
  const token = `heel-network-confinement-${process.pid}`;
  const stateSymbol = Symbol.for(confinementSymbolKey);
  const previousStateDescriptor = Object.getOwnPropertyDescriptor(globalThis, stateSymbol);
  const restorers = [];
  const state = {
    deny(label) {
      attempts.push(label);
      throw new Error(`${networkDeniedMessage}: ${label}`);
    },
    token,
  };
  Object.defineProperty(globalThis, stateSymbol, {
    configurable: true,
    value: state,
  });

  const moduleUrls = {
    undici: deniedModuleUrl("undici"),
    ws: deniedModuleUrl("ws"),
  };
  const moduleHooks = registerHooks({
    resolve(specifier, context, nextResolve) {
      if (specifier === "ws") return { shortCircuit: true, url: moduleUrls.ws };
      if (specifier === "undici" || specifier.startsWith("undici/")) {
        return { shortCircuit: true, url: moduleUrls.undici };
      }
      return nextResolve(specifier, context);
    },
  });

  function guard(owner, name, label, { construct = false, optional = false } = {}) {
    const original = owner?.[name];
    if (typeof original !== "function") {
      if (optional) return undefined;
      assert.fail(`${label} is unavailable and cannot be confined`);
    }
    const ownDescriptor = Object.getOwnPropertyDescriptor(owner, name);
    const denied = function deniedOutboundMechanism(...args) {
      return state.deny(label, args);
    };
    Object.defineProperty(owner, name, {
      configurable: ownDescriptor?.configurable ?? true,
      enumerable: ownDescriptor?.enumerable ?? false,
      value: denied,
      writable: ownDescriptor?.writable ?? true,
    });
    restorers.push(() => {
      if (ownDescriptor) Object.defineProperty(owner, name, ownDescriptor);
      else delete owner[name];
    });
    const installed = { construct, denied, label, name, original, owner };
    return installed;
  }

  const methodGuards = [
    guard(http, "get", "node:http.get"),
    guard(http, "request", "node:http.request"),
    guard(https, "get", "node:https.get"),
    guard(https, "request", "node:https.request"),
    guard(http.Agent.prototype, "createConnection", "node:http.Agent.createConnection"),
    guard(https.Agent.prototype, "createConnection", "node:https.Agent.createConnection"),
    guard(net, "connect", "node:net.connect"),
    guard(net, "createConnection", "node:net.createConnection"),
    guard(net.Socket.prototype, "connect", "node:net.Socket.connect"),
    guard(tls, "connect", "node:tls.connect"),
    guard(dgram, "createSocket", "node:dgram.createSocket"),
    guard(dgram.Socket.prototype, "connect", "node:dgram.Socket.connect"),
    guard(dgram.Socket.prototype, "send", "node:dgram.Socket.send"),
    guard(dgram.Socket.prototype, "sendto", "node:dgram.Socket.sendto"),
    guard(http2, "connect", "node:http2.connect"),
  ];
  const dnsMethods = [...new Set([...Object.keys(dns), ...Object.keys(dnsPromises)])]
    .filter((name) => /^(lookup|resolve|reverse)/.test(name))
    .sort();
  for (const name of dnsMethods) {
    methodGuards.push(guard(dns, name, `node:dns.${name}`));
    methodGuards.push(guard(dnsPromises, name, `node:dns/promises.${name}`));
  }
  methodGuards.push(guard(dns, "Resolver", "node:dns.Resolver", { construct: true }));
  methodGuards.push(guard(
    dnsPromises,
    "Resolver",
    "node:dns/promises.Resolver",
    { construct: true },
  ));
  syncBuiltinESMExports();
  const builtinEsmModules = [
    { defaultExport: http, names: ["get", "request"], specifier: "node:http" },
    { defaultExport: https, names: ["get", "request"], specifier: "node:https" },
    { defaultExport: net, names: ["connect", "createConnection"], specifier: "node:net" },
    { defaultExport: tls, names: ["connect"], specifier: "node:tls" },
    { defaultExport: dgram, names: ["createSocket"], specifier: "node:dgram" },
    { defaultExport: http2, names: ["connect"], specifier: "node:http2" },
    { defaultExport: dns, names: [...dnsMethods, "Resolver"], specifier: "node:dns" },
    {
      defaultExport: dnsPromises,
      names: [...dnsMethods, "Resolver"],
      specifier: "node:dns/promises",
    },
  ];

  const globalGuards = [
    guard(globalThis, "fetch", "global.fetch"),
    guard(globalThis, "WebSocket", "global.WebSocket", { construct: true }),
    guard(globalThis, "EventSource", "global.EventSource", { construct: true, optional: true }),
    guard(
      globalThis,
      "XMLHttpRequest",
      "global.XMLHttpRequest",
      { construct: true, optional: true },
    ),
    guard(
      globalThis,
      "WebSocketStream",
      "global.WebSocketStream",
      { construct: true, optional: true },
    ),
  ].filter(Boolean);
  if (typeof globalThis.navigator?.sendBeacon === "function") {
    globalGuards.push(guard(globalThis.navigator, "sendBeacon", "navigator.sendBeacon"));
  }

  function proveGuards(selectedGuards) {
    for (const installed of selectedGuards) {
      assert.equal(
        installed.owner[installed.name],
        installed.denied,
        `${installed.label} remains usable`,
      );
      const before = attempts.length;
      assert.throws(
        () => installed.construct
          ? Reflect.construct(installed.owner[installed.name], [])
          : Reflect.apply(installed.owner[installed.name], installed.owner, []),
        new RegExp(networkDeniedMessage),
        installed.label,
      );
      assert.deepEqual(attempts.slice(before), [installed.label]);
    }
  }

  return {
    attempts,
    guard,
    methodGuards,
    globalGuards,
    async proveBuiltinEsmGuards() {
      for (const { defaultExport, names, specifier } of builtinEsmModules) {
        const namespace = await import(specifier);
        for (const name of names) {
          const installed = methodGuards.find((candidate) => (
            candidate.owner === defaultExport && candidate.name === name
          ));
          assert.ok(installed, `${specifier}.${name} has no matching confinement guard`);
          assert.equal(
            namespace[name],
            installed.denied,
            `${specifier}.${name} named ESM export bypasses confinement`,
          );
          const before = attempts.length;
          assert.throws(
            () => installed.construct
              ? Reflect.construct(namespace[name], [])
              : Reflect.apply(namespace[name], namespace, []),
            new RegExp(networkDeniedMessage),
            `${specifier}.${name}`,
          );
          assert.deepEqual(attempts.slice(before), [installed.label]);
        }
      }
    },
    async proveBuiltinEsmRestoration() {
      for (const { defaultExport, names, specifier } of builtinEsmModules) {
        const namespace = await import(specifier);
        for (const name of names) {
          const installed = methodGuards.find((candidate) => (
            candidate.owner === defaultExport && candidate.name === name
          ));
          assert.equal(defaultExport[name], installed.original, `${specifier}.${name} default restore`);
          assert.equal(namespace[name], installed.original, `${specifier}.${name} named ESM restore`);
          assert.notEqual(namespace[name], installed.denied, `${specifier}.${name} retained denial guard`);
        }
      }
    },
    async proveModuleGuards() {
      const wsModule = await import("ws");
      assert.equal(wsModule.__heelNetworkDenied, true);
      assert.equal(wsModule.__heelConfinementToken, token);
      for (const name of ["default", "WebSocket", "WebSocketServer", "createWebSocketStream"]) {
        assert.throws(
          () => Reflect.construct(wsModule[name], ["ws://127.0.0.1/"]),
          new RegExp(networkDeniedMessage),
          `ws.${name}`,
        );
      }
      const undiciModule = await import("undici");
      assert.equal(undiciModule.__heelNetworkDenied, true);
      assert.equal(undiciModule.__heelConfinementToken, token);
      for (const name of ["fetch", "request", "stream", "pipeline", "connect"]) {
        assert.throws(
          () => undiciModule[name]("https://example.invalid/"),
          new RegExp(networkDeniedMessage),
          `undici.${name}`,
        );
      }
      for (const name of ["WebSocket", "EventSource", "Client", "Pool", "Agent", "ProxyAgent"]) {
        assert.throws(
          () => Reflect.construct(undiciModule[name], ["https://example.invalid/"]),
          new RegExp(networkDeniedMessage),
          `undici.${name}`,
        );
      }
    },
    proveGuards,
    resetAttempts() {
      attempts.length = 0;
    },
    restore() {
      moduleHooks.deregister();
      for (const restore of restorers.reverse()) restore();
      syncBuiltinESMExports();
      if (previousStateDescriptor) {
        Object.defineProperty(globalThis, stateSymbol, previousStateDescriptor);
      } else {
        delete globalThis[stateSymbol];
      }
    },
  };
}


test("prepares only integrity-pinned local engine and Pyodide runtime assets", async () => {
  const vendoredPyodideBefore = await readFile(join(appRoot, "node_modules/pyodide/pyodide.mjs"));
  const expectedPyodide = expectedPreparedPyodide(vendoredPyodideBefore);
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
    packageLock,
    readme,
    gitignore,
    shippedPyodide,
    vendoredPyodideAfter,
  ] = await Promise.all([
    readFile(join(runtimeRoot, "runtime-manifest.json"), "utf8").then(JSON.parse),
    readFile(join(engineRoot, "manifest.json"), "utf8").then(JSON.parse),
    readFile(join(runtimeRoot, "THIRD_PARTY_NOTICES.txt"), "utf8"),
    readFile(join(runtimeRoot, "LICENSE.PYODIDE-MPL-2.0.txt")),
    readFile(join(runtimeRoot, "LICENSE.CPYTHON-PSF-2.0.txt")),
    readFile(join(appRoot, "package.json"), "utf8").then(JSON.parse),
    readFile(join(appRoot, "package-lock.json"), "utf8").then(JSON.parse),
    readFile(join(appRoot, "README.md"), "utf8"),
    readFile(join(appRoot, ".gitignore"), "utf8"),
    readFile(join(runtimeRoot, "pyodide.mjs")),
    readFile(join(appRoot, "node_modules/pyodide/pyodide.mjs")),
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
  const expectedAssets = { ...upstreamPyodideAssets };
  assert.deepEqual([expectedPyodide.byteLength, sha256(expectedPyodide)], preparedPyodideAsset);
  expectedAssets["pyodide.mjs"] = preparedPyodideAsset;
  assert.deepEqual(
    Object.fromEntries(Object.entries(runtimeManifest.pyodide.assets).map(([name, value]) => [
      name,
      [value.size, value.sha256],
    ])),
    expectedAssets,
  );
  assert.deepEqual(shippedPyodide, expectedPyodide);
  assert.notDeepEqual(shippedPyodide, vendoredPyodideBefore);
  assert.deepEqual(vendoredPyodideAfter, vendoredPyodideBefore);
  assert.doesNotMatch(shippedPyodide.toString("utf8"), /cdn\.jsdelivr\.net|sourceMappingURL=/i);
  assert.equal(
    shippedPyodide.toString("utf8").split(sameOriginCdnFallback).length - 1,
    1,
    "prepared module must contain exactly one same-origin fallback",
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
  assert.equal(packageJson.engines.node, ">=24.13.1");
  assert.equal(packageLock.packages[""].engines.node, ">=24.13.1");
  assert.match(readme, /Production and hosting: Node\.js `>=24\.13\.1`/);
  assert.match(readme, /Security verification: Node\.js 25\+; Node\.js 26 is recommended/);
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
  const temporary = await realpath(await mkdtemp(join(tmpdir(), "heel-runtime-security-")));
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

    const outsideOutput = join(temporary, "outside-output");
    await mkdir(outsideOutput);
    const directOutput = join(temporary, "direct-output");
    await symlink(outsideOutput, directOutput);
    await assert.rejects(
      prepare({ outputRoot: directOutput }),
      /symbolic link/i,
    );
    assert.deepEqual(await readdir(outsideOutput), []);
    const outsideRuntime = join(outsideOutput, "runtime");
    await mkdir(outsideRuntime);
    const linkedOutputParent = join(temporary, "linked-output-parent");
    await symlink(outsideOutput, linkedOutputParent);
    await assert.rejects(
      prepare({ outputRoot: join(linkedOutputParent, "runtime") }),
      /symbolic link/i,
    );
    assert.deepEqual(await readdir(outsideRuntime), []);

    const linkedAppRoot = join(temporary, "linked-app-root");
    await symlink(appRoot, linkedAppRoot);
    await assert.rejects(
      prepare({ appRoot: linkedAppRoot, outputRoot: join(temporary, "app-root-output") }),
      /symbolic link/i,
    );
    const linkedEngineRoot = join(temporary, "linked-engine-root");
    await symlink(engineRoot, linkedEngineRoot);
    await assert.rejects(
      prepare({ engineRoot: linkedEngineRoot, outputRoot: join(temporary, "engine-root-output") }),
      /symbolic link/i,
    );
    const linkedPyodideRoot = join(temporary, "linked-pyodide-root");
    await symlink(join(appRoot, "node_modules/pyodide"), linkedPyodideRoot);
    await assert.rejects(
      prepare({ pyodideRoot: linkedPyodideRoot, outputRoot: join(temporary, "pyodide-root-output") }),
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


test("loads third-party licenses only from digest-pinned tracked assets", async () => {
  const prepared = prepareRuntime();
  assert.equal(prepared.status, 0, prepared.stderr);
  const { prepareRuntime: prepare } = await importPrepareModule();
  const temporary = await realpath(await mkdtemp(join(tmpdir(), "heel-license-security-")));
  try {
    const filenames = [
      "LICENSE.CPYTHON-PSF-2.0.txt",
      "LICENSE.PYODIDE-MPL-2.0.txt",
    ];
    const tamperedLegal = join(temporary, "tampered-legal");
    await mkdir(tamperedLegal);
    for (const filename of filenames) {
      await copyFile(join(runtimeRoot, filename), join(tamperedLegal, filename));
    }
    await writeFile(join(tamperedLegal, filenames[0]), "tampered", { flag: "a" });

    const linkedLegal = join(temporary, "linked-legal");
    await symlink(runtimeRoot, linkedLegal);
    const linkedLeafLegal = join(temporary, "linked-leaf-legal");
    await mkdir(linkedLeafLegal);
    await copyFile(join(runtimeRoot, filenames[0]), join(linkedLeafLegal, filenames[0]));
    await symlink(
      join(runtimeRoot, filenames[1]),
      join(linkedLeafLegal, filenames[1]),
    );

    const attempts = await Promise.allSettled([
      prepare({ legalRoot: tamperedLegal, outputRoot: join(temporary, "tampered-output") }),
      prepare({ legalRoot: linkedLegal, outputRoot: join(temporary, "linked-output") }),
      prepare({ legalRoot: linkedLeafLegal, outputRoot: join(temporary, "linked-leaf-output") }),
    ]);
    for (const attempt of attempts) {
      assert.equal(attempt.status, "rejected", "untrusted legal assets were accepted");
      assert.match(attempt.reason.message, /digest|size|symbolic link/i);
    }

    const source = await readFile(prepareScript, "utf8");
    assert.doesNotMatch(source, /_GZIP_BASE64/);
    assert.deepEqual((await readdir(legalRoot)).sort(), filenames);
    for (const filename of filenames) {
      assert.deepEqual(
        await readFile(join(runtimeRoot, filename)),
        await readFile(join(legalRoot, filename)),
      );
    }
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

  const confinement = installNetworkConfinement();

  try {
    confinement.proveGuards([
      ...confinement.methodGuards,
      ...confinement.globalGuards,
    ]);
    await confinement.proveBuiltinEsmGuards();
    await confinement.proveModuleGuards();
    confinement.resetAttempts();

    const runtimeModule = await import(pathToFileURL(join(runtimeRoot, "pyodide.mjs")).href);
    assert.equal(runtimeModule.version, "314.0.3");
    const pyodide = await runtimeModule.loadPyodide({
      cdnUrl: runtimeRoot,
      indexURL: runtimeRoot,
      lockFileURL: join(runtimeRoot, "pyodide-lock.json"),
      packageBaseUrl: runtimeRoot,
    });
    const packageLoadingGuards = [
      confinement.guard(pyodide, "loadPackage", "pyodide.loadPackage"),
      confinement.guard(
        pyodide,
        "loadPackagesFromImports",
        "pyodide.loadPackagesFromImports",
      ),
    ];
    confinement.proveGuards(packageLoadingGuards);
    assert.equal(
      pyodide.runPython("import importlib.util; importlib.util.find_spec('micropip') is not None"),
      false,
      "micropip must not be available in the no-dependency local runtime",
    );
    confinement.resetAttempts();

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
    assert.deepEqual(
      confinement.attempts,
      [],
      "runtime or engine attempted an outbound or dynamic-package mechanism",
    );
  } finally {
    confinement.restore();
    await confinement.proveBuiltinEsmRestoration();
  }
});


test("executes the real wheel in a Node permission-confined process", async () => {
  const nodeMajor = Number.parseInt(process.versions.node.split(".", 1)[0], 10);
  assert.ok(
    nodeMajor >= 25,
    `browser security test requires Node 25+ permission capabilities; Node 26 is recommended (found ${process.version})`,
  );
  const prepared = prepareRuntime();
  assert.equal(prepared.status, 0, prepared.stderr);
  const sample = await readFile(join(repositoryRoot, "tests/fixtures/openapi/saas_api.json"), "utf8");
  const native = spawnSync(
    process.env.PYTHON ?? "python3",
    ["-c", "import sys; from heel.browser_review import review_openapi_json; sys.stdout.write(review_openapi_json(sys.stdin.read()))"],
    { cwd: repositoryRoot, input: sample, encoding: "utf8", timeout: 30_000 },
  );
  assert.equal(native.status, 0, native.stderr);

  const permissionArguments = [
    "--permission",
    `--allow-fs-read=${runtimeRoot}`,
    `--allow-fs-read=${join(appRoot, "node_modules/ws")}`,
    permissionRunner,
  ];
  for (const forbidden of [
    "--allow-addons",
    "--allow-child-process",
    "--allow-fs-write",
    "--allow-net",
    "--allow-wasi",
    "--allow-worker",
  ]) {
    assert.ok(
      permissionArguments.every((argument) => !argument.startsWith(forbidden)),
      `${forbidden} must not be granted to the browser security child`,
    );
  }
  const controlledEnvironment = {
    HEEL_PERMISSION_CHILD: "browser-security-test",
    LANG: "C",
    LC_ALL: "C",
    NODE_NO_WARNINGS: "1",
    TZ: "UTC",
  };
  assert.equal(controlledEnvironment.NODE_OPTIONS, undefined);
  assert.equal(controlledEnvironment.NODE_PATH, undefined);
  const outsideRoot = await realpath(await mkdtemp(join(tmpdir(), "heel-permission-outside-")));
  const outsideRead = join(outsideRoot, "read-sentinel.txt");
  const outsideWrite = join(outsideRoot, "write-must-fail.txt");
  const outsideAddon = join(outsideRoot, "addon-must-not-load.node");
  await writeFile(outsideRead, "outside read sentinel");
  await writeFile(outsideAddon, "outside addon sentinel");
  try {
    const confined = spawnSync(process.execPath, permissionArguments, {
      cwd: appRoot,
      encoding: "utf8",
      env: controlledEnvironment,
      input: JSON.stringify({
        expected: native.stdout,
        outsideAddon,
        outsideRead,
        outsideWrite,
        sample,
      }),
      timeout: 30_000,
    });
    assert.equal(confined.status, 0, confined.stderr);
    const result = JSON.parse(confined.stdout);
    assert.equal(result.actual, native.stdout);
    assert.deepEqual(result.bindingRequests, ["constants"]);
    assert.equal(result.cpythonVersion, "3.14.2");
    assert.deepEqual(result.denied, [
      "net",
      "child",
      "worker",
      "fs.read",
      "fs.write",
      "wasi",
      "addons",
    ]);
    assert.deepEqual(result.environment, controlledEnvironment);
    assert.equal(result.runtimeReadAllowed, true);
    assert.equal(result.wsReadAllowed, true);
    assert.equal(await readFile(outsideRead, "utf8"), "outside read sentinel");
    assert.equal(await readFile(outsideAddon, "utf8"), "outside addon sentinel");
    await assert.rejects(readFile(outsideWrite), { code: "ENOENT" });
  } finally {
    await rm(outsideRoot, { recursive: true, force: true });
  }
});
