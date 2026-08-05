// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { constants as fsConstants } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import net from "node:net";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { WASI } from "node:wasi";
import { Worker } from "node:worker_threads";


const appRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const runtimeRoot = join(appRoot, "public/heel-runtime");
const wsRoot = join(appRoot, "node_modules/ws");
const wheelName = "heel_browser-1.1.0-py3-none-any.whl";
const wheelPath = join(runtimeRoot, wheelName);


function assertDenied(label, operation, expectedCodes = ["ERR_ACCESS_DENIED"]) {
  try {
    const result = operation();
    assert.ok(
      expectedCodes.includes(result?.error?.code),
      `${label} was not denied by Node permissions`,
    );
    return result.error.code;
  } catch (error) {
    if (error?.code === "ERR_ASSERTION") throw error;
    assert.ok(expectedCodes.includes(error?.code), `${label}: ${error}`);
    return error.code;
  }
}


assert.ok(process.permission, "Node permission model must be active");
assert.equal(process.permission.has("fs.read", runtimeRoot), true);
assert.equal(process.permission.has("fs.read", wheelPath), true);
assert.equal(process.permission.has("fs.read", wsRoot), true);
assert.equal(process.permission.has("fs.write", appRoot), false);
for (const scope of ["addons", "child", "net", "wasi", "worker"]) {
  assert.equal(process.permission.has(scope), false, `${scope} permission must be denied`);
}
const expectedEnvironment = {
  HEEL_PERMISSION_CHILD: "browser-security-test",
  LANG: "C",
  LC_ALL: "C",
  NODE_NO_WARNINGS: "1",
  TZ: "UTC",
};
assert.equal(process.env.NODE_OPTIONS, undefined);
assert.equal(process.env.NODE_PATH, undefined);
for (const name of Object.keys(process.env)) {
  if (!(name in expectedEnvironment)) delete process.env[name];
}
assert.deepEqual({ ...process.env }, expectedEnvironment);

let input = "";
for await (const chunk of process.stdin) input += chunk;
const { expected, outsideAddon, outsideRead, outsideWrite, sample } = JSON.parse(input);
assert.equal(typeof expected, "string");
assert.equal(typeof outsideAddon, "string");
assert.equal(typeof outsideRead, "string");
assert.equal(typeof outsideWrite, "string");
assert.equal(typeof sample, "string");
assert.equal(process.permission.has("fs.read", outsideRead), false);
assert.equal(process.permission.has("fs.write", outsideWrite), false);

await assert.rejects(
  new Promise((resolveConnection, rejectConnection) => {
    const socket = net.connect({ host: "127.0.0.1", port: 9 });
    socket.once("connect", () => {
      socket.destroy();
      resolveConnection();
    });
    socket.once("error", rejectConnection);
  }),
  { code: "ERR_ACCESS_DENIED" },
);
assertDenied("child process", () => spawnSync(process.execPath, ["--version"]));
assertDenied("worker", () => new Worker("0", { eval: true }));
await assert.rejects(readFile(outsideRead), { code: "ERR_ACCESS_DENIED" });
await assert.rejects(
  writeFile(outsideWrite, "denied"),
  { code: "ERR_ACCESS_DENIED" },
);
assertDenied("WASI", () => new WASI({ version: "preview1" }));
assertDenied(
  "native addon",
  () => process.dlopen({ exports: {} }, outsideAddon),
  ["ERR_DLOPEN_DISABLED", "ERR_ACCESS_DENIED"],
);

const bindingRequests = [];
Object.defineProperty(process, "binding", {
  configurable: true,
  enumerable: true,
  value(name) {
    bindingRequests.push(name);
    assert.equal(name, "constants", `Pyodide requested forbidden process binding: ${name}`);
    return Object.freeze({ fs: fsConstants });
  },
  writable: false,
});
const runtimeModule = await import(pathToFileURL(join(runtimeRoot, "pyodide.mjs")).href);
assert.equal(runtimeModule.version, "314.0.3");
const pyodide = await runtimeModule.loadPyodide({
  cdnUrl: runtimeRoot,
  indexURL: runtimeRoot,
  lockFileURL: join(runtimeRoot, "pyodide-lock.json"),
  packageBaseUrl: runtimeRoot,
});
assert.equal(
  pyodide.runPython("import importlib.util; importlib.util.find_spec('micropip') is not None"),
  false,
);
const wheel = await readFile(wheelPath);
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
assert.equal(actual, expected);
assert.deepEqual(bindingRequests, ["constants"]);

process.stdout.write(JSON.stringify({
  actual,
  bindingRequests,
  cpythonVersion,
  denied: ["net", "child", "worker", "fs.read", "fs.write", "wasi", "addons"],
  environment: { ...process.env },
  runtimeReadAllowed: process.permission.has("fs.read", runtimeRoot),
  wsReadAllowed: process.permission.has("fs.read", wsRoot),
}));
