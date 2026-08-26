// SPDX-License-Identifier: LicenseRef-Heel-Commercial
/// <reference lib="webworker" />

import type {
  HeelPyodideRuntime,
  PyodideCallable,
  PyodideModule,
} from "../types/pyodide";


const WORKER_PROTOCOL_VERSION = "heel.browser-worker.v1";
const PYODIDE_VERSION = "314.0.3";
const ENGINE_VERSION = "1.2.0";
const RUNTIME_ROOT = "/heel-runtime/";
const RUNTIME_MODULE_URL = "/heel-runtime/pyodide.mjs";
const RUNTIME_MANIFEST_URL = "/heel-runtime/runtime-manifest.json";
const WHEEL_FILENAME = "heel_browser-1.2.0-py3-none-any.whl";
const WHEEL_URL = `${RUNTIME_ROOT}${WHEEL_FILENAME}`;
const MAX_BROWSER_INPUT_BYTES = 2 * 1024 * 1024;
const MAX_BROWSER_ANSWERS_BYTES = 64 * 1024;
// Keep fan-out bounded before the result crosses the structured-clone boundary.
const MAX_BROWSER_RESULT_BYTES = 4 * 1024 * 1024;
const MAX_WORKER_REQUEST_BYTES = MAX_BROWSER_INPUT_BYTES * 2 + MAX_BROWSER_ANSWERS_BYTES * 2 + 64 * 1024;
const MAX_FINDINGS_SYNC_BYTES = 256 * 1024;
const MAX_FINDINGS_REVIEW_BYTES = 4 * 1024 * 1024;
const REQUEST_ID = /^request_[0-9]+$/;
const PROJECT_REF = /^prj_[0-9a-f]{32}$/;
const SHA256 = /^[0-9a-f]{64}$/;

const PUBLIC_ERRORS: Readonly<Record<string, string>> = Object.freeze({
  invalid_json: "The OpenAPI input must be valid duplicate-free JSON.",
  invalid_document: "The OpenAPI input must be a supported JSON object.",
  invalid_unicode: "The submitted text contains invalid Unicode.",
  input_too_large: "The OpenAPI input exceeds the browser review size limit.",
  input_too_complex: "The OpenAPI input exceeds browser review complexity limits.",
  invalid_openapi: "The document is not a supported OpenAPI 3.0 or 3.1 document.",
  unsafe_document: "The OpenAPI document contains unsupported unsafe content.",
  invalid_answers: "The submitted review answers are invalid or unsupported.",
  review_failed: "The browser-local review could not be completed safely.",
  result_too_large: "The review result exceeds the safe browser limit.",
  engine_unavailable: "The browser-local review engine could not be started.",
  engine_not_ready: "The browser-local review engine is not ready.",
  review_in_progress: "A browser-local review is already running.",
  projection_failed: "The findings projection could not be completed safely.",
  projection_too_large: "The findings projection exceeds the browser limit.",
  operation_in_progress: "A browser-local Heel operation is already running.",
  worker_protocol: "The browser-local review received an invalid request.",
});

interface RuntimeManifest {
  heel: {
    engine_version: string;
    schema_version: string;
    wheel: { filename: string; sha256: string; size: number };
  };
  pyodide: { version: string };
  schema_version: string;
}

interface ReviewRequest {
  type: "review";
  protocol_version: typeof WORKER_PROTOCOL_VERSION;
  request_id: string;
  source: string;
  answers_json: string;
}

interface FindingsRequest {
  type: "project_findings";
  protocol_version: typeof WORKER_PROTOCOL_VERSION;
  request_id: string;
  review_json: string;
  project_ref: string;
  namespace_key: ArrayBuffer;
}


const scope = globalThis as unknown as DedicatedWorkerGlobalScope;
let bootstrapFetch: typeof fetch | null = scope.fetch.bind(scope);
let reviewEntry: PyodideCallable | null = null;
let findingsEntry: PyodideCallable | null = null;
let acceptingInput = false;
let reviewing = false;


function send(value: Record<string, unknown>): void {
  scope.postMessage(JSON.stringify(value));
}


function error(requestId: string, code: string): void {
  const safeCode = PUBLIC_ERRORS[code] ? code : "review_failed";
  send({
    type: "error",
    protocol_version: WORKER_PROTOCOL_VERSION,
    request_id: requestId,
    code: safeCode,
    message: PUBLIC_ERRORS[safeCode],
  });
}


function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}


function exactFields(value: Record<string, unknown>, fields: string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}


function parseManifest(value: unknown): RuntimeManifest {
  if (!isRecord(value) || value.schema_version !== "heel.browser-runtime-manifest.v1") {
    throw new Error("runtime manifest schema mismatch");
  }
  const heel = value.heel;
  const pyodide = value.pyodide;
  if (!isRecord(heel) || !isRecord(pyodide) || !isRecord(heel.wheel)) {
    throw new Error("runtime manifest shape mismatch");
  }
  if (
    heel.schema_version !== "heel.browser-engine-manifest.v1"
    || heel.engine_version !== ENGINE_VERSION
    || pyodide.version !== PYODIDE_VERSION
    || heel.wheel.filename !== WHEEL_FILENAME
    || !SHA256.test(String(heel.wheel.sha256))
    || !Number.isSafeInteger(heel.wheel.size)
    || (heel.wheel.size as number) <= 0
  ) throw new Error("runtime manifest pins do not match this worker");
  return value as unknown as RuntimeManifest;
}


async function fetchLocal(path: string): Promise<Response> {
  const fetcher = bootstrapFetch;
  if (fetcher === null || !path.startsWith(RUNTIME_ROOT) || path.includes("..")) {
    throw new Error("runtime asset path is unavailable");
  }
  const response = await fetcher(path, {
    cache: "no-store",
    credentials: "same-origin",
    redirect: "error",
  });
  if (!response.ok || response.redirected) throw new Error("runtime asset request failed");
  const responseUrl = new URL(response.url || path, scope.location.href);
  if (responseUrl.origin !== scope.location.origin || !responseUrl.pathname.startsWith(RUNTIME_ROOT)) {
    throw new Error("runtime asset escaped the same-origin boundary");
  }
  return response;
}


async function digestHex(payload: ArrayBuffer): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", payload);
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}


function denyCapability(): never {
  throw new Error("browser review capability is disabled");
}


function guardProperty(owner: Record<string, unknown>, name: string): void {
  Object.defineProperty(owner, name, {
    configurable: false,
    enumerable: false,
    value: denyCapability,
    writable: false,
  });
  if (owner[name] !== denyCapability) throw new Error(`could not guard ${name}`);
}


function guardAmbientNetwork(): void {
  const ambient = scope as unknown as Record<string, unknown>;
  for (const name of ["fetch", "XMLHttpRequest", "WebSocket", "EventSource"]) {
    guardProperty(ambient, name);
  }
}


function guardDynamicPackages(pyodide: HeelPyodideRuntime): void {
  const runtime = pyodide as unknown as Record<string, unknown>;
  for (const name of ["loadPackage", "loadPackagesFromImports"]) guardProperty(runtime, name);
}


function parseRequest(message: string): ReviewRequest {
  if (new TextEncoder().encode(message).byteLength > MAX_WORKER_REQUEST_BYTES) {
    throw new Error("worker request exceeds its transport bound");
  }
  let value: unknown;
  try {
    value = JSON.parse(message);
  } catch {
    throw new Error("worker request is invalid JSON");
  }
  if (!isRecord(value) || !exactFields(value, [
    "type", "protocol_version", "request_id", "source", "answers_json",
  ])) throw new Error("worker request shape mismatch");
  if (
    value.type !== "review"
    || value.protocol_version !== WORKER_PROTOCOL_VERSION
    || typeof value.request_id !== "string"
    || !REQUEST_ID.test(value.request_id)
    || typeof value.source !== "string"
    || typeof value.answers_json !== "string"
  ) throw new Error("worker request fields are invalid");
  if (new TextEncoder().encode(value.source).byteLength > MAX_BROWSER_INPUT_BYTES) {
    throw new Error("worker source exceeds its input bound");
  }
  if (new TextEncoder().encode(value.answers_json).byteLength > MAX_BROWSER_ANSWERS_BYTES) {
    throw new Error("worker answers exceed their input bound");
  }
  return value as unknown as ReviewRequest;
}


function parseFindingsRequest(value: unknown): FindingsRequest {
  if (!isRecord(value) || !exactFields(value, [
    "type", "protocol_version", "request_id", "review_json", "project_ref", "namespace_key",
  ])) throw new Error("worker findings request shape mismatch");
  if (
    value.type !== "project_findings"
    || value.protocol_version !== WORKER_PROTOCOL_VERSION
    || typeof value.request_id !== "string"
    || !REQUEST_ID.test(value.request_id)
    || typeof value.review_json !== "string"
    || typeof value.project_ref !== "string"
    || !PROJECT_REF.test(value.project_ref)
    || !(value.namespace_key instanceof ArrayBuffer)
    || value.namespace_key.byteLength !== 32
  ) throw new Error("worker findings request fields are invalid");
  if (new TextEncoder().encode(value.review_json).byteLength > MAX_FINDINGS_REVIEW_BYTES) {
    throw new Error("worker findings review exceeds its input bound");
  }
  return value as unknown as FindingsRequest;
}


function bytesHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}


function projectFindings(request: FindingsRequest): void {
  const namespaceKey = new Uint8Array(request.namespace_key);
  let ownsOperation = false;
  try {
    if (reviewing) {
      error(request.request_id, "operation_in_progress");
      return;
    }
    const entry = findingsEntry;
    if (!acceptingInput || entry === null) {
      error(request.request_id, "engine_not_ready");
      return;
    }
    reviewing = true;
    ownsOperation = true;
    const response = entry(request.review_json, request.project_ref, bytesHex(namespaceKey));
    if (typeof response !== "string" || response.length < 2 || response[0] !== "R") {
      error(request.request_id, "projection_failed");
      return;
    }
    const requestJson = response.slice(1);
    if (new TextEncoder().encode(requestJson).byteLength > MAX_FINDINGS_SYNC_BYTES) {
      error(request.request_id, "projection_too_large");
      return;
    }
    send({
      type: "findings_result",
      protocol_version: WORKER_PROTOCOL_VERSION,
      request_id: request.request_id,
      request_json: requestJson,
    });
  } catch {
    error(request.request_id, "projection_failed");
  } finally {
    namespaceKey.fill(0);
    if (ownsOperation) reviewing = false;
  }
}


async function boot(): Promise<void> {
  try {
    const manifestResponse = await fetchLocal(RUNTIME_MANIFEST_URL);
    const manifestText = await manifestResponse.text();
    const manifest = parseManifest(JSON.parse(manifestText));
    const wheelResponse = await fetchLocal(WHEEL_URL);
    const wheel = await wheelResponse.arrayBuffer();
    if (wheel.byteLength !== manifest.heel.wheel.size) throw new Error("Heel wheel size mismatch");
    if (await digestHex(wheel) !== manifest.heel.wheel.sha256) throw new Error("Heel wheel digest mismatch");

    const runtimeModule = await import(/* @vite-ignore */ RUNTIME_MODULE_URL) as PyodideModule;
    if (runtimeModule.version !== PYODIDE_VERSION) throw new Error("Pyodide module version mismatch");
    const pyodide = await runtimeModule.loadPyodide({
      cdnUrl: RUNTIME_ROOT,
      indexURL: RUNTIME_ROOT,
      lockFileURL: `${RUNTIME_ROOT}pyodide-lock.json`,
      packageBaseUrl: RUNTIME_ROOT,
    });
    const sitePackages = pyodide.runPython("import sysconfig; sysconfig.get_paths()['purelib']");
    if (typeof sitePackages !== "string") throw new Error("Python package path is unavailable");
    pyodide.unpackArchive(new Uint8Array(wheel), "wheel", { extractDir: sitePackages });
    pyodide.runPython(`
from heel.browser_review import BrowserReviewError as _HeelBrowserReviewError
from heel.browser_review import review_openapi_json as _heel_review_openapi_json
from heel.findings_sync import project_findings_sync as _heel_project_findings_sync
from heel.review_contract import stable_json as _heel_stable_json
import json as _heel_json
def _heel_browser_entry(source, answers_json):
    try:
        return "R" + _heel_review_openapi_json(source, answers_json)
    except _HeelBrowserReviewError as error:
        return "E" + _heel_stable_json({"code": error.code})
def _heel_findings_entry(review_json, project_ref, namespace_key_hex):
    try:
        review = _heel_json.loads(review_json)
        key = bytes.fromhex(namespace_key_hex)
        return "R" + _heel_stable_json(_heel_project_findings_sync(review, project_ref, key))
    except Exception:
        return "E" + _heel_stable_json({"code": "projection_failed"})
`);
    const callable = pyodide.globals.get("_heel_browser_entry");
    pyodide.globals.delete("_heel_browser_entry");
    if (typeof callable !== "function") throw new Error("Heel browser entry point is unavailable");
    reviewEntry = callable as PyodideCallable;
    const findingsCallable = pyodide.globals.get("_heel_findings_entry");
    pyodide.globals.delete("_heel_findings_entry");
    if (typeof findingsCallable !== "function") {
      throw new Error("Heel findings entry point is unavailable");
    }
    findingsEntry = findingsCallable as PyodideCallable;

    guardDynamicPackages(pyodide);
    guardAmbientNetwork();
    bootstrapFetch = null;
    acceptingInput = true;
    send({ type: "ready", protocol_version: WORKER_PROTOCOL_VERSION });
  } catch {
    acceptingInput = false;
    bootstrapFetch = null;
    send({
      type: "fatal",
      protocol_version: WORKER_PROTOCOL_VERSION,
      code: "engine_unavailable",
      message: PUBLIC_ERRORS.engine_unavailable,
    });
  }
}


scope.onmessage = (event: MessageEvent<unknown>) => {
  if (isRecord(event.data) && event.data.type === "project_findings") {
    let findingsRequest: FindingsRequest;
    try {
      findingsRequest = parseFindingsRequest(event.data);
    } catch {
      if (event.data.namespace_key instanceof ArrayBuffer) {
        new Uint8Array(event.data.namespace_key).fill(0);
      }
      error("request_0", "worker_protocol");
      return;
    }
    projectFindings(findingsRequest);
    return;
  }
  if (typeof event.data !== "string") {
    error("request_0", "worker_protocol");
    return;
  }
  if (!acceptingInput || reviewEntry === null) {
    error("request_0", "engine_not_ready");
    return;
  }
  let request: ReviewRequest;
  try {
    request = parseRequest(event.data);
  } catch {
    error("request_0", "worker_protocol");
    return;
  }
  if (reviewing) {
    error(request.request_id, "review_in_progress");
    return;
  }
  reviewing = true;
  try {
    const response = reviewEntry(request.source, request.answers_json);
    if (typeof response !== "string" || response.length < 2) {
      error(request.request_id, "review_failed");
      return;
    }
    if (response[0] === "E") {
      let failure: unknown;
      try {
        failure = JSON.parse(response.slice(1));
      } catch {
        error(request.request_id, "review_failed");
        return;
      }
      const code = isRecord(failure) && typeof failure.code === "string"
        ? failure.code
        : "review_failed";
      error(request.request_id, code);
      return;
    }
    if (response[0] !== "R") {
      error(request.request_id, "review_failed");
      return;
    }
    if (new TextEncoder().encode(response).byteLength - 1 > MAX_BROWSER_RESULT_BYTES) {
      error(request.request_id, "result_too_large");
      return;
    }
    const resultJson = response.slice(1);
    send({
      type: "result",
      protocol_version: WORKER_PROTOCOL_VERSION,
      request_id: request.request_id,
      result_json: resultJson,
    });
  } catch {
    error(request.request_id, "review_failed");
  } finally {
    reviewing = false;
  }
};


void boot();
