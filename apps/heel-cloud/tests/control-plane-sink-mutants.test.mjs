// SPDX-License-Identifier: LicenseRef-Heel-Commercial

// H0X E4: an executable differential corpus at the private control-plane sink. Each corpus entry is
// one recorded or re-expressed source change; it is judged by what the composed Worker observably
// does at the sink, never by whether an analyzer recognizes its spelling. A deviation is a change in
// any of: HTTP status; count of binding calls; for each binding call its URL, method, redirect mode,
// header multimap and delivered body bytes or body-read rejection; count of asset, page-handler and
// global fetch calls (H0X design section 5).

import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";
import ts from "typescript";


const appRoot = fileURLToPath(new URL("../", import.meta.url));
const FILES = {
  index: "worker/index.ts",
  dispatch: "worker/control-plane-dispatch.ts",
  config: "build/deployment-config.ts",
};
// Bare and extensionless specifiers resolve to the copied sources or to observing stubs.
const SPECIFIERS = new Map([
  ["vinext/server/image-optimization", "../stubs/image-optimization.js"],
  ["vinext/server/app-router-entry", "../stubs/app-router-entry.js"],
  ["../build/deployment-config", "../build/deployment-config.js"],
  ["./control-plane-dispatch", "./control-plane-dispatch.js"],
]);
const STUBS = {
  "package.json": '{"type":"module"}\n',
  "stubs/image-optimization.js": [
    "export const DEFAULT_DEVICE_SIZES = [];",
    "export const DEFAULT_IMAGE_SIZES = [];",
    'export async function handleImageOptimization(_request, options) { return options.fetchAsset("/_next/static/media/probe.png"); }',
    "",
  ].join("\n"),
  "stubs/app-router-entry.js": "export default { fetch: (...values) => globalThis.__heelSinkObserver.page(...values) };\n",
};

// Reserved example/test names are syntax fixtures, not owned domains.
const CONFIGURED_ORIGINS = ["https://heel.example", "https://control-two.heel.test"];
const edge = "a".repeat(43);
const clientAddress = "203.0.113.4";
const workspace = "ws_0123456789abcdef";
const project = `prj_${"a".repeat(32)}`;
const review = `synrev_${"b".repeat(32)}`;
const runner = "runr_0123456789abcdef0123456789abcdef";
const run = `crun_${"c".repeat(32)}`;
const environment = `env_${"d".repeat(32)}`;
const binding = `rcb_${"e".repeat(32)}`;
const pairing = `pending_${"f".repeat(32)}`;
const rotation = `rotation_${"9".repeat(32)}`;
const runnerProof = {
  "X-Heel-Runner-Id": runner, "X-Heel-Runner-Key-Id": "key", "X-Heel-Runner-Timestamp-Ms": "1",
  "X-Heel-Runner-Nonce": "nonce", "X-Heel-Runner-Sequence": "1", "X-Heel-Runner-Signature": "sig",
};
const resyncProof = {
  "X-Heel-Runner-Id": runner, "X-Heel-Runner-Key-Id": "key", "X-Heel-Runner-Timestamp-Ms": "1",
  "X-Heel-Runner-Signature": "sig",
};
const session = { Cookie: "__Host-heel_session=private" };
const destinationNoise = {
  Host: "attacker.invalid",
  Forwarded: "for=192.0.2.1;host=attacker.invalid;proto=https",
  "X-Forwarded-Host": "attacker.invalid",
  "X-Forwarded-Proto": "http",
  "X-Forwarded-Port": "444",
};
const REFUSED_ORIGINS = [
  undefined, "", " https://heel.example", "https://heel.example ", "HTTPS://heel.example", "https://Heel.example",
  "http://heel.example", "http://127.0.0.1:8787", "http://localhost:8787", "https://heel.example/", "https://heel.example/v1",
  "https://heel.example?", "https://heel.example#", "https://user@heel.example", "https://heel.example:443",
  "https://heel.example:8443", "https://127.0.0.1", "https://0x7f000001", "https://[::1]", "https://heel",
  "https://heel.example.", "https://heel_ingress.example", "https://-heel.example", "https://heel%2eexample",
  "https://hëel.example", "https://localhost", "https://heel.localhost", "https://heel.local",
  "https://heel-control-plane.internal", "https://cp.heel.internal", 443,
];

function routeCases(origin) {
  const browser = { ...session, Origin: origin, "Sec-Fetch-Site": "same-origin" };
  return [
    { label: "account signup", method: "POST", path: "/v1/signup", headers: { "CF-Connecting-IP": clientAddress }, body: "{}", clientKey: true },
    { label: "account login", method: "POST", path: "/v1/login", headers: {}, body: "{}" },
    { label: "account me", method: "GET", path: "/v1/me", headers: session },
    { label: "account logout", method: "POST", path: "/v1/logout", headers: session, body: "{}" },
    { label: "device start", method: "POST", path: "/v1/device/start", headers: { "CF-Connecting-IP": clientAddress }, body: "{}", clientKey: true },
    ...["poll", "token", "refresh", "revoke"].map((route) => (
      { label: `device ${route}`, method: "POST", path: `/v1/device/${route}`, headers: {}, body: "{}" }
    )),
    { label: "device verify", method: "POST", path: "/v1/device/verify", headers: browser, body: "{}", human: true },
    { label: "findings projects list", method: "GET", path: `/v1/workspaces/${workspace}/projects`, headers: session },
    { label: "findings projects create", method: "POST", path: `/v1/workspaces/${workspace}/projects`, headers: { Authorization: "Bearer heel_sk_private" }, body: "{}" },
    { label: "findings namespace key", method: "GET", path: `/v1/workspaces/${workspace}/projects/${project}/namespace-key`, headers: session },
    { label: "findings approve", method: "POST", path: `/v1/workspaces/${workspace}/projects/${project}/findings-sync/approve`, headers: session, body: "{}" },
    { label: "findings sync", method: "POST", path: `/v1/workspaces/${workspace}/projects/${project}/findings-sync`, headers: { ...session, "Idempotency-Key": `fs1-${"0".repeat(64)}` }, body: "{}" },
    { label: "findings reviews", method: "GET", path: `/v1/workspaces/${workspace}/projects/${project}/reviews`, headers: session },
    { label: "findings review detail", method: "GET", path: `/v1/workspaces/${workspace}/projects/${project}/reviews/${review}`, headers: session },
    { label: "runner pairing exchange", method: "POST", path: "/v1/runner-pairings/exchange", headers: {}, body: "{}" },
    { label: "runner pairing activate", method: "POST", path: `/v1/runner-pairings/${pairing}/activate`, headers: {}, body: "{}" },
    { label: "runner rotation poll", method: "POST", path: `/v1/runner-rotations/${rotation}/poll`, headers: {}, body: "{}" },
    { label: "runner pairing manage", method: "GET", path: `/v1/workspaces/${workspace}/runner-pairings`, headers: browser, human: true },
    { label: "runner rotation start", method: "POST", path: `/v1/workspaces/${workspace}/runners/${runner}/rotate`, headers: browser, body: "{}", human: true },
    { label: "runner revoke", method: "POST", path: `/v1/workspaces/${workspace}/runners/${runner}/revoke`, headers: browser, body: "{}", human: true },
    { label: "runner claim", method: "POST", path: `/v1/workspaces/${workspace}/runners/${runner}/claim`, headers: runnerProof, body: "{}", runnerProtocol: true },
    { label: "runner heartbeat", method: "POST", path: `/v1/workspaces/${workspace}/runners/${runner}/runs/${run}/heartbeat`, headers: runnerProof, body: "{}", runnerProtocol: true },
    { label: "runner context list", method: "POST", path: `/v1/workspaces/${workspace}/runners/${runner}/contexts/list`, headers: runnerProof, body: "{}", runnerProtocol: true },
    { label: "runner context claim", method: "POST", path: `/v1/workspaces/${workspace}/runners/${runner}/contexts/${binding}/claim`, headers: runnerProof, body: "{}", runnerProtocol: true },
    { label: "runner result projection", method: "POST", path: `/v1/workspaces/${workspace}/runners/${runner}/runs/${run}/result-projection`, headers: runnerProof, body: "{}", runnerProtocol: true },
    { label: "runner resync", method: "POST", path: `/v1/workspaces/${workspace}/runners/${runner}/resync/start`, headers: resyncProof, body: "{}", runnerProtocol: true },
    { label: "canary run", method: "GET", path: `/v1/workspaces/${workspace}/projects/${project}/canary-runs/${run}`, headers: session },
    { label: "canary approve", method: "POST", path: `/v1/workspaces/${workspace}/projects/${project}/canary-runs/${run}/approve`, headers: { ...browser, "Idempotency-Key": `ca1-${"1".repeat(64)}`, "If-Heel-Control-Generation": "3" }, body: "{}", human: true },
    { label: "runner context bindings", method: "POST", path: `/v1/workspaces/${workspace}/projects/${project}/runner-context-bindings`, headers: browser, body: "{}", human: true },
    { label: "environments list", method: "GET", path: `/v1/workspaces/${workspace}/projects/${project}/environments`, headers: session },
    { label: "environment check", method: "POST", path: `/v1/workspaces/${workspace}/projects/${project}/environments/${environment}/check`, headers: browser, body: "{}", human: true },
  ];
}

function route(origin, label) {
  return routeCases(origin).find((candidate) => candidate.label === label);
}

function incoming(routeCase, { base = "https://request-host.invalid", extra = {}, declared, query = "", body = routeCase.body } = {}) {
  const headers = { ...routeCase.headers, ...extra };
  if (routeCase.method === "POST") {
    headers["Content-Type"] = "application/json";
    headers["Content-Length"] = declared ?? String(Buffer.byteLength(body ?? ""));
  }
  return new Request(`${base}/api/control-plane${routeCase.path}${query}`, {
    method: routeCase.method, headers, ...(routeCase.method === "POST" && body !== null ? { body } : {}),
  });
}

function noise(routeCase) {
  const extra = routeCase.runnerProtocol
    ? { ...destinationNoise }
    : { ...destinationNoise, "X-Heel-Internal-Origin": "https://attacker.invalid" };
  if (!routeCase.human) extra.Origin = "https://attacker.invalid";
  return extra;
}

function upstreamResponse(upstream) {
  const pathname = new URL(upstream.url).pathname;
  const setCookie = pathname === "/v1/logout"
    ? "heel_session=; Max-Age=0; Path=/"
    : pathname === "/v1/signup" || pathname === "/v1/login"
      ? "heel_session=private; HttpOnly; SameSite=Lax; Path=/"
      : null;
  return new Response("{}", {
    headers: { "Content-Type": "application/json", ...(setCookie === null ? {} : { "Set-Cookie": setCookie }) },
  });
}

// The fixed request set. Each case names the configuration and upstream behavior it runs under.
function requestSet() {
  const [origin] = CONFIGURED_ORIGINS;
  const cases = [];
  for (const configured of CONFIGURED_ORIGINS) {
    for (const routeCase of routeCases(configured)) {
      cases.push({ label: `route ${configured} ${routeCase.label}`, origin: configured, routeCase, request: () => incoming(routeCase, { extra: noise(routeCase) }) });
    }
  }
  for (const routeCase of routeCases(origin).filter(({ method }) => method === "POST")) {
    for (const declared of ["3", "1"]) {
      cases.push({ label: `length ${declared} ${routeCase.label}`, origin, routeCase, declared, request: () => incoming(routeCase, { base: origin, declared }) });
    }
  }
  for (const label of ["account me", "account login"]) {
    const routeCase = route(origin, label);
    cases.push({ label: `redirect ${label}`, origin, routeCase, respond: "redirect", request: () => incoming(routeCase, { base: origin }) });
  }
  const reviews = route(origin, "findings reviews");
  cases.push({ label: "binding throws", origin, routeCase: reviews, respond: "throw", request: () => incoming(reviews, { base: origin }) });
  const login = route(origin, "account login");
  cases.push({ label: "declared body absent", origin, request: () => incoming(login, { base: origin, declared: "2", body: null }) });
  cases.push({ label: "zero-length body", origin, routeCase: login, declared: "0", request: () => incoming(login, { base: origin, body: null, declared: "0" }) });
  // Configuration values are built fresh for every observation: a mutant may write to the
  // configuration it receives, and that write must not reach another variant.
  for (const [label, value] of [
    ["missing", () => undefined], ["null", () => null], ["empty object", () => ({})],
    ["missing fetch", () => ({ fetch: undefined })], ["non-callable fetch", () => ({ fetch: 43 })], ["number", () => 43],
  ]) {
    for (const routeLabel of ["account me", "runner claim"]) {
      const routeCase = route(origin, routeLabel);
      cases.push({ label: `binding ${label} ${routeLabel}`, origin, configuration: () => ({ CONTROL_PLANE: value() }), request: () => incoming(routeCase, { base: origin }) });
    }
  }
  // A malformed binding must win over every 400-producing request check (fixed 503 ordering).
  const refusedRequests = [
    ["foreign human Origin", () => incoming(route(origin, "device verify"), { base: origin, extra: { Origin: "https://attacker.invalid" } })],
    ["runner proof missing", () => incoming({ ...route(origin, "runner claim"), headers: {} }, { base: origin })],
    ["wrong content type", () => new Request(`${origin}/api/control-plane/v1/login`, {
      method: "POST", body: "{}", headers: { "Content-Type": "text/plain", "Content-Length": "2" },
    })],
    ["client address missing", () => incoming({ ...route(origin, "account signup"), headers: {} }, { base: origin })],
  ];
  for (const [label, value] of [
    ["missing", () => undefined], ["null", () => null], ["empty object", () => ({})], ["non-callable fetch", () => ({ fetch: 43 })],
  ]) {
    for (const [requestLabel, request] of refusedRequests) {
      cases.push({ label: `binding ${label} refused ${requestLabel}`, origin, configuration: () => ({ CONTROL_PLANE: value() }), request });
    }
  }
  for (const [label, value] of [
    ["missing", () => undefined], ["number", () => 43], ["empty", () => ""], ["short", () => "short"],
    ["malformed", () => `${edge}=`], ["String object", () => new String(edge)],
  ]) {
    const routeCase = route(origin, "runner claim");
    cases.push({ label: `secret ${label}`, origin, configuration: () => ({ CONTROL_PLANE_EDGE_SECRET: value() }), request: () => incoming(routeCase, { base: origin }) });
  }
  for (const refused of REFUSED_ORIGINS) {
    for (const routeLabel of ["account me", "device verify", "runner revoke", "runner claim"]) {
      const routeCase = route(typeof refused === "string" ? refused : "", routeLabel);
      cases.push({ label: `refused origin ${JSON.stringify(refused)} ${routeLabel}`, origin, configuration: () => ({ PUBLIC_ORIGIN: refused }), request: () => incoming(routeCase, { base: origin }) });
    }
  }
  const me = route(origin, "account me");
  cases.push({ label: "caller query", origin, request: () => incoming(me, { base: origin, query: "?a" }) });
  cases.push({ label: "unlisted route", origin, request: () => new Request(`${origin}/api/control-plane/v1/admin`) });
  cases.push({ label: "foreign human origin", origin, request: () => incoming(route(origin, "device verify"), { base: origin, extra: { Origin: "https://attacker.invalid" } }) });
  cases.push({ label: "runner proof missing", origin, request: () => incoming({ ...route(origin, "runner claim"), headers: {} }, { base: origin }) });
  cases.push({ label: "page", origin, request: () => new Request("https://request-host.invalid/dashboard") });
  cases.push({ label: "image", origin, request: () => new Request("https://request-host.invalid/_vinext/image?url=%2Fprobe.png&w=64&q=75") });
  return cases;
}

// The absolute expected observation for the unmodified sources, derived from the route contract.
function expectedHeaders(routeCase, origin, declared) {
  const headers = { "x-heel-edge-auth": edge };
  if (routeCase.runnerProtocol) {
    for (const [name, value] of Object.entries(routeCase.headers)) headers[name.toLowerCase()] = value;
  } else {
    if (routeCase.headers.Cookie !== undefined) headers.cookie = "heel_session=private";
    if (routeCase.headers.Authorization !== undefined) headers.authorization = routeCase.headers.Authorization;
    if (routeCase.headers["Idempotency-Key"] !== undefined) headers["idempotency-key"] = routeCase.headers["Idempotency-Key"];
    if (routeCase.headers["If-Heel-Control-Generation"] !== undefined) headers["if-heel-control-generation"] = routeCase.headers["If-Heel-Control-Generation"];
    if (routeCase.human) {
      headers.origin = origin;
      headers["x-heel-internal-origin"] = "same-origin";
    }
  }
  if (routeCase.method === "POST") {
    headers["content-type"] = "application/json";
    headers["content-encoding"] = "identity";
    headers["content-length"] = declared ?? String(Buffer.byteLength(routeCase.body));
    if (routeCase.clientKey) {
      headers["x-heel-client-key"] = createHmac("sha256", edge)
        .update(`heel-client-rate-limit\0${routeCase.path}\0${clientAddress}`).digest("hex");
    }
  }
  return Object.entries(headers).sort(([a], [b]) => a.localeCompare(b));
}

function expectedObservation(testCase) {
  const quiet = { asset: 0, page: 0, globalFetch: 0 };
  const call = (body) => [{
    url: `${testCase.origin}${testCase.routeCase.path}`,
    method: testCase.routeCase.method,
    redirect: "manual",
    headers: expectedHeaders(testCase.routeCase, testCase.origin, testCase.declared),
    body,
  }];
  const sentBody = testCase.routeCase?.method === "POST" && testCase.declared !== "0" ? testCase.routeCase.body : "";
  if (testCase.label.startsWith("route ")) return { status: 200, binding: call(sentBody), ...quiet };
  if (testCase.label.startsWith("length ")) return { status: 502, binding: call({ rejected: "TypeError" }), ...quiet };
  if (testCase.label.startsWith("redirect ") || testCase.label === "binding throws") return { status: 502, binding: call(sentBody), ...quiet };
  if (testCase.label === "zero-length body") return { status: 200, binding: call(""), ...quiet };
  if (testCase.label.startsWith("binding ") || testCase.label.startsWith("secret ") || testCase.label.startsWith("refused origin ")) {
    return { status: 503, binding: [], ...quiet };
  }
  if (testCase.label === "unlisted route") return { status: 404, binding: [], ...quiet };
  if (testCase.label === "page") return { status: 200, binding: [], asset: 0, page: 1, globalFetch: 0 };
  if (testCase.label === "image") return { status: 404, binding: [], asset: 1, page: 0, globalFetch: 0 };
  return { status: 400, binding: [], ...quiet };
}

// Globals a mutant may replace; each is restored after every load so mutants cannot leak.
const pipeThroughDescriptor = Object.getOwnPropertyDescriptor(ReadableStream.prototype, "pipeThrough");
const savedGlobals = { fetch: globalThis.fetch, Request: globalThis.Request, URL: globalThis.URL, ReadableStream: globalThis.ReadableStream };

class EnforcedLengthStream extends TransformStream {
  constructor(expected) {
    let received = 0;
    super({
      transform(chunk, controller) {
        received += chunk.byteLength;
        if (received > expected) throw new TypeError("body exceeds the declared length");
        controller.enqueue(chunk);
      },
      flush() {
        if (received !== expected) throw new TypeError("body is shorter than the declared length");
      },
    });
  }
}

function restoreGlobals() {
  Object.defineProperty(ReadableStream.prototype, "pipeThrough", pipeThroughDescriptor);
  Object.assign(globalThis, savedGlobals, { FixedLengthStream: EnforcedLengthStream });
  assert.equal(ReadableStream.prototype.pipeThrough, pipeThroughDescriptor.value);
}

async function observe(worker, testCase) {
  const calls = { binding: [], asset: 0, page: 0, globalFetch: 0 };
  globalThis.__heelSinkObserver = { page: async () => { calls.page += 1; return new Response("page"); } };
  globalThis.fetch = async () => {
    calls.globalFetch += 1;
    throw new Error("public fetch must never carry control-plane traffic");
  };
  const env = {
    ASSETS: { fetch: async () => { calls.asset += 1; return new Response("asset", { status: 404 }); } },
    IMAGES: { input: () => { throw new Error("image transform is not used by the sink corpus"); } },
    PUBLIC_ORIGIN: testCase.origin,
    CONTROL_PLANE_EDGE_SECRET: edge,
    CONTROL_PLANE: {
      async fetch(upstream) {
        const record = {
          url: upstream.url,
          method: upstream.method,
          redirect: upstream.redirect,
          headers: [...upstream.headers].sort(([a], [b]) => a.localeCompare(b)),
          body: "",
        };
        calls.binding.push(record);
        try {
          record.body = new TextDecoder().decode(await upstream.arrayBuffer());
        } catch (error) {
          record.body = { rejected: error?.name ?? "unknown" };
          throw error;
        }
        if (testCase.respond === "throw") throw new Error("private-upstream-marker");
        if (testCase.respond === "redirect") {
          return new Response(null, { status: 307, headers: { Location: "https://attacker.invalid/" } });
        }
        return upstreamResponse(upstream);
      },
    },
    ...testCase.configuration?.(),
  };
  let status;
  try {
    status = (await worker.fetch(testCase.request(), env, { waitUntil() {}, passThroughOnException() {} })).status;
  } catch (error) {
    status = `threw ${error?.name ?? "unknown"}`;
  }
  return { status, ...calls };
}

let loads = 0;
async function load(root, sources) {
  const directory = join(root, `variant-${loads += 1}`);
  const files = {
    "worker/index.js": sources.index,
    "worker/control-plane-dispatch.js": sources.dispatch,
    "build/deployment-config.js": sources.config,
  };
  for (const [name, text] of Object.entries(STUBS)) {
    await mkdir(dirname(join(directory, name)), { recursive: true });
    await writeFile(join(directory, name), text);
  }
  for (const [name, text] of Object.entries(files)) {
    await mkdir(dirname(join(directory, name)), { recursive: true });
    const output = ts.transpileModule(text, {
      compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext },
    }).outputText;
    await writeFile(join(directory, name), output.replace(
      /(\bfrom\s*|\bimport\s*\(\s*)(["'])([^"']+)\2/g,
      (match, prefix, quote, specifier) => (
        SPECIFIERS.has(specifier) ? `${prefix}${quote}${SPECIFIERS.get(specifier)}${quote}` : match
      ),
    ));
  }
  return (await import(`${pathToFileURL(join(directory, "worker/index.js")).href}?v=${loads}`)).default;
}

async function record(root, sources, cases) {
  restoreGlobals();
  let worker;
  try {
    worker = await load(root, sources);
  } catch (error) {
    restoreGlobals();
    return { load: error?.code ?? error?.name ?? "unknown" };
  }
  const observations = {};
  for (const testCase of cases) observations[testCase.label] = await observe(worker, testCase);
  restoreGlobals();
  return observations;
}

function deviation(candidate, mutated) {
  if (mutated.load !== undefined) return { load: mutated.load };
  const fields = new Set();
  const cases = [];
  for (const [label, observed] of Object.entries(candidate)) {
    const changed = Object.keys(observed).filter((field) => (
      JSON.stringify(observed[field]) !== JSON.stringify(mutated[label][field])
    ));
    if (changed.length > 0) {
      cases.push(label);
      for (const field of changed) fields.add(field);
    }
  }
  return cases.length === 0 ? null : { cases: cases.length, fields: [...fields].sort(), examples: cases.slice(0, 3) };
}

// Anchors in the reviewed layout.
const CALL = "  const outcome = await dispatchControlPlane({";
const CALL_END = "    body: request.body,\n  });\n";
const ENTRY = "      return proxyControlPlane(request, env, csp, upstreamPath);";
const EXPORT = "export default worker;";
const SECRET = '  if (typeof env.CONTROL_PLANE_EDGE_SECRET !== "string") {\n    return proxyError(503, "control plane unavailable", csp);\n  }\n  const edgeAuthSecret = env.CONTROL_PLANE_EDGE_SECRET.trim();';
const ORIGIN = "  const controlPlaneOrigin = canonicalPublicOrigin(env.PUBLIC_ORIGIN);";
const WORKER_GUARD = '  if (\n    env.CONTROL_PLANE === undefined\n    || env.CONTROL_PLANE === null\n    || typeof env.CONTROL_PLANE.fetch !== "function"\n  ) {\n    return proxyError(503, "control plane unavailable", csp);\n  }\n';
const REFUSAL = '  if (controlPlaneOrigin === null) return proxyError(503, "control plane unavailable", csp);';
const IMPORT = 'import { canonicalPublicOrigin } from "../build/deployment-config";';
const URL_LINE = "  const url = new URL(input.upstreamPath, origin);";
const SINK = "    const response = await input.binding.fetch(new Request(url, init));";
const GUARD = '  if (input.method === "POST") {';
const BINDING_GUARD_END = '    return { kind: "unavailable" };\n  }\n';
const DISPATCH_END = '  } catch {\n    return { kind: "failed" };\n  }\n}\n';
const SUBSTITUTE = 'supplied[["CONTROL", "PLANE"].join("_")] = supplied.ASSETS;';
const SKIP_PIPE = "pipeThrough = function () { return this; };";
const LOCAL_STREAM = "const FixedLengthStream = class extends TransformStream { constructor(_length: number) { super(); } };";

const beforeCall = (code) => ["index", CALL, `  ${code}\n${CALL}`];
const beforeEntry = (code) => ["index", ENTRY, `      ${code}\n${ENTRY}`];
const beforeExport = (code) => ["index", EXPORT, `${code}\n\n${EXPORT}`];
const afterUrl = (code) => ["dispatch", URL_LINE, `${URL_LINE}\n  ${code}`];
const beforeUrl = (code) => ["dispatch", URL_LINE, `  ${code}\n${URL_LINE}`];
const beforeSink = (code) => ["dispatch", SINK, `    ${code}\n${SINK}`];

const H0AR = "H0AR original F1 survivor";
const H0AR1 = "H0AR1 matrix (retired)";
const H0AR1R = "H0AR1R exact receiver/flow residual (H0AR2 matrix, retired)";
const H0AR2 = "H0AR2 matrix (retired)";
const H0AR3 = "H0AR3 matrix (retired)";
const D02 = "H0AR2RDB d02 exact lead";
const D03 = "H0AR2RDB d03 exact lead";
const C04 = "H0AR3RDB c04 exact challenge";
const H0A = "H0A first matrix dataflow case (retired)";
const H0X = "H0X design re-created shape";
const H0X_ORDER = "H0X implementation 5fc14fb ordering regression";
const DEFENSE = "the Worker's own guard refuses every malformed binding first, so the module recheck is defense in depth";

// [label, kind, sources, edits, note]. kind: "mutant" must deviate; "neutral" is a retired analyzer case
// with no sink-boundary behavior change in this layout and must be identical (reported to Astra);
// "control" must be identical.
const CORPUS = [
  // H0AR original survivors and the H0X re-created shapes.
  ["caller URL host", "mutant", [H0AR, H0AR1, H0X], [beforeCall("upstreamPath = `//${new URL(request.url).hostname}${upstreamPath}`;")], "re-expressed: the caller host can reach the URL only through the explicit upstreamPath input"],
  ["caller Host header", "mutant", [H0AR, H0AR1], [beforeCall('upstreamPath = `//${request.headers.get("Host") ?? "attacker.invalid"}${upstreamPath}`;')], "re-expressed through the explicit upstreamPath input"],
  ["caller query", "neutral", [H0AR, H0AR1, H0A], [beforeCall("upstreamPath = upstreamPath + new URL(request.url).search;")], "the entry refuses every non-empty query before the proxy, so the search is always empty"],
  ["fixed path", "mutant", [H0AR, H0AR1], [afterUrl('url.pathname = "/v1/admin";')]],
  ["redirect override", "mutant", [H0AR, H0AR1, H0X], [beforeSink('init.redirect = "follow";')]],
  ["header reconstruction override", "mutant", [H0AR, H0AR1], [["index", "    headers: requestContract.headers,\n", "    headers: request.headers,\n"]], "re-expressed at the call site: the module receives only explicit headers"],
  ["framing override", "mutant", [H0AR, H0AR1], [beforeSink("init.body = input.body;")]],
  ["public fetch fallback", "mutant", [H0X, "H0A first matrix"], [["dispatch", SINK, SINK.replace("input.binding.fetch(", "fetch(")]]],
  // H0AR1 matrix destination and option cases.
  ["whole href", "mutant", [H0AR1], [beforeCall("upstreamPath = request.url;")], "re-expressed through the explicit upstreamPath input"],
  ["computed URL member", "mutant", [H0AR1], [afterUrl('url["host"] = "attacker.invalid";')]],
  ["query parameters", "mutant", [H0AR1], [afterUrl('url.searchParams.set("destination", "attacker.invalid");')]],
  ["port", "mutant", [H0AR1], [afterUrl('url.port = "8443";')]],
  ["Object.assign URL escape", "mutant", [H0AR1], [afterUrl('Object.assign(url, { host: "attacker.invalid" });')]],
  ["call escape", "mutant", [H0AR1], [afterUrl("retargetControlPlane(url);")], "the undefined helper throws at the sink path"],
  ["URL alias", "mutant", [H0AR1], [afterUrl('const destination = url;\n  destination.host = "attacker.invalid";')]],
  ["URL destructuring alias", "neutral", [H0AR1], [afterUrl("const [destination] = [url];")], "an unused alias changes no sink value"],
  ["URL closure escape", "neutral", [H0AR1], [afterUrl('const retarget = () => { url.host = "attacker.invalid"; };')], "the closure is never called"],
  ["route path reassignment", "mutant", [H0AR1], [beforeCall('upstreamPath = "/v1/admin";')]],
  ["method override", "mutant", [H0AR1], [beforeSink('init.method = "DELETE";')]],
  ["computed option", "mutant", [H0AR1], [beforeSink('init["redirect"] = "follow";')]],
  ["deleted option", "mutant", [H0AR1], [beforeSink("delete init.redirect;")]],
  ["Object.assign options", "mutant", [H0AR1], [beforeSink('Object.assign(init, { redirect: "follow" });')]],
  ["options alias", "mutant", [H0AR1], [beforeSink('const options = init;\n    options.redirect = "follow";')]],
  ["duplicate literal option", "mutant", [H0AR1], [["dispatch", '    redirect: "manual",\n', '    redirect: "manual",\n    redirect: "follow",\n']]],
  ["spread literal option", "neutral", [H0AR1], [["index", `${CALL}\n`, `${CALL}\n    ...request,\n`]], "a Request has no own enumerable fields to spread and every named input follows the spread"],
  ["header object mutation", "mutant", [H0AR1], [beforeCall('requestContract.headers.set("Host", "attacker.invalid");')]],
  ["request contract replacement", "mutant", [H0AR1], [beforeCall("requestContract = { headers: request.headers, contentLength: 0 };")]],
  ["module binding presence only", "neutral", [H0AR1], [["dispatch", '    input.binding === undefined\n    || input.binding === null\n    || typeof input.binding.fetch !== "function"\n', "    input.binding === undefined\n"]], DEFENSE],
  ["module binding null accepted", "neutral", [H0AR1], [["dispatch", "    || input.binding === null\n", ""]], DEFENSE],
  ["module binding callability unchecked", "neutral", [H0AR1], [["dispatch", '    || typeof input.binding.fetch !== "function"\n', ""]], DEFENSE],
  ["worker binding presence only", "mutant", [H0AR1], [["index", '    env.CONTROL_PLANE === undefined\n    || env.CONTROL_PLANE === null\n    || typeof env.CONTROL_PLANE.fetch !== "function"\n', "    env.CONTROL_PLANE === undefined\n"]]],
  ["worker binding null accepted", "mutant", [H0AR1], [["index", "    || env.CONTROL_PLANE === null\n", ""]]],
  ["worker binding callability unchecked", "mutant", [H0AR1], [["index", '    || typeof env.CONTROL_PLANE.fetch !== "function"\n', ""]]],
  ["worker binding guard removed", "mutant", [H0X_ORDER], [["index", WORKER_GUARD, ""]], "the 5fc14fb layout: only the module guard remains"],
  ["worker binding guard after the request checks", "mutant", [H0X_ORDER], [["index", WORKER_GUARD, ""], ["index", CALL, `${WORKER_GUARD}${CALL}`]]],
  ["capability guard moved", "neutral", [H0AR1], [["dispatch", BINDING_GUARD_END, `${BINDING_GUARD_END}  const moved = typeof input.binding.fetch;\n`]], "a typeof read after the guard changes no sink value"],
  ["secret type unchecked", "mutant", [H0AR1], [["index", SECRET, '  const edgeAuthSecret = env.CONTROL_PLANE_EDGE_SECRET?.trim() ?? "";']]],
  ["secret type weakened", "mutant", [H0AR1], [["index", 'typeof env.CONTROL_PLANE_EDGE_SECRET !== "string"', "env.CONTROL_PLANE_EDGE_SECRET === undefined"]]],
  ["secret read elsewhere", "neutral", [H0AR1], [["index", "  const edgeAuthSecret = env.CONTROL_PLANE_EDGE_SECRET.trim();", "  const edgeAuthSecret = env.CONTROL_PLANE_EDGE_SECRET.trim();\n  const rawSecret = env.CONTROL_PLANE_EDGE_SECRET;"]], "an unused read changes no sink value"],
  // H0AR1R exact receiver and flow residuals.
  ["direct binding replacement", "mutant", [H0AR1R], [beforeCall("env.CONTROL_PLANE = env.ASSETS;")]],
  ["computed binding replacement", "mutant", [H0AR1R], [beforeCall('env["CONTROL_PLANE"] = env.ASSETS;')]],
  ["whole env replacement", "mutant", [H0AR1R], [beforeCall("env = { ...env, CONTROL_PLANE: env.ASSETS };")]],
  ["env alias replacement", "mutant", [H0AR1R], [beforeCall("const runtime = env; runtime.CONTROL_PLANE = runtime.ASSETS;")]],
  ["lexical env shadow at the sink", "mutant", [H0AR1R], [beforeCall("const assets = env.ASSETS;"), ["index", "    binding: env.CONTROL_PLANE,\n", "    binding: ((env) => env.CONTROL_PLANE)({ CONTROL_PLANE: assets }),\n"]], "re-expressed: the shadow sits on the binding argument"],
  ["binding cleared after the guard", "mutant", [H0AR1R], [beforeCall("env.CONTROL_PLANE = null;")]],
  ["always-false body guard", "mutant", [H0AR1R], [["dispatch", GUARD, '  if (false && input.method === "POST") {']]],
  ["caller-controlled body guard", "neutral", [H0AR1R], [["dispatch", GUARD, '  if (input.method === "POST" && input.headers.get("X-Frame-Body") !== "skip") {']], "the module sees only reconstructed headers, which never carry a caller X-Frame-Body"],
  ["local FixedLengthStream before the URL", "mutant", [H0AR1R], [beforeUrl(LOCAL_STREAM)]],
  ["local FixedLengthStream after the URL", "mutant", [H0AR1R, "design: FixedLengthStream local shadow"], [afterUrl(LOCAL_STREAM)]],
  // H0AR2 matrix.
  ["Object.assign binding replacement", "mutant", [H0AR2], [beforeCall("Object.assign(env, { CONTROL_PLANE: env.ASSETS });")]],
  ["Reflect.set binding replacement", "mutant", [H0AR2], [beforeCall('Reflect.set(env, "CONTROL_PLANE", env.ASSETS);')]],
  ["binding method replacement", "mutant", [H0AR2], [beforeCall("env.CONTROL_PLANE.fetch = env.ASSETS.fetch;")]],
  ["destructured binding alias", "neutral", [H0AR2], [beforeCall("const { CONTROL_PLANE: privateBinding } = env;")], "an unused alias changes no sink value"],
  ["entry env replacement", "mutant", [H0AR2], [beforeEntry("env = { ...env, CONTROL_PLANE: env.ASSETS };")]],
  ["entry argument substitution", "mutant", [H0AR2], [["index", ENTRY, "      return proxyControlPlane(request, { ...env, CONTROL_PLANE: env.ASSETS }, csp, upstreamPath);"]]],
  ["entry env shadow", "mutant", [H0AR2], [["index", "    if (upstreamPath !== null) {\n", "    const configured = env;\n    if (upstreamPath !== null) {\n      const env = { ...configured, CONTROL_PLANE: configured.ASSETS };\n"]]],
  ["entry env alias replacement", "mutant", [H0AR2], [beforeEntry("const runtime = env;\n      runtime.CONTROL_PLANE = runtime.ASSETS;")]],
  ["entry helper rebinding", "mutant", [H0AR2], [beforeEntry("rebindControlPlane(env);"), beforeExport("function rebindControlPlane(target: Env): void {\n  target.CONTROL_PLANE = target.ASSETS;\n}")]],
  ["second proxy dispatch", "neutral", [H0AR2], [beforeEntry("if (upstreamPath === ME_ROUTE) return proxyControlPlane(request, env, csp, ME_ROUTE);")], "the second dispatch is the same call for the same route"],
  ["inverted body guard", "mutant", [H0AR2], [["dispatch", GUARD, '  if (input.method !== "POST") {']]],
  ["nested body guard", "mutant", [H0AR2], [["dispatch", GUARD, '  if (input.upstreamPath === "/v1/signup") if (input.method === "POST") {']]],
  ["labelled framing skip", "neutral", [H0AR2], [["dispatch", GUARD, `  framing: if (input.method === "POST") {\n    if (input.headers.has("X-Frame-Body")) break framing;`]], "the module sees only reconstructed headers, which never carry a caller X-Frame-Body"],
  ["request parameter rebound before framing", "mutant", [H0AR2], [beforeCall('request = new Request(new URL(upstreamPath, controlPlaneOrigin), { method: "GET" });')]],
  ["hoisted local FixedLengthStream", "mutant", [H0AR2], [["dispatch", DISPATCH_END, '  } catch {\n    return { kind: "failed" };\n  }\n  function FixedLengthStream(_length: number) { return new TransformStream(); }\n}\n']]],
  ["local Request constructor", "neutral", [H0AR2], [beforeUrl("const Request = globalThis.Request;")], "the same constructor under a local name"],
  ["module URL constructor", "neutral", [H0AR2], [["dispatch", IMPORT, `${IMPORT}\nconst URL = globalThis.URL;`]], "the same constructor under a module name"],
  ["local header contract helper", "mutant", [H0AR2], [["index", "  let requestContract;\n", "  const controlPlaneRequestHeaders = (headers: Headers) => ({ headers, contentLength: 0 });\n  let requestContract;\n"]]],
  // H0AR2RDB / H0AR3RDB exact leads and challenges, inserted at the equivalent position.
  ["binding-entry-arguments", "mutant", [D02, H0AR3], [beforeEntry(`const supplied = arguments[1]; ${SUBSTITUTE}`)]],
  ["binding-proxy-arguments", "mutant", [D02, H0AR3], [beforeCall(`const supplied = arguments[1]; ${SUBSTITUTE}`)]],
  ["body-instance-pipe", "mutant", [D03, H0AR3], [beforeCall(`if (request.body) request.body.${SKIP_PIPE}`)]],
  ["body-aliased-pipe", "mutant", [D03, H0AR3], [beforeCall(`const incomingBody = request.body; if (incomingBody) incomingBody.${SKIP_PIPE}`)]],
  ["body-destructured-pipe", "mutant", [D03, H0AR3], [beforeCall(`const { body: incomingBody } = request; if (incomingBody) incomingBody.${SKIP_PIPE}`)]],
  ["prototype-pipe-through-joined-key", "mutant", [C04, "cycle-3 survivor"], [beforeCall('const streamPrototype: any = ReadableStream.prototype; const pipeName = ["pipe", "Through"].join(""); streamPrototype[pipeName] = function () { return this; };')]],
  ["prototype-pipe-through-concatenated-key", "mutant", [C04], [beforeCall('const streamPrototype: any = ReadableStream.prototype; const pipeName = "pipe" + "Through"; streamPrototype[pipeName] = function () { return this; };')]],
  ["body-guard-return", "mutant", [D02, C04], [beforeCall('if (request.method === "POST") return new Response("skipped");')]],
  ["binding-array-env", "mutant", [D02], [beforeCall("[env] = [{ ...env, CONTROL_PLANE: env.ASSETS }];")]],
  ["binding-catch-shadow", "mutant", [D02], [["index", CALL, "  let outcome;\n  try { throw { CONTROL_PLANE: env.ASSETS, PUBLIC_ORIGIN: env.PUBLIC_ORIGIN }; } catch (env) {\n  outcome = await dispatchControlPlane({"], ["index", CALL_END, `${CALL_END}  }\n`]], "re-expressed: the catch-bound env encloses the one dispatch call"],
  ["binding-destructure-env", "mutant", [D02], [beforeCall("({ value: env } = { value: { ...env, CONTROL_PLANE: env.ASSETS } });")]],
  ["binding-return-alias", "mutant", [D02], [beforeCall("const supplied = (() => env)(); supplied.CONTROL_PLANE = supplied.ASSETS;")]],
  ["body-method-direct", "mutant", [D02], [beforeCall('Object.defineProperty(request, "method", { value: "GET" });')]],
  ["body-method-alias", "mutant", [D02], [beforeCall('const incoming = request; Object.defineProperty(incoming, "method", { value: "GET" });')]],
  ["body-method-arguments", "mutant", [D02], [beforeCall('Object.defineProperty(arguments[0], "method", { value: "GET" });')]],
  ["body-method-destructured", "mutant", [D02], [beforeCall('const { 0: incoming } = arguments; Object.defineProperty(incoming, "method", { value: "GET" });')]],
  ["entry-arguments-through-nested-arrows", "mutant", [C04], [beforeEntry(`const supplied = (() => (() => arguments[1])())(); ${SUBSTITUTE}`)]],
  ["entry-arguments-through-reflect-get", "mutant", [C04], [beforeEntry(`const supplied = Reflect.get(arguments, 1); ${SUBSTITUTE}`)]],
  ["entry-env-passed-through-rest-forwarder", "mutant", [C04], [beforeEntry(`const supplied = ((...values: Env[]) => values[1])(request as unknown as Env, env); ${SUBSTITUTE}`)]],
  ["proxy-arguments-through-array-from", "mutant", [C04], [beforeCall(`const [, supplied] = Array.from(arguments); ${SUBSTITUTE}`)]],
  ["request-body-through-computed-element-access", "mutant", [C04], [beforeCall(`const incomingBody = request[["bo", "dy"].join("")] as ReadableStream | null; if (incomingBody) incomingBody.${SKIP_PIPE}`)]],
  ["request-body-through-reflect-get", "mutant", [C04], [beforeCall(`const incomingBody = Reflect.get(request, "body") as ReadableStream | null; if (incomingBody) incomingBody.${SKIP_PIPE}`)]],
  // H0AR3 matrix (the five exact leads above are its first five cases).
  ["destructured entry arguments", "mutant", [H0AR3], [beforeEntry(`const [, supplied] = arguments; ${SUBSTITUTE}`)]],
  ["arrow-captured entry arguments", "mutant", [H0AR3], [beforeEntry(`const supplied = (() => arguments[1])(); ${SUBSTITUTE}`)]],
  ["proxy body through arguments", "mutant", [H0AR3], [beforeCall(`if (arguments[0].body) arguments[0].body.${SKIP_PIPE}`)]],
  ["computed body pipe replaced", "mutant", [H0AR3], [beforeCall('if (request.body) request.body[["pipe", "Through"].join("")] = () => request.body;')]],
  ["request alias body pipe replaced", "mutant", [H0AR3], [beforeCall(`const incoming = request; if (incoming.body) incoming.body.${SKIP_PIPE}`)]],
  ["Reflect.set body pipe", "mutant", [H0AR3], [beforeCall('if (request.body) Reflect.set(request.body, "pipeThrough", function (this: ReadableStream) { return this; });')]],
  ["Object.assign body pipe", "mutant", [H0AR3], [beforeCall("if (request.body) Object.assign(request.body, { pipeThrough(this: ReadableStream) { return this; } });")]],
  ["entry body pipe replaced before dispatch", "mutant", [H0AR3], [beforeEntry(`if (request.body) request.body.${SKIP_PIPE}`)]],
  ["request body redefined", "mutant", [H0AR3], [beforeCall('Object.defineProperty(request, "body", { value: new Response("{}").body });')], "observed by the declared-but-absent body case"],
  ["stream prototype pipe replaced", "mutant", [H0AR3], [beforeCall(`ReadableStream.prototype.${SKIP_PIPE}`)]],
  ["hoisted helper body pipe", "mutant", [H0AR3], [beforeCall("skipFraming(request.body);"), beforeExport(`function skipFraming(stream: ReadableStream | null): void {\n  if (stream) stream.${SKIP_PIPE}\n}`)]],
  // H0A first-matrix dataflow cases.
  ["request-derived destination", "mutant", [H0A], [["index", "    publicOrigin: env.PUBLIC_ORIGIN,\n", "    publicOrigin: new URL(request.url).origin,\n"]], "re-expressed at the call site"],
  ["legacy fixed destination", "mutant", [H0A], [["dispatch", "new URL(input.upstreamPath, origin)", 'new URL(input.upstreamPath, "https://heel-control-plane.internal")']]],
  ["unvalidated configured destination", "mutant", [H0A], [["index", ORIGIN, "  const controlPlaneOrigin = env.PUBLIC_ORIGIN ?? null;"]]],
  ["reassignable destination", "neutral", [H0A], [["index", ORIGIN, ORIGIN.replace("const ", "let ")]], "the binding is never reassigned"],
  ["raw configured origin elsewhere", "neutral", [H0A], [["index", "      controlPlaneOrigin,\n      edgeClientKey,", "      env.PUBLIC_ORIGIN,\n      edgeClientKey,"]], "a refused origin already returned 503, so the raw and validated values are equal here"],
  ["missing configuration refusal", "mutant", [H0A], [["index", `${REFUSAL}\n`, ""]]],
  ["conditional configuration refusal", "neutral", [H0A], [["index", REFUSAL, REFUSAL.replace("controlPlaneOrigin === null", "controlPlaneOrigin === null && upstreamPath !== ME_ROUTE")]], "the module re-validates the raw origin, so the skipped Worker refusal still ends in the fixed 503"],
  ["substitute validator module", "mutant", [H0A], [["index", IMPORT, IMPORT.replace("../build/deployment-config", "./deployment-config")]]],
  ["aliased validator import", "mutant", [H0A], [["index", IMPORT, 'import { deploymentConfig as canonicalPublicOrigin } from "../build/deployment-config";']]],
  ["shadowed validator", "mutant", [H0A], [["index", ORIGIN, `  const canonicalPublicOrigin = (value: unknown) => String(value);\n${ORIGIN}`]]],
  ["unbounded request body", "mutant", [H0A], [["dispatch", "input.body!.pipeThrough(new FixedLengthStream(input.contentLength))", "input.body!"]]],
  ["redirect forwarding", "mutant", [H0A], [["dispatch", "if (response.status >= 300 && response.status <= 399)", "if (response.status === 399)"]]],
  // Harmless controls: none may change an observation.
  ["comment after the URL", "control", [H0AR1], [afterUrl("// The destination is now final.")]],
  ["unrelated local", "control", [H0AR1], [afterUrl('const unrelatedLabel = "control-plane";')]],
  ["declared length read", "control", [H0AR1], [beforeSink("const declaredLength = input.contentLength;")]],
  ["comment inside framing", "control", [H0AR2], [["dispatch", '      init.duplex = "half";', '      // Streaming bodies are half-duplex.\n      init.duplex = "half";']]],
  ["entry asset binding read", "control", [H0AR2], [["index", "    const csp = contentSecurityPolicy(nonce);\n", "    const csp = contentSecurityPolicy(nonce);\n    const assetsBound = env.ASSETS !== undefined;\n"]]],
  ["unrelated environment helper", "control", [H0AR2], [beforeExport("function assetBinding(env: Env): AssetFetcher {\n  return env.ASSETS;\n}")]],
  ["entry method read", "control", [H0AR3], [beforeEntry("const incomingMethod = request.method;")]],
  ["header read before framing", "control", [H0AR3], [beforeCall('const declaredType = request.headers.get("Content-Type");')]],
  ["unrelated helper arguments", "control", [H0AR3], [beforeExport("function argumentCount(..._values: unknown[]): number {\n  return arguments.length;\n}")]],
  ["comment naming the pipe", "control", [H0AR3], [["dispatch", '      init.duplex = "half";', '      // pipeThrough enforces the declared length.\n      init.duplex = "half";']]],
  ["entry ordinary read", "control", [D02], [beforeEntry("const assetsPresent = env.ASSETS !== undefined;")]],
];

function apply(sources, edits) {
  const mutated = { ...sources };
  for (const [file, anchor, replacement] of edits) {
    assert.equal(mutated[file].split(anchor).length, 2, `mutation anchor is not unique in ${file}: ${anchor}`);
    mutated[file] = mutated[file].replace(anchor, () => replacement);
  }
  return mutated;
}

const sha256 = (text) => createHash("sha256").update(text).digest("hex");

test("the executable sink corpus: the candidate is exact, every mutant deviates, controls and neutral cases do not", async () => {
  const sources = {};
  for (const [name, path] of Object.entries(FILES)) sources[name] = await readFile(join(appRoot, path), "utf8");
  const root = await mkdtemp(join(tmpdir(), "heel-sink-corpus-"));
  try {
    const cases = requestSet();
    assert.equal(new Set(cases.map(({ label }) => label)).size, cases.length, "request labels are not unique");
    const candidate = await record(root, sources, cases);
    assert.equal(candidate.load, undefined, `the candidate did not load: ${candidate.load}`);
    // Absolute: the unmodified Worker matches the record derived from the route contract.
    for (const testCase of cases) {
      assert.deepEqual(candidate[testCase.label], expectedObservation(testCase), testCase.label);
    }

    assert.equal(new Set(CORPUS.map(([label]) => label)).size, CORPUS.length, "corpus labels are not unique");
    assert.ok(CORPUS.filter(([, kind]) => kind === "control").length >= 4);
    const manifest = [];
    for (const [label, kind, origins, edits, note] of CORPUS) {
      const mutated = apply(sources, edits);
      const changed = Object.keys(mutated).filter((name) => mutated[name] !== sources[name]);
      assert.notEqual(changed.length, 0, `${label} did not change the source`);
      for (const name of changed) {
        const parsed = ts.createSourceFile(FILES[name], mutated[name], ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
        assert.equal(parsed.parseDiagnostics.length, 0, `${label} does not parse in ${FILES[name]}`);
      }
      const observed = await record(root, mutated, cases);
      const found = deviation(candidate, observed);
      manifest.push({
        label, kind, sources: origins, note: note ?? null,
        edits: edits.map(([file, anchor, replacement]) => ({ file: FILES[file], anchor, replacement })),
        mutated_sha256: Object.fromEntries(changed.map((name) => [FILES[name], sha256(mutated[name])])),
        deviation: found,
      });
    }
    if (process.env.H0X_CORPUS_OUT) {
      await writeFile(process.env.H0X_CORPUS_OUT, `${JSON.stringify({
        sources_sha256: Object.fromEntries(Object.entries(FILES).map(([name, path]) => [path, sha256(sources[name])])),
        request_cases: cases.length,
        corpus: manifest,
      }, null, 2)}\n`);
    }
    for (const entry of manifest) {
      if (entry.kind === "mutant") assert.notEqual(entry.deviation, null, `${entry.label}: no deviation observed at the sink`);
      else assert.equal(entry.deviation, null, `${entry.label} (${entry.kind}): ${JSON.stringify(entry.deviation)}`);
    }
  } finally {
    restoreGlobals();
    delete globalThis.__heelSinkObserver;
    await rm(root, { recursive: true, force: true });
  }
});
