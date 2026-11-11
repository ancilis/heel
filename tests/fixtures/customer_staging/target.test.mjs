// Component proof for the controlled staging target. Every request here is a constructed
// Request handed to the Worker's fetch function in-process: this is NOT deployed
// acceptance and proves nothing about DNS, TLS, workers.dev framing or the released runner.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import worker, { CANARY_ID, MODES, ROUTES } from "./worker.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, "../../..");
const ORIGIN = "https://target.example";
// Synthetic, non-secret test tokens; real tokens are generated locally per README.md.
const FREE = "synthetic-free-session-0001";
const PRO = "synthetic-pro-session-0001";
const OTHER = "synthetic-other-session-0001";
const VERIFY = "synthetic-ownership-token-0001-AbC_-";
const sha = (value) => createHash("sha256").update(value).digest("hex");
const EXPORT = { account_id: "acct_canary", format: "csv", rows: [{ id: "row_1", amount_cents: 1200 }], total: 1, protected_canary: CANARY_ID };
const EXPORT_PATH = `/api/exports/${CANARY_ID}`;

function env(overrides = {}) {
  return {
    HEEL_TARGET_MODE: "vulnerable",
    HEEL_TARGET_REVISION: "7d259259",
    HEEL_VERIFY_TOKEN: VERIFY,
    HEEL_FREE_TOKEN_SHA256: sha(FREE),
    HEEL_PRO_TOKEN_SHA256: sha(PRO),
    ...overrides,
  };
}

const logs = [];
async function call(path, { method = "GET", token, authorization, headers = {}, config = env(), body } = {}) {
  const all = new Headers(headers);
  if (token !== undefined) all.set("authorization", `Bearer ${token}`);
  if (authorization !== undefined) all.set("authorization", authorization);
  const original = console.log;
  console.log = (...items) => logs.push(items.join(" "));
  try {
    const response = await worker.fetch(new Request(ORIGIN + path, { method, headers: all, body }), config);
    const bytes = new Uint8Array(await response.arrayBuffer());
    return { status: response.status, headers: response.headers, bytes, text: new TextDecoder().decode(bytes) };
  } finally {
    console.log = original;
  }
}

test("ownership file serves exactly the operator-configured token with framing the verifier accepts", async () => {
  const got = await call("/.well-known/heel-verify.txt");
  assert.equal(got.status, 200);
  assert.equal(got.text, VERIFY + "\n");
  assert.equal(got.headers.get("content-length"), String(VERIFY.length + 1));
  assert.equal(got.headers.get("content-type"), "text/plain; charset=utf-8");
  assert.equal(got.headers.get("content-encoding"), null);
  assert.equal(got.headers.get("cache-control"), "no-store");
  const head = await call("/.well-known/heel-verify.txt", { method: "HEAD" });
  assert.equal(head.status, 200);
  assert.equal(head.bytes.length, 0);
  assert.equal(head.headers.get("content-length"), String(VERIFY.length + 1));
  // No public setter: every writing method is refused and the token is unchanged.
  for (const method of ["PUT", "POST", "PATCH", "DELETE"]) {
    const write = await call("/.well-known/heel-verify.txt", { method, body: "attacker-token-000000" });
    assert.equal(write.status, 405, method);
    assert.equal(write.headers.get("allow"), "GET, HEAD");
  }
  assert.equal((await call("/.well-known/heel-verify.txt")).text, VERIFY + "\n");
});

test("ownership file fails closed when the token is missing or not an exact ASCII token", async () => {
  for (const value of [undefined, "", "short", "has space in-token-0001", "tab\tin-token-00000001", "x".repeat(513), "café-token-00000001", 12345678901234567890]) {
    const got = await call("/.well-known/heel-verify.txt", { config: env({ HEEL_VERIFY_TOKEN: value }) });
    assert.equal(got.status, 503, String(value));
    assert.deepEqual(JSON.parse(got.text), { error: "target not configured" });
  }
});

test("unknown paths are 404 and other methods on known routes are 405", async () => {
  const unknown = [
    "/", "/api", "/api/export", "/api/export/", "/API/export", "/api/export.json", "/api/exports", "/api/exports/",
    "/api/exports/heel-canary-export-0002", "/api/exports/HEEL-CANARY-EXPORT-0001", `${EXPORT_PATH}/`, `${EXPORT_PATH}x`,
    `/api/exports/%68eel-canary-export-0001`, `/API/exports/${CANARY_ID}`, `/api/exports/${CANARY_ID}/rows`,
    "/api/exports/attacker-id-0001", "/.well-known/", "/exports/1", "/api/pricing", "/healthz/x", "/openapi.yaml",
  ];
  for (const path of unknown) {
    for (const method of ["GET", "HEAD", "POST", "DELETE"]) {
      const got = await call(path, { method, token: PRO });
      assert.equal(got.status, 404, `${method} ${path}`);
      assert.ok(!got.text.includes("attacker-id") && !got.text.includes("acct_canary"), path);
      if (method === "GET") assert.deepEqual(JSON.parse(got.text), { error: "not found" });
    }
  }
  for (const path of Object.keys(ROUTES)) {
    for (const method of ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"]) {
      const got = await call(path, { method, token: PRO });
      assert.equal(got.status, 405, `${method} ${path}`);
      assert.equal(got.headers.get("allow"), "GET, HEAD");
      assert.ok(!got.text.includes("acct_canary"));
    }
  }
});

test("export authenticates only the two configured digests", async () => {
  assert.equal((await call(EXPORT_PATH, { token: FREE })).status, 200);
  assert.equal((await call(EXPORT_PATH, { token: PRO })).status, 200);
  const refused = [
    {},
    { token: OTHER },
    { token: sha(FREE) },
    { authorization: `bearer ${PRO}` },
    { authorization: `Basic ${PRO}` },
    { authorization: "Bearer" },
    { authorization: "Bearer " },
    { authorization: `Bearer ${PRO} ${PRO}` },
    { authorization: `Bearer  ${PRO}` },
    { authorization: `Bearer ${PRO}, Bearer ${FREE}` },
    { authorization: `Bearer ${"a".repeat(513)}` },
  ];
  for (const options of refused) {
    const got = await call(EXPORT_PATH, options);
    assert.equal(got.status, 401, JSON.stringify(options));
    assert.deepEqual(JSON.parse(got.text), { error: "unauthenticated" });
    assert.equal(got.headers.get("www-authenticate"), "Bearer");
  }
});

test("missing, malformed or equal digest configuration and an unknown mode fail closed", async () => {
  const broken = [
    { HEEL_FREE_TOKEN_SHA256: undefined },
    { HEEL_PRO_TOKEN_SHA256: undefined },
    { HEEL_FREE_TOKEN_SHA256: "" },
    { HEEL_FREE_TOKEN_SHA256: sha(FREE).toUpperCase() },
    { HEEL_FREE_TOKEN_SHA256: sha(FREE).slice(1) },
    { HEEL_FREE_TOKEN_SHA256: sha(FREE) + "\n" },
    { HEEL_PRO_TOKEN_SHA256: PRO },
    { HEEL_FREE_TOKEN_SHA256: sha(PRO) },
    { HEEL_TARGET_MODE: undefined },
    { HEEL_TARGET_MODE: "unset" },
    { HEEL_TARGET_MODE: "Vulnerable" },
    { HEEL_TARGET_MODE: "hardened" },
  ];
  for (const overrides of broken) {
    for (const token of [FREE, PRO]) {
      const got = await call(EXPORT_PATH, { token, config: env(overrides) });
      assert.equal(got.status, 503, JSON.stringify(overrides));
      assert.deepEqual(JSON.parse(got.text), { error: "target not configured" });
    }
  }
  assert.equal((await call(EXPORT_PATH, { token: PRO, config: null })).status, 503);
  assert.equal((await call(EXPORT_PATH, { token: PRO, config: {} })).status, 503);
});

test("modes are operator configured: vulnerable, patched and error_envelope", async () => {
  const exportFor = async (mode, token, extra = {}) => call(EXPORT_PATH, { token, config: env({ HEEL_TARGET_MODE: mode }), ...extra });
  const vulnerable = await exportFor("vulnerable", FREE);
  assert.equal(vulnerable.status, 200);
  assert.deepEqual(JSON.parse(vulnerable.text), EXPORT);
  const patched = await exportFor("patched", FREE);
  assert.equal(patched.status, 403);
  assert.equal(patched.bytes.length, 0);
  assert.equal(patched.headers.get("content-length"), "0");
  const envelope = await exportFor("error_envelope", FREE);
  assert.equal(envelope.status, 403);
  assert.deepEqual(JSON.parse(envelope.text), { error: "upgrade required" });
  for (const mode of MODES) {
    const pro = await exportFor(mode, PRO);
    assert.equal(pro.status, 200, mode);
    assert.deepEqual(JSON.parse(pro.text), EXPORT);
    const head = await call(EXPORT_PATH, { method: "HEAD", token: PRO, config: env({ HEEL_TARGET_MODE: mode }) });
    assert.equal(head.status, 200);
    assert.equal(head.bytes.length, 0);
    assert.equal(head.headers.get("content-length"), String(JSON.stringify(EXPORT).length));
  }
  // The request cannot select or override the mode.
  for (const extra of [
    { headers: { "x-heel-target-mode": "vulnerable" } },
    { headers: { cookie: "mode=vulnerable" } },
  ]) {
    assert.equal((await exportFor("patched", FREE, extra)).status, 403);
  }
  assert.equal((await call(`${EXPORT_PATH}?mode=vulnerable`, { token: FREE, config: env({ HEEL_TARGET_MODE: "patched" }) })).status, 403);
});

test("health reports only mode, revision and configured flags", async () => {
  const got = await call("/healthz", { config: env({ HEEL_TARGET_MODE: "patched" }) });
  assert.equal(got.status, 200);
  assert.deepEqual(JSON.parse(got.text), {
    status: "ok", mode: "patched", revision: "7d259259", ownership_configured: true, export_configured: true,
  });
  const broken = await call("/healthz", { config: env({ HEEL_TARGET_MODE: "unset", HEEL_TARGET_REVISION: "<b>", HEEL_VERIFY_TOKEN: "x" }) });
  assert.deepEqual(JSON.parse(broken.text), {
    status: "ok", mode: "invalid", revision: "unknown", ownership_configured: false, export_configured: false,
  });
});

test("no token, digest, header, query or body value is reflected or logged; receipts are bounded", async () => {
  logs.length = 0;
  const secrets = [FREE, PRO, OTHER, sha(FREE), sha(PRO), VERIFY, "query-value-0001", "posted-body-0001", "header-value-0001"];
  const responses = [];
  for (const mode of MODES) {
    for (const token of [FREE, PRO, OTHER]) {
      for (const method of ["GET", "HEAD", "POST"]) {
        responses.push(await call(`${EXPORT_PATH}?q=query-value-0001`, {
          method, token, config: env({ HEEL_TARGET_MODE: mode }), headers: { "x-probe": "header-value-0001" },
          body: method === "POST" ? "posted-body-0001" : undefined,
        }));
      }
    }
  }
  responses.push(await call("/healthz", { token: PRO }));
  responses.push(await call("/nowhere?q=query-value-0001", { token: FREE }));
  for (const response of responses) {
    const visible = response.text + JSON.stringify([...response.headers]);
    for (const value of secrets.slice(0, 5)) assert.ok(!visible.includes(value), value);
  }
  assert.equal(logs.length, responses.length);
  const allowed = {
    method: new Set(["GET", "HEAD", "OTHER"]),
    route: new Set([...Object.values(ROUTES), "unknown"]),
    role: new Set(["free", "pro", "none", "malformed", "unknown", "-"]),
    mode: new Set([...MODES, "invalid"]),
  };
  for (const line of logs) {
    for (const value of [...secrets, "authorization", "Bearer"]) assert.ok(!line.includes(value), value);
    const receipt = JSON.parse(line);
    assert.deepEqual(Object.keys(receipt).sort(), ["body_sha256", "method", "mode", "receipt", "role", "route", "status"]);
    assert.match(receipt.receipt, /^[0-9a-f-]{36}$/);
    assert.match(receipt.body_sha256, /^[0-9a-f]{64}$/);
    assert.ok(Number.isInteger(receipt.status));
    for (const [key, set] of Object.entries(allowed)) assert.ok(set.has(receipt[key]), `${key}=${receipt[key]}`);
  }
});

test("source has no outbound fetch, redirect, import, binding or plan metadata", () => {
  const source = readFileSync(join(HERE, "worker.mjs"), "utf8");
  // The only fetch is the exported handler itself; nothing calls out.
  assert.equal(source.match(/\bfetch\s*\(/g).length, 1);
  assert.match(source, /async fetch\(request, env\)/);
  assert.doesNotMatch(source, /^\s*import\b|\bimport\s*\(|\brequire\s*\(/m);
  assert.doesNotMatch(source, /Response\.redirect|["']location["']|WebSocket|\bconnect\s*\(/i);
  assert.doesNotMatch(source, /\b(KV|DurableObject|D1|R2|caches)\b/);
  const config = readFileSync(join(HERE, "wrangler.jsonc"), "utf8");
  for (const key of ["kv_namespaces", "durable_objects", "d1_databases", "r2_buckets", "services", "vpc", "routes", "route", "queues", "ai", "browser", "hyperdrive", "secrets_store", "observability", "limits", "placement"]) {
    assert.ok(!config.includes(`"${key}"`), key);
  }
  for (const forbidden of [FREE, PRO, VERIFY]) assert.ok(!config.includes(forbidden));
  const openapi = JSON.parse(readFileSync(join(HERE, "openapi.json"), "utf8"));
  assert.deepEqual(Object.keys(openapi.paths), ["/api/exports/{id}"]);
  const item = openapi.paths["/api/exports/{id}"];
  assert.deepEqual(Object.keys(item).sort(), ["get", "head", "parameters"]);
  // An ordinary required path parameter: no example, enum, default or marker value.
  assert.deepEqual(item.parameters, [{ name: "id", in: "path", required: true, schema: { type: "string" } }]);
  assert.doesNotMatch(JSON.stringify(openapi), /"x-|plan|finding|security|canary|protected|example|enum|default/i);
});

test("the target serves its own inventory at /openapi.json, byte-identical to openapi.json", async () => {
  const file = readFileSync(join(HERE, "openapi.json"), "utf8");
  for (const mode of [...MODES, "unset"]) {
    const got = await call("/openapi.json", { config: env({ HEEL_TARGET_MODE: mode }) });
    assert.equal(got.status, 200, mode);
    assert.equal(got.text, file);
    assert.equal(got.headers.get("content-type"), "application/json");
    assert.equal(got.headers.get("content-length"), String(Buffer.byteLength(file)));
  }
  const head = await call("/openapi.json", { method: "HEAD" });
  assert.equal(head.status, 200);
  assert.equal(head.bytes.length, 0);
  // The inventory lists only the export route: no ownership, health or spec endpoint.
  assert.deepEqual(Object.keys(JSON.parse(file).paths), ["/api/exports/{id}"]);
});

// Component proof only: the worker's own responses are evaluated by the UNCHANGED product
// predicate heel.runner.plan_differential.evaluate_plan_pair (stdlib import from this
// checkout). replay_plan_differential maps a held verdict to pass/blocked, a finding on
// the saved body_superset predicate to fail/still_reachable, and anything else to
// fail/inconclusive. Deployed acceptance still requires the released runner over DNS/TLS.
const PREDICATE = `
import base64, json, sys
sys.path.insert(0, sys.argv[1])
from heel.runner.plan_differential import ExecutorOutcome, PlanObservation, evaluate_plan_pair
out = []
for case in json.load(sys.stdin):
    observe = lambda side: PlanObservation(side["status"], base64.b64decode(side["body"]))
    verdict = evaluate_plan_pair(
        observe(case["lower"]), observe(case["higher"]), method=case["method"], marker=None,
        executor_outcome=ExecutorOutcome("completed", "observed"),
    )
    out.append({"verdict": verdict.verdict, "row": verdict.row, "reason": verdict.reason,
                "body_superset": verdict.body_superset})
json.dump(out, sys.stdout)
`;

function python() {
  for (const candidate of [process.env.HEEL_FIXTURE_PYTHON, "python3", "python"].filter(Boolean)) {
    const probe = spawnSync(candidate, ["-I", "-c", "import sys; assert sys.version_info >= (3, 11)"]);
    if (probe.status === 0) return candidate;
  }
  assert.fail("component predicate check requires Python 3.11+ (set HEEL_FIXTURE_PYTHON)");
}

test("component proof (not deployed acceptance): existing predicate on the worker's responses", async () => {
  const cases = [];
  const expected = [];
  const observe = (got) => ({ status: got.status, body: Buffer.from(got.bytes).toString("base64") });
  const add = async (mode, method, want) => {
    const config = env({ HEEL_TARGET_MODE: mode });
    cases.push({
      method,
      lower: observe(await call(EXPORT_PATH, { method, token: FREE, config })),
      higher: observe(await call(EXPORT_PATH, { method, token: PRO, config })),
    });
    expected.push({ mode, method, ...want });
  };
  // Vulnerable: a stored body_superset finding (row 6) -> replay fail/still_reachable.
  await add("vulnerable", "GET", { verdict: "finding", row: 6, reason: "lower_superset", body_superset: true });
  // Patched: 403 with an empty body against a valid pro control is held (row 7) -> replay pass/blocked.
  await add("patched", "GET", { verdict: "held", row: 7, reason: "lower_denied", body_superset: false });
  // Error envelope: 403 {"error": ...} stays undecided (row 9) -> replay fail/inconclusive, never pass.
  await add("error_envelope", "GET", { verdict: "inconclusive", row: 9, reason: "lower_denial_envelope", body_superset: null });
  // HEAD on the vulnerable target is status parity only, never a stored finding.
  await add("vulnerable", "HEAD", { verdict: "inconclusive", row: 8, reason: "head_status_only", body_superset: null });
  // The alternative patched shape proposed by ops, 403 with "{}", is checked directly too.
  cases.push({ method: "GET", lower: { status: 403, body: Buffer.from("{}").toString("base64") }, higher: cases[1].higher });
  expected.push({ mode: "patched-{}", method: "GET", verdict: "held", row: 7, reason: "lower_denied", body_superset: false });

  const run = spawnSync(python(), ["-I", "-B", "-c", PREDICATE, REPO], { input: JSON.stringify(cases), encoding: "utf8" });
  assert.equal(run.status, 0, run.stderr);
  const results = JSON.parse(run.stdout);
  assert.equal(results.length, expected.length);
  results.forEach((result, index) => {
    const { mode, method, ...want } = expected[index];
    assert.deepEqual(result, want, `${mode} ${method}`);
  });
});

// Canary-dependent paired-read validation (component proof, not deployed acceptance).
// This is the composition the released paired runner performs in heel/runner/execution.py,
// using the UNCHANGED product functions: RouteInventory on the inventory the target serves,
// the runner store's mapping validator, the closed catalog action schema, prepare_action,
// the transport body-shape check, protected_content with the marker taken from the bound
// fixture id exactly as execution.py does, and adapters.evaluate_pair. No product function
// is replaced or mocked; only the HTTP hop is an in-process Worker call. It validates a
// read only when the bound heel-canary marker appears in protected_canary: it is not
// inference over arbitrary responses.
const PAIRED = `
import base64, json, sys
sys.path.insert(0, sys.argv[1])
from heel.runner.adapters import evaluate_pair, prepare_action
from heel.runner.catalog import CATALOG_BY_ID
from heel.runner.content_assertion import protected_content
from heel.runner.http_transport import _body_shape
from heel.runner.openapi_routes import RouteInventory
from heel.runner.store import _mapping_record

SCENARIO = "plan_entitlement_read"
request = json.load(sys.stdin)
inventory = RouteInventory(json.loads(base64.b64decode(request["openapi"])))

def actions(method, fixture_id):
    catalog = CATALOG_BY_ID[SCENARIO]
    mapping = _mapping_record({
        "scenario_id": SCENARIO, "method": method, "route_template": "/api/exports/{id}",
        "fixture_bindings": [{"parameter_name": "id", "fixture_id": fixture_id}],
    })
    return [{
        "ordinal": ordinal, "scenario_id": SCENARIO, "adapter_version": catalog["adapter_version"],
        "method": method, "route_template": mapping["route_template"],
        "fixture_bindings": [dict(item) for item in mapping["fixture_bindings"]],
        "semantic_auth_role": role, "auth_profile": "bearer",
        "assertion_class": catalog["assertion_class"],
        "allowed_status_codes": list(catalog["allowed_status_codes"]),
        "allowed_body_shapes": list(catalog["allowed_body_shapes"]),
        "side_effect_class": catalog["side_effect_class"],
    } for ordinal, role in enumerate(catalog["semantic_roles"])]

if request["phase"] == "prepare":
    out = {"inventory": inventory.read_routes(), "cases": []}
    for case in request["cases"]:
        prepared = [prepare_action(action) for action in actions(case["method"], case["fixture_id"])]
        out["cases"].append([{"role": p.semantic_auth_role, "method": p.method, "route": p.route} for p in prepared])
    json.dump(out, sys.stdout)
else:
    out = []
    for case in request["cases"]:
        observations = []
        for action, side in zip(actions(case["method"], case["fixture_id"]), case["responses"]):
            body = base64.b64decode(side["body"])
            markers = [b["fixture_id"] for b in action["fixture_bindings"] if b["fixture_id"].startswith("heel-canary-")]
            observations.append({
                "status": side["status"],
                "shape": _body_shape(body, method=action["method"]),
                "protected": protected_content(body, marker=markers[0] if len(markers) == 1 else None,
                                               status=side["status"], method=action["method"]),
            })
        pair = evaluate_pair(
            SCENARIO, observations[0]["status"], observations[1]["status"], method=case["method"],
            first_body_shape=observations[0]["shape"], second_body_shape=observations[1]["shape"],
            first_protected=observations[0]["protected"], second_protected=observations[1]["protected"],
        )
        out.append({"outcome": pair.outcome, "protected": [o["protected"] for o in observations]})
    json.dump(out, sys.stdout)
`;

function paired(payload) {
  const run = spawnSync(python(), ["-I", "-B", "-c", PAIRED, REPO], { input: JSON.stringify(payload), encoding: "utf8" });
  assert.equal(run.status, 0, run.stderr);
  return JSON.parse(run.stdout);
}

test("canary-dependent paired read: the unchanged paired evaluator decides the worker's responses", async () => {
  const served = await call("/openapi.json");
  const openapi = Buffer.from(served.bytes).toString("base64");
  // [label, mode, method, bound fixture id, token sent as lower_plan, token sent as higher_plan, expected]
  const matrix = [
    ["vulnerable", "vulnerable", "GET", CANARY_ID, FREE, PRO, { outcome: "observed", protected: [true, true] }],
    ["patched", "patched", "GET", CANARY_ID, FREE, PRO, { outcome: "blocked", protected: [false, true] }],
    ["error_envelope", "error_envelope", "GET", CANARY_ID, FREE, PRO, { outcome: "inconclusive", protected: [null, true] }],
    // HEAD carries no body: never a finding, in any mode.
    ...MODES.map((mode) => [`HEAD ${mode}`, mode, "HEAD", CANARY_ID, FREE, PRO, { outcome: "inconclusive", protected: [null, null] }]),
    // Positive control failure: the higher identity does not receive the protected export.
    ["control denied", "patched", "GET", CANARY_ID, FREE, FREE, { outcome: "inconclusive", protected: [false, false] }],
    ["control unauthenticated", "vulnerable", "GET", CANARY_ID, FREE, OTHER, { outcome: "inconclusive", protected: [true, null] }],
    // No marker bound: a non-canary fixture id, or a different canary id, reaches only 404s.
    ["no marker", "vulnerable", "GET", "export-0001", FREE, PRO, { outcome: "inconclusive", protected: [null, null] }],
    ["other canary", "vulnerable", "GET", "heel-canary-export-0002", FREE, PRO, { outcome: "inconclusive", protected: [null, null] }],
  ];
  const prepared = paired({ phase: "prepare", openapi, cases: matrix.map(([, , method, fixture_id]) => ({ method, fixture_id })) });
  // The runner reads exactly the served inventory: one templated export route, GET and HEAD.
  assert.deepEqual(prepared.inventory, [
    { method: "GET", route_template: "/api/exports/{id}", operation_id: "getexport", placeholders: ["id"] },
    { method: "HEAD", route_template: "/api/exports/{id}", operation_id: "headexport", placeholders: ["id"] },
  ]);
  const cases = [];
  for (const [index, [label, mode, method, fixture_id, lowerToken, higherToken]] of matrix.entries()) {
    const actions = prepared.cases[index];
    assert.deepEqual(actions.map((a) => a.role), ["lower_plan", "higher_plan"], label);
    assert.ok(actions.every((a) => a.method === method && a.route === `/api/exports/${fixture_id}`), label);
    const config = env({ HEEL_TARGET_MODE: mode });
    const responses = [];
    for (const [action, token] of [[actions[0], lowerToken], [actions[1], higherToken]]) {
      const got = await call(action.route, { method, token, config });
      responses.push({ status: got.status, body: Buffer.from(got.bytes).toString("base64") });
    }
    cases.push({ method, fixture_id, responses });
  }
  const results = paired({ phase: "evaluate", openapi, cases });
  assert.equal(results.length, matrix.length);
  results.forEach((result, index) => assert.deepEqual(result, matrix[index][6], matrix[index][0]));
});
