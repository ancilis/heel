// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";

import { CanaryApi, CanaryApiError } from "../lib/canary-api.ts";


const workspace = "ws_0123456789abcdef";
const project = "prj_0123456789abcdef0123456789abcdef";
const run = "crun_0123456789abcdef0123456789abcdef";
const digest = "a".repeat(64);


function jsonResponse(value: unknown, status = 200, headers: Record<string, string> = {}): Response {
  const body = JSON.stringify(value);
  return new Response(body, {
    status,
    headers: { "Content-Type": "application/json", "Content-Length": String(Buffer.byteLength(body)), ...headers },
  });
}


function statusValue(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const runStatus = {
    schema_version: "heel.canary-run-status.v1",
    run_id: run,
    approval_id: "cap_0123456789abcdef0123456789abcdef",
    grant_id: null,
    status: "awaiting_execution_approval",
    execution_disposition: null,
    error_category: "none",
    stop_reason: "none",
    source_event_sequence: -1,
    quota_state: "unreserved",
    kill_switch_generation: 0,
    stop_generation: 0,
    stop_deadline_ms: null,
    stop_acknowledged_at_ms: null,
    stop_ack_late: false,
    ...overrides,
  };
  return {
    schema_version: "heel.canary-run-dashboard.v1",
    run: runStatus,
    progress: {
      schema_version: "heel.canary-run-progress.v1",
      available: true,
      current_scenario_id: null,
      scenarios_completed: 0,
      scenarios_total: 3,
      requests_started: 0,
      requests_completed: 0,
      remaining_requests: 12,
      remaining_wall_ms: 45_000,
      retries_used: 0,
      redaction_count: 0,
      local_result_ready: false,
    },
  };
}


test("CanaryApi exposes named methods only and sends same-origin closed requests", async () => {
  const calls: Array<[string, RequestInit]> = [];
  const transport = async (path: string, init: RequestInit): Promise<Response> => {
    calls.push([path, init]);
    return jsonResponse(statusValue());
  };
  const api = new CanaryApi({ transport });

  assert.equal("request" in api, false);
  const value = await api.getRun(workspace, project, run);
  assert.equal(value.run.runId, run);
  assert.equal(Object.isFrozen(value), true);
  assert.equal(Object.isFrozen(value.progress), true);
  assert.deepEqual(calls.map(([path]) => path), [
    `/api/control-plane/v1/workspaces/${workspace}/projects/${project}/canary-runs/${run}`,
  ]);
  const init = calls[0][1];
  assert.equal(init.method, "GET");
  assert.equal(init.credentials, "same-origin");
  assert.equal(init.cache, "no-store");
  assert.equal(init.redirect, "error");
  assert.deepEqual([...new Headers(init.headers).entries()], [["accept", "application/json"]]);
});


test("getRun rejects extra fields, malformed JSON, and oversized declared responses", async () => {
  for (const response of [
    jsonResponse(statusValue({ surprise: true })),
    new Response("{", { status: 200, headers: { "Content-Type": "application/json" } }),
    new Response("{}", { status: 200, headers: { "Content-Type": "application/json", "Content-Length": String(273 * 1024) } }),
  ]) {
    const api = new CanaryApi({ transport: async () => response });
    await assert.rejects(api.getRun(workspace, project, run), (error: unknown) => {
      assert.ok(error instanceof CanaryApiError);
      assert.equal(error.code, "invalid_response");
      return true;
    });
  }
});


test("approveRun pins the immutable body, idempotency, and control generation", async () => {
  let call: [string, RequestInit] | undefined;
  const api = new CanaryApi({ transport: async (path, init) => {
    call = [path, init];
    return jsonResponse({
      schema_version: "heel.execution-approved.v1",
      run_id: run,
      grant_id: "cgr_0123456789abcdef0123456789abcdef",
      reservation_id: "res_0123456789abcdef0123456789abcdef",
      grant: {
        schema_version: "heel.execution-grant.v1",
        grant_id: "cgr_0123456789abcdef0123456789abcdef",
        run_id: run,
        workspace_id: workspace,
        project_id: project,
        approval: { projection_id: "cap_0123456789abcdef0123456789abcdef", projection_digest: digest, manifest_digest: "b".repeat(64) },
        environment: { environment_id: "env_0123456789abcdef0123456789abcdef", origin: "https://staging.acme.dev", environment_class: "staging", verification_record_digest: "c".repeat(64) },
        runner_binding: { runner_id: "runr_0123456789abcdef0123456789abcdef", runner_key_id: "key_0123456789abcdef", public_key_digest: "d".repeat(64) },
        approval_actor: { user_id: "usr_0123456789abcdef", role: "owner" },
        approval_reason: "Release boundary check",
        consented_at_ms: 1,
        budgets: { maximum_requests: 12, maximum_concurrency: 1, action_timeout_ms: 5000, wall_timeout_ms: 45000, maximum_response_bytes: 262144 },
        egress: { hostname: "staging.acme.dev", port: 443, redirect_policy: "deny" },
        retry_policy: { maximum_retries: 0, retryable_failure_codes: [] },
        grant_nonce: "nonce_0123456789abcdef",
        kill_switch_generation: 7,
        operational_receipt_policy: { schema_version: "heel.operational-run-projection.v1", maximum_bytes: 32768, allowed_error_categories: ["none"], allowed_stop_reasons: ["none"], allowed_containment_codes: ["admitted"] },
        issued_at_ms: 1,
        expires_at_ms: 60_001,
        grant_digest: "e".repeat(64),
        signing_key_id: "cloud_0123456789abcdef",
        signature_b64: "A".repeat(86) + "==",
      },
    }, 201);
  } });

  const approved = await api.approveRun(workspace, project, run, {
    projectionDigest: digest,
    hostnameRetype: "staging.acme.dev",
    reason: "Release boundary check",
    idempotencyKey: `ca1-${"f".repeat(64)}`,
    controlGeneration: 7,
  });
  assert.equal(approved.grantId, "cgr_0123456789abcdef0123456789abcdef");
  assert.ok(call);
  assert.equal(call[0], `/api/control-plane/v1/workspaces/${workspace}/projects/${project}/canary-runs/${run}/approve`);
  const headers = new Headers(call[1].headers);
  assert.equal(headers.get("Idempotency-Key"), `ca1-${"f".repeat(64)}`);
  assert.equal(headers.get("If-Heel-Control-Generation"), "7");
  assert.deepEqual(JSON.parse(String(call[1].body)), {
    schema_version: "heel.canary-execution-approval.v1",
    projection_digest: digest,
    hostname_retype: "staging.acme.dev",
    reason: "Release boundary check",
  });
});


test("submitApprovalProjection accepts only the frozen local manifest projection and returns a safe summary", async () => {
  const projection = {
    schema_version: "heel.approval-manifest-projection.v1",
    projection_id: "ap_canary",
    workspace_id: workspace,
    project_id: project,
    environment: { environment_id: "env_0123456789abcdef0123456789abcdef", verification_record_digest: "b".repeat(64), origin: "https://staging.acme.dev", environment_class: "staging" },
    runner: { runner_id: "runr_0123456789abcdef0123456789abcdef", runner_key_id: "key_0123456789abcdef", runner_version: "1.2.0", adapter_versions: ["1.0.0"] },
    compiler: { compiler_version: "1.2.0", engine_version: "1.2.0" },
    scenarios: [{ ordinal: 0, scenario_id: "anonymous_read", adapter_version: "1.0.0" }],
    actions: [{ ordinal: 0, scenario_id: "anonymous_read", adapter_version: "1.0.0", method: "GET", route_template: "/account", semantic_auth_role: "anonymous", assertion_class: "anonymous_authenticated", allowed_status_codes: [200, 401], allowed_body_shapes: ["json_object"], side_effect_class: "read_only" }],
    budgets: { maximum_requests: 4, maximum_concurrency: 1, action_timeout_ms: 5000, wall_timeout_ms: 45_000, maximum_response_bytes: 262_144 },
    egress: { hostname: "staging.acme.dev", port: 443, redirect_policy: "deny" },
    retry_policy: { maximum_retries: 0, retryable_failure_codes: [] },
    compiled_at_ms: 1,
    manifest_digest: "c".repeat(64),
    projection_digest: digest,
    signing_key_id: "key_0123456789abcdef",
    signature_b64: `${"A".repeat(86)}==`,
  };
  let body: unknown;
  const api = new CanaryApi({ transport: async (_path, init) => {
    body = JSON.parse(String(init.body));
    return jsonResponse({ schema_version: "heel.canary-projection-submitted.v1", approval_id: "ap_canary", run_id: run, status: "awaiting_execution_approval", projection_digest: digest }, 201);
  } });
  const summary = await api.submitApprovalProjection(workspace, project, projection);
  assert.deepEqual(body, projection);
  assert.deepEqual(summary.routes, ["GET /account"]);
  assert.deepEqual(summary.scenarios, ["anonymous_read"]);
  assert.equal(summary.requestBudget, 4);
  assert.equal(Object.isFrozen(summary.routes), true);

  await assert.rejects(api.submitApprovalProjection(workspace, project, { ...projection, raw_response: "secret" }), (error: unknown) => error instanceof CanaryApiError && error.code === "invalid_request");
});


test("environment activation validates exact public records including proof versions", async () => {
  const value = {
    schema_version: "VerifiedEnvironment.v1",
    environment_id: "env_0123456789abcdef0123456789abcdef",
    origin: "https://staging.acme.dev",
    environment_class: "staging",
    status: "verified",
    attestation: "ownership verified; environment classification supplied by you",
    attestation_version: "v1",
    attestation_acknowledgement: "accepted",
    proof_method: "https-file",
    proof_version: "https-file.v1",
    normalization_version: "exact-origin.v1",
    challenge_generation: 1,
    challenge_expires_at: 1000.5,
    last_failure_code: null,
    verified_at: 900.5,
    proof_expires_at: 2000.5,
    verification_record_digest: digest,
    revoked_at: null,
    is_executable: true,
  };
  const api = new CanaryApi({ transport: async () => jsonResponse({ schema_version: "heel.verified-environment-list.v1", environments: [value] }) });
  const environments = await api.listEnvironments(workspace, project);
  assert.equal(environments[0].isExecutable, true);
  assert.equal(environments[0].schemaVersion, "VerifiedEnvironment.v1");
  assert.equal(Object.isFrozen(environments), true);

  const malformed = new CanaryApi({ transport: async () => jsonResponse({ schema_version: "heel.verified-environment-list.v1", environments: [{ ...value, proof_version: "future" }] }) });
  await assert.rejects(malformed.listEnvironments(workspace, project), (error: unknown) => error instanceof CanaryApiError && error.code === "invalid_response");
});


test("canary actions use fixed routes and closed disclosure metadata", async () => {
  const calls: Array<[string, RequestInit]> = [];
  const responses = [
    jsonResponse({ schema_version: "heel.canary-run-events.v1", run_id: run, events: [] }),
    jsonResponse({ schema_version: "heel.canary-stop-requested.v1", run_id: run, stop_generation: 7, deadline_ms: 10_000, reason: "cloud_stop" }),
    jsonResponse({
      schema_version: "heel.disclosure-permit.v1", permit_id: "cdp_0123456789abcdef0123456789abcdef",
      workspace_id: workspace, project_id: project, run_id: run,
      grant_id: "cgr_0123456789abcdef0123456789abcdef",
      runner_binding: { runner_id: "runr_0123456789abcdef0123456789abcdef", runner_key_id: "key_0123456789abcdef" },
      projection: { schema_version: "heel.canary-findings-projection.v1", projection_digest: digest, maximum_bytes: 1024, scenario_count: 2, finding_count: 1 },
      approved_by: "usr_0123456789abcdef", approved_at_ms: 1, issued_at_ms: 1, expires_at_ms: 600001,
      permit_nonce: "nonce_0123456789abcdef", permit_digest: "b".repeat(64), signing_key_id: "cloud_0123456789abcdef", signature_b64: "A".repeat(86) + "==",
    }, 201),
    jsonResponse({ schema_version: "heel.canary-disclosure-state.v1", run_id: run, status: "local_only" }),
  ];
  const api = new CanaryApi({ transport: async (path, init) => {
    calls.push([path, init]);
    return responses.shift()!;
  } });
  await api.listEvents(workspace, project, run);
  await api.stopRun(workspace, project, run, 7);
  const metadata = { projectionDigest: digest, projectionBytes: 1024, scenarioCount: 2, findingCount: 1 };
  const permit = await api.createDisclosurePermit(workspace, project, run, metadata);
  await api.markDisclosureLocalOnly(workspace, project, run, metadata);

  assert.equal(Object.isFrozen(permit), true);
  assert.deepEqual(calls.map(([path]) => path), [
    `/api/control-plane/v1/workspaces/${workspace}/projects/${project}/canary-runs/${run}/events`,
    `/api/control-plane/v1/workspaces/${workspace}/projects/${project}/canary-runs/${run}/stop`,
    `/api/control-plane/v1/workspaces/${workspace}/projects/${project}/canary-runs/${run}/disclosure-permits`,
    `/api/control-plane/v1/workspaces/${workspace}/projects/${project}/canary-runs/${run}/disclosure-local-only`,
  ]);
  assert.equal(new Headers(calls[1][1].headers).get("If-Heel-Control-Generation"), "7");
  assert.deepEqual(JSON.parse(String(calls[2][1].body)), {
    schema_version: "heel.canary-disclosure-request.v1",
    projection_digest: digest,
    projection_bytes: 1024,
    scenario_count: 2,
    finding_count: 1,
  });
  assert.equal(JSON.parse(String(calls[3][1].body)).schema_version, "heel.canary-disclosure-local-only.v1");
});


test("stable canary errors never reflect server text", async () => {
  const api = new CanaryApi({ transport: async () => jsonResponse({
    schema_version: "heel.canary-error.v1",
    code: "hostname_confirmation_mismatch",
  }, 400) });
  await assert.rejects(api.getRun(workspace, project, run), (error: unknown) => {
    assert.ok(error instanceof CanaryApiError);
    assert.equal(error.code, "hostname_confirmation_mismatch");
    assert.equal(error.message.includes("script"), false);
    return true;
  });

  const malformed = new CanaryApi({ transport: async () => jsonResponse({
    schema_version: "heel.canary-error.v1",
    code: "hostname_confirmation_mismatch",
    error: "<script>reflect me</script>",
  }, 400) });
  await assert.rejects(malformed.getRun(workspace, project, run), (error: unknown) => {
    assert.ok(error instanceof CanaryApiError);
    assert.equal(error.code, "unavailable");
    assert.equal(error.message.includes("script"), false);
    return true;
  });
});


test("timeouts abort the transport and stay unavailable", async () => {
  let observed: AbortSignal | null = null;
  const api = new CanaryApi({ timeoutMs: 5, transport: async (_path, init) => {
    observed = init.signal as AbortSignal;
    await new Promise((_resolve, reject) => observed!.addEventListener("abort", () => reject(observed!.reason), { once: true }));
    throw new Error("unreachable");
  } });
  await assert.rejects(api.getRun(workspace, project, run), (error: unknown) => {
    assert.ok(error instanceof CanaryApiError);
    assert.equal(error.code, "unavailable");
    return true;
  });
  assert.equal(observed?.aborted, true);
});


test("worker source declares every exact canary authority route and result upload cap", async () => {
  const worker = await readFile(new URL("../worker/index.ts", import.meta.url), "utf8");
  for (const fragment of [
    "const CANARY_APPROVAL_PROJECTION_ROUTE = new RegExp(",
    "const CANARY_RUN_ROUTE = new RegExp(",
    "const CANARY_RUN_EVENTS_ROUTE = new RegExp(",
    "const CANARY_RUN_APPROVE_ROUTE = new RegExp(",
    "const CANARY_RUN_STOP_ROUTE = new RegExp(",
    "const CANARY_DISCLOSURE_PERMIT_ROUTE = new RegExp(",
    "const CANARY_DISCLOSURE_LOCAL_ROUTE = new RegExp(",
    "const CANARY_FINDINGS_ROUTE = new RegExp(",
    "const RUNNER_RESULT_PROJECTION = new RegExp(",
    "const MAX_RUNNER_RESULT_PROJECTION_BODY_BYTES = 272 * 1024;",
  ]) assert.equal(worker.split(fragment).length - 1, 1, `missing exact ${fragment}`);
});


test("runner UI never places one-use invitation material in shell argv or URLs", async () => {
  const runnerPage = await readFile(new URL("../app/runner/page.tsx", import.meta.url), "utf8");
  assert.equal(runnerPage.includes("--invitation"), false);
  assert.equal(runnerPage.includes("?invitation="), false);
  assert.match(runnerPage, /read --silent|paste it only when the runner prompts/i);
});


test("actual worker isolates human canary and runner-result authority headers and routes", async (context) => {
  const source = await readFile(new URL("../worker/index.ts", import.meta.url), "utf8");
  const runnable = source
    .replace('import { handleImageOptimization, DEFAULT_DEVICE_SIZES, DEFAULT_IMAGE_SIZES } from "vinext/server/image-optimization";', 'const handleImageOptimization = async () => new Response("unused"); const DEFAULT_DEVICE_SIZES: number[] = []; const DEFAULT_IMAGE_SIZES: number[] = [];')
    .replace('import handler from "vinext/server/app-router-entry";', 'const handler = { fetch: async () => new Response("unused", { status: 404 }) };');
  const directory = await mkdtemp(join(tmpdir(), "heel-edge-test-"));
  const modulePath = join(directory, "worker.ts");
  context.after(() => rm(directory, { recursive: true, force: true }));
  await writeFile(modulePath, runnable);
  class LengthStream extends TransformStream<Uint8Array, Uint8Array> {
    constructor(expected: number) {
      let received = 0;
      super({
        transform(chunk, controller) { received += chunk.byteLength; controller.enqueue(chunk); },
        flush() { if (received !== expected) throw new Error("length mismatch"); },
      });
    }
  }
  (globalThis as typeof globalThis & { FixedLengthStream: typeof LengthStream }).FixedLengthStream = LengthStream;
  const worker = (await import(`${pathToFileURL(modulePath).href}?v=${Date.now()}`)).default;
  const upstream: Request[] = [];
  const env = {
    CONTROL_PLANE_EDGE_SECRET: "e".repeat(43),
    PUBLIC_ORIGIN: "https://heel.example",
    CONTROL_PLANE: { fetch: async (request: Request) => {
      upstream.push(request);
      return jsonResponse({ ok: true }, 200, {
        "X-Heel-Runner-Next-Nonce": `${"A".repeat(43)}=`,
        Forwarded: "for=private",
        Connection: "X-Leak",
        "X-Leak": "private",
        "X-Heel-Internal-Origin": "private",
      });
    } },
  };
  const ctx = { waitUntil() {}, passThroughOnException() {} };
  const body = JSON.stringify({ schema_version: "heel.canary-execution-approval.v1", projection_digest: digest, hostname_retype: "staging.acme.dev", reason: "Release boundary check" });
  const human = new Request(`https://heel.example/api/control-plane/v1/workspaces/${workspace}/projects/${project}/canary-runs/${run}/approve`, {
    method: "POST", body, headers: {
      "Content-Type": "application/json", "Content-Length": String(Buffer.byteLength(body)),
      Cookie: "__Host-heel_session=session-token", Origin: "https://heel.example", "Sec-Fetch-Site": "same-origin",
      "Idempotency-Key": `ca1-${"f".repeat(64)}`, "If-Heel-Control-Generation": "7",
      Forwarded: "host=attacker", "X-Forwarded-Host": "attacker", "X-Heel-Internal-Origin": "attacker",
      "X-Heel-Runner-Id": "runner-crossing-attempt",
    },
  });
  const humanResponse = await worker.fetch(human, env, ctx);
  assert.equal(humanResponse.status, 200);
  assert.equal(upstream.length, 1);
  assert.deepEqual([...upstream[0].headers.keys()].sort(), [
    "content-encoding", "content-length", "content-type", "cookie", "idempotency-key",
    "if-heel-control-generation", "origin", "x-heel-edge-auth", "x-heel-internal-origin",
  ]);
  assert.equal(upstream[0].headers.get("cookie"), "heel_session=session-token");
  assert.equal(humanResponse.headers.get("x-heel-runner-next-nonce"), null);
  assert.equal(humanResponse.headers.get("forwarded"), null);
  assert.equal(humanResponse.headers.get("x-leak"), null);
  assert.equal(humanResponse.headers.get("x-heel-internal-origin"), null);

  const crossOrigin = new Request(human.url, { method: "POST", body, headers: {
    "Content-Type": "application/json", "Content-Length": String(Buffer.byteLength(body)),
    Cookie: "__Host-heel_session=session-token", Origin: "https://attacker.invalid", "Sec-Fetch-Site": "cross-site",
    "Idempotency-Key": `ca1-${"f".repeat(64)}`, "If-Heel-Control-Generation": "7",
  } });
  assert.equal((await worker.fetch(crossOrigin, env, ctx)).status, 400);
  assert.equal(upstream.length, 1);

  const generic = await worker.fetch(new Request(`https://heel.example/api/control-plane/v1/workspaces/${workspace}/runs`, { method: "GET" }), env, ctx);
  assert.equal(generic.status, 404);
  const wrongMethod = await worker.fetch(new Request(`https://heel.example/api/control-plane/v1/workspaces/${workspace}/projects/${project}/canary-approval-projections`, { method: "GET" }), env, ctx);
  assert.equal(wrongMethod.status, 404);

  const runner = "runr_0123456789abcdef0123456789abcdef";
  const uploadBody = "{}";
  const runnerHeaders = {
    "Content-Type": "application/json", "Content-Length": "2", "X-Heel-Runner-Id": runner,
    "X-Heel-Runner-Key-Id": "key", "X-Heel-Runner-Timestamp-Ms": "1", "X-Heel-Runner-Nonce": "nonce",
    "X-Heel-Runner-Sequence": "1", "X-Heel-Runner-Signature": "signature",
  };
  const resultPath = `https://heel.example/api/control-plane/v1/workspaces/${workspace}/runners/${runner}/runs/${run}/result-projection`;
  const mixed = await worker.fetch(new Request(resultPath, { method: "POST", body: uploadBody, headers: { ...runnerHeaders, Cookie: "__Host-heel_session=session-token" } }), env, ctx);
  assert.equal(mixed.status, 400);
  assert.equal(upstream.length, 1);
  const oversized = await worker.fetch(new Request(resultPath, { method: "POST", body: uploadBody, headers: { ...runnerHeaders, "Content-Length": String(272 * 1024 + 1) } }), env, ctx);
  assert.equal(oversized.status, 400);
  assert.equal(upstream.length, 1);
  const accepted = await worker.fetch(new Request(resultPath, { method: "POST", body: uploadBody, headers: runnerHeaders }), env, ctx);
  assert.equal(accepted.status, 200);
  assert.equal(accepted.headers.get("x-heel-runner-next-nonce"), `${"A".repeat(43)}=`);
  assert.equal(upstream.length, 2);
  assert.deepEqual([...upstream[1].headers.keys()].sort(), [
    "content-encoding", "content-length", "content-type", "x-heel-edge-auth", "x-heel-runner-id",
    "x-heel-runner-key-id", "x-heel-runner-nonce", "x-heel-runner-sequence",
    "x-heel-runner-signature", "x-heel-runner-timestamp-ms",
  ]);

  const invalidNonceEnv = {
    ...env,
    CONTROL_PLANE: { fetch: async () => jsonResponse({ ok: true }, 200, { "X-Heel-Runner-Next-Nonce": "attacker,duplicate" }) },
  };
  const invalidNonce = await worker.fetch(new Request(resultPath, { method: "POST", body: uploadBody, headers: runnerHeaders }), invalidNonceEnv, ctx);
  assert.equal(invalidNonce.status, 502);
  assert.equal(invalidNonce.headers.get("x-heel-runner-next-nonce"), null);
});
