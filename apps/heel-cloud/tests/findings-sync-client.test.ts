// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import { createHash, createHmac } from "node:crypto";
import { afterEach, describe, expect, test, vi } from "vitest";

import sampleReview from "../data/sample-review.v1.json";
import {
  FindingsSyncClient,
  FindingsSyncClientError,
  WORKER_PROTOCOL_VERSION,
  sendApprovedFindingsSyncV1,
  type FindingsSyncApprovalV1,
  type FindingsSyncWorkerLike,
  type PreparedFindingsSyncV1,
} from "../lib/findings-sync-client";
import type { FindingsSyncReceiptV1, FindingsSyncRequestV1 } from "../lib/findings-sync-v1";
import type { ReviewEnvelopeV1, ReviewFindingV1 } from "../lib/review-v1";


const PROJECT_REF = "prj_0123456789abcdef0123456789abcdef";
const WORKSPACE_REF = "ws_0123456789abcdef0123456789abcdef";
const KEY = Uint8Array.from({ length: 32 }, (_, index) => index);
const NOW = 1_786_000_000_000;
const CONTROL_CODES: Record<string, string> = {
  export_without_entitlement: "server_side_entitlement_check",
  export_without_tenant_quota: "tenant_quota",
  endpoint_without_tenant_filter: "tenant_filter",
  ui_backing_endpoint_paid_api_bypass: "shared_ui_api_entitlement_and_lookup_quota",
  unmetered_billable_resource: "server_side_meter_accounting_and_cost_ceiling",
  stackable_coupon_without_redemption_limit: "redemption_limit_and_proof_of_uniqueness",
  oauth_scope_overbroad: "oauth_scope_minimization_and_approval",
  admin_action_without_role_or_audit_control: "admin_role_gate_and_audit_event",
  agent_surface_overscope: "tool_scope_minimization",
  feature_flag_plan_mismatch: "server_side_feature_entitlement_check",
  tenant_or_data_control_change: "tenant_data_control_review",
};


function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") return JSON.stringify(Object.is(value, -0) ? 0 : value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const item = value as Record<string, unknown>;
  return `{${Object.keys(item).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(item[key])}`).join(",")}}`;
}


function digest(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value), "utf8").digest("hex");
}


function tagged(tag: string, values: string[]): string {
  return createHmac("sha256", KEY).update(canonicalJson([
    "heel.findings-sync.v1", tag, ...values,
  ]), "utf8").digest("hex");
}


function project(review: ReviewEnvelopeV1): Record<string, unknown> {
  const findings = review.findings.map((finding: ReviewFindingV1) => {
    const surfaceRef = `surf1_${tagged("surface", [finding.surface_type, finding.surface_id])}`;
    return {
      finding_id: `find1_${tagged("finding", [surfaceRef, finding.risk])}`,
      surface_ref: surfaceRef,
      surface_type: finding.surface_type,
      risk_code: finding.risk,
      control_code: CONTROL_CODES[finding.risk],
      severity: finding.severity,
      reachable: finding.reachable,
    };
  }).sort((left, right) => left.finding_id.localeCompare(right.finding_id));
  const blockers = findings.filter(({ severity }) => severity === "block").length;
  const request: Record<string, unknown> = {
    schema_version: "heel.findings-sync.v1",
    project_ref: PROJECT_REF,
    source: {
      engine_version: review.engine_version,
      execution_mode: review.execution_mode,
      result_ref: `src1_${tagged("source", [review.result_hash])}`,
    },
    gate_status: blockers > 0 ? "block" : findings.length > 0 ? "warn" : "pass",
    summary: { findings: findings.length, blockers },
    findings,
  };
  request.projection_hash = digest({
    schema_version: request.schema_version,
    gate_status: request.gate_status,
    summary: request.summary,
    findings: request.findings,
  });
  return request;
}


function preparedSync(): PreparedFindingsSyncV1 {
  const request = project(sampleReview as ReviewEnvelopeV1) as unknown as FindingsSyncRequestV1;
  const requestJson = canonicalJson(request);
  const requestDigest = digest(request);
  return {
    request,
    requestJson,
    requestDigest,
    idempotencyKey: `fs1-${requestDigest}`,
  };
}


function approvalFor(
  prepared: PreparedFindingsSyncV1,
  overrides: Partial<FindingsSyncApprovalV1> = {},
): FindingsSyncApprovalV1 {
  return {
    workspaceRef: WORKSPACE_REF,
    projectRef: prepared.request.project_ref,
    requestDigest: prepared.requestDigest,
    approvedAt: NOW - 1_000,
    expiresAt: NOW + 60_000,
    ...overrides,
  };
}


function receiptFor(
  prepared: PreparedFindingsSyncV1,
  overrides: Partial<FindingsSyncReceiptV1> = {},
): FindingsSyncReceiptV1 {
  return {
    schema_version: "heel.findings-sync-receipt.v1",
    receipt_id: `fsr_${"1".repeat(32)}`,
    project_ref: prepared.request.project_ref,
    request_digest: prepared.requestDigest,
    projection_hash: prepared.request.projection_hash,
    synced_review_id: `synrev_${"2".repeat(32)}`,
    disposition: "created",
    metered: true,
    accepted_at: "2026-08-04T12:34:56.789Z",
    ...overrides,
  };
}


async function clientFailure(action: () => Promise<unknown>): Promise<FindingsSyncClientError> {
  try {
    await action();
  } catch (error) {
    expect(error).toBeInstanceOf(FindingsSyncClientError);
    return error as FindingsSyncClientError;
  }
  throw new Error("expected findings sync client failure");
}


class FakeWorker implements FindingsSyncWorkerLike {
  onmessage: ((event: MessageEvent<string>) => void) | null = null;
  onerror: ((event: ErrorEvent) => void) | null = null;
  keyAtPost: number[] = [];
  message: Record<string, unknown> | null = null;
  transfer: Transferable[] = [];
  terminated = false;

  postMessage(message: Record<string, unknown>, transfer: Transferable[]): void {
    this.message = message;
    this.transfer = transfer;
    this.keyAtPost = Array.from(new Uint8Array(message.namespace_key as ArrayBuffer));
  }

  terminate(): void {
    this.terminated = true;
  }

  emit(value: Record<string, unknown>): void {
    this.onmessage?.({ data: JSON.stringify(value) } as MessageEvent<string>);
  }
}


afterEach(() => vi.unstubAllGlobals());


describe("FindingsSyncClient", () => {
  test("previews through a transferred key copy with no network and returns only prepared projection data", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    const worker = new FakeWorker();
    const client = new FindingsSyncClient({ workerFactory: () => worker });
    worker.emit({ type: "ready", protocol_version: WORKER_PROTOCOL_VERSION });
    await client.whenReady();

    const callerKey = KEY.slice();
    const pending = client.preview(sampleReview as ReviewEnvelopeV1, PROJECT_REF, callerKey);
    expect(worker.message).toMatchObject({
      type: "project_findings",
      protocol_version: WORKER_PROTOCOL_VERSION,
      request_id: "request_1",
      project_ref: PROJECT_REF,
    });
    expect(Object.keys(worker.message!).sort()).toEqual([
      "namespace_key", "project_ref", "protocol_version", "request_id", "review_json", "type",
    ]);
    expect(worker.keyAtPost).toEqual(Array.from(KEY));
    expect(callerKey).toEqual(KEY);
    expect(worker.transfer).toEqual([worker.message!.namespace_key]);
    expect(Array.from(new Uint8Array(worker.message!.namespace_key as ArrayBuffer))).toEqual(new Array(32).fill(0));

    const request = project(sampleReview as ReviewEnvelopeV1);
    worker.emit({
      type: "findings_result",
      protocol_version: WORKER_PROTOCOL_VERSION,
      request_id: "request_1",
      request_json: canonicalJson(request),
    });
    const prepared = await pending;
    expect(prepared).toEqual({
      request,
      requestJson: canonicalJson(request),
      requestDigest: digest(request),
      idempotencyKey: `fs1-${digest(request)}`,
    });
    expect(Object.isFrozen(prepared)).toBe(true);
    expect(Object.isFrozen(prepared.request.findings)).toBe(true);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  test("rejects projection responses with extra fields and can be disposed without network", async () => {
    const fetchSpy = vi.fn();
    vi.stubGlobal("fetch", fetchSpy);
    const worker = new FakeWorker();
    const client = new FindingsSyncClient({ workerFactory: () => worker });
    worker.emit({ type: "ready", protocol_version: WORKER_PROTOCOL_VERSION });
    const pending = client.preview(sampleReview as ReviewEnvelopeV1, PROJECT_REF, KEY);
    worker.emit({
      type: "findings_result",
      protocol_version: WORKER_PROTOCOL_VERSION,
      request_id: "request_1",
      request_json: canonicalJson(project(sampleReview as ReviewEnvelopeV1)),
      raw_review: "never-cross",
    });
    await expect(pending).rejects.not.toThrow("never-cross");
    client.dispose();
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  test("sends an unexpired exact approval through the injected transport and binds its receipt", async () => {
    const prepared = preparedSync();
    const receipt = receiptFor(prepared);
    const transport = vi.fn(async () => canonicalJson(receipt));

    await expect(sendApprovedFindingsSyncV1(
      prepared,
      approvalFor(prepared),
      WORKSPACE_REF,
      transport,
      NOW,
    )).resolves.toEqual(receipt);
    expect(transport).toHaveBeenCalledTimes(1);
    expect(transport).toHaveBeenCalledWith(prepared.requestJson, prepared.idempotencyKey);
  });

  test.each([
    ["expired", (prepared: PreparedFindingsSyncV1) => approvalFor(prepared, { expiresAt: NOW - 1 })],
    ["future", (prepared: PreparedFindingsSyncV1) => approvalFor(prepared, { approvedAt: NOW + 1 })],
    ["wrong project", (prepared: PreparedFindingsSyncV1) => approvalFor(prepared, {
      projectRef: `prj_${"f".repeat(32)}`,
    })],
    ["wrong digest", (prepared: PreparedFindingsSyncV1) => approvalFor(prepared, {
      requestDigest: "0".repeat(64),
    })],
    ["overlong", (prepared: PreparedFindingsSyncV1) => approvalFor(prepared, {
      approvedAt: NOW - 10 * 60 * 1_000 - 1,
    })],
  ])("rejects a %s approval before invoking transport", async (_label, makeApproval) => {
    const prepared = preparedSync();
    const transport = vi.fn(async () => canonicalJson(receiptFor(prepared)));

    await expect(sendApprovedFindingsSyncV1(
      prepared,
      makeApproval(prepared),
      WORKSPACE_REF,
      transport,
      NOW,
    )).rejects.toMatchObject({ code: "projection_failed" });
    expect(transport).not.toHaveBeenCalled();
  });

  test.each([
    ["project", (prepared: PreparedFindingsSyncV1) => receiptFor(prepared, {
      project_ref: `prj_${"f".repeat(32)}`,
    })],
    ["request digest", (prepared: PreparedFindingsSyncV1) => receiptFor(prepared, {
      request_digest: "0".repeat(64),
    })],
    ["projection", (prepared: PreparedFindingsSyncV1) => receiptFor(prepared, {
      projection_hash: "0".repeat(64),
    })],
  ])("rejects a receipt bound to the wrong %s", async (_label, makeReceipt) => {
    const prepared = preparedSync();
    const transport = vi.fn(async () => canonicalJson(makeReceipt(prepared)));

    await expect(sendApprovedFindingsSyncV1(
      prepared,
      approvalFor(prepared),
      WORKSPACE_REF,
      transport,
      NOW,
    )).rejects.toMatchObject({ code: "context_mismatch" });
    expect(transport).toHaveBeenCalledTimes(1);
  });

  test.each([
    ["malformed", "{not-json"],
    ["duplicate", canonicalJson(receiptFor(preparedSync())).replace(
      `"receipt_id":"fsr_${"1".repeat(32)}"`,
      `"receipt_id":"fsr_${"1".repeat(32)}","receipt_id":"fsr_${"2".repeat(32)}"`,
    )],
  ])("rejects a %s transport receipt with a public non-echoing contract error", async (_label, response) => {
    const prepared = preparedSync();
    const error = await clientFailure(() => sendApprovedFindingsSyncV1(
      prepared,
      approvalFor(prepared),
      WORKSPACE_REF,
      async () => response,
      NOW,
    ));
    expect(error.message).not.toContain(response.slice(0, 16));
  });

  test("redacts arbitrary transport failures instead of exposing backend response text", async () => {
    const prepared = preparedSync();
    const secret = "private-backend-response-never-echo";
    const error = await clientFailure(() => sendApprovedFindingsSyncV1(
      prepared,
      approvalFor(prepared),
      WORKSPACE_REF,
      async () => { throw new Error(secret); },
      NOW,
    ));

    expect(error).toMatchObject({ code: "projection_failed" });
    expect(error.message).not.toContain(secret);
  });

  test("binds approval to the expected workspace before invoking transport", async () => {
    const prepared = preparedSync();
    const transport = vi.fn(async () => canonicalJson(receiptFor(prepared)));

    await expect(sendApprovedFindingsSyncV1(
      prepared,
      approvalFor(prepared),
      "ws_ffffffffffffffffffffffffffffffff",
      transport,
      NOW,
    )).rejects.toMatchObject({ code: "projection_failed" });
    expect(transport).not.toHaveBeenCalled();
  });

  test("rejects a non-finite approval clock before invoking transport", async () => {
    const prepared = preparedSync();
    const transport = vi.fn(async () => canonicalJson(receiptFor(prepared)));

    await expect(sendApprovedFindingsSyncV1(
      prepared,
      approvalFor(prepared, { expiresAt: NOW - 1 }),
      WORKSPACE_REF,
      transport,
      Number.NaN,
    )).rejects.toMatchObject({ code: "projection_failed" });
    expect(transport).not.toHaveBeenCalled();
  });

  test.each([
    ["request bytes", (prepared: PreparedFindingsSyncV1) => ({
      ...prepared,
      requestJson: canonicalJson({ ...prepared.request, raw_review: "never-cross" }),
    })],
    ["request object", (prepared: PreparedFindingsSyncV1) => ({
      ...prepared,
      request: { ...prepared.request, raw_review: "never-cross" } as FindingsSyncRequestV1,
    })],
    ["digest", (prepared: PreparedFindingsSyncV1) => ({
      ...prepared,
      requestDigest: "0".repeat(64),
    })],
    ["idempotency key", (prepared: PreparedFindingsSyncV1) => ({
      ...prepared,
      idempotencyKey: `fs1-${"0".repeat(64)}` as const,
    })],
  ])("rejects tampered prepared %s before invoking transport", async (_label, mutate) => {
    const prepared = preparedSync();
    const transport = vi.fn(async () => canonicalJson(receiptFor(prepared)));

    await expect(sendApprovedFindingsSyncV1(
      mutate(prepared),
      approvalFor(prepared),
      WORKSPACE_REF,
      transport,
      NOW,
    )).rejects.toMatchObject({ code: "projection_failed" });
    expect(transport).not.toHaveBeenCalled();
  });
});
