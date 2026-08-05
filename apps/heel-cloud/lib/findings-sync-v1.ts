// SPDX-License-Identifier: LicenseRef-Heel-Commercial

/** Exact browser-side validation for Heel's privacy-minimized findings wire contract. */

import { parseReviewEnvelopeV1, type ReviewEnvelopeV1 } from "./review-v1";


export const FINDINGS_SYNC_SCHEMA_VERSION = "heel.findings-sync.v1" as const;
export const FINDINGS_SYNC_RECEIPT_SCHEMA_VERSION = "heel.findings-sync-receipt.v1" as const;
export const MAX_FINDINGS_SYNC_BYTES = 256 * 1024;
export const MAX_FINDINGS_SYNC_RECEIPT_BYTES = 8 * 1024;
export const MAX_FINDINGS = 512;
export const MAX_JSON_DEPTH = 16;

export type SourceEngineVersion = "1.1.0" | "1.1.1" | "1.2.0";
export type SourceExecutionMode = "browser_local" | "machine_local" | "cloud_isolated";
export type FindingsSyncGateStatus = "pass" | "warn" | "block";
export type FindingsSyncSeverity = "warn" | "block";
export type FindingsSyncRiskCode =
  | "export_without_entitlement"
  | "export_without_tenant_quota"
  | "endpoint_without_tenant_filter"
  | "ui_backing_endpoint_paid_api_bypass"
  | "unmetered_billable_resource"
  | "stackable_coupon_without_redemption_limit"
  | "oauth_scope_overbroad"
  | "admin_action_without_role_or_audit_control"
  | "agent_surface_overscope"
  | "feature_flag_plan_mismatch"
  | "tenant_or_data_control_change";
export type FindingsSyncControlCode =
  | "server_side_entitlement_check"
  | "tenant_quota"
  | "tenant_filter"
  | "shared_ui_api_entitlement_and_lookup_quota"
  | "server_side_meter_accounting_and_cost_ceiling"
  | "redemption_limit_and_proof_of_uniqueness"
  | "oauth_scope_minimization_and_approval"
  | "admin_role_gate_and_audit_event"
  | "tool_scope_minimization"
  | "server_side_feature_entitlement_check"
  | "tenant_data_control_review";
export type FindingsSyncSurfaceType =
  | "endpoints_routes"
  | "exports"
  | "meters"
  | "billing_objects"
  | "coupons_promotions"
  | "integration_oauth_apps"
  | "support_admin_actions"
  | "agent_tools"
  | "mcp_connectors"
  | "features_flags"
  | "data_classes"
  | "declared_controls";

export interface FindingsSyncFindingV1 {
  finding_id: `find1_${string}`;
  surface_ref: `surf1_${string}`;
  surface_type: FindingsSyncSurfaceType;
  risk_code: FindingsSyncRiskCode;
  control_code: FindingsSyncControlCode;
  severity: FindingsSyncSeverity;
  reachable: boolean;
}

export interface FindingsSyncRequestV1 {
  schema_version: typeof FINDINGS_SYNC_SCHEMA_VERSION;
  project_ref: `prj_${string}`;
  source: {
    engine_version: SourceEngineVersion;
    execution_mode: SourceExecutionMode;
    result_ref: `src1_${string}`;
  };
  gate_status: FindingsSyncGateStatus;
  summary: { findings: number; blockers: number };
  findings: FindingsSyncFindingV1[];
  projection_hash: string;
}

export interface FindingsSyncReceiptV1 {
  schema_version: typeof FINDINGS_SYNC_RECEIPT_SCHEMA_VERSION;
  receipt_id: `fsr_${string}`;
  project_ref: `prj_${string}`;
  request_digest: string;
  projection_hash: string;
  synced_review_id: `synrev_${string}`;
  disposition: "created" | "reused";
  metered: boolean;
  accepted_at: string;
}

export interface PreparedFindingsSyncBindingV1 {
  request: FindingsSyncRequestV1;
  requestJson: string;
  requestDigest: string;
  idempotencyKey: `fs1-${string}`;
}

export type FindingsSyncContractErrorCode =
  | "invalid_json"
  | "duplicate_field"
  | "size_limit"
  | "complexity_limit"
  | "invalid_shape"
  | "invalid_value"
  | "invalid_identity"
  | "invalid_hash"
  | "invalid_receipt"
  | "context_mismatch";

const ERROR_MESSAGES: Readonly<Record<FindingsSyncContractErrorCode, string>> = Object.freeze({
  invalid_json: "The findings data is not valid JSON.",
  duplicate_field: "The findings data contains duplicate fields.",
  size_limit: "The findings data exceeds its size limit.",
  complexity_limit: "The findings data exceeds its complexity limit.",
  invalid_shape: "The findings data does not match the v1 shape.",
  invalid_value: "The findings data contains an unsupported value.",
  invalid_identity: "The findings data contains an invalid pseudonymous identity.",
  invalid_hash: "The findings data does not match its content hash.",
  invalid_receipt: "The findings receipt is invalid.",
  context_mismatch: "The findings projection does not match its local review context.",
});

export class FindingsSyncContractError extends Error {
  readonly code: FindingsSyncContractErrorCode;

  constructor(code: FindingsSyncContractErrorCode) {
    super(ERROR_MESSAGES[code]);
    this.name = "FindingsSyncContractError";
    this.code = code;
  }
}

interface RiskCatalogEntry {
  rawControl: string;
  controlCode: FindingsSyncControlCode;
  surfaces: readonly FindingsSyncSurfaceType[];
  states: readonly string[];
}

const RISK_CATALOG: Readonly<Record<FindingsSyncRiskCode, RiskCatalogEntry>> = Object.freeze({
  export_without_entitlement: Object.freeze({
    rawControl: "server-side entitlement check",
    controlCode: "server_side_entitlement_check",
    surfaces: Object.freeze(["endpoints_routes", "exports"] as const),
    states: Object.freeze(["warn:false", "block:true"]),
  }),
  export_without_tenant_quota: Object.freeze({
    rawControl: "tenant quota",
    controlCode: "tenant_quota",
    surfaces: Object.freeze(["endpoints_routes", "exports"] as const),
    states: Object.freeze(["warn:false", "block:true"]),
  }),
  endpoint_without_tenant_filter: Object.freeze({
    rawControl: "tenant filter",
    controlCode: "tenant_filter",
    surfaces: Object.freeze(["endpoints_routes"] as const),
    states: Object.freeze(["warn:false", "block:true"]),
  }),
  ui_backing_endpoint_paid_api_bypass: Object.freeze({
    rawControl: "shared UI/API entitlement and lookup quota",
    controlCode: "shared_ui_api_entitlement_and_lookup_quota",
    surfaces: Object.freeze(["endpoints_routes"] as const),
    states: Object.freeze(["warn:false", "block:true"]),
  }),
  unmetered_billable_resource: Object.freeze({
    rawControl: "server-side meter accounting and cost ceiling",
    controlCode: "server_side_meter_accounting_and_cost_ceiling",
    surfaces: Object.freeze(["meters", "billing_objects"] as const),
    states: Object.freeze(["warn:false", "warn:true"]),
  }),
  stackable_coupon_without_redemption_limit: Object.freeze({
    rawControl: "redemption limit and proof of uniqueness",
    controlCode: "redemption_limit_and_proof_of_uniqueness",
    surfaces: Object.freeze(["coupons_promotions"] as const),
    states: Object.freeze(["warn:false", "warn:true", "block:true"]),
  }),
  oauth_scope_overbroad: Object.freeze({
    rawControl: "OAuth scope minimization and approval",
    controlCode: "oauth_scope_minimization_and_approval",
    surfaces: Object.freeze(["integration_oauth_apps"] as const),
    states: Object.freeze(["warn:false", "warn:true", "block:true"]),
  }),
  admin_action_without_role_or_audit_control: Object.freeze({
    rawControl: "admin role gate and audit event",
    controlCode: "admin_role_gate_and_audit_event",
    surfaces: Object.freeze(["support_admin_actions"] as const),
    states: Object.freeze(["warn:false", "warn:true", "block:true"]),
  }),
  agent_surface_overscope: Object.freeze({
    rawControl: "tool scope minimization",
    controlCode: "tool_scope_minimization",
    surfaces: Object.freeze(["agent_tools", "mcp_connectors"] as const),
    states: Object.freeze(["block:true"]),
  }),
  feature_flag_plan_mismatch: Object.freeze({
    rawControl: "server-side feature entitlement check",
    controlCode: "server_side_feature_entitlement_check",
    surfaces: Object.freeze(["features_flags"] as const),
    states: Object.freeze(["warn:false", "warn:true"]),
  }),
  tenant_or_data_control_change: Object.freeze({
    rawControl: "tenant/data control review",
    controlCode: "tenant_data_control_review",
    surfaces: Object.freeze(["data_classes", "declared_controls"] as const),
    states: Object.freeze(["warn:false"]),
  }),
});
const RISK_CODES = new Set(Object.keys(RISK_CATALOG));

const REQUEST_FIELDS = [
  "schema_version", "project_ref", "source", "gate_status", "summary", "findings", "projection_hash",
] as const;
const SOURCE_FIELDS = ["engine_version", "execution_mode", "result_ref"] as const;
const SUMMARY_FIELDS = ["findings", "blockers"] as const;
const FINDING_FIELDS = [
  "finding_id", "surface_ref", "surface_type", "risk_code", "control_code", "severity", "reachable",
] as const;
const RECEIPT_FIELDS = [
  "schema_version", "receipt_id", "project_ref", "request_digest", "projection_hash",
  "synced_review_id", "disposition", "metered", "accepted_at",
] as const;
const PREPARED_FIELDS = ["request", "requestJson", "requestDigest", "idempotencyKey"] as const;
const ENGINE_VERSIONS = new Set<SourceEngineVersion>(["1.1.0", "1.1.1", "1.2.0"]);
const EXECUTION_MODES = new Set<SourceExecutionMode>(["browser_local", "machine_local", "cloud_isolated"]);
const SHA256 = /^[0-9a-f]{64}$/;
const PROJECT_REF = /^prj_[0-9a-f]{32}$/;
const SOURCE_REF = /^src1_[0-9a-f]{64}$/;
const SURFACE_REF = /^surf1_[0-9a-f]{64}$/;
const FINDING_ID = /^find1_[0-9a-f]{64}$/;
const RECEIPT_ID = /^fsr_[0-9a-f]{32}$/;
const SYNCED_REVIEW_ID = /^synrev_[0-9a-f]{32}$/;
const ACCEPTED_AT = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})\.([0-9]{3})Z$/;


function fail(code: FindingsSyncContractErrorCode): never {
  throw new FindingsSyncContractError(code);
}


function asContractError(error: unknown, fallback: FindingsSyncContractErrorCode): never {
  if (error instanceof FindingsSyncContractError) throw error;
  throw new FindingsSyncContractError(fallback);
}


function record(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail("invalid_shape");
  return value as Record<string, unknown>;
}


function exactFields(value: Record<string, unknown>, expected: readonly string[]): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    fail("invalid_shape");
  }
}


function validUnicode(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) return false;
  }
  return true;
}


function boundedString(value: unknown): string {
  if (typeof value !== "string" || !validUnicode(value) || Array.from(value).length > 256) {
    fail("invalid_value");
  }
  return value;
}


function compareUnicode(left: string, right: string): number {
  const a = Array.from(left, (character) => character.codePointAt(0)!);
  const b = Array.from(right, (character) => character.codePointAt(0)!);
  for (let index = 0; index < Math.min(a.length, b.length); index += 1) {
    if (a[index] !== b[index]) return a[index] - b[index];
  }
  return a.length - b.length;
}


function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    const encoded = JSON.stringify(value);
    if (encoded === undefined) fail("invalid_value");
    return encoded;
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) fail("invalid_value");
    return JSON.stringify(Object.is(value, -0) ? 0 : value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const item = record(value);
  return `{${Object.keys(item).sort(compareUnicode).map(
    (key) => `${JSON.stringify(key)}:${canonicalJson(item[key])}`,
  ).join(",")}}`;
}


function preflight(
  value: unknown,
  maximumNodes: number,
  maximumContainerItems: number,
): void {
  let nodes = 0;
  const ancestors = new Set<object>();
  function visit(current: unknown, depth: number): void {
    nodes += 1;
    if (nodes > maximumNodes || depth > MAX_JSON_DEPTH) fail("complexity_limit");
    if (current === null || typeof current === "boolean") return;
    if (typeof current === "string") {
      boundedString(current);
      return;
    }
    if (typeof current === "number") {
      if (!Number.isSafeInteger(current)) fail("invalid_value");
      return;
    }
    if (typeof current !== "object") fail("invalid_value");
    if (ancestors.has(current)) fail("complexity_limit");
    ancestors.add(current);
    if (Array.isArray(current)) {
      if (current.length > maximumContainerItems) fail("complexity_limit");
      for (const child of current) visit(child, depth + 1);
    } else {
      const keys = Object.keys(current);
      if (keys.length > maximumContainerItems) fail("complexity_limit");
      for (const key of keys) {
        boundedString(key);
        visit((current as Record<string, unknown>)[key], depth + 1);
      }
    }
    ancestors.delete(current);
  }
  visit(value, 0);
}


class DuplicateAwareJsonParser {
  readonly #source: string;
  readonly #maximumContainerItems: number;
  readonly #maximumNodes: number;
  #index = 0;
  #nodes = 0;

  constructor(source: string, maximumContainerItems: number, maximumNodes: number) {
    this.#source = source;
    this.#maximumContainerItems = maximumContainerItems;
    this.#maximumNodes = maximumNodes;
  }

  parse(): unknown {
    const value = this.#value(0);
    this.#whitespace();
    if (this.#index !== this.#source.length) fail("invalid_json");
    return value;
  }

  #value(depth: number): unknown {
    this.#nodes += 1;
    if (this.#nodes > this.#maximumNodes || depth > MAX_JSON_DEPTH) fail("complexity_limit");
    this.#whitespace();
    const character = this.#source[this.#index];
    if (character === "{") return this.#object(depth + 1);
    if (character === "[") return this.#array(depth + 1);
    if (character === '"') return this.#string();
    if (character === "t" && this.#take("true")) return true;
    if (character === "f" && this.#take("false")) return false;
    if (character === "n" && this.#take("null")) return null;
    if (character === "-" || (character >= "0" && character <= "9")) return this.#number();
    fail("invalid_json");
  }

  #object(depth: number): Record<string, unknown> {
    if (depth > MAX_JSON_DEPTH) fail("complexity_limit");
    this.#index += 1;
    const entries: [string, unknown][] = [];
    const keys = new Set<string>();
    this.#whitespace();
    if (this.#source[this.#index] === "}") {
      this.#index += 1;
      return Object.fromEntries(entries);
    }
    while (true) {
      this.#whitespace();
      if (this.#source[this.#index] !== '"') fail("invalid_json");
      const key = this.#string();
      if (keys.has(key)) fail("duplicate_field");
      keys.add(key);
      if (keys.size > this.#maximumContainerItems) fail("complexity_limit");
      this.#whitespace();
      if (this.#source[this.#index] !== ":") fail("invalid_json");
      this.#index += 1;
      entries.push([key, this.#value(depth)]);
      this.#whitespace();
      const separator = this.#source[this.#index++];
      if (separator === "}") return Object.fromEntries(entries);
      if (separator !== ",") fail("invalid_json");
    }
  }

  #array(depth: number): unknown[] {
    if (depth > MAX_JSON_DEPTH) fail("complexity_limit");
    this.#index += 1;
    const result: unknown[] = [];
    this.#whitespace();
    if (this.#source[this.#index] === "]") {
      this.#index += 1;
      return result;
    }
    while (true) {
      result.push(this.#value(depth));
      if (result.length > this.#maximumContainerItems) fail("complexity_limit");
      this.#whitespace();
      const separator = this.#source[this.#index++];
      if (separator === "]") return result;
      if (separator !== ",") fail("invalid_json");
    }
  }

  #string(): string {
    const start = this.#index;
    this.#index += 1;
    let escaped = false;
    while (this.#index < this.#source.length) {
      const character = this.#source[this.#index++];
      if (escaped) {
        if (character === "u") {
          const digits = this.#source.slice(this.#index, this.#index + 4);
          if (!/^[0-9a-fA-F]{4}$/.test(digits)) fail("invalid_json");
          this.#index += 4;
        } else if (!'"\\/bfnrt'.includes(character)) fail("invalid_json");
        escaped = false;
      } else if (character === "\\") escaped = true;
      else if (character === '"') {
        let value: unknown;
        try {
          value = JSON.parse(this.#source.slice(start, this.#index));
        } catch {
          fail("invalid_json");
        }
        return boundedString(value);
      } else if (character.charCodeAt(0) < 0x20) fail("invalid_json");
    }
    fail("invalid_json");
  }

  #number(): number {
    const match = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(
      this.#source.slice(this.#index),
    );
    if (match === null) fail("invalid_json");
    this.#index += match[0].length;
    if (/[.eE]/.test(match[0])) fail("invalid_value");
    const value = Number(match[0]);
    if (!Number.isSafeInteger(value)) fail("invalid_value");
    return value;
  }

  #take(token: string): boolean {
    if (!this.#source.startsWith(token, this.#index)) return false;
    this.#index += token.length;
    return true;
  }

  #whitespace(): void {
    while (/\s/.test(this.#source[this.#index] ?? "") && this.#index < this.#source.length) {
      const character = this.#source[this.#index];
      if (character !== " " && character !== "\n" && character !== "\r" && character !== "\t") {
        fail("invalid_json");
      }
      this.#index += 1;
    }
  }
}


function parseJsonText(
  source: string,
  maximumBytes: number,
  maximumContainerItems: number,
  maximumNodes = 10_000,
): unknown {
  if (typeof source !== "string" || !validUnicode(source)) fail("invalid_json");
  if (source.length > maximumBytes) fail("size_limit");
  const payload = new TextEncoder().encode(source);
  if (payload.byteLength > maximumBytes) fail("size_limit");
  return new DuplicateAwareJsonParser(source, maximumContainerItems, maximumNodes).parse();
}


function copyNamespaceKey(namespaceKey: Uint8Array): Uint8Array<ArrayBuffer> {
  if (!(namespaceKey instanceof Uint8Array) || namespaceKey.byteLength !== 32) fail("invalid_identity");
  const copied = new Uint8Array(32);
  copied.set(namespaceKey);
  return copied;
}


async function withHmacKey<T>(
  namespaceKey: Uint8Array,
  action: (key: CryptoKey) => Promise<T>,
): Promise<T> {
  const copied = copyNamespaceKey(namespaceKey);
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      copied,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    return await action(key);
  } catch (error) {
    return asContractError(error, "invalid_identity");
  } finally {
    copied.fill(0);
  }
}


function hex(bytes: ArrayBuffer): string {
  return Array.from(new Uint8Array(bytes), (byte) => byte.toString(16).padStart(2, "0")).join("");
}


async function hmacHex(key: CryptoKey, tag: string, values: string[]): Promise<string> {
  const material = new TextEncoder().encode(canonicalJson([
    FINDINGS_SYNC_SCHEMA_VERSION,
    tag,
    ...values,
  ]));
  return hex(await crypto.subtle.sign("HMAC", key, material));
}


async function sha256Hex(value: unknown): Promise<string> {
  const payload = new TextEncoder().encode(canonicalJson(value));
  return hex(await crypto.subtle.digest("SHA-256", payload));
}


function riskEntry(value: unknown): [FindingsSyncRiskCode, RiskCatalogEntry] {
  if (typeof value !== "string" || !RISK_CODES.has(value)) {
    fail("invalid_value");
  }
  const risk = value as FindingsSyncRiskCode;
  return [risk, RISK_CATALOG[risk]];
}


function projectionMaterial(request: Pick<
  FindingsSyncRequestV1,
  "schema_version" | "gate_status" | "summary" | "findings"
>): Record<string, unknown> {
  return {
    schema_version: request.schema_version,
    gate_status: request.gate_status,
    summary: request.summary,
    findings: request.findings,
  };
}


function assertRequestWireShape(value: unknown): Record<string, unknown> {
  preflight(value, 10_000, MAX_FINDINGS);
  const item = record(value);
  exactFields(item, REQUEST_FIELDS);
  exactFields(record(item.source), SOURCE_FIELDS);
  exactFields(record(item.summary), SUMMARY_FIELDS);
  if (!Array.isArray(item.findings) || item.findings.length > MAX_FINDINGS) fail("invalid_shape");
  for (const finding of item.findings) exactFields(record(finding), FINDING_FIELDS);
  return item;
}


export async function assertPreparedFindingsSyncBindingV1(value: unknown): Promise<void> {
  try {
    const prepared = record(value);
    exactFields(prepared, PREPARED_FIELDS);
    if (
      typeof prepared.requestJson !== "string"
      || typeof prepared.requestDigest !== "string"
      || !SHA256.test(prepared.requestDigest)
      || prepared.idempotencyKey !== `fs1-${prepared.requestDigest}`
    ) fail("invalid_shape");
    const request = assertRequestWireShape(prepared.request);
    const parsed = assertRequestWireShape(parseJsonText(
      prepared.requestJson,
      MAX_FINDINGS_SYNC_BYTES,
      MAX_FINDINGS,
    ));
    const canonical = canonicalJson(parsed);
    if (
      canonical !== prepared.requestJson
      || canonicalJson(request) !== canonical
      || await sha256Hex(parsed) !== prepared.requestDigest
    ) fail("invalid_hash");
  } catch (error) {
    return asContractError(error, "invalid_shape");
  }
}


export async function validateFindingsSyncRequestV1(
  value: unknown,
  namespaceKey: Uint8Array,
): Promise<FindingsSyncRequestV1> {
  try {
    preflight(value, 10_000, MAX_FINDINGS);
    const item = record(value);
    exactFields(item, REQUEST_FIELDS);
    if (item.schema_version !== FINDINGS_SYNC_SCHEMA_VERSION) fail("invalid_value");
    if (typeof item.project_ref !== "string" || !PROJECT_REF.test(item.project_ref)) fail("invalid_value");

    const source = record(item.source);
    exactFields(source, SOURCE_FIELDS);
    if (typeof source.engine_version !== "string" || !ENGINE_VERSIONS.has(source.engine_version as SourceEngineVersion)) {
      fail("invalid_value");
    }
    if (typeof source.execution_mode !== "string" || !EXECUTION_MODES.has(source.execution_mode as SourceExecutionMode)) {
      fail("invalid_value");
    }
    if (typeof source.result_ref !== "string" || !SOURCE_REF.test(source.result_ref)) fail("invalid_value");

    const summary = record(item.summary);
    exactFields(summary, SUMMARY_FIELDS);
    if (!Number.isSafeInteger(summary.findings) || (summary.findings as number) < 0 || (summary.findings as number) > MAX_FINDINGS) {
      fail("invalid_value");
    }
    if (!Number.isSafeInteger(summary.blockers) || (summary.blockers as number) < 0 || (summary.blockers as number) > MAX_FINDINGS) {
      fail("invalid_value");
    }
    if (!Array.isArray(item.findings) || item.findings.length > MAX_FINDINGS) fail("invalid_shape");

    const findings = await withHmacKey(namespaceKey, async (key) => {
      const normalized: FindingsSyncFindingV1[] = [];
      const findingIds = new Set<string>();
      const compounds = new Set<string>();
      for (const candidate of item.findings as unknown[]) {
        const finding = record(candidate);
        exactFields(finding, FINDING_FIELDS);
        if (typeof finding.finding_id !== "string" || !FINDING_ID.test(finding.finding_id)) fail("invalid_identity");
        if (typeof finding.surface_ref !== "string" || !SURFACE_REF.test(finding.surface_ref)) fail("invalid_identity");
        const [risk, catalog] = riskEntry(finding.risk_code);
        if (typeof finding.surface_type !== "string" || !catalog.surfaces.includes(finding.surface_type as FindingsSyncSurfaceType)) {
          fail("invalid_value");
        }
        if (finding.severity !== "warn" && finding.severity !== "block") fail("invalid_value");
        if (typeof finding.reachable !== "boolean") fail("invalid_value");
        if (!catalog.states.includes(`${finding.severity}:${finding.reachable}`)) fail("invalid_value");
        if (finding.control_code !== catalog.controlCode) fail("invalid_value");
        const expectedId = `find1_${await hmacHex(key, "finding", [finding.surface_ref, risk])}`;
        if (finding.finding_id !== expectedId) fail("invalid_identity");
        const compound = `${finding.surface_ref}\u0000${risk}`;
        if (findingIds.has(finding.finding_id) || compounds.has(compound)) fail("invalid_identity");
        findingIds.add(finding.finding_id);
        compounds.add(compound);
        normalized.push({
          finding_id: finding.finding_id as `find1_${string}`,
          surface_ref: finding.surface_ref as `surf1_${string}`,
          surface_type: finding.surface_type as FindingsSyncSurfaceType,
          risk_code: risk,
          control_code: catalog.controlCode,
          severity: finding.severity,
          reachable: finding.reachable,
        });
      }
      return normalized;
    });
    for (let index = 1; index < findings.length; index += 1) {
      if (compareUnicode(findings[index - 1].finding_id, findings[index].finding_id) > 0) fail("invalid_value");
    }
    const blockers = findings.filter(({ severity }) => severity === "block").length;
    if (summary.findings !== findings.length || summary.blockers !== blockers) fail("invalid_value");
    const gateStatus: FindingsSyncGateStatus = blockers > 0 ? "block" : findings.length > 0 ? "warn" : "pass";
    if (item.gate_status !== gateStatus) fail("invalid_value");
    if (typeof item.projection_hash !== "string" || !SHA256.test(item.projection_hash)) fail("invalid_hash");

    const normalized: FindingsSyncRequestV1 = {
      schema_version: FINDINGS_SYNC_SCHEMA_VERSION,
      project_ref: item.project_ref as `prj_${string}`,
      source: {
        engine_version: source.engine_version as SourceEngineVersion,
        execution_mode: source.execution_mode as SourceExecutionMode,
        result_ref: source.result_ref as `src1_${string}`,
      },
      gate_status: gateStatus,
      summary: {
        findings: summary.findings as number,
        blockers: summary.blockers as number,
      },
      findings,
      projection_hash: item.projection_hash,
    };
    if (normalized.projection_hash !== await sha256Hex(projectionMaterial(normalized))) fail("invalid_hash");
    if (new TextEncoder().encode(canonicalJson(normalized)).byteLength > MAX_FINDINGS_SYNC_BYTES) fail("size_limit");
    return normalized;
  } catch (error) {
    return asContractError(error, "invalid_value");
  }
}


export async function parseFindingsSyncRequestJsonV1(
  json: string,
  namespaceKey: Uint8Array,
): Promise<FindingsSyncRequestV1> {
  try {
    return await validateFindingsSyncRequestV1(
      parseJsonText(json, MAX_FINDINGS_SYNC_BYTES, MAX_FINDINGS),
      namespaceKey,
    );
  } catch (error) {
    return asContractError(error, "invalid_json");
  }
}


export async function canonicalFindingsSyncRequestJsonV1(
  request: FindingsSyncRequestV1,
  namespaceKey: Uint8Array,
): Promise<string> {
  return canonicalJson(await validateFindingsSyncRequestV1(request, namespaceKey));
}


export async function findingsSyncRequestDigestV1(
  request: FindingsSyncRequestV1,
  namespaceKey: Uint8Array,
): Promise<string> {
  return sha256Hex(await validateFindingsSyncRequestV1(request, namespaceKey));
}


async function expectedProjection(
  reviewValue: ReviewEnvelopeV1,
  projectRef: string,
  namespaceKey: Uint8Array,
): Promise<FindingsSyncRequestV1> {
  let review: ReviewEnvelopeV1;
  try {
    review = parseReviewEnvelopeV1(reviewValue);
  } catch (error) {
    return asContractError(error, "context_mismatch");
  }
  if (!PROJECT_REF.test(projectRef) || review.findings.length > MAX_FINDINGS) fail("context_mismatch");
  return withHmacKey(namespaceKey, async (key) => {
    const findings: FindingsSyncFindingV1[] = [];
    const identities = new Set<string>();
    for (const finding of review.findings) {
      const [risk, catalog] = riskEntry(finding.risk);
      if (
        finding.control !== catalog.rawControl
        || !catalog.surfaces.includes(finding.surface_type as FindingsSyncSurfaceType)
        || !catalog.states.includes(`${finding.severity}:${finding.reachable}`)
      ) fail("context_mismatch");
      const surfaceRef = `surf1_${await hmacHex(
        key,
        "surface",
        [finding.surface_type, finding.surface_id],
      )}` as const;
      const findingId = `find1_${await hmacHex(key, "finding", [surfaceRef, risk])}` as const;
      if (identities.has(findingId)) fail("context_mismatch");
      identities.add(findingId);
      findings.push({
        finding_id: findingId,
        surface_ref: surfaceRef,
        surface_type: finding.surface_type as FindingsSyncSurfaceType,
        risk_code: risk,
        control_code: catalog.controlCode,
        severity: finding.severity,
        reachable: finding.reachable,
      });
    }
    findings.sort((left, right) => compareUnicode(left.finding_id, right.finding_id));
    const blockers = findings.filter(({ severity }) => severity === "block").length;
    const request: FindingsSyncRequestV1 = {
      schema_version: FINDINGS_SYNC_SCHEMA_VERSION,
      project_ref: projectRef as `prj_${string}`,
      source: {
        engine_version: review.engine_version,
        execution_mode: review.execution_mode,
        result_ref: `src1_${await hmacHex(key, "source", [review.result_hash])}`,
      },
      gate_status: blockers > 0 ? "block" : findings.length > 0 ? "warn" : "pass",
      summary: { findings: findings.length, blockers },
      findings,
      projection_hash: "",
    };
    request.projection_hash = await sha256Hex(projectionMaterial(request));
    return request;
  });
}


export async function verifyProjectedFindingsSyncV1(
  value: unknown,
  context: {
    review: ReviewEnvelopeV1;
    projectRef: string;
    namespaceKey: Uint8Array;
  },
): Promise<FindingsSyncRequestV1> {
  try {
    const actual = await validateFindingsSyncRequestV1(value, context.namespaceKey);
    const expected = await expectedProjection(context.review, context.projectRef, context.namespaceKey);
    if (canonicalJson(actual) !== canonicalJson(expected)) fail("context_mismatch");
    return actual;
  } catch (error) {
    return asContractError(error, "context_mismatch");
  }
}


function validAcceptedAt(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const match = ACCEPTED_AT.exec(value);
  if (match === null) return false;
  const [year, month, day, hour, minute, second] = match.slice(1, 7).map(Number);
  if (year < 1 || month < 1 || month > 12 || hour > 23 || minute > 59 || second > 59) return false;
  const days = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
  if (year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0)) days[1] = 29;
  return day >= 1 && day <= days[month - 1];
}


export function validateFindingsSyncReceiptV1(value: unknown): FindingsSyncReceiptV1 {
  try {
    preflight(value, 256, 64);
    const item = record(value);
    exactFields(item, RECEIPT_FIELDS);
    if (item.schema_version !== FINDINGS_SYNC_RECEIPT_SCHEMA_VERSION) fail("invalid_receipt");
    if (typeof item.receipt_id !== "string" || !RECEIPT_ID.test(item.receipt_id)) fail("invalid_receipt");
    if (typeof item.project_ref !== "string" || !PROJECT_REF.test(item.project_ref)) fail("invalid_receipt");
    if (typeof item.request_digest !== "string" || !SHA256.test(item.request_digest)) fail("invalid_receipt");
    if (typeof item.projection_hash !== "string" || !SHA256.test(item.projection_hash)) fail("invalid_receipt");
    if (typeof item.synced_review_id !== "string" || !SYNCED_REVIEW_ID.test(item.synced_review_id)) fail("invalid_receipt");
    if (item.disposition !== "created" && item.disposition !== "reused") fail("invalid_receipt");
    if (typeof item.metered !== "boolean" || item.metered !== (item.disposition === "created")) fail("invalid_receipt");
    if (!validAcceptedAt(item.accepted_at)) fail("invalid_receipt");
    const normalized: FindingsSyncReceiptV1 = {
      schema_version: FINDINGS_SYNC_RECEIPT_SCHEMA_VERSION,
      receipt_id: item.receipt_id as `fsr_${string}`,
      project_ref: item.project_ref as `prj_${string}`,
      request_digest: item.request_digest,
      projection_hash: item.projection_hash,
      synced_review_id: item.synced_review_id as `synrev_${string}`,
      disposition: item.disposition,
      metered: item.metered,
      accepted_at: item.accepted_at,
    };
    if (new TextEncoder().encode(canonicalJson(normalized)).byteLength > MAX_FINDINGS_SYNC_RECEIPT_BYTES) {
      fail("size_limit");
    }
    return normalized;
  } catch (error) {
    return asContractError(error, "invalid_receipt");
  }
}


export function parseFindingsSyncReceiptJsonV1(json: string): FindingsSyncReceiptV1 {
  try {
    return validateFindingsSyncReceiptV1(
      parseJsonText(json, MAX_FINDINGS_SYNC_RECEIPT_BYTES, 64, 256),
    );
  } catch (error) {
    return asContractError(error, "invalid_receipt");
  }
}


export function assertFindingsSyncReceiptMatchesV1(
  receiptValue: FindingsSyncReceiptV1,
  prepared: PreparedFindingsSyncBindingV1,
): void {
  const receipt = validateFindingsSyncReceiptV1(receiptValue);
  if (
    receipt.project_ref !== prepared.request.project_ref
    || receipt.request_digest !== prepared.requestDigest
    || receipt.projection_hash !== prepared.request.projection_hash
    || prepared.idempotencyKey !== `fs1-${prepared.requestDigest}`
  ) fail("context_mismatch");
}
