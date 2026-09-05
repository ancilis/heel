// SPDX-License-Identifier: LicenseRef-Heel-Commercial

/** Dependency-free validation for the untrusted Python worker response. */

export const REVIEW_SCHEMA_VERSION = "heel.review.v1" as const;
export const REVIEW_ENGINE_VERSION = "1.2.0" as const;
export type ReviewEngineVersion = "1.1.0" | "1.1.1" | typeof REVIEW_ENGINE_VERSION;

const SUPPORTED_REVIEW_ENGINE_VERSIONS = new Set<ReviewEngineVersion>([
  "1.1.0",
  "1.1.1",
  REVIEW_ENGINE_VERSION,
]);

const SHA256 = /^[0-9a-f]{64}$/;
const REVIEW_ID = /^review_[0-9a-f]{20}$/;
const MAX_RECORDS_PER_COLLECTION = 100_000;

const ENVELOPE_FIELDS = [
  "review_id", "result_hash", "schema_version", "engine_version", "product_id",
  "source_hash", "model_hash", "baseline_hash", "execution_mode", "gate_status",
  "summary", "findings", "recommended_controls", "suggested_regressions",
  "questions", "safety", "privacy",
] as const;
const FINDING_FIELDS = [
  "surface_type", "surface_id", "risk", "severity", "control", "reason", "reachable",
] as const;
const REGRESSION_FIELDS = [
  "surface_type", "surface_id", "name", "expected_status", "scenario_hint", "safety",
] as const;
const QUESTION_FIELDS = ["id", "field", "surface", "prompt", "required"] as const;


export interface ReviewFindingV1 {
  surface_type: string;
  surface_id: string;
  risk: string;
  severity: "warn" | "block";
  control: string;
  reason: string;
  reachable: boolean;
  evidence_state?: "unknown" | "customer_declared" | "inferred";
  rule_source?: string;
  execution_disposition?: "static_only";
}

export interface ReviewRegressionV1 {
  surface_type: string;
  surface_id: string;
  name: string;
  expected_status: string;
  scenario_hint: string;
  safety: string;
}

export interface ReviewQuestionV1 {
  id: string;
  field: string;
  surface: string;
  prompt: string;
  required: boolean;
}

export interface ReviewEnvelopeV1 {
  review_id: string;
  result_hash: string;
  schema_version: typeof REVIEW_SCHEMA_VERSION;
  engine_version: ReviewEngineVersion;
  product_id: string;
  source_hash: string;
  model_hash: string;
  baseline_hash: string | null;
  execution_mode: "browser_local";
  gate_status: "pass" | "warn" | "block";
  summary: {
    findings: number;
    blockers: number;
    questions: number;
  };
  findings: ReviewFindingV1[];
  recommended_controls: ReviewFindingV1[];
  suggested_regressions: ReviewRegressionV1[];
  questions: ReviewQuestionV1[];
  safety: {
    mode: "static ProductModel diff";
    live_probing: false;
    network_calls: false;
    requires_signed_scope_for_live_or_staging_runs: true;
    canary_only: true;
  };
  privacy: {
    execution: "browser_local";
    network_calls: false;
    uploaded: false;
    sync_intent: "none";
  };
}


export class ReviewEnvelopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ReviewEnvelopeError";
  }
}


function record(value: unknown, path: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new ReviewEnvelopeError(`${path} must be an object`);
  }
  return value as Record<string, unknown>;
}


function exactFields(value: Record<string, unknown>, expected: readonly string[], path: string): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new ReviewEnvelopeError(`${path} must contain exactly the v1 fields`);
  }
}


function string(value: unknown, path: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new ReviewEnvelopeError(`${path} must be a nonempty string`);
  }
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new ReviewEnvelopeError(`${path} contains invalid Unicode`);
      }
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new ReviewEnvelopeError(`${path} contains invalid Unicode`);
    }
  }
  return value;
}


function boolean(value: unknown, path: string): boolean {
  if (typeof value !== "boolean") throw new ReviewEnvelopeError(`${path} must be a boolean`);
  return value;
}


function count(value: unknown, path: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new ReviewEnvelopeError(`${path} must be a nonnegative safe integer`);
  }
  return value as number;
}


function hash(value: unknown, path: string, nullable = false): string | null {
  if (nullable && value === null) return null;
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new ReviewEnvelopeError(`${path} must be a lowercase SHA-256 digest`);
  }
  return value;
}


function array(value: unknown, path: string): unknown[] {
  if (!Array.isArray(value)) throw new ReviewEnvelopeError(`${path} must be an array`);
  if (value.length > MAX_RECORDS_PER_COLLECTION) {
    throw new ReviewEnvelopeError(`${path} contains too many records`);
  }
  return value;
}


function finding(value: unknown, path: string): ReviewFindingV1 {
  const item = record(value, path);
  exactFields(item, "evidence_state" in item ? [...FINDING_FIELDS, "evidence_state", "rule_source", "execution_disposition"] : FINDING_FIELDS, path);
  let evidence: Pick<ReviewFindingV1, "evidence_state" | "rule_source" | "execution_disposition"> = {};
  if ("evidence_state" in item) {
    if (!["unknown", "customer_declared", "inferred"].includes(String(item.evidence_state)) || item.execution_disposition !== "static_only") {
      throw new ReviewEnvelopeError("Static review cannot verify behavior");
    }
    evidence = { evidence_state: item.evidence_state as "unknown" | "customer_declared" | "inferred", rule_source: string(item.rule_source, `${path}.rule_source`), execution_disposition: "static_only" };
  }
  const severity = string(item.severity, `${path}.severity`);
  if (severity !== "warn" && severity !== "block") {
    throw new ReviewEnvelopeError(`${path}.severity must be warn or block`);
  }
  return {
    surface_type: string(item.surface_type, `${path}.surface_type`),
    surface_id: string(item.surface_id, `${path}.surface_id`),
    risk: string(item.risk, `${path}.risk`),
    severity,
    control: string(item.control, `${path}.control`),
    reason: string(item.reason, `${path}.reason`),
    reachable: boolean(item.reachable, `${path}.reachable`),
    ...evidence,
  };
}


function regression(value: unknown, path: string): ReviewRegressionV1 {
  const item = record(value, path);
  exactFields(item, REGRESSION_FIELDS, path);
  return {
    surface_type: string(item.surface_type, `${path}.surface_type`),
    surface_id: string(item.surface_id, `${path}.surface_id`),
    name: string(item.name, `${path}.name`),
    expected_status: string(item.expected_status, `${path}.expected_status`),
    scenario_hint: string(item.scenario_hint, `${path}.scenario_hint`),
    safety: string(item.safety, `${path}.safety`),
  };
}


function question(value: unknown, path: string): ReviewQuestionV1 {
  const item = record(value, path);
  exactFields(item, QUESTION_FIELDS, path);
  return {
    id: string(item.id, `${path}.id`),
    field: string(item.field, `${path}.field`),
    surface: string(item.surface, `${path}.surface`),
    prompt: string(item.prompt, `${path}.prompt`),
    required: boolean(item.required, `${path}.required`),
  };
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
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value) || !Number.isSafeInteger(value)) {
      throw new ReviewEnvelopeError("envelope contains an unsafe numeric value");
    }
    return JSON.stringify(Object.is(value, -0) ? 0 : value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const item = record(value, "envelope value");
  const keys = Object.keys(item).sort(compareUnicode);
  return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(item[key])}`).join(",")}}`;
}


function findingSort(left: ReviewFindingV1, right: ReviewFindingV1): number {
  const leftValues = [
    left.severity === "block" ? "0" : "1",
    left.surface_type,
    left.surface_id,
    left.risk,
    canonicalJson(left),
  ];
  const rightValues = [
    right.severity === "block" ? "0" : "1",
    right.surface_type,
    right.surface_id,
    right.risk,
    canonicalJson(right),
  ];
  for (let index = 0; index < leftValues.length; index += 1) {
    const comparison = compareUnicode(leftValues[index], rightValues[index]);
    if (comparison !== 0) return comparison;
  }
  return 0;
}


function assertSorted<T>(items: T[], compare: (left: T, right: T) => number, path: string): void {
  for (let index = 1; index < items.length; index += 1) {
    if (compare(items[index - 1], items[index]) > 0) {
      throw new ReviewEnvelopeError(`${path} must use canonical v1 ordering`);
    }
  }
}


// Synchronous SHA-256 keeps strict parsing dependency-free and usable before WebCrypto promises settle.
function sha256(source: string): string {
  const constants = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];
  const bytes = new TextEncoder().encode(source);
  const bitLength = bytes.length * 8;
  const paddedLength = Math.ceil((bytes.length + 9) / 64) * 64;
  const payload = new Uint8Array(paddedLength);
  payload.set(bytes);
  payload[bytes.length] = 0x80;
  const view = new DataView(payload.buffer);
  view.setUint32(paddedLength - 8, Math.floor(bitLength / 2 ** 32));
  view.setUint32(paddedLength - 4, bitLength >>> 0);
  const state = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);
  const words = new Uint32Array(64);
  const rotate = (value: number, amount: number) => (value >>> amount) | (value << (32 - amount));

  for (let offset = 0; offset < payload.length; offset += 64) {
    for (let index = 0; index < 16; index += 1) words[index] = view.getUint32(offset + index * 4);
    for (let index = 16; index < 64; index += 1) {
      const s0 = rotate(words[index - 15], 7) ^ rotate(words[index - 15], 18) ^ (words[index - 15] >>> 3);
      const s1 = rotate(words[index - 2], 17) ^ rotate(words[index - 2], 19) ^ (words[index - 2] >>> 10);
      words[index] = (words[index - 16] + s0 + words[index - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, h] = state;
    for (let index = 0; index < 64; index += 1) {
      const sum1 = rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25);
      const choice = (e & f) ^ (~e & g);
      const temporary1 = (h + sum1 + choice + constants[index] + words[index]) >>> 0;
      const sum0 = rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22);
      const majority = (a & b) ^ (a & c) ^ (b & c);
      const temporary2 = (sum0 + majority) >>> 0;
      h = g; g = f; f = e; e = (d + temporary1) >>> 0;
      d = c; c = b; b = a; a = (temporary1 + temporary2) >>> 0;
    }
    state[0] = (state[0] + a) >>> 0;
    state[1] = (state[1] + b) >>> 0;
    state[2] = (state[2] + c) >>> 0;
    state[3] = (state[3] + d) >>> 0;
    state[4] = (state[4] + e) >>> 0;
    state[5] = (state[5] + f) >>> 0;
    state[6] = (state[6] + g) >>> 0;
    state[7] = (state[7] + h) >>> 0;
  }
  return Array.from(state, (value) => value.toString(16).padStart(8, "0")).join("");
}


export function parseReviewEnvelopeV1(value: unknown): ReviewEnvelopeV1 {
  const item = record(value, "envelope");
  exactFields(item, ENVELOPE_FIELDS, "envelope");

  if (item.schema_version !== REVIEW_SCHEMA_VERSION) {
    throw new ReviewEnvelopeError(`schema_version must be ${REVIEW_SCHEMA_VERSION}`);
  }
  if (
    typeof item.engine_version !== "string"
    || !SUPPORTED_REVIEW_ENGINE_VERSIONS.has(item.engine_version as ReviewEngineVersion)
  ) {
    throw new ReviewEnvelopeError("engine_version is not supported");
  }
  const engineVersion = item.engine_version as ReviewEngineVersion;
  if (item.execution_mode !== "browser_local") {
    throw new ReviewEnvelopeError("execution_mode must be browser_local");
  }
  const gate = string(item.gate_status, "gate_status");
  if (gate !== "pass" && gate !== "warn" && gate !== "block") {
    throw new ReviewEnvelopeError("gate_status must be pass, warn, or block");
  }

  const findings = array(item.findings, "findings").map((entry, index) => finding(entry, `findings[${index}]`));
  const controls = array(item.recommended_controls, "recommended_controls").map(
    (entry, index) => finding(entry, `recommended_controls[${index}]`),
  );
  const regressions = array(item.suggested_regressions, "suggested_regressions").map(
    (entry, index) => regression(entry, `suggested_regressions[${index}]`),
  );
  const questions = array(item.questions, "questions").map(
    (entry, index) => question(entry, `questions[${index}]`),
  );
  assertSorted(findings, findingSort, "findings");
  assertSorted(controls, (left, right) => compareUnicode(canonicalJson(left), canonicalJson(right)), "recommended_controls");
  assertSorted(regressions, (left, right) => compareUnicode(canonicalJson(left), canonicalJson(right)), "suggested_regressions");
  assertSorted(questions, (left, right) => compareUnicode(canonicalJson(left), canonicalJson(right)), "questions");

  const blockers = findings.filter((entry) => entry.severity === "block").length;
  const expectedGate = blockers > 0 ? "block" : findings.length > 0 ? "warn" : "pass";
  if (gate !== expectedGate) throw new ReviewEnvelopeError(`gate_status must be ${expectedGate}`);
  const summary = record(item.summary, "summary");
  exactFields(summary, ["findings", "blockers", "questions"], "summary");
  const normalizedSummary = {
    findings: count(summary.findings, "summary.findings"),
    blockers: count(summary.blockers, "summary.blockers"),
    questions: count(summary.questions, "summary.questions"),
  };
  if (
    normalizedSummary.findings !== findings.length
    || normalizedSummary.blockers !== blockers
    || normalizedSummary.questions !== questions.length
  ) throw new ReviewEnvelopeError("summary does not match the envelope contents");

  const safety = record(item.safety, "safety");
  exactFields(safety, [
    "mode", "live_probing", "network_calls",
    "requires_signed_scope_for_live_or_staging_runs", "canary_only",
  ], "safety");
  if (
    safety.mode !== "static ProductModel diff"
    || boolean(safety.live_probing, "safety.live_probing") !== false
    || boolean(safety.network_calls, "safety.network_calls") !== false
    || boolean(safety.requires_signed_scope_for_live_or_staging_runs, "safety.requires_signed_scope_for_live_or_staging_runs") !== true
    || boolean(safety.canary_only, "safety.canary_only") !== true
  ) throw new ReviewEnvelopeError("safety contradicts the static v1 contract");

  const privacy = record(item.privacy, "privacy");
  exactFields(privacy, ["execution", "network_calls", "uploaded", "sync_intent"], "privacy");
  if (
    privacy.execution !== "browser_local"
    || boolean(privacy.network_calls, "privacy.network_calls") !== false
    || boolean(privacy.uploaded, "privacy.uploaded") !== false
    || privacy.sync_intent !== "none"
  ) throw new ReviewEnvelopeError("privacy contradicts the browser-local v1 contract");

  const resultHash = hash(item.result_hash, "result_hash")!;
  const reviewId = string(item.review_id, "review_id");
  if (!REVIEW_ID.test(reviewId)) throw new ReviewEnvelopeError("review id has invalid syntax");
  const body = Object.fromEntries(ENVELOPE_FIELDS
    .filter((key) => key !== "review_id" && key !== "result_hash")
    .map((key) => [key, item[key]]));
  const expectedHash = sha256(canonicalJson(body));
  if (resultHash !== expectedHash) throw new ReviewEnvelopeError("result hash does not match the envelope contents");
  if (reviewId !== `review_${expectedHash.slice(0, 20)}`) {
    throw new ReviewEnvelopeError("review id does not match the result hash");
  }

  return {
    review_id: reviewId,
    result_hash: resultHash,
    schema_version: REVIEW_SCHEMA_VERSION,
    engine_version: engineVersion,
    product_id: string(item.product_id, "product_id"),
    source_hash: hash(item.source_hash, "source_hash")!,
    model_hash: hash(item.model_hash, "model_hash")!,
    baseline_hash: hash(item.baseline_hash, "baseline_hash", true),
    execution_mode: "browser_local",
    gate_status: gate,
    summary: normalizedSummary,
    findings,
    recommended_controls: controls,
    suggested_regressions: regressions,
    questions,
    safety: {
      mode: "static ProductModel diff",
      live_probing: false,
      network_calls: false,
      requires_signed_scope_for_live_or_staging_runs: true,
      canary_only: true,
    },
    privacy: {
      execution: "browser_local",
      network_calls: false,
      uploaded: false,
      sync_intent: "none",
    },
  };
}


export type CurrentReviewEnvelopeV1 = ReviewEnvelopeV1 & {
  engine_version: typeof REVIEW_ENGINE_VERSION;
};


export function parseCurrentReviewEnvelopeV1(value: unknown): CurrentReviewEnvelopeV1 {
  const parsed = parseReviewEnvelopeV1(value);
  if (parsed.engine_version !== REVIEW_ENGINE_VERSION) {
    throw new ReviewEnvelopeError(`engine_version must be current (${REVIEW_ENGINE_VERSION})`);
  }
  return parsed as CurrentReviewEnvelopeV1;
}
