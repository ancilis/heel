// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import {
  deriveAnswerReceipt,
  MAX_REVIEW_ANSWERS_BYTES,
  type ReviewAnswer,
  type ReviewAnswerReceiptV1,
} from "./review-presentation";
import {
  parseCurrentReviewEnvelopeV1,
  parseReviewEnvelopeV1,
  type ReviewEnvelopeV1,
} from "./review-v1";


export const WORKER_PROTOCOL_VERSION = "heel.browser-worker.v1" as const;
export const MAX_BROWSER_INPUT_BYTES = 2 * 1024 * 1024;
export const MAX_BROWSER_ANSWERS_BYTES = MAX_REVIEW_ANSWERS_BYTES;
// A review may fan out beyond its source, but never without a deterministic UI/storage ceiling.
export const MAX_BROWSER_RESULT_BYTES = 4 * 1024 * 1024;
const MAX_WORKER_MESSAGE_BYTES = MAX_BROWSER_RESULT_BYTES * 2 + 64 * 1024;
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_BOOT_TIMEOUT_MS = 20_000;
const MAX_AUTOMATIC_BOOT_RETRIES = 1;

export type BrowserReviewStatus =
  | "loading_engine"
  | "ready"
  | "reviewing"
  | "complete"
  | "failed";

export interface ReviewWorkerLike {
  onmessage: ((event: MessageEvent<string>) => void) | null;
  onerror: ((event: ErrorEvent) => void) | null;
  postMessage(message: string): void;
  terminate(): void;
}

export interface BrowserReviewResult {
  envelope: ReviewEnvelopeV1;
  receipt: ReviewAnswerReceiptV1 | null;
}

export type ScenarioAssessmentOutcome =
  | "inferred_finding"
  | "handoff"
  | "investigation_prompt"
  | "criterion_unknown"
  | "criterion_not_met"
  | "no_matching_surface";

/** One explicitly selected definition, exactly as the workspace listing supplied it with its digest. */
export interface ScenarioAssessmentSelectionEntry {
  scenario_id: string;
  source: "library" | "custom";
  revision: number | null;
  definition_digest: string;
  definition: Readonly<Record<string, unknown>>;
}

export interface ScenarioAssessmentSelection {
  library_digest: string;
  scenarios: readonly ScenarioAssessmentSelectionEntry[];
}

export type ScenarioAssessmentSurface =
  | { method: string; route: string }
  | { source_field: string; item: string };

export interface ScenarioAssessmentMatch {
  outcome: ScenarioAssessmentOutcome;
  surface: ScenarioAssessmentSurface;
  evidence_state: "inferred" | "customer_declared" | "unknown";
  rule_source: string;
}

export interface ScenarioAssessmentResult {
  scenario_id: string;
  source: "library" | "custom";
  revision: number | null;
  definition_digest: string;
  mechanism_id: string;
  outcome: ScenarioAssessmentOutcome;
  applicability: "unknown" | "matched_surface";
  evidence_state: "inferred" | "customer_declared" | "unknown";
  rule_source: string;
  surface: ScenarioAssessmentSurface | null;
  match_count: number;
  matches: readonly ScenarioAssessmentMatch[];
  recommended_control: string;
  note: string;
}

/** The browser-local static assessment envelope; it never leaves this browser. */
export interface ScenarioAssessmentEnvelopeV1 {
  schema_version: "heel.scenario-assessment.v1";
  engine_version: string;
  source_hash: string;
  model_hash: string;
  answers_hash: string;
  library_digest: string;
  selection_hash: string;
  custom: readonly { scenario_id: string; revision: number; definition_digest: string }[];
  model_coverage: { product_model_fields: "evaluated"; entitlement_graph_edges: "not_evaluated"; agent_surface: "declared" | "unknown" };
  results: readonly ScenarioAssessmentResult[];
  privacy: { execution: "browser_local"; network_calls: false; uploaded: false };
}

export const SCENARIO_ASSESSMENT_NOTES: Readonly<Record<ScenarioAssessmentOutcome, string>> = Object.freeze({
  inferred_finding: "inferred from the supplied model only; nothing was executed against the product",
  handoff: "pure model-jailbreak surface handed off to model red-team; not a Heel finding",
  investigation_prompt: "investigation prompt: confirm the intended product rule; nothing was executed",
  criterion_unknown: "the criterion depends on properties absent from the supplied model; unknown, not a negative result",
  criterion_not_met: "the supplied properties do not meet the criterion; static only, not evidence the product is safe",
  no_matching_surface: "no matching surface in the supplied model; not evidence of absence",
});
export const MAX_ASSESSMENT_SELECTION_BYTES = 512 * 1024;
const MAX_ASSESSMENT_SELECTED = 160;
const HEX64 = /^[0-9a-f]{64}$/;
const EVIDENCE_STATES = new Set(["inferred", "customer_declared", "unknown"]);

function assessmentSurface(value: unknown): value is ScenarioAssessmentSurface {
  const record = messageRecord(value);
  if (record === null) return false;
  if (exactFields(record, ["method", "route"])) {
    return typeof record.method === "string" && typeof record.route === "string" && record.route.length <= 512;
  }
  return exactFields(record, ["source_field", "item"]) && typeof record.source_field === "string"
    && typeof record.item === "string" && record.item.length <= 160;
}

/** Strictly parse an assessment envelope and bind it to the exact ordered selection that produced it. */
export function parseScenarioAssessmentV1(
  value: unknown,
  selection: ScenarioAssessmentSelection,
): ScenarioAssessmentEnvelopeV1 {
  const envelope = messageRecord(value);
  if (envelope === null || !exactFields(envelope, [
    "schema_version", "engine_version", "source_hash", "model_hash", "answers_hash", "library_digest",
    "selection_hash", "custom", "model_coverage", "results", "privacy",
  ]) || envelope.schema_version !== "heel.scenario-assessment.v1" || typeof envelope.engine_version !== "string"
    || ![envelope.source_hash, envelope.model_hash, envelope.answers_hash, envelope.selection_hash].every((item) => typeof item === "string" && HEX64.test(item))
    || envelope.library_digest !== selection.library_digest) throw new BrowserReviewClientError("worker_protocol");
  const privacy = messageRecord(envelope.privacy);
  if (privacy === null || !exactFields(privacy, ["execution", "network_calls", "uploaded"])
    || privacy.execution !== "browser_local" || privacy.network_calls !== false || privacy.uploaded !== false) throw new BrowserReviewClientError("worker_protocol");
  const coverage = messageRecord(envelope.model_coverage);
  if (coverage === null || !exactFields(coverage, ["product_model_fields", "entitlement_graph_edges", "agent_surface"])
    || coverage.product_model_fields !== "evaluated" || coverage.entitlement_graph_edges !== "not_evaluated"
    || (coverage.agent_surface !== "declared" && coverage.agent_surface !== "unknown")) throw new BrowserReviewClientError("worker_protocol");
  const results = envelope.results;
  if (!Array.isArray(results) || results.length !== selection.scenarios.length) throw new BrowserReviewClientError("worker_protocol");
  (results as unknown[]).forEach((candidate, index) => {
    const row = messageRecord(candidate);
    const chosen = selection.scenarios[index];
    if (row === null || !exactFields(row, [
      "scenario_id", "source", "revision", "definition_digest", "mechanism_id", "outcome", "applicability",
      "evidence_state", "rule_source", "surface", "match_count", "matches", "recommended_control", "note",
    ]) || row.scenario_id !== chosen.scenario_id || row.source !== chosen.source || row.revision !== chosen.revision
      || row.definition_digest !== chosen.definition_digest || typeof row.mechanism_id !== "string"
      || typeof row.outcome !== "string" || !(row.outcome in SCENARIO_ASSESSMENT_NOTES)
      || row.note !== SCENARIO_ASSESSMENT_NOTES[row.outcome as ScenarioAssessmentOutcome]
      || !EVIDENCE_STATES.has(String(row.evidence_state)) || typeof row.rule_source !== "string"
      || typeof row.recommended_control !== "string" || !Number.isSafeInteger(row.match_count)
      || !Array.isArray(row.matches) || row.matches.length > 16 || (row.match_count as number) < row.matches.length) throw new BrowserReviewClientError("worker_protocol");
    const matched = row.surface !== null;
    if (matched !== (row.applicability === "matched_surface") || (!matched && row.applicability !== "unknown")
      || (matched && !assessmentSurface(row.surface))
      || (row.outcome === "no_matching_surface") !== !matched
      || (!matched && (row.evidence_state !== "unknown" || (row.matches as unknown[]).length !== 0))) throw new BrowserReviewClientError("worker_protocol");
    for (const match of row.matches as unknown[]) {
      const item = messageRecord(match);
      if (item === null || !exactFields(item, ["outcome", "surface", "evidence_state", "rule_source"])
        || typeof item.outcome !== "string" || !(item.outcome in SCENARIO_ASSESSMENT_NOTES)
        || item.outcome === "no_matching_surface" || !assessmentSurface(item.surface)
        || !EVIDENCE_STATES.has(String(item.evidence_state)) || typeof item.rule_source !== "string") throw new BrowserReviewClientError("worker_protocol");
    }
  });
  const customs = selection.scenarios.filter((item) => item.source === "custom");
  if (!Array.isArray(envelope.custom) || envelope.custom.length !== customs.length
    || !(envelope.custom as unknown[]).every((item, index) => {
      const row = messageRecord(item);
      return row !== null && exactFields(row, ["scenario_id", "revision", "definition_digest"])
        && row.scenario_id === customs[index].scenario_id && row.revision === customs[index].revision
        && row.definition_digest === customs[index].definition_digest;
    })) throw new BrowserReviewClientError("worker_protocol");
  return envelope as unknown as ScenarioAssessmentEnvelopeV1;
}

export interface RetainedBrowserInput {
  source: string;
  answers: ReviewAnswer[];
}

interface ActiveRequest {
  kind: "review" | "assess";
  selection: ScenarioAssessmentSelection | null;
  resolveAssessment: ((value: ScenarioAssessmentEnvelopeV1) => void) | null;
  id: string;
  source: string;
  before: ReviewEnvelopeV1 | null;
  answers: ReviewAnswer[];
  resolve(value: BrowserReviewResult): void;
  reject(error: BrowserReviewClientError): void;
  timer: ReturnType<typeof setTimeout>;
}

interface QueuedRequest {
  kind: "review" | "assess";
  selection: ScenarioAssessmentSelection | null;
  selectionJson: string;
  resolveAssessment: ((value: ScenarioAssessmentEnvelopeV1) => void) | null;
  source: string;
  answers: ReviewAnswer[];
  answersJson: string;
  before: ReviewEnvelopeV1 | null;
  resolve(value: BrowserReviewResult): void;
  reject(error: BrowserReviewClientError): void;
}

interface ReviewBaseline {
  source: string;
  envelope: ReviewEnvelopeV1;
}

export interface BrowserReviewClientOptions {
  workerFactory?: () => ReviewWorkerLike;
  timeoutMs?: number;
  bootTimeoutMs?: number;
}


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
  engine_unavailable: "The browser-local review engine could not be started.",
  engine_failed: "The browser-local review engine stopped unexpectedly.",
  review_in_progress: "A browser-local review is already running.",
  review_cancelled: "The browser-local review was cancelled.",
  review_timeout: "The browser-local review exceeded its safe time limit.",
  answers_too_large: "The submitted review answers exceed the browser limit.",
  result_too_large: "The review result exceeds the safe browser limit.",
  worker_protocol: "The browser-local review returned an invalid response.",
  invalid_selection: "The scenario selection is invalid or unsupported.",
  invalid_custom_scenario: "A custom scenario definition is not a supported validated criterion.",
  definition_digest_mismatch: "A scenario definition does not match its recorded digest.",
  assessment_failed: "The browser-local assessment could not be completed safely.",
});
const PUBLIC_ERROR_CODES = new Set(Object.keys(PUBLIC_ERRORS));


function isPublicErrorCode(code: string): boolean {
  return PUBLIC_ERROR_CODES.has(code);
}


export class BrowserReviewClientError extends Error {
  readonly code: string;
  readonly publicMessage: string;

  constructor(code: string) {
    const safeCode = isPublicErrorCode(code) ? code : "review_failed";
    const publicMessage = PUBLIC_ERRORS[safeCode];
    super(publicMessage);
    this.name = "BrowserReviewClientError";
    this.code = safeCode;
    this.publicMessage = publicMessage;
  }
}


function defaultWorkerFactory(): ReviewWorkerLike {
  return new Worker(new URL("../workers/heel-review.worker.ts", import.meta.url), {
    type: "module",
    name: "heel-browser-review",
  });
}


function exactFields(value: Record<string, unknown>, fields: string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}


function messageRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}


function normalizeAnswers(value: readonly ReviewAnswer[]): ReviewAnswer[] {
  if (!Array.isArray(value) || value.length > 64) throw new BrowserReviewClientError("invalid_answers");
  const seen = new Set<string>();
  const normalized = value.map((candidate) => {
    if (
      candidate === null
      || typeof candidate !== "object"
      || !exactFields(candidate as unknown as Record<string, unknown>, ["surface", "field", "value"])
      || typeof candidate.surface !== "string"
      || candidate.surface.length === 0
      || !["tenant_filter", "entitlement_check", "rate_limit"].includes(candidate.field)
      || !["enforced", "not_enforced", "unknown"].includes(candidate.value)
    ) throw new BrowserReviewClientError("invalid_answers");
    const key = `${candidate.surface}\u0000${candidate.field}`;
    if (seen.has(key)) throw new BrowserReviewClientError("invalid_answers");
    seen.add(key);
    return { ...candidate };
  });
  return normalized;
}


export class BrowserReviewClient {
  readonly #workerFactory: () => ReviewWorkerLike;
  readonly #timeoutMs: number;
  readonly #bootTimeoutMs: number;
  readonly #listeners = new Set<(status: BrowserReviewStatus) => void>();
  readonly #readyWaiters = new Set<{
    resolve(): void;
    reject(error: BrowserReviewClientError): void;
  }>();
  #worker: ReviewWorkerLike | null = null;
  #status: BrowserReviewStatus = "loading_engine";
  #engineReady = false;
  #active: ActiveRequest | null = null;
  #queued: QueuedRequest | null = null;
  #bootTimer: ReturnType<typeof setTimeout> | null = null;
  #bootRetriesRemaining = MAX_AUTOMATIC_BOOT_RETRIES;
  #retainedInput: RetainedBrowserInput | null = null;
  #baseline: ReviewBaseline | null = null;
  #requestSequence = 0;
  #disposed = false;

  constructor(options: BrowserReviewClientOptions = {}) {
    this.#workerFactory = options.workerFactory ?? defaultWorkerFactory;
    this.#timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.#bootTimeoutMs = options.bootTimeoutMs ?? DEFAULT_BOOT_TIMEOUT_MS;
    if (
      !Number.isSafeInteger(this.#timeoutMs)
      || this.#timeoutMs <= 0
      || !Number.isSafeInteger(this.#bootTimeoutMs)
      || this.#bootTimeoutMs <= 0
    ) {
      throw new Error("review and boot timeouts must be positive safe integers");
    }
    this.#spawnWorker();
  }

  get status(): BrowserReviewStatus {
    return this.#status;
  }

  get retainedInput(): RetainedBrowserInput | null {
    return this.#retainedInput === null
      ? null
      : { source: this.#retainedInput.source, answers: this.#retainedInput.answers.map((answer) => ({ ...answer })) };
  }

  subscribe(listener: (status: BrowserReviewStatus) => void): () => void {
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  whenReady(): Promise<void> {
    if (this.#disposed) return Promise.reject(new BrowserReviewClientError("engine_unavailable"));
    if (this.#engineReady) return Promise.resolve();
    if (this.#status === "failed" && this.#worker === null) {
      return Promise.reject(new BrowserReviewClientError("engine_unavailable"));
    }
    return new Promise((resolve, reject) => this.#readyWaiters.add({ resolve, reject }));
  }

  review(source: string, answers: readonly ReviewAnswer[] = []): Promise<BrowserReviewResult> {
    return this.#request(source, answers, null);
  }

  rerun(
    source: string,
    before: ReviewEnvelopeV1,
    answers: readonly ReviewAnswer[],
  ): Promise<BrowserReviewResult> {
    let parsedBefore: ReviewEnvelopeV1;
    try {
      parsedBefore = parseReviewEnvelopeV1(before);
      if (
        this.#baseline === null
        || source !== this.#baseline.source
        || parsedBefore.review_id !== this.#baseline.envelope.review_id
        || parsedBefore.result_hash !== this.#baseline.envelope.result_hash
      ) {
        throw new BrowserReviewClientError("invalid_answers");
      }
    } catch (error) {
      return Promise.reject(
        error instanceof BrowserReviewClientError
          ? error
          : new BrowserReviewClientError("invalid_answers"),
      );
    }
    return this.#request(source, answers, parsedBefore);
  }

  /**
   * Statically assess explicitly selected scenarios against this browser's own OpenAPI source.
   * The source, answers, model and result never leave the browser; retained review input is unchanged.
   */
  assessScenarios(
    source: string,
    answers: readonly ReviewAnswer[],
    selection: ScenarioAssessmentSelection,
  ): Promise<ScenarioAssessmentEnvelopeV1> {
    let normalized: ReviewAnswer[];
    let answersJson: string;
    let selectionJson: string;
    try {
      if (typeof source !== "string") throw new BrowserReviewClientError("invalid_document");
      if (new TextEncoder().encode(source).byteLength > MAX_BROWSER_INPUT_BYTES) {
        throw new BrowserReviewClientError("input_too_large");
      }
      normalized = normalizeAnswers(answers);
      answersJson = JSON.stringify(normalized);
      if (new TextEncoder().encode(answersJson).byteLength > MAX_BROWSER_ANSWERS_BYTES) {
        throw new BrowserReviewClientError("answers_too_large");
      }
      if (
        selection === null || typeof selection !== "object" || typeof selection.library_digest !== "string"
        || !HEX64.test(selection.library_digest) || !Array.isArray(selection.scenarios)
        || selection.scenarios.length < 1 || selection.scenarios.length > MAX_ASSESSMENT_SELECTED
        || new Set(selection.scenarios.map((item) => item.scenario_id)).size !== selection.scenarios.length
      ) throw new BrowserReviewClientError("invalid_selection");
      const ordered = {
        library_digest: selection.library_digest,
        scenarios: selection.scenarios.map((item) => ({
          definition: item.definition, definition_digest: item.definition_digest, revision: item.revision,
          scenario_id: item.scenario_id, source: item.source,
        })),
        schema_version: "heel.scenario-assessment-selection.v1",
      };
      selectionJson = JSON.stringify(ordered);
      if (new TextEncoder().encode(selectionJson).byteLength > MAX_ASSESSMENT_SELECTION_BYTES) {
        throw new BrowserReviewClientError("invalid_selection");
      }
      if (this.#active !== null || this.#queued !== null) throw new BrowserReviewClientError("review_in_progress");
    } catch (error) {
      return Promise.reject(error instanceof BrowserReviewClientError ? error : new BrowserReviewClientError("invalid_selection"));
    }
    const frozenSelection: ScenarioAssessmentSelection = {
      library_digest: selection.library_digest,
      scenarios: selection.scenarios.map((item) => ({ ...item })),
    };
    return new Promise((resolve, reject) => {
      const queued: QueuedRequest = {
        kind: "assess", selection: frozenSelection, selectionJson, resolveAssessment: resolve,
        source, answers: normalized, answersJson, before: null,
        resolve: () => reject(new BrowserReviewClientError("worker_protocol")), reject,
      };
      if (this.#engineReady) this.#beginRequest(queued);
      else if (this.#worker === null || this.#status === "failed") reject(new BrowserReviewClientError("engine_unavailable"));
      else this.#queued = queued;
    });
  }

  cancel(): void {
    if (this.#active !== null) {
      this.#failActive("review_cancelled", true);
      return;
    }
    if (this.#queued !== null) {
      const queued = this.#queued;
      this.#queued = null;
      queued.reject(new BrowserReviewClientError("review_cancelled"));
      this.#rejectReadyWaiters("engine_unavailable");
      this.#bootRetriesRemaining = MAX_AUTOMATIC_BOOT_RETRIES;
      this.#replaceWorker();
    }
  }

  restart(): void {
    if (this.#disposed) return;
    this.#bootRetriesRemaining = MAX_AUTOMATIC_BOOT_RETRIES;
    if (this.#active !== null) this.#failActive("engine_failed", false);
    if (this.#queued !== null) {
      const queued = this.#queued;
      this.#queued = null;
      queued.reject(new BrowserReviewClientError("engine_failed"));
    }
    this.#replaceWorker();
  }

  dispose(): void {
    this.#disposed = true;
    if (this.#active !== null) this.#failActive("review_cancelled", false);
    if (this.#queued !== null) {
      const queued = this.#queued;
      this.#queued = null;
      queued.reject(new BrowserReviewClientError("review_cancelled"));
    }
    this.#detachAndTerminate();
    this.#rejectReadyWaiters("engine_unavailable");
    this.#setStatus("failed");
  }

  #request(
    source: string,
    answersValue: readonly ReviewAnswer[],
    before: ReviewEnvelopeV1 | null,
  ): Promise<BrowserReviewResult> {
    let answers: ReviewAnswer[];
    let answersJson: string;
    try {
      if (typeof source !== "string") throw new BrowserReviewClientError("invalid_document");
      if (new TextEncoder().encode(source).byteLength > MAX_BROWSER_INPUT_BYTES) {
        throw new BrowserReviewClientError("input_too_large");
      }
      answers = normalizeAnswers(answersValue);
      answersJson = JSON.stringify(answers);
      if (new TextEncoder().encode(answersJson).byteLength > MAX_BROWSER_ANSWERS_BYTES) {
        throw new BrowserReviewClientError("answers_too_large");
      }
      if (before !== null && answers.length === 0) throw new BrowserReviewClientError("invalid_answers");
      if (before === null && answers.length !== 0) throw new BrowserReviewClientError("invalid_answers");
      if (this.#active !== null || this.#queued !== null) {
        throw new BrowserReviewClientError("review_in_progress");
      }
    } catch (error) {
      return Promise.reject(
        error instanceof BrowserReviewClientError
          ? error
          : new BrowserReviewClientError("invalid_answers"),
      );
    }
    this.#retainedInput = { source, answers: answers.map((answer) => ({ ...answer })) };
    return new Promise((resolve, reject) => {
      const queued: QueuedRequest = {
        kind: "review", selection: null, selectionJson: "", resolveAssessment: null,
        source, answers, answersJson, before, resolve, reject,
      };
      if (this.#engineReady) {
        this.#beginRequest(queued);
      } else if (this.#worker === null || this.#status === "failed") {
        reject(new BrowserReviewClientError("engine_unavailable"));
      } else {
        this.#queued = queued;
      }
    });
  }

  #beginRequest(request: QueuedRequest): void {
    const worker = this.#worker;
    if (this.#active !== null || worker === null || !this.#engineReady) {
      request.reject(new BrowserReviewClientError("engine_unavailable"));
      return;
    }
    const id = `request_${++this.#requestSequence}`;
    this.#setStatus("reviewing");
    const timer = setTimeout(() => this.#failActive("review_timeout", true), this.#timeoutMs);
    this.#active = {
      kind: request.kind,
      selection: request.selection,
      resolveAssessment: request.resolveAssessment,
      id,
      source: request.source,
      before: request.before,
      answers: request.answers,
      resolve: request.resolve,
      reject: request.reject,
      timer,
    };
    try {
      worker.postMessage(JSON.stringify(request.kind === "assess" ? {
        type: "assess",
        protocol_version: WORKER_PROTOCOL_VERSION,
        request_id: id,
        source: request.source,
        answers_json: request.answersJson,
        selection_json: request.selectionJson,
      } : {
        type: "review",
        protocol_version: WORKER_PROTOCOL_VERSION,
        request_id: id,
        source: request.source,
        answers_json: request.answersJson,
      }));
    } catch {
      this.#failActive("engine_failed", true);
    }
  }

  #spawnWorker(): void {
    this.#engineReady = false;
    this.#setStatus("loading_engine");
    try {
      const worker = this.#workerFactory();
      this.#worker = worker;
      worker.onmessage = (event) => this.#handleMessage(event.data);
      worker.onerror = () => this.#handleCrash();
      this.#bootTimer = setTimeout(
        () => this.#failBoot("engine_unavailable"),
        this.#bootTimeoutMs,
      );
    } catch {
      this.#worker = null;
      this.#setStatus("failed");
      this.#rejectReadyWaiters("engine_unavailable");
    }
  }

  #handleMessage(message: unknown): void {
    if (typeof message !== "string") {
      this.#protocolFailure();
      return;
    }
    if (new TextEncoder().encode(message).byteLength > MAX_WORKER_MESSAGE_BYTES) {
      if (this.#engineReady) this.#failActive("result_too_large", true);
      else this.#failBoot("engine_unavailable");
      return;
    }
    let decoded: unknown;
    try {
      decoded = JSON.parse(message);
    } catch {
      this.#protocolFailure();
      return;
    }
    const record = messageRecord(decoded);
    if (record === null || record.protocol_version !== WORKER_PROTOCOL_VERSION || typeof record.type !== "string") {
      this.#protocolFailure();
      return;
    }
    if (record.type === "ready") {
      if (!exactFields(record, ["type", "protocol_version"]) || this.#active !== null) {
        this.#protocolFailure();
        return;
      }
      this.#clearBootTimer();
      this.#engineReady = true;
      this.#bootRetriesRemaining = MAX_AUTOMATIC_BOOT_RETRIES;
      this.#setStatus("ready");
      for (const waiter of this.#readyWaiters) waiter.resolve();
      this.#readyWaiters.clear();
      if (this.#queued !== null) {
        const queued = this.#queued;
        this.#queued = null;
        this.#beginRequest(queued);
      }
      return;
    }
    if (record.type === "fatal") {
      if (!exactFields(record, ["type", "protocol_version", "code", "message"])) {
        this.#protocolFailure();
        return;
      }
      this.#failBoot("engine_unavailable", !this.#engineReady);
      return;
    }
    const active = this.#active;
    if (active === null || record.request_id !== active.id) return;
    if (record.type === "error") {
      if (!exactFields(record, ["type", "protocol_version", "request_id", "code", "message"])) {
        this.#failActive("worker_protocol", true);
        return;
      }
      const code = typeof record.code === "string" && isPublicErrorCode(record.code)
        ? record.code
        : "review_failed";
      this.#failActive(code, true);
      return;
    }
    if (active.kind === "assess") {
      if (record.type !== "assess_result" || !exactFields(record, ["type", "protocol_version", "request_id", "result_json"])
        || typeof record.result_json !== "string" || active.selection === null || active.resolveAssessment === null) {
        this.#failActive("worker_protocol", true);
        return;
      }
      if (new TextEncoder().encode(record.result_json).byteLength > MAX_BROWSER_RESULT_BYTES) {
        this.#failActive("result_too_large", true);
        return;
      }
      try {
        const assessment = parseScenarioAssessmentV1(JSON.parse(record.result_json), active.selection);
        clearTimeout(active.timer);
        this.#active = null;
        this.#setStatus("complete");
        active.resolveAssessment(assessment);
      } catch {
        this.#failActive("worker_protocol", true);
      }
      return;
    }
    if (record.type !== "result" || !exactFields(record, ["type", "protocol_version", "request_id", "result_json"])) {
      this.#failActive("worker_protocol", true);
      return;
    }
    if (typeof record.result_json !== "string") {
      this.#failActive("worker_protocol", true);
      return;
    }
    if (new TextEncoder().encode(record.result_json).byteLength > MAX_BROWSER_RESULT_BYTES) {
      this.#failActive("result_too_large", true);
      return;
    }
    try {
      const envelope = parseCurrentReviewEnvelopeV1(JSON.parse(record.result_json));
      if (
        active.before !== null
        && (
          envelope.product_id !== active.before.product_id
          || envelope.baseline_hash !== active.before.baseline_hash
        )
      ) {
        throw new Error("rerun result identity does not match its baseline");
      }
      const receipt = active.before === null
        ? null
        : deriveAnswerReceipt(active.before, envelope, active.answers);
      if (active.before === null) {
        this.#baseline = {
          source: active.source,
          envelope: parseCurrentReviewEnvelopeV1(envelope),
        };
      }
      clearTimeout(active.timer);
      this.#active = null;
      this.#setStatus("complete");
      active.resolve({ envelope, receipt });
    } catch {
      this.#failActive("worker_protocol", true);
    }
  }

  #handleCrash(): void {
    if (this.#disposed) return;
    if (!this.#engineReady) this.#failBoot("engine_failed");
    else if (this.#active !== null) this.#failActive("engine_failed", true);
    else this.#replaceWorker();
  }

  #failBoot(code: string, allowRetry = true): void {
    this.#clearBootTimer();
    if (this.#active !== null) {
      const active = this.#active;
      clearTimeout(active.timer);
      this.#active = null;
      active.reject(new BrowserReviewClientError(code));
    }
    if (this.#queued !== null) {
      const queued = this.#queued;
      this.#queued = null;
      queued.reject(new BrowserReviewClientError(code));
    }
    this.#rejectReadyWaiters(code);
    this.#detachAndTerminate();
    if (allowRetry && !this.#disposed && this.#bootRetriesRemaining > 0) {
      this.#bootRetriesRemaining -= 1;
      this.#spawnWorker();
    } else {
      this.#setStatus("failed");
    }
  }

  #protocolFailure(): void {
    if (this.#engineReady) this.#failActive("worker_protocol", true);
    else this.#failBoot("engine_unavailable");
  }

  #failActive(code: string, restart: boolean): void {
    const active = this.#active;
    if (active !== null) {
      clearTimeout(active.timer);
      this.#active = null;
      this.#setStatus("failed");
      active.reject(new BrowserReviewClientError(code));
    }
    if (restart && !this.#disposed) this.#replaceWorker();
  }

  #replaceWorker(): void {
    this.#detachAndTerminate();
    if (!this.#disposed) this.#spawnWorker();
  }

  #detachAndTerminate(): void {
    this.#clearBootTimer();
    const worker = this.#worker;
    this.#worker = null;
    this.#engineReady = false;
    if (worker !== null) {
      worker.onmessage = null;
      worker.onerror = null;
      worker.terminate();
    }
  }

  #clearBootTimer(): void {
    if (this.#bootTimer !== null) {
      clearTimeout(this.#bootTimer);
      this.#bootTimer = null;
    }
  }

  #rejectReadyWaiters(code: string): void {
    const error = new BrowserReviewClientError(code);
    for (const waiter of this.#readyWaiters) waiter.reject(error);
    this.#readyWaiters.clear();
  }

  #setStatus(status: BrowserReviewStatus): void {
    this.#status = status;
    for (const listener of this.#listeners) {
      try {
        listener(status);
      } catch {
        // Subscriber failures never control the review state machine.
      }
    }
  }
}
