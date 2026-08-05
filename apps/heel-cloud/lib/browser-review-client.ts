// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import {
  deriveAnswerReceipt,
  MAX_REVIEW_ANSWERS_BYTES,
  type ReviewAnswer,
  type ReviewAnswerReceiptV1,
} from "./review-presentation";
import { parseReviewEnvelopeV1, type ReviewEnvelopeV1 } from "./review-v1";


export const WORKER_PROTOCOL_VERSION = "heel.browser-worker.v1" as const;
export const MAX_BROWSER_INPUT_BYTES = 2 * 1024 * 1024;
export const MAX_BROWSER_ANSWERS_BYTES = MAX_REVIEW_ANSWERS_BYTES;
// A review may fan out beyond its source, but never without a deterministic UI/storage ceiling.
export const MAX_BROWSER_RESULT_BYTES = 4 * 1024 * 1024;
const MAX_WORKER_MESSAGE_BYTES = MAX_BROWSER_RESULT_BYTES * 2 + 64 * 1024;
const DEFAULT_TIMEOUT_MS = 30_000;

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

export interface RetainedBrowserInput {
  source: string;
  answers: ReviewAnswer[];
}

interface ActiveRequest {
  id: string;
  before: ReviewEnvelopeV1 | null;
  answers: ReviewAnswer[];
  resolve(value: BrowserReviewResult): void;
  reject(error: BrowserReviewClientError): void;
  timer: ReturnType<typeof setTimeout>;
}

interface BrowserReviewClientOptions {
  workerFactory?: () => ReviewWorkerLike;
  timeoutMs?: number;
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
});


export class BrowserReviewClientError extends Error {
  readonly code: string;
  readonly publicMessage: string;

  constructor(code: string) {
    const publicMessage = PUBLIC_ERRORS[code] ?? PUBLIC_ERRORS.review_failed;
    super(publicMessage);
    this.name = "BrowserReviewClientError";
    this.code = PUBLIC_ERRORS[code] ? code : "review_failed";
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
  readonly #listeners = new Set<(status: BrowserReviewStatus) => void>();
  readonly #readyWaiters = new Set<{
    resolve(): void;
    reject(error: BrowserReviewClientError): void;
  }>();
  #worker: ReviewWorkerLike | null = null;
  #status: BrowserReviewStatus = "loading_engine";
  #engineReady = false;
  #active: ActiveRequest | null = null;
  #retainedInput: RetainedBrowserInput | null = null;
  #requestSequence = 0;
  #disposed = false;

  constructor(options: BrowserReviewClientOptions = {}) {
    this.#workerFactory = options.workerFactory ?? defaultWorkerFactory;
    this.#timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    if (!Number.isSafeInteger(this.#timeoutMs) || this.#timeoutMs <= 0) {
      throw new Error("timeoutMs must be a positive safe integer");
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
    return this.#request(source, answers, parseReviewEnvelopeV1(before));
  }

  cancel(): void {
    if (this.#active === null) return;
    this.#failActive("review_cancelled", true);
  }

  restart(): void {
    if (this.#disposed) return;
    if (this.#active !== null) this.#failActive("engine_failed", false);
    this.#replaceWorker();
  }

  dispose(): void {
    this.#disposed = true;
    if (this.#active !== null) this.#failActive("review_cancelled", false);
    this.#detachAndTerminate();
    const error = new BrowserReviewClientError("engine_unavailable");
    for (const waiter of this.#readyWaiters) waiter.reject(error);
    this.#readyWaiters.clear();
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
      if (this.#active !== null) throw new BrowserReviewClientError("review_in_progress");
    } catch (error) {
      return Promise.reject(
        error instanceof BrowserReviewClientError
          ? error
          : new BrowserReviewClientError("invalid_answers"),
      );
    }
    if (!this.#engineReady) {
      return this.whenReady().then(() => this.#startRequest(source, answers, answersJson, before));
    }
    return this.#startRequest(source, answers, answersJson, before);
  }

  #startRequest(
    source: string,
    answers: ReviewAnswer[],
    answersJson: string,
    before: ReviewEnvelopeV1 | null,
  ): Promise<BrowserReviewResult> {
    if (this.#active !== null) return Promise.reject(new BrowserReviewClientError("review_in_progress"));
    const worker = this.#worker;
    if (worker === null || !this.#engineReady) {
      return Promise.reject(new BrowserReviewClientError("engine_unavailable"));
    }

    const id = `request_${++this.#requestSequence}`;
    this.#retainedInput = { source, answers: answers.map((answer) => ({ ...answer })) };
    this.#setStatus("reviewing");
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => this.#failActive("review_timeout", true), this.#timeoutMs);
      this.#active = { id, before, answers, resolve, reject, timer };
      try {
        worker.postMessage(JSON.stringify({
          type: "review",
          protocol_version: WORKER_PROTOCOL_VERSION,
          request_id: id,
          source,
          answers_json: answersJson,
        }));
      } catch {
        this.#failActive("engine_failed", true);
      }
    });
  }

  #spawnWorker(): void {
    this.#engineReady = false;
    this.#setStatus("loading_engine");
    try {
      const worker = this.#workerFactory();
      this.#worker = worker;
      worker.onmessage = (event) => this.#handleMessage(event.data);
      worker.onerror = () => this.#handleCrash();
    } catch {
      this.#worker = null;
      this.#setStatus("failed");
      const error = new BrowserReviewClientError("engine_unavailable");
      for (const waiter of this.#readyWaiters) waiter.reject(error);
      this.#readyWaiters.clear();
    }
  }

  #handleMessage(message: unknown): void {
    if (typeof message !== "string") {
      this.#failActive("worker_protocol", true);
      return;
    }
    if (new TextEncoder().encode(message).byteLength > MAX_WORKER_MESSAGE_BYTES) {
      this.#failActive("result_too_large", true);
      return;
    }
    let decoded: unknown;
    try {
      decoded = JSON.parse(message);
    } catch {
      this.#failActive("worker_protocol", true);
      return;
    }
    const record = messageRecord(decoded);
    if (record === null || record.protocol_version !== WORKER_PROTOCOL_VERSION || typeof record.type !== "string") {
      this.#failActive("worker_protocol", true);
      return;
    }
    if (record.type === "ready") {
      if (!exactFields(record, ["type", "protocol_version"]) || this.#active !== null) {
        this.#failActive("worker_protocol", true);
        return;
      }
      this.#engineReady = true;
      this.#setStatus("ready");
      for (const waiter of this.#readyWaiters) waiter.resolve();
      this.#readyWaiters.clear();
      return;
    }
    if (record.type === "fatal") {
      if (!exactFields(record, ["type", "protocol_version", "code", "message"])) {
        this.#failActive("worker_protocol", true);
        return;
      }
      this.#failActive("engine_unavailable", false);
      this.#engineReady = false;
      this.#setStatus("failed");
      const error = new BrowserReviewClientError("engine_unavailable");
      for (const waiter of this.#readyWaiters) waiter.reject(error);
      this.#readyWaiters.clear();
      this.#detachAndTerminate();
      return;
    }
    const active = this.#active;
    if (active === null || record.request_id !== active.id) return;
    if (record.type === "error") {
      if (!exactFields(record, ["type", "protocol_version", "request_id", "code", "message"])) {
        this.#failActive("worker_protocol", true);
        return;
      }
      const code = typeof record.code === "string" && PUBLIC_ERRORS[record.code]
        ? record.code
        : "review_failed";
      this.#failActive(code, true);
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
      const envelope = parseReviewEnvelopeV1(JSON.parse(record.result_json));
      const receipt = active.before === null
        ? null
        : deriveAnswerReceipt(active.before, envelope, active.answers);
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
    if (this.#active !== null) this.#failActive("engine_failed", true);
    else this.#replaceWorker();
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
    const worker = this.#worker;
    this.#worker = null;
    this.#engineReady = false;
    if (worker !== null) {
      worker.onmessage = null;
      worker.onerror = null;
      worker.terminate();
    }
  }

  #setStatus(status: BrowserReviewStatus): void {
    this.#status = status;
    for (const listener of this.#listeners) listener(status);
  }
}
