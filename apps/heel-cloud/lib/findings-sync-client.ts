// SPDX-License-Identifier: LicenseRef-Heel-Commercial

/** Local projection orchestration. This module deliberately has no HTTP capability. */

import {
  assertPreparedFindingsSyncBindingV1,
  assertFindingsSyncReceiptMatchesV1,
  canonicalFindingsSyncRequestJsonV1,
  findingsSyncRequestDigestV1,
  MAX_FINDINGS_SYNC_BYTES,
  parseFindingsSyncReceiptJsonV1,
  parseFindingsSyncRequestJsonV1,
  verifyProjectedFindingsSyncV1,
  type FindingsSyncReceiptV1,
  type FindingsSyncRequestV1,
} from "./findings-sync-v1";
import { parseReviewEnvelopeV1, type ReviewEnvelopeV1 } from "./review-v1";


export const WORKER_PROTOCOL_VERSION = "heel.browser-worker.v1" as const;
export const MAX_FINDINGS_WORKER_MESSAGE_BYTES = 2 * MAX_FINDINGS_SYNC_BYTES + 64 * 1024;
const MAX_LOCAL_REVIEW_JSON_BYTES = 4 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_BOOT_TIMEOUT_MS = 20_000;
const PROJECT_REF = /^prj_[0-9a-f]{32}$/;

export interface PreparedFindingsSyncV1 {
  request: FindingsSyncRequestV1;
  requestJson: string;
  requestDigest: string;
  idempotencyKey: `fs1-${string}`;
}

export interface FindingsSyncWorkerLike {
  onmessage: ((event: MessageEvent<string>) => void) | null;
  onerror: ((event: ErrorEvent) => void) | null;
  postMessage(message: Record<string, unknown>, transfer: Transferable[]): void;
  terminate(): void;
}

export interface FindingsSyncClientOptions {
  workerFactory?: () => FindingsSyncWorkerLike;
  timeoutMs?: number;
  bootTimeoutMs?: number;
}

export type FindingsSyncClientErrorCode =
  | "engine_unavailable"
  | "projection_failed"
  | "projection_too_large"
  | "operation_in_progress"
  | "projection_cancelled"
  | "projection_timeout"
  | "context_mismatch"
  | "worker_protocol";

const PUBLIC_ERRORS: Readonly<Record<FindingsSyncClientErrorCode, string>> = Object.freeze({
  engine_unavailable: "The browser-local findings engine could not be started.",
  projection_failed: "The findings projection could not be completed safely.",
  projection_too_large: "The findings projection exceeds the browser limit.",
  operation_in_progress: "A browser-local Heel operation is already running.",
  projection_cancelled: "The findings projection was cancelled.",
  projection_timeout: "The findings projection exceeded its safe time limit.",
  context_mismatch: "The findings receipt does not match the approved projection.",
  worker_protocol: "The browser-local findings engine returned an invalid response.",
});
const PUBLIC_ERROR_CODES = new Set(Object.keys(PUBLIC_ERRORS));

export class FindingsSyncClientError extends Error {
  readonly code: FindingsSyncClientErrorCode;
  readonly publicMessage: string;

  constructor(code: string) {
    const safeCode = PUBLIC_ERROR_CODES.has(code)
      ? code as FindingsSyncClientErrorCode
      : "projection_failed";
    super(PUBLIC_ERRORS[safeCode]);
    this.name = "FindingsSyncClientError";
    this.code = safeCode;
    this.publicMessage = PUBLIC_ERRORS[safeCode];
  }
}

interface PendingProjection {
  review: ReviewEnvelopeV1;
  reviewJson: string;
  projectRef: string;
  namespaceKey: Uint8Array<ArrayBuffer>;
  resolve(value: PreparedFindingsSyncV1): void;
  reject(error: FindingsSyncClientError): void;
}

interface ActiveProjection extends PendingProjection {
  requestId: string;
  timer: ReturnType<typeof setTimeout>;
}


function defaultWorkerFactory(): FindingsSyncWorkerLike {
  return new Worker(new URL("../workers/heel-review.worker.ts", import.meta.url), {
    type: "module",
    name: "heel-findings-projection",
  });
}


function exactFields(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}


function messageRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}


function copiedKey(namespaceKey: Uint8Array): Uint8Array<ArrayBuffer> {
  if (!(namespaceKey instanceof Uint8Array) || namespaceKey.byteLength !== 32) {
    throw new FindingsSyncClientError("projection_failed");
  }
  const copied = new Uint8Array(32);
  copied.set(namespaceKey);
  return copied;
}


function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object") {
    const item = value as Record<string, unknown>;
    for (const key of Object.keys(item)) deepFreeze(item[key]);
    Object.freeze(value);
  }
  return value;
}


export class FindingsSyncClient {
  readonly #workerFactory: () => FindingsSyncWorkerLike;
  readonly #timeoutMs: number;
  readonly #bootTimeoutMs: number;
  readonly #readyWaiters = new Set<{
    resolve(): void;
    reject(error: FindingsSyncClientError): void;
  }>();
  #worker: FindingsSyncWorkerLike | null = null;
  #ready = false;
  #disposed = false;
  #bootTimer: ReturnType<typeof setTimeout> | null = null;
  #queued: PendingProjection | null = null;
  #active: ActiveProjection | null = null;
  #requestSequence = 0;

  constructor(options: FindingsSyncClientOptions = {}) {
    this.#workerFactory = options.workerFactory ?? defaultWorkerFactory;
    this.#timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.#bootTimeoutMs = options.bootTimeoutMs ?? DEFAULT_BOOT_TIMEOUT_MS;
    if (
      !Number.isSafeInteger(this.#timeoutMs)
      || this.#timeoutMs <= 0
      || !Number.isSafeInteger(this.#bootTimeoutMs)
      || this.#bootTimeoutMs <= 0
    ) throw new Error("findings projection timeouts must be positive safe integers");
    this.#spawnWorker();
  }

  whenReady(): Promise<void> {
    if (this.#disposed || this.#worker === null) {
      return Promise.reject(new FindingsSyncClientError("engine_unavailable"));
    }
    if (this.#ready) return Promise.resolve();
    return new Promise((resolve, reject) => this.#readyWaiters.add({ resolve, reject }));
  }

  preview(
    reviewValue: ReviewEnvelopeV1,
    projectRef: string,
    namespaceKey: Uint8Array,
  ): Promise<PreparedFindingsSyncV1> {
    let review: ReviewEnvelopeV1;
    let reviewJson: string;
    let key: Uint8Array<ArrayBuffer>;
    try {
      if (this.#disposed || this.#active !== null || this.#queued !== null) {
        throw new FindingsSyncClientError("operation_in_progress");
      }
      review = parseReviewEnvelopeV1(reviewValue);
      if (typeof projectRef !== "string" || !PROJECT_REF.test(projectRef)) {
        throw new FindingsSyncClientError("projection_failed");
      }
      key = copiedKey(namespaceKey);
      reviewJson = JSON.stringify(review);
      if (new TextEncoder().encode(reviewJson).byteLength > MAX_LOCAL_REVIEW_JSON_BYTES) {
        key.fill(0);
        throw new FindingsSyncClientError("projection_too_large");
      }
    } catch (error) {
      return Promise.reject(
        error instanceof FindingsSyncClientError
          ? error
          : new FindingsSyncClientError("projection_failed"),
      );
    }
    return new Promise((resolve, reject) => {
      const pending = { review, reviewJson, projectRef, namespaceKey: key, resolve, reject };
      if (this.#ready) this.#begin(pending);
      else if (this.#worker === null) {
        key.fill(0);
        reject(new FindingsSyncClientError("engine_unavailable"));
      } else this.#queued = pending;
    });
  }

  cancel(): void {
    if (this.#active !== null) {
      this.#failActive("projection_cancelled", true);
      return;
    }
    if (this.#queued !== null) {
      const queued = this.#queued;
      this.#queued = null;
      queued.namespaceKey.fill(0);
      queued.reject(new FindingsSyncClientError("projection_cancelled"));
      this.#replaceWorker();
    }
  }

  restart(): void {
    if (this.#disposed) return;
    if (this.#active !== null) this.#failActive("projection_cancelled", false);
    if (this.#queued !== null) {
      const queued = this.#queued;
      this.#queued = null;
      queued.namespaceKey.fill(0);
      queued.reject(new FindingsSyncClientError("projection_cancelled"));
    }
    this.#replaceWorker();
  }

  dispose(): void {
    this.#disposed = true;
    if (this.#active !== null) this.#failActive("projection_cancelled", false);
    if (this.#queued !== null) {
      const queued = this.#queued;
      this.#queued = null;
      queued.namespaceKey.fill(0);
      queued.reject(new FindingsSyncClientError("projection_cancelled"));
    }
    this.#detachAndTerminate();
    this.#rejectReadyWaiters();
  }

  #begin(pending: PendingProjection): void {
    const worker = this.#worker;
    if (worker === null || !this.#ready || this.#active !== null) {
      pending.namespaceKey.fill(0);
      pending.reject(new FindingsSyncClientError("engine_unavailable"));
      return;
    }
    const requestId = `request_${++this.#requestSequence}`;
    const timer = setTimeout(
      () => this.#failActive("projection_timeout", true),
      this.#timeoutMs,
    );
    this.#active = { ...pending, requestId, timer };
    const transferKey = new Uint8Array(32);
    transferKey.set(pending.namespaceKey);
    const namespaceBuffer = transferKey.buffer;
    const message: Record<string, unknown> = {
      type: "project_findings",
      protocol_version: WORKER_PROTOCOL_VERSION,
      request_id: requestId,
      review_json: pending.reviewJson,
      project_ref: pending.projectRef,
      namespace_key: namespaceBuffer,
    };
    try {
      worker.postMessage(message, [namespaceBuffer]);
    } catch {
      this.#failActive("engine_unavailable", true);
    } finally {
      if (transferKey.byteLength > 0) transferKey.fill(0);
    }
  }

  #spawnWorker(): void {
    this.#ready = false;
    try {
      const worker = this.#workerFactory();
      this.#worker = worker;
      worker.onmessage = (event) => this.#handleMessage(event.data);
      worker.onerror = () => {
        if (this.#active !== null) this.#failActive("engine_unavailable", true);
        else this.#failBoot();
      };
      this.#bootTimer = setTimeout(() => this.#failBoot(), this.#bootTimeoutMs);
    } catch {
      this.#worker = null;
      this.#rejectReadyWaiters();
    }
  }

  #handleMessage(message: unknown): void {
    if (typeof message !== "string" || new TextEncoder().encode(message).byteLength > MAX_FINDINGS_WORKER_MESSAGE_BYTES) {
      this.#protocolFailure();
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
      this.#ready = true;
      for (const waiter of this.#readyWaiters) waiter.resolve();
      this.#readyWaiters.clear();
      if (this.#queued !== null) {
        const queued = this.#queued;
        this.#queued = null;
        this.#begin(queued);
      }
      return;
    }
    if (record.type === "fatal") {
      this.#failBoot();
      return;
    }
    const active = this.#active;
    if (active === null || record.request_id !== active.requestId) return;
    if (record.type === "error") {
      if (!exactFields(record, ["type", "protocol_version", "request_id", "code", "message"])) {
        this.#failActive("worker_protocol", true);
        return;
      }
      const code = typeof record.code === "string" ? record.code : "projection_failed";
      this.#failActive(code, false);
      return;
    }
    if (
      record.type !== "findings_result"
      || !exactFields(record, ["type", "protocol_version", "request_id", "request_json"])
      || typeof record.request_json !== "string"
      || new TextEncoder().encode(record.request_json).byteLength > MAX_FINDINGS_SYNC_BYTES
    ) {
      this.#failActive("worker_protocol", true);
      return;
    }
    void this.#finish(active, record.request_json);
  }

  async #finish(active: ActiveProjection, requestJson: string): Promise<void> {
    try {
      const parsed = await parseFindingsSyncRequestJsonV1(requestJson, active.namespaceKey);
      const request = await verifyProjectedFindingsSyncV1(parsed, {
        review: active.review,
        projectRef: active.projectRef,
        namespaceKey: active.namespaceKey,
      });
      const canonical = await canonicalFindingsSyncRequestJsonV1(request, active.namespaceKey);
      if (canonical !== requestJson) throw new Error("noncanonical projection");
      const requestDigest = await findingsSyncRequestDigestV1(request, active.namespaceKey);
      if (this.#active !== active) return;
      clearTimeout(active.timer);
      active.namespaceKey.fill(0);
      this.#active = null;
      active.resolve(deepFreeze({
        request,
        requestJson: canonical,
        requestDigest,
        idempotencyKey: `fs1-${requestDigest}` as const,
      }));
    } catch {
      if (this.#active === active) this.#failActive("worker_protocol", true);
    }
  }

  #protocolFailure(): void {
    if (this.#active !== null) this.#failActive("worker_protocol", true);
    else this.#failBoot();
  }

  #failActive(code: string, restart: boolean): void {
    const active = this.#active;
    if (active !== null) {
      clearTimeout(active.timer);
      active.namespaceKey.fill(0);
      this.#active = null;
      active.reject(new FindingsSyncClientError(code));
    }
    if (restart && !this.#disposed) this.#replaceWorker();
  }

  #failBoot(): void {
    if (this.#queued !== null) {
      const queued = this.#queued;
      this.#queued = null;
      queued.namespaceKey.fill(0);
      queued.reject(new FindingsSyncClientError("engine_unavailable"));
    }
    this.#rejectReadyWaiters();
    this.#detachAndTerminate();
  }

  #replaceWorker(): void {
    this.#detachAndTerminate();
    if (!this.#disposed) this.#spawnWorker();
  }

  #detachAndTerminate(): void {
    this.#clearBootTimer();
    const worker = this.#worker;
    this.#worker = null;
    this.#ready = false;
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

  #rejectReadyWaiters(): void {
    const error = new FindingsSyncClientError("engine_unavailable");
    for (const waiter of this.#readyWaiters) waiter.reject(error);
    this.#readyWaiters.clear();
  }
}


export interface FindingsSyncApprovalV1 {
  workspaceRef: string;
  projectRef: string;
  requestDigest: string;
  approvedAt: number;
  expiresAt: number;
}

export type FindingsSyncTransportV1 = (
  requestJson: string,
  idempotencyKey: `fs1-${string}`,
) => Promise<string>;


export async function sendApprovedFindingsSyncV1(
  prepared: PreparedFindingsSyncV1,
  approval: FindingsSyncApprovalV1,
  expectedWorkspaceRef: string,
  transport: FindingsSyncTransportV1,
  now = Date.now(),
): Promise<FindingsSyncReceiptV1> {
  if (
    typeof approval.workspaceRef !== "string"
    || approval.workspaceRef.length === 0
    || typeof expectedWorkspaceRef !== "string"
    || expectedWorkspaceRef.length === 0
    || approval.workspaceRef !== expectedWorkspaceRef
    || approval.projectRef !== prepared.request.project_ref
    || approval.requestDigest !== prepared.requestDigest
    || !Number.isSafeInteger(now)
    || !Number.isSafeInteger(approval.approvedAt)
    || !Number.isSafeInteger(approval.expiresAt)
    || approval.approvedAt > now
    || approval.expiresAt < now
    || approval.expiresAt - approval.approvedAt > 10 * 60 * 1000
    || typeof transport !== "function"
  ) throw new FindingsSyncClientError("projection_failed");
  try {
    await assertPreparedFindingsSyncBindingV1(prepared);
    const responseText = await transport(prepared.requestJson, prepared.idempotencyKey);
    const receipt = parseFindingsSyncReceiptJsonV1(responseText);
    assertFindingsSyncReceiptMatchesV1(receipt, prepared);
    return receipt;
  } catch (error) {
    if (
      error !== null
      && typeof error === "object"
      && "code" in error
      && error.code === "context_mismatch"
    ) throw new FindingsSyncClientError("context_mismatch");
    throw new FindingsSyncClientError("projection_failed");
  }
}
