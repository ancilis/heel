// SPDX-License-Identifier: LicenseRef-Heel-Commercial

/** Durable, privacy-minimized retries for explicitly approved findings projections. */

import type { FindingsSyncApprovalV1, PreparedFindingsSyncV1 } from "./findings-sync-client";
import {
  MAX_FINDINGS_SYNC_BYTES,
  assertFindingsSyncReceiptMatchesV1,
  assertPreparedFindingsSyncBindingV1,
  validateFindingsSyncReceiptV1,
  type FindingsSyncReceiptV1,
  type FindingsSyncRequestV1,
} from "./findings-sync-v1";


export const FINDINGS_SYNC_QUEUE_DATABASE = "heel-findings-sync-queue-v1";
export const FINDINGS_SYNC_QUEUE_STORE = "approved-findings-v1";
export const FINDINGS_SYNC_QUEUE_SCHEMA_VERSION = "heel.findings-sync-queue.v1" as const;
const DATABASE_VERSION = 2;
const WORKSPACE_INDEX = "workspace-ref";
const WORKSPACE_NEXT_ATTEMPT_INDEX = "workspace-next-attempt";
const DEFAULT_LEASE_MS = 30_000;
const MAX_LEASE_MS = 5 * 60 * 1000;
const MAX_APPROVAL_MS = 10 * 60 * 1000;
const WORKSPACE_REF = /^ws_[0-9a-f]{16}$/;
const PROJECT_REF = /^prj_[0-9a-f]{32}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const LEASE_TOKEN = /^fsl_[0-9a-f]{32}$/;

export type FindingsSyncRetryErrorCode =
  | "transport_error"
  | "server_rejected"
  | "approval_expired";

const RETRY_ERROR_CODES = new Set<FindingsSyncRetryErrorCode>([
  "transport_error",
  "server_rejected",
  "approval_expired",
]);

export interface FindingsSyncRetryStateV1 {
  attempts: number;
  next_attempt_at: number | null;
  last_error_code: FindingsSyncRetryErrorCode | null;
  lease_token: string | null;
  lease_expires_at: number | null;
}

export interface StoredFindingsSyncV1 {
  schema_version: typeof FINDINGS_SYNC_QUEUE_SCHEMA_VERSION;
  workspace_ref: string;
  project_ref: string;
  request_digest: string;
  request_json: string;
  approved_at: number;
  expires_at: number;
  retry: FindingsSyncRetryStateV1;
  receipt: FindingsSyncReceiptV1 | null;
}

export interface FindingsSyncLeaseV1 {
  leaseToken: string;
  leaseExpiresAt: number;
  record: StoredFindingsSyncV1;
}

interface FindingsSyncQueueOptions {
  indexedDB?: IDBFactory;
  keyRange?: typeof IDBKeyRange;
  leaseMs?: number;
  now?: () => number;
  token?: () => string;
}

export type FindingsSyncQueueErrorCode =
  | "invalid_input"
  | "immutable_conflict"
  | "storage_corrupt"
  | "storage_unavailable";

const ERROR_MESSAGES: Readonly<Record<FindingsSyncQueueErrorCode, string>> = Object.freeze({
  invalid_input: "The approved findings retry is invalid.",
  immutable_conflict: "The approved findings retry contradicts its immutable record.",
  storage_corrupt: "The approved findings retry store contains an invalid record.",
  storage_unavailable: "The approved findings retry store is unavailable.",
});

export class FindingsSyncQueueError extends Error {
  readonly code: FindingsSyncQueueErrorCode;

  constructor(code: FindingsSyncQueueErrorCode) {
    super(ERROR_MESSAGES[code]);
    this.name = "FindingsSyncQueueError";
    this.code = code;
  }
}


function queueError(code: FindingsSyncQueueErrorCode): never {
  throw new FindingsSyncQueueError(code);
}


function asQueueError(error: unknown, fallback: FindingsSyncQueueErrorCode): never {
  if (error instanceof FindingsSyncQueueError) throw error;
  return queueError(fallback);
}


function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}


function exactFields(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length
    && actual.every((key, index) => key === wanted[index]);
}


function timestamp(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) queueError("invalid_input");
  return value as number;
}


function storedTimestamp(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) queueError("storage_corrupt");
  return value as number;
}


function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object") {
    for (const child of Object.values(value as Record<string, unknown>)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}


function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("findings retry request failed"));
  });
}


function transactionComplete(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onabort = () => reject(transaction.error ?? new Error("findings retry transaction aborted"));
    transaction.onerror = () => reject(transaction.error ?? new Error("findings retry transaction failed"));
  });
}


function openDatabase(factory: IDBFactory): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    let request: IDBOpenDBRequest;
    try {
      request = factory.open(FINDINGS_SYNC_QUEUE_DATABASE, DATABASE_VERSION);
    } catch (error) {
      reject(error);
      return;
    }
    request.onupgradeneeded = () => {
      const database = request.result;
      let store: IDBObjectStore;
      if (!database.objectStoreNames.contains(FINDINGS_SYNC_QUEUE_STORE)) {
        store = database.createObjectStore(FINDINGS_SYNC_QUEUE_STORE, {
          keyPath: ["workspace_ref", "project_ref", "request_digest"],
        });
      } else {
        store = request.transaction!.objectStore(FINDINGS_SYNC_QUEUE_STORE);
      }
      if (!store.indexNames.contains(WORKSPACE_INDEX)) {
        store.createIndex(WORKSPACE_INDEX, "workspace_ref", { unique: false });
      }
      if (!store.indexNames.contains(WORKSPACE_NEXT_ATTEMPT_INDEX)) {
        store.createIndex(
          WORKSPACE_NEXT_ATTEMPT_INDEX,
          ["workspace_ref", "retry.next_attempt_at"],
          { unique: false },
        );
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("findings retry store could not open"));
    request.onblocked = () => reject(new Error("findings retry store upgrade is blocked"));
  });
}


function preparedFromStored(value: StoredFindingsSyncV1): PreparedFindingsSyncV1 {
  let request: FindingsSyncRequestV1;
  try {
    request = JSON.parse(value.request_json) as FindingsSyncRequestV1;
  } catch {
    return queueError("storage_corrupt");
  }
  return {
    request,
    requestJson: value.request_json,
    requestDigest: value.request_digest,
    idempotencyKey: `fs1-${value.request_digest}`,
  };
}


function parseStoredShape(value: unknown): StoredFindingsSyncV1 {
  if (!isRecord(value) || !exactFields(value, [
    "schema_version",
    "workspace_ref",
    "project_ref",
    "request_digest",
    "request_json",
    "approved_at",
    "expires_at",
    "retry",
    "receipt",
  ])) queueError("storage_corrupt");
  if (
    value.schema_version !== FINDINGS_SYNC_QUEUE_SCHEMA_VERSION
    || typeof value.workspace_ref !== "string"
    || !WORKSPACE_REF.test(value.workspace_ref)
    || typeof value.project_ref !== "string"
    || !PROJECT_REF.test(value.project_ref)
    || typeof value.request_digest !== "string"
    || !SHA256.test(value.request_digest)
    || typeof value.request_json !== "string"
    || new TextEncoder().encode(value.request_json).byteLength > MAX_FINDINGS_SYNC_BYTES
  ) queueError("storage_corrupt");
  const approvedAt = storedTimestamp(value.approved_at);
  const expiresAt = storedTimestamp(value.expires_at);
  if (approvedAt > expiresAt || expiresAt - approvedAt > MAX_APPROVAL_MS) {
    queueError("storage_corrupt");
  }
  if (!isRecord(value.retry) || !exactFields(value.retry, [
    "attempts",
    "next_attempt_at",
    "last_error_code",
    "lease_token",
    "lease_expires_at",
  ])) queueError("storage_corrupt");
  const retry = value.retry;
  if (!Number.isSafeInteger(retry.attempts) || (retry.attempts as number) < 0) {
    queueError("storage_corrupt");
  }
  const nextAttemptAt = retry.next_attempt_at === null
    ? null
    : storedTimestamp(retry.next_attempt_at);
  const lastErrorCode = retry.last_error_code;
  if (
    lastErrorCode !== null
    && (typeof lastErrorCode !== "string"
      || !RETRY_ERROR_CODES.has(lastErrorCode as FindingsSyncRetryErrorCode))
  ) queueError("storage_corrupt");
  const leaseToken = retry.lease_token;
  const leaseExpiresAt = retry.lease_expires_at;
  if (
    (leaseToken === null) !== (leaseExpiresAt === null)
    || (leaseToken !== null && (typeof leaseToken !== "string" || !LEASE_TOKEN.test(leaseToken)))
  ) queueError("storage_corrupt");
  const normalizedLeaseExpiry = leaseExpiresAt === null
    ? null
    : storedTimestamp(leaseExpiresAt);
  if (value.receipt === null && nextAttemptAt === null) queueError("storage_corrupt");
  if (
    value.receipt !== null
    && (nextAttemptAt !== null || leaseToken !== null || normalizedLeaseExpiry !== null)
  ) queueError("storage_corrupt");
  return {
    schema_version: FINDINGS_SYNC_QUEUE_SCHEMA_VERSION,
    workspace_ref: value.workspace_ref,
    project_ref: value.project_ref,
    request_digest: value.request_digest,
    request_json: value.request_json,
    approved_at: approvedAt,
    expires_at: expiresAt,
    retry: {
      attempts: retry.attempts as number,
      next_attempt_at: nextAttemptAt,
      last_error_code: lastErrorCode as FindingsSyncRetryErrorCode | null,
      lease_token: leaseToken as string | null,
      lease_expires_at: normalizedLeaseExpiry,
    },
    receipt: value.receipt as FindingsSyncReceiptV1 | null,
  };
}


async function parseStored(value: unknown): Promise<StoredFindingsSyncV1> {
  try {
    const shaped = parseStoredShape(value);
    const prepared = preparedFromStored(shaped);
    await assertPreparedFindingsSyncBindingV1(prepared);
    if (prepared.request.project_ref !== shaped.project_ref) queueError("storage_corrupt");
    let receipt: FindingsSyncReceiptV1 | null = null;
    if (shaped.receipt !== null) {
      receipt = validateFindingsSyncReceiptV1(shaped.receipt);
      assertFindingsSyncReceiptMatchesV1(receipt, prepared);
    }
    return deepFreeze({ ...shaped, retry: { ...shaped.retry }, receipt });
  } catch (error) {
    return asQueueError(error, "storage_corrupt");
  }
}


function immutableEqual(left: StoredFindingsSyncV1, right: StoredFindingsSyncV1): boolean {
  return left.workspace_ref === right.workspace_ref
    && left.project_ref === right.project_ref
    && left.request_digest === right.request_digest
    && left.request_json === right.request_json
    && left.approved_at === right.approved_at
    && left.expires_at === right.expires_at;
}


function sameRequestBytes(left: StoredFindingsSyncV1, right: StoredFindingsSyncV1): boolean {
  return left.workspace_ref === right.workspace_ref
    && left.project_ref === right.project_ref
    && left.request_digest === right.request_digest
    && left.request_json === right.request_json;
}


function keyOf(value: Pick<StoredFindingsSyncV1, "workspace_ref" | "project_ref" | "request_digest">): string[] {
  return [value.workspace_ref, value.project_ref, value.request_digest];
}


function validKey(workspaceRef: string, projectRef: string, requestDigest: string): boolean {
  return WORKSPACE_REF.test(workspaceRef) && PROJECT_REF.test(projectRef) && SHA256.test(requestDigest);
}


function validateApproval(
  prepared: PreparedFindingsSyncV1,
  approval: FindingsSyncApprovalV1,
  now: number,
): void {
  if (!isRecord(approval) || !exactFields(approval, [
    "workspaceRef",
    "projectRef",
    "requestDigest",
    "approvedAt",
    "expiresAt",
  ])) queueError("invalid_input");
  const approvedAt = timestamp(approval.approvedAt);
  const expiresAt = timestamp(approval.expiresAt);
  if (
    typeof approval.workspaceRef !== "string"
    || !WORKSPACE_REF.test(approval.workspaceRef)
    || approval.projectRef !== prepared.request.project_ref
    || approval.requestDigest !== prepared.requestDigest
    || approvedAt > now
    || expiresAt < now
    || expiresAt - approvedAt > MAX_APPROVAL_MS
  ) queueError("invalid_input");
}


function collectCursor(request: IDBRequest<IDBCursorWithValue | null>): Promise<unknown[]> {
  return new Promise((resolve, reject) => {
    const values: unknown[] = [];
    request.onerror = () => reject(request.error ?? new Error("findings retry cursor failed"));
    request.onsuccess = () => {
      const cursor = request.result;
      if (cursor === null) {
        resolve(values);
        return;
      }
      values.push(cursor.value);
      cursor.continue();
    };
  });
}


export class FindingsSyncQueue {
  readonly #factory: IDBFactory | undefined;
  readonly #keyRange: typeof IDBKeyRange | undefined;
  readonly #leaseMs: number;
  readonly #now: () => number;
  readonly #token: () => string;

  constructor(options: FindingsSyncQueueOptions = {}) {
    this.#factory = options.indexedDB ?? globalThis.indexedDB;
    this.#keyRange = options.keyRange ?? globalThis.IDBKeyRange;
    this.#leaseMs = options.leaseMs ?? DEFAULT_LEASE_MS;
    this.#now = options.now ?? Date.now;
    this.#token = options.token ?? (() => `fsl_${crypto.randomUUID().replaceAll("-", "")}`);
    if (
      !Number.isSafeInteger(this.#leaseMs)
      || this.#leaseMs <= 0
      || this.#leaseMs > MAX_LEASE_MS
      || typeof this.#now !== "function"
      || typeof this.#token !== "function"
    ) queueError("invalid_input");
  }

  async enqueue(
    prepared: PreparedFindingsSyncV1,
    approval: FindingsSyncApprovalV1,
  ): Promise<StoredFindingsSyncV1> {
    const now = timestamp(this.#now());
    try {
      await assertPreparedFindingsSyncBindingV1(prepared);
      validateApproval(prepared, approval, now);
    } catch (error) {
      return asQueueError(error, "invalid_input");
    }
    const stored: StoredFindingsSyncV1 = {
      schema_version: FINDINGS_SYNC_QUEUE_SCHEMA_VERSION,
      workspace_ref: approval.workspaceRef,
      project_ref: prepared.request.project_ref,
      request_digest: prepared.requestDigest,
      request_json: prepared.requestJson,
      approved_at: approval.approvedAt,
      expires_at: approval.expiresAt,
      retry: {
        attempts: 0,
        next_attempt_at: now,
        last_error_code: null,
        lease_token: null,
        lease_expires_at: null,
      },
      receipt: null,
    };
    const database = await this.#open();
    let result: StoredFindingsSyncV1 = stored;
    try {
      const transaction = database.transaction(FINDINGS_SYNC_QUEUE_STORE, "readwrite");
      const store = transaction.objectStore(FINDINGS_SYNC_QUEUE_STORE);
      const existingValue = await requestResult(store.get(keyOf(stored)));
      if (existingValue === undefined) store.add(stored);
      else {
        let existing: StoredFindingsSyncV1;
        try {
          existing = parseStoredShape(existingValue);
        } catch {
          return queueError("storage_corrupt");
        }
        if (immutableEqual(existing, stored)) result = existing;
        else if (
          sameRequestBytes(existing, stored)
          && existing.receipt === null
          && (existing.expires_at < now || existing.retry.last_error_code === "approval_expired")
          && (existing.retry.lease_token === null || existing.retry.lease_expires_at! <= now)
        ) {
          store.put(stored);
          result = stored;
        } else queueError("immutable_conflict");
      }
      await transactionComplete(transaction);
    } catch (error) {
      return asQueueError(error, "storage_unavailable");
    } finally {
      database.close();
    }
    return parseStored(result);
  }

  async get(
    workspaceRef: string,
    projectRef: string,
    requestDigest: string,
  ): Promise<StoredFindingsSyncV1 | null> {
    if (!validKey(workspaceRef, projectRef, requestDigest)) return null;
    const database = await this.#open();
    let value: unknown;
    try {
      const transaction = database.transaction(FINDINGS_SYNC_QUEUE_STORE, "readonly");
      value = await requestResult(transaction.objectStore(FINDINGS_SYNC_QUEUE_STORE).get([
        workspaceRef, projectRef, requestDigest,
      ]));
      await transactionComplete(transaction);
    } catch (error) {
      return asQueueError(error, "storage_unavailable");
    } finally {
      database.close();
    }
    if (value === undefined) return null;
    try {
      return await parseStored(value);
    } catch {
      return null;
    }
  }

  async list(workspaceRef: string): Promise<StoredFindingsSyncV1[]> {
    if (!WORKSPACE_REF.test(workspaceRef)) queueError("invalid_input");
    const database = await this.#open();
    let values: unknown[];
    try {
      const transaction = database.transaction(FINDINGS_SYNC_QUEUE_STORE, "readonly");
      values = await collectCursor(transaction
        .objectStore(FINDINGS_SYNC_QUEUE_STORE)
        .index(WORKSPACE_INDEX)
        .openCursor(workspaceRef));
      await transactionComplete(transaction);
    } catch (error) {
      return asQueueError(error, "storage_unavailable");
    } finally {
      database.close();
    }
    const result: StoredFindingsSyncV1[] = [];
    for (const value of values) {
      try {
        const parsed = await parseStored(value);
        if (parsed.workspace_ref === workspaceRef) result.push(parsed);
      } catch {
        // A malformed injected record never reaches a product surface.
      }
    }
    return result;
  }

  async claimNext(workspaceRef: string): Promise<FindingsSyncLeaseV1 | null> {
    if (!WORKSPACE_REF.test(workspaceRef)) queueError("invalid_input");
    const now = timestamp(this.#now());
    if (this.#keyRange === undefined) queueError("storage_unavailable");
    const range = this.#keyRange.bound([workspaceRef, 0], [workspaceRef, now]);
    const database = await this.#open();
    let values: unknown[];
    try {
      const transaction = database.transaction(FINDINGS_SYNC_QUEUE_STORE, "readonly");
      values = await collectCursor(transaction
        .objectStore(FINDINGS_SYNC_QUEUE_STORE)
        .index(WORKSPACE_NEXT_ATTEMPT_INDEX)
        .openCursor(range));
      await transactionComplete(transaction);
    } catch (error) {
      return asQueueError(error, "storage_unavailable");
    } finally {
      database.close();
    }
    for (const value of values) {
      let candidate: StoredFindingsSyncV1;
      try {
        candidate = await parseStored(value);
      } catch {
        continue;
      }
      if (
        candidate.workspace_ref !== workspaceRef
        || !this.#isClaimable(candidate, now)
      ) continue;
      const claimed = await this.#tryClaim(candidate, now);
      if (claimed !== null) return claimed;
    }
    return null;
  }

  async claim(
    workspaceRef: string,
    projectRef: string,
    requestDigest: string,
  ): Promise<FindingsSyncLeaseV1 | null> {
    if (!validKey(workspaceRef, projectRef, requestDigest)) queueError("invalid_input");
    const now = timestamp(this.#now());
    const candidate = await this.get(workspaceRef, projectRef, requestDigest);
    if (candidate === null || !this.#isClaimable(candidate, now)) return null;
    return this.#tryClaim(candidate, now);
  }

  async renew(lease: FindingsSyncLeaseV1): Promise<FindingsSyncLeaseV1 | null> {
    if (!this.#validLease(lease)) queueError("invalid_input");
    const now = timestamp(this.#now());
    const leaseToken = this.#newToken();
    const leaseExpiresAt = now + this.#leaseMs;
    if (!Number.isSafeInteger(leaseExpiresAt)) queueError("invalid_input");
    const database = await this.#open();
    let updated: StoredFindingsSyncV1 | null = null;
    try {
      const transaction = database.transaction(FINDINGS_SYNC_QUEUE_STORE, "readwrite");
      const store = transaction.objectStore(FINDINGS_SYNC_QUEUE_STORE);
      const currentValue = await requestResult(store.get(keyOf(lease.record)));
      if (currentValue !== undefined) {
        let current: StoredFindingsSyncV1 | null;
        try {
          current = parseStoredShape(currentValue);
        } catch {
          current = null;
        }
        if (
          current !== null
          && immutableEqual(current, lease.record)
          && current.receipt === null
          && current.retry.lease_token === lease.leaseToken
          && current.retry.lease_expires_at === lease.leaseExpiresAt
          && current.retry.lease_expires_at > now
        ) {
          updated = {
            ...current,
            retry: {
              ...current.retry,
              lease_token: leaseToken,
              lease_expires_at: leaseExpiresAt,
            },
          };
          store.put(updated);
        }
      }
      await transactionComplete(transaction);
    } catch (error) {
      return asQueueError(error, "storage_unavailable");
    } finally {
      database.close();
    }
    if (updated === null) return null;
    const record = await parseStored(updated);
    return deepFreeze({ leaseToken, leaseExpiresAt, record });
  }

  async scheduleRetry(
    lease: FindingsSyncLeaseV1,
    nextAttemptAtValue: number,
    errorCode: FindingsSyncRetryErrorCode,
  ): Promise<boolean> {
    const now = timestamp(this.#now());
    const nextAttemptAt = timestamp(nextAttemptAtValue);
    if (
      nextAttemptAt < now
      || !RETRY_ERROR_CODES.has(errorCode)
      || !this.#validLease(lease)
    ) queueError("invalid_input");
    return this.#updateLease(lease, now, (current) => ({
      ...current,
      retry: {
        ...current.retry,
        next_attempt_at: nextAttemptAt,
        last_error_code: errorCode,
        lease_token: null,
        lease_expires_at: null,
      },
    }));
  }

  async complete(lease: FindingsSyncLeaseV1, receiptValue: unknown): Promise<boolean> {
    if (!this.#validLease(lease)) queueError("invalid_input");
    let receipt: FindingsSyncReceiptV1;
    try {
      receipt = validateFindingsSyncReceiptV1(receiptValue);
      assertFindingsSyncReceiptMatchesV1(receipt, preparedFromStored(lease.record));
    } catch (error) {
      return asQueueError(error, "invalid_input");
    }
    const now = timestamp(this.#now());
    return this.#updateLease(lease, now, (current) => ({
      ...current,
      retry: {
        ...current.retry,
        next_attempt_at: null,
        last_error_code: null,
        lease_token: null,
        lease_expires_at: null,
      },
      receipt,
    }));
  }

  async delete(workspaceRef: string, projectRef: string, requestDigest: string): Promise<boolean> {
    if (!validKey(workspaceRef, projectRef, requestDigest)) return false;
    const database = await this.#open();
    let existed = false;
    try {
      const transaction = database.transaction(FINDINGS_SYNC_QUEUE_STORE, "readwrite");
      const store = transaction.objectStore(FINDINGS_SYNC_QUEUE_STORE);
      existed = await requestResult(store.get([workspaceRef, projectRef, requestDigest])) !== undefined;
      if (existed) store.delete([workspaceRef, projectRef, requestDigest]);
      await transactionComplete(transaction);
      return existed;
    } catch (error) {
      return asQueueError(error, "storage_unavailable");
    } finally {
      database.close();
    }
  }

  async #open(): Promise<IDBDatabase> {
    if (this.#factory === undefined) queueError("storage_unavailable");
    try {
      return await openDatabase(this.#factory);
    } catch (error) {
      return asQueueError(error, "storage_unavailable");
    }
  }

  async #tryClaim(
    candidate: StoredFindingsSyncV1,
    now: number,
  ): Promise<FindingsSyncLeaseV1 | null> {
    const token = this.#newToken();
    const leaseExpiresAt = now + this.#leaseMs;
    if (!Number.isSafeInteger(leaseExpiresAt)) queueError("invalid_input");
    const database = await this.#open();
    let updated: StoredFindingsSyncV1 | null = null;
    try {
      const transaction = database.transaction(FINDINGS_SYNC_QUEUE_STORE, "readwrite");
      const store = transaction.objectStore(FINDINGS_SYNC_QUEUE_STORE);
      const currentValue = await requestResult(store.get(keyOf(candidate)));
      if (currentValue !== undefined) {
        let current: StoredFindingsSyncV1 | null;
        try {
          current = parseStoredShape(currentValue);
        } catch {
          current = null;
        }
        if (
          current !== null
          && immutableEqual(current, candidate)
          && this.#isClaimable(current, now)
          && current.retry.attempts < Number.MAX_SAFE_INTEGER
        ) {
          updated = {
            ...current,
            retry: {
              ...current.retry,
              attempts: current.retry.attempts + 1,
              lease_token: token,
              lease_expires_at: leaseExpiresAt,
            },
          };
          store.put(updated);
        }
      }
      await transactionComplete(transaction);
    } catch (error) {
      return asQueueError(error, "storage_unavailable");
    } finally {
      database.close();
    }
    if (updated === null) return null;
    const record = await parseStored(updated);
    return deepFreeze({ leaseToken: token, leaseExpiresAt, record });
  }

  #isClaimable(record: StoredFindingsSyncV1, now: number): boolean {
    return record.receipt === null
      && record.expires_at >= now
      && record.retry.next_attempt_at !== null
      && record.retry.next_attempt_at <= now
      && (record.retry.lease_token === null || record.retry.lease_expires_at! <= now);
  }

  #newToken(): string {
    const token = this.#token();
    if (typeof token !== "string" || !LEASE_TOKEN.test(token)) queueError("invalid_input");
    return token;
  }

  async #updateLease(
    lease: FindingsSyncLeaseV1,
    now: number,
    update: (current: StoredFindingsSyncV1) => StoredFindingsSyncV1,
  ): Promise<boolean> {
    const database = await this.#open();
    let changed = false;
    try {
      const transaction = database.transaction(FINDINGS_SYNC_QUEUE_STORE, "readwrite");
      const store = transaction.objectStore(FINDINGS_SYNC_QUEUE_STORE);
      const currentValue = await requestResult(store.get(keyOf(lease.record)));
      if (currentValue !== undefined) {
        let current: StoredFindingsSyncV1 | null;
        try {
          current = parseStoredShape(currentValue);
        } catch {
          current = null;
        }
        if (
          current !== null
          && immutableEqual(current, lease.record)
          && current.receipt === null
          && current.retry.lease_token === lease.leaseToken
          && current.retry.lease_expires_at === lease.leaseExpiresAt
          && current.retry.lease_expires_at > now
        ) {
          store.put(update(current));
          changed = true;
        }
      }
      await transactionComplete(transaction);
      return changed;
    } catch (error) {
      return asQueueError(error, "storage_unavailable");
    } finally {
      database.close();
    }
  }

  #validLease(value: FindingsSyncLeaseV1): boolean {
    return isRecord(value)
      && exactFields(value, ["leaseToken", "leaseExpiresAt", "record"])
      && typeof value.leaseToken === "string"
      && LEASE_TOKEN.test(value.leaseToken)
      && Number.isSafeInteger(value.leaseExpiresAt)
      && value.leaseExpiresAt >= 0
      && isRecord(value.record)
      && validKey(
        value.record.workspace_ref as string,
        value.record.project_ref as string,
        value.record.request_digest as string,
      );
  }
}
