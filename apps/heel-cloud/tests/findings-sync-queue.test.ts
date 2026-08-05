// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { IDBFactory, IDBKeyRange } from "fake-indexeddb";
import { describe, expect, test } from "vitest";

import type { PreparedFindingsSyncV1 } from "../lib/findings-sync-client";
import type { FindingsSyncReceiptV1, FindingsSyncRequestV1 } from "../lib/findings-sync-v1";
import {
  FINDINGS_SYNC_QUEUE_DATABASE,
  FINDINGS_SYNC_QUEUE_STORE,
  FindingsSyncQueue,
} from "../lib/findings-sync-queue";


const WORKSPACE_REF = "ws_0123456789abcdef";
const NOW = 1_786_000_000_000;
const REQUEST_ONE_TEXT = readFileSync(
  resolve(process.cwd(), "../../tests/fixtures/findings_sync/request-one-finding.json"),
  "utf8",
).trim();
const REQUEST_PASS_TEXT = readFileSync(
  resolve(process.cwd(), "../../tests/fixtures/findings_sync/request-pass.json"),
  "utf8",
).trim();
const RECEIPT = JSON.parse(readFileSync(
  resolve(process.cwd(), "../../tests/fixtures/findings_sync/receipt-created.json"),
  "utf8",
)) as FindingsSyncReceiptV1;


function prepared(requestJson = REQUEST_ONE_TEXT): PreparedFindingsSyncV1 {
  const request = JSON.parse(requestJson) as FindingsSyncRequestV1;
  const requestDigest = createHash("sha256").update(requestJson, "utf8").digest("hex");
  return {
    request,
    requestJson,
    requestDigest,
    idempotencyKey: `fs1-${requestDigest}`,
  };
}


function approval(item = prepared(), overrides: Record<string, unknown> = {}) {
  return {
    workspaceRef: WORKSPACE_REF,
    projectRef: item.request.project_ref,
    requestDigest: item.requestDigest,
    approvedAt: NOW - 1_000,
    expiresAt: NOW + 60_000,
    ...overrides,
  };
}


function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolvePromise, reject) => {
    request.onsuccess = () => resolvePromise(request.result);
    request.onerror = () => reject(request.error ?? new Error("IndexedDB request failed"));
  });
}


function transactionComplete(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolvePromise, reject) => {
    transaction.oncomplete = () => resolvePromise();
    transaction.onerror = () => reject(transaction.error ?? new Error("IndexedDB transaction failed"));
    transaction.onabort = () => reject(transaction.error ?? new Error("IndexedDB transaction aborted"));
  });
}


async function rawRecord(
  factory: IDBFactory,
  item: PreparedFindingsSyncV1,
): Promise<Record<string, unknown> | undefined> {
  const database = await requestResult(factory.open(FINDINGS_SYNC_QUEUE_DATABASE));
  try {
    return await requestResult(database
      .transaction(FINDINGS_SYNC_QUEUE_STORE, "readonly")
      .objectStore(FINDINGS_SYNC_QUEUE_STORE)
      .get([WORKSPACE_REF, item.request.project_ref, item.requestDigest]));
  } finally {
    database.close();
  }
}


async function injectRecord(factory: IDBFactory, value: unknown): Promise<void> {
  return injectRecords(factory, [value]);
}


async function injectRecords(factory: IDBFactory, values: readonly unknown[]): Promise<void> {
  const database = await requestResult(factory.open(FINDINGS_SYNC_QUEUE_DATABASE));
  try {
    const transaction = database.transaction(FINDINGS_SYNC_QUEUE_STORE, "readwrite");
    const store = transaction.objectStore(FINDINGS_SYNC_QUEUE_STORE);
    for (const value of values) store.put(value);
    await transactionComplete(transaction);
  } finally {
    database.close();
  }
}


describe("FindingsSyncQueue", () => {
  test("persists only the exact approved canonical projection and closed retry state", async () => {
    const factory = new IDBFactory();
    const item = prepared();
    const queue = new FindingsSyncQueue({ indexedDB: factory, now: () => NOW });

    const stored = await queue.enqueue(item, approval(item));
    expect(stored).toMatchObject({
      schema_version: "heel.findings-sync-queue.v1",
      workspace_ref: WORKSPACE_REF,
      project_ref: item.request.project_ref,
      request_digest: item.requestDigest,
      request_json: item.requestJson,
      approved_at: NOW - 1_000,
      expires_at: NOW + 60_000,
      retry: {
        attempts: 0,
        next_attempt_at: NOW,
        last_error_code: null,
        lease_token: null,
        lease_expires_at: null,
      },
      receipt: null,
    });
    expect(Object.isFrozen(stored)).toBe(true);
    expect(Object.isFrozen(stored.retry)).toBe(true);

    const raw = await rawRecord(factory, item);
    expect(Object.keys(raw!).sort()).toEqual([
      "approved_at",
      "expires_at",
      "project_ref",
      "receipt",
      "request_digest",
      "request_json",
      "retry",
      "schema_version",
      "workspace_ref",
    ]);
    expect(Object.keys(raw!.retry as object).sort()).toEqual([
      "attempts",
      "last_error_code",
      "lease_expires_at",
      "lease_token",
      "next_attempt_at",
    ]);
    const rendered = JSON.stringify(raw);
    for (const forbidden of [
      "raw-customer-openapi",
      "raw_review",
      "questions",
      "answers",
      "reason",
      "arbitrary_metadata",
    ]) expect(rendered).not.toContain(forbidden);

    await expect(queue.enqueue(
      { ...item, raw_review: "raw-customer-openapi" } as unknown as PreparedFindingsSyncV1,
      approval(item),
    )).rejects.toMatchObject({ code: "invalid_input" });
    await expect(queue.enqueue(
      item,
      approval(item, { arbitrary_metadata: "raw-customer-openapi" }),
    )).rejects.toMatchObject({ code: "invalid_input" });
  });

  test("keeps request bytes immutable and permits fresh human approval after expiry", async () => {
    const factory = new IDBFactory();
    let now = NOW;
    const queue = new FindingsSyncQueue({ indexedDB: factory, now: () => now });
    const first = prepared();
    const second = prepared(REQUEST_PASS_TEXT);
    const firstApproval = approval(first);

    const original = await queue.enqueue(first, firstApproval);
    await expect(queue.enqueue(first, firstApproval)).resolves.toEqual(original);
    await expect(queue.enqueue(first, approval(first, {
      approvedAt: NOW,
      expiresAt: NOW + 120_000,
    }))).rejects.toMatchObject({ code: "immutable_conflict" });
    await expect(queue.enqueue(second, firstApproval)).rejects.toMatchObject({ code: "invalid_input" });

    now = NOW + 60_001;
    const refreshed = await queue.enqueue(first, approval(first, {
      approvedAt: now,
      expiresAt: now + 60_000,
    }));
    expect(refreshed).toMatchObject({
      request_json: first.requestJson,
      request_digest: first.requestDigest,
      approved_at: now,
      expires_at: now + 60_000,
      retry: { attempts: 0, next_attempt_at: now },
    });

    const distinct = await queue.enqueue(second, approval(second, {
      approvedAt: now,
      expiresAt: now + 60_000,
    }));
    expect(distinct.request_digest).not.toBe(refreshed.request_digest);
    await expect(queue.list(WORKSPACE_REF)).resolves.toEqual([refreshed, distinct]);
    expect((await rawRecord(factory, first))?.approved_at).toBe(now);
  });

  test("claims one due item transactionally and prevents stale or duplicate transmitters", async () => {
    const factory = new IDBFactory();
    let now = NOW;
    const firstQueue = new FindingsSyncQueue({
      indexedDB: factory,
      keyRange: IDBKeyRange,
      leaseMs: 100,
      now: () => now,
      token: () => `fsl_${"1".repeat(32)}`,
    });
    const secondQueue = new FindingsSyncQueue({
      indexedDB: factory,
      keyRange: IDBKeyRange,
      leaseMs: 100,
      now: () => now,
      token: () => `fsl_${"2".repeat(32)}`,
    });
    const item = prepared();
    await firstQueue.enqueue(item, approval(item));

    const claims = await Promise.all([
      firstQueue.claimNext(WORKSPACE_REF),
      secondQueue.claimNext(WORKSPACE_REF),
    ]);
    const active = claims.find((claim) => claim !== null)!;
    expect(claims.filter((claim) => claim !== null)).toHaveLength(1);
    expect(active.record.retry.attempts).toBe(1);
    await expect(firstQueue.claimNext(WORKSPACE_REF)).resolves.toBeNull();

    now += 101;
    const reclaimed = await secondQueue.claimNext(WORKSPACE_REF);
    expect(reclaimed).not.toBeNull();
    expect(reclaimed!.leaseToken).not.toBe(active.leaseToken);
    expect(reclaimed!.record.retry.attempts).toBe(2);
    await expect(firstQueue.scheduleRetry(
      active,
      now + 500,
      "transport_error",
    )).resolves.toBe(false);
    await expect(secondQueue.scheduleRetry(
      reclaimed!,
      now + 500,
      "transport_error",
    )).resolves.toBe(true);
    await expect(firstQueue.claimNext(WORKSPACE_REF)).resolves.toBeNull();

    now += 500;
    const retry = await firstQueue.claimNext(WORKSPACE_REF);
    expect(retry?.record.retry).toMatchObject({
      attempts: 3,
      last_error_code: "transport_error",
    });
  });

  test("renews and fences an in-flight lease before its old expiry can be reclaimed", async () => {
    const factory = new IDBFactory();
    let now = NOW;
    let tokenNumber = 4;
    const firstQueue = new FindingsSyncQueue({
      indexedDB: factory,
      keyRange: IDBKeyRange,
      leaseMs: 100,
      now: () => now,
      token: () => `fsl_${String(tokenNumber++).repeat(32)}`,
    });
    const secondQueue = new FindingsSyncQueue({
      indexedDB: factory,
      keyRange: IDBKeyRange,
      leaseMs: 100,
      now: () => now,
      token: () => `fsl_${"8".repeat(32)}`,
    });
    const item = prepared();
    await firstQueue.enqueue(item, approval(item));
    const original = await firstQueue.claim(
      WORKSPACE_REF,
      item.request.project_ref,
      item.requestDigest,
    );
    expect(original).not.toBeNull();

    now += 80;
    const renewed = await firstQueue.renew(original!);
    expect(renewed).toMatchObject({
      leaseToken: `fsl_${"5".repeat(32)}`,
      leaseExpiresAt: NOW + 180,
    });
    now += 21;
    await expect(secondQueue.claim(
      WORKSPACE_REF,
      item.request.project_ref,
      item.requestDigest,
    )).resolves.toBeNull();
    await expect(firstQueue.complete(original!, RECEIPT)).resolves.toBe(false);
    await expect(firstQueue.complete(renewed!, RECEIPT)).resolves.toBe(true);
  });

  test("scopes list and due scans so other-workspace poison cannot starve a retry", async () => {
    const factory = new IDBFactory();
    const queue = new FindingsSyncQueue({
      indexedDB: factory,
      keyRange: IDBKeyRange,
      now: () => NOW,
      token: () => `fsl_${"9".repeat(32)}`,
    });
    const item = prepared();
    const target = await queue.enqueue(item, approval(item));
    const poison = Array.from({ length: 1_025 }, (_, index) => {
      const suffix = index.toString(16).padStart(32, "0");
      return {
        ...target,
        workspace_ref: "ws_0000000000000000",
        project_ref: `prj_${suffix}`,
        request_digest: suffix.repeat(2),
        retry: { ...target.retry, next_attempt_at: NOW - 1_000 },
        raw_review: "must-never-surface",
      };
    });
    await injectRecords(factory, poison);

    await expect(queue.list(WORKSPACE_REF)).resolves.toEqual([target]);
    await expect(queue.claimNext(WORKSPACE_REF)).resolves.toMatchObject({
      record: { request_digest: item.requestDigest },
    });
  });

  test("claims the exact newly approved request without selecting an older workspace retry", async () => {
    const factory = new IDBFactory();
    const queue = new FindingsSyncQueue({
      indexedDB: factory,
      keyRange: IDBKeyRange,
      now: () => NOW,
      token: () => `fsl_${"4".repeat(32)}`,
    });
    const older = prepared();
    const justApproved = prepared(REQUEST_PASS_TEXT);
    await queue.enqueue(older, approval(older));
    await queue.enqueue(justApproved, approval(justApproved));

    const exact = await queue.claim(
      WORKSPACE_REF,
      justApproved.request.project_ref,
      justApproved.requestDigest,
    );

    expect(exact?.record.request_digest).toBe(justApproved.requestDigest);
    expect(exact?.record.request_json).toBe(justApproved.requestJson);
    expect(exact?.record.retry.attempts).toBe(1);
    await expect(queue.claim(
      WORKSPACE_REF,
      justApproved.request.project_ref,
      justApproved.requestDigest,
    )).resolves.toBeNull();
    await expect(queue.claimNext(WORKSPACE_REF)).resolves.toMatchObject({
      record: { request_digest: older.requestDigest },
    });
  });

  test("binds a validated receipt to the active lease and survives logout until explicit deletion", async () => {
    const factory = new IDBFactory();
    const item = prepared();
    const queue = new FindingsSyncQueue({
      indexedDB: factory,
      keyRange: IDBKeyRange,
      now: () => NOW,
      token: () => `fsl_${"3".repeat(32)}`,
    });
    await queue.enqueue(item, approval(item));
    const claim = await queue.claimNext(WORKSPACE_REF);
    expect(claim).not.toBeNull();

    await expect(queue.complete(claim!, RECEIPT)).resolves.toBe(true);
    await expect(queue.claimNext(WORKSPACE_REF)).resolves.toBeNull();
    await expect(queue.get(
      WORKSPACE_REF,
      item.request.project_ref,
      item.requestDigest,
    )).resolves.toMatchObject({ receipt: RECEIPT });

    const afterLogout = new FindingsSyncQueue({ indexedDB: factory, now: () => NOW + 10_000 });
    await expect(afterLogout.list(WORKSPACE_REF)).resolves.toHaveLength(1);
    expect(afterLogout).not.toHaveProperty("clear");

    const malformedReceipt = { ...RECEIPT, raw_review: "never-store" };
    await expect(afterLogout.complete(claim!, malformedReceipt)).rejects.toMatchObject({
      code: "invalid_input",
    });
    await expect(afterLogout.delete(
      WORKSPACE_REF,
      item.request.project_ref,
      item.requestDigest,
    )).resolves.toBe(true);
    await expect(afterLogout.list(WORKSPACE_REF)).resolves.toEqual([]);
  });

  test("never surfaces or overwrites an injected record with extra fields", async () => {
    const factory = new IDBFactory();
    const item = prepared();
    const queue = new FindingsSyncQueue({
      indexedDB: factory,
      keyRange: IDBKeyRange,
      now: () => NOW,
    });
    await queue.enqueue(item, approval(item));
    const raw = await rawRecord(factory, item);
    await injectRecord(factory, { ...raw, raw_review: "raw-review-poison" });

    await expect(queue.get(
      WORKSPACE_REF,
      item.request.project_ref,
      item.requestDigest,
    )).resolves.toBeNull();
    await expect(queue.list(WORKSPACE_REF)).resolves.toEqual([]);
    await expect(queue.claimNext(WORKSPACE_REF)).resolves.toBeNull();
    await expect(queue.enqueue(item, approval(item))).rejects.toMatchObject({
      code: "storage_corrupt",
    });
    expect(JSON.stringify(await rawRecord(factory, item))).toContain("raw-review-poison");
  });
});
