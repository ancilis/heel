// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import { createHash } from "node:crypto";
import { IDBFactory } from "fake-indexeddb";
import { describe, expect, test } from "vitest";

import sampleEnvelope from "../../../tests/fixtures/reviews/sample_review_v1.json";
import legacyEnvelope from "./legacy-review-1.1.0.fixture.json";
import {
  LOCAL_REVIEW_DATABASE,
  LOCAL_REVIEW_STORE,
  LocalReviewStore,
  MAX_LOCAL_REVIEWS,
} from "../lib/local-reviews";
import { reviewToJson, reviewToMarkdown } from "../lib/review-export";


function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}


function envelope(productId = "sample-saas"): Record<string, unknown> {
  const body = structuredClone(sampleEnvelope) as unknown as Record<string, unknown>;
  delete body.review_id;
  delete body.result_hash;
  body.product_id = productId;
  body.execution_mode = "browser_local";
  body.privacy = {
    execution: "browser_local",
    network_calls: false,
    uploaded: false,
    sync_intent: "none",
  };
  const resultHash = createHash("sha256").update(canonicalJson(body), "utf8").digest("hex");
  return {
    review_id: `review_${resultHash.slice(0, 20)}`,
    result_hash: resultHash,
    ...body,
  };
}


function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("IndexedDB request failed"));
  });
}


async function rawStoredValue(factory: IDBFactory, reviewId: string): Promise<unknown> {
  const database = await requestResult(factory.open(LOCAL_REVIEW_DATABASE));
  try {
    return await requestResult(
      database.transaction(LOCAL_REVIEW_STORE, "readonly").objectStore(LOCAL_REVIEW_STORE).get(reviewId),
    );
  } finally {
    database.close();
  }
}


function transactionComplete(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error ?? new Error("IndexedDB transaction failed"));
    transaction.onabort = () => reject(transaction.error ?? new Error("IndexedDB transaction aborted"));
  });
}


async function injectStoredValue(factory: IDBFactory, value: unknown): Promise<void> {
  await injectStoredValues(factory, [value]);
}


async function injectStoredValues(factory: IDBFactory, values: readonly unknown[]): Promise<void> {
  const database = await requestResult(factory.open(LOCAL_REVIEW_DATABASE));
  try {
    const transaction = database.transaction(LOCAL_REVIEW_STORE, "readwrite");
    const store = transaction.objectStore(LOCAL_REVIEW_STORE);
    for (const value of values) store.put(value);
    await transactionComplete(transaction);
  } finally {
    database.close();
  }
}


async function rawRecordCount(factory: IDBFactory): Promise<number> {
  const database = await requestResult(factory.open(LOCAL_REVIEW_DATABASE));
  try {
    return await requestResult(
      database.transaction(LOCAL_REVIEW_STORE, "readonly").objectStore(LOCAL_REVIEW_STORE).count(),
    );
  } finally {
    database.close();
  }
}


function storedEnvelope(productId: string, savedAt: number): Record<string, unknown> {
  return {
    schema_version: "heel.local-review.v1",
    envelope: envelope(productId),
    saved_at: savedAt,
    sync_state: "local_only",
  };
}


describe("LocalReviewStore", () => {
  test("retains genuine 1.1.0 history through get, list, save, and trimming", async () => {
    const factory = new IDBFactory();
    const store = new LocalReviewStore({ indexedDB: factory, maxItems: 2, now: () => 30 });
    await expect(store.list()).resolves.toEqual([]);
    await injectStoredValue(factory, {
      schema_version: "heel.local-review.v1",
      envelope: legacyEnvelope,
      saved_at: 10,
      sync_state: "local_only",
    });

    const loaded = await store.get(legacyEnvelope.review_id);
    expect(loaded).toMatchObject({
      envelope: { engine_version: "1.1.0", review_id: legacyEnvelope.review_id },
    });
    expect(JSON.parse(reviewToJson(loaded?.envelope)).engine_version).toBe("1.1.0");
    expect(reviewToMarkdown(loaded?.envelope)).toContain("legacy\\-1\\-1\\-0");
    await expect(store.list()).resolves.toMatchObject([
      { envelope: { engine_version: "1.1.0", review_id: legacyEnvelope.review_id } },
    ]);

    const current = envelope("current-after-upgrade");
    await expect(store.save(current)).resolves.toBe(true);
    await expect(store.list()).resolves.toMatchObject([
      { envelope: { engine_version: "1.1.1", review_id: current.review_id } },
      { envelope: { engine_version: "1.1.0", review_id: legacyEnvelope.review_id } },
    ]);
  });

  test("persists only a validated local-only envelope wrapper", async () => {
    const factory = new IDBFactory();
    const store = new LocalReviewStore({ indexedDB: factory, now: () => 1_700_000_000_000 });
    const review = envelope();

    await expect(store.save(review)).resolves.toBe(true);
    await expect(store.get(review.review_id as string)).resolves.toEqual({
      schema_version: "heel.local-review.v1",
      envelope: review,
      saved_at: 1_700_000_000_000,
      sync_state: "local_only",
    });
    await expect(store.list()).resolves.toHaveLength(1);

    const raw = await rawStoredValue(factory, review.review_id as string) as Record<string, unknown>;
    expect(Object.keys(raw).sort()).toEqual([
      "envelope",
      "saved_at",
      "schema_version",
      "sync_state",
    ]);
    expect(raw).not.toHaveProperty("source");
    expect(raw).not.toHaveProperty("answers");
  });

  test("bounds history and removes the oldest completed results", async () => {
    const factory = new IDBFactory();
    let time = 0;
    const store = new LocalReviewStore({
      indexedDB: factory,
      maxItems: 3,
      now: () => ++time,
    });

    for (let index = 0; index < 5; index += 1) {
      await expect(store.save(envelope(`product-${index}`))).resolves.toBe(true);
    }
    const records = await store.list();
    expect(records).toHaveLength(3);
    expect(records.map((record) => record.envelope.product_id)).toEqual([
      "product-4",
      "product-3",
      "product-2",
    ]);
    expect(MAX_LOCAL_REVIEWS).toBeGreaterThanOrEqual(3);
  });

  test("trims with a bounded cursor without materializing every key", async () => {
    const factory = new IDBFactory();
    let time = 0;
    const store = new LocalReviewStore({
      indexedDB: factory,
      maxItems: 2,
      now: () => ++time,
    });
    await expect(store.save(envelope("seed"))).resolves.toBe(true);

    const database = await requestResult(factory.open(LOCAL_REVIEW_DATABASE));
    const index = database
      .transaction(LOCAL_REVIEW_STORE, "readonly")
      .objectStore(LOCAL_REVIEW_STORE)
      .index("saved-at");
    const prototype = Object.getPrototypeOf(index) as {
      getAllKeys: IDBIndex["getAllKeys"];
      openCursor: IDBIndex["openCursor"];
    };
    database.close();
    const originalGetAllKeys = prototype.getAllKeys;
    const originalOpenCursor = prototype.openCursor;
    let cursorCalls = 0;
    prototype.getAllKeys = () => { throw new Error("unbounded getAllKeys is forbidden"); };
    prototype.openCursor = function (...args: Parameters<IDBIndex["openCursor"]>) {
      cursorCalls += 1;
      return originalOpenCursor.apply(this as unknown as IDBIndex, args);
    };
    try {
      await expect(store.save(envelope("second"))).resolves.toBe(true);
      await expect(store.save(envelope("third"))).resolves.toBe(true);
      expect(cursorCalls).toBeGreaterThan(0);
      await expect(store.list()).resolves.toHaveLength(2);
    } finally {
      prototype.getAllKeys = originalGetAllKeys;
      prototype.openCursor = originalOpenCursor;
    }
  });

  test("purges key-valid rows missing saved_at before enforcing the total bound", async () => {
    const factory = new IDBFactory();
    const store = new LocalReviewStore({ indexedDB: factory, maxItems: 2, now: () => 100 });
    await expect(store.list()).resolves.toEqual([]);
    await injectStoredValues(factory, Array.from({ length: 5 }, (_, index) => ({
      schema_version: "heel.local-review.v1",
      envelope: { review_id: `review_${index.toString(16).padStart(20, "0")}` },
      sync_state: "local_only",
    })));

    const saved = envelope("retained-after-unindexed-poison");
    await expect(store.save(saved)).resolves.toBe(true);
    await expect(rawRecordCount(factory)).resolves.toBeLessThanOrEqual(2);
    await expect(store.list()).resolves.toMatchObject([
      { envelope: { review_id: saved.review_id } },
    ]);
  });

  test("purges malformed indexed rows instead of counting them as retained history", async () => {
    const factory = new IDBFactory();
    const store = new LocalReviewStore({ indexedDB: factory, maxItems: 2, now: () => 100 });
    await expect(store.list()).resolves.toEqual([]);
    await injectStoredValues(factory, Array.from({ length: 3 }, (_, index) => ({
      schema_version: "heel.local-review.v1",
      envelope: { review_id: `review_${(index + 10).toString(16).padStart(20, "0")}` },
      saved_at: index,
      sync_state: "local_only",
    })));

    const saved = envelope("retained-after-indexed-poison");
    await expect(store.save(saved)).resolves.toBe(true);
    await expect(rawRecordCount(factory)).resolves.toBe(1);
    await expect(store.list()).resolves.toMatchObject([
      { envelope: { review_id: saved.review_id } },
    ]);
  });

  test("trims a large valid preexisting set oldest-first with constant-memory cursors", async () => {
    const factory = new IDBFactory();
    const store = new LocalReviewStore({ indexedDB: factory, maxItems: 3, now: () => 10_000 });
    await expect(store.list()).resolves.toEqual([]);
    await injectStoredValues(factory, Array.from(
      { length: 75 },
      (_, index) => storedEnvelope(`bulk-${index}`, index + 1),
    ));

    await expect(store.save(envelope("latest"))).resolves.toBe(true);
    await expect(rawRecordCount(factory)).resolves.toBe(3);
    const records = await store.list();
    expect(records.map((record) => record.envelope.product_id)).toEqual([
      "latest",
      "bulk-74",
      "bulk-73",
    ]);
  });

  test("supports delete and clear without adding a cloud sync state", async () => {
    const store = new LocalReviewStore({ indexedDB: new IDBFactory() });
    const first = envelope("first");
    const second = envelope("second");
    await store.save(first);
    await store.save(second);

    await expect(store.delete(first.review_id as string)).resolves.toBe(true);
    await expect(store.get(first.review_id as string)).resolves.toBeNull();
    await expect(store.clear()).resolves.toBe(true);
    await expect(store.list()).resolves.toEqual([]);
  });

  test("fails invalid untrusted envelopes closed before opening storage", async () => {
    const review = envelope();
    review.product_id = "tampered";
    const factory = {
      open: () => { throw new Error("storage should not open"); },
    } as unknown as IDBFactory;
    const store = new LocalReviewStore({ indexedDB: factory });
    await expect(store.save(review)).rejects.toThrow(/result hash/i);
  });

  test("treats storage unavailability as nonfatal to an in-memory review", async () => {
    const factory = {
      open: () => { throw new Error("storage unavailable"); },
    } as unknown as IDBFactory;
    const store = new LocalReviewStore({ indexedDB: factory });

    await expect(store.save(envelope())).resolves.toBe(false);
    await expect(store.list()).resolves.toEqual([]);
    await expect(store.get(`review_${"0".repeat(20)}`)).resolves.toBeNull();
    await expect(store.delete(`review_${"0".repeat(20)}`)).resolves.toBe(false);
    await expect(store.clear()).resolves.toBe(false);
  });

  test("rejects an oversized valid injected envelope before local hash validation", async () => {
    const targetBytes = 4_207_478;
    const seed = envelope("x");
    const seedBytes = new TextEncoder().encode(JSON.stringify(seed)).byteLength;
    const oversized = envelope("x".repeat(1 + targetBytes - seedBytes));
    expect(new TextEncoder().encode(JSON.stringify(oversized)).byteLength).toBe(targetBytes);

    const factory = new IDBFactory();
    const store = new LocalReviewStore({ indexedDB: factory });
    const retained = envelope("retained");
    await expect(store.save(retained)).resolves.toBe(true);
    await injectStoredValue(factory, {
      schema_version: "heel.local-review.v1",
      envelope: oversized,
      saved_at: 1_800_000_000_000,
      sync_state: "local_only",
    });

    await expect(store.get(oversized.review_id as string)).resolves.toBeNull();
    const records = await store.list();
    expect(records.map((record) => record.envelope.review_id)).toEqual([
      retained.review_id,
    ]);
  });

  test("uses a bounded default count even if callers request an invalid limit", () => {
    expect(() => new LocalReviewStore({ indexedDB: new IDBFactory(), maxItems: 0 })).toThrow();
    expect(() => new LocalReviewStore({ indexedDB: new IDBFactory(), maxItems: MAX_LOCAL_REVIEWS + 1 })).toThrow();
  });
});
