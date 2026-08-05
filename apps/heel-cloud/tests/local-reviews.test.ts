// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import { createHash } from "node:crypto";
import { IDBFactory } from "fake-indexeddb";
import { describe, expect, test } from "vitest";

import sampleEnvelope from "../../../tests/fixtures/reviews/sample_review_v1.json";
import {
  LOCAL_REVIEW_DATABASE,
  LOCAL_REVIEW_STORE,
  LocalReviewStore,
  MAX_LOCAL_REVIEWS,
} from "../lib/local-reviews";


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


describe("LocalReviewStore", () => {
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

  test("uses a bounded default count even if callers request an invalid limit", () => {
    expect(() => new LocalReviewStore({ indexedDB: new IDBFactory(), maxItems: 0 })).toThrow();
    expect(() => new LocalReviewStore({ indexedDB: new IDBFactory(), maxItems: MAX_LOCAL_REVIEWS + 1 })).toThrow();
  });
});
