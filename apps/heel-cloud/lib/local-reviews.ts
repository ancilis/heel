// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import { MAX_BROWSER_RESULT_BYTES } from "./browser-review-client";
import { parseReviewEnvelopeV1, type ReviewEnvelopeV1 } from "./review-v1";


export const LOCAL_REVIEW_DATABASE = "heel-browser-reviews-v1";
export const LOCAL_REVIEW_STORE = "completed-reviews-v1";
export const MAX_LOCAL_REVIEWS = 50;
const DATABASE_VERSION = 1;
const SAVED_AT_INDEX = "saved-at";
const MAX_LOCAL_SCAN_RECORDS = MAX_LOCAL_REVIEWS * 4;

export interface StoredLocalReviewV1 {
  schema_version: "heel.local-review.v1";
  envelope: ReviewEnvelopeV1;
  saved_at: number;
  sync_state: "local_only";
}

interface LocalReviewStoreOptions {
  indexedDB?: IDBFactory;
  maxItems?: number;
  now?: () => number;
}


function requestResult<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("browser storage request failed"));
  });
}


function transactionComplete(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onabort = () => reject(transaction.error ?? new Error("browser storage transaction aborted"));
    transaction.onerror = () => reject(transaction.error ?? new Error("browser storage transaction failed"));
  });
}


function openDatabase(factory: IDBFactory): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    let request: IDBOpenDBRequest;
    try {
      request = factory.open(LOCAL_REVIEW_DATABASE, DATABASE_VERSION);
    } catch (error) {
      reject(error);
      return;
    }
    request.onupgradeneeded = () => {
      const database = request.result;
      if (!database.objectStoreNames.contains(LOCAL_REVIEW_STORE)) {
        const store = database.createObjectStore(LOCAL_REVIEW_STORE, {
          keyPath: "envelope.review_id",
        });
        store.createIndex(SAVED_AT_INDEX, "saved_at", { unique: false });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error("browser storage could not open"));
    request.onblocked = () => reject(new Error("browser storage upgrade is blocked"));
  });
}


function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}


function isBoundedJson(value: unknown): boolean {
  try {
    const encoded = JSON.stringify(value);
    return typeof encoded === "string"
      && new TextEncoder().encode(encoded).byteLength <= MAX_BROWSER_RESULT_BYTES;
  } catch {
    return false;
  }
}


function parseStoredReview(value: unknown): StoredLocalReviewV1 {
  if (!isBoundedJson(value)) throw new Error("stored review exceeds the local size limit");
  if (!isRecord(value)) throw new Error("stored review must be an object");
  const actual = Object.keys(value).sort();
  const expected = ["schema_version", "envelope", "saved_at", "sync_state"].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error("stored review has unexpected fields");
  }
  if (value.schema_version !== "heel.local-review.v1" || value.sync_state !== "local_only") {
    throw new Error("stored review has an unsupported local schema");
  }
  if (!Number.isSafeInteger(value.saved_at) || (value.saved_at as number) < 0) {
    throw new Error("stored review has an invalid saved_at value");
  }
  if (!isBoundedJson(value.envelope)) throw new Error("stored envelope exceeds the local size limit");
  return {
    schema_version: "heel.local-review.v1",
    envelope: parseReviewEnvelopeV1(value.envelope),
    saved_at: value.saved_at as number,
    sync_state: "local_only",
  };
}


export class LocalReviewStore {
  readonly #factory: IDBFactory | undefined;
  readonly #maxItems: number;
  readonly #now: () => number;

  constructor(options: LocalReviewStoreOptions = {}) {
    this.#factory = options.indexedDB ?? globalThis.indexedDB;
    this.#maxItems = options.maxItems ?? MAX_LOCAL_REVIEWS;
    this.#now = options.now ?? Date.now;
    if (!Number.isSafeInteger(this.#maxItems) || this.#maxItems <= 0 || this.#maxItems > MAX_LOCAL_REVIEWS) {
      throw new Error(`maxItems must be between 1 and ${MAX_LOCAL_REVIEWS}`);
    }
  }

  async save(value: unknown): Promise<boolean> {
    const envelope = parseReviewEnvelopeV1(value);
    if (!isBoundedJson(envelope)) {
      throw new Error("review result exceeds the local storage size limit");
    }
    const savedAt = this.#now();
    if (!Number.isSafeInteger(savedAt) || savedAt < 0) throw new Error("saved_at must be a nonnegative safe integer");
    const stored: StoredLocalReviewV1 = {
      schema_version: "heel.local-review.v1",
      envelope,
      saved_at: savedAt,
      sync_state: "local_only",
    };
    if (!isBoundedJson(stored)) throw new Error("review wrapper exceeds the local storage size limit");
    const database = await this.#openOrNull();
    if (database === null) return false;
    try {
      const transaction = database.transaction(LOCAL_REVIEW_STORE, "readwrite");
      transaction.objectStore(LOCAL_REVIEW_STORE).put(stored);
      await transactionComplete(transaction);
      await this.#trim(database);
      return true;
    } catch {
      return false;
    } finally {
      database.close();
    }
  }

  async list(): Promise<StoredLocalReviewV1[]> {
    const database = await this.#openOrNull();
    if (database === null) return [];
    try {
      const transaction = database.transaction(LOCAL_REVIEW_STORE, "readonly");
      const valid = await this.#readBounded(transaction);
      await transactionComplete(transaction);
      return valid;
    } catch {
      return [];
    } finally {
      database.close();
    }
  }

  async get(reviewId: string): Promise<StoredLocalReviewV1 | null> {
    if (!/^review_[0-9a-f]{20}$/.test(reviewId)) return null;
    const database = await this.#openOrNull();
    if (database === null) return null;
    try {
      const transaction = database.transaction(LOCAL_REVIEW_STORE, "readonly");
      const value = await requestResult(transaction.objectStore(LOCAL_REVIEW_STORE).get(reviewId));
      await transactionComplete(transaction);
      return value === undefined ? null : parseStoredReview(value);
    } catch {
      return null;
    } finally {
      database.close();
    }
  }

  async delete(reviewId: string): Promise<boolean> {
    if (!/^review_[0-9a-f]{20}$/.test(reviewId)) return false;
    return this.#write((store) => store.delete(reviewId));
  }

  async clear(): Promise<boolean> {
    return this.#write((store) => store.clear());
  }

  async #openOrNull(): Promise<IDBDatabase | null> {
    if (this.#factory === undefined) return null;
    try {
      return await openDatabase(this.#factory);
    } catch {
      return null;
    }
  }

  async #write(operation: (store: IDBObjectStore) => void): Promise<boolean> {
    const database = await this.#openOrNull();
    if (database === null) return false;
    try {
      const transaction = database.transaction(LOCAL_REVIEW_STORE, "readwrite");
      operation(transaction.objectStore(LOCAL_REVIEW_STORE));
      await transactionComplete(transaction);
      return true;
    } catch {
      return false;
    } finally {
      database.close();
    }
  }

  async #trim(database: IDBDatabase): Promise<void> {
    const transaction = database.transaction(LOCAL_REVIEW_STORE, "readwrite");
    const store = transaction.objectStore(LOCAL_REVIEW_STORE);
    const validCount = await this.#purgeMalformedAndCount(store);
    const excess = Math.max(0, validCount - this.#maxItems);
    if (excess > 0) await this.#deleteOldest(store.index(SAVED_AT_INDEX), excess);
    await transactionComplete(transaction);
  }

  #purgeMalformedAndCount(store: IDBObjectStore): Promise<number> {
    return new Promise((resolve, reject) => {
      let validCount = 0;
      const request = store.openCursor(null, "next");
      request.onerror = () => reject(request.error ?? new Error("browser storage cursor failed"));
      request.onsuccess = () => {
        const cursor = request.result;
        if (cursor === null) {
          resolve(validCount);
          return;
        }
        try {
          parseStoredReview(cursor.value);
          validCount += 1;
        } catch {
          const deletion = cursor.delete();
          deletion.onerror = () => reject(deletion.error ?? new Error("browser storage deletion failed"));
        }
        cursor.continue();
      };
    });
  }

  #deleteOldest(index: IDBIndex, count: number): Promise<void> {
    return new Promise((resolve, reject) => {
      let deleted = 0;
      const request = index.openCursor(null, "next");
      request.onerror = () => reject(request.error ?? new Error("browser storage cursor failed"));
      request.onsuccess = () => {
        const cursor = request.result;
        if (cursor === null || deleted >= count) {
          resolve();
          return;
        }
        cursor.delete();
        deleted += 1;
        cursor.continue();
      };
    });
  }

  #readBounded(transaction: IDBTransaction): Promise<StoredLocalReviewV1[]> {
    return new Promise((resolve, reject) => {
      const valid: StoredLocalReviewV1[] = [];
      let visited = 0;
      const request = transaction
        .objectStore(LOCAL_REVIEW_STORE)
        .index(SAVED_AT_INDEX)
        .openCursor(null, "prev");
      request.onerror = () => reject(request.error ?? new Error("browser storage cursor failed"));
      request.onsuccess = () => {
        const cursor = request.result;
        if (cursor === null || valid.length >= this.#maxItems || visited >= MAX_LOCAL_SCAN_RECORDS) {
          resolve(valid);
          return;
        }
        visited += 1;
        try {
          valid.push(parseStoredReview(cursor.value));
        } catch {
          // A malformed or oversized local record never reaches the product surface.
        }
        cursor.continue();
      };
    });
  }
}


const defaultStore = new LocalReviewStore();

export const saveLocalReview = (value: unknown) => defaultStore.save(value);
export const listLocalReviews = () => defaultStore.list();
export const getLocalReview = (reviewId: string) => defaultStore.get(reviewId);
export const deleteLocalReview = (reviewId: string) => defaultStore.delete(reviewId);
export const clearLocalReviews = () => defaultStore.clear();
