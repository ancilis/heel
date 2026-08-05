// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import { createHash } from "node:crypto";
import { afterEach, describe, expect, test, vi } from "vitest";

import sampleEnvelope from "../../../tests/fixtures/reviews/sample_review_v1.json";
import {
  BrowserReviewClient,
  BrowserReviewClientError,
  MAX_BROWSER_ANSWERS_BYTES,
  MAX_BROWSER_INPUT_BYTES,
  MAX_BROWSER_RESULT_BYTES,
  WORKER_PROTOCOL_VERSION,
  type ReviewWorkerLike,
} from "../lib/browser-review-client";
import { parseReviewEnvelopeV1 } from "../lib/review-v1";


function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}


function browserEnvelope(): Record<string, unknown> {
  const body = structuredClone(sampleEnvelope) as unknown as Record<string, unknown>;
  delete body.review_id;
  delete body.result_hash;
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


class FakeWorker implements ReviewWorkerLike {
  onmessage: ((event: MessageEvent<string>) => void) | null = null;
  onerror: ((event: ErrorEvent) => void) | null = null;
  readonly sent: string[] = [];
  terminated = false;
  throwOnPost = false;

  postMessage(message: string): void {
    if (this.throwOnPost) throw new Error("sensitive postMessage failure");
    expect(typeof message).toBe("string");
    this.sent.push(message);
  }

  terminate(): void {
    this.terminated = true;
  }

  emit(message: unknown): void {
    this.onmessage?.({ data: message } as MessageEvent<string>);
  }

  crash(): void {
    this.onerror?.(new ErrorEvent("error", { message: "sensitive traceback" }));
  }
}


function ready(worker: FakeWorker): void {
  worker.emit(JSON.stringify({
    type: "ready",
    protocol_version: WORKER_PROTOCOL_VERSION,
  }));
}


function result(worker: FakeWorker, requestId: string, envelope = browserEnvelope()): void {
  worker.emit(JSON.stringify({
    type: "result",
    protocol_version: WORKER_PROTOCOL_VERSION,
    request_id: requestId,
    result_json: JSON.stringify(envelope),
  }));
}


async function failureOf(promise: Promise<unknown>): Promise<BrowserReviewClientError> {
  try {
    await promise;
  } catch (error) {
    return error as BrowserReviewClientError;
  }
  throw new Error("expected browser review to fail");
}


afterEach(() => {
  vi.useRealTimers();
});


describe("BrowserReviewClient", () => {
  test("rejects readiness after worker construction fails", async () => {
    const client = new BrowserReviewClient({
      workerFactory: () => { throw new Error("sensitive worker construction failure"); },
    });
    expect(client.status).toBe("failed");
    await expect(client.whenReady()).rejects.toMatchObject({ code: "engine_unavailable" });
  });

  test("boots immediately and uses string-only request/result messages", async () => {
    const workers: FakeWorker[] = [];
    const client = new BrowserReviewClient({
      workerFactory: () => {
        const worker = new FakeWorker();
        workers.push(worker);
        return worker;
      },
    });
    expect(client.status).toBe("loading_engine");
    expect(workers).toHaveLength(1);

    ready(workers[0]);
    await client.whenReady();
    expect(client.status).toBe("ready");

    const source = '{"openapi":"3.1.0"}';
    const pending = client.review(source);
    expect(client.status).toBe("reviewing");
    const request = JSON.parse(workers[0].sent.at(-1)!);
    expect(request).toEqual({
      type: "review",
      protocol_version: WORKER_PROTOCOL_VERSION,
      request_id: expect.stringMatching(/^request_[0-9]+$/),
      source,
      answers_json: "[]",
    });
    result(workers[0], request.request_id);

    const completed = await pending;
    expect(completed.envelope).toEqual(parseReviewEnvelopeV1(browserEnvelope()));
    expect(completed.receipt).toBeNull();
    expect(client.status).toBe("complete");
  });

  test("rejects concurrent reviews and ignores stale request identifiers", async () => {
    const worker = new FakeWorker();
    const client = new BrowserReviewClient({ workerFactory: () => worker });
    ready(worker);
    await client.whenReady();

    const first = client.review("first");
    await expect(client.review("second")).rejects.toMatchObject({ code: "review_in_progress" });
    const request = JSON.parse(worker.sent.at(-1)!);

    let settled = false;
    first.finally(() => { settled = true; });
    result(worker, "request_999999");
    await Promise.resolve();
    expect(settled).toBe(false);

    result(worker, request.request_id);
    await expect(first).resolves.toBeDefined();
  });

  test("preflights UTF-8 input and bounded answer payloads before worker messaging", async () => {
    const worker = new FakeWorker();
    const client = new BrowserReviewClient({ workerFactory: () => worker });
    ready(worker);
    await client.whenReady();

    await expect(client.review("a".repeat(MAX_BROWSER_INPUT_BYTES + 1))).rejects.toMatchObject({
      code: "input_too_large",
    });
    await expect(client.review("{}", [{
      surface: "x".repeat(MAX_BROWSER_ANSWERS_BYTES),
      field: "tenant_filter",
      value: "unknown",
    }])).rejects.toMatchObject({ code: "answers_too_large" });
    expect(worker.sent).toHaveLength(0);
  });

  test("cancel terminates and recreates the worker while preserving caller input", async () => {
    const workers: FakeWorker[] = [];
    const client = new BrowserReviewClient({ workerFactory: () => {
      const worker = new FakeWorker();
      workers.push(worker);
      return worker;
    } });
    ready(workers[0]);
    await client.whenReady();
    const source = "private-openapi";
    const pending = client.review(source);

    client.cancel();
    await expect(pending).rejects.toMatchObject({ code: "review_cancelled" });
    expect(workers[0].terminated).toBe(true);
    expect(workers).toHaveLength(2);
    expect(client.status).toBe("loading_engine");
    expect(client.retainedInput?.source).toBe(source);
  });

  test("times out, restarts, and recovers from worker crashes without traceback leakage", async () => {
    vi.useFakeTimers();
    const workers: FakeWorker[] = [];
    const client = new BrowserReviewClient({
      timeoutMs: 100,
      workerFactory: () => {
        const worker = new FakeWorker();
        workers.push(worker);
        return worker;
      },
    });
    ready(workers[0]);
    await client.whenReady();
    const timedOut = client.review("timeout-source");
    const timeoutAssertion = expect(timedOut).rejects.toMatchObject({ code: "review_timeout" });
    await vi.advanceTimersByTimeAsync(101);
    await timeoutAssertion;
    expect(workers[0].terminated).toBe(true);

    ready(workers[1]);
    await client.whenReady();
    const crashed = client.review("crash-source");
    workers[1].crash();
    const failure = await failureOf(crashed);
    expect(failure.code).toBe("engine_failed");
    expect(failure.message).not.toContain("traceback");
    expect(workers[1].terminated).toBe(true);
    expect(workers).toHaveLength(3);
  });

  test("redacts worker errors and rejects oversized or malformed returned JSON", async () => {
    const workers: FakeWorker[] = [];
    const client = new BrowserReviewClient({ workerFactory: () => {
      const worker = new FakeWorker();
      workers.push(worker);
      return worker;
    } });
    ready(workers[0]);
    await client.whenReady();
    const failed = client.review("secret-source");
    const request = JSON.parse(workers[0].sent.at(-1)!);
    workers[0].emit(JSON.stringify({
      type: "error",
      protocol_version: WORKER_PROTOCOL_VERSION,
      request_id: request.request_id,
      code: "invalid_json",
      message: "secret-source traceback",
    }));
    const failure = await failureOf(failed);
    expect(failure.code).toBe("invalid_json");
    expect(failure.message).not.toContain("secret-source");
    expect(failure.message).not.toContain("traceback");

    ready(workers[1]);
    await client.whenReady();
    const oversized = client.review("retained-large-result-source");
    workers[1].emit("x".repeat(MAX_BROWSER_RESULT_BYTES * 2 + 70_000));
    await expect(oversized).rejects.toMatchObject({ code: "result_too_large" });
    expect(client.retainedInput?.source).toBe("retained-large-result-source");
  });

  test("reruns against the retained pre-envelope and derives the receipt in the main thread", async () => {
    const worker = new FakeWorker();
    const client = new BrowserReviewClient({ workerFactory: () => worker });
    ready(worker);
    await client.whenReady();
    const before = parseReviewEnvelopeV1(browserEnvelope());
    const answer = {
      surface: "downloadbulkexport",
      field: "rate_limit",
      value: "unknown",
    } as const;

    const pending = client.rerun("same-source", before, [answer]);
    const request = JSON.parse(worker.sent.at(-1)!);
    expect(JSON.parse(request.answers_json)).toEqual([answer]);
    result(worker, request.request_id, before as unknown as Record<string, unknown>);
    const completed = await pending;
    expect(completed.receipt).toMatchObject({
      confidence: "preliminary",
      items: [{ ...answer, receipt: "unanswered" }],
    });
  });

  test("redacts synchronous postMessage failures and restarts cleanly", async () => {
    const workers: FakeWorker[] = [];
    const client = new BrowserReviewClient({ workerFactory: () => {
      const worker = new FakeWorker();
      workers.push(worker);
      return worker;
    } });
    ready(workers[0]);
    await client.whenReady();
    workers[0].throwOnPost = true;

    const failure = await failureOf(client.review("retained-post-source"));
    expect(failure.code).toBe("engine_failed");
    expect(failure.message).not.toContain("sensitive");
    expect(workers[0].terminated).toBe(true);
    expect(workers).toHaveLength(2);
    expect(client.retainedInput?.source).toBe("retained-post-source");
  });
});
