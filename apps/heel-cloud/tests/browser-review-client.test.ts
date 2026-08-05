// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import { createHash } from "node:crypto";
import { afterEach, describe, expect, test, vi } from "vitest";

import sampleEnvelope from "../../../tests/fixtures/reviews/sample_review_v1.json";
import canonicalEnforcedRerun from "./canonical-enforced-rerun.fixture.json";
import legacyEnvelope from "./legacy-review-1.1.0.fixture.json";
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


function browserEnvelope(productId?: string): Record<string, unknown> {
  const body = structuredClone(sampleEnvelope) as unknown as Record<string, unknown>;
  delete body.review_id;
  delete body.result_hash;
  body.execution_mode = "browser_local";
  if (productId !== undefined) body.product_id = productId;
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


function withoutQuestion(
  envelope: Record<string, unknown>,
  surface: string,
  field: string,
): Record<string, unknown> {
  const body = structuredClone(envelope);
  delete body.review_id;
  delete body.result_hash;
  body.questions = (body.questions as Array<Record<string, unknown>>).filter(
    (question) => question.surface !== surface || question.field !== field,
  );
  body.summary = {
    ...(body.summary as Record<string, unknown>),
    questions: (body.questions as unknown[]).length,
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

  test("automatically retries one never-ready boot and reviews after the replacement is ready", async () => {
    vi.useFakeTimers();
    const workers: FakeWorker[] = [];
    const client = new BrowserReviewClient({
      bootTimeoutMs: 50,
      workerFactory: () => {
        const worker = new FakeWorker();
        workers.push(worker);
        return worker;
      },
    });
    let readinessFailure: BrowserReviewClientError | null = null;
    void client.whenReady().catch((error: BrowserReviewClientError) => { readinessFailure = error; });
    const queued = client.review("queued-private-source");
    let queuedFailure: BrowserReviewClientError | null = null;
    void queued.catch((error: BrowserReviewClientError) => { queuedFailure = error; });

    expect(client.retainedInput?.source).toBe("queued-private-source");
    let secondFailure: BrowserReviewClientError | null = null;
    void client.review("second-source").catch((error: BrowserReviewClientError) => { secondFailure = error; });
    await Promise.resolve();
    expect(secondFailure).toMatchObject({ code: "review_in_progress" });
    expect(workers[0].sent).toEqual([]);
    expect(vi.getTimerCount()).toBe(1);
    await vi.advanceTimersByTimeAsync(51);
    expect(queuedFailure).toMatchObject({ code: "engine_unavailable" });
    expect(readinessFailure).toMatchObject({ code: "engine_unavailable" });

    expect(workers[0].terminated).toBe(true);
    expect(workers).toHaveLength(2);
    expect(client.status).toBe("loading_engine");
    expect(vi.getTimerCount()).toBe(1);

    ready(workers[1]);
    await client.whenReady();
    expect(vi.getTimerCount()).toBe(0);
    const retried = client.review("replacement-source");
    const request = JSON.parse(workers[1].sent.at(-1)!);
    result(workers[1], request.request_id);
    await expect(retried).resolves.toBeDefined();
  });

  test("exhausts a finite boot retry without a worker or timer loop and explicit restart resets it", async () => {
    vi.useFakeTimers();
    const workers: FakeWorker[] = [];
    const client = new BrowserReviewClient({
      bootTimeoutMs: 25,
      workerFactory: () => {
        const worker = new FakeWorker();
        workers.push(worker);
        return worker;
      },
    });
    let firstReadinessFailure: BrowserReviewClientError | null = null;
    void client.whenReady().catch((error: BrowserReviewClientError) => { firstReadinessFailure = error; });
    await vi.advanceTimersByTimeAsync(26);
    expect(firstReadinessFailure).toMatchObject({ code: "engine_unavailable" });
    expect(workers).toHaveLength(2);
    expect(workers[0].terminated).toBe(true);
    expect(client.status).toBe("loading_engine");
    expect(vi.getTimerCount()).toBe(1);

    let secondReadinessFailure: BrowserReviewClientError | null = null;
    void client.whenReady().catch((error: BrowserReviewClientError) => { secondReadinessFailure = error; });
    await vi.advanceTimersByTimeAsync(26);
    expect(secondReadinessFailure).toMatchObject({ code: "engine_unavailable" });
    expect(workers).toHaveLength(2);
    expect(workers[1].terminated).toBe(true);
    expect(client.status).toBe("failed");
    expect(vi.getTimerCount()).toBe(0);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(workers).toHaveLength(2);
    expect(vi.getTimerCount()).toBe(0);

    client.restart();
    expect(workers).toHaveLength(3);
    expect(client.status).toBe("loading_engine");
    await vi.advanceTimersByTimeAsync(26);
    expect(workers).toHaveLength(4);
    expect(workers[2].terminated).toBe(true);
    ready(workers[3]);
    await client.whenReady();
    expect(client.status).toBe("ready");
    expect(vi.getTimerCount()).toBe(0);
  });

  test("cancels a queued pre-ready review and immediately boots a usable replacement", async () => {
    vi.useFakeTimers();
    const workers: FakeWorker[] = [];
    const client = new BrowserReviewClient({
      bootTimeoutMs: 100,
      workerFactory: () => {
        const worker = new FakeWorker();
        workers.push(worker);
        return worker;
      },
    });
    let readinessFailure: BrowserReviewClientError | null = null;
    void client.whenReady().catch((error: BrowserReviewClientError) => { readinessFailure = error; });
    const queued = client.review("cancel-before-ready");
    let cancelled: BrowserReviewClientError | null = null;
    void queued.catch((error: BrowserReviewClientError) => { cancelled = error; });
    client.cancel();
    await Promise.resolve();

    expect(cancelled).toMatchObject({ code: "review_cancelled" });
    expect(readinessFailure).toMatchObject({ code: "engine_unavailable" });
    expect(workers[0].terminated).toBe(true);
    expect(workers).toHaveLength(2);
    expect(client.status).toBe("loading_engine");
    expect(client.retainedInput?.source).toBe("cancel-before-ready");
    expect(vi.getTimerCount()).toBe(1);

    ready(workers[1]);
    await client.whenReady();
    expect(vi.getTimerCount()).toBe(0);
    const recovered = client.review("after-cancel");
    const request = JSON.parse(workers[1].sent.at(-1)!);
    result(workers[1], request.request_id);
    await expect(recovered).resolves.toBeDefined();
  });

  test("terminal worker failure rejects an active review and clears every timer", async () => {
    vi.useFakeTimers();
    const worker = new FakeWorker();
    const client = new BrowserReviewClient({ workerFactory: () => worker });
    ready(worker);
    await client.whenReady();

    const pending = client.review("fatal-after-ready");
    worker.emit(JSON.stringify({
      type: "fatal",
      protocol_version: WORKER_PROTOCOL_VERSION,
      code: "engine_unavailable",
      message: "redacted",
    }));

    await expect(pending).rejects.toMatchObject({ code: "engine_unavailable" });
    expect(worker.terminated).toBe(true);
    expect(client.status).toBe("failed");
    expect(vi.getTimerCount()).toBe(0);
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

  test("listener exceptions never interrupt readiness, queued work, or other listeners", async () => {
    const worker = new FakeWorker();
    const client = new BrowserReviewClient({ workerFactory: () => worker });
    const statuses: string[] = [];
    client.subscribe(() => { throw new Error("listener failure"); });
    client.subscribe((status) => { statuses.push(status); });
    const pending = client.review("listener-safe-source");

    expect(() => ready(worker)).not.toThrow();
    const request = JSON.parse(worker.sent.at(-1)!);
    result(worker, request.request_id);
    await expect(pending).resolves.toBeDefined();
    expect(statuses).toEqual(["ready", "reviewing", "complete"]);
    await expect(client.whenReady()).resolves.toBeUndefined();
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

  test("rejects a valid persisted 1.1.0 envelope when returned by the live worker", async () => {
    const worker = new FakeWorker();
    const client = new BrowserReviewClient({ workerFactory: () => worker });
    ready(worker);
    await client.whenReady();

    const pending = client.review("legacy-live-worker-source");
    const request = JSON.parse(worker.sent.at(-1)!);
    result(worker, request.request_id, legacyEnvelope);

    await expect(pending).rejects.toMatchObject({ code: "worker_protocol" });
  });

  test.each(["toString", "constructor", "__proto__"])(
    "rejects inherited public error name %s in constructors and worker messages",
    async (inheritedCode) => {
      const direct = new BrowserReviewClientError(inheritedCode);
      expect(direct.code).toBe("review_failed");
      expect(typeof direct.publicMessage).toBe("string");

      const worker = new FakeWorker();
      const client = new BrowserReviewClient({ workerFactory: () => worker });
      ready(worker);
      await client.whenReady();
      const pending = client.review(`prototype-${inheritedCode}`);
      const request = JSON.parse(worker.sent.at(-1)!);
      worker.emit(JSON.stringify({
        type: "error",
        protocol_version: WORKER_PROTOCOL_VERSION,
        request_id: request.request_id,
        code: inheritedCode,
        message: "redacted",
      }));
      await expect(pending).rejects.toMatchObject({
        code: "review_failed",
        publicMessage: expect.any(String),
      });
    },
  );

  test("rejects answers on an initial review before worker messaging", async () => {
    const worker = new FakeWorker();
    const client = new BrowserReviewClient({ workerFactory: () => worker });
    ready(worker);
    await client.whenReady();

    await expect(client.review("source", [{
      surface: "downloadbulkexport",
      field: "rate_limit",
      value: "unknown",
    }])).rejects.toMatchObject({ code: "invalid_answers" });
    expect(worker.sent).toEqual([]);
  });

  test("binds cumulative reruns to the last successful initial source and envelope", async () => {
    const worker = new FakeWorker();
    const client = new BrowserReviewClient({ workerFactory: () => worker });
    ready(worker);
    await client.whenReady();
    const before = parseReviewEnvelopeV1(browserEnvelope());
    const firstAnswer = {
      surface: "downloadbulkexport",
      field: "tenant_filter",
      value: "enforced",
    } as const;
    const secondAnswer = {
      surface: "downloadbulkexport",
      field: "rate_limit",
      value: "unknown",
    } as const;

    await expect(client.rerun("same-source", before, [firstAnswer])).rejects.toMatchObject({
      code: "invalid_answers",
    });

    const initial = client.review("same-source");
    const initialRequest = JSON.parse(worker.sent.at(-1)!);
    result(worker, initialRequest.request_id, before as unknown as Record<string, unknown>);
    const initialResult = await initial;
    expect(initialResult).toMatchObject({ receipt: null });
    (initialResult.envelope as unknown as Record<string, unknown>).review_id = "review_00000000000000000000";

    const sentAfterInitial = worker.sent.length;
    await expect(client.rerun("different-source", before, [firstAnswer])).rejects.toMatchObject({
      code: "invalid_answers",
    });
    const differentBefore = parseReviewEnvelopeV1(browserEnvelope("different-product"));
    await expect(client.rerun("same-source", differentBefore, [firstAnswer])).rejects.toMatchObject({
      code: "invalid_answers",
    });
    expect(worker.sent).toHaveLength(sentAfterInitial);

    const afterFirst = withoutQuestion(
      before as unknown as Record<string, unknown>,
      firstAnswer.surface,
      firstAnswer.field,
    );
    const first = client.rerun("same-source", before, [firstAnswer]);
    const firstRequest = JSON.parse(worker.sent.at(-1)!);
    result(worker, firstRequest.request_id, afterFirst);
    await expect(first).resolves.toMatchObject({
      receipt: { items: [{ ...firstAnswer, receipt: "applied" }] },
    });

    const cumulativeAnswers = [firstAnswer, secondAnswer];
    const second = client.rerun("same-source", before, cumulativeAnswers);
    const secondRequest = JSON.parse(worker.sent.at(-1)!);
    expect(JSON.parse(secondRequest.answers_json)).toEqual(cumulativeAnswers);
    result(worker, secondRequest.request_id, afterFirst);
    await expect(second).resolves.toMatchObject({
      receipt: {
        confidence: "preliminary",
        items: [
          { ...secondAnswer, receipt: "unanswered" },
          { ...firstAnswer, receipt: "applied" },
        ],
      },
    });
  });

  test("rejects a rerun result whose product identity differs from its baseline", async () => {
    const worker = new FakeWorker();
    const client = new BrowserReviewClient({ workerFactory: () => worker });
    ready(worker);
    await client.whenReady();
    const before = parseReviewEnvelopeV1(browserEnvelope());
    const answer = {
      surface: "downloadbulkexport",
      field: "tenant_filter",
      value: "enforced",
    } as const;

    const initial = client.review("identity-bound-source");
    const initialRequest = JSON.parse(worker.sent.at(-1)!);
    result(worker, initialRequest.request_id, before as unknown as Record<string, unknown>);
    await initial;

    const rerun = client.rerun("identity-bound-source", before, [answer]);
    const rerunRequest = JSON.parse(worker.sent.at(-1)!);
    const unrelatedAfter = withoutQuestion(browserEnvelope("unrelated-product"), answer.surface, answer.field);
    result(worker, rerunRequest.request_id, unrelatedAfter);
    await expect(rerun).rejects.toMatchObject({ code: "worker_protocol" });
  });

  test("accepts canonical enforced-answer output when enrichment changes the source hash", async () => {
    const adapter = canonicalEnforcedRerun as {
      source: string;
      answer: { surface: string; field: "tenant_filter"; value: "enforced" };
      before: Record<string, unknown>;
      after: Record<string, unknown>;
    };
    expect(adapter.after.source_hash).not.toBe(adapter.before.source_hash);
    const worker = new FakeWorker();
    const client = new BrowserReviewClient({ workerFactory: () => worker });
    ready(worker);
    await client.whenReady();

    const initial = client.review(adapter.source);
    const initialRequest = JSON.parse(worker.sent.at(-1)!);
    result(worker, initialRequest.request_id, adapter.before);
    await initial;

    const rerun = client.rerun(
      adapter.source,
      parseReviewEnvelopeV1(adapter.before),
      [adapter.answer],
    );
    const rerunRequest = JSON.parse(worker.sent.at(-1)!);
    result(worker, rerunRequest.request_id, adapter.after);
    await expect(rerun).resolves.toMatchObject({
      receipt: {
        items: [{ ...adapter.answer, receipt: "applied" }],
      },
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
