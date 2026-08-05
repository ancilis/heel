// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import { createHash } from "node:crypto";
import { describe, expect, test } from "vitest";

import sampleEnvelope from "../../../tests/fixtures/reviews/sample_review_v1.json";
import presentationFixture from "../../../tests/fixtures/reviews/browser_answer_presentation_v1.json";
import {
  parseReviewEnvelopeV1,
  type ReviewEnvelopeV1,
} from "../lib/review-v1";
import {
  deriveAnswerReceipt,
  parseReviewPresentationVocabulary,
} from "../lib/review-presentation";


function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) => (
      `${JSON.stringify(key)}:${canonicalJson(record[key])}`
    )).join(",")}}`;
  }
  return JSON.stringify(Object.is(value, -0) ? 0 : value);
}


function rehash(value: Record<string, unknown>): Record<string, unknown> {
  const body = structuredClone(value);
  delete body.review_id;
  delete body.result_hash;
  const resultHash = createHash("sha256").update(canonicalJson(body), "utf8").digest("hex");
  return {
    review_id: `review_${resultHash.slice(0, 20)}`,
    result_hash: resultHash,
    ...body,
  };
}


function browserEnvelope(): Record<string, unknown> {
  const value = structuredClone(sampleEnvelope) as unknown as Record<string, unknown>;
  value.execution_mode = "browser_local";
  value.privacy = {
    execution: "browser_local",
    network_calls: false,
    uploaded: false,
    sync_intent: "none",
  };
  return rehash(value);
}


function withoutQuestion(
  envelope: Record<string, unknown>,
  surface: string,
  field: string,
): Record<string, unknown> {
  const value = structuredClone(envelope);
  value.questions = (value.questions as Array<Record<string, unknown>>).filter(
    (question) => question.surface !== surface || question.field !== field,
  );
  value.summary = {
    ...(value.summary as Record<string, unknown>),
    questions: (value.questions as unknown[]).length,
  };
  return rehash(value);
}


describe("parseReviewEnvelopeV1", () => {
  test("accepts and detaches the exact content-addressed browser-local envelope", () => {
    const source = browserEnvelope();
    const parsed = parseReviewEnvelopeV1(source);

    expect(parsed).toEqual(source);
    expect(parsed).not.toBe(source);
    expect(parsed.findings).not.toBe(source.findings);
    expect(parsed.schema_version).toBe("heel.review.v1");
    expect(parsed.engine_version).toBe("1.1.0");
    expect(parsed.execution_mode).toBe("browser_local");
    expect(parsed.privacy).toEqual({
      execution: "browser_local",
      network_calls: false,
      uploaded: false,
      sync_intent: "none",
    });
  });

  test.each([
    ["unknown top-level field", (value: Record<string, unknown>) => { value.raw_source = "secret"; }],
    ["unknown finding field", (value: Record<string, unknown>) => {
      (value.findings as Array<Record<string, unknown>>)[0].extra = true;
    }],
    ["uppercase hash", (value: Record<string, unknown>) => { value.source_hash = "A".repeat(64); }],
    ["unsafe integer", (value: Record<string, unknown>) => {
      (value.summary as Record<string, unknown>).findings = Number.MAX_SAFE_INTEGER + 1;
    }],
    ["non-finite number", (value: Record<string, unknown>) => {
      (value.summary as Record<string, unknown>).findings = Number.POSITIVE_INFINITY;
    }],
    ["wrong summary", (value: Record<string, unknown>) => {
      (value.summary as Record<string, unknown>).questions = 0;
    }],
    ["non-canonical finding order", (value: Record<string, unknown>) => {
      (value.findings as unknown[]).reverse();
    }],
    ["non-static safety", (value: Record<string, unknown>) => {
      (value.safety as Record<string, unknown>).live_probing = true;
    }],
    ["uploaded browser input", (value: Record<string, unknown>) => {
      (value.privacy as Record<string, unknown>).uploaded = true;
    }],
    ["machine-local execution", (value: Record<string, unknown>) => {
      value.execution_mode = "machine_local";
      (value.privacy as Record<string, unknown>).execution = "machine_local";
    }],
  ])("rejects %s even when the attacker recomputes the hash", (_label, mutate) => {
    const value = browserEnvelope();
    mutate(value);
    expect(() => parseReviewEnvelopeV1(rehash(value))).toThrow();
  });

  test("rejects result hash and review identifier tampering", () => {
    const hashTampered = browserEnvelope();
    hashTampered.product_id = "tampered";
    expect(() => parseReviewEnvelopeV1(hashTampered)).toThrow(/result hash/i);

    const idTampered = browserEnvelope();
    idTampered.review_id = `review_${"0".repeat(20)}`;
    expect(() => parseReviewEnvelopeV1(idTampered)).toThrow(/review id/i);
  });
});


describe("deriveAnswerReceipt", () => {
  test("loads the versioned fixture and produces exact applied/improved vocabulary", () => {
    const vocabulary = parseReviewPresentationVocabulary(presentationFixture);
    expect(vocabulary).toEqual(presentationFixture);

    const before = parseReviewEnvelopeV1(browserEnvelope());
    const answer = {
      surface: "downloadbulkexport",
      field: "tenant_filter",
      value: "enforced",
    } as const;
    const after = parseReviewEnvelopeV1(withoutQuestion(before as unknown as Record<string, unknown>, answer.surface, answer.field));

    expect(deriveAnswerReceipt(before, after, [answer], vocabulary)).toEqual({
      schema_version: "heel.review-presentation.v1",
      assumption: "not declared in this OpenAPI; not proof the control is absent",
      confidence: "improved",
      items: [{ ...answer, receipt: "applied" }],
    });
  });

  test.each([
    ["not_enforced", "confirmed_gap", "confirmed_gaps"],
    ["unknown", "unanswered", "preliminary"],
  ] as const)("keeps a %s question visible and projects its exact receipt", (value, receipt, confidence) => {
    const before = parseReviewEnvelopeV1(browserEnvelope());
    const answer = {
      surface: "downloadbulkexport",
      field: "rate_limit",
      value,
    } as const;

    expect(deriveAnswerReceipt(before, before, [answer])).toMatchObject({
      confidence,
      items: [{ ...answer, receipt }],
    });
  });

  test("fails closed for absent, ambiguous, contradictory, or inconsistent questions", () => {
    const before = parseReviewEnvelopeV1(browserEnvelope());
    const unknown = [{ surface: "absent", field: "tenant_filter", value: "unknown" }] as const;
    expect(() => deriveAnswerReceipt(before, before, unknown)).toThrow(/question/i);

    const contradictory = [
      { surface: "downloadbulkexport", field: "rate_limit", value: "unknown" },
      { surface: "downloadbulkexport", field: "rate_limit", value: "enforced" },
    ] as const;
    expect(() => deriveAnswerReceipt(before, before, contradictory)).toThrow();

    const enforcedStillVisible = [
      { surface: "downloadbulkexport", field: "rate_limit", value: "enforced" },
    ] as const;
    expect(() => deriveAnswerReceipt(before, before, enforcedStillVisible)).toThrow(/disappear/i);

    const gapDisappeared = [
      { surface: "downloadbulkexport", field: "rate_limit", value: "not_enforced" },
    ] as const;
    const after = parseReviewEnvelopeV1(withoutQuestion(
      before as unknown as Record<string, unknown>,
      "downloadbulkexport",
      "rate_limit",
    ));
    expect(() => deriveAnswerReceipt(before, after, gapDisappeared)).toThrow(/remain/i);
  });

  test("exposes the strict envelope as a stable TypeScript contract", () => {
    const value: ReviewEnvelopeV1 = parseReviewEnvelopeV1(browserEnvelope());
    expect(value.summary.findings).toBe(value.findings.length);
  });
});
