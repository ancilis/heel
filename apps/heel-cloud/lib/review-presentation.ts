// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import {
  parseReviewEnvelopeV1,
  type ReviewEnvelopeV1,
  type ReviewQuestionV1,
} from "./review-v1";


export const MAX_REVIEW_ANSWER_COUNT = 64;
export const MAX_REVIEW_ANSWERS_BYTES = 64 * 1024;

export type ReviewAnswerValue = "enforced" | "not_enforced" | "unknown";
export type ReviewAnswerField = "tenant_filter" | "entitlement_check" | "rate_limit";

export interface ReviewAnswer {
  surface: string;
  field: ReviewAnswerField;
  value: ReviewAnswerValue;
}

export interface ReviewPresentationVocabularyV1 {
  schema_version: "heel.review-presentation.v1";
  assumption: "not declared in this OpenAPI; not proof the control is absent";
  answer_receipts: {
    enforced: "applied";
    not_enforced: "declared_gap";
    unknown: "unanswered";
  };
  confidence: {
    unanswered_or_unknown: "preliminary";
    not_enforced: "declared_gaps";
    enforced_reduced_questions_without_declared_gap: "improved";
  };
}

export interface ReviewAnswerReceiptV1 {
  schema_version: "heel.review-presentation.v1";
  assumption: ReviewPresentationVocabularyV1["assumption"];
  confidence: "preliminary" | "declared_gaps" | "improved";
  items: Array<ReviewAnswer & {
    receipt: "applied" | "declared_gap" | "unanswered";
  }>;
}


export const REVIEW_PRESENTATION_VOCABULARY: ReviewPresentationVocabularyV1 = Object.freeze({
  schema_version: "heel.review-presentation.v1",
  assumption: "not declared in this OpenAPI; not proof the control is absent",
  answer_receipts: Object.freeze({
    enforced: "applied",
    not_enforced: "declared_gap",
    unknown: "unanswered",
  }),
  confidence: Object.freeze({
    unanswered_or_unknown: "preliminary",
    not_enforced: "declared_gaps",
    enforced_reduced_questions_without_declared_gap: "improved",
  }),
});


function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}


function exactFields(value: Record<string, unknown>, fields: string[], label: string): void {
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} has unexpected fields`);
  }
}


export function parseReviewPresentationVocabulary(value: unknown): ReviewPresentationVocabularyV1 {
  if (!isRecord(value)) throw new Error("presentation vocabulary must be an object");
  exactFields(value, ["schema_version", "assumption", "answer_receipts", "confidence"], "presentation vocabulary");
  const receipts = value.answer_receipts;
  const confidence = value.confidence;
  if (!isRecord(receipts) || !isRecord(confidence)) {
    throw new Error("presentation vocabulary is malformed");
  }
  exactFields(receipts, ["enforced", "not_enforced", "unknown"], "answer receipt vocabulary");
  exactFields(confidence, [
    "unanswered_or_unknown",
    "not_enforced",
    "enforced_reduced_questions_without_declared_gap",
  ], "confidence vocabulary");
  if (
    value.schema_version !== REVIEW_PRESENTATION_VOCABULARY.schema_version
    || value.assumption !== REVIEW_PRESENTATION_VOCABULARY.assumption
    || receipts.enforced !== REVIEW_PRESENTATION_VOCABULARY.answer_receipts.enforced
    || receipts.not_enforced !== REVIEW_PRESENTATION_VOCABULARY.answer_receipts.not_enforced
    || receipts.unknown !== REVIEW_PRESENTATION_VOCABULARY.answer_receipts.unknown
    || confidence.unanswered_or_unknown !== REVIEW_PRESENTATION_VOCABULARY.confidence.unanswered_or_unknown
    || confidence.not_enforced !== REVIEW_PRESENTATION_VOCABULARY.confidence.not_enforced
    || confidence.enforced_reduced_questions_without_declared_gap !== REVIEW_PRESENTATION_VOCABULARY.confidence.enforced_reduced_questions_without_declared_gap
  ) throw new Error("presentation vocabulary does not match heel.review-presentation.v1");
  return {
    schema_version: REVIEW_PRESENTATION_VOCABULARY.schema_version,
    assumption: REVIEW_PRESENTATION_VOCABULARY.assumption,
    answer_receipts: { ...REVIEW_PRESENTATION_VOCABULARY.answer_receipts },
    confidence: { ...REVIEW_PRESENTATION_VOCABULARY.confidence },
  };
}


function normalizeAnswers(value: unknown): ReviewAnswer[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_REVIEW_ANSWER_COUNT) {
    throw new Error("submitted answers must be a bounded nonempty array");
  }
  let encoded: Uint8Array;
  try {
    encoded = new TextEncoder().encode(JSON.stringify(value));
  } catch {
    throw new Error("submitted answers are not JSON-safe");
  }
  if (encoded.byteLength > MAX_REVIEW_ANSWERS_BYTES) {
    throw new Error("submitted answers exceed the size limit");
  }
  const seen = new Set<string>();
  return value.map((candidate, index) => {
    if (!isRecord(candidate)) throw new Error(`answer ${index} must be an object`);
    exactFields(candidate, ["surface", "field", "value"], `answer ${index}`);
    if (typeof candidate.surface !== "string" || candidate.surface.length === 0) {
      throw new Error(`answer ${index} has an invalid surface`);
    }
    if (!(["tenant_filter", "entitlement_check", "rate_limit"] as unknown[]).includes(candidate.field)) {
      throw new Error(`answer ${index} has an unsupported field`);
    }
    if (!(["enforced", "not_enforced", "unknown"] as unknown[]).includes(candidate.value)) {
      throw new Error(`answer ${index} has an unsupported value`);
    }
    const key = `${candidate.surface}\u0000${candidate.field}`;
    if (seen.has(key)) throw new Error("submitted answers contain a duplicate or contradiction");
    seen.add(key);
    return {
      surface: candidate.surface,
      field: candidate.field as ReviewAnswerField,
      value: candidate.value as ReviewAnswerValue,
    };
  }).sort((left, right) => (
    left.surface.localeCompare(right.surface, "en-US")
    || left.field.localeCompare(right.field, "en-US")
  ));
}


function questionKey(question: Pick<ReviewQuestionV1, "surface" | "field">): string {
  return `${question.surface}\u0000${question.field}`;
}


function sameQuestion(left: ReviewQuestionV1, right: ReviewQuestionV1): boolean {
  return (
    left.id === right.id
    && left.field === right.field
    && left.surface === right.surface
    && left.prompt === right.prompt
    && left.required === right.required
  );
}


export function deriveAnswerReceipt(
  beforeValue: unknown,
  afterValue: unknown,
  submittedAnswers: unknown,
  vocabularyValue: unknown = REVIEW_PRESENTATION_VOCABULARY,
): ReviewAnswerReceiptV1 {
  const before: ReviewEnvelopeV1 = parseReviewEnvelopeV1(beforeValue);
  const after: ReviewEnvelopeV1 = parseReviewEnvelopeV1(afterValue);
  const answers = normalizeAnswers(submittedAnswers);
  const vocabulary = parseReviewPresentationVocabulary(vocabularyValue);
  const beforeByKey = new Map<string, ReviewQuestionV1[]>();
  const afterByKey = new Map<string, ReviewQuestionV1[]>();
  for (const question of before.questions) {
    const entries = beforeByKey.get(questionKey(question)) ?? [];
    entries.push(question);
    beforeByKey.set(questionKey(question), entries);
  }
  for (const question of after.questions) {
    const entries = afterByKey.get(questionKey(question)) ?? [];
    entries.push(question);
    afterByKey.set(questionKey(question), entries);
  }

  const items = answers.map((answer) => {
    const key = questionKey(answer);
    const beforeMatches = beforeByKey.get(key) ?? [];
    const afterMatches = afterByKey.get(key) ?? [];
    if (beforeMatches.length !== 1) {
      throw new Error("each answer must match exactly one real pre-review question");
    }
    if (answer.value === "enforced") {
      if (afterMatches.length !== 0) throw new Error("an enforced answer must make its question disappear");
    } else if (afterMatches.length !== 1 || !sameQuestion(beforeMatches[0], afterMatches[0])) {
      throw new Error("a negative or unknown answer must make its original question remain");
    }
    return {
      ...answer,
      receipt: vocabulary.answer_receipts[answer.value],
    };
  });

  const hasDeclaredGap = answers.some((answer) => answer.value === "not_enforced");
  const hasUnknown = answers.some((answer) => answer.value === "unknown");
  const hasApplied = answers.some((answer) => answer.value === "enforced");
  let confidence: ReviewAnswerReceiptV1["confidence"] = vocabulary.confidence.unanswered_or_unknown;
  if (hasDeclaredGap) {
    confidence = vocabulary.confidence.not_enforced;
  } else if (
    !hasUnknown
    && after.questions.length === 0
    && hasApplied
    && after.questions.length < before.questions.length
  ) {
    confidence = vocabulary.confidence.enforced_reduced_questions_without_declared_gap;
  }
  return {
    schema_version: vocabulary.schema_version,
    assumption: vocabulary.assumption,
    confidence,
    items,
  };
}
