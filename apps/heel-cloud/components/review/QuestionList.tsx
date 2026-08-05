// SPDX-License-Identifier: LicenseRef-Heel-Commercial

"use client";

import { useState } from "react";
import type { ReviewAnswer, ReviewAnswerField, ReviewAnswerValue } from "../../lib/review-presentation";
import type { ReviewQuestionV1 } from "../../lib/review-v1";


const SUPPORTED_FIELDS = new Set<ReviewAnswerField>([
  "tenant_filter",
  "entitlement_check",
  "rate_limit",
]);
const ANSWERS: Array<{ value: ReviewAnswerValue; label: string }> = [
  { value: "enforced", label: "Enforced" },
  { value: "not_enforced", label: "Not enforced" },
  { value: "unknown", label: "Unknown" },
];
const QUESTION_PAGE_SIZE = 20;


export function questionAnswerKey(question: Pick<ReviewQuestionV1, "surface" | "field">): string {
  return `${question.surface}\u0000${question.field}`;
}


export function QuestionList({
  questions,
  answers,
  disabled,
  onAnswer,
  onRerun,
}: {
  questions: ReviewQuestionV1[];
  answers: Map<string, ReviewAnswer>;
  disabled: boolean;
  onAnswer(answer: ReviewAnswer): void;
  onRerun(): void;
}) {
  const [visible, setVisible] = useState(QUESTION_PAGE_SIZE);
  if (questions.length === 0) {
    return (
      <section className="questions-card" aria-labelledby="questions-title">
        <p className="eyebrow">Confidence questions</p>
        <h3 id="questions-title">No unanswered control questions.</h3>
      </section>
    );
  }
  return (
    <section className="questions-card" aria-labelledby="questions-title">
      <p className="eyebrow">Improve this review</p>
      <h3 id="questions-title">Answer only what the OpenAPI can model safely.</h3>
      <p className="section-intro">
        Answers stay in memory and rerun the same local Python engine.
      </p>
      <div className="question-list">
        {questions.slice(0, visible).map((question, index) => {
          const supported = SUPPORTED_FIELDS.has(question.field as ReviewAnswerField);
          if (!supported) {
            return (
              <article className="question question-unsupported" key={`${question.id}:${index}`}>
                <span className="question-field">{question.field}</span>
                <strong>{question.prompt}</strong>
                <p>Not answerable from this OpenAPI — retained as visible uncertainty.</p>
              </article>
            );
          }
          const field = question.field as ReviewAnswerField;
          const selected = answers.get(questionAnswerKey(question))?.value;
          return (
            <fieldset className="question" key={`${question.id}:${index}`}>
              <legend>{question.prompt}</legend>
              <span className="question-surface">{question.surface} · {field}</span>
              <div className="answer-options">
                {ANSWERS.map((answer) => (
                  <label key={answer.value}>
                    <input
                      type="radio"
                      name={`answer-${question.id}-${index}`}
                      value={answer.value}
                      checked={selected === answer.value}
                      disabled={disabled}
                      onChange={() => onAnswer({ surface: question.surface, field, value: answer.value })}
                      aria-label={`${answer.label}: ${question.prompt}`}
                    />
                    <span>{answer.label}</span>
                  </label>
                ))}
              </div>
            </fieldset>
          );
        })}
      </div>
      {visible < questions.length ? (
        <button
          className="text-button load-more"
          type="button"
          onClick={() => setVisible((current) => Math.min(current + QUESTION_PAGE_SIZE, questions.length))}
        >
          Load more confidence questions ({questions.length - visible} remaining)
        </button>
      ) : null}
      <button
        className="button button-secondary"
        type="button"
        onClick={onRerun}
        disabled={disabled || answers.size === 0}
      >
        Rerun with answers
      </button>
    </section>
  );
}
