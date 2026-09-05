// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import type { ReviewAnswerReceiptV1 } from "./review-presentation";
import { parseReviewEnvelopeV1, type ReviewEnvelopeV1 } from "./review-v1";


const MARKDOWN_PUNCTUATION = new Set(
  Array.from("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"),
);


function markdownPlaintext(value: string): string {
  let output = "";
  for (const character of value) {
    const code = character.codePointAt(0)!;
    if (
      code <= 0x1f
      || (code >= 0x7f && code <= 0x9f)
      || code === 0x2028
      || code === 0x2029
    ) {
      if (!output.endsWith(" ")) output += " ";
      continue;
    }
    if (MARKDOWN_PUNCTUATION.has(character)) output += "\\";
    output += character;
  }
  return output;
}


function slug(value: string): string {
  const normalized = value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
  return normalized.slice(0, 48) || "review";
}


export function reviewToJson(value: unknown): string {
  const envelope = parseReviewEnvelopeV1(value);
  return `${JSON.stringify(envelope, null, 2)}\n`;
}


export function reviewToMarkdown(
  value: unknown,
  receipt: ReviewAnswerReceiptV1 | null = null,
): string {
  const review: ReviewEnvelopeV1 = parseReviewEnvelopeV1(value);
  const lines = [
    `# Heel launch review: ${markdownPlaintext(review.product_id)}`,
    "",
    `Review: ${markdownPlaintext(review.review_id)}`,
    `Gate: **${review.gate_status.toUpperCase()}**`,
    `Findings: ${review.summary.findings} · Blockers: ${review.summary.blockers}`,
    "Privacy: Browser-local analysis; source not uploaded; no analyzer network calls.",
    "",
    "Static triage only. No findings does not establish complete coverage or launch safety.",
    "## Findings",
    "",
  ];
  if (review.findings.length === 0) lines.push("No findings.", "");
  review.findings.forEach((finding, index) => {
    const surface = `${markdownPlaintext(finding.surface_type)} / ${markdownPlaintext(finding.surface_id)}`;
    lines.push(
      `### ${index + 1}. ${surface}`,
      "",
      `- Severity: **${finding.severity.toUpperCase()}**`,
      `- Evidence: ${markdownPlaintext(finding.evidence_state ?? "legacy static claim")}; execution: static only`,
      `- Reachable: ${finding.reachable ? "yes" : "not established"}`,
      `- Reason: ${markdownPlaintext(finding.reason)}`,
      `- Recommended control: ${markdownPlaintext(finding.control)}`,
      "",
    );
  });
  lines.push("## Unanswered questions", "");
  review.questions.forEach((question) => lines.push(`- ${markdownPlaintext(question.surface)}: ${markdownPlaintext(question.prompt)}`));
  lines.push("Customer answers declare intent or controls; they do not verify behavior.", "");
  lines.push("## Suggested regressions", "");
  review.suggested_regressions.forEach((regression) => {
    lines.push(
      `- ${markdownPlaintext(regression.name)} — ${markdownPlaintext(regression.scenario_hint)}`,
    );
  });
  if (receipt !== null) {
    lines.push(
      "",
      "## Current session answer receipt",
      "",
      `Confidence: ${markdownPlaintext(receipt.confidence)}`,
      `Assumption: ${markdownPlaintext(receipt.assumption)}`,
    );
    receipt.items.forEach((item) => {
      lines.push(
        `- ${markdownPlaintext(item.surface)} / ${markdownPlaintext(item.field)}: ${markdownPlaintext(item.receipt)}`,
      );
    });
  }
  return `${lines.join("\n").trimEnd()}\n`;
}


export function reviewDownloadName(review: ReviewEnvelopeV1, extension: "json" | "md"): string {
  return `heel-${slug(review.product_id)}-${review.review_id}.${extension}`;
}
