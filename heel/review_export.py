"""Deterministic, integrity-checked exports for Heel review envelopes."""
from __future__ import annotations

import string
from typing import Any, Mapping
import unicodedata

from .review_contract import stable_json, validate_review_envelope


_COMMONMARK_PUNCTUATION = frozenset(string.punctuation)
_COLLAPSED_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp"})


def _markdown_plaintext(value: str) -> str:
    """Collapse controls and escape every ASCII punctuation mark CommonMark can parse."""
    encoded = []
    for character in value:
        if unicodedata.category(character) in _COLLAPSED_CATEGORIES:
            if not encoded or encoded[-1] != " ":
                encoded.append(" ")
            continue
        if character in _COMMONMARK_PUNCTUATION:
            encoded.append("\\")
        encoded.append(character)
    return "".join(encoded)


def review_to_markdown(envelope: Mapping[str, Any]) -> str:
    """Render a deterministic text-only Markdown report for a valid review."""
    review = validate_review_envelope(dict(envelope))
    summary = review["summary"]
    lines = [
        f"# Heel launch review: {_markdown_plaintext(review['product_id'])}",
        "",
        f"Review: {_markdown_plaintext(review['review_id'])}",
        f"Gate: **{_markdown_plaintext(review['gate_status'].upper())}**",
        f"Findings: {summary['findings']} · Blockers: {summary['blockers']}",
        "Static triage only. No findings does not establish complete coverage or launch safety.",
    ]
    if review["execution_mode"] in {"browser_local", "machine_local"}:
        lines.append(
            "Privacy: Envelope declares local analysis, no upload, "
            "and no analyzer network calls."
        )
    else:
        lines.append(
            "Privacy: Envelope declares isolated cloud analysis, sanitized-model upload, "
            "and no analyzer network calls."
        )

    lines.extend(["", "## Findings", ""])
    if not review["findings"]:
        lines.extend(["No findings.", ""])
    for index, finding in enumerate(review["findings"], 1):
        surface = (
            f"{_markdown_plaintext(finding['surface_type'])} / "
            f"{_markdown_plaintext(finding['surface_id'])}"
        )
        lines.extend([
            f"### {index}. {surface}",
            "",
            f"- Severity: **{_markdown_plaintext(finding['severity'].upper())}**",
            f"- Surface: {surface}",
            f"- Evidence: {_markdown_plaintext(finding.get('evidence_state', 'legacy static claim'))}; execution: static only",
            f"- Reason: {_markdown_plaintext(finding['reason'])}",
            f"- Recommended control: {_markdown_plaintext(finding['control'])}",
            "",
        ])
    lines.extend(["", "## Unanswered questions", ""])
    for question in review["questions"]:
        lines.append(f"- {_markdown_plaintext(question['surface'])}: {_markdown_plaintext(question['prompt'])}")
    lines.append("Customer answers declare intent or controls; they do not verify behavior.")
    return "\n".join(lines).rstrip() + "\n"


def review_to_json(envelope: Mapping[str, Any]) -> str:
    """Render a canonical UTF-8 JSON representation for a valid review."""
    review = validate_review_envelope(dict(envelope))
    return stable_json(review) + "\n"
