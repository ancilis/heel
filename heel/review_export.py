"""Deterministic, integrity-checked exports for Heel review envelopes."""
from __future__ import annotations

import html
from typing import Any, Mapping

from .review_contract import stable_json, validate_review_envelope


def _safe_text(value: str) -> str:
    return html.escape(value, quote=True)


def review_to_markdown(envelope: Mapping[str, Any]) -> str:
    """Render a deterministic text-only Markdown report for a valid review."""
    review = validate_review_envelope(dict(envelope))
    summary = review["summary"]
    lines = [
        f"# Heel launch review: {_safe_text(review['product_id'])}",
        "",
        f"Review: `{_safe_text(review['review_id'])}`",
        f"Gate: **{review['gate_status'].upper()}**",
        f"Findings: {summary['findings']} · Blockers: {summary['blockers']}",
    ]
    if review["execution_mode"] in {"browser_local", "machine_local"}:
        lines.append("Privacy: analyzed locally; source content was not uploaded.")
    else:
        lines.append(
            "Privacy: analyzed in an isolated cloud worker; "
            "an explicitly sanitized model was uploaded."
        )

    lines.extend(["", "## Findings", ""])
    if not review["findings"]:
        lines.extend(["No findings.", ""])
    for index, finding in enumerate(review["findings"], 1):
        surface = (
            f"{_safe_text(finding['surface_type'])} / "
            f"{_safe_text(finding['surface_id'])}"
        )
        lines.extend([
            f"### {index}. {surface}",
            "",
            f"- Severity: **{finding['severity'].upper()}**",
            f"- Surface: {surface}",
            f"- Reason: {_safe_text(finding['reason'])}",
            f"- Recommended control: {_safe_text(finding['control'])}",
            "",
        ])
    return "\n".join(lines).rstrip() + "\n"


def review_to_json(envelope: Mapping[str, Any]) -> str:
    """Render a canonical UTF-8 JSON representation for a valid review."""
    review = validate_review_envelope(dict(envelope))
    return stable_json(review) + "\n"
