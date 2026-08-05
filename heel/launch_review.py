"""Native file, Git, and rendering helpers for static launch review."""
from __future__ import annotations

import json
import subprocess

from .importers import ProductModelError, load_product_model, validate_product_model
from .static_review import (
    SURFACE_FIELDS,
    ChangedSurface,
    LaunchReview,
    RiskFinding,
    SuggestedRegression,
    is_broad_scope,
    review_product_models,
)


def load_and_review(before_path: str, after_path: str) -> LaunchReview:
    return review_product_models(
        load_product_model(before_path), load_product_model(after_path)
    )


def review_git_diff(rev_range: str) -> LaunchReview:
    """Review the first changed ProductModel JSON file in a git revision range."""
    base, head = _split_rev_range(rev_range)
    paths = _changed_json_paths(rev_range)
    errors: list[str] = []
    for path in paths:
        try:
            before = _git_json(base, path)
            after = _git_json(head, path)
        except ProductModelError as exc:
            errors.append(str(exc))
            continue
        if validate_product_model(before).ok and validate_product_model(after).ok:
            return review_product_models(before, after)
    detail = "; ".join(errors) if errors else "no changed ProductModel JSON files found"
    raise ProductModelError(
        f"cannot build launch review from git diff {rev_range}: {detail}"
    )


def render_human_summary(review: LaunchReview) -> str:
    lines = [
        f"Launch gate: {review.launch_gate_status}",
        f"Product: {review.product_id}",
        f"Changed surfaces: {len(review.changed_surfaces)}",
        f"New abuse affordances: {len(review.new_abuse_affordances)}",
        f"High-risk missing controls: {len(review.high_risk_missing_controls)}",
    ]
    for finding in review.high_risk_missing_controls:
        lines.append(f"Blocker: {finding.reason}")
    if review.launch_gate_status == "warn":
        for finding in review.new_abuse_affordances:
            lines.append(f"Warning: {finding.reason}")
    return "\n".join(lines)


def review_to_json(review: LaunchReview) -> str:
    return json.dumps(review.to_dict(), indent=2, sort_keys=True)


def _split_rev_range(rev_range: str) -> tuple[str, str]:
    if "..." in rev_range:
        left, right = rev_range.split("...", 1)
    elif ".." in rev_range:
        left, right = rev_range.split("..", 1)
    else:
        raise ProductModelError(
            "--diff must be a git revision range such as main..feature"
        )
    return left or "HEAD~1", right or "HEAD"


def _changed_json_paths(rev_range: str) -> list[str]:
    result = subprocess.run(
        ["git", "diff", "--name-only", rev_range, "--", "*.json"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise ProductModelError(
            result.stderr.strip() or f"git diff failed for {rev_range}"
        )
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _git_json(rev: str, path: str) -> dict:
    result = subprocess.run(
        ["git", "show", f"{rev}:{path}"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise ProductModelError(
            result.stderr.strip() or f"cannot read {path} at {rev}"
        )
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ProductModelError(f"{path} at {rev} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ProductModelError(f"{path} at {rev} is not a JSON object")
    return data
