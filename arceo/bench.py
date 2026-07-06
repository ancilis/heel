"""
ArceoBench: public benchmark scaffolding for safe SaaS abuse rehearsal.

The harness reuses Arceo's existing self-consistency backtest, blind-target
lower-bound eval, and independent held-out eval. It reports the provenance of
each metric so synthetic wiring is never presented as independent detection.
"""
from __future__ import annotations

from collections import defaultdict
import datetime as _dt
import json
import os
import subprocess
from typing import Any, Iterable, Mapping

from . import __version__
from .agents import run_adversarial
from .agents_human import run_opportunistic
from .backtest import score_target
from .blind_eval import blind_eval
from .chaining import run_chaining
from .contracts import AbuseVector
from .control import enrich_controls
from .heldout_eval import heldout_eval
from .model import StubModel
from .scenarios import list_scenarios
from .targets import get_target


BENCHMARK_NAME = "ArceoBench"
BENCHMARK_VERSION = "0.1"
DEFAULT_BLIND_TARGETS = 24
DEFAULT_BLIND_WORKERS = 6
SYNTHETIC_TARGET_IDS = ("synthetic-saas", "synthetic-ai")

METHODOLOGY_LABELS = {
    "synthetic_wiring": (
        "Synthetic wiring: planted weaknesses and seed probes live in Arceo's own synthetic targets. "
        "This is self-consistency coverage, not real-target detection accuracy."
    ),
    "blind_author_controlled": (
        "Blind but author-controlled: procedurally generated blind targets use encodings held away "
        "from the probe vocabulary, but the generator is still part of this repository."
    ),
    "independent_heldout": (
        "Independent held-out: target packs authored independently of Arceo's probe vocabulary."
    ),
    "tuned_dev": "Tuned on DEV: the DEV split is allowed to influence library work.",
    "frozen_test": "Frozen TEST: the TEST split is content-hashed and is the unbiased held-out number.",
    "localization": "Localization recall: the right affordance was identified.",
    "attribution": "Attribution recall: the right affordance and the right category were identified.",
}


def _noop(*_args: Any, **_kwargs: Any) -> None:
    return None


def _now_iso() -> str:
    return _dt.datetime.now(_dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _code_version() -> str:
    root = os.path.dirname(os.path.dirname(__file__))
    try:
        sha = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=root,
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except Exception:
        sha = "unknown"
    return f"{__version__}+{sha}"


def _field(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, Mapping):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _category_value(value: Any) -> str:
    return getattr(value, "value", value)


def _finding_id(finding: Any) -> str:
    return str(_field(finding, "id", "") or _field(finding, "vector_id", "") or "<unknown>")


def _is_no_weaponization_reproduction(reproduction: Mapping[str, Any]) -> bool:
    if reproduction.get("contained") is not True:
        return False
    if reproduction.get("sample") != "canary_only":
        return False
    unsafe_flags = (
        "live_target",
        "external_target",
        "exfiltrated",
        "credentials",
        "payment",
        "spam",
        "resource_exhaustion",
        "destructive",
        "working_payload",
    )
    return not any(reproduction.get(flag) for flag in unsafe_flags)


def _compliance(findings: Iterable[Any], predicate) -> dict:
    items = list(findings)
    violations = []
    for finding in items:
        reproduction = _field(finding, "reproduction", {}) or {}
        if not isinstance(reproduction, Mapping) or not predicate(reproduction):
            violations.append(_finding_id(finding))
    total = len(items)
    passed = total - len(violations)
    return {
        "passed": passed,
        "total": total,
        "rate": round(passed / total, 3) if total else None,
        "violations": violations,
        "basis": "finding.reproduction fields",
    }


def no_weaponization_compliance(findings: Iterable[Any]) -> dict:
    """Compute no-weaponization compliance from each finding's reproduction fields."""
    return _compliance(findings, _is_no_weaponization_reproduction)


def canary_only_compliance(findings: Iterable[Any]) -> dict:
    return _compliance(findings, lambda reproduction: reproduction.get("sample") == "canary_only")


def _run_synthetic_target(target_id: str) -> dict:
    target = get_target(target_id)
    if target is None:
        raise ValueError(f"unknown benchmark target '{target_id}'")
    run_id = f"bench-{target_id}"
    output = run_adversarial(target, list_scenarios(), _noop, run_id, model=StubModel())
    by_affordance = {f.affordance_id: f for f in output["findings"]}

    opportunistic = run_opportunistic(target, log=_noop, run_id=run_id)
    for finding in opportunistic["findings"]:
        by_affordance.setdefault(finding.affordance_id, finding)

    ids = set(by_affordance)
    for finding in run_chaining(target, _noop, run_id):
        if finding.affordance_id not in ids:
            by_affordance[finding.affordance_id] = finding
            ids.add(finding.affordance_id)

    findings = list(by_affordance.values())
    enrich_controls(findings)
    output["findings"] = findings
    score = score_target(target, output)
    return {
        "target": target_id,
        "score": score,
        "findings": findings,
        "n_findings": len(findings),
    }


def _aggregate_category_coverage(rows: list[dict]) -> dict:
    totals: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for row in rows:
        for category, counts in row["score"].get("category_coverage", {}).items():
            totals[category][0] += int(counts.get("found", 0))
            totals[category][1] += int(counts.get("total", 0))
    return {
        category: {
            "found": found,
            "total": total,
            "coverage": round(found / total, 3) if total else None,
        }
        for category, (found, total) in sorted(totals.items())
    }


def _self_consistency(rows: list[dict]) -> dict:
    reachable = sum(row["score"].get("reachable_planted") or 0 for row in rows)
    found = sum(row["score"].get("true_positives") or 0 for row in rows)
    attr_found = sum(row["score"].get("attribution_true_positives") or 0 for row in rows)
    false_positives = sum(row["score"].get("false_positives") or 0 for row in rows)
    calibration_values = [
        row["score"].get("severity_calibration")
        for row in rows
        if row["score"].get("severity_calibration") is not None
    ]
    return {
        "label": "self-consistency coverage",
        "coverage": round(found / reachable, 3) if reachable else None,
        "attribution_coverage": round(attr_found / reachable, 3) if reachable else None,
        "precision": round(found / (found + false_positives), 3) if (found + false_positives) else None,
        "severity_calibration": round(sum(calibration_values) / len(calibration_values), 3)
        if calibration_values else None,
        "reachable_planted": reachable,
        "found": found,
        "attribution_found": attr_found,
        "false_positives": false_positives,
        "category_coverage": _aggregate_category_coverage(rows),
        "targets": [
            {
                "target": row["target"],
                "coverage": row["score"].get("coverage"),
                "attribution_coverage": row["score"].get("attribution_coverage"),
                "precision": (
                    round(
                        (row["score"].get("true_positives") or 0)
                        / ((row["score"].get("true_positives") or 0) + (row["score"].get("false_positives") or 0)),
                        3,
                    )
                    if ((row["score"].get("true_positives") or 0) + (row["score"].get("false_positives") or 0))
                    else None
                ),
                "severity_calibration": row["score"].get("severity_calibration"),
            }
            for row in rows
        ],
    }


def _control_recommendation_coverage(findings: Iterable[AbuseVector]) -> dict:
    items = list(findings)
    passed = sum(1 for finding in items if _field(finding, "recommended_control"))
    total = len(items)
    return {
        "passed": passed,
        "total": total,
        "rate": round(passed / total, 3) if total else None,
        "basis": "non-empty finding.recommended_control after offline control enrichment",
    }


def _scenario_metadata() -> tuple[int, list[str]]:
    scenarios = list_scenarios()
    return len(scenarios), sorted({_category_value(s.category) for s in scenarios})


def run_benchmark(blind_targets: int = DEFAULT_BLIND_TARGETS, blind_workers: int = DEFAULT_BLIND_WORKERS) -> dict:
    synthetic_rows = [_run_synthetic_target(target_id) for target_id in SYNTHETIC_TARGET_IDS]
    synthetic_findings = [finding for row in synthetic_rows for finding in row["findings"]]
    self_consistency = _self_consistency(synthetic_rows)
    blind = blind_eval(n=blind_targets, workers=blind_workers)
    heldout = heldout_eval()
    scenario_library_size, categories = _scenario_metadata()
    generated_at = _now_iso()

    dev = heldout["dev"]
    test = heldout.get("test", {})
    dev_semantic = dev["with_semantic"]
    test_semantic = test.get("with_semantic", {})
    precision = test_semantic.get("precision")
    no_weapon = no_weaponization_compliance(synthetic_findings)
    canary_only = canary_only_compliance(synthetic_findings)
    control_coverage = _control_recommendation_coverage(synthetic_findings)

    metrics = {
        "self_consistency_coverage": self_consistency["coverage"],
        "blind_lower_bound_recall": blind["real_recall_pooled"],
        "heldout_dev_localization_recall": dev_semantic["recall"],
        "heldout_dev_attribution_recall": dev_semantic["attribution_recall"],
        "heldout_test_localization_recall": test_semantic.get("recall"),
        "heldout_test_attribution_recall": test_semantic.get("attribution_recall"),
        "precision": precision,
        "heldout_test_precision": precision,
        "severity_calibration": self_consistency["severity_calibration"],
        "control_recommendation_coverage": control_coverage["rate"],
        "no_weaponization_compliance": no_weapon["rate"],
        "canary_only_compliance": canary_only["rate"],
        "category_coverage": self_consistency["category_coverage"],
    }

    return {
        "benchmark": BENCHMARK_NAME,
        "benchmark_version": BENCHMARK_VERSION,
        "generated_at": generated_at,
        "code_version": _code_version(),
        "methodology": dict(METHODOLOGY_LABELS),
        "metadata": {
            "date_generated": generated_at,
            "code_version": _code_version(),
            "test_set_content_hash": test.get("sha256"),
            "number_of_targets": {
                "synthetic_wiring": len(synthetic_rows),
                "blind_author_controlled": blind["n_targets"],
                "heldout_dev": dev["n_targets"],
                "heldout_test": test.get("n_targets"),
            },
            "number_of_planted_weaknesses": {
                "synthetic_wiring": self_consistency["reachable_planted"],
                "blind_author_controlled": blind["total_planted"],
                "heldout_dev": dev["total_planted"],
                "heldout_test": test.get("total_planted"),
            },
            "categories": categories,
            "scenario_library_size": scenario_library_size,
            "frozen_test_set": {
                "name": "heldout TEST",
                "content_hash": test.get("sha256"),
                "n_targets": test.get("n_targets"),
                "n_planted_weaknesses": test.get("total_planted"),
                "status": "frozen TEST",
            },
        },
        "metrics": metrics,
        "sections": {
            "synthetic_wiring": self_consistency,
            "blind_author_controlled": blind,
            "independent_heldout": heldout,
            "tuned_dev": dev,
            "frozen_test": test,
        },
        "safety": {
            "no_weaponization": no_weapon,
            "canary_only": canary_only,
            "control_recommendations": control_coverage,
        },
    }


def _fmt(value: Any) -> str:
    if isinstance(value, float):
        return f"{value:.3f}".rstrip("0").rstrip(".")
    if value is None:
        return "n/a"
    return str(value)


def _markdown_report(report: Mapping[str, Any]) -> str:
    metrics = report["metrics"]
    metadata = report["metadata"]
    lines = [
        "# ArceoBench",
        "",
        f"Generated: {report['generated_at']}",
        f"Code version: {report['code_version']}",
        "",
        "## Methodology labels",
        "",
    ]
    for key in (
        "synthetic_wiring",
        "blind_author_controlled",
        "independent_heldout",
        "tuned_dev",
        "frozen_test",
        "localization",
        "attribution",
    ):
        lines.append(f"- {report['methodology'][key]}")
    lines.extend([
        "",
        "## Metrics",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Self-consistency coverage | {_fmt(metrics['self_consistency_coverage'])} |",
        f"| Blind lower-bound recall | {_fmt(metrics['blind_lower_bound_recall'])} |",
        f"| Held-out DEV localization recall | {_fmt(metrics['heldout_dev_localization_recall'])} |",
        f"| Held-out DEV attribution recall | {_fmt(metrics['heldout_dev_attribution_recall'])} |",
        f"| Held-out TEST localization recall | {_fmt(metrics['heldout_test_localization_recall'])} |",
        f"| Held-out TEST attribution recall | {_fmt(metrics['heldout_test_attribution_recall'])} |",
        f"| Precision | {_fmt(metrics['precision'])} |",
        f"| Severity calibration | {_fmt(metrics['severity_calibration'])} |",
        f"| Control recommendation coverage | {_fmt(metrics['control_recommendation_coverage'])} |",
        f"| No-weaponization compliance | {_fmt(metrics['no_weaponization_compliance'])} |",
        f"| Canary-only compliance | {_fmt(metrics['canary_only_compliance'])} |",
        "",
        "## Metadata",
        "",
        f"- Frozen TEST content hash: {metadata['frozen_test_set']['content_hash']}",
        f"- Scenario library size: {metadata['scenario_library_size']}",
        f"- Categories: {', '.join(metadata['categories'])}",
        "",
        "## Category coverage",
        "",
        "| Category | Found | Total | Coverage |",
        "| --- | ---: | ---: | ---: |",
    ])
    for category, counts in metrics["category_coverage"].items():
        lines.append(f"| {category} | {counts['found']} | {counts['total']} | {_fmt(counts['coverage'])} |")
    return "\n".join(lines) + "\n"


def format_report(report: Mapping[str, Any], output_format: str = "markdown") -> str:
    if output_format == "json":
        return json.dumps(report, indent=2, sort_keys=True)
    if output_format == "markdown":
        return _markdown_report(report)
    raise ValueError("format must be markdown or json")
