#!/usr/bin/env python3
"""Deterministic local demo workflows for Makefile targets."""
from __future__ import annotations

import argparse
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
PRODUCT_MODEL = ROOT / "examples" / "saas_demo" / "product_model.json"
sys.path.insert(0, str(ROOT))

from heel import cli  # noqa: E402


def _run_cli(argv: list[str], *, echo: bool = True) -> tuple[int, str]:
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = cli.main(argv)
    out = buf.getvalue()
    if echo:
        print(out, end="")
    return rc, out


def _run_cli_json(argv: list[str], *, echo: bool = True) -> tuple[int, dict]:
    rc, out = _run_cli(argv, echo=echo)
    if rc != 0:
        return rc, {}
    return rc, json.loads(out)


def demo_import() -> int:
    print("mode: imported")
    print("safety: local ProductModel validation only; no live probing or network calls")
    rc, _ = _run_cli(["import", "validate", str(PRODUCT_MODEL)])
    return rc


def demo_launch_review() -> int:
    print("mode: staging")
    print("safety: static ProductModel diff; no live probing or network calls")
    rc, _ = _run_cli([
        "launch-review",
        "--before",
        str(PRODUCT_MODEL),
        "--after",
        str(PRODUCT_MODEL),
    ])
    return rc


def demo_bench() -> int:
    print("mode: synthetic benchmark")
    print("safety: local synthetic corpus only; no API keys, network access, or real systems")
    rc, _ = _run_cli(["bench", "report", "--blind-targets", "2", "--workers", "1"])
    return rc


def demo_regressions() -> int:
    print("mode: synthetic")
    print("safety: temporary HEEL_HOME; synthetic target only; no live probing or network calls")
    original_home = os.environ.get("HEEL_HOME")
    with tempfile.TemporaryDirectory(prefix="heel-demo-regressions-") as home:
        os.environ["HEEL_HOME"] = home
        try:
            rc, scope_doc = _run_cli_json([
                "scope",
                "create",
                "--target",
                "synthetic-saas",
                "--operator",
                "demo-human",
                "--confirm",
            ], echo=False)
            if rc != 0:
                return rc
            scope_id = scope_doc["created_scope"]
            print(f"created_scope: {scope_id}")

            rc, run_doc = _run_cli_json([
                "run",
                "--mode",
                "synthetic",
                "--scope",
                scope_id,
                "--target",
                "synthetic-saas",
                "--scenario",
                "sc.trial.serial",
            ], echo=False)
            if rc != 0:
                return rc
            run_id = run_doc["run_id"]
            print(f"synthetic_run: {run_id}")

            rc, findings_doc = _run_cli_json(["findings", "--run", run_id], echo=False)
            if rc != 0:
                return rc
            vector_id = next(
                finding["id"]
                for finding in findings_doc["findings"]
                if finding["scenario_id"] == "sc.trial.serial"
            )
            print(f"captured_vector: {vector_id} (sc.trial.serial)")

            print("mode: incident-regression")
            rc, regression_doc = _run_cli_json([
                "regress",
                "add",
                "--run",
                run_id,
                "--vector",
                vector_id,
                "--name",
                "free_trial_serial_signup",
            ], echo=False)
            if rc != 0:
                return rc
            regression = regression_doc["regression"]
            print(f"regression: {regression['name']} ({regression['regression_id']})")

            rc, results_doc = _run_cli_json([
                "regress",
                "run",
                "--scope",
                scope_id,
                "--target",
                "synthetic-saas",
            ], echo=False)
            if rc != 0:
                return rc
            result = results_doc["results"][0]
            print(f"current_status: {result['current_status']}")
            print(f"expected_status: {result['expected_status']}")
            print(f"regression_run: {result['run_id']}")
        finally:
            if original_home is None:
                os.environ.pop("HEEL_HOME", None)
            else:
                os.environ["HEEL_HOME"] = original_home
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Run deterministic local HEEL demo workflows")
    ap.add_argument("workflow", choices=["import", "launch-review", "regressions", "bench"])
    args = ap.parse_args(argv)
    if args.workflow == "import":
        return demo_import()
    if args.workflow == "launch-review":
        return demo_launch_review()
    if args.workflow == "regressions":
        return demo_regressions()
    if args.workflow == "bench":
        return demo_bench()
    raise AssertionError(args.workflow)


if __name__ == "__main__":
    raise SystemExit(main())
