"""Fail-closed boundary tests for the Apache-only Heel release contract."""
from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "release/open-core-v1.json"
FORBIDDEN_PREFIXES = (
    "apps/",
    "deploy/",
    "docs/saas/",
    "docs/superpowers/",
    "heel/saas/",
    "web/",
)
EXPECTED_CONTRACT = {
    "console_scripts": {
        "heel": "heel.cli:main",
        "heel-mcp": "heel.mcp_server:main",
        "heel-rest": "heel.rest:serve",
    },
    "documents": [
        "ARCHITECTURE.md",
        "CHANGELOG.md",
        "CONTRIBUTING.md",
        "DECISIONS.md",
        "README.md",
        "SECURITY.md",
        "TRUST.md",
        "docs/ENTITLEMENTS.md",
        "docs/LAUNCH_REVIEW.md",
        "docs/MCP_QUICKSTART.md",
        "docs/MODES.md",
        "docs/OPENAPI_IMPORT.md",
        "docs/REGRESSIONS.md",
    ],
    "licenses": ["DCO", "LICENSE", "NOTICE"],
    "package_data": [
        "heel/heldout/targets.json",
        "heel/heldout/test_targets.json",
        "heel/scenarios_lib/community.json",
        "heel/scenarios_lib/research_owasp.json",
    ],
    "python_modules": [
        "heel/__init__.py",
        "heel/agents.py",
        "heel/agents_human.py",
        "heel/backtest.py",
        "heel/bench.py",
        "heel/blind.py",
        "heel/blind_eval.py",
        "heel/browser_review.py",
        "heel/chaining.py",
        "heel/classify.py",
        "heel/cli.py",
        "heel/containment.py",
        "heel/contracts.py",
        "heel/control.py",
        "heel/control_simulator.py",
        "heel/economics.py",
        "heel/entitlements.py",
        "heel/heldout_eval.py",
        "heel/importers.py",
        "heel/incident.py",
        "heel/launch_review.py",
        "heel/local_projects.py",
        "heel/mcp_server.py",
        "heel/model.py",
        "heel/modes.py",
        "heel/openapi_import.py",
        "heel/openapi_model.py",
        "heel/orchestrator.py",
        "heel/product_model.py",
        "heel/profiles.py",
        "heel/regressions.py",
        "heel/rest.py",
        "heel/review_answers.py",
        "heel/review_contract.py",
        "heel/review_export.py",
        "heel/review_rules.py",
        "heel/review_service.py",
        "heel/scenario_validate.py",
        "heel/scenarios.py",
        "heel/scope.py",
        "heel/semantic.py",
        "heel/static_review.py",
        "heel/store.py",
        "heel/targets.py",
        "heel/web_export.py",
    ],
    "schema_version": "heel.open-core-release.v1",
    "version": "1.1.0",
}
EXPECTED_MANIFEST = """include ARCHITECTURE.md CHANGELOG.md CONTRIBUTING.md DCO DECISIONS.md LICENSE NOTICE README.md SECURITY.md TRUST.md
include docs/ENTITLEMENTS.md docs/LAUNCH_REVIEW.md docs/MCP_QUICKSTART.md docs/MODES.md docs/OPENAPI_IMPORT.md docs/REGRESSIONS.md
include heel/*.py
include heel/heldout/*.json
include heel/scenarios_lib/*.json
prune heel/saas
prune docs/saas
prune docs/superpowers
global-exclude __pycache__/*
global-exclude *.pyc
"""


class OpenCoreReleaseTests(unittest.TestCase):
    def test_release_contract_is_an_exact_public_allowlist(self):
        self.assertTrue(CONTRACT.is_file(), "release/open-core-v1.json is missing")
        contract_text = CONTRACT.read_text(encoding="utf-8")
        contract = json.loads(contract_text)

        self.assertEqual(contract, EXPECTED_CONTRACT)
        self.assertEqual(
            contract_text,
            json.dumps(
                contract,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ) + "\n",
        )
        self.assertEqual(
            set(contract),
            {
                "console_scripts",
                "documents",
                "licenses",
                "package_data",
                "python_modules",
                "schema_version",
                "version",
            },
        )
        self.assertEqual(contract["schema_version"], "heel.open-core-release.v1")
        paths = (
            contract["python_modules"]
            + contract["package_data"]
            + contract["documents"]
            + contract["licenses"]
        )
        self.assertEqual(len(paths), len(set(paths)))
        for path in paths:
            normalized = PurePosixPath(path)
            self.assertEqual(normalized.as_posix(), path)
            self.assertFalse(normalized.is_absolute(), path)
            self.assertFalse(path.startswith(FORBIDDEN_PREFIXES), path)
            self.assertNotIn("..", normalized.parts)

        with (ROOT / "pyproject.toml").open("rb") as file:
            setuptools = tomllib.load(file)["tool"]["setuptools"]
        self.assertEqual(
            setuptools,
            {
                "include-package-data": False,
                "packages": ["heel"],
                "package-data": {
                    "heel": ["scenarios_lib/*.json", "heldout/*.json"],
                },
            },
        )
        self.assertEqual(
            (ROOT / "MANIFEST.in").read_text(encoding="utf-8"),
            EXPECTED_MANIFEST,
        )


if __name__ == "__main__":
    unittest.main()
