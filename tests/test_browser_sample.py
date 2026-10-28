"""Contract tests for Heel's committed browser demo review."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import unittest

from heel.browser_review import review_openapi_json


ROOT = Path(__file__).resolve().parents[1]
SAMPLE_SOURCE = ROOT / "apps/heel-cloud/data/sample-openapi.json"
SAMPLE_REVIEW = ROOT / "apps/heel-cloud/data/sample-review.v1.json"
BUILDER = ROOT / "scripts/build_browser_sample.py"


class BrowserSampleTests(unittest.TestCase):
    def test_committed_sample_is_exact_browser_engine_output(self):
        self.assertTrue(SAMPLE_SOURCE.is_file(), "browser sample OpenAPI is missing")
        self.assertTrue(SAMPLE_REVIEW.is_file(), "browser sample review is missing")

        source = SAMPLE_SOURCE.read_text(encoding="utf-8")
        expected = SAMPLE_REVIEW.read_text(encoding="utf-8").strip()
        self.assertEqual(review_openapi_json(source), expected)

        review = json.loads(expected)
        finding = next(
            item for item in review["findings"]
            if item["risk"] == "agent_surface_overscope"
        )
        self.assertEqual(review["execution_mode"], "browser_local")
        self.assertEqual(review["gate_status"], "block")
        self.assertEqual(finding["surface_id"], "runagenttool")
        self.assertEqual(finding["severity"], "block")
        self.assertTrue(finding["reachable"])
        self.assertIn("global beyond intended tenant", finding["reason"])
        self.assertEqual(finding["control"], "tool scope minimization")
        self.assertTrue(any(
            item["surface_id"] == "runagenttool"
            and item["scenario_hint"] == "agent_surface_overscope"
            for item in review["suggested_regressions"]
        ))

    def test_builder_check_detects_no_drift(self):
        completed = subprocess.run(
            [sys.executable, str(BUILDER), "--check"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)


if __name__ == "__main__":
    unittest.main()
