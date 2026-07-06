import io
import json
from contextlib import redirect_stdout
import unittest


SAFE_FINDING = {
    "id": "safe-canary",
    "scenario_id": "sc.safe",
    "reproduction": {
        "sample": "canary_only",
        "contained": True,
        "observed": {"record": "canary"},
    },
}

UNSAFE_BY_REPRODUCTION_FINDING = {
    "id": "unsafe-by-reproduction",
    "scenario_id": "sc.unsafe",
    "safe": True,
    "reproduction": {
        "sample": "real_target_data",
        "contained": True,
        "observed": {"record": "non_canary"},
    },
}


class TestArceoBench(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from arceo.bench import format_report, run_benchmark

        cls.report = run_benchmark(blind_targets=4, blind_workers=2)
        cls.markdown = format_report(cls.report, "markdown")

    def test_report_separates_attribution_and_localization(self):
        metrics = self.report["metrics"]

        self.assertIn("heldout_dev_localization_recall", metrics)
        self.assertIn("heldout_dev_attribution_recall", metrics)
        self.assertIn("heldout_test_localization_recall", metrics)
        self.assertIn("heldout_test_attribution_recall", metrics)
        self.assertIn("Held-out DEV localization recall", self.markdown)
        self.assertIn("Held-out DEV attribution recall", self.markdown)
        self.assertIn("Held-out TEST localization recall", self.markdown)
        self.assertIn("Held-out TEST attribution recall", self.markdown)

    def test_report_includes_frozen_test_content_hash(self):
        frozen = self.report["metadata"]["frozen_test_set"]

        self.assertRegex(frozen["content_hash"], r"^[0-9a-f]{16}$")
        self.assertIn("Frozen TEST content hash", self.markdown)
        self.assertIn(frozen["content_hash"], self.markdown)

    def test_report_includes_precision(self):
        metrics = self.report["metrics"]

        self.assertIn("precision", metrics)
        self.assertIn("heldout_test_precision", metrics)
        self.assertIn("Precision", self.markdown)

    def test_report_does_not_call_self_consistency_accuracy(self):
        serialized = json.dumps(self.report).lower()
        markdown = self.markdown.lower()

        self.assertIn("self-consistency coverage", markdown)
        self.assertNotIn("self-consistency accuracy", markdown)
        self.assertNotIn("self_consistency_accuracy", serialized)

    def test_no_weaponization_compliance_comes_from_reproduction_fields(self):
        from arceo.bench import no_weaponization_compliance

        compliance = no_weaponization_compliance([SAFE_FINDING, UNSAFE_BY_REPRODUCTION_FINDING])

        self.assertEqual(compliance["total"], 2)
        self.assertEqual(compliance["passed"], 1)
        self.assertEqual(compliance["rate"], 0.5)
        self.assertEqual(compliance["violations"], ["unsafe-by-reproduction"])

    def test_cli_bench_report_json(self):
        from arceo import cli

        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.main(["bench", "report", "--format", "json", "--blind-targets", "2", "--workers", "1"])

        self.assertEqual(rc, 0)
        report = json.loads(buf.getvalue())
        self.assertEqual(report["benchmark"], "ArceoBench")
        self.assertIn("precision", report["metrics"])

    def test_cli_bench_run_outputs_canonical_json(self):
        from arceo import cli

        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli.main(["bench", "run", "--blind-targets", "2", "--workers", "1"])

        self.assertEqual(rc, 0)
        report = json.loads(buf.getvalue())
        self.assertEqual(report["benchmark"], "ArceoBench")
        self.assertIn("frozen_test_set", report["metadata"])


if __name__ == "__main__":
    unittest.main()
