import json
import os
from pathlib import Path
import tempfile
import unittest


class TestWarRoomSnapshot(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._old_home = os.environ.get("ARCEO_HOME")
        cls._tmp = tempfile.TemporaryDirectory()
        os.environ["ARCEO_HOME"] = cls._tmp.name
        from arceo.web_export import build_snapshot

        cls.snapshot = build_snapshot()

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()
        if cls._old_home is None:
            os.environ.pop("ARCEO_HOME", None)
        else:
            os.environ["ARCEO_HOME"] = cls._old_home

    def test_snapshot_contains_war_room_sections(self):
        for section in (
            "economics",
            "launch_review",
            "existing_product",
            "controls",
            "regressions",
            "incidents",
            "safety_authorization",
        ):
            self.assertIn(section, self.snapshot)

    def test_abuse_board_findings_include_economic_and_filter_dimensions(self):
        board = self.snapshot["abuse_board"]
        self.assertEqual(board["rank_formula"], "reachability + severity + economic_impact")
        for filter_name in ("category", "persona", "pack", "product_area"):
            self.assertIn(filter_name, board["filters"])

        top = board["ranked_findings"][0]
        self.assertIn("economic_impact", top)
        self.assertIn("estimated_monthly_range_usd", top["economic_impact"])
        self.assertIn("persona", top)
        self.assertIn("pack", top)
        self.assertIn("product_area", top)

    def test_snapshot_labels_safe_modes_and_scope_read_only(self):
        modes = self.snapshot["existing_product"]["mode_indicator"]["available_modes"]
        self.assertEqual(modes, ["synthetic", "imported", "staging"])
        self.assertEqual(self.snapshot["existing_product"]["mode_indicator"]["active_mode"], "synthetic")
        safety = self.snapshot["safety_authorization"]
        self.assertTrue(safety["scope_panel"]["read_only"])
        self.assertTrue(safety["canary_only"])
        self.assertFalse(safety["scope_mutation_path"])
        self.assertIn("no production probing", safety["mode_note"].lower())

    def test_regression_and_incident_sections_are_canary_only(self):
        regressions = self.snapshot["regressions"]
        self.assertIn("with_regression", regressions)
        self.assertIn("without_regression", regressions)
        self.assertEqual(regressions["last_run_status"], "canary-only")

        incidents = self.snapshot["incidents"]
        self.assertTrue(incidents["sanitized_incidents"])
        self.assertTrue(incidents["generated_scenarios"])
        self.assertTrue(incidents["generated_regressions"])
        self.assertTrue(all(i["prohibited_fields_removed_confirmed"] for i in incidents["sanitized_incidents"]))

    def test_build_snapshot_is_deterministic(self):
        from arceo.web_export import build_snapshot

        again = build_snapshot()
        self.assertEqual(
            json.dumps(self.snapshot, sort_keys=True, default=str),
            json.dumps(again, sort_keys=True, default=str),
        )


class TestWarRoomUiSource(unittest.TestCase):
    def test_dashboard_labels_operator_war_room_sections(self):
        source = Path("web/src/components/screens.tsx").read_text()
        for label in (
            "Launch Review",
            "Existing Product Review",
            "Control Simulator",
            "Regression Coverage",
            "Incident Library",
            "Safety & Authorization",
        ):
            self.assertIn(label, source)

    def test_dashboard_labels_modes_without_unsafe_production_probe_copy(self):
        page = Path("web/src/app/page.tsx").read_text()
        screens = Path("web/src/components/screens.tsx").read_text()
        combined = page + "\n" + screens
        for label in ("synthetic", "imported", "staging"):
            self.assertIn(label, combined.lower())
        self.assertIn("No production probing", combined)
        self.assertNotIn("safe production probing", combined.lower())
        self.assertNotIn("probe production", combined.lower())


if __name__ == "__main__":
    unittest.main()
