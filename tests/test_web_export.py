import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


class TestWarRoomSnapshot(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._old_home = os.environ.get("HEEL_HOME")
        cls._tmp = tempfile.TemporaryDirectory()
        os.environ["HEEL_HOME"] = cls._tmp.name
        from heel.web_export import build_snapshot

        cls.snapshot = build_snapshot()

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()
        if cls._old_home is None:
            os.environ.pop("HEEL_HOME", None)
        else:
            os.environ["HEEL_HOME"] = cls._old_home

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
        from heel.web_export import build_snapshot

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


class TestWebExportOutputPath(unittest.TestCase):
    def test_no_argument_main_targets_cwd_without_creating_a_parent(self):
        from heel import web_export

        with tempfile.TemporaryDirectory() as temporary:
            cwd = Path(temporary).resolve()
            with (
                mock.patch.object(sys, "argv", ["heel.web_export"]),
                mock.patch.object(web_export.os, "getcwd", return_value=str(cwd)),
                mock.patch.object(web_export, "build_snapshot", return_value={}),
                mock.patch.object(web_export.os, "makedirs") as makedirs,
                mock.patch("builtins.open", mock.mock_open()) as opened,
                mock.patch.object(web_export.os.path, "getsize", return_value=2),
            ):
                web_export.main()

        self.assertEqual(opened.call_args.args[0], str(cwd / "heel-snapshot.json"))
        makedirs.assert_not_called()

    def test_explicit_bare_filename_does_not_create_an_empty_parent(self):
        from heel import web_export

        with (
            mock.patch.object(
                sys,
                "argv",
                ["heel.web_export", "customer-snapshot.json"],
            ),
            mock.patch.object(web_export, "build_snapshot", return_value={}),
            mock.patch.object(web_export.os, "makedirs") as makedirs,
            mock.patch("builtins.open", mock.mock_open()) as opened,
            mock.patch.object(web_export.os.path, "getsize", return_value=2),
        ):
            web_export.main()

        makedirs.assert_not_called()
        opened.assert_called_once_with("customer-snapshot.json", "w")

    def test_explicit_nested_output_creates_its_parent_and_writes_snapshot(self):
        from heel import web_export

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary).resolve() / "exports" / "customer.json"
            with (
                mock.patch.object(
                    sys,
                    "argv",
                    ["heel.web_export", str(output)],
                ),
                mock.patch.object(
                    web_export,
                    "build_snapshot",
                    return_value={"schema": "test"},
                ),
            ):
                web_export.main()

            self.assertEqual(
                json.loads(output.read_text(encoding="utf-8")),
                {"schema": "test"},
            )

    def test_no_argument_subprocess_uses_cwd_in_installed_public_layout(self):
        contract = json.loads(
            (ROOT / "release/open-core-v1.json").read_text(encoding="utf-8")
        )
        with tempfile.TemporaryDirectory() as temporary:
            temporary_path = Path(temporary).resolve()
            site = temporary_path / "site"
            run = temporary_path / "run"
            run.mkdir()
            for relative_name in contract["python_modules"] + contract["package_data"]:
                source = ROOT / relative_name
                destination = site / relative_name
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)

            environment = os.environ.copy()
            environment.update(
                {
                    "HEEL_HOME": str(temporary_path / "state"),
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "PYTHONPATH": str(site),
                }
            )
            result = subprocess.run(
                [sys.executable, "-m", "heel.web_export"],
                cwd=run,
                env=environment,
                capture_output=True,
                text=True,
                timeout=60,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            output = run / "heel-snapshot.json"
            self.assertTrue(output.is_file(), result.stdout)
            self.assertIn("meta", json.loads(output.read_text(encoding="utf-8")))
            self.assertFalse((site / "web").exists())


if __name__ == "__main__":
    unittest.main()
