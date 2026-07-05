import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class DemoCommandTests(unittest.TestCase):
    def run_make(self, target):
        with tempfile.TemporaryDirectory() as home:
            env = os.environ.copy()
            env["HEEL_HOME"] = home
            proc = subprocess.run(
                ["make", target],
                cwd=ROOT,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=30,
            )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        return proc.stdout

    def test_makefile_lists_operator_demo_targets(self):
        makefile = (ROOT / "Makefile").read_text()
        for target in (
            "demo",
            "demo-import",
            "demo-launch-review",
            "demo-regressions",
            "demo-bench",
            "test",
            "ui",
        ):
            self.assertIn(target, makefile)

        help_text = subprocess.run(
            ["make", "help"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=10,
        ).stdout
        for target in ("demo-import", "demo-launch-review", "demo-regressions", "demo-bench"):
            self.assertIn(f"make {target}", help_text)

    def test_demo_import_is_local_imported_mode(self):
        out = self.run_make("demo-import")

        self.assertIn("mode: imported", out)
        self.assertIn("ProductModel validation: PASS", out)
        self.assertIn("no live probing or network calls", out)

    def test_demo_launch_review_is_static_staging_mode(self):
        out = self.run_make("demo-launch-review")

        self.assertIn("mode: staging", out)
        self.assertIn("Launch gate:", out)
        self.assertIn("static ProductModel diff", out)
        self.assertIn("no live probing", out)

    def test_demo_regressions_labels_synthetic_and_incident_modes(self):
        out = self.run_make("demo-regressions")

        self.assertIn("mode: synthetic", out)
        self.assertIn("mode: incident-regression", out)
        self.assertIn("free_trial_serial_signup", out)
        self.assertIn("current_status", out)

    def test_demo_bench_is_fast_synthetic_benchmark(self):
        out = self.run_make("demo-bench")

        self.assertIn("mode: synthetic benchmark", out)
        self.assertIn("HEELBench", out)
        self.assertIn("Held-out TEST", out)

    def test_cli_help_surfaces_new_workflows(self):
        checks = [
            (["--help"], ["bench", "import", "launch-review", "regress", "run"]),
            (["bench", "--help"], ["run", "report"]),
            (["import", "--help"], ["validate", "openapi"]),
            (["launch-review", "--help"], ["--before", "--after", "--diff"]),
            (["regress", "--help"], ["add", "run", "export"]),
            (["run", "--help"], ["--mode", "synthetic", "incident-regression", "launch-review"]),
        ]
        for args, expected in checks:
            proc = subprocess.run(
                [sys.executable, "-m", "heel.cli", *args],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=10,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout)
            for snippet in expected:
                self.assertIn(snippet, proc.stdout)

    def test_readme_has_saas_abuse_review_path(self):
        readme = (ROOT / "README.md").read_text()

        self.assertIn("Try a SaaS abuse review", readme)
        self.assertIn("heel import validate examples/saas_demo/product_model.json", readme)
        self.assertIn(
            "heel launch-review --before examples/saas_demo/product_model.json "
            "--after examples/saas_demo/product_model.json",
            readme,
        )
        self.assertIn("heel regress add", readme)
        self.assertIn("heel regress run", readme)


if __name__ == "__main__":
    unittest.main()
