import json
from pathlib import Path
import subprocess
import sys
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[1]


class FinalIntegrationDocsTests(unittest.TestCase):
    def read(self, rel):
        return (ROOT / rel).read_text(encoding="utf-8")

    def test_readme_docs_section_links_all_operator_docs(self):
        readme = self.read("README.md")
        required_docs = [
            "docs/ADAPTERS.md",
            "docs/CONTROL_SIMULATOR.md",
            "docs/ECONOMIC_SEVERITY.md",
            "docs/ENTITLEMENTS.md",
            "docs/HEELBENCH.md",
            "docs/HELDOUT_PROVENANCE.md",
            "docs/INCIDENTS.md",
            "docs/LAUNCH_REVIEW.md",
            "docs/MODES.md",
            "docs/OPENAPI_IMPORT.md",
            "docs/PERSONAS.md",
            "docs/POSITIONING.md",
            "docs/REGRESSIONS.md",
            "docs/RESEARCH_LIBRARY.md",
            "docs/SCENARIO_AUTHORING.md",
            "docs/SCENARIO_PACKS.md",
        ]

        for doc in required_docs:
            self.assertIn(doc, readme)

    def test_changelog_has_unreleased_integration_summary(self):
        changelog = self.read("CHANGELOG.md")
        self.assertIn("## [Unreleased]", changelog)
        for phrase in (
            "continuous abuse rehearsal positioning",
            "ProductModel adapter contract",
            "entitlement graph",
            "launch review",
            "regressions",
            "economic severity",
            "personas",
            "scenario packs",
            "control simulator",
            "HeelBench",
            "incident-to-scenario",
            "dashboard war room",
        ):
            self.assertIn(phrase, changelog)

    def test_eval_doc_leads_with_current_metrics_and_library_size(self):
        eval_doc = self.read("EVAL.md")
        self.assertIn("120 scenarios", eval_doc)
        self.assertIn("localization recall 0.50", eval_doc)
        self.assertIn("attribution recall 0.33", eval_doc)
        self.assertIn("precision 0.98", eval_doc)
        self.assertNotIn("19 seed scenarios", eval_doc)
        self.assertNotIn("27 tests pass", eval_doc)
        self.assertNotIn("47 tests pass", eval_doc)

    def test_core_docs_agree_on_final_positioning_and_safety(self):
        docs = {
            rel: self.read(rel).lower()
            for rel in ("README.md", "ARCHITECTURE.md", "SECURITY.md", "TRUST.md", "EVAL.md", "DECISIONS.md")
        }
        for rel, text in docs.items():
            self.assertIn("pre-launch", text, rel)
            self.assertIn("existing-product", text, rel)
            self.assertIn("canary", text, rel)
            self.assertIn("scope", text, rel)
            self.assertIn("no scope", text, rel)
            self.assertIn("held-out", text, rel)

    def test_pyproject_keeps_zero_runtime_dependencies_and_matches_readme_positioning(self):
        with (ROOT / "pyproject.toml").open("rb") as fh:
            project = tomllib.load(fh)["project"]
        readme = self.read("README.md").lower()
        description = project["description"].lower()

        self.assertEqual(project["dependencies"], [])
        self.assertIn("abuse rehearsal", description)
        self.assertIn("pre-launch", description)
        self.assertIn("existing-product", description)
        self.assertIn("abuse rehearsal", readme)
        self.assertIn("pre-launch", readme)
        self.assertIn("existing products", readme)


class FinalIntegrationCliTests(unittest.TestCase):
    def run_cli_help(self, *args):
        proc = subprocess.run(
            [sys.executable, "-m", "heel.cli", *args, "--help"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=10,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout)
        return proc.stdout

    def test_cli_help_includes_all_final_workflows(self):
        top = self.run_cli_help()
        for command in ("import", "init", "launch-review", "regress", "controls", "bench", "incident", "scenario"):
            self.assertIn(command, top)

        help_checks = [
            (("init",), ["--from-openapi"]),
            (("controls",), ["simulate"]),
            (("controls", "simulate"), ["--vector", "--finding-json", "--run"]),
            (("scenario",), ["validate"]),
            (("scenario", "validate"), ["path"]),
            (("incident",), ["import", "draft-scenario", "add-regression", "review"]),
            (("bench",), ["run", "report"]),
            (("regress",), ["add", "run", "export"]),
            (("launch-review",), ["--before", "--after", "--diff"]),
            (("import",), ["validate", "openapi"]),
        ]
        for args, snippets in help_checks:
            out = self.run_cli_help(*args)
            for snippet in snippets:
                self.assertIn(snippet, out)

    def test_progress_marks_prompt_19_as_final_completed_prompt(self):
        progress = json.loads((ROOT / ".github/codex/prompt_queue/progress.json").read_text(encoding="utf-8"))

        self.assertIn(19, progress["completed_prompt_ids"])
        self.assertIsNone(progress["next_prompt_id"])
        self.assertEqual(progress["last_pr"]["prompt_id"], 19)
        self.assertEqual(progress["last_pr"]["slug"], "19_final_integration_pass")


if __name__ == "__main__":
    unittest.main()
