import importlib
from pathlib import Path
import subprocess
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[1]
FORMER_BRAND_NAMES = ("Arc" + "eo", "arc" + "eo", "ARC" + "EO")
LEGACY_STATE_QUARANTINE = "." + "arc" + "eo/"


def tracked_paths() -> list[str]:
    return subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout.decode().split("\0")


class HeelBrandingTests(unittest.TestCase):
    def test_python_package_imports_as_heel(self):
        module = importlib.import_module("heel")

        self.assertTrue(hasattr(module, "__version__"))

    def test_project_metadata_uses_heel_names(self):
        with (ROOT / "pyproject.toml").open("rb") as fh:
            project = tomllib.load(fh)["project"]

        self.assertEqual(project["name"], "heel-sim")
        self.assertEqual(
            project["description"],
            "Privacy-first local SaaS launch review for browser, CLI, and MCP workflows.",
        )
        self.assertEqual(project["readme"], "release/open-core/README.md")
        self.assertNotIn("urls", project)

    def test_console_scripts_use_heel_names_only(self):
        with (ROOT / "pyproject.toml").open("rb") as fh:
            scripts = tomllib.load(fh)["project"]["scripts"]

        self.assertEqual(
            scripts,
            {
                "heel": "heel.cli:main",
                "heel-mcp": "heel.mcp_server:main",
                "heel-rest": "heel.rest:serve",
            },
        )

    def test_setuptools_discovers_only_the_public_top_level_package(self):
        with (ROOT / "pyproject.toml").open("rb") as fh:
            setuptools = tomllib.load(fh)["tool"]["setuptools"]

        self.assertEqual(
            setuptools,
            {
                "include-package-data": False,
                "license-files": ["LICENSE", "NOTICE"],
                "packages": ["heel"],
                "package-data": {
                    "heel": [
                        "heldout/targets.json",
                        "scenarios_lib/community.json",
                    ],
                },
            },
        )

    def test_legacy_state_directory_is_quarantined(self):
        ignore_lines = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        result = subprocess.run(
            ["git", "check-ignore", LEGACY_STATE_QUARANTINE + "signing.key"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

        self.assertEqual(ignore_lines.count(LEGACY_STATE_QUARANTINE), 1)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), LEGACY_STATE_QUARANTINE + "signing.key")

    def test_changelog_install_command_uses_distribution_name(self):
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")

        self.assertIn("pip install heel-sim", changelog)
        self.assertNotIn("pip install heel`", changelog)

    def test_tracked_product_paths_have_no_former_brand_references(self):
        offenders = [
            relative_name
            for relative_name in filter(None, tracked_paths())
            if not relative_name.startswith("docs/superpowers/")
            and any(name in relative_name for name in FORMER_BRAND_NAMES)
        ]

        self.assertEqual(offenders, [])

    def test_tracked_product_files_have_no_former_brand_references(self):
        offenders = []
        for relative_name in filter(None, tracked_paths()):
            if relative_name.startswith("docs/superpowers/"):
                continue
            path = ROOT / relative_name
            if not path.exists():
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            if relative_name == ".gitignore":
                text = "\n".join(
                    line for line in text.splitlines()
                    if line != LEGACY_STATE_QUARANTINE
                )
            if any(name in text for name in FORMER_BRAND_NAMES):
                offenders.append(relative_name)

        self.assertEqual(offenders, [])
