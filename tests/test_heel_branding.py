import importlib
from pathlib import Path
import subprocess
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[1]


class HeelBrandingTests(unittest.TestCase):
    def test_python_package_imports_as_heel(self):
        module = importlib.import_module("heel")

        self.assertTrue(hasattr(module, "__version__"))

    def test_project_metadata_uses_heel_names(self):
        with (ROOT / "pyproject.toml").open("rb") as fh:
            project = tomllib.load(fh)["project"]

        self.assertEqual(project["name"], "heel-sim")
        self.assertIn("Heel", project["description"])
        self.assertEqual(project["urls"]["Homepage"], "https://github.com/ancilis/heel")
        self.assertEqual(project["urls"]["Source"], "https://github.com/ancilis/heel")
        self.assertEqual(project["urls"]["Issues"], "https://github.com/ancilis/heel/issues")

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

    def test_setuptools_discovers_all_heel_subpackages(self):
        with (ROOT / "pyproject.toml").open("rb") as fh:
            setuptools = tomllib.load(fh)["tool"]["setuptools"]

        self.assertEqual(setuptools["packages"]["find"]["include"], ["heel*"])

    def test_tracked_product_files_have_no_former_brand_references(self):
        old_names = ("Arc" + "eo", "arc" + "eo", "ARC" + "EO")
        tracked = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=ROOT,
            check=True,
            capture_output=True,
        ).stdout.decode().split("\0")
        offenders = []
        for relative_name in filter(None, tracked):
            if relative_name.startswith("docs/superpowers/"):
                continue
            path = ROOT / relative_name
            if not path.exists():
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            if any(name in text for name in old_names):
                offenders.append(relative_name)

        self.assertEqual(offenders, [])
