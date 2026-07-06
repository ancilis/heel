import importlib
from pathlib import Path
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ArceoBrandingTests(unittest.TestCase):
    def test_python_package_imports_as_arceo(self):
        module = importlib.import_module("arceo")

        self.assertTrue(hasattr(module, "__version__"))

    def test_project_metadata_uses_arceo_names(self):
        with (ROOT / "pyproject.toml").open("rb") as fh:
            project = tomllib.load(fh)["project"]

        self.assertEqual(project["name"], "arceo")
        self.assertIn("Arceo", project["description"])
        self.assertEqual(project["urls"]["Homepage"], "https://github.com/ancilis/arceo")
        self.assertEqual(project["urls"]["Source"], "https://github.com/ancilis/arceo")
        self.assertEqual(project["urls"]["Issues"], "https://github.com/ancilis/arceo/issues")

    def test_console_scripts_use_arceo_names_only(self):
        with (ROOT / "pyproject.toml").open("rb") as fh:
            scripts = tomllib.load(fh)["project"]["scripts"]

        self.assertEqual(
            scripts,
            {
                "arceo": "arceo.cli:main",
                "arceo-mcp": "arceo.mcp_server:main",
                "arceo-rest": "arceo.rest:serve",
            },
        )
