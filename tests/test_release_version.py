"""One current release identity across package, Agent, browser, and customer copy."""
from __future__ import annotations

import json
from pathlib import Path
import tomllib
import unittest

from heel import __version__
from heel.review_contract import ENGINE_VERSION, SUPPORTED_ENGINE_VERSIONS


ROOT = Path(__file__).resolve().parents[1]
VERSION = "1.2.0"
LEGACY_VERSIONS = frozenset({"1.1.0", "1.1.1"})
AGENT_WHEEL = f"heel_sim-{VERSION}-py3-none-any.whl"
AGENT_SDIST = f"heel_sim-{VERSION}.tar.gz"
BROWSER_WHEEL = f"heel_browser-{VERSION}-py3-none-any.whl"


class ReleaseVersionContractTests(unittest.TestCase):
    def test_authoritative_versions_are_current_and_saved_reviews_remain_readable(self):
        pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        descriptor = json.loads(
            (ROOT / "release/open-core-v1.json").read_text(encoding="utf-8")
        )
        server = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))
        app_package = json.loads(
            (ROOT / "apps/heel-cloud/package.json").read_text(encoding="utf-8")
        )
        app_lock = json.loads(
            (ROOT / "apps/heel-cloud/package-lock.json").read_text(encoding="utf-8")
        )

        self.assertEqual(__version__, VERSION)
        self.assertEqual(ENGINE_VERSION, VERSION)
        self.assertEqual(SUPPORTED_ENGINE_VERSIONS, LEGACY_VERSIONS | {VERSION})
        self.assertEqual(pyproject["project"]["version"], VERSION)
        self.assertEqual(descriptor["version"], VERSION)
        self.assertEqual(server["version"], VERSION)
        self.assertEqual(server["packages"][0]["version"], VERSION)
        self.assertEqual(app_package["version"], VERSION)
        self.assertEqual(app_lock["version"], VERSION)
        self.assertEqual(app_lock["packages"][""]["version"], VERSION)

    def test_committed_release_directories_contain_only_current_named_artifacts(self):
        downloads = ROOT / "apps/heel-cloud/public/downloads"
        browser = ROOT / "apps/heel-cloud/browser-engine"
        self.assertEqual(
            {path.name for path in downloads.iterdir()},
            {AGENT_WHEEL, AGENT_SDIST, "heel-open-core-manifest.json"},
        )
        self.assertEqual(
            {path.name for path in browser.iterdir()},
            {BROWSER_WHEEL, "manifest.json"},
        )
        manifest = json.loads(
            (downloads / "heel-open-core-manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["version"], VERSION)
        self.assertEqual(
            [artifact["name"] for artifact in manifest["artifacts"]],
            [AGENT_WHEEL, AGENT_SDIST],
        )
        browser_manifest = json.loads(
            (browser / "manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(browser_manifest["engine_version"], VERSION)
        self.assertEqual(browser_manifest["wheel"]["filename"], BROWSER_WHEEL)

    def test_customer_and_publish_contracts_name_only_the_current_release(self):
        paths = [
            ROOT / "README.md",
            ROOT / "docs/MCP_QUICKSTART.md",
            ROOT / "apps/heel-cloud/README.md",
            ROOT / "apps/heel-cloud/app/agent/page.tsx",
            ROOT / ".github/workflows/ci.yml",
            ROOT / ".github/workflows/publish.yml",
        ]
        combined = "\n".join(path.read_text(encoding="utf-8") for path in paths)
        self.assertIn(AGENT_WHEEL, combined)
        self.assertIn(AGENT_SDIST, combined)
        for legacy_version in LEGACY_VERSIONS:
            self.assertNotIn(f"heel_sim-{legacy_version}", combined)
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn("## [1.2.0]: 2026-08-04", changelog)
        self.assertIn("## [1.1.1]: 2026-08-04", changelog)


if __name__ == "__main__":
    unittest.main()
