"""One current release identity across package, Agent, browser, and customer copy."""
from __future__ import annotations

import json
from pathlib import Path
import tomllib
import unittest

from heel import __version__
from heel.review_contract import ENGINE_VERSION, SUPPORTED_ENGINE_VERSIONS


ROOT = Path(__file__).resolve().parents[1]
# The Python package, release contract, engine and server.json use the PEP 440 spelling.
# The current version is the checked-in 1.3.0rc4 candidate, which is not yet published.
VERSION = "1.3.0rc4"
# npm metadata needs SemVer; this is the single normalization mapping, not a second version.
NPM_VERSION = "1.3.0-rc.4"
LEGACY_VERSIONS = frozenset({"1.1.0", "1.1.1", "1.2.0", "1.3.0rc1", "1.3.0rc2", "1.3.0rc3"})
# The public GitHub prerelease that customer copy installs from its pinned release URL. 1.3.0rc1
# stays a published prerelease, named in copy only as erratum history.
PUBLIC_VERSION = "1.3.0rc2"
PREVIOUS_PREVIEW_VERSION = "1.3.0rc1"
PUBLIC_RELEASE_URL = f"https://github.com/ancilis/heel/releases/tag/v{PUBLIC_VERSION}"
# Only the paired-runner surfaces carry the published v1.3.0rc3 runner release; every other customer
# surface stays on PUBLIC_VERSION. Pinned literally so a later version move cannot carry it along.
PAIRED_RUNNER_VERSION = "1.3.0rc3"
PAIRED_RUNNER_RELEASE_URL = f"https://github.com/ancilis/heel/releases/tag/v{PAIRED_RUNNER_VERSION}"
PUBLIC_WHEEL_URL = (
    f"https://github.com/ancilis/heel/releases/download/v{PUBLIC_VERSION}/"
    f"heel_sim-{PUBLIC_VERSION}-py3-none-any.whl"
)
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
        # server.json schema 2025-07-09: the PyPI package version must be the exact published
        # version (no range); the server version mirrors MCP serverInfo.version.
        self.assertEqual(server["version"], VERSION)
        self.assertEqual(server["packages"][0]["registry_type"], "pypi")
        self.assertEqual(server["packages"][0]["version"], VERSION)
        self.assertEqual(app_package["version"], NPM_VERSION)
        self.assertEqual(app_lock["version"], NPM_VERSION)
        self.assertEqual(app_lock["packages"][""]["version"], NPM_VERSION)

    def test_pep440_and_semver_spellings_name_one_release(self):
        self.assertRegex(VERSION, r"\A1\.3\.0rc4\Z")
        self.assertRegex(NPM_VERSION, r"\A1\.3\.0-rc\.4\Z")
        major_minor_patch, candidate = VERSION.split("rc")
        self.assertEqual(NPM_VERSION, f"{major_minor_patch}-rc.{candidate}")
        self.assertNotEqual(VERSION, NPM_VERSION)
        from heel.mcp_server import SERVER_INFO

        self.assertEqual(SERVER_INFO["version"], VERSION)

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
        # The only older wheel name allowed is the published rc2 wheel inside its own release URL.
        without_public_install = combined.replace(PUBLIC_WHEEL_URL, "")
        for legacy_version in LEGACY_VERSIONS:
            self.assertNotIn(f"heel_sim-{legacy_version}", without_public_install)
        # Customer copy installs the published rc2 from its own public release, never from an older
        # release's download URL, and claims no public release for the unpublished candidate. The
        # paired-runner page is checked separately below.
        customer = paths[:4] + [ROOT / "docs/EXPORT_DEMO.md"]
        for path in customer:
            text = path.read_text(encoding="utf-8")
            self.assertIn(f"releases/tag/v{PUBLIC_VERSION}", text, path)
            self.assertNotIn(f"releases/download/v{PREVIOUS_PREVIEW_VERSION}", text, path)
            self.assertNotRegex(text, rf"{PUBLIC_VERSION}[^.]*not yet published as a GitHub release", path)
            self.assertNotIn(f"releases/tag/v{VERSION}", text, path)
            self.assertNotIn(f"releases/download/v{VERSION}", text, path)
        # The paired-runner page installs the reviewed rc3 runner from its own public release
        # (pinned exactly in test_release_automation) and never from rc1 or rc2.
        runner = (ROOT / "apps/heel-cloud/app/runner/page.tsx").read_text(encoding="utf-8")
        self.assertIn(f"releases/tag/v{PAIRED_RUNNER_VERSION}", runner)
        for older in (PREVIOUS_PREVIEW_VERSION, PUBLIC_VERSION):
            self.assertNotIn(f"releases/download/v{older}", runner)
            self.assertNotIn(f"releases/tag/v{older}", runner)
        self.assertNotRegex(runner, rf"{PAIRED_RUNNER_VERSION}[^.]*not yet published as a GitHub release")
        for path in customer[:2] + customer[4:5]:
            self.assertIn(PUBLIC_WHEEL_URL, path.read_text(encoding="utf-8"), path)
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn(f"## [{VERSION}]: unpublished candidate", changelog)
        self.assertEqual(changelog.count("unpublished candidate"), 1)
        self.assertNotIn(f"https://github.com/ancilis/heel/releases/tag/v{VERSION}", changelog)
        self.assertIn(f"## [{PAIRED_RUNNER_VERSION}]: 2026-11-11", changelog)
        self.assertIn(PAIRED_RUNNER_RELEASE_URL, changelog)
        self.assertIn(f"## [{PUBLIC_VERSION}]: 2026-11-10", changelog)
        self.assertIn(PUBLIC_RELEASE_URL, changelog)
        self.assertIn(f"## [{PREVIOUS_PREVIEW_VERSION}]: 2026-10-23", changelog)
        self.assertIn(
            f"https://github.com/ancilis/heel/releases/tag/v{PREVIOUS_PREVIEW_VERSION}", changelog,
        )
        self.assertIn("## [1.2.0]: 2026-08-04", changelog)
        self.assertIn("## [1.1.1]: 2026-08-04", changelog)


if __name__ == "__main__":
    unittest.main()
