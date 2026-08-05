"""Fail-closed contracts for Heel's CI, publication, and customer release copy."""
from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
CI = ROOT / ".github/workflows/ci.yml"
PUBLISH = ROOT / ".github/workflows/publish.yml"
WHEEL = "heel_sim-1.2.0-py3-none-any.whl"
SDIST = "heel_sim-1.2.0.tar.gz"
MANIFEST = "heel-open-core-manifest.json"
RELEASE_REQUIREMENTS = ROOT / "release/requirements-release.txt"


def _job(source: str, name: str, next_name: str | None = None) -> str:
    start = source.index(f"  {name}:\n")
    end = source.index(f"  {next_name}:\n", start) if next_name else len(source)
    return source[start:end]


class ReleaseAutomationContractTests(unittest.TestCase):
    def test_ci_checks_and_installs_the_committed_release_with_real_mcp_lifecycle(self):
        source = CI.read_text(encoding="utf-8")
        package = _job(source, "package", "ui")

        self.assertIn(
            "python scripts/build_open_core_release.py "
            "--output apps/heel-cloud/public/downloads --check",
            package,
        )
        self.assertIn("HEEL_REQUIRE_STANDARD_BUILD=1", package)
        self.assertIn("python -m unittest tests.test_open_core_release -v", package)
        self.assertIn("--require-hashes", package)
        self.assertIn("--only-binary=:all:", package)
        self.assertIn("release/requirements-release.txt", package)
        self.assertIn(
            f"apps/heel-cloud/public/downloads/{WHEEL}",
            package,
        )
        self.assertNotIn("python -m build", package)
        self.assertNotIn("heldout_eval", package)
        self.assertNotIn("dist/*.whl", package)
        self.assertLess(package.index('"method":"initialize"'), package.index('"method":"tools/list"'))
        self.assertIn('"method":"notifications/initialized"', package)
        self.assertIn('"method":"tools/call"', package)
        self.assertIn("heel_review_openapi", package)
        self.assertIn("find_spec(\"heel.saas\") is None", package)
        self.assertIn('environment.pop("PYTHONHOME", None)', package)
        self.assertIn('cwd="/tmp/heel-ci-workspace"', package)
        self.assertNotIn("npm ci || npm install", source)
        self.assertIn("actionlint_1.7.8_linux_amd64.tar.gz", source)
        self.assertIn(
            "be92c2652ab7b6d08425428797ceabeb16e31a781c07bc388456b4e592f3e36a",
            source,
        )
        self.assertIn("permissions:\n  contents: read", source)
        self.assertEqual(
            source.count("persist-credentials: false"),
            source.count("actions/checkout@"),
        )

    def test_publish_attests_and_uploads_only_allowlist_builder_bytes(self):
        source = PUBLISH.read_text(encoding="utf-8")

        verify = _job(source, "verify-release", "publish")
        publish = _job(source, "publish")

        self.assertIn("test ! -e dist", verify)
        self.assertIn("python scripts/build_open_core_release.py --output dist", verify)
        self.assertIn("python scripts/build_open_core_release.py --output dist --check", verify)
        self.assertIn("HEEL_REQUIRE_STANDARD_BUILD=1", verify)
        self.assertIn("python -m unittest tests.test_open_core_release -v", verify)
        self.assertNotIn("python -m build", source)
        self.assertIn(f"dist/{WHEEL}", verify)
        self.assertIn(f"dist/{SDIST}", verify)
        self.assertIn(f"public/downloads/{WHEEL}", verify)
        self.assertIn(f"public/downloads/{SDIST}", verify)
        self.assertIn(f"public/downloads/{MANIFEST}", verify)
        self.assertIn("python -m twine check", verify)
        self.assertIn(f"release-evidence/{MANIFEST}", verify)
        self.assertIn("packages-dir: release/publish", publish)
        self.assertIn("needs: verify-release", publish)
        self.assertNotIn("id-token: write", verify)
        self.assertIn("id-token: write", publish)
        self.assertNotIn("actions/checkout@", publish)
        self.assertIn("actions/upload-artifact@", verify)
        self.assertIn("actions/download-artifact@", publish)
        self.assertIn("release.tag_name", verify)
        self.assertIn('f"v{descriptor[\'version\']}"', verify)
        self.assertIn("ref: ${{ github.sha }}", verify)
        self.assertIn("EVENT_SHA: ${{ github.sha }}", verify)
        self.assertIn("EVENT_REF: ${{ github.ref }}", verify)
        self.assertIn('f"refs/tags/{actual}"', verify)
        self.assertIn('head != os.environ["EVENT_SHA"]', verify)
        self.assertIn("release.prerelease == false", verify)
        self.assertIn("release.draft == false", verify)
        self.assertIn("--require-hashes", verify)
        self.assertIn("--only-binary=:all:", verify)
        self.assertIn("concurrency:", source)
        self.assertNotRegex(source, r"subject-path:\s*[\"']?dist/\*")
        self.assertNotRegex(source, r"uses:\s*[^\s]+@(?:v\d+|release/)\b")
        for workflow in (CI, PUBLISH):
            for reference in re.findall(r"uses:\s*[^\s@]+@([^\s#]+)", workflow.read_text()):
                self.assertRegex(reference, r"^[0-9a-f]{40}$", workflow.as_posix())

    def test_release_tool_lock_is_hash_complete(self):
        source = RELEASE_REQUIREMENTS.read_text(encoding="utf-8")
        self.assertIn("build==1.5.0", source)
        self.assertIn("setuptools==83.0.0", source)
        self.assertIn("twine==7.0.0", source)
        self.assertIn("wheel==0.47.0", source)
        records = re.split(r"\n(?=[a-z0-9][a-z0-9._-]*==)", source.strip())
        self.assertGreaterEqual(len(records), 4)
        for record in records:
            first_line = record.splitlines()[0]
            self.assertRegex(first_line, r"^[a-z0-9][a-z0-9._-]*==[^ ]+ \\$", first_line)
            self.assertRegex(record, r"--hash=sha256:[0-9a-f]{64}", first_line)

    def test_customer_docs_state_the_current_release_and_commercial_boundary(self):
        documents = {
            "README.md": (ROOT / "README.md").read_text(encoding="utf-8"),
            "docs/MCP_QUICKSTART.md": (ROOT / "docs/MCP_QUICKSTART.md").read_text(encoding="utf-8"),
            "apps/heel-cloud/README.md": (ROOT / "apps/heel-cloud/README.md").read_text(encoding="utf-8"),
        }
        combined = "\n".join(documents.values())

        self.assertIn(f"/downloads/{WHEEL}", combined)
        self.assertRegex(combined, r"(?i)not yet (?:available|published) (?:on|to) PyPI")
        self.assertRegex(combined, r"(?i)Apache-2\.0.{0,160}(?:unlimited|usage limit)")
        self.assertRegex(combined, r"(?is)hosted (?:findings )?synchronization.{0,180}paid")
        self.assertRegex(combined, r"(?is)remote MCP.{0,180}paid")
        self.assertRegex(combined, r"(?is)Windows.{0,180}(?:not supported|unsupported)")
        self.assertRegex(combined, r"(?is)public repository.{0,180}release-owner action")
        self.assertNotRegex(combined, r"(?i)Sigstore-signed release provenance")
        self.assertNotIn("gh attestation verify", combined)
        for path in ("docs/MCP_QUICKSTART.md", "apps/heel-cloud/README.md"):
            source = documents[path]
            self.assertIn("Python 3.13", source)
            self.assertIn("PIP_CONFIG_FILE=/dev/null", source)
            self.assertIn("PYTHONNOUSERSITE=1", source)
            self.assertIn("python3.13 -m pip --isolated install", source)
            self.assertIn("--require-hashes --only-binary=:all:", source)


if __name__ == "__main__":
    unittest.main()
