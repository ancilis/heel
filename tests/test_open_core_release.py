"""Fail-closed boundary tests for the Apache-only Heel release contract."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "release/open-core-v1.json"
# Task5 CI must install the PyPA ``build`` frontend, then run this exact command.
STANDARD_BUILD_CI_COMMAND = (
    "HEEL_REQUIRE_STANDARD_BUILD=1 "
    "python -m unittest tests.test_open_core_release -v"
)
FORBIDDEN_PREFIXES = (
    "apps/",
    "deploy/",
    "docs/saas/",
    "docs/superpowers/",
    "heel/saas/",
    "tests/",
    "web/",
)
FORBIDDEN_RELEASE_MARKERS = (
    b"LicenseRef-Heel-Commercial",
    b"LICENSE-COMMERCIAL",
)
FORBIDDEN_DISTRIBUTED_CONTENT_MARKERS = FORBIDDEN_RELEASE_MARKERS + (
    b"apps/heel-cloud",
    b"deploy/",
    b"docs/saas",
    b"docs/superpowers",
    b"heel/saas",
    b"tests/saas",
)
FORBIDDEN_RELEASE_DOC_MARKERS = (
    "apps/",
    "docs/saas",
    "github.com/ancilis/heel",
    "heel/saas",
    "pypi.org/project/heel-sim",
    "pip install heel-sim",
    "tests/",
    "web/",
)
EXPECTED_CONTRACT = {
    "build_files": [
        "MANIFEST.in",
        "pyproject.toml",
        "release/open-core-v1.json",
    ],
    "console_scripts": {
        "heel": "heel.cli:main",
        "heel-mcp": "heel.mcp_server:main",
        "heel-rest": "heel.rest:serve",
    },
    "documents": [
        "release/open-core/MCP_QUICKSTART.md",
        "release/open-core/README.md",
        "release/open-core/SECURITY.md",
    ],
    "licenses": ["DCO", "LICENSE", "NOTICE"],
    "package_data": [
        "heel/heldout/targets.json",
        "heel/scenarios_lib/community.json",
    ],
    "python_modules": [
        "heel/__init__.py",
        "heel/agents.py",
        "heel/agents_human.py",
        "heel/backtest.py",
        "heel/bench.py",
        "heel/blind.py",
        "heel/blind_eval.py",
        "heel/browser_review.py",
        "heel/chaining.py",
        "heel/classify.py",
        "heel/cli.py",
        "heel/containment.py",
        "heel/contracts.py",
        "heel/control.py",
        "heel/control_simulator.py",
        "heel/economics.py",
        "heel/entitlements.py",
        "heel/heldout_eval.py",
        "heel/importers.py",
        "heel/incident.py",
        "heel/launch_review.py",
        "heel/local_projects.py",
        "heel/mcp_server.py",
        "heel/model.py",
        "heel/modes.py",
        "heel/openapi_import.py",
        "heel/openapi_model.py",
        "heel/orchestrator.py",
        "heel/product_model.py",
        "heel/profiles.py",
        "heel/regressions.py",
        "heel/rest.py",
        "heel/review_answers.py",
        "heel/review_contract.py",
        "heel/review_export.py",
        "heel/review_rules.py",
        "heel/review_service.py",
        "heel/scenario_validate.py",
        "heel/scenarios.py",
        "heel/scope.py",
        "heel/semantic.py",
        "heel/static_review.py",
        "heel/store.py",
        "heel/targets.py",
        "heel/web_export.py",
    ],
    "schema_version": "heel.open-core-release.v1",
    "version": "1.1.0",
}
EXPECTED_MANIFEST = """include DCO LICENSE NOTICE
include heel/*.py
include heel/heldout/targets.json
include heel/scenarios_lib/community.json
include release/open-core-v1.json
include release/open-core/MCP_QUICKSTART.md release/open-core/README.md release/open-core/SECURITY.md
exclude LICENSE-COMMERCIAL.md
exclude README.md
exclude heel/heldout/test_targets.json
exclude heel/scenarios_lib/research_owasp.json
prune apps
prune deploy
prune docs/saas
prune docs/superpowers
prune heel/saas
prune tests
prune web
global-exclude __pycache__/*
global-exclude *.pyc
"""


def _standard_build_frontend_available() -> bool:
    """Return whether ``python -m build`` has a real importable entry point."""
    try:
        return importlib.util.find_spec("build.__main__") is not None
    except (AttributeError, ImportError):
        return False


STANDARD_BUILD_FRONTEND_AVAILABLE = _standard_build_frontend_available()
STANDARD_BUILD_REQUIRED = os.environ.get("HEEL_REQUIRE_STANDARD_BUILD") == "1"


def _copy_tracked_snapshot(destination: Path) -> None:
    """Copy tracked files plus newly allowlisted release inputs for pre-commit builds."""
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    relative_paths = {
        os.fsdecode(raw_path)
        for raw_path in result.stdout.split(b"\0")
        if raw_path
    }
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    for field in ("build_files", "documents", "licenses", "package_data", "python_modules"):
        relative_paths.update(contract[field])
    for relative_name in sorted(relative_paths):
        relative = Path(relative_name)
        source = ROOT / relative
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_symlink():
            target.symlink_to(os.readlink(source))
        else:
            shutil.copy2(source, target)


def _assert_contract_path_is_safe(
    test_case: unittest.TestCase,
    path: str,
    *,
    root: Path = ROOT,
) -> None:
    """Require a canonical path whose components never traverse a symlink."""
    normalized = PurePosixPath(path)
    test_case.assertNotIn("\\", path, f"{path}: backslash separators are forbidden")
    test_case.assertEqual(normalized.as_posix(), path)
    test_case.assertFalse(normalized.is_absolute(), path)
    test_case.assertFalse(path.startswith(FORBIDDEN_PREFIXES), path)
    test_case.assertNotIn("..", normalized.parts)
    test_case.assertTrue(normalized.parts, f"{path}: empty path is forbidden")

    candidate = root
    status = None
    for index, part in enumerate(normalized.parts):
        candidate = candidate / part
        try:
            status = candidate.lstat()
        except OSError as error:
            test_case.fail(
                f"{path}: inaccessible path component {part!r}: "
                f"{type(error).__name__}"
            )
        test_case.assertFalse(
            stat.S_ISLNK(status.st_mode),
            f"{path}: symlink component {part!r} is forbidden",
        )
        if index < len(normalized.parts) - 1:
            test_case.assertTrue(
                stat.S_ISDIR(status.st_mode),
                f"{path}: parent component {part!r} is not a directory",
            )

    test_case.assertIsNotNone(status, path)
    test_case.assertTrue(
        stat.S_ISREG(status.st_mode),
        f"{path}: listed source is not a regular file",
    )


class OpenCoreReleaseTests(unittest.TestCase):
    def _run_standard_build_gate_without_frontend(
        self,
        *,
        required: bool,
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory(prefix="heel-build-namespace-") as temporary:
            namespace_root = Path(temporary)
            (namespace_root / "build").mkdir()
            environment = os.environ.copy()
            environment["PYTHONPATH"] = os.pathsep.join(
                (str(namespace_root), str(ROOT))
            )
            if required:
                environment["HEEL_REQUIRE_STANDARD_BUILD"] = "1"
            else:
                environment.pop("HEEL_REQUIRE_STANDARD_BUILD", None)
            return subprocess.run(
                [
                    sys.executable,
                    "-S",
                    "-m",
                    "unittest",
                    (
                        "tests.test_open_core_release.OpenCoreReleaseTests."
                        "test_standard_setuptools_artifacts_preserve_public_boundary"
                    ),
                    "-v",
                ],
                cwd=namespace_root,
                env=environment,
                capture_output=True,
                text=True,
                timeout=120,
            )

    def test_release_contract_is_an_exact_public_allowlist(self):
        self.assertTrue(CONTRACT.is_file(), "release/open-core-v1.json is missing")
        contract_text = CONTRACT.read_text(encoding="utf-8")
        contract = json.loads(contract_text)

        self.assertEqual(contract, EXPECTED_CONTRACT)
        self.assertEqual(
            contract_text,
            json.dumps(
                contract,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ) + "\n",
        )
        self.assertEqual(
            set(contract),
            {
                "build_files",
                "console_scripts",
                "documents",
                "licenses",
                "package_data",
                "python_modules",
                "schema_version",
                "version",
            },
        )
        self.assertEqual(contract["schema_version"], "heel.open-core-release.v1")
        paths = (
            contract["build_files"]
            + contract["python_modules"]
            + contract["package_data"]
            + contract["documents"]
            + contract["licenses"]
        )
        self.assertEqual(len(paths), len(set(paths)))
        for path in paths:
            _assert_contract_path_is_safe(self, path)

        actual_python_modules = {
            path.relative_to(ROOT).as_posix()
            for path in (ROOT / "heel").glob("*.py")
            if path.is_file()
        }
        self.assertEqual(actual_python_modules, set(contract["python_modules"]))

        with (ROOT / "pyproject.toml").open("rb") as file:
            pyproject = tomllib.load(file)
        project = pyproject["project"]
        self.assertEqual(
            project["description"],
            "Privacy-first local SaaS launch review for browser, CLI, and MCP workflows.",
        )
        self.assertEqual(project["readme"], "release/open-core/README.md")
        self.assertNotIn("urls", project)
        setuptools = pyproject["tool"]["setuptools"]
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
        self.assertEqual(
            {f"heel/{path}" for path in setuptools["package-data"]["heel"]},
            set(contract["package_data"]),
        )
        self.assertEqual(
            (ROOT / "MANIFEST.in").read_text(encoding="utf-8"),
            EXPECTED_MANIFEST,
        )

    def test_release_docs_are_self_contained_and_avoid_private_commands(self):
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        documents = set(contract["documents"])
        missing_links: dict[str, list[str]] = {}

        for source in contract["documents"]:
            source_path = ROOT / source
            text = source_path.read_text(encoding="utf-8")
            for destination in re.findall(r"\[[^]]*\]\(([^)]+)\)", text):
                destination = destination.split("#", 1)[0].strip()
                if not destination or "://" in destination or destination.startswith("mailto:"):
                    continue
                target = (source_path.parent / destination).resolve()
                try:
                    relative = target.relative_to(ROOT.resolve()).as_posix()
                except ValueError:
                    self.fail(f"release doc link escapes the repository: {source} -> {destination}")
                if relative.endswith(".md") and relative not in documents:
                    missing_links.setdefault(relative, []).append(source)

            fenced_blocks = re.findall(r"```[^\n]*\n(.*?)```", text, flags=re.DOTALL)
            for block in fenced_blocks:
                for marker in FORBIDDEN_RELEASE_DOC_MARKERS:
                    self.assertNotIn(marker, block, f"{source}: {marker}")
            for marker in FORBIDDEN_RELEASE_DOC_MARKERS:
                self.assertNotIn(marker, text, f"{source}: {marker}")

        self.assertEqual(missing_links, {})
        readme = (ROOT / "release/open-core/README.md").read_text(encoding="utf-8")
        readme_prose = " ".join(readme.split())
        self.assertIn(
            "`heel-mcp` itself does not upload the OpenAPI document",
            readme_prose,
        )
        self.assertIn(
            "AI client or model provider may receive or upload the document before invoking Heel",
            readme_prose,
        )
        self.assertIn("Heel cannot enforce that upstream boundary", readme_prose)

    def test_contract_path_validation_rejects_backslashes(self):
        with self.assertRaisesRegex(AssertionError, "backslash"):
            _assert_contract_path_is_safe(self, r"heel\cli.py")

    def test_contract_path_validation_rejects_symlinked_components(self):
        with tempfile.TemporaryDirectory(prefix="heel-contract-symlink-") as temporary:
            root = Path(temporary)
            (root / "real.py").write_text("pass\n", encoding="utf-8")
            (root / "heel").mkdir()
            (root / "heel/cli.py").symlink_to(root / "real.py")
            with self.assertRaisesRegex(AssertionError, "symlink"):
                _assert_contract_path_is_safe(self, "heel/cli.py", root=root)

            parent_root = root / "parent-case"
            parent_root.mkdir()
            real_package = root / "real-package"
            real_package.mkdir()
            (real_package / "cli.py").write_text("pass\n", encoding="utf-8")
            (parent_root / "heel").symlink_to(real_package, target_is_directory=True)
            with self.assertRaisesRegex(AssertionError, "symlink"):
                _assert_contract_path_is_safe(
                    self,
                    "heel/cli.py",
                    root=parent_root,
                )

    def test_namespace_only_build_package_skips_optional_frontend_integration(self):
        result = self._run_standard_build_gate_without_frontend(required=False)
        output = result.stdout + result.stderr

        self.assertEqual(result.returncode, 0, output)
        self.assertIn("skipped", output)
        self.assertIn("build.__main__", output)

    def test_required_standard_build_fails_when_frontend_is_absent(self):
        result = self._run_standard_build_gate_without_frontend(required=True)
        output = result.stdout + result.stderr

        self.assertNotEqual(result.returncode, 0, output)
        self.assertIn(
            "HEEL_REQUIRE_STANDARD_BUILD=1 requires importable build.__main__",
            output,
        )
        self.assertNotIn("skipped", output)

    @unittest.skipUnless(
        STANDARD_BUILD_FRONTEND_AVAILABLE or STANDARD_BUILD_REQUIRED,
        "optional integration requires importable build.__main__; Task5 CI: "
        + STANDARD_BUILD_CI_COMMAND,
    )
    def test_standard_setuptools_artifacts_preserve_public_boundary(self):
        self.assertTrue(
            STANDARD_BUILD_FRONTEND_AVAILABLE,
            "HEEL_REQUIRE_STANDARD_BUILD=1 requires importable build.__main__; "
            "install the PyPA build frontend. Task5 CI: "
            + STANDARD_BUILD_CI_COMMAND,
        )
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        dist_info = "heel_sim-1.1.0.dist-info"

        with tempfile.TemporaryDirectory(prefix="heel-open-core-build-") as temporary:
            temporary_path = Path(temporary)
            source = temporary_path / "source"
            dist = temporary_path / "dist"
            source.mkdir()
            _copy_tracked_snapshot(source)
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "build",
                    "--no-isolation",
                    "--outdir",
                    str(dist),
                    str(source),
                ],
                cwd=source,
                check=False,
                capture_output=True,
                text=True,
                timeout=120,
            )
            self.assertEqual(
                result.returncode,
                0,
                result.stdout + "\n" + result.stderr,
            )

            wheels = list(dist.glob("*.whl"))
            sdists = list(dist.glob("*.tar.gz"))
            self.assertEqual(len(wheels), 1, wheels)
            self.assertEqual(len(sdists), 1, sdists)

            expected_wheel_files = set(contract["python_modules"])
            expected_wheel_files.update(contract["package_data"])
            expected_wheel_files.update(
                {
                    f"{dist_info}/METADATA",
                    f"{dist_info}/RECORD",
                    f"{dist_info}/WHEEL",
                    f"{dist_info}/entry_points.txt",
                    f"{dist_info}/licenses/LICENSE",
                    f"{dist_info}/licenses/NOTICE",
                    f"{dist_info}/top_level.txt",
                }
            )
            with zipfile.ZipFile(wheels[0]) as wheel:
                wheel_files = wheel.namelist()
                self.assertEqual(len(wheel_files), len(set(wheel_files)))
                self.assertEqual(set(wheel_files), expected_wheel_files)
                for path in wheel_files:
                    self.assertFalse(path.startswith(FORBIDDEN_PREFIXES), path)
                metadata = wheel.read(f"{dist_info}/METADATA")
                self.assertEqual(
                    [
                        line
                        for line in metadata.decode("utf-8").splitlines()
                        if line.startswith("License-File: ")
                    ],
                    ["License-File: LICENSE", "License-File: NOTICE"],
                )
                for path in wheel_files:
                    contents = wheel.read(path)
                    for marker in FORBIDDEN_DISTRIBUTED_CONTENT_MARKERS:
                        self.assertNotIn(marker, contents, path)

            sdist_prefix = f"heel_sim-{contract['version']}/"
            expected_sdist_files = {
                *contract["build_files"],
                *contract["documents"],
                *contract["licenses"],
                *contract["python_modules"],
                *contract["package_data"],
                "PKG-INFO",
                "setup.cfg",
                "heel_sim.egg-info/PKG-INFO",
                "heel_sim.egg-info/SOURCES.txt",
                "heel_sim.egg-info/dependency_links.txt",
                "heel_sim.egg-info/entry_points.txt",
                "heel_sim.egg-info/requires.txt",
                "heel_sim.egg-info/top_level.txt",
            }
            with tarfile.open(sdists[0], "r:gz") as sdist:
                members = sdist.getmembers()
                self.assertFalse(
                    [member.name for member in members if member.issym() or member.islnk()]
                )
                sdist_files = [member for member in members if member.isfile()]
                names = [member.name for member in sdist_files]
                self.assertEqual(len(names), len(set(names)))
                for name in names:
                    self.assertTrue(name.startswith(sdist_prefix), name)
                relative_files = {name.removeprefix(sdist_prefix) for name in names}
                self.assertEqual(relative_files, expected_sdist_files)
                for path in relative_files:
                    self.assertFalse(path.startswith(FORBIDDEN_PREFIXES), path)
                    self.assertNotIn("LICENSE-COMMERCIAL", path)
                for member in sdist_files:
                    file = sdist.extractfile(member)
                    self.assertIsNotNone(file, member.name)
                    contents = file.read()
                    if member.name == sdist_prefix + "MANIFEST.in":
                        self.assertEqual(contents.count(b"LICENSE-COMMERCIAL"), 1)
                        self.assertNotIn(b"LicenseRef-Heel-Commercial", contents)
                        continue
                    for marker in FORBIDDEN_DISTRIBUTED_CONTENT_MARKERS:
                        self.assertNotIn(marker, contents, member.name)


if __name__ == "__main__":
    unittest.main()
