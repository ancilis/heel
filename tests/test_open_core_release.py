"""Fail-closed boundary tests for the Apache-only Heel release contract."""
from __future__ import annotations

import base64
import csv
from email import policy
from email.parser import BytesParser
import gzip
import hashlib
import importlib.metadata
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import unittest
from unittest import mock
import zipfile


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "release/open-core-v1.json"
BUILDER = ROOT / "scripts/build_open_core_release.py"
WHEEL = "heel_sim-1.2.0-py3-none-any.whl"
SDIST = "heel_sim-1.2.0.tar.gz"
ARTIFACT_MANIFEST = "heel-open-core-manifest.json"
DIST_INFO = "heel_sim-1.2.0.dist-info"
RECORD_PATH = f"{DIST_INFO}/RECORD"
FIXED_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
EXPECTED_METADATA = (
    "Metadata-Version: 2.4\n"
    "Name: heel-sim\n"
    "Version: 1.2.0\n"
    "Summary: Privacy-first local SaaS launch review for browser, CLI, and MCP workflows.\n"
    "Requires-Python: >=3.11\n"
    "License-Expression: Apache-2.0\n"
    "License-File: LICENSE\n"
    "License-File: NOTICE\n"
    "Provides-Extra: runner\n"
    "Requires-Dist: cryptography==45.0.7; extra == \"runner\"\n"
    "\n"
).encode("utf-8")
EXPECTED_WHEEL_METADATA = (
    "Wheel-Version: 1.0\n"
    "Generator: heel-open-core-release\n"
    "Root-Is-Purelib: true\n"
    "Tag: py3-none-any\n"
    "\n"
).encode("utf-8")
EXPECTED_ENTRY_POINTS = (
    "[console_scripts]\n"
    "heel = heel.cli:main\n"
    "heel-mcp = heel.mcp_server:main\n"
    "heel-rest = heel.rest:serve\n"
).encode("utf-8")
EXPECTED_GZIP_HEADER = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff"
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_MEMBER_BYTES = 4 * 1024 * 1024
MAX_TOTAL_MEMBER_BYTES = 24 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 128
MIN_SETUPTOOLS_MAJOR = 77
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
        "heel/heldout/test_targets.json",
        "heel/scenarios_lib/community.json",
        "heel/scenarios_lib/research_owasp.json",
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
        "heel/business_rules.py",
        "heel/canary_contracts.py",
        "heel/chaining.py",
        "heel/classify.py",
        "heel/cli.py",
        "heel/cloud_auth.py",
        "heel/cloud_client.py",
        "heel/containment.py",
        "heel/contracts.py",
        "heel/control.py",
        "heel/control_simulator.py",
        "heel/crypto.py",
        "heel/economics.py",
        "heel/entitlements.py",
        "heel/findings_sync.py",
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
        "heel/reference_product.py",
        "heel/reference_rehearsal.py",
        "heel/regressions.py",
        "heel/rest.py",
        "heel/review_answers.py",
        "heel/review_contract.py",
        "heel/review_export.py",
        "heel/review_rules.py",
        "heel/review_service.py",
        "heel/runner/__init__.py",
        "heel/runner/adapters.py",
        "heel/runner/catalog.py",
        "heel/runner/companion.py",
        "heel/runner/compiler.py",
        "heel/runner/containment.py",
        "heel/runner/content_assertion.py",
        "heel/runner/control_client.py",
        "heel/runner/coordinator.py",
        "heel/runner/execution.py",
        "heel/runner/http_transport.py",
        "heel/runner/identity.py",
        "heel/runner/openapi_routes.py",
        "heel/runner/redaction.py",
        "heel/runner/runtime.py",
        "heel/runner/service.py",
        "heel/runner/store.py",
        "heel/runner/vault.py",
        "heel/scenario_validate.py",
        "heel/scenarios.py",
        "heel/scope.py",
        "heel/semantic.py",
        "heel/static_review.py",
        "heel/store.py",
        "heel/sync_queue.py",
        "heel/targets.py",
        "heel/web_export.py",
    ],
    "schema_version": "heel.open-core-release.v1",
    "version": "1.2.0",
}
EXPECTED_MANIFEST = """include DCO LICENSE NOTICE
include heel/*.py
include heel/runner/*.py
include heel/heldout/targets.json
include heel/scenarios_lib/community.json
include release/open-core-v1.json
include release/open-core/MCP_QUICKSTART.md release/open-core/README.md release/open-core/SECURITY.md
exclude LICENSE-COMMERCIAL.md
exclude README.md
include heel/heldout/test_targets.json
include heel/scenarios_lib/research_owasp.json
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


def _run_release_builder(
    output: Path,
    *,
    builder: Path = BUILDER,
    check: bool = False,
    hash_seed: str = "1",
    locale: str = "C",
    process_umask: int = 0o022,
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment.pop("PYTHONHOME", None)
    environment.pop("PYTHONPATH", None)
    environment.update(
        {
            "LANG": locale,
            "LC_ALL": locale,
            "PYTHONHASHSEED": hash_seed,
            "PYTHONNOUSERSITE": "1",
        }
    )
    launcher = (
        "import os,runpy,sys;"
        "mask=int(sys.argv.pop(1),8);"
        "script=sys.argv[1];"
        "sys.argv=sys.argv[1:];"
        "os.umask(mask);"
        "runpy.run_path(script,run_name='__main__')"
    )
    command = [
        sys.executable,
        "-I",
        "-c",
        launcher,
        f"{process_umask:o}",
        str(builder),
        "--output",
        str(output),
    ]
    if check:
        command.append("--check")
    return subprocess.run(
        command,
        cwd=output.parent,
        env=environment,
        capture_output=True,
        text=True,
        timeout=120,
    )


def _copy_public_builder_snapshot(destination: Path) -> None:
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    paths = {"scripts/build_open_core_release.py"}
    for field in ("build_files", "documents", "licenses", "package_data", "python_modules"):
        paths.update(contract[field])
    for relative_name in sorted(paths):
        source = ROOT / relative_name
        target = destination / relative_name
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_symlink():
            target.symlink_to(os.readlink(source))
        else:
            shutil.copy2(source, target)


def _assert_safe_archive_name(test_case: unittest.TestCase, name: str) -> None:
    normalized = PurePosixPath(name)
    test_case.assertNotIn("\\", name, name)
    test_case.assertFalse(normalized.is_absolute(), name)
    test_case.assertNotIn("..", normalized.parts, name)
    test_case.assertEqual(normalized.as_posix(), name)
    test_case.assertTrue(normalized.parts, name)
    lower_name = name.lower()
    test_case.assertFalse(
        lower_name == ".env" or "/.env" in lower_name,
        name,
    )
    test_case.assertFalse(
        lower_name.endswith((".key", ".pem", ".crt", ".cer", ".p12", ".pfx")),
        name,
    )


def _assert_public_payload(
    test_case: unittest.TestCase,
    name: str,
    payload: bytes,
) -> None:
    _assert_safe_archive_name(test_case, name)
    test_case.assertLessEqual(len(payload), MAX_MEMBER_BYTES, name)
    if name.endswith("MANIFEST.in"):
        test_case.assertEqual(payload.count(b"LICENSE-COMMERCIAL"), 1, name)
        test_case.assertNotIn(b"LicenseRef-Heel-Commercial", payload, name)
        return
    for marker in FORBIDDEN_DISTRIBUTED_CONTENT_MARKERS:
        test_case.assertNotIn(marker, payload, name)
    for pattern in (
        rb"AKIA[0-9A-Z]{16}",
        rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----",
        rb"(?i)(?:api[_-]?key|secret|token)\s*[:=]\s*['\"][A-Za-z0-9+/=_-]{24,}",
    ):
        test_case.assertIsNone(re.search(pattern, payload), name)


def _record_digest(payload: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest())
    return "sha256=" + digest.rstrip(b"=").decode("ascii")


def _read_bounded_path(path: Path, limit: int, label: str) -> bytes:
    size = path.stat().st_size
    if size > limit:
        raise AssertionError(f"{label} exceeds the byte limit")
    with path.open("rb") as stream:
        payload = stream.read(limit + 1)
    if len(payload) > limit:
        raise AssertionError(f"{label} exceeds the byte limit")
    return payload


def _assert_bounded_zip_eocd(test_case: unittest.TestCase, payload: bytes) -> int:
    test_case.assertGreaterEqual(len(payload), 22)
    fields = struct.unpack("<IHHHHIIH", payload[-22:])
    test_case.assertEqual(fields[0], 0x06054B50)
    test_case.assertEqual(fields[1:3], (0, 0))
    test_case.assertEqual(fields[3], fields[4])
    test_case.assertLessEqual(fields[4], MAX_ARCHIVE_MEMBERS)
    test_case.assertNotEqual(fields[5], 0xFFFFFFFF)
    test_case.assertNotEqual(fields[6], 0xFFFFFFFF)
    test_case.assertEqual(fields[7], 0)
    test_case.assertEqual(fields[5] + fields[6], len(payload) - 22)
    return fields[4]


def _bounded_tar_members_for_test(
    test_case: unittest.TestCase,
    archive: tarfile.TarFile,
) -> list[tarfile.TarInfo]:
    members: list[tarfile.TarInfo] = []
    for member in archive:
        test_case.assertLess(len(members), MAX_ARCHIVE_MEMBERS)
        members.append(member)
    return members


def _bounded_gzip_decompress(payload: bytes, limit: int) -> bytes:
    with gzip.GzipFile(fileobj=io.BytesIO(payload), mode="rb") as stream:
        expanded = stream.read(limit + 1)
    if len(expanded) > limit:
        raise AssertionError("source archive expands beyond the total limit")
    return expanded


def _load_builder_module():
    specification = importlib.util.spec_from_file_location(
        "heel_open_core_release_builder_for_test",
        BUILDER,
    )
    if specification is None or specification.loader is None:
        raise AssertionError("release builder cannot be imported")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _assert_record_is_valid(
    test_case: unittest.TestCase,
    payloads: dict[str, bytes],
    *,
    exact_order: bool,
) -> None:
    rows = list(csv.reader(io.StringIO(payloads[RECORD_PATH].decode("utf-8"))))
    expected_paths = [*sorted(path for path in payloads if path != RECORD_PATH), RECORD_PATH]
    if exact_order:
        test_case.assertEqual([row[0] for row in rows], expected_paths)
    else:
        test_case.assertEqual({row[0] for row in rows}, set(expected_paths))
        test_case.assertEqual(rows[-1][0], RECORD_PATH)
    test_case.assertEqual(len(rows), len({row[0] for row in rows}))
    for row in rows[:-1]:
        test_case.assertEqual(len(row), 3, row)
        name, digest, size = row
        test_case.assertEqual(digest, _record_digest(payloads[name]), name)
        test_case.assertNotIn("=", digest.removeprefix("sha256="), name)
        test_case.assertEqual(size, str(len(payloads[name])), name)
    test_case.assertEqual(rows[-1], [RECORD_PATH, "", ""])


def _assert_wheel_is_bounded_and_canonical(
    test_case: unittest.TestCase,
    wheel_path: Path,
    expected_names: set[str],
) -> dict[str, bytes]:
    raw = _read_bounded_path(wheel_path, MAX_ARCHIVE_BYTES, "wheel")
    expected_member_count = _assert_bounded_zip_eocd(test_case, raw)
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        test_case.assertEqual(archive.comment, b"")
        infos = archive.infolist()
        test_case.assertEqual(len(infos), expected_member_count)
        test_case.assertLessEqual(len(infos), MAX_ARCHIVE_MEMBERS)
        names = [info.filename for info in infos]
        test_case.assertEqual(names, [*sorted(expected_names - {RECORD_PATH}), RECORD_PATH])
        test_case.assertEqual(len(names), len(set(names)))
        payloads: dict[str, bytes] = {}
        total_size = 0
        for info in infos:
            _assert_safe_archive_name(test_case, info.filename)
            test_case.assertFalse(info.is_dir(), info.filename)
            test_case.assertEqual(info.date_time, FIXED_ZIP_TIMESTAMP, info.filename)
            test_case.assertEqual(info.compress_type, zipfile.ZIP_STORED, info.filename)
            test_case.assertEqual(info.flag_bits, 0, info.filename)
            test_case.assertEqual(info.extra, b"", info.filename)
            test_case.assertEqual(info.comment, b"", info.filename)
            test_case.assertLessEqual(info.extract_version, 20, info.filename)
            test_case.assertEqual(info.create_system, 3, info.filename)
            test_case.assertEqual(info.external_attr >> 16, stat.S_IFREG | 0o644, info.filename)
            test_case.assertLessEqual(info.file_size, MAX_MEMBER_BYTES, info.filename)
            test_case.assertEqual(info.compress_size, info.file_size, info.filename)
            test_case.assertLessEqual(
                total_size + info.file_size,
                MAX_TOTAL_MEMBER_BYTES,
                info.filename,
            )
            payload = archive.read(info)
            test_case.assertEqual(info.CRC, __import__("zlib").crc32(payload) & 0xFFFFFFFF)
            payloads[info.filename] = payload
            total_size += len(payload)

            local_header = raw[info.header_offset:info.header_offset + 30]
            test_case.assertEqual(len(local_header), 30, info.filename)
            fields = struct.unpack("<IHHHHHIIIHH", local_header)
            test_case.assertEqual(fields[0], 0x04034B50, info.filename)
            test_case.assertLessEqual(fields[1], 20, info.filename)
            test_case.assertEqual(fields[2:6], (0, 0, 0, 33), info.filename)
            test_case.assertEqual(fields[6:9], (info.CRC, info.file_size, info.file_size))
            name_length, extra_length = fields[9:11]
            encoded_name = raw[
                info.header_offset + 30:info.header_offset + 30 + name_length
            ]
            test_case.assertEqual(encoded_name, info.filename.encode("utf-8"))
            test_case.assertEqual(extra_length, 0, info.filename)
        test_case.assertLessEqual(total_size, MAX_TOTAL_MEMBER_BYTES)
    _assert_record_is_valid(test_case, payloads, exact_order=True)
    return payloads


def _normalized_wheel(
    test_case: unittest.TestCase,
    wheel_path: Path,
    expected_names: set[str],
    *,
    canonical: bool,
) -> tuple[dict[str, bytes], tuple[tuple[str, tuple[str, ...]], ...]]:
    if canonical:
        payloads = _assert_wheel_is_bounded_and_canonical(
            test_case,
            wheel_path,
            expected_names,
        )
    else:
        raw = _read_bounded_path(wheel_path, MAX_ARCHIVE_BYTES, "rebuilt wheel")
        expected_member_count = _assert_bounded_zip_eocd(test_case, raw)
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            infos = archive.infolist()
            test_case.assertEqual(len(infos), expected_member_count)
            names = [info.filename for info in infos]
            test_case.assertEqual(set(names), expected_names)
            test_case.assertEqual(len(names), len(set(names)))
            payloads = {}
            total_size = 0
            for info in infos:
                _assert_safe_archive_name(test_case, info.filename)
                test_case.assertFalse(info.flag_bits & 0x1, info.filename)
                test_case.assertLessEqual(info.file_size, MAX_MEMBER_BYTES, info.filename)
                test_case.assertLessEqual(
                    total_size + info.file_size,
                    MAX_TOTAL_MEMBER_BYTES,
                    info.filename,
                )
                payloads[info.filename] = archive.read(info)
                total_size += info.file_size
            test_case.assertLessEqual(total_size, MAX_TOTAL_MEMBER_BYTES)
        _assert_record_is_valid(test_case, payloads, exact_order=False)
    message = BytesParser(policy=policy.default).parsebytes(
        payloads[f"{DIST_INFO}/METADATA"]
    )
    wheel_message = BytesParser(policy=policy.default).parsebytes(
        payloads[f"{DIST_INFO}/WHEEL"]
    )
    metadata = tuple(
        (name, tuple(message.get_all(name, [])))
        for name in (
            "Metadata-Version",
            "Name",
            "Version",
            "Summary",
            "Requires-Python",
            "License",
            "License-Expression",
            "License-File",
            "Requires-Dist",
            "Provides-Extra",
        )
    ) + tuple(
        (f"WHEEL:{name}", tuple(wheel_message.get_all(name, [])))
        for name in ("Wheel-Version", "Root-Is-Purelib", "Tag")
    )
    substantive = {
        name: payload
        for name, payload in payloads.items()
        if name not in {f"{DIST_INFO}/METADATA", f"{DIST_INFO}/WHEEL", RECORD_PATH}
    }
    return substantive, metadata


def _tree_state(path: Path) -> dict[str, tuple[int, int, int, bytes | str | None]]:
    if not path.exists() and not path.is_symlink():
        return {}
    state: dict[str, tuple[int, int, int, bytes | str | None]] = {}
    for candidate in [path, *sorted(path.rglob("*"))]:
        relative = "." if candidate == path else candidate.relative_to(path).as_posix()
        status = candidate.lstat()
        content: bytes | str | None = None
        if stat.S_ISREG(status.st_mode):
            content = candidate.read_bytes()
        elif stat.S_ISLNK(status.st_mode):
            content = os.readlink(candidate)
        state[relative] = (status.st_mode, status.st_size, status.st_mtime_ns, content)
    return state


def _isolated_environment(root: Path) -> dict[str, str]:
    environment = os.environ.copy()
    environment.pop("PYTHONHOME", None)
    environment.pop("PYTHONPATH", None)
    environment.update(
        {
            "HEEL_HOME": str(root / "heel-home"),
            "HOME": str(root / "home"),
            "PIP_CONFIG_FILE": os.devnull,
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_NO_CACHE_DIR": "1",
            "PYTHONNOUSERSITE": "1",
        }
    )
    return environment


def _provision_local_build_tools(
    venv_python: Path,
    *,
    cwd: Path,
    environment: dict[str, str],
) -> None:
    purelib_result = subprocess.run(
        [
            str(venv_python),
            "-I",
            "-c",
            "import sysconfig; print(sysconfig.get_path('purelib'))",
        ],
        cwd=cwd,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    purelib = Path(purelib_result.stdout.strip())
    for distribution_name in ("setuptools", "wheel"):
        distribution = importlib.metadata.distribution(distribution_name)
        distribution_root = Path(distribution.locate_file(""))
        for package_path in distribution.files or ():
            relative = PurePosixPath(str(package_path))
            if relative.is_absolute() or ".." in relative.parts:
                continue
            source = Path(distribution.locate_file(package_path))
            if not source.is_file():
                continue
            source.relative_to(distribution_root)
            destination = purelib.joinpath(*relative.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)


def _require_local_build_tools(test_case: unittest.TestCase) -> None:
    missing: list[str] = []
    for distribution_name in ("setuptools", "wheel"):
        try:
            distribution = importlib.metadata.distribution(distribution_name)
        except importlib.metadata.PackageNotFoundError:
            missing.append(distribution_name)
            continue
        if distribution_name == "setuptools":
            try:
                major = int(distribution.version.split(".", 1)[0])
            except ValueError:
                missing.append(f"setuptools>={MIN_SETUPTOOLS_MAJOR}")
            else:
                if major < MIN_SETUPTOOLS_MAJOR:
                    missing.append(f"setuptools>={MIN_SETUPTOOLS_MAJOR}")
    if not missing:
        return
    message = (
        "clean source rebuild requires locally installed release tooling: "
        + ", ".join(missing)
    )
    if STANDARD_BUILD_REQUIRED:
        test_case.fail(message)
    test_case.skipTest(message)


class OpenCoreReleaseTests(unittest.TestCase):
    def _assert_mutated_snapshot_is_rejected(
        self,
        mutation,
        expected_message: str,
    ) -> None:
        self.assertTrue(BUILDER.is_file(), "scripts/build_open_core_release.py is missing")
        with tempfile.TemporaryDirectory(prefix="heel-open-core-mutation-") as temporary:
            temporary_path = Path(temporary).resolve()
            source = temporary_path / "source"
            source.mkdir()
            _copy_public_builder_snapshot(source)
            mutation(source)
            result = _run_release_builder(
                temporary_path / "output",
                builder=source / "scripts/build_open_core_release.py",
            )
            output = result.stdout + result.stderr
            self.assertNotEqual(result.returncode, 0, output)
            self.assertIn(expected_message.lower(), output.lower())

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

    def test_release_smoke_inspects_the_open_core_runner_boundary(self):
        """The smoke harness must not require hosted modules from this wheel."""
        from scripts.release_smoke import _inspect_wheel

        with tempfile.TemporaryDirectory(prefix="heel-release-smoke-boundary-") as temporary:
            wheel = Path(temporary) / "open-core.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                for name in (
                    "heel/__init__.py", "heel/cli.py", "heel/mcp_server.py",
                    "heel/runner/__init__.py", "heel/runner/runtime.py",
                ):
                    archive.writestr(name, b"")
            _inspect_wheel(wheel)

    def test_release_smoke_bootstraps_an_isolated_uv_environment(self):
        """The smoke must neither seed a venv nor install from the source tree."""
        from scripts import release_smoke

        class StopAfterInstall(RuntimeError):
            pass

        def create_environment(root: Path) -> None:
            scripts = root / ("Scripts" if os.name == "nt" else "bin")
            scripts.mkdir(parents=True)
            (scripts / ("python.exe" if os.name == "nt" else "python")).symlink_to(
                Path(sys.executable).resolve()
            )

        class FakeVenvBuilder:
            def __init__(self, **_: object) -> None:
                pass

            def create(self, root: Path) -> None:
                create_environment(root)

        with tempfile.TemporaryDirectory(prefix="heel-release-smoke-uv-") as temporary:
            scratch = Path(temporary)
            environment_root = scratch / "environment"
            wheel = scratch / "heel_sim-1.2.0-py3-none-any.whl"
            wheel.write_bytes(b"wheel")
            commands: list[list[str]] = []
            base_python = Path(sys.executable).resolve()

            def record(command: list[str], **_: object) -> subprocess.CompletedProcess[str]:
                commands.append(command)
                if command[:3] == ["uv", "python", "find"]:
                    return subprocess.CompletedProcess(command, 0, f"{base_python}\n", "")
                if command[:2] == ["uv", "venv"]:
                    create_environment(Path(command[-1]))
                if command[:2] == ["uv", "pip"] or command[1:3] == ["-m", "pip"]:
                    raise StopAfterInstall
                return subprocess.CompletedProcess(command, 0, "", "")

            with (
                mock.patch.object(release_smoke, "_run", side_effect=record),
                mock.patch.object(release_smoke.shutil, "which", return_value="uv"),
                mock.patch("venv.EnvBuilder", FakeVenvBuilder),
                self.assertRaises(StopAfterInstall),
            ):
                release_smoke._exercise_installed_wheel(
                    wheel,
                    scratch,
                    environment_root,
                    scratch,
                )

            python = environment_root / ("Scripts" if os.name == "nt" else "bin") / (
                "python.exe" if os.name == "nt" else "python"
            )
            self.assertEqual(
                commands,
                [
                    ["uv", "python", "find", "--system", "--resolve-links", "--no-project",
                     "--no-config", "--no-python-downloads", "--offline", ">=3.11"],
                    ["uv", "venv", "--no-project", "--no-config", "--no-python-downloads",
                     "--offline", "--no-cache", "--python", str(base_python),
                     str(environment_root.resolve())],
                    [
                        "uv", "pip", "install", "--no-config", "--no-python-downloads",
                        "--offline", "--no-cache", "--no-index", "--python", str(python.absolute()),
                        "--no-deps", str(wheel.resolve()),
                    ],
                ],
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
            for path in (ROOT / "heel").rglob("*.py")
            if "saas" not in path.relative_to(ROOT / "heel").parts
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
        self.assertEqual(project["license"], "Apache-2.0")
        self.assertEqual(project["license-files"], ["LICENSE", "NOTICE"])
        self.assertFalse(
            any(classifier.startswith("License ::") for classifier in project["classifiers"])
        )
        self.assertNotIn("urls", project)
        setuptools = pyproject["tool"]["setuptools"]
        self.assertEqual(
            setuptools,
            {
                "include-package-data": False,
                "packages": ["heel", "heel.runner"],
                "package-data": {
                    "heel": [
                        "heldout/targets.json",
                        "heldout/test_targets.json",
                        "scenarios_lib/community.json",
                        "scenarios_lib/research_owasp.json",
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

    def test_checked_in_runner_artifacts_match_the_current_public_pairing_and_recovery_api(self):
        """The downloadable wheel and sdist must not lag any public runner API."""
        downloads = ROOT / "apps" / "heel-cloud" / "public" / "downloads"
        sources = {
            f"heel/runner/{name}": (ROOT / "heel" / "runner" / name).read_bytes()
            for name in (
                "__init__.py", "adapters.py", "catalog.py", "companion.py", "compiler.py",
                "containment.py", "control_client.py", "coordinator.py", "execution.py", "http_transport.py",
                "identity.py", "openapi_routes.py", "redaction.py", "runtime.py", "service.py", "store.py",
                "vault.py",
            )
        }
        for required in (
            b"def runner_phrase_words", b"class SystemSecureSigner",
            b"def create_runner_pairing_material", b"def bind_runner_identity",
        ):
            self.assertIn(required, sources["heel/runner/identity.py"])
        for required in (
            b"class PendingRunnerResync", b"class RecoveredRunnerChain",
            b"class RunnerRotationActivated", b"def install_rotation_claim",
        ):
            self.assertIn(required, sources["heel/runner/control_client.py"])
        with zipfile.ZipFile(downloads / WHEEL) as wheel:
            for name, source in sources.items():
                self.assertEqual(wheel.read(name), source)
        with tarfile.open(downloads / SDIST, "r:gz") as archive:
            for name, source in sources.items():
                stream = archive.extractfile(f"heel_sim-1.2.0/{name}")
                self.assertIsNotNone(stream)
                self.assertEqual(stream.read(), source)

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

    def test_build_is_deterministic_and_exact(self):
        self.assertTrue(BUILDER.is_file(), "scripts/build_open_core_release.py is missing")
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        expected_wheel_names = {
            *contract["python_modules"],
            *contract["package_data"],
            f"{DIST_INFO}/METADATA",
            f"{DIST_INFO}/WHEEL",
            f"{DIST_INFO}/entry_points.txt",
            f"{DIST_INFO}/licenses/LICENSE",
            f"{DIST_INFO}/licenses/NOTICE",
            f"{DIST_INFO}/top_level.txt",
            RECORD_PATH,
        }
        sdist_relative_names = {
            *contract["build_files"],
            *contract["documents"],
            *contract["licenses"],
            *contract["package_data"],
            *contract["python_modules"],
            "PKG-INFO",
        }

        with tempfile.TemporaryDirectory(prefix="heel-open-core-artifacts-") as temporary:
            temporary_path = Path(temporary).resolve()
            first = temporary_path / "first"
            second = temporary_path / "second"
            first_result = _run_release_builder(
                first,
                hash_seed="1",
                locale="C",
                process_umask=0o022,
            )
            second_result = _run_release_builder(
                second,
                hash_seed="8675309",
                locale="en_US.UTF-8",
                process_umask=0o077,
            )
            self.assertEqual(
                first_result.returncode,
                0,
                first_result.stdout + first_result.stderr,
            )
            self.assertEqual(
                second_result.returncode,
                0,
                second_result.stdout + second_result.stderr,
            )
            expected_artifacts = {WHEEL, SDIST, ARTIFACT_MANIFEST}
            self.assertEqual({path.name for path in first.iterdir()}, expected_artifacts)
            self.assertEqual({path.name for path in second.iterdir()}, expected_artifacts)
            for name in expected_artifacts:
                limit = MAX_MEMBER_BYTES if name == ARTIFACT_MANIFEST else MAX_ARCHIVE_BYTES
                self.assertEqual(
                    _read_bounded_path(first / name, limit, name),
                    _read_bounded_path(second / name, limit, name),
                    name,
                )
                self.assertEqual(stat.S_IMODE((first / name).stat().st_mode), 0o644, name)

            wheel_payloads = _assert_wheel_is_bounded_and_canonical(
                self,
                first / WHEEL,
                expected_wheel_names,
            )
            self.assertEqual(wheel_payloads[f"{DIST_INFO}/METADATA"], EXPECTED_METADATA)
            self.assertEqual(
                wheel_payloads[f"{DIST_INFO}/WHEEL"],
                EXPECTED_WHEEL_METADATA,
            )
            self.assertEqual(
                wheel_payloads[f"{DIST_INFO}/entry_points.txt"],
                EXPECTED_ENTRY_POINTS,
            )
            self.assertEqual(wheel_payloads[f"{DIST_INFO}/top_level.txt"], b"heel\n")
            self.assertEqual(
                wheel_payloads[f"{DIST_INFO}/licenses/LICENSE"],
                (ROOT / "LICENSE").read_bytes(),
            )
            self.assertEqual(
                wheel_payloads[f"{DIST_INFO}/licenses/NOTICE"],
                (ROOT / "NOTICE").read_bytes(),
            )
            for name, payload in wheel_payloads.items():
                _assert_public_payload(self, name, payload)

            sdist_raw = _read_bounded_path(
                first / SDIST,
                MAX_ARCHIVE_BYTES,
                "source archive",
            )
            self.assertEqual(sdist_raw[:10], EXPECTED_GZIP_HEADER)
            tar_raw = _bounded_gzip_decompress(
                sdist_raw,
                MAX_TOTAL_MEMBER_BYTES + 65536,
            )
            self.assertEqual(len(tar_raw) % tarfile.BLOCKSIZE, 0)
            self.assertTrue(tar_raw.endswith(b"\0" * 1024))
            prefix = "heel_sim-1.2.0/"
            with tarfile.open(fileobj=io.BytesIO(sdist_raw), mode="r:gz") as archive:
                members = _bounded_tar_members_for_test(self, archive)
                names = [member.name for member in members]
                expected_names = [prefix + name for name in sorted(sdist_relative_names)]
                self.assertEqual(names, expected_names)
                self.assertEqual(len(names), len(set(names)))
                final_member = members[-1]
                canonical_end = (
                    final_member.offset_data
                    + ((final_member.size + tarfile.BLOCKSIZE - 1) // tarfile.BLOCKSIZE)
                    * tarfile.BLOCKSIZE
                    + 2 * tarfile.BLOCKSIZE
                )
                self.assertEqual(len(tar_raw), canonical_end)
                total_size = 0
                for member in members:
                    self.assertEqual(member.type, tarfile.REGTYPE, member.name)
                    self.assertFalse(member.pax_headers, member.name)
                    self.assertFalse(member.sparse, member.name)
                    self.assertEqual(member.linkname, "", member.name)
                    self.assertEqual(member.mode, 0o644, member.name)
                    self.assertEqual(member.mtime, 0, member.name)
                    self.assertEqual(member.uid, 0, member.name)
                    self.assertEqual(member.gid, 0, member.name)
                    self.assertEqual(member.uname, "", member.name)
                    self.assertEqual(member.gname, "", member.name)
                    self.assertEqual(member.devmajor, 0, member.name)
                    self.assertEqual(member.devminor, 0, member.name)
                    self.assertLessEqual(member.size, MAX_MEMBER_BYTES, member.name)
                    self.assertLessEqual(
                        total_size + member.size,
                        MAX_TOTAL_MEMBER_BYTES,
                        member.name,
                    )
                    header = tar_raw[member.offset:member.offset + tarfile.BLOCKSIZE]
                    self.assertEqual(header[257:263], b"ustar\x00", member.name)
                    extracted = archive.extractfile(member)
                    self.assertIsNotNone(extracted, member.name)
                    payload = extracted.read()
                    self.assertEqual(len(payload), member.size, member.name)
                    total_size += len(payload)
                    _assert_public_payload(self, member.name, payload)
                    relative_name = member.name.removeprefix(prefix)
                    if relative_name == "PKG-INFO":
                        self.assertEqual(payload, EXPECTED_METADATA)
                    else:
                        self.assertEqual(payload, (ROOT / relative_name).read_bytes())
                self.assertLessEqual(total_size, MAX_TOTAL_MEMBER_BYTES)
            self.assertIn("heel/heldout/test_targets.json", sdist_relative_names)
            self.assertIn(
                "heel/scenarios_lib/research_owasp.json",
                sdist_relative_names,
            )
            self.assertNotIn("scripts/build_open_core_release.py", sdist_relative_names)

            archives = []
            for name in (WHEEL, SDIST):
                payload = _read_bounded_path(
                    first / name,
                    MAX_ARCHIVE_BYTES,
                    name,
                )
                archives.append(
                    {
                        "name": name,
                        "sha256": hashlib.sha256(payload).hexdigest(),
                        "size": len(payload),
                    }
                )
            expected_manifest = {
                "artifacts": sorted(archives, key=lambda artifact: artifact["name"]),
                "schema_version": "heel.open-core-artifacts.v1",
                "version": "1.2.0",
            }
            manifest_bytes = _read_bounded_path(
                first / ARTIFACT_MANIFEST,
                MAX_MEMBER_BYTES,
                "artifact manifest",
            )
            self.assertEqual(
                manifest_bytes,
                (
                    json.dumps(
                        expected_manifest,
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=False,
                        allow_nan=False,
                    )
                    + "\n"
                ).encode("utf-8"),
            )

    def test_builder_rejects_contract_source_and_import_mutations(self):
        def contract_path(source: Path) -> Path:
            return source / "release/open-core-v1.json"

        def canonical_contract(source: Path) -> dict:
            return json.loads(contract_path(source).read_text(encoding="utf-8"))

        def write_contract(source: Path, contract: dict) -> None:
            contract_path(source).write_text(
                json.dumps(
                    contract,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    allow_nan=False,
                )
                + "\n",
                encoding="utf-8",
            )

        def duplicate_nested_key(source: Path) -> None:
            path = contract_path(source)
            text = path.read_text(encoding="utf-8")
            needle = '"heel":"heel.cli:main"'
            path.write_text(
                text.replace(needle, needle + "," + needle, 1),
                encoding="utf-8",
            )

        def non_finite(source: Path, token: str) -> None:
            path = contract_path(source)
            text = path.read_text(encoding="utf-8")
            path.write_text(
                text.replace('"version":"1.2.0"', f'"version":{token}', 1),
                encoding="utf-8",
            )

        def unknown_field(source: Path) -> None:
            contract = canonical_contract(source)
            contract["unexpected"] = "closed"
            write_contract(source, contract)

        def wrong_type(source: Path) -> None:
            contract = canonical_contract(source)
            contract["python_modules"] = "heel/cli.py"
            write_contract(source, contract)

        def noncanonical(source: Path) -> None:
            contract_path(source).write_text(
                json.dumps(canonical_contract(source), indent=2) + "\n",
                encoding="utf-8",
            )

        def schema_mismatch(source: Path) -> None:
            contract = canonical_contract(source)
            contract["schema_version"] = "heel.open-core-release.v2"
            write_contract(source, contract)

        def contract_version_mismatch(source: Path) -> None:
            contract = canonical_contract(source)
            contract["version"] = "1.2.1"
            write_contract(source, contract)

        def pyproject_version_mismatch(source: Path) -> None:
            path = source / "pyproject.toml"
            text = path.read_text(encoding="utf-8")
            path.write_text(text.replace('version = "1.2.0"', 'version = "1.2.1"', 1))

        def proprietary_license(source: Path) -> None:
            path = source / "pyproject.toml"
            text = path.read_text(encoding="utf-8")
            path.write_text(
                text.replace('license = "Apache-2.0"', 'license = "Proprietary"', 1),
                encoding="utf-8",
            )

        def dependency_bearing_extra(source: Path) -> None:
            path = source / "pyproject.toml"
            text = path.read_text(encoding="utf-8")
            path.write_text(
                text.replace(
                    'runner = ["cryptography==45.0.7"]',
                    'runner = ["cryptography==45.0.7"]\nllm = ["requests"]',
                    1,
                ),
                encoding="utf-8",
            )

        def wrong_build_backend(source: Path) -> None:
            path = source / "pyproject.toml"
            text = path.read_text(encoding="utf-8")
            path.write_text(
                text.replace('build-backend = "setuptools.build_meta"', 'build-backend = "hatchling.build"', 1),
                encoding="utf-8",
            )

        def package_version_mismatch(source: Path) -> None:
            path = source / "heel/__init__.py"
            text = path.read_text(encoding="utf-8")
            path.write_text(text.replace('__version__ = "1.2.0"', '__version__ = "1.2.1"'))

        def backslash_contract_path(source: Path) -> None:
            contract = canonical_contract(source)
            contract["python_modules"][0] = r"heel\__init__.py"
            write_contract(source, contract)

        def unclassified_module(source: Path) -> None:
            (source / "heel/TEST.py").write_text("VALUE = 'not public'\n", encoding="utf-8")

        def proprietary_import(source: Path, statement: str) -> None:
            path = source / "heel/cli.py"
            with path.open("a", encoding="utf-8") as stream:
                stream.write("\n" + statement + "\n")

        def symlinked_source(source: Path) -> None:
            path = source / "heel/cli.py"
            path.unlink()
            path.symlink_to(source / "heel/model.py")

        def symlinked_parent(source: Path) -> None:
            package = source / "heel"
            real_package = source / "real-heel"
            package.rename(real_package)
            package.symlink_to(real_package, target_is_directory=True)

        mutations = (
            ("recursive duplicate key", duplicate_nested_key, "duplicate key"),
            ("NaN", lambda source: non_finite(source, "NaN"), "non-finite"),
            ("Infinity", lambda source: non_finite(source, "Infinity"), "non-finite"),
            ("unknown field", unknown_field, "exact fields"),
            ("wrong type", wrong_type, "list of strings"),
            ("noncanonical JSON", noncanonical, "canonical"),
            ("schema mismatch", schema_mismatch, "schema version"),
            ("contract version mismatch", contract_version_mismatch, "version mismatch"),
            ("pyproject version mismatch", pyproject_version_mismatch, "pyproject version"),
            ("proprietary project license", proprietary_license, "apache-2.0 license"),
            ("dependency-bearing optional extra", dependency_bearing_extra, "optional dependencies"),
            ("wrong build backend", wrong_build_backend, "build backend"),
            ("package version mismatch", package_version_mismatch, "heel.__version__"),
            ("backslash path", backslash_contract_path, "backslash"),
            ("future TEST module", unclassified_module, "unclassified top-level module"),
            (
                "absolute proprietary import",
                lambda source: proprietary_import(source, "import heel.saas"),
                "forbidden local import: heel.saas",
            ),
            (
                "absolute from proprietary import",
                lambda source: proprietary_import(source, "from heel import saas"),
                "forbidden local import: heel.saas",
            ),
            (
                "relative proprietary module import",
                lambda source: proprietary_import(source, "from .saas import auth"),
                "forbidden local import: heel.saas",
            ),
            (
                "relative proprietary name import",
                lambda source: proprietary_import(source, "from . import saas"),
                "forbidden local import: heel.saas",
            ),
            ("symlinked source", symlinked_source, "symbolic link"),
            ("symlinked source parent", symlinked_parent, "symbolic link"),
        )
        for label, mutation, expected_message in mutations:
            with self.subTest(label):
                self._assert_mutated_snapshot_is_rejected(mutation, expected_message)

    def test_zip64_signature_inside_regular_payload_is_not_rejected(self):
        with tempfile.TemporaryDirectory(prefix="heel-open-core-zip64-payload-") as temporary:
            temporary_path = Path(temporary).resolve()
            source = temporary_path / "source"
            source.mkdir()
            _copy_public_builder_snapshot(source)
            notice = source / "NOTICE"
            notice.write_bytes(notice.read_bytes() + b"\nopaque marker: PK\x06\x06\n")
            result = _run_release_builder(
                temporary_path / "output",
                builder=source / "scripts/build_open_core_release.py",
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_gzip_validation_stops_at_the_expansion_limit(self):
        module = _load_builder_module()
        compressed = gzip.compress(b"x" * 131072, mtime=0)
        self.assertTrue(
            hasattr(module, "_bounded_gzip_decompress"),
            "builder must expose bounded gzip validation",
        )
        with self.assertRaisesRegex(module.OpenCoreBuildError, "expands beyond"):
            module._bounded_gzip_decompress(compressed, limit=1024)

    def test_zip_member_count_is_rejected_before_zipfile_parsing(self):
        module = _load_builder_module()
        oversized_eocd = struct.pack(
            "<IHHHHIIH",
            0x06054B50,
            0,
            0,
            MAX_ARCHIVE_MEMBERS + 1,
            MAX_ARCHIVE_MEMBERS + 1,
            0,
            0,
            0,
        )

        def unexpected_zipfile(*_args, **_kwargs):
            raise AssertionError("ZipFile must not parse an over-count archive")

        original_zipfile = module.zipfile.ZipFile
        module.zipfile.ZipFile = unexpected_zipfile
        try:
            with self.assertRaisesRegex(module.OpenCoreBuildError, "too many members"):
                module._validate_wheel(oversized_eocd, {})
        finally:
            module.zipfile.ZipFile = original_zipfile

    def test_tar_member_iteration_stops_at_the_count_limit(self):
        module = _load_builder_module()
        self.assertTrue(
            hasattr(module, "_bounded_tar_members"),
            "builder must expose bounded tar-member iteration",
        )

        class FakeArchive:
            def __iter__(self):
                for index in range(MAX_ARCHIVE_MEMBERS + 1):
                    yield tarfile.TarInfo(f"member-{index}")

            def getmembers(self):
                raise AssertionError("getmembers must not materialize the archive")

        with self.assertRaisesRegex(module.OpenCoreBuildError, "too many members"):
            module._bounded_tar_members(FakeArchive())

    def test_builder_rejects_unsafe_output_and_check_is_read_only(self):
        self.assertTrue(BUILDER.is_file(), "scripts/build_open_core_release.py is missing")
        with tempfile.TemporaryDirectory(prefix="heel-open-core-output-") as temporary:
            temporary_path = Path(temporary).resolve()
            baseline = temporary_path / "baseline"
            build_result = _run_release_builder(baseline)
            self.assertEqual(
                build_result.returncode,
                0,
                build_result.stdout + build_result.stderr,
            )

            before_valid_check = _tree_state(baseline)
            valid_check = _run_release_builder(baseline, check=True)
            self.assertEqual(
                valid_check.returncode,
                0,
                valid_check.stdout + valid_check.stderr,
            )
            self.assertIn("artifacts are current", valid_check.stdout)
            self.assertEqual(_tree_state(baseline), before_valid_check)

            missing_output = temporary_path / "missing-output"
            missing_check = _run_release_builder(missing_output, check=True)
            self.assertNotEqual(missing_check.returncode, 0)
            self.assertFalse(missing_output.exists())

            def run_check_mutation(label: str, mutation, expected_message: str) -> None:
                case = temporary_path / ("case-" + label)
                shutil.copytree(baseline, case)
                mutation(case)
                before = _tree_state(case)
                result = _run_release_builder(case, check=True)
                output = result.stdout + result.stderr
                self.assertNotEqual(result.returncode, 0, output)
                self.assertIn(expected_message, output.lower())
                self.assertEqual(_tree_state(case), before)

            def remove_wheel(case: Path) -> None:
                (case / WHEEL).unlink()

            def stale_wheel(case: Path) -> None:
                path = case / WHEEL
                path.write_bytes(path.read_bytes() + b"stale")

            def unexpected_member(case: Path) -> None:
                (case / "unexpected.txt").write_text("not published\n", encoding="utf-8")

            def symlinked_member(case: Path) -> None:
                target = temporary_path / "symlink-target.whl"
                target.write_bytes((case / WHEEL).read_bytes())
                (case / WHEEL).unlink()
                (case / WHEEL).symlink_to(target)

            def nonregular_member(case: Path) -> None:
                (case / ARTIFACT_MANIFEST).unlink()
                (case / ARTIFACT_MANIFEST).mkdir()

            for label, mutation, expected_message in (
                ("missing", remove_wheel, "missing"),
                ("stale", stale_wheel, "stale"),
                ("unexpected", unexpected_member, "unexpected"),
                ("symlink", symlinked_member, "symbolic link"),
                ("nonregular", nonregular_member, "regular file"),
            ):
                with self.subTest(check=label):
                    run_check_mutation(label, mutation, expected_message)

            real_output = temporary_path / "real-output"
            real_output.mkdir()
            symlink_output = temporary_path / "symlink-output"
            symlink_output.symlink_to(real_output, target_is_directory=True)
            symlink_root_result = _run_release_builder(symlink_output)
            self.assertNotEqual(symlink_root_result.returncode, 0)
            self.assertIn(
                "symbolic link",
                (symlink_root_result.stdout + symlink_root_result.stderr).lower(),
            )
            self.assertEqual(list(real_output.iterdir()), [])

            real_parent = temporary_path / "real-parent"
            real_parent.mkdir()
            symlink_parent = temporary_path / "symlink-parent"
            symlink_parent.symlink_to(real_parent, target_is_directory=True)
            parent_result = _run_release_builder(symlink_parent / "artifacts")
            self.assertNotEqual(parent_result.returncode, 0)
            self.assertIn(
                "symbolic link",
                (parent_result.stdout + parent_result.stderr).lower(),
            )
            self.assertFalse((real_parent / "artifacts").exists())

            artifact_output = temporary_path / "artifact-symlink"
            artifact_output.mkdir()
            artifact_target = temporary_path / "artifact-target"
            artifact_target.write_bytes(b"do not overwrite")
            (artifact_output / WHEEL).symlink_to(artifact_target)
            artifact_result = _run_release_builder(artifact_output)
            self.assertNotEqual(artifact_result.returncode, 0)
            self.assertIn(
                "symbolic link",
                (artifact_result.stdout + artifact_result.stderr).lower(),
            )
            self.assertEqual(artifact_target.read_bytes(), b"do not overwrite")

    def test_clean_wheel_and_sdist_installs_reproduce_the_public_package(self):
        self.assertTrue(BUILDER.is_file(), "scripts/build_open_core_release.py is missing")
        _require_local_build_tools(self)
        contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
        expected_names = {
            *contract["python_modules"],
            *contract["package_data"],
            f"{DIST_INFO}/METADATA",
            f"{DIST_INFO}/WHEEL",
            f"{DIST_INFO}/entry_points.txt",
            f"{DIST_INFO}/licenses/LICENSE",
            f"{DIST_INFO}/licenses/NOTICE",
            f"{DIST_INFO}/top_level.txt",
            RECORD_PATH,
        }
        import_names = [
            "heel" if path == "heel/__init__.py" else path[:-3].replace("/", ".")
            for path in contract["python_modules"]
        ]

        with tempfile.TemporaryDirectory(prefix="heel-open-core-install-") as temporary:
            temporary_path = Path(temporary).resolve()
            artifacts = temporary_path / "artifacts"
            workspace = temporary_path / "outside-repository"
            workspace.mkdir()
            environment = _isolated_environment(temporary_path)
            (temporary_path / "home").mkdir()
            build_result = _run_release_builder(artifacts)
            self.assertEqual(
                build_result.returncode,
                0,
                build_result.stdout + build_result.stderr,
            )

            wheel_venv = temporary_path / "wheel-venv"
            subprocess.run(
                [sys.executable, "-m", "venv", str(wheel_venv)],
                cwd=workspace,
                env=environment,
                check=True,
                capture_output=True,
                text=True,
                timeout=120,
            )
            wheel_python = wheel_venv / "bin/python"
            preinstall = subprocess.run(
                [
                    str(wheel_python),
                    "-I",
                    "-c",
                    "import importlib.util; assert importlib.util.find_spec('heel') is None",
                ],
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(preinstall.returncode, 0, preinstall.stdout + preinstall.stderr)
            wheel_install = subprocess.run(
                [
                    str(wheel_python),
                    "-m",
                    "pip",
                    "--isolated",
                    "install",
                    "--no-index",
                    "--no-deps",
                    "--no-cache-dir",
                    str(artifacts / WHEEL),
                ],
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                timeout=120,
            )
            self.assertEqual(
                wheel_install.returncode,
                0,
                wheel_install.stdout + wheel_install.stderr,
            )
            import_script = (
                "import importlib,importlib.util;"
                f"modules={import_names!r};"
                "[importlib.import_module(name) for name in modules];"
                "import heel;"
                "assert heel.__version__ == '1.2.0';"
                "assert importlib.util.find_spec('heel.saas') is None"
            )
            imported = subprocess.run(
                [str(wheel_python), "-I", "-c", import_script],
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(imported.returncode, 0, imported.stdout + imported.stderr)

            specification = workspace / "sample-openapi.json"
            specification.write_text(
                json.dumps(
                    {
                        "openapi": "3.1.0",
                        "info": {"title": "Synthetic Projects API", "version": "1.0.0"},
                        "paths": {
                            "/projects": {
                                "get": {
                                    "operationId": "listProjects",
                                    "responses": {"200": {"description": "Synthetic"}},
                                }
                            }
                        },
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n",
                encoding="utf-8",
            )
            cli = subprocess.run(
                [
                    str(wheel_venv / "bin/heel"),
                    "review",
                    "openapi",
                    str(specification),
                    "--json",
                ],
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(cli.returncode, 0, cli.stdout + cli.stderr)
            cli_review = json.loads(cli.stdout)
            self.assertEqual(cli_review["schema_version"], "heel.review.v1")
            self.assertEqual(cli_review["privacy"]["network_calls"], False)

            messages = [
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {},
                        "clientInfo": {"name": "release-test", "version": "1.0"},
                    },
                },
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized",
                    "params": {},
                },
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            ]
            mcp = subprocess.run(
                [str(wheel_venv / "bin/heel-mcp")],
                cwd=workspace,
                env=environment,
                input="".join(
                    json.dumps(message, separators=(",", ":")) + "\n"
                    for message in messages
                ),
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(mcp.returncode, 0, mcp.stdout + mcp.stderr)
            responses = [json.loads(line) for line in mcp.stdout.splitlines() if line]
            self.assertEqual(len(responses), 2, responses)
            self.assertEqual(responses[0]["result"]["serverInfo"]["name"], "heel")
            self.assertIn(
                "heel_review_openapi",
                {tool["name"] for tool in responses[1]["result"]["tools"]},
            )

            source_venv = temporary_path / "source-venv"
            source_venv_result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "venv",
                    str(source_venv),
                ],
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                timeout=120,
            )
            self.assertEqual(
                source_venv_result.returncode,
                0,
                source_venv_result.stdout + source_venv_result.stderr,
            )
            source_python = source_venv / "bin/python"
            _provision_local_build_tools(
                source_python,
                cwd=workspace,
                environment=environment,
            )
            build_tool_probe = subprocess.run(
                [
                    str(source_python),
                    "-I",
                    "-c",
                    (
                        "import importlib.util,setuptools,wheel;"
                        f"assert int(setuptools.__version__.split('.',1)[0]) >= {MIN_SETUPTOOLS_MAJOR};"
                        "assert importlib.util.find_spec('heel') is None"
                    ),
                ],
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(
                build_tool_probe.returncode,
                0,
                build_tool_probe.stdout + build_tool_probe.stderr,
            )
            source_install = subprocess.run(
                [
                    str(source_python),
                    "-m",
                    "pip",
                    "--isolated",
                    "install",
                    "--no-index",
                    "--no-deps",
                    "--no-build-isolation",
                    "--no-cache-dir",
                    str(artifacts / SDIST),
                ],
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                timeout=120,
            )
            self.assertEqual(
                source_install.returncode,
                0,
                source_install.stdout + source_install.stderr,
            )
            source_import = subprocess.run(
                [str(source_python), "-I", "-c", import_script],
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(
                source_import.returncode,
                0,
                source_import.stdout + source_import.stderr,
            )

            rebuilt = temporary_path / "rebuilt"
            rebuilt.mkdir()
            rebuild = subprocess.run(
                [
                    str(source_python),
                    "-m",
                    "pip",
                    "--isolated",
                    "wheel",
                    "--no-index",
                    "--no-deps",
                    "--no-build-isolation",
                    "--no-cache-dir",
                    "--wheel-dir",
                    str(rebuilt),
                    str(artifacts / SDIST),
                ],
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                timeout=120,
            )
            self.assertEqual(rebuild.returncode, 0, rebuild.stdout + rebuild.stderr)
            rebuilt_wheels = list(rebuilt.glob("*.whl"))
            self.assertEqual(len(rebuilt_wheels), 1, rebuilt_wheels)
            custom_normalized = _normalized_wheel(
                self,
                artifacts / WHEEL,
                expected_names,
                canonical=True,
            )
            rebuilt_normalized = _normalized_wheel(
                self,
                rebuilt_wheels[0],
                expected_names,
                canonical=False,
            )
            self.assertEqual(rebuilt_normalized, custom_normalized)

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
        dist_info = "heel_sim-1.2.0.dist-info"

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
                parsed_metadata = BytesParser(policy=policy.default).parsebytes(metadata)
                self.assertEqual(parsed_metadata.get_all("License-Expression"), ["Apache-2.0"])
                self.assertEqual(parsed_metadata.get_all("License", []), [])
                self.assertEqual(
                    parsed_metadata.get_all("Requires-Dist", []),
                    ['cryptography==45.0.7; extra == "runner"'],
                )
                self.assertEqual(parsed_metadata.get_all("Provides-Extra", []), ["runner"])
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
                members = _bounded_tar_members_for_test(self, sdist)
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
