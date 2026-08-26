#!/usr/bin/env python3
"""Build deterministic, Apache-only Heel wheel and source release artifacts."""
from __future__ import annotations

import argparse
import ast
import base64
import csv
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import secrets
import stat
import struct
import sys
import tarfile
import tomllib
import zipfile
import zlib


ROOT = Path(os.path.abspath(__file__)).parents[1]
CONTRACT_PATH = "release/open-core-v1.json"
RELEASE_VERSION = "1.2.0"
WHEEL_NAME = "heel_sim-1.2.0-py3-none-any.whl"
SDIST_NAME = "heel_sim-1.2.0.tar.gz"
MANIFEST_NAME = "heel-open-core-manifest.json"
ARTIFACT_NAMES = (WHEEL_NAME, SDIST_NAME, MANIFEST_NAME)
DIST_INFO = "heel_sim-1.2.0.dist-info"
RECORD_PATH = f"{DIST_INFO}/RECORD"
SDIST_PREFIX = "heel_sim-1.2.0/"
FIXED_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
FIXED_TAR_MTIME = 0
EXPECTED_GZIP_HEADER = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff"
MAX_SOURCE_BYTES = 4 * 1024 * 1024
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_MEMBER_BYTES = 4 * 1024 * 1024
MAX_TOTAL_MEMBER_BYTES = 24 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 128
EXPECTED_FIELDS = frozenset(
    {
        "build_files",
        "console_scripts",
        "documents",
        "licenses",
        "package_data",
        "python_modules",
        "schema_version",
        "version",
    }
)
PATH_FIELDS = (
    "build_files",
    "documents",
    "licenses",
    "package_data",
    "python_modules",
)
EXPECTED_BUILD_FILES = (
    "MANIFEST.in",
    "pyproject.toml",
    "release/open-core-v1.json",
)
EXPECTED_DOCUMENTS = (
    "release/open-core/MCP_QUICKSTART.md",
    "release/open-core/README.md",
    "release/open-core/SECURITY.md",
)
EXPECTED_LICENSES = ("DCO", "LICENSE", "NOTICE")
EXPECTED_PACKAGE_DATA = (
    "heel/heldout/targets.json",
    "heel/scenarios_lib/community.json",
)
EXPECTED_CONSOLE_SCRIPTS = {
    "heel": "heel.cli:main",
    "heel-mcp": "heel.mcp_server:main",
    "heel-rest": "heel.rest:serve",
}
EXPECTED_OPTIONAL_DEPENDENCIES = {"runner": ["cryptography==45.0.7"]}
FORBIDDEN_PREFIXES = (
    "apps/",
    "deploy/",
    "docs/saas/",
    "docs/superpowers/",
    "heel/saas/",
    "tests/",
    "web/",
)
FORBIDDEN_CONTENT = (
    b"LicenseRef-Heel-Commercial",
    b"apps/heel-cloud",
    b"docs/saas",
    b"docs/superpowers",
)
METADATA = (
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
WHEEL_METADATA = (
    "Wheel-Version: 1.0\n"
    "Generator: heel-open-core-release\n"
    "Root-Is-Purelib: true\n"
    "Tag: py3-none-any\n"
    "\n"
).encode("utf-8")


class OpenCoreBuildError(RuntimeError):
    """Raised when the public release cannot be proven safe and deterministic."""


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _file_read_flags() -> int:
    return os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)


def _open_absolute_directory(path: Path, *, create: bool, label: str) -> int:
    absolute = Path(os.path.abspath(path))
    descriptor = os.open(absolute.anchor, _directory_flags())
    try:
        for component in absolute.parts[1:]:
            try:
                status = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
            except FileNotFoundError:
                if not create:
                    raise OpenCoreBuildError(f"{label} is missing") from None
                try:
                    os.mkdir(component, 0o755, dir_fd=descriptor)
                    os.fsync(descriptor)
                    status = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
                except OSError as error:
                    raise OpenCoreBuildError(f"{label} cannot be created") from error
            if stat.S_ISLNK(status.st_mode):
                raise OpenCoreBuildError(f"{label} contains a symbolic link")
            if not stat.S_ISDIR(status.st_mode):
                raise OpenCoreBuildError(f"{label} contains a non-directory component")
            try:
                child = os.open(component, _directory_flags(), dir_fd=descriptor)
            except OSError as error:
                raise OpenCoreBuildError(f"{label} cannot be opened safely") from error
            child_status = os.fstat(child)
            if not stat.S_ISDIR(child_status.st_mode):
                os.close(child)
                raise OpenCoreBuildError(f"{label} is not a directory")
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _validated_relative_path(path: str) -> tuple[str, ...]:
    if type(path) is not str or not path:
        raise OpenCoreBuildError("contract path must be a non-empty string")
    if "\\" in path:
        raise OpenCoreBuildError(f"contract path uses a backslash: {path}")
    normalized = PurePosixPath(path)
    if normalized.is_absolute() or normalized.as_posix() != path:
        raise OpenCoreBuildError(f"contract path is not canonical: {path}")
    if not normalized.parts or ".." in normalized.parts:
        raise OpenCoreBuildError(f"contract path escapes the source root: {path}")
    if path.startswith(FORBIDDEN_PREFIXES):
        raise OpenCoreBuildError(f"contract path uses a forbidden prefix: {path}")
    return normalized.parts


def _read_descriptor(descriptor: int, *, label: str, limit: int) -> bytes:
    status = os.fstat(descriptor)
    if not stat.S_ISREG(status.st_mode):
        raise OpenCoreBuildError(f"{label} is not a regular file")
    if status.st_size > limit:
        raise OpenCoreBuildError(f"{label} exceeds the byte limit")
    chunks: list[bytes] = []
    observed = 0
    while True:
        chunk = os.read(descriptor, min(65536, limit + 1 - observed))
        if not chunk:
            break
        chunks.append(chunk)
        observed += len(chunk)
        if observed > limit:
            raise OpenCoreBuildError(f"{label} exceeds the byte limit")
    return b"".join(chunks)


class SourceTree:
    """Descriptor-anchored source reader that never traverses symlinks."""

    def __init__(self, root: Path):
        self._root = root
        self._descriptor: int | None = None

    def __enter__(self) -> SourceTree:
        self._descriptor = _open_absolute_directory(
            self._root,
            create=False,
            label="open-core source root",
        )
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        if self._descriptor is not None:
            os.close(self._descriptor)
            self._descriptor = None

    def _root_descriptor(self) -> int:
        if self._descriptor is None:
            raise OpenCoreBuildError("source tree is not open")
        return self._descriptor

    def read(self, relative_path: str) -> bytes:
        parts = _validated_relative_path(relative_path)
        descriptor = os.dup(self._root_descriptor())
        try:
            for component in parts[:-1]:
                status = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
                if stat.S_ISLNK(status.st_mode):
                    raise OpenCoreBuildError(
                        f"required source contains a symbolic link: {relative_path}"
                    )
                if not stat.S_ISDIR(status.st_mode):
                    raise OpenCoreBuildError(
                        f"required source parent is not a directory: {relative_path}"
                    )
                child = os.open(component, _directory_flags(), dir_fd=descriptor)
                if not stat.S_ISDIR(os.fstat(child).st_mode):
                    os.close(child)
                    raise OpenCoreBuildError(
                        f"required source parent is not a directory: {relative_path}"
                    )
                os.close(descriptor)
                descriptor = child
            status = os.stat(parts[-1], dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISLNK(status.st_mode):
                raise OpenCoreBuildError(
                    f"required source contains a symbolic link: {relative_path}"
                )
            if not stat.S_ISREG(status.st_mode):
                raise OpenCoreBuildError(
                    f"required source is not a regular file: {relative_path}"
                )
            file_descriptor = os.open(parts[-1], _file_read_flags(), dir_fd=descriptor)
            try:
                return _read_descriptor(
                    file_descriptor,
                    label=f"required source {relative_path}",
                    limit=MAX_SOURCE_BYTES,
                )
            finally:
                os.close(file_descriptor)
        except FileNotFoundError as error:
            raise OpenCoreBuildError(f"required source is missing: {relative_path}") from error
        except OSError as error:
            if error.errno in {getattr(os, "ELOOP", 62), 40}:
                raise OpenCoreBuildError(
                    f"required source contains a symbolic link: {relative_path}"
                ) from error
            raise OpenCoreBuildError(f"required source cannot be read: {relative_path}") from error
        finally:
            os.close(descriptor)

    def top_level_python_modules(self) -> set[str]:
        descriptor = os.dup(self._root_descriptor())
        try:
            status = os.stat("heel", dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISLNK(status.st_mode):
                raise OpenCoreBuildError("required source contains a symbolic link: heel")
            if not stat.S_ISDIR(status.st_mode):
                raise OpenCoreBuildError("heel source package is not a directory")
            package_descriptor = os.open("heel", _directory_flags(), dir_fd=descriptor)
            try:
                modules: set[str] = set()
                for name in os.listdir(package_descriptor):
                    if not name.endswith(".py"):
                        continue
                    module_status = os.stat(
                        name,
                        dir_fd=package_descriptor,
                        follow_symlinks=False,
                    )
                    if stat.S_ISLNK(module_status.st_mode):
                        raise OpenCoreBuildError(
                            f"top-level module contains a symbolic link: heel/{name}"
                        )
                    if not stat.S_ISREG(module_status.st_mode):
                        raise OpenCoreBuildError(
                            f"top-level module is not a regular file: heel/{name}"
                        )
                    modules.add(f"heel/{name}")
                runner_status = os.stat("runner", dir_fd=package_descriptor, follow_symlinks=False)
                if stat.S_ISLNK(runner_status.st_mode) or not stat.S_ISDIR(runner_status.st_mode):
                    raise OpenCoreBuildError("runner source package is unsafe")
                runner_descriptor = os.open("runner", _directory_flags(), dir_fd=package_descriptor)
                try:
                    for name in os.listdir(runner_descriptor):
                        if not name.endswith(".py"):
                            continue
                        module_status = os.stat(name, dir_fd=runner_descriptor, follow_symlinks=False)
                        if stat.S_ISLNK(module_status.st_mode) or not stat.S_ISREG(module_status.st_mode):
                            raise OpenCoreBuildError(f"runner module is unsafe: heel/runner/{name}")
                        modules.add(f"heel/runner/{name}")
                finally:
                    os.close(runner_descriptor)
                return modules
            finally:
                os.close(package_descriptor)
        except OSError as error:
            raise OpenCoreBuildError("heel source package cannot be inspected") from error
        finally:
            os.close(descriptor)


def _reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise OpenCoreBuildError(f"release contract contains duplicate key: {key}")
        result[key] = value
    return result


def _reject_non_finite(token: str) -> object:
    raise OpenCoreBuildError(f"release contract contains non-finite value: {token}")


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _load_contract(source: SourceTree) -> tuple[dict[str, object], bytes]:
    raw = source.read(CONTRACT_PATH)
    try:
        contract = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_non_finite,
        )
    except OpenCoreBuildError:
        raise
    except (UnicodeError, json.JSONDecodeError) as error:
        raise OpenCoreBuildError("release contract is not valid UTF-8 JSON") from error
    if type(contract) is not dict:
        raise OpenCoreBuildError("release contract must be an object")
    if raw != _canonical_json(contract):
        raise OpenCoreBuildError("release contract must use canonical JSON")
    _validate_contract(contract)
    return contract, raw


def _string_list(contract: dict[str, object], field: str) -> list[str]:
    value = contract[field]
    if type(value) is not list or any(type(item) is not str for item in value):
        raise OpenCoreBuildError(f"release contract {field} must be a list of strings")
    for item in value:
        _validated_relative_path(item)
    if value != sorted(value) or len(value) != len(set(value)):
        raise OpenCoreBuildError(f"release contract {field} must be sorted and unique")
    return value


def _validate_contract(contract: dict[str, object]) -> None:
    if set(contract) != EXPECTED_FIELDS:
        raise OpenCoreBuildError("release contract must contain the exact fields")
    if contract["schema_version"] != "heel.open-core-release.v1":
        raise OpenCoreBuildError("release contract schema version is unsupported")
    if contract["version"] != RELEASE_VERSION:
        raise OpenCoreBuildError("release contract version mismatch")
    lists = {field: _string_list(contract, field) for field in PATH_FIELDS}
    expected_fixed = {
        "build_files": EXPECTED_BUILD_FILES,
        "documents": EXPECTED_DOCUMENTS,
        "licenses": EXPECTED_LICENSES,
        "package_data": EXPECTED_PACKAGE_DATA,
    }
    for field, expected in expected_fixed.items():
        if tuple(lists[field]) != expected:
            raise OpenCoreBuildError(f"release contract {field} does not match the public boundary")
    scripts = contract["console_scripts"]
    if type(scripts) is not dict or any(
        type(name) is not str or type(target) is not str
        for name, target in scripts.items()
    ):
        raise OpenCoreBuildError("release contract console_scripts must map strings to strings")
    if scripts != EXPECTED_CONSOLE_SCRIPTS:
        raise OpenCoreBuildError("release contract console_scripts mismatch")
    all_paths = [path for field in PATH_FIELDS for path in lists[field]]
    if len(all_paths) != len(set(all_paths)):
        raise OpenCoreBuildError("release contract paths must be globally unique")
    for path in all_paths:
        _validated_relative_path(path)
    for path in lists["python_modules"]:
        parsed = PurePosixPath(path)
        if parsed.parent.as_posix() not in {"heel", "heel/runner"} or parsed.suffix != ".py":
            raise OpenCoreBuildError(f"invalid public Python module path: {path}")


def _package_version(source: bytes) -> str:
    try:
        tree = ast.parse(source, filename="heel/__init__.py")
    except SyntaxError as error:
        raise OpenCoreBuildError("heel/__init__.py cannot be parsed") from error
    versions: list[str] = []
    for statement in tree.body:
        if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
            continue
        targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
        value = statement.value
        if any(isinstance(target, ast.Name) and target.id == "__version__" for target in targets):
            if not isinstance(value, ast.Constant) or type(value.value) is not str:
                raise OpenCoreBuildError("heel.__version__ must be a static string")
            versions.append(value.value)
    if versions != [RELEASE_VERSION]:
        raise OpenCoreBuildError("heel.__version__ mismatch")
    return versions[0]


def _forbidden_local_import(tree: ast.Module) -> str | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "heel.saas" or alias.name.startswith("heel.saas."):
                    return "heel.saas"
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level == 0:
                if module == "heel.saas" or module.startswith("heel.saas."):
                    return "heel.saas"
                if module == "heel" and any(
                    alias.name == "saas" or alias.name.startswith("saas.")
                    for alias in node.names
                ):
                    return "heel.saas"
            elif node.level == 1:
                if module == "saas" or module.startswith("saas."):
                    return "heel.saas"
                if not module and any(
                    alias.name == "saas" or alias.name.startswith("saas.")
                    for alias in node.names
                ):
                    return "heel.saas"
    return None


def _validate_pyproject(payload: bytes, contract: dict[str, object]) -> None:
    try:
        pyproject = tomllib.loads(payload.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise OpenCoreBuildError("pyproject.toml cannot be parsed") from error
    try:
        build_system = pyproject["build-system"]
        project = pyproject["project"]
        setuptools = pyproject["tool"]["setuptools"]
    except (KeyError, TypeError) as error:
        raise OpenCoreBuildError("pyproject.toml is missing release metadata") from error
    if build_system != {
        "requires": ["setuptools>=77"],
        "build-backend": "setuptools.build_meta",
    }:
        raise OpenCoreBuildError("pyproject build backend mismatch")
    if project.get("name") != "heel-sim":
        raise OpenCoreBuildError("pyproject name mismatch")
    if project.get("version") != contract["version"]:
        raise OpenCoreBuildError("pyproject version mismatch")
    if project.get("requires-python") != ">=3.11":
        raise OpenCoreBuildError("pyproject requires-python mismatch")
    if project.get("scripts") != contract["console_scripts"]:
        raise OpenCoreBuildError("pyproject console scripts mismatch")
    if project.get("dependencies") != []:
        raise OpenCoreBuildError("open-core runtime dependencies must remain empty")
    if project.get("optional-dependencies", {}) != EXPECTED_OPTIONAL_DEPENDENCIES:
        raise OpenCoreBuildError(
            "open-core optional dependencies must contain only the pinned runner extra"
        )
    if "dynamic" in project:
        raise OpenCoreBuildError("open-core dynamic metadata is forbidden")
    if project.get("license") != "Apache-2.0":
        raise OpenCoreBuildError("pyproject must declare the Apache-2.0 license")
    if project.get("license-files") != ["LICENSE", "NOTICE"]:
        raise OpenCoreBuildError("pyproject Apache-2.0 license files mismatch")
    classifiers = project.get("classifiers")
    if type(classifiers) is not list:
        raise OpenCoreBuildError("pyproject classifiers must be a list")
    if any(
        type(classifier) is not str
        or classifier.startswith("License ::")
        for classifier in classifiers
    ):
        raise OpenCoreBuildError("pyproject legacy license classifiers are forbidden")
    if setuptools.get("packages") != ["heel", "heel.runner"]:
        raise OpenCoreBuildError("pyproject package boundary mismatch")
    package_data = setuptools.get("package-data", {}).get("heel")
    expected_data = [path.removeprefix("heel/") for path in contract["package_data"]]
    if package_data != expected_data:
        raise OpenCoreBuildError("pyproject package data mismatch")
    if "license-files" in setuptools:
        raise OpenCoreBuildError("pyproject legacy setuptools license files are forbidden")


def _load_public_sources(source: SourceTree) -> tuple[dict[str, object], dict[str, bytes]]:
    contract, contract_raw = _load_contract(source)
    paths = [path for field in PATH_FIELDS for path in contract[field]]
    if len(paths) > MAX_ARCHIVE_MEMBERS:
        raise OpenCoreBuildError("release contract contains too many members")
    payloads: dict[str, bytes] = {CONTRACT_PATH: contract_raw}
    total = len(contract_raw)
    for path in paths:
        if path in payloads:
            continue
        payload = source.read(path)
        payloads[path] = payload
        total += len(payload)
        if total > MAX_TOTAL_MEMBER_BYTES:
            raise OpenCoreBuildError("public source closure exceeds the byte limit")
        if path != "MANIFEST.in":
            for marker in FORBIDDEN_CONTENT:
                if marker in payload:
                    raise OpenCoreBuildError(f"public source contains forbidden content: {path}")

    actual_modules = source.top_level_python_modules()
    expected_modules = set(contract["python_modules"])
    if actual_modules != expected_modules:
        unclassified = sorted(actual_modules - expected_modules)
        if unclassified:
            raise OpenCoreBuildError(
                f"unclassified top-level module: {unclassified[0]}"
            )
        missing = sorted(expected_modules - actual_modules)
        raise OpenCoreBuildError(f"contract module is missing: {missing[0]}")
    for path in contract["python_modules"]:
        try:
            tree = ast.parse(payloads[path], filename=path)
        except SyntaxError as error:
            raise OpenCoreBuildError(f"public Python module cannot be parsed: {path}") from error
        forbidden = _forbidden_local_import(tree)
        if forbidden is not None:
            raise OpenCoreBuildError(f"forbidden local import: {forbidden} in {path}")
    _validate_pyproject(payloads["pyproject.toml"], contract)
    package_version = _package_version(payloads["heel/__init__.py"])
    if package_version != contract["version"]:
        raise OpenCoreBuildError("package and contract version mismatch")
    return contract, payloads


def _entry_points(scripts: dict[str, str]) -> bytes:
    lines = ["[console_scripts]"]
    lines.extend(f"{name} = {scripts[name]}" for name in sorted(scripts))
    return ("\n".join(lines) + "\n").encode("utf-8")


def _record_hash(payload: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest())
    return "sha256=" + digest.rstrip(b"=").decode("ascii")


def _record(payloads: dict[str, bytes]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for path in sorted(payloads):
        payload = payloads[path]
        writer.writerow((path, _record_hash(payload), str(len(payload))))
    writer.writerow((RECORD_PATH, "", ""))
    return output.getvalue().encode("utf-8")


def _zip_info(path: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(path, date_time=FIXED_ZIP_TIMESTAMP)
    info.create_system = 3
    info.create_version = 20
    info.extract_version = 20
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    info.compress_type = zipfile.ZIP_STORED
    info.flag_bits = 0
    info.extra = b""
    info.comment = b""
    return info


def _build_wheel(contract: dict[str, object], sources: dict[str, bytes]) -> tuple[bytes, dict[str, bytes]]:
    payloads = {
        path: sources[path]
        for path in (*contract["python_modules"], *contract["package_data"])
    }
    payloads.update(
        {
            f"{DIST_INFO}/METADATA": METADATA,
            f"{DIST_INFO}/WHEEL": WHEEL_METADATA,
            f"{DIST_INFO}/entry_points.txt": _entry_points(contract["console_scripts"]),
            f"{DIST_INFO}/licenses/LICENSE": sources["LICENSE"],
            f"{DIST_INFO}/licenses/NOTICE": sources["NOTICE"],
            f"{DIST_INFO}/top_level.txt": b"heel\n",
        }
    )
    payloads[RECORD_PATH] = _record(payloads)
    output = io.BytesIO()
    with zipfile.ZipFile(
        output,
        mode="w",
        compression=zipfile.ZIP_STORED,
        allowZip64=False,
    ) as archive:
        order = [*sorted(path for path in payloads if path != RECORD_PATH), RECORD_PATH]
        for path in order:
            archive.writestr(_zip_info(path), payloads[path])
    wheel = output.getvalue()
    _validate_wheel(wheel, payloads)
    return wheel, payloads


def _build_sdist(contract: dict[str, object], sources: dict[str, bytes]) -> tuple[bytes, dict[str, bytes]]:
    payloads = {
        path: sources[path]
        for path in (
            *contract["build_files"],
            *contract["documents"],
            *contract["licenses"],
            *contract["package_data"],
            *contract["python_modules"],
        )
    }
    payloads["PKG-INFO"] = METADATA
    tar_output = io.BytesIO()
    with tarfile.open(
        fileobj=tar_output,
        mode="w",
        format=tarfile.USTAR_FORMAT,
        dereference=False,
    ) as archive:
        for path in sorted(payloads):
            payload = payloads[path]
            info = tarfile.TarInfo(SDIST_PREFIX + path)
            info.type = tarfile.REGTYPE
            info.mode = 0o644
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = FIXED_TAR_MTIME
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    padded_tar_payload = tar_output.getvalue()
    member_bytes = sum(
        tarfile.BLOCKSIZE
        + ((len(payload) + tarfile.BLOCKSIZE - 1) // tarfile.BLOCKSIZE)
        * tarfile.BLOCKSIZE
        for payload in payloads.values()
    )
    canonical_tar_size = member_bytes + 2 * tarfile.BLOCKSIZE
    if (
        len(padded_tar_payload) < canonical_tar_size
        or any(padded_tar_payload[member_bytes:canonical_tar_size])
        or any(padded_tar_payload[canonical_tar_size:])
    ):
        raise OpenCoreBuildError("generated source archive has noncanonical termination")
    tar_payload = padded_tar_payload[:canonical_tar_size]
    gzip_output = io.BytesIO()
    with gzip.GzipFile(
        filename="",
        mode="wb",
        compresslevel=9,
        fileobj=gzip_output,
        mtime=0,
    ) as compressor:
        compressor.write(tar_payload)
    sdist = gzip_output.getvalue()
    _validate_sdist(sdist, payloads)
    return sdist, payloads


def _safe_archive_name(name: str) -> None:
    if "\\" in name:
        raise OpenCoreBuildError(f"archive member uses a backslash: {name}")
    parsed = PurePosixPath(name)
    if parsed.is_absolute() or parsed.as_posix() != name or ".." in parsed.parts:
        raise OpenCoreBuildError(f"archive member is not canonical: {name}")


def _validate_record(payloads: dict[str, bytes]) -> None:
    try:
        rows = list(csv.reader(io.StringIO(payloads[RECORD_PATH].decode("utf-8"))))
    except (UnicodeError, csv.Error) as error:
        raise OpenCoreBuildError("wheel RECORD cannot be parsed") from error
    expected_order = [*sorted(path for path in payloads if path != RECORD_PATH), RECORD_PATH]
    if [row[0] for row in rows] != expected_order:
        raise OpenCoreBuildError("wheel RECORD order mismatch")
    if len(rows) != len({row[0] for row in rows}):
        raise OpenCoreBuildError("wheel RECORD contains duplicate rows")
    for row in rows[:-1]:
        if len(row) != 3:
            raise OpenCoreBuildError("wheel RECORD row has the wrong schema")
        name, digest, size = row
        expected_digest = _record_hash(payloads[name])
        if digest != expected_digest or "=" in digest.removeprefix("sha256="):
            raise OpenCoreBuildError(f"wheel RECORD hash mismatch: {name}")
        if size != str(len(payloads[name])):
            raise OpenCoreBuildError(f"wheel RECORD size mismatch: {name}")
    if rows[-1] != [RECORD_PATH, "", ""]:
        raise OpenCoreBuildError("wheel RECORD self row mismatch")


def _zip_eocd_member_count(wheel: bytes) -> int:
    if len(wheel) < 22:
        raise OpenCoreBuildError("wheel end-of-central-directory is truncated")
    (
        signature,
        disk_number,
        central_disk,
        disk_entries,
        total_entries,
        central_size,
        central_offset,
        comment_length,
    ) = struct.unpack("<IHHHHIIH", wheel[-22:])
    if disk_entries > MAX_ARCHIVE_MEMBERS or total_entries > MAX_ARCHIVE_MEMBERS:
        raise OpenCoreBuildError("wheel contains too many members")
    if (
        signature != 0x06054B50
        or disk_number != 0
        or central_disk != 0
        or disk_entries != total_entries
        or disk_entries == 0xFFFF
        or central_size == 0xFFFFFFFF
        or central_offset == 0xFFFFFFFF
        or comment_length != 0
        or central_offset + central_size != len(wheel) - 22
    ):
        raise OpenCoreBuildError("wheel central directory is noncanonical or ZIP64")
    return total_entries


def _validate_wheel(wheel: bytes, expected_payloads: dict[str, bytes]) -> None:
    if len(wheel) > MAX_ARCHIVE_BYTES:
        raise OpenCoreBuildError("wheel exceeds the archive byte limit")
    expected_member_count = _zip_eocd_member_count(wheel)
    try:
        with zipfile.ZipFile(io.BytesIO(wheel)) as archive:
            if archive.comment:
                raise OpenCoreBuildError("wheel comment is forbidden")
            infos = archive.infolist()
            if len(infos) != expected_member_count:
                raise OpenCoreBuildError("wheel central-directory member count mismatch")
            expected_order = [
                *sorted(path for path in expected_payloads if path != RECORD_PATH),
                RECORD_PATH,
            ]
            if [info.filename for info in infos] != expected_order:
                raise OpenCoreBuildError("wheel member order mismatch")
            if len(infos) > MAX_ARCHIVE_MEMBERS:
                raise OpenCoreBuildError("wheel contains too many members")
            total = 0
            observed: dict[str, bytes] = {}
            for info in infos:
                _safe_archive_name(info.filename)
                if info.flag_bits != 0 or info.extra or info.comment:
                    raise OpenCoreBuildError(f"wheel member has forbidden ZIP flags: {info.filename}")
                if info.extract_version > 20 or info.create_version > 20:
                    raise OpenCoreBuildError(f"wheel member unexpectedly uses ZIP64: {info.filename}")
                if info.compress_type != zipfile.ZIP_STORED:
                    raise OpenCoreBuildError(f"wheel member is not stored: {info.filename}")
                if info.date_time != FIXED_ZIP_TIMESTAMP:
                    raise OpenCoreBuildError(f"wheel timestamp mismatch: {info.filename}")
                if info.create_system != 3 or info.external_attr >> 16 != stat.S_IFREG | 0o644:
                    raise OpenCoreBuildError(f"wheel mode mismatch: {info.filename}")
                if info.file_size > MAX_MEMBER_BYTES or info.compress_size != info.file_size:
                    raise OpenCoreBuildError(f"wheel member exceeds bounds: {info.filename}")
                if total + info.file_size > MAX_TOTAL_MEMBER_BYTES:
                    raise OpenCoreBuildError("wheel uncompressed payload exceeds the total limit")
                payload = archive.read(info)
                if zlib.crc32(payload) & 0xFFFFFFFF != info.CRC:
                    raise OpenCoreBuildError(f"wheel CRC mismatch: {info.filename}")
                if payload != expected_payloads[info.filename]:
                    raise OpenCoreBuildError(f"wheel content mismatch: {info.filename}")
                observed[info.filename] = payload
                total += len(payload)
                local = wheel[info.header_offset:info.header_offset + 30]
                if len(local) != 30:
                    raise OpenCoreBuildError(f"wheel local header is truncated: {info.filename}")
                fields = struct.unpack("<IHHHHHIIIHH", local)
                if fields[0] != 0x04034B50 or fields[1] > 20:
                    raise OpenCoreBuildError(f"wheel local header is invalid: {info.filename}")
                if fields[2:6] != (0, 0, 0, 33):
                    raise OpenCoreBuildError(f"wheel local header is noncanonical: {info.filename}")
                if fields[6:9] != (info.CRC, info.file_size, info.file_size):
                    raise OpenCoreBuildError(f"wheel local sizes are invalid: {info.filename}")
                name_length, extra_length = fields[9:11]
                encoded_name = wheel[
                    info.header_offset + 30:info.header_offset + 30 + name_length
                ]
                if encoded_name != info.filename.encode("utf-8") or extra_length != 0:
                    raise OpenCoreBuildError(f"wheel local name is invalid: {info.filename}")
            if total > MAX_TOTAL_MEMBER_BYTES:
                raise OpenCoreBuildError("wheel uncompressed payload exceeds the total limit")
            _validate_record(observed)
    except (zipfile.BadZipFile, KeyError, RuntimeError, struct.error) as error:
        raise OpenCoreBuildError("generated wheel is invalid") from error


def _bounded_gzip_decompress(payload: bytes, *, limit: int) -> bytes:
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(payload), mode="rb") as stream:
            expanded = stream.read(limit + 1)
    except (EOFError, OSError) as error:
        raise OpenCoreBuildError("source archive gzip stream is invalid") from error
    if len(expanded) > limit:
        raise OpenCoreBuildError("source archive expands beyond the total limit")
    return expanded


def _bounded_tar_members(archive: tarfile.TarFile) -> list[tarfile.TarInfo]:
    members: list[tarfile.TarInfo] = []
    for member in archive:
        if len(members) >= MAX_ARCHIVE_MEMBERS:
            raise OpenCoreBuildError("source archive contains too many members")
        members.append(member)
    return members


def _validate_sdist(sdist: bytes, expected_payloads: dict[str, bytes]) -> None:
    if len(sdist) > MAX_ARCHIVE_BYTES:
        raise OpenCoreBuildError("source archive exceeds the archive byte limit")
    if sdist[:10] != EXPECTED_GZIP_HEADER:
        raise OpenCoreBuildError("source archive gzip header is noncanonical")
    tar_payload = _bounded_gzip_decompress(
        sdist,
        limit=MAX_TOTAL_MEMBER_BYTES + 65536,
    )
    expected_crc, expected_size = struct.unpack("<II", sdist[-8:])
    if expected_crc != zlib.crc32(tar_payload) & 0xFFFFFFFF:
        raise OpenCoreBuildError("source archive gzip CRC mismatch")
    if expected_size != len(tar_payload) & 0xFFFFFFFF:
        raise OpenCoreBuildError("source archive gzip size mismatch")
    if len(tar_payload) % tarfile.BLOCKSIZE != 0 or not tar_payload.endswith(b"\0" * 1024):
        raise OpenCoreBuildError("source archive tar padding is noncanonical")
    try:
        with tarfile.open(fileobj=io.BytesIO(tar_payload), mode="r:") as archive:
            members = _bounded_tar_members(archive)
            expected_order = [SDIST_PREFIX + path for path in sorted(expected_payloads)]
            if [member.name for member in members] != expected_order:
                raise OpenCoreBuildError("source archive member order mismatch")
            if members:
                final_member = members[-1]
                canonical_end = (
                    final_member.offset_data
                    + ((final_member.size + tarfile.BLOCKSIZE - 1) // tarfile.BLOCKSIZE)
                    * tarfile.BLOCKSIZE
                    + 2 * tarfile.BLOCKSIZE
                )
                if canonical_end != len(tar_payload):
                    raise OpenCoreBuildError(
                        "source archive has data after its canonical termination"
                    )
            total = 0
            for member in members:
                _safe_archive_name(member.name)
                if (
                    member.type != tarfile.REGTYPE
                    or member.pax_headers
                    or member.sparse
                    or member.linkname
                ):
                    raise OpenCoreBuildError(f"source archive member type is forbidden: {member.name}")
                if (
                    member.mode != 0o644
                    or member.mtime != 0
                    or member.uid != 0
                    or member.gid != 0
                    or member.uname
                    or member.gname
                    or member.devmajor != 0
                    or member.devminor != 0
                ):
                    raise OpenCoreBuildError(f"source archive metadata mismatch: {member.name}")
                if member.size > MAX_MEMBER_BYTES:
                    raise OpenCoreBuildError(f"source archive member exceeds bounds: {member.name}")
                if total + member.size > MAX_TOTAL_MEMBER_BYTES:
                    raise OpenCoreBuildError("source archive payload exceeds the total limit")
                header = tar_payload[member.offset:member.offset + tarfile.BLOCKSIZE]
                if header[257:263] != b"ustar\x00":
                    raise OpenCoreBuildError(f"source archive member is not USTAR: {member.name}")
                stream = archive.extractfile(member)
                if stream is None:
                    raise OpenCoreBuildError(f"source archive member cannot be read: {member.name}")
                payload = stream.read(MAX_MEMBER_BYTES + 1)
                relative = member.name.removeprefix(SDIST_PREFIX)
                if payload != expected_payloads[relative]:
                    raise OpenCoreBuildError(f"source archive content mismatch: {member.name}")
                total += len(payload)
            if total > MAX_TOTAL_MEMBER_BYTES:
                raise OpenCoreBuildError("source archive payload exceeds the total limit")
    except (tarfile.TarError, KeyError, struct.error) as error:
        raise OpenCoreBuildError("generated source archive is invalid") from error


def _artifact_manifest(wheel: bytes, sdist: bytes) -> bytes:
    artifacts = []
    for name, payload in ((WHEEL_NAME, wheel), (SDIST_NAME, sdist)):
        artifacts.append(
            {
                "name": name,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "size": len(payload),
            }
        )
    return _canonical_json(
        {
            "artifacts": sorted(artifacts, key=lambda artifact: artifact["name"]),
            "schema_version": "heel.open-core-artifacts.v1",
            "version": RELEASE_VERSION,
        }
    )


def build_release() -> dict[str, bytes]:
    with SourceTree(ROOT) as source:
        contract, sources = _load_public_sources(source)
        wheel, _ = _build_wheel(contract, sources)
        sdist, _ = _build_sdist(contract, sources)
    manifest = _artifact_manifest(wheel, sdist)
    return {WHEEL_NAME: wheel, SDIST_NAME: sdist, MANIFEST_NAME: manifest}


def _output_status(directory: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        return None


def _validate_output_entries(directory: int, *, require_complete: bool) -> None:
    observed = set(os.listdir(directory))
    expected = set(ARTIFACT_NAMES)
    unexpected = sorted(observed - expected)
    if unexpected:
        raise OpenCoreBuildError(f"output contains unexpected member: {unexpected[0]}")
    if require_complete:
        missing = sorted(expected - observed)
        if missing:
            raise OpenCoreBuildError(f"generated artifact is missing: {missing[0]}")
    for name in sorted(observed & expected):
        status = _output_status(directory, name)
        if status is None:
            raise OpenCoreBuildError(f"generated artifact is missing: {name}")
        if stat.S_ISLNK(status.st_mode):
            raise OpenCoreBuildError(f"generated artifact contains a symbolic link: {name}")
        if not stat.S_ISREG(status.st_mode):
            raise OpenCoreBuildError(f"generated artifact is not a regular file: {name}")


def _read_output(directory: int, name: str, *, limit: int) -> bytes:
    status = _output_status(directory, name)
    if status is None:
        raise OpenCoreBuildError(f"generated artifact is missing: {name}")
    if stat.S_ISLNK(status.st_mode):
        raise OpenCoreBuildError(f"generated artifact contains a symbolic link: {name}")
    if not stat.S_ISREG(status.st_mode):
        raise OpenCoreBuildError(f"generated artifact is not a regular file: {name}")
    try:
        descriptor = os.open(name, _file_read_flags(), dir_fd=directory)
    except OSError as error:
        raise OpenCoreBuildError(f"generated artifact cannot be opened safely: {name}") from error
    try:
        return _read_descriptor(descriptor, label=f"generated artifact {name}", limit=limit)
    finally:
        os.close(descriptor)


def _stage_output(directory: int, payload: bytes) -> str:
    for _ in range(128):
        name = f".heel-open-core-{os.getpid()}-{secrets.token_hex(12)}.tmp"
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(name, flags, 0o600, dir_fd=directory)
            break
        except FileExistsError:
            continue
    else:
        raise OpenCoreBuildError("cannot allocate an atomic output staging file")
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise OpenCoreBuildError("atomic output staging file is not regular")
        view = memoryview(payload)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                raise OpenCoreBuildError("atomic output write did not make progress")
            written += count
        os.fchmod(descriptor, 0o644)
        os.fsync(descriptor)
    except BaseException:
        os.close(descriptor)
        try:
            os.unlink(name, dir_fd=directory)
        except FileNotFoundError:
            pass
        raise
    os.close(descriptor)
    return name


def _destination_is_safe(directory: int, name: str) -> None:
    status = _output_status(directory, name)
    if status is None:
        return
    if stat.S_ISLNK(status.st_mode):
        raise OpenCoreBuildError(f"generated artifact contains a symbolic link: {name}")
    if not stat.S_ISREG(status.st_mode):
        raise OpenCoreBuildError(f"generated artifact is not a regular file: {name}")


def _publish_release(directory: int, artifacts: dict[str, bytes]) -> None:
    _validate_output_entries(directory, require_complete=False)
    staged: dict[str, str] = {}
    try:
        for name in ARTIFACT_NAMES:
            staged[name] = _stage_output(directory, artifacts[name])
        os.fsync(directory)
        for name in (WHEEL_NAME, SDIST_NAME):
            _destination_is_safe(directory, name)
            os.replace(
                staged.pop(name),
                name,
                src_dir_fd=directory,
                dst_dir_fd=directory,
            )
        os.fsync(directory)
        _destination_is_safe(directory, MANIFEST_NAME)
        os.replace(
            staged.pop(MANIFEST_NAME),
            MANIFEST_NAME,
            src_dir_fd=directory,
            dst_dir_fd=directory,
        )
        os.fsync(directory)
    finally:
        for temporary_name in staged.values():
            try:
                status = os.stat(
                    temporary_name,
                    dir_fd=directory,
                    follow_symlinks=False,
                )
                if stat.S_ISREG(status.st_mode):
                    os.unlink(temporary_name, dir_fd=directory)
            except FileNotFoundError:
                pass


def _check_release(directory: int, artifacts: dict[str, bytes]) -> None:
    _validate_output_entries(directory, require_complete=True)
    for name in ARTIFACT_NAMES:
        limit = MAX_ARCHIVE_BYTES if name != MANIFEST_NAME else MAX_MEMBER_BYTES
        actual = _read_output(directory, name, limit=limit)
        if actual != artifacts[name]:
            raise OpenCoreBuildError(f"generated artifact is stale: {name}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args(argv)
    output = Path(os.path.abspath(arguments.output.expanduser()))
    directory: int | None = None
    try:
        artifacts = build_release()
        directory = _open_absolute_directory(
            output,
            create=not arguments.check,
            label="open-core release output",
        )
        if arguments.check:
            _check_release(directory, artifacts)
        else:
            _publish_release(directory, artifacts)
    except (OpenCoreBuildError, OSError, ValueError) as error:
        print(f"open-core release build failed: {error}", file=sys.stderr)
        return 1
    finally:
        if directory is not None:
            os.close(directory)
    if arguments.check:
        print("open-core release artifacts are current")
    else:
        print(f"built {WHEEL_NAME}, {SDIST_NAME}, and {MANIFEST_NAME}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
