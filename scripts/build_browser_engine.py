#!/usr/bin/env python3
"""Build Heel's reviewed browser-only Python closure as a deterministic wheel."""
from __future__ import annotations

import argparse
import ast
import base64
import csv
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parents[1]
ENGINE_VERSION = "1.1.0"
WHEEL_NAME = f"heel_browser-{ENGINE_VERSION}-py3-none-any.whl"
DIST_INFO = f"heel_browser-{ENGINE_VERSION}.dist-info"
RECORD_PATH = f"{DIST_INFO}/RECORD"
FIXED_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
MODULE_PATHS = (
    "heel/__init__.py",
    "heel/browser_review.py",
    "heel/openapi_model.py",
    "heel/product_model.py",
    "heel/review_answers.py",
    "heel/review_contract.py",
    "heel/review_rules.py",
    "heel/review_service.py",
    "heel/static_review.py",
)
ALLOWED_STDLIB_IMPORTS = frozenset({
    "__future__",
    "copy",
    "dataclasses",
    "hashlib",
    "hmac",
    "json",
    "math",
    "re",
    "typing",
})
FORBIDDEN_DYNAMIC_CALLS = frozenset({"__import__", "compile", "eval", "exec", "open"})
FORBIDDEN_DYNAMIC_NAMESPACES = frozenset({"__builtins__", "builtins", "importlib"})


class BrowserEngineBuildError(RuntimeError):
    pass


def _regular_source(relative_path: str) -> bytes:
    path = ROOT / relative_path
    try:
        status = path.lstat()
    except OSError as error:
        raise BrowserEngineBuildError(f"required source is unavailable: {relative_path}") from error
    if path.is_symlink() or not stat.S_ISREG(status.st_mode):
        raise BrowserEngineBuildError(f"required source is not a regular file: {relative_path}")
    return path.read_bytes()


def _module_name(relative_path: str) -> str:
    return PureModulePath(relative_path).module


class PureModulePath:
    """Strict conversion for the fixed top-level Heel module allowlist."""

    def __init__(self, relative_path: str):
        path = Path(relative_path)
        if path.parent != Path("heel") or path.suffix != ".py":
            raise BrowserEngineBuildError(f"invalid browser module path: {relative_path}")
        self.module = path.stem


def _prove_import_closure() -> None:
    allowed_modules = {
        _module_name(path)
        for path in MODULE_PATHS
    }
    pending = ["__init__", "browser_review"]
    observed: set[str] = set()
    while pending:
        module = pending.pop()
        if module in observed:
            continue
        if module not in allowed_modules:
            raise BrowserEngineBuildError(f"browser import closure contains unreviewed module: {module}")
        relative_path = f"heel/{module}.py"
        source = _regular_source(relative_path)
        try:
            tree = ast.parse(source, filename=relative_path)
        except SyntaxError as error:
            raise BrowserEngineBuildError(f"browser module cannot be parsed: {relative_path}") from error
        observed.add(module)
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in FORBIDDEN_DYNAMIC_CALLS
            ):
                raise BrowserEngineBuildError(
                    f"browser module uses forbidden dynamic primitive: {node.func.id}"
                )
            if isinstance(node, ast.Name) and node.id in FORBIDDEN_DYNAMIC_NAMESPACES:
                raise BrowserEngineBuildError(
                    f"browser module uses forbidden dynamic primitive: {node.id}"
                )
            if isinstance(node, ast.Import):
                imported = {alias.name.split(".", 1)[0] for alias in node.names}
                unexpected = imported - ALLOWED_STDLIB_IMPORTS
                if unexpected:
                    raise BrowserEngineBuildError(
                        f"browser module imports unreviewed dependency: {sorted(unexpected)[0]}"
                    )
            elif isinstance(node, ast.ImportFrom):
                if node.level:
                    if node.level != 1 or not node.module:
                        raise BrowserEngineBuildError(
                            f"browser module has unsupported relative import: {relative_path}"
                        )
                    pending.append(node.module.split(".", 1)[0])
                else:
                    imported = (node.module or "").split(".", 1)[0]
                    if imported not in ALLOWED_STDLIB_IMPORTS:
                        raise BrowserEngineBuildError(
                            f"browser module imports unreviewed dependency: {imported}"
                        )
    if observed != allowed_modules:
        unused = sorted(allowed_modules - observed)
        raise BrowserEngineBuildError(
            f"browser wheel allowlist contains unused module: {unused[0]}"
        )


def _metadata() -> bytes:
    return (
        "Metadata-Version: 2.4\n"
        "Name: heel-browser\n"
        f"Version: {ENGINE_VERSION}\n"
        "Summary: Heel browser-local OpenAPI launch review kernel\n"
        "Requires-Python: >=3.11\n"
        "License-Expression: Apache-2.0\n"
        "License-File: LICENSE\n"
        "License-File: NOTICE\n"
        "\n"
    ).encode("utf-8")


def _wheel_metadata() -> bytes:
    return (
        "Wheel-Version: 1.0\n"
        "Generator: heel-browser-engine\n"
        "Root-Is-Purelib: true\n"
        "Tag: py3-none-any\n"
        "\n"
    ).encode("utf-8")


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
    info = zipfile.ZipInfo(path, date_time=FIXED_TIMESTAMP)
    info.create_system = 3
    info.external_attr = (stat.S_IFREG | 0o644) << 16
    info.compress_type = zipfile.ZIP_STORED
    return info


def build_wheel() -> bytes:
    _prove_import_closure()
    payloads = {path: _regular_source(path) for path in MODULE_PATHS}
    payloads.update({
        f"{DIST_INFO}/METADATA": _metadata(),
        f"{DIST_INFO}/WHEEL": _wheel_metadata(),
        f"{DIST_INFO}/licenses/LICENSE": _regular_source("LICENSE"),
        f"{DIST_INFO}/licenses/NOTICE": _regular_source("NOTICE"),
    })
    payloads[RECORD_PATH] = _record(payloads)

    output = io.BytesIO()
    with zipfile.ZipFile(output, mode="w", compression=zipfile.ZIP_STORED) as archive:
        for path in (*sorted(name for name in payloads if name != RECORD_PATH), RECORD_PATH):
            archive.writestr(_zip_info(path), payloads[path])
    return output.getvalue()


def build_manifest(wheel: bytes) -> bytes:
    manifest = {
        "engine_version": ENGINE_VERSION,
        "schema_version": "heel.browser-engine-manifest.v1",
        "wheel": {
            "filename": WHEEL_NAME,
            "sha256": hashlib.sha256(wheel).hexdigest(),
            "size": len(wheel),
        },
    }
    return (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "utf-8"
    )


def _write_atomic(output: Path, filename: str, payload: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=".heel-browser-", dir=output)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, output / filename)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _check_exact(path: Path, expected: bytes) -> None:
    try:
        actual = path.read_bytes()
    except OSError as error:
        raise BrowserEngineBuildError(f"generated artifact is missing: {path.name}") from error
    if actual != expected:
        raise BrowserEngineBuildError(f"generated artifact is stale: {path.name}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args(argv)
    output = arguments.output.expanduser().absolute()
    try:
        wheel = build_wheel()
        manifest = build_manifest(wheel)
        if arguments.check:
            _check_exact(output / WHEEL_NAME, wheel)
            _check_exact(output / "manifest.json", manifest)
        else:
            output.mkdir(parents=True, exist_ok=True)
            if not output.is_dir():
                raise BrowserEngineBuildError("output must be a directory")
            _write_atomic(output, WHEEL_NAME, wheel)
            _write_atomic(output, "manifest.json", manifest)
    except (BrowserEngineBuildError, OSError) as error:
        print(f"browser engine build failed: {error}", file=sys.stderr)
        return 1
    print("browser engine artifacts are current" if arguments.check else f"built {WHEEL_NAME}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
