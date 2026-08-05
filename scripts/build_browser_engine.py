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


ROOT = Path(os.path.abspath(__file__)).parents[1]
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
# This is a trusted-source capability policy for the reviewed browser closure,
# not a malware sandbox for arbitrary Python or precompiled bytecode.
# Each import form and module attribute is derived from the current source closure.
# Additions require source review plus executable mutation coverage; imported module
# objects may not be aliased, copied, or rebound.
REVIEWED_MODULE_ATTRIBUTES = {
    "copy": frozenset({"deepcopy"}),
    "hashlib": frozenset({"sha256"}),
    "hmac": frozenset({"compare_digest"}),
    "json": frozenset({"JSONDecodeError", "dumps", "loads"}),
    "math": frozenset({"isfinite"}),
    "re": frozenset({"compile", "match", "sub"}),
}
REVIEWED_FROM_IMPORTS = {
    (0, "__future__"): frozenset({"annotations"}),
    (0, "dataclasses"): frozenset({"dataclass", "field"}),
    (0, "typing"): frozenset({"Any", "Mapping"}),
    (1, "openapi_model"): frozenset({
        "OpenAPIImportError",
        "QUESTION_PROMPTS",
        "operation_surface_id",
        "product_model_from_openapi",
    }),
    (1, "product_model"): frozenset({
        "LIST_FIELDS",
        "PRODUCT_MODEL_VERSION",
        "ProductModelError",
        "validate_product_model",
    }),
    (1, "review_answers"): frozenset({
        "ReviewAnswerError",
        "apply_review_answers",
        "parse_review_answers",
    }),
    (1, "review_contract"): frozenset({
        "build_review_envelope",
        "stable_json",
        "stable_json_hash",
        "validate_review_envelope",
    }),
    (1, "review_rules"): frozenset({"is_broad_scope"}),
    (1, "review_service"): frozenset({"review_openapi"}),
    (1, "static_review"): frozenset({"review_product_models"}),
}
# Bare calls have no ambient authority: only these closure-derived builtins,
# same-module definitions, and exact reviewed imports may be called by name.
REVIEWED_BUILTIN_CALLS = frozenset({
    "ValueError",
    "all",
    "any",
    "bool",
    "dict",
    "enumerate",
    "float",
    "frozenset",
    "isinstance",
    "len",
    "list",
    "ord",
    "set",
    "sorted",
    "str",
    "sum",
    "super",
    "tuple",
    "type",
})
# Attribute calls are either exact reviewed module capabilities, the single
# super().__init__ pattern, or these per-module data methods. Lambda, subscript,
# call-result, conditional, and every other indirect call target are rejected.
REVIEWED_DATA_METHOD_CALLS = {
    "__init__": frozenset(),
    "browser_review": frozenset({
        "append",
        "encode",
        "extend",
        "items",
        "lower",
        "pop",
    }),
    "openapi_model": frozenset({
        "append",
        "extend",
        "fromkeys",
        "fullmatch",
        "get",
        "items",
        "join",
        "keys",
        "lower",
        "pop",
        "search",
        "setdefault",
        "startswith",
        "strip",
        "update",
        "upper",
        "values",
    }),
    "product_model": frozenset({
        "append",
        "extend",
        "get",
        "items",
        "join",
        "search",
        "strip",
    }),
    "review_answers": frozenset({
        "append",
        "encode",
        "get",
        "items",
        "join",
        "lower",
        "setdefault",
        "startswith",
        "strip",
        "update",
        "upper",
    }),
    "review_contract": frozenset({
        "append",
        "encode",
        "fullmatch",
        "get",
        "hexdigest",
        "items",
        "sort",
        "strip",
    }),
    "review_rules": frozenset({"lower", "strip"}),
    "review_service": frozenset({"append", "get", "to_dict", "update"}),
    "static_review": frozenset({
        "add",
        "append",
        "extend",
        "get",
        "isalnum",
        "issubset",
        "join",
        "lower",
        "split",
        "strip",
        "to_dict",
    }),
}
FORBIDDEN_DYNAMIC_NAMES = frozenset({
    "__builtins__",
    "__import__",
    "builtins",
    "compile",
    "delattr",
    "eval",
    "exec",
    "getattr",
    "globals",
    "importlib",
    "locals",
    "open",
    "setattr",
    "vars",
})
FORBIDDEN_DYNAMIC_ATTRIBUTES = frozenset({
    "__base__",
    "__bases__",
    "__builtins__",
    "__class__",
    "__closure__",
    "__code__",
    "__dict__",
    "__func__",
    "__getattr__",
    "__getattribute__",
    "__globals__",
    "__import__",
    "__loader__",
    "__mro__",
    "__reduce__",
    "__reduce_ex__",
    "__spec__",
    "__subclasses__",
    "compile",
    "delattr",
    "eval",
    "exec",
    "getattr",
    "globals",
    "locals",
    "open",
    "setattr",
    "vars",
})


class BrowserEngineBuildError(RuntimeError):
    pass


def _static_string(node: ast.expr) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _static_string(node.left)
        right = _static_string(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def _forbidden_dynamic_primitive(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name) and node.id in FORBIDDEN_DYNAMIC_NAMES:
        return node.id
    if isinstance(node, ast.Attribute) and node.attr in FORBIDDEN_DYNAMIC_ATTRIBUTES:
        if (
            node.attr == "compile"
            and isinstance(node.value, ast.Name)
            and node.value.id == "re"
        ):
            return None
        return node.attr
    if isinstance(node, ast.Subscript):
        key = _static_string(node.slice)
        if key is not None and (
            key.startswith("_") or key in FORBIDDEN_DYNAMIC_ATTRIBUTES
        ):
            return key
    return None


def _reviewed_private_attribute(node: ast.Attribute) -> bool:
    return (
        node.attr == "__init__"
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "super"
        and not node.value.args
        and not node.value.keywords
    )


def _module_attribute_path(
    node: ast.Attribute,
    module_bindings: frozenset[str],
) -> tuple[str, tuple[str, ...]] | None:
    attributes: list[str] = []
    value: ast.expr = node
    while isinstance(value, ast.Attribute):
        attributes.append(value.attr)
        value = value.value
    if not isinstance(value, ast.Name) or value.id not in module_bindings:
        return None
    return value.id, tuple(reversed(attributes))


def _validate_reviewed_imports(
    tree: ast.Module,
    relative_path: str,
    pending: list[str],
) -> tuple[frozenset[str], frozenset[str]]:
    module_bindings: set[str] = set()
    imported_symbols: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name not in REVIEWED_MODULE_ATTRIBUTES:
                    dependency = alias.name.split(".", 1)[0]
                    raise BrowserEngineBuildError(
                        f"browser module imports unreviewed dependency: {dependency}"
                    )
                if alias.asname is not None:
                    raise BrowserEngineBuildError(
                        f"browser module uses unreviewed import alias: {alias.asname}"
                    )
                module_bindings.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level not in {0, 1} or (node.level == 1 and not module):
                raise BrowserEngineBuildError(
                    f"browser module has unsupported relative import: {relative_path}"
                )
            import_key = (node.level, module)
            allowed_symbols = REVIEWED_FROM_IMPORTS.get(import_key)
            if allowed_symbols is None:
                dependency = module.split(".", 1)[0]
                raise BrowserEngineBuildError(
                    f"browser module imports unreviewed dependency: {dependency}"
                )
            for alias in node.names:
                if alias.asname is not None:
                    raise BrowserEngineBuildError(
                        f"browser module uses unreviewed import alias: {alias.asname}"
                    )
                if alias.name.startswith("_") or alias.name not in allowed_symbols:
                    raise BrowserEngineBuildError(
                        f"browser module imports unreviewed symbol: {module}.{alias.name}"
                    )
                if module != "__future__":
                    imported_symbols.add(alias.name)
            if node.level == 1:
                pending.append(module)
    return frozenset(module_bindings), frozenset(imported_symbols)


def _validate_reviewed_module_uses(
    tree: ast.Module,
    module_bindings: frozenset[str],
) -> None:
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            if node.attr.startswith("_") and not _reviewed_private_attribute(node):
                raise BrowserEngineBuildError(
                    f"browser module uses unreviewed private attribute: {node.attr}"
                )
            rooted_attribute = _module_attribute_path(node, module_bindings)
            if rooted_attribute is not None:
                module, attributes = rooted_attribute
                allowed_attributes = REVIEWED_MODULE_ATTRIBUTES[module]
                if len(attributes) != 1 or attributes[0] not in allowed_attributes:
                    rendered = ".".join((module, *attributes))
                    raise BrowserEngineBuildError(
                        f"browser module uses unreviewed module attribute: {rendered}"
                    )
        elif (
            isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Load)
            and node.id in module_bindings
        ):
            parent = parents.get(node)
            if not isinstance(parent, ast.Attribute) or parent.value is not node:
                raise BrowserEngineBuildError(
                    f"browser module uses unreviewed module reference: {node.id}"
                )
        elif (
            isinstance(node, ast.Name)
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and node.id in module_bindings
        ):
            raise BrowserEngineBuildError(
                f"browser module rebinds reviewed module: {node.id}"
            )
        elif isinstance(node, ast.arg) and node.arg in module_bindings:
            raise BrowserEngineBuildError(
                f"browser module rebinds reviewed module: {node.arg}"
            )
        elif (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and node.name in module_bindings
        ):
            raise BrowserEngineBuildError(
                f"browser module rebinds reviewed module: {node.name}"
            )
        elif isinstance(node, ast.ExceptHandler) and node.name in module_bindings:
            raise BrowserEngineBuildError(
                f"browser module rebinds reviewed module: {node.name}"
            )


def _validate_reviewed_calls(
    tree: ast.Module,
    module: str,
    module_bindings: frozenset[str],
    imported_symbols: frozenset[str],
) -> frozenset[str]:
    local_call_targets = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    }
    reviewed_name_targets = (
        REVIEWED_BUILTIN_CALLS | local_call_targets | imported_symbols
    )
    reviewed_data_methods = REVIEWED_DATA_METHOD_CALLS[module]
    observed_builtin_calls: set[str] = set()
    observed_data_methods: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        target = node.func
        if isinstance(target, ast.Name):
            if target.id not in reviewed_name_targets:
                raise BrowserEngineBuildError(
                    f"browser module uses unreviewed call target: {target.id}"
                )
            if target.id in REVIEWED_BUILTIN_CALLS:
                observed_builtin_calls.add(target.id)
            continue
        if isinstance(target, ast.Attribute):
            if _module_attribute_path(target, module_bindings) is not None:
                continue
            if _reviewed_private_attribute(target):
                continue
            if target.attr not in reviewed_data_methods:
                raise BrowserEngineBuildError(
                    f"browser module uses unreviewed call target: attribute.{target.attr}"
                )
            observed_data_methods.add(target.attr)
            continue
        raise BrowserEngineBuildError(
            "browser module uses unreviewed call target shape: "
            f"{type(target).__name__}"
        )
    if observed_data_methods != reviewed_data_methods:
        unused = sorted(reviewed_data_methods - observed_data_methods)
        raise BrowserEngineBuildError(
            "browser call policy contains unused data method: "
            f"{module}.{unused[0]}"
        )
    return frozenset(observed_builtin_calls)


def _assert_no_symlink_components(
    path: Path,
    label: str,
    *,
    allow_missing: bool = False,
) -> Path:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        try:
            status = current.lstat()
        except FileNotFoundError as error:
            if allow_missing:
                continue
            raise BrowserEngineBuildError(f"{label} is unavailable: {current}") from error
        if stat.S_ISLNK(status.st_mode):
            raise BrowserEngineBuildError(
                f"{label} contains a symbolic link: {current}"
            )
    return absolute


def _regular_source(relative_path: str) -> bytes:
    _assert_no_symlink_components(ROOT, "browser source root")
    path = _assert_no_symlink_components(
        ROOT / relative_path,
        f"required source {relative_path}",
    )
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
    observed_builtin_calls: set[str] = set()
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
        module_bindings, imported_symbols = _validate_reviewed_imports(
            tree,
            relative_path,
            pending,
        )
        for node in ast.walk(tree):
            forbidden = _forbidden_dynamic_primitive(node)
            if forbidden is not None:
                raise BrowserEngineBuildError(
                    f"browser module uses forbidden dynamic primitive: {forbidden}"
                )
        _validate_reviewed_module_uses(tree, module_bindings)
        observed_builtin_calls.update(
            _validate_reviewed_calls(
                tree,
                module,
                module_bindings,
                imported_symbols,
            )
        )
    if observed != allowed_modules:
        unused = sorted(allowed_modules - observed)
        raise BrowserEngineBuildError(
            f"browser wheel allowlist contains unused module: {unused[0]}"
        )
    if observed_builtin_calls != REVIEWED_BUILTIN_CALLS:
        unused = sorted(REVIEWED_BUILTIN_CALLS - observed_builtin_calls)
        raise BrowserEngineBuildError(
            f"browser call policy contains unused builtin: {unused[0]}"
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
    _assert_no_symlink_components(output, "browser engine output")
    destination = _assert_no_symlink_components(
        output / filename,
        f"browser engine artifact {filename}",
        allow_missing=True,
    )
    descriptor, temporary_name = tempfile.mkstemp(prefix=".heel-browser-", dir=output)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        _assert_no_symlink_components(output, "browser engine output")
        _assert_no_symlink_components(temporary, "browser engine temporary artifact")
        _assert_no_symlink_components(
            destination,
            f"browser engine artifact {filename}",
            allow_missing=True,
        )
        os.replace(temporary, destination)
    finally:
        try:
            _assert_no_symlink_components(temporary, "browser engine temporary artifact")
        except BrowserEngineBuildError:
            pass
        else:
            temporary.unlink(missing_ok=True)


def _validate_output_directory(output: Path) -> None:
    _assert_no_symlink_components(output, "browser engine output")
    try:
        status = output.lstat()
    except OSError as error:
        raise BrowserEngineBuildError("output must be a directory") from error
    if not stat.S_ISDIR(status.st_mode):
        raise BrowserEngineBuildError("output must be a directory")


def _validate_output_artifacts(output: Path) -> None:
    for filename in (WHEEL_NAME, "manifest.json"):
        _assert_no_symlink_components(
            output / filename,
            f"browser engine artifact {filename}",
            allow_missing=True,
        )


def _check_exact(path: Path, expected: bytes) -> None:
    _assert_no_symlink_components(path, f"generated artifact {path.name}")
    try:
        actual = path.read_bytes()
    except OSError as error:
        raise BrowserEngineBuildError(f"generated artifact is missing: {path.name}") from error
    if actual != expected:
        raise BrowserEngineBuildError(f"generated artifact is stale: {path.name}")


def _prepare_output_directory(output: Path) -> None:
    _assert_no_symlink_components(
        output,
        "browser engine output",
        allow_missing=True,
    )
    output.mkdir(parents=True, exist_ok=True)
    _validate_output_directory(output)
    _validate_output_artifacts(output)
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
            _validate_output_directory(output)
            _validate_output_artifacts(output)
            _check_exact(output / WHEEL_NAME, wheel)
            _check_exact(output / "manifest.json", manifest)
        else:
            _prepare_output_directory(output)
            _write_atomic(output, WHEEL_NAME, wheel)
            _write_atomic(output, "manifest.json", manifest)
    except (BrowserEngineBuildError, OSError) as error:
        print(f"browser engine build failed: {error}", file=sys.stderr)
        return 1
    print("browser engine artifacts are current" if arguments.check else f"built {WHEEL_NAME}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
