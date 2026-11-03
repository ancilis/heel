"""The private managed codec stays out of the public open-core artifacts (C4 P01).

``heel/saas/managed_authority_contracts.py`` is commercial, private control-plane code. These
checks inspect the real committed wheel, source archive and manifest, rebuild all three in a
scratch directory and compare bytes, install the committed wheel outside the checkout and run
useful public operations from it with the private modules absent, and confirm the release
builder refuses the three ways the codec could leak into the public closure.

What this does NOT prove: private image delivery of the codec (P17 owns the ``/opt/heel`` image
proof), managed admission, pairing, serving, HTTP, hosted findings or any runtime behaviour. A
public wheel that works does not authorize any managed fallback.
"""
from __future__ import annotations

import ast
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import sysconfig
import tarfile
import tempfile
import zipfile

import pytest


ROOT = Path(__file__).resolve().parents[1]
DOWNLOADS = ROOT / "apps/heel-cloud/public/downloads"
CONTRACT = ROOT / "release/open-core-v1.json"
BUILDER = ROOT / "scripts/build_open_core_release.py"
PRIVATE_CODEC = "heel/saas/managed_authority_contracts.py"
OLD_PUBLIC_PATH = "heel/managed_authority_contracts.py"
# Pinned private codec revisions. 126b2186 is the original P01 codec (candidate 5fa01be8), moved
# byte-identically to heel/saas at cee76db7. The current pin is the deliberate C4-P01-SEMANTIC-FIX
# revision of those bytes (observation phase matrix + fixed surrogate refusal only), pending independent
# review. Any other change to the private codec must update this pin consciously, never silently.
RELOCATED_CODEC_SHA256 = "126b2186636579fd3206609526355abdbd32a2aba4582510317befcbd2cb3915"
CODEC_SHA256 = "c02b5ae91f2bf52f18c365502f98e0934ef7914072a3d5a2602bde69042ec28e"
COMMERCIAL_MARKER = b"LicenseRef-Heel-Commercial"
VERSION = json.loads(CONTRACT.read_text(encoding="utf-8"))["version"]
WHEEL = f"heel_sim-{VERSION}-py3-none-any.whl"
SDIST = f"heel_sim-{VERSION}.tar.gz"
MANIFEST = "heel-open-core-manifest.json"
ARTIFACTS = (WHEEL, SDIST, MANIFEST)
PRIVATE_PREFIXES = ("heel/saas/", "deploy/", "tests/", "apps/", "docs/saas/", "docs/superpowers/", "web/")
SECRET_NAME = re.compile(r"(^|/)(\.env[^/]*|[^/]*\.(pem|key|p12|pfx|sqlite3?|db)|id_(rsa|ed25519)[^/]*|[^/]*secret[^/]*)$",
                         re.IGNORECASE)
CRYPTOGRAPHY_CLOSURE = ("cryptography", "cffi", "pycparser")
TIMEOUT = 300


def _contract() -> dict:
    return json.loads(CONTRACT.read_text(encoding="utf-8"))


def _public_paths() -> list[str]:
    contract = _contract()
    return sorted({path for field in ("build_files", "documents", "licenses", "package_data", "python_modules")
                   for path in contract[field]})


def _tracked(*paths: str) -> set[str]:
    out = subprocess.run(["git", "ls-files", "-z", "--", *paths], cwd=ROOT, capture_output=True, check=True).stdout
    return {name for name in out.decode().split("\0") if name}


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _wheel_members(payload: bytes) -> dict[str, bytes]:
    with tempfile.TemporaryDirectory(prefix="heel-p01-wheel-") as temporary:
        path = Path(temporary) / WHEEL
        path.write_bytes(payload)
        with zipfile.ZipFile(path) as wheel:
            return {name: wheel.read(name) for name in wheel.namelist() if not name.endswith("/")}


def _sdist_members(payload: bytes) -> dict[str, bytes]:
    prefix = f"heel_sim-{VERSION}/"
    members: dict[str, bytes] = {}
    with tempfile.TemporaryDirectory(prefix="heel-p01-sdist-") as temporary:
        path = Path(temporary) / SDIST
        path.write_bytes(payload)
        with tarfile.open(path, "r:gz") as sdist:
            for member in sdist.getmembers():
                assert member.isfile() or member.isdir(), member.name
                assert member.name == prefix.rstrip("/") or member.name.startswith(prefix), member.name
                if member.isfile():
                    stream = sdist.extractfile(member)
                    assert stream is not None
                    members[member.name[len(prefix):]] = stream.read()
    return members


def _builder_env() -> dict[str, str]:
    environment = {key: value for key, value in os.environ.items() if key not in ("PYTHONHOME", "PYTHONPATH")}
    environment.update({"LANG": "C", "LC_ALL": "C", "PYTHONHASHSEED": "1", "PYTHONNOUSERSITE": "1"})
    return environment


def _run_builder(builder: Path, output: Path, *extra: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, "-I", str(builder), "--output", str(output), *extra], cwd=output.parent,
                          env=_builder_env(), capture_output=True, text=True, timeout=TIMEOUT)


def _tree_state(path: Path) -> dict[str, tuple[int, int, bytes]]:
    return {child.name: (child.stat().st_mode, child.stat().st_mtime_ns, child.read_bytes())
            for child in sorted(path.iterdir())}


def _absolute_import_targets(path: str, tree: ast.Module) -> set[str]:
    """Every module an import statement in ``path`` names, resolved to an absolute dotted name."""
    package = PurePosixPath(path).with_suffix("").parts[:-1]
    if PurePosixPath(path).name == "__init__.py":
        package = PurePosixPath(path).parent.parts
    targets: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            targets.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = package[: len(package) - (node.level - 1)] if node.level > 1 else package
                stem = ".".join(base)
            else:
                stem = ""
            module = ".".join(part for part in (stem, node.module or "") if part)
            targets.add(module)
            targets.update(f"{module}.{alias.name}" for alias in node.names)
        elif isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant):
            name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
            if name in ("import_module", "__import__", "find_spec") and isinstance(node.args[0].value, str):
                targets.add(node.args[0].value)
    return targets


# ---------------------------------------------------------------------------------------------
# Source classification


def test_private_codec_is_under_saas_at_its_pinned_revision_with_its_commercial_header():
    assert PRIVATE_CODEC in _tracked("heel"), "private codec is not tracked under heel/saas"
    assert OLD_PUBLIC_PATH not in _tracked("heel") and not (ROOT / OLD_PUBLIC_PATH).exists(), "old public path remains"
    payload = (ROOT / PRIVATE_CODEC).read_bytes()
    assert _sha256(payload) == CODEC_SHA256 != RELOCATED_CODEC_SHA256
    assert b"SPDX-License-Identifier: " + COMMERCIAL_MARKER in payload.split(b"\n\n", 2)[1]
    # No shim, copy or second definition anywhere in the tracked heel tree.
    for name in sorted(_tracked("heel")):
        if name != PRIVATE_CODEC and name.endswith(".py"):
            assert b"managed_authority_contracts" not in (ROOT / name).read_bytes(), name
    # Only the codec's own tests import it; they import the private path.
    test_source = (ROOT / "tests/test_managed_authority_contracts.py").read_text(encoding="utf-8")
    assert "from heel.saas import managed_authority_contracts as mac" in test_source
    assert "from heel.saas.managed_authority_contracts import ManagedContractError" in test_source
    assert "from heel import managed_authority_contracts" not in test_source


def test_release_contract_never_lists_the_private_codec_or_any_private_prefix():
    for path in _public_paths():
        assert not path.startswith(PRIVATE_PREFIXES), path
        assert "managed_authority" not in path, path
    builder_source = BUILDER.read_text(encoding="utf-8")
    # The builder's own refusal lists stay as they were (this packet edits no release policy).
    for literal in ('"heel/saas/"', 'b"LicenseRef-Heel-Commercial"', '"deploy/"', '"tests/"'):
        assert literal in builder_source, literal


def test_public_sources_never_reference_or_import_the_private_codec():
    contract = _contract()
    for path in contract["python_modules"] + contract["package_data"]:
        payload = (ROOT / path).read_bytes()
        for marker in (COMMERCIAL_MARKER, b"managed_authority", b"heel.saas", b"heel/saas"):
            assert marker not in payload, (path, marker)
    for path in contract["python_modules"]:
        tree = ast.parse((ROOT / path).read_bytes(), filename=path)
        for target in _absolute_import_targets(path, tree):
            assert target != "heel.saas" and not target.startswith("heel.saas."), (path, target)
            assert "managed_authority" not in target, (path, target)


def test_import_resolver_sees_every_relative_and_dynamic_form():
    """Positive control for the scan above: each leak form resolves to the private package."""
    forms = {
        "heel/runner/execution.py": ("from ..saas import managed_authority_contracts",
                                     "from ..saas.managed_authority_contracts import ManagedContractError"),
        "heel/cli.py": ("from .saas import managed_authority_contracts", "from . import saas",
                        "import heel.saas.managed_authority_contracts",
                        "importlib.import_module('heel.saas.managed_authority_contracts')",
                        "__import__('heel.saas.managed_authority_contracts')"),
    }
    for path, statements in forms.items():
        for statement in statements:
            targets = _absolute_import_targets(path, ast.parse(statement))
            assert any(t == "heel.saas" or t.startswith("heel.saas.") for t in targets), (path, statement, targets)


# ---------------------------------------------------------------------------------------------
# Committed artifacts


def test_committed_artifacts_exclude_every_private_member_and_carry_the_current_public_bytes():
    artifacts = {name: (DOWNLOADS / name).read_bytes() for name in ARTIFACTS}
    assert {path.name for path in DOWNLOADS.iterdir()} == set(ARTIFACTS)
    manifest = json.loads(artifacts[MANIFEST])
    records = {record["name"]: record for record in manifest["artifacts"]}
    assert sorted(records) == sorted((WHEEL, SDIST)) and manifest["version"] == VERSION
    for name in (WHEEL, SDIST):
        assert records[name] == {**records[name], "sha256": _sha256(artifacts[name]), "size": len(artifacts[name])}
    codec = (ROOT / PRIVATE_CODEC).read_bytes()
    contract = _contract()
    wheel = _wheel_members(artifacts[WHEEL])
    sdist = _sdist_members(artifacts[SDIST])
    for label, members in (("wheel", wheel), ("sdist", sdist)):
        for name, payload in members.items():
            assert not name.startswith(PRIVATE_PREFIXES), (label, name)
            assert "managed_authority" not in name and "saas" not in PurePosixPath(name).parts, (label, name)
            assert not SECRET_NAME.search(name), (label, name)
            assert COMMERCIAL_MARKER not in payload and b"managed_authority" not in payload, (label, name)
            assert codec not in payload, (label, name)
    # Source-hash parity: every public module and data file ships exactly the checkout's bytes.
    for path in contract["python_modules"] + contract["package_data"]:
        assert wheel[path] == (ROOT / path).read_bytes(), ("wheel", path)
    for path in _public_paths():
        assert sdist[path] == (ROOT / path).read_bytes(), ("sdist", path)
    shipped_python = {name for name in wheel if name.endswith(".py")}
    assert shipped_python == set(contract["python_modules"])


def test_independent_rebuild_is_byte_identical_and_check_leaves_the_downloads_untouched(tmp_path):
    output = tmp_path / "rebuilt"
    built = _run_builder(BUILDER, output)
    assert built.returncode == 0, built.stdout + built.stderr
    assert sorted(path.name for path in output.iterdir()) == sorted(ARTIFACTS)
    for name in ARTIFACTS:
        assert (output / name).read_bytes() == (DOWNLOADS / name).read_bytes(), name
    before = _tree_state(DOWNLOADS)
    checked = _run_builder(BUILDER, DOWNLOADS, "--check")
    assert checked.returncode == 0, checked.stdout + checked.stderr
    assert _tree_state(DOWNLOADS) == before


# ---------------------------------------------------------------------------------------------
# Installed public wheel, outside the checkout, private modules absent


_DRIVER = r'''
import hashlib, importlib, importlib.util, json, sys
from pathlib import Path

venv, checkout = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
modules = json.loads(sys.argv[3])
for entry in sys.path:
    if entry and Path(entry).resolve().is_relative_to(checkout):
        raise SystemExit(f"checkout on sys.path: {entry}")
origins = {}
for name in modules:
    module = importlib.import_module(name)
    origin = Path(module.__file__).resolve()
    if not origin.is_relative_to(venv):
        raise SystemExit(f"{name} not imported from the installed wheel: {origin}")
    origins[name] = [str(origin.relative_to(venv)), hashlib.sha256(origin.read_bytes()).hexdigest()]
private = {}
for name in ("heel.saas", "heel.saas.managed_authority_contracts", "heel.managed_authority_contracts"):
    try:
        private[name] = importlib.util.find_spec(name) is not None
    except ModuleNotFoundError as error:
        private[name] = "missing:" + str(error.name)
try:
    importlib.import_module("heel.saas.managed_authority_contracts")
except ModuleNotFoundError as error:
    refused = error.name
else:
    raise SystemExit("private codec resolved from the public install")
leaked = sorted(name for name in sys.modules if name.startswith("heel.saas") or "managed_authority" in name)
print(json.dumps({"origins": origins, "private": private, "refused": refused, "leaked": leaked}, sort_keys=True))
'''

_MCP_MESSAGES = (
    {"jsonrpc": "2.0", "id": 1, "method": "initialize",
     "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "heel-p01", "version": "1"}}},
    {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
    {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
    {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "heel_review_openapi", "arguments": {
        "openapi": {"openapi": "3.1.0", "info": {"title": "P01 synthetic", "version": "1.0.0"}, "paths": {}}}}},
)


def _provision_installed_cryptography(purelib: Path) -> dict[str, str]:
    """Copy the test interpreter's pinned cryptography closure into the venv (offline, source-free)."""
    versions = {}
    for name in CRYPTOGRAPHY_CLOSURE:
        distribution = importlib.metadata.distribution(name)
        versions[name] = distribution.version
        for relative in distribution.files or ():
            relative = PurePosixPath(str(relative))
            if relative.is_absolute() or ".." in relative.parts:
                continue
            source = Path(distribution.locate_file(relative))
            if source.is_file():
                target = purelib.joinpath(*relative.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
    assert versions["cryptography"] == "50.0.1", versions
    return versions


def test_installed_public_wheel_runs_useful_operations_source_free_with_private_codec_unresolvable(tmp_path):
    root = tmp_path.resolve()
    assert not root.is_relative_to(ROOT.resolve())
    workspace, acquisition, venv = root / "workspace", root / "acquisition", root / "venv"
    for path in (workspace, acquisition, root / "home"):
        path.mkdir(mode=0o700)
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("PYTHON", "PIP_", "HEEL_", "VIRTUAL_ENV", "UV_"))}
    environment.update({"HOME": str(root / "home"), "HEEL_HOME": str(root / "heel-home"), "PIP_CONFIG_FILE": os.devnull,
                        "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PIP_NO_CACHE_DIR": "1", "PIP_NO_INPUT": "1",
                        "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1"})

    def run(*command: str, stdin: str | None = None) -> str:
        result = subprocess.run(list(command), cwd=workspace, env=environment, input=stdin, capture_output=True,
                                text=True, timeout=TIMEOUT)
        assert result.returncode == 0, (command, result.stdout[-2000:], result.stderr[-2000:])
        return result.stdout

    shutil.copyfile(DOWNLOADS / WHEEL, acquisition / WHEEL)
    wheel_bytes = (acquisition / WHEEL).read_bytes()
    run(sys.executable, "-m", "venv", str(venv))
    python = str(venv / "bin/python")
    run(python, "-I", "-m", "pip", "--isolated", "install", "--no-index", "--no-deps", "--no-cache-dir",
        str(acquisition / WHEEL))
    purelib = Path(run(python, "-I", "-c", "import sysconfig;print(sysconfig.get_path('purelib'))").strip())
    assert purelib.is_relative_to(venv.resolve()) or purelib.is_relative_to(venv)
    _provision_installed_cryptography(purelib)
    assert sysconfig.get_python_version() == run(python, "-I", "-c", "import sysconfig;print(sysconfig.get_python_version())").strip()

    contract = _contract()
    modules = ["heel" if path == "heel/__init__.py" else path[:-3].removesuffix("/__init__").replace("/", ".")
               for path in contract["python_modules"]]
    driver = root / "driver.py"
    driver.write_text(_DRIVER, encoding="utf-8")
    evidence = json.loads(run(python, "-I", str(driver), str(venv), str(ROOT), json.dumps(modules)))
    wheel = _wheel_members(wheel_bytes)
    by_module = dict(zip(modules, contract["python_modules"]))
    for name, (relative, digest) in evidence["origins"].items():
        path = by_module[name]
        assert relative.endswith(path), (name, relative)
        assert digest == _sha256(wheel[path]) == _sha256((ROOT / path).read_bytes()), name
    assert evidence["private"] == {"heel.saas": False, "heel.saas.managed_authority_contracts": "missing:heel.saas",
                                   "heel.managed_authority_contracts": False}
    assert evidence["refused"] == "heel.saas" and evidence["leaked"] == []

    # Useful public operations from the installed console scripts.
    bin_dir = venv / "bin"
    doctor = run(str(bin_dir / "heel"), "doctor")
    assert f"heel {VERSION}" in doctor and "heel doctor: OK" in doctor
    responses = [json.loads(line) for line in run(
        str(bin_dir / "heel-mcp"), stdin="\n".join(json.dumps(m) for m in _MCP_MESSAGES) + "\n").splitlines() if line]
    assert [response["id"] for response in responses] == [1, 2, 3]
    assert responses[0]["result"]["serverInfo"]["name"] == "heel"
    assert "heel_review_openapi" in {tool["name"] for tool in responses[1]["result"]["tools"]}
    assert responses[2]["result"].get("isError") is not True
    scope = json.loads(run(str(bin_dir / "heel"), "scope", "create", "--target", "reference:export",
                           "--operator", "synthetic P01 parity test", "--confirm"))["created_scope"]
    outcomes = {case: json.loads(run(str(bin_dir / "heel"), "reference", "run", "--scope", scope, "--case", case,
                                     "--attempt", digit * 32))["result"]
                for case, digit in (("vulnerable", "a"), ("hardened", "b"), ("error_envelope", "c"), ("public", "d"))}
    assert outcomes == {"vulnerable": "verified_violation", "hardened": "inconclusive",
                        "error_envelope": "inconclusive", "public": "invariant_held"}
    assert (acquisition / WHEEL).read_bytes() == wheel_bytes == (DOWNLOADS / WHEEL).read_bytes()


# ---------------------------------------------------------------------------------------------
# Builder boundary mutants (scratch copies of the public builder input only)


def _copy_public_snapshot(destination: Path) -> None:
    for relative in ["scripts/build_open_core_release.py", *_public_paths()]:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)


def _restore_codec_as_public_module(source: Path) -> None:
    shutil.copy2(ROOT / PRIVATE_CODEC, source / OLD_PUBLIC_PATH)


def _import_private_codec_from_public_runner(source: Path) -> None:
    with (source / "heel/runner/execution.py").open("a", encoding="utf-8") as stream:
        stream.write("\nfrom heel.saas import managed_authority_contracts\n")


def _commercial_marker_in_public_source(source: Path) -> None:
    with (source / "heel/runner/http_transport.py").open("a", encoding="utf-8") as stream:
        stream.write("\n# SPDX-License-Identifier: LicenseRef-Heel-Commercial\n")


def _allowlist_private_codec(source: Path) -> None:
    contract_path = source / "release/open-core-v1.json"
    contract = json.loads(contract_path.read_text(encoding="utf-8"))
    contract["python_modules"] = sorted([*contract["python_modules"], PRIVATE_CODEC])
    contract_path.write_text(json.dumps(contract, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


@pytest.mark.parametrize(("mutation", "expected"), (
    (None, None),
    (_restore_codec_as_public_module, f"unclassified top-level module: {OLD_PUBLIC_PATH}"),
    (_import_private_codec_from_public_runner, "forbidden local import: heel.saas in heel/runner/execution.py"),
    (_commercial_marker_in_public_source, "public source contains forbidden content: heel/runner/http_transport.py"),
    (_allowlist_private_codec, f"contract path uses a forbidden prefix: {PRIVATE_CODEC}"),
), ids=("unmutated-control", "unlisted-public-module", "saas-import", "commercial-marker", "allowlisted-private-path"))
def test_builder_refuses_each_private_boundary_mutant_for_its_intended_reason(tmp_path, mutation, expected):
    source = tmp_path / "source"
    _copy_public_snapshot(source)
    if mutation is not None:
        mutation(source)
    output = tmp_path / "output"
    result = _run_builder(source / "scripts/build_open_core_release.py", output)
    text = result.stdout + result.stderr
    if expected is None:
        assert result.returncode == 0, text
        for name in ARTIFACTS:
            assert (output / name).read_bytes() == (DOWNLOADS / name).read_bytes(), name
        return
    assert result.returncode != 0, text
    assert expected in text, text
    assert not output.exists() or not any(output.iterdir()), sorted(path.name for path in output.iterdir())
