"""R26 and R27: the shipped runner modules and the checked-in release artifacts agree.

These tests only read. They never write under ``apps/``.
"""
from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import zipfile


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "release/open-core-v1.json"
BUILDER = ROOT / "scripts/build_open_core_release.py"
DOWNLOADS = ROOT / "apps/heel-cloud/public/downloads"
VERSION = "1.3.0rc1"
WHEEL = f"heel_sim-{VERSION}-py3-none-any.whl"
SDIST = f"heel_sim-{VERSION}.tar.gz"
MANIFEST = "heel-open-core-manifest.json"
NEW_MODULE = "heel/runner/plan_differential.py"
EXTENDED = (
    "heel/runner/catalog.py", "heel/runner/compiler.py", "heel/runner/http_transport.py",
    "heel/runner/store.py",
)


def _contract_modules() -> list[str]:
    return json.loads(CONTRACT.read_text(encoding="utf-8"))["python_modules"]


def _module_name(path: str) -> str:
    return path.removesuffix(".py").removesuffix("/__init__").replace("/", ".")


def test_r26_shipped_runner_modules_match_the_checked_in_wheel():
    modules = _contract_modules()
    runner_modules = [path for path in modules if path.startswith("heel/runner/")]
    assert NEW_MODULE in runner_modules and set(EXTENDED) <= set(runner_modules)
    # The contract names every runner module in the tree; none ships unlisted.
    assert sorted(runner_modules) == sorted(
        "heel/runner/" + path.name for path in (ROOT / "heel/runner").glob("*.py")
    )
    with zipfile.ZipFile(DOWNLOADS / WHEEL) as wheel, tarfile.open(DOWNLOADS / SDIST, "r:gz") as sdist:
        for path in runner_modules:
            source = (ROOT / path).read_bytes()
            assert wheel.read(path) == source, path
            member = sdist.extractfile(f"heel_sim-{VERSION}/" + path)
            assert member is not None and member.read() == source, path

    # The new module imports only shipped modules and the standard library; cryptography is
    # imported lazily, inside functions, never at module import.
    shipped = {_module_name(path) for path in modules}
    tree = ast.parse((ROOT / NEW_MODULE).read_text(encoding="utf-8"))
    top_level = {id(node) for node in tree.body}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base = "heel.runner" if node.level == 1 else "heel"
                names = [base + ("." + node.module if node.module else "")]
            else:
                names = [node.module or ""]
        else:
            continue
        for name in names:
            root = name.split(".")[0]
            if root == "heel":
                assert name in shipped, name
            elif root == "cryptography":
                assert id(node) not in top_level, "cryptography must be imported lazily"
            else:
                assert root in sys.stdlib_module_names, name


def test_r27_release_artifacts_are_current_and_exactly_three():
    specification = importlib.util.spec_from_file_location(
        "heel_open_core_release_builder_for_plan_differential", BUILDER,
    )
    assert specification is not None and specification.loader is not None
    builder = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(builder)
    assert (builder.WHEEL_NAME, builder.SDIST_NAME, builder.MANIFEST_NAME) == (WHEEL, SDIST, MANIFEST)

    # The same comparison the CI package job makes with --check, on the working tree.
    built = builder.build_release()
    assert set(built) == {WHEEL, SDIST, MANIFEST}
    checked_in = {name: (DOWNLOADS / name).read_bytes() for name in (WHEEL, SDIST, MANIFEST)}
    for name in (MANIFEST, WHEEL, SDIST):
        assert built[name] == checked_in[name], f"generated artifact is stale: {name}"

    manifest = json.loads(checked_in[MANIFEST])
    assert manifest["version"] == VERSION
    assert {item["name"]: (item["sha256"], item["size"]) for item in manifest["artifacts"]} == {
        name: (hashlib.sha256(checked_in[name]).hexdigest(), len(checked_in[name]))
        for name in (WHEEL, SDIST)
    }

    with zipfile.ZipFile(DOWNLOADS / WHEEL) as wheel:
        names = wheel.namelist()
        assert NEW_MODULE in names
        assert wheel.read(NEW_MODULE) == (ROOT / NEW_MODULE).read_bytes()
        assert not any(name.startswith("tests/") for name in names)
        (entry_points,) = [name for name in names if name.endswith(".dist-info/entry_points.txt")]
        assert "heel = heel.cli:main" in wheel.read(entry_points).decode("utf-8").splitlines()

    # The downloads directory holds exactly the three authorized artifacts.
    tracked = subprocess.run(
        ["git", "ls-files", "apps/heel-cloud/public/downloads"], cwd=ROOT, check=True,
        capture_output=True, text=True,
    ).stdout.splitlines()
    assert sorted(tracked) == sorted(
        "apps/heel-cloud/public/downloads/" + name for name in (MANIFEST, WHEEL, SDIST)
    )
    assert sorted(path.name for path in DOWNLOADS.iterdir()) == sorted((MANIFEST, WHEEL, SDIST))
