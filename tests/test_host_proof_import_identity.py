"""The H1 authority-proof fixture shares one authority/profile/codec set with its cycle in any import order.

``deploy/host/cycle.py`` and ``deploy/host/h2_policy.py`` install the authority domain, the runtime
profile and the authority codec under fixed ``sys.modules`` names and reuse a module already there
(the cleanup registry of ``authority.py`` is process-global state). The proof fixture
``tests/linux/test_host_authority_proof.py`` must bind its AUTHORITY, PROFILE and LISTENER to the
very objects its CYCLE uses, whether or not another collector loaded them first: a second copy is a
second exception hierarchy and a second, invisible cleanup registry. Every case runs in a fresh
Python process, compares object identities (never equality), and drives pytest by file collection
with ``-k`` because naming an explicit H1 node imports H1 first and hides the order. No network,
listener, namespace or privilege is used; the proof's dynamic cases skip without the launcher.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROOF_MODULE = "tests/linux/test_host_authority_proof.py"
H2_UNIT_MODULE = "tests/test_host_h2_policy.py"
IDENTITY_CASE = "test_static_profile_pin_and_closure_are_imported_from_h1f_not_copied"
CANONICAL = ("heel_host_authority_domain", "heel_host_profile", "heel_host_authority_codec")

# Runs in a fresh interpreter: argv = [root, preload kind]; preload is "cycle", "h2" or "none".
# It loads what an earlier collector would, then the proof fixture as pytest would, and prints the
# identity facts as JSON for the parent to assert.
PROBE = r'''
import importlib.util, json, sys
from pathlib import Path

root, preload = Path(sys.argv[1]), sys.argv[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


before = {}
if preload == "cycle":
    pre = load("heel_host_cycle_preload", root / "deploy" / "host" / "cycle.py")
    before = {"authority": pre.authority, "profile": pre.profile, "codec": pre.codec}
elif preload == "h2":
    pre = load("heel_host_h2_policy_preload", root / "deploy" / "host" / "h2_policy.py")
    before = {"authority": pre._authority, "codec": pre._codec}
names = ("heel_host_authority_domain", "heel_host_profile", "heel_host_authority_codec")
cached = {name: sys.modules.get(name) for name in names}
proof = load("heel_proof_identity_probe", root / "tests" / "linux" / "test_host_authority_proof.py")
fixture = {"authority": proof.AUTHORITY, "profile": proof.PROFILE, "codec": proof.LISTENER}
cycle = {"authority": proof.CYCLE.authority, "profile": proof.CYCLE.profile, "codec": proof.CYCLE.codec}
by_name = dict(zip(names, ("authority", "profile", "codec")))
result = {
    "fixture_is_cycle": {key: fixture[key] is cycle[key] for key in fixture},
    "fixture_is_preloaded": {key: fixture[key] is before[key] for key in before},
    "cache_kept": {name: cached[name] is None or sys.modules.get(name) is cached[name] for name in names},
    "cache_is_fixture": {name: sys.modules.get(name) is fixture[by_name[name]] for name in names},
    "registry_shared": proof.AUTHORITY._UNREAPED is proof.CYCLE.authority._UNREAPED,
    "reap_lock_shared": proof.AUTHORITY._REAP_LOCK is proof.CYCLE.authority._REAP_LOCK,
    "exceptions_shared": all(getattr(proof.AUTHORITY, name) is getattr(proof.CYCLE.authority, name)
                             for name in ("InstallerFailed", "PrepareFailed", "DomainUnavailable", "HostQuarantined")),
    "launcher_profile_is_cycle": proof.LAUNCHER.profile() is proof.CYCLE.profile,
    "files": {key: str(Path(module.__file__).resolve()) for key, module in fixture.items()},
}
if "authority" in before:
    result["registry_is_preloaded"] = proof.AUTHORITY._UNREAPED is before["authority"]._UNREAPED
    result["exception_is_preloaded"] = proof.AUTHORITY.InstallerFailed is before["authority"].InstallerFailed
print(json.dumps(result))
'''


def _env(tmp_path: Path) -> dict:
    """A constructed environment: no inherited pytest options, plugins or proof switches."""
    (tmp_path / "tmp").mkdir(exist_ok=True)
    return {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C", "HOME": str(tmp_path),
            "TMPDIR": str(tmp_path / "tmp"), "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1"}


def _probe(root: Path, preload: str, tmp_path: Path) -> dict:
    done = subprocess.run([sys.executable, "-I", "-B", "-c", PROBE, str(root), preload], cwd=root, env=_env(tmp_path),
                          capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


def _assert_one_set(result: dict, root: Path) -> None:
    assert result["fixture_is_cycle"] == {"authority": True, "profile": True, "codec": True}, result
    assert all(result["fixture_is_preloaded"].values()), result
    assert all(result["cache_kept"].values()) and all(result["cache_is_fixture"].values()), result
    assert result["registry_shared"] and result["reap_lock_shared"] and result["exceptions_shared"], result
    assert result["files"] == {"authority": str(root / "deploy" / "host" / "authority.py"),
                               "profile": str(root / "deploy" / "host" / "profile.py"),
                               "codec": str(root / "heel" / "saas" / "host_authority.py")}, result


def _pytest(root: Path, files: list[str], tmp_path: Path, *config: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-I", "-B", "-m", "pytest", "-p", "no:cacheprovider", "-q", "-rA",
                           "--tb=short", *config, *files, "-k", IDENTITY_CASE], cwd=root, env=_env(tmp_path),
                          capture_output=True, text=True, timeout=300)


def test_authority_proof_reuses_preloaded_cycle_dependencies(tmp_path):
    result = _probe(ROOT, "cycle", tmp_path)
    assert set(result["fixture_is_preloaded"]) == {"authority", "profile", "codec"}
    assert result["registry_is_preloaded"] and result["exception_is_preloaded"], result
    _assert_one_set(result, ROOT)


def test_authority_proof_reuses_preloaded_h2_authority(tmp_path):
    result = _probe(ROOT, "h2", tmp_path)
    assert set(result["fixture_is_preloaded"]) == {"authority", "codec"}
    assert result["registry_is_preloaded"] and result["exception_is_preloaded"], result
    _assert_one_set(result, ROOT)


def test_authority_proof_import_order_is_independent(tmp_path):
    for files in ([H2_UNIT_MODULE, PROOF_MODULE], [PROOF_MODULE, H2_UNIT_MODULE]):
        done = _pytest(ROOT, files, tmp_path)
        tail = done.stdout.strip().splitlines()[-1] if done.stdout.strip() else ""
        assert done.returncode == 0 and f"PASSED {PROOF_MODULE}::{IDENTITY_CASE}" in done.stdout, (files, done.stdout,
                                                                                                    done.stderr)
        assert re.fullmatch(r"1 passed, [0-9]+ deselected in [0-9.]+s", tail), (files, tail)


def test_authority_proof_clean_staged_closure_preserves_identity(tmp_path):
    spec = importlib.util.spec_from_file_location("host_authority_proof_identity_stage", ROOT / "scripts" /
                                                  "host_authority_proof.py")
    launcher = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(launcher)
    assert launcher.TEST_MODULE == PROOF_MODULE
    source = launcher.stage_tree(tmp_path / "stage" / "src").resolve()
    staged = sorted(str(path.relative_to(source)) for path in source.rglob("*") if path.is_file())
    assert staged == sorted(launcher.STAGE_FILES) and H2_UNIT_MODULE not in staged
    result = _probe(source, "none", tmp_path)
    assert result["fixture_is_preloaded"] == {} and result["launcher_profile_is_cycle"], result
    _assert_one_set(result, source)
    # The launcher's child: a fresh pytest over the staged tree and its one module, outside any ancestor config.
    done = _pytest(source, [PROOF_MODULE], tmp_path, "-c", os.devnull, f"--rootdir={source}")
    assert done.returncode == 0 and f"PASSED {PROOF_MODULE}::{IDENTITY_CASE}" in done.stdout, done.stdout + done.stderr
