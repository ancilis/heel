"""Candidate runner preview artifacts install and run without the source tree.

These checks use only the committed candidate wheel, source archive and manifest plus public
synthetic inputs.  They are packaging evidence for the ``[runner]`` extra: they do not pair,
serve, open an HTTP socket, sync findings, or prove any hosted or customer-target journey, and
they make no claim that the candidate has been published.

The installation case needs a package index for ``cryptography`` and its dependencies.  Local
runs skip it when that prerequisite is unavailable; ``HEEL_REQUIRE_RUNNER_EXTRA_INSTALL=1``
turns every skip into a failure so the required CI gate cannot pass by skipping.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]
DOWNLOADS = ROOT / "apps/heel-cloud/public/downloads"
CONTRACT = ROOT / "release/open-core-v1.json"
VERSION = "1.3.0rc1"
WHEEL = f"heel_sim-{VERSION}-py3-none-any.whl"
SDIST = f"heel_sim-{VERSION}.tar.gz"
MANIFEST = "heel-open-core-manifest.json"
RUNNER_REQUIREMENT = "cryptography==45.0.7"
INSTALL_REQUIRED = os.environ.get("HEEL_REQUIRE_RUNNER_EXTRA_INSTALL") == "1"
# Optional reviewer evidence: a directory outside the checkout receives a JSON summary.
EVIDENCE_DIR = os.environ.get("HEEL_RUNNER_EXTRA_EVIDENCE_DIR")
DIGEST = re.compile(rb"(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])")
# Phrases a packaging test must never print as an outcome: it proves none of them.
UNPROVEN_CLAIMS = ("paired", "serving", "http_verified", "findings_synced", "launch_ready")


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"


def _candidate_bytes() -> dict[str, bytes]:
    return {name: (DOWNLOADS / name).read_bytes() for name in (WHEEL, SDIST, MANIFEST)}


def _verified_manifest(artifacts: dict[str, bytes]) -> dict:
    manifest = json.loads(artifacts[MANIFEST])
    if artifacts[MANIFEST] != _canonical(manifest):
        raise AssertionError("candidate manifest is not canonical JSON")
    if manifest["schema_version"] != "heel.open-core-artifacts.v1" or manifest["version"] != VERSION:
        raise AssertionError("candidate manifest identity mismatch")
    records = {record["name"]: record for record in manifest["artifacts"]}
    if [record["name"] for record in manifest["artifacts"]] != [WHEEL, SDIST]:
        raise AssertionError("candidate manifest artifact set mismatch")
    for name in (WHEEL, SDIST):
        if records[name]["size"] != len(artifacts[name]):
            raise AssertionError(f"{name}: size mismatch")
        if records[name]["sha256"] != hashlib.sha256(artifacts[name]).hexdigest():
            raise AssertionError(f"{name}: digest mismatch")
    return manifest


def render_external_installer(manifest_bytes: bytes) -> str:
    """Installer text for surfaces outside the hashed closure (web page, release notes)."""
    manifest = json.loads(manifest_bytes)
    wheel = next(record for record in manifest["artifacts"] if record["name"] == WHEEL)
    return (
        f"# Heel runner preview {VERSION} (candidate; not a published release)\n"
        f"# {MANIFEST} sha256 {hashlib.sha256(manifest_bytes).hexdigest()}\n"
        f"# {WHEEL} sha256 {wheel['sha256']}\n"
        f"python -m pip install './{WHEEL}[runner]'\n"
    )


def _packaged_text(artifacts: dict[str, bytes]) -> dict[str, bytes]:
    members: dict[str, bytes] = {}
    with tempfile.TemporaryDirectory(prefix="heel-preview-closure-") as temporary:
        wheel_path = Path(temporary) / WHEEL
        sdist_path = Path(temporary) / SDIST
        wheel_path.write_bytes(artifacts[WHEEL])
        sdist_path.write_bytes(artifacts[SDIST])
        with zipfile.ZipFile(wheel_path) as wheel:
            for name in wheel.namelist():
                members[f"wheel:{name}"] = wheel.read(name)
        with tarfile.open(sdist_path, "r:gz") as sdist:
            for member in sdist.getmembers():
                if member.isfile():
                    stream = sdist.extractfile(member)
                    assert stream is not None
                    members[f"sdist:{member.name}"] = stream.read()
    return members


class _SourceFreeEnvironment:
    """A fresh acquisition directory, venv, HOME and HEEL_HOME outside every checkout."""

    def __init__(self, test_case: unittest.TestCase, temporary: Path):
        self.test_case = test_case
        self.root = temporary
        self.acquisition = temporary / "acquisition"
        self.workspace = temporary / "workspace"
        self.venv = temporary / "venv"
        for path in (self.acquisition, self.workspace, temporary / "home"):
            path.mkdir(mode=0o700)
        environment = {
            key: value for key, value in os.environ.items()
            if not key.startswith(("PYTHON", "PIP_", "HEEL_", "VIRTUAL_ENV", "UV_"))
        }
        environment.update(
            {
                "HOME": str(temporary / "home"),
                "HEEL_HOME": str(temporary / "heel-home"),
                "PIP_CONFIG_FILE": os.devnull,
                "PIP_DISABLE_PIP_VERSION_CHECK": "1",
                "PIP_NO_CACHE_DIR": "1",
                "PIP_NO_INPUT": "1",
                "PYTHONNOUSERSITE": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
            }
        )
        self.environment = environment

    @property
    def python(self) -> Path:
        return self.venv / "bin/python"

    def run(self, *command: str, timeout: int = 120, **keywords) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            list(command), cwd=keywords.pop("cwd", self.workspace), env=self.environment,
            capture_output=True, text=True, timeout=timeout, **keywords,
        )

    def require(self, result: subprocess.CompletedProcess[str]) -> str:
        self.test_case.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout

    def unavailable(self, message: str) -> None:
        if INSTALL_REQUIRED:
            self.test_case.fail(f"required runner-extra installation prerequisite missing: {message}")
        self.test_case.skipTest(f"runner-extra installation prerequisite unavailable: {message}")


class CandidateArtifactClosureTests(unittest.TestCase):
    def test_manifest_names_exactly_the_candidate_wheel_and_source_archive(self):
        artifacts = _candidate_bytes()
        _verified_manifest(artifacts)
        self.assertEqual(
            {path.name for path in DOWNLOADS.iterdir()}, {WHEEL, SDIST, MANIFEST},
        )

    def test_hashed_closure_embeds_no_artifact_or_manifest_digest(self):
        artifacts = _candidate_bytes()
        manifest = _verified_manifest(artifacts)
        closure_digests = {
            hashlib.sha256(artifacts[name]).hexdigest().encode("ascii")
            for name in (WHEEL, SDIST, MANIFEST)
        }
        for name, payload in _packaged_text(artifacts).items():
            for digest in closure_digests:
                self.assertNotIn(digest, payload, name)
        # The manifest hashes the wheel and sdist; its own digest lives only outside it.
        self.assertNotIn(hashlib.sha256(artifacts[MANIFEST]).hexdigest().encode(), artifacts[MANIFEST])
        self.assertEqual(
            set(DIGEST.findall(artifacts[MANIFEST])),
            {record["sha256"].encode("ascii") for record in manifest["artifacts"]},
        )

    def test_external_installer_rendering_leaves_artifact_bytes_unchanged(self):
        before = _candidate_bytes()
        installer = render_external_installer(before[MANIFEST])
        after = _candidate_bytes()
        self.assertEqual(before, after)
        self.assertIn(hashlib.sha256(before[WHEEL]).hexdigest(), installer)
        self.assertIn(hashlib.sha256(before[MANIFEST]).hexdigest(), installer)
        self.assertIn("candidate; not a published release", installer)
        for payload in _packaged_text(after).values():
            self.assertNotIn(installer.encode("utf-8"), payload)

    def test_wheel_declares_only_the_existing_pinned_runner_extra(self):
        with zipfile.ZipFile(DOWNLOADS / WHEEL) as wheel:
            metadata = wheel.read(f"heel_sim-{VERSION}.dist-info/METADATA").decode("utf-8")
            names = wheel.namelist()
        requirements = [line for line in metadata.splitlines() if line.startswith("Requires-Dist:")]
        self.assertEqual(
            requirements, [f'Requires-Dist: {RUNNER_REQUIREMENT}; extra == "runner"'],
        )
        self.assertIn(f"Version: {VERSION}\n", metadata)
        self.assertIn("Provides-Extra: runner\n", metadata)
        self.assertFalse([name for name in names if name.startswith(("heel/saas/", "tests/", "apps/"))])
        runner_modules = sorted(
            path for path in json.loads(CONTRACT.read_text(encoding="utf-8"))["python_modules"]
            if path.startswith("heel/runner/")
        )
        self.assertTrue(runner_modules)
        self.assertLessEqual(set(runner_modules), set(names))


_DRIVER = r'''
import importlib, importlib.abc, importlib.util, json, sys
from pathlib import Path

venv = Path(sys.argv[1]).resolve()
checkout = Path(sys.argv[2]).resolve()
modules = json.loads(sys.argv[3])
for entry in sys.path:
    if entry and Path(entry).resolve().is_relative_to(checkout):
        raise SystemExit(f"checkout on sys.path: {entry}")
loaded = {name: importlib.import_module(name) for name in modules}
for name, module in loaded.items():
    origin = Path(module.__file__).resolve()
    if not origin.is_relative_to(venv) or origin.is_relative_to(checkout):
        raise SystemExit(f"{name} not imported from the installed wheel: {origin}")
import heel
assert importlib.util.find_spec("heel.saas") is None
from heel.reference_rehearsal import TARGET, run_reference
from heel.scope import create_scope

class Block(importlib.abc.MetaPathFinder):
    def find_spec(self, name, path=None, target=None):
        if name == "cryptography" or name.startswith("cryptography."):
            raise ModuleNotFoundError(f"blocked {name}", name=name)
        return None

scope = create_scope([TARGET], "synthetic packaging driver")
assert not any(name == "cryptography" or name.startswith("cryptography.") for name in sys.modules)
blocker = Block()
sys.meta_path.insert(0, blocker)
try:
    run_reference(scope.scope_id, "hardened", "3" * 32)
except ModuleNotFoundError as error:
    blocked = error.name
else:
    raise SystemExit("reference flow completed without reaching cryptography")
finally:
    sys.meta_path.remove(blocker)
report = run_reference(scope.scope_id, "vulnerable", "4" * 32)
import cryptography
from cryptography.hazmat.primitives.asymmetric import ed25519
crypto_origin = Path(cryptography.__file__).resolve()
print(json.dumps({
    "heel_version": heel.__version__,
    "heel_origin": str(Path(heel.__file__).resolve()),
    "blocked_import": blocked,
    "cryptography_version": cryptography.__version__,
    "cryptography_in_venv": crypto_origin.is_relative_to(venv),
    "ed25519_loaded": "cryptography.hazmat.primitives.asymmetric.ed25519" in sys.modules,
    "imported_modules": sorted(loaded),
    "result": report["result"],
}, sort_keys=True))
'''


class SourceFreeRunnerExtraInstallTests(unittest.TestCase):
    def test_candidate_runner_extra_installs_and_runs_both_synthetic_outcomes(self):
        self.assertGreaterEqual(sys.version_info[:2], (3, 11))
        with tempfile.TemporaryDirectory(prefix="heel-preview-install-") as temporary:
            temporary_path = Path(temporary).resolve()
            self.assertFalse(temporary_path.is_relative_to(ROOT.resolve()))
            env = _SourceFreeEnvironment(self, temporary_path)

            # Acquire by copying only the reviewed candidate bytes, then verify them there.
            for name in (WHEEL, SDIST, MANIFEST):
                shutil.copyfile(DOWNLOADS / name, env.acquisition / name)
            acquired = {name: (env.acquisition / name).read_bytes() for name in (WHEEL, SDIST, MANIFEST)}
            _verified_manifest(acquired)

            env.require(env.run(sys.executable, "-m", "venv", str(env.venv)))
            probe = env.run(
                str(env.python), "-I", "-m", "pip", "--isolated", "download", "--no-deps",
                "--only-binary=:all:", "--dest", str(temporary_path / "probe"), RUNNER_REQUIREMENT,
                timeout=180,
            )
            if probe.returncode != 0:
                env.unavailable("package index unreachable for " + RUNNER_REQUIREMENT)
            env.require(env.run(
                str(env.python), "-I", "-m", "pip", "--isolated", "install",
                f"./{WHEEL}[runner]", cwd=env.acquisition, timeout=600,
            ))
            env.require(env.run(str(env.python), "-I", "-m", "pip", "check"))
            installed = json.loads(env.require(env.run(
                str(env.python), "-I", "-c",
                "import importlib.metadata as m, json;"
                "print(json.dumps({d.metadata['Name'].lower(): d.version for d in m.distributions()}))",
            )))
            self.assertEqual(installed["heel-sim"], VERSION)
            self.assertEqual(installed["cryptography"], RUNNER_REQUIREMENT.split("==")[1])

            # Import every shipped runner module and reach the cryptography-backed signer.
            modules = [
                "heel" if path == "heel/__init__.py"
                else path.removesuffix(".py").removesuffix("/__init__").replace("/", ".")
                for path in json.loads(acquired_contract(acquired))["python_modules"]
                if path == "heel/__init__.py" or path.startswith("heel/runner/")
                or path in ("heel/reference_rehearsal.py", "heel/reference_product.py", "heel/crypto.py")
            ]
            driver = temporary_path / "driver.py"
            driver.write_text(_DRIVER, encoding="utf-8")
            evidence = json.loads(env.require(env.run(
                str(env.python), "-I", str(driver), str(env.venv), str(ROOT), json.dumps(modules),
            )))
            self.assertEqual(evidence["heel_version"], VERSION)
            self.assertTrue(Path(evidence["heel_origin"]).is_relative_to(env.venv.resolve()))
            self.assertEqual(evidence["blocked_import"].split(".")[0], "cryptography")
            self.assertTrue(evidence["cryptography_in_venv"])
            self.assertTrue(evidence["ed25519_loaded"])
            self.assertEqual(evidence["result"], "verified_violation")
            self.assertIn("heel.runner.identity", evidence["imported_modules"])

            # The documented public CLI journey: human scope, then both synthetic outcomes.
            heel = str(env.venv / "bin/heel")
            scope = json.loads(env.require(env.run(
                heel, "scope", "create", "--target", "reference:export",
                "--operator", "synthetic packaging test", "--confirm",
            )))["created_scope"]
            outcomes = {}
            for case, attempt in (("vulnerable", "1" * 32), ("hardened", "2" * 32)):
                outcomes[case] = json.loads(env.require(env.run(
                    heel, "reference", "run", "--scope", scope, "--case", case, "--attempt", attempt,
                )))
            self.assertEqual(outcomes["vulnerable"]["result"], "verified_violation")
            self.assertFalse(outcomes["vulnerable"]["regression_passed"])
            self.assertEqual(outcomes["hardened"]["result"], "invariant_held")
            self.assertTrue(outcomes["hardened"]["regression_passed"])
            for report in outcomes.values():
                self.assertEqual(report["execution_support"], "reference_only")
                self.assertEqual(report["provenance"]["kind"], "reference_product_execution")
                self.assertIs(report["provenance"]["network_calls"], False)
                self.assertIs(report["uploaded"], False)
                rendered = json.dumps(report).lower()
                for claim in UNPROVEN_CLAIMS:
                    self.assertNotIn(claim, rendered)
            if EVIDENCE_DIR:
                summary = {
                    "python": sys.version.split()[0],
                    "installed": installed,
                    "driver": evidence,
                    "cli_results": {case: report["result"] for case, report in outcomes.items()},
                    "acquired_sha256": {
                        name: hashlib.sha256(payload).hexdigest() for name, payload in acquired.items()
                    },
                    "not_proven": "pairing, serving, HTTP, hosted findings, public acquisition",
                }
                Path(EVIDENCE_DIR, "runner-extra-install.json").write_text(
                    json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8",
                )

            # Only the signed scopes and the closed reference store exist: no runner pairing or
            # daemon state was made, so nothing here is evidence of pairing, serving or a
            # control-plane connection.
            self.assertEqual(
                sorted(path.name for path in (temporary_path / "heel-home").iterdir()
                       if path.is_dir()),
                ["reference", "scopes"],
            )
            # Acquired candidate bytes were not modified by installation or execution.
            self.assertEqual(
                {name: (env.acquisition / name).read_bytes() for name in (WHEEL, SDIST, MANIFEST)},
                acquired,
            )


def acquired_contract(artifacts: dict[str, bytes]) -> str:
    """Read the release contract from the acquired source archive, not the checkout."""
    with tempfile.TemporaryDirectory(prefix="heel-preview-contract-") as temporary:
        path = Path(temporary) / SDIST
        path.write_bytes(artifacts[SDIST])
        with tarfile.open(path, "r:gz") as sdist:
            stream = sdist.extractfile(f"heel_sim-{VERSION}/release/open-core-v1.json")
            assert stream is not None
            return stream.read().decode("utf-8")


if __name__ == "__main__":
    unittest.main()
