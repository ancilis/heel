"""H2-2 static oracle (ordinary CI, every platform; DECISION revision 5, section 6.2).

The fixed ``h2-policy-v1`` launcher, its exact staged closure and isolated import smoke, the eight
H0-locked wheels, the six-job ``codeql.yml`` composition as all three pinning oracles see it, the
recorded fixture literals, the evidence rule, and the Linux proof module's own guards under in-memory
mutations. Nothing here runs the privileged proof, creates a namespace or runs nft: a green result is
source/static evidence only, never the runtime proof.
"""
from __future__ import annotations

import hashlib
import importlib.util
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
import xml.etree.ElementTree as ElementTree
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "codeql.yml"
H0_LOCK = ROOT / "deploy" / "host" / "ingress" / "runtime-lock.json"
LINUX_MODULE_FILE = ROOT / "tests" / "linux" / "test_host_h2_policy.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses resolve string annotations through sys.modules
    spec.loader.exec_module(module)
    return module


PROOF = _load("h2_policy_proof_linux_static", LINUX_MODULE_FILE)
LAUNCHER = PROOF.LAUNCHER
LEASE_KEY = _load("h2_policy_proof_lease_key_static", ROOT / "tests" / "linux" / "test_host_lease_key_shape.py")
AUTHORITY_PROOF = _load("h2_policy_proof_authority_static", ROOT / "tests" / "linux" / "test_host_authority_proof.py")
ORACLES = {"h2_policy": PROOF.workflow_violations, "lease_key": LEASE_KEY.workflow_violations,
           "authority": AUTHORITY_PROOF.workflow_violations}

# The design's exact staged list (DECISION 6.2 item H) and the accepted, unchanged inputs at 4bce951.
DESIGN_STAGE_FILES = (
    "deploy/host/authority.py", "deploy/host/profile.py", "deploy/host/h2_policy.py", "tests/linux/__init__.py",
    "tests/linux/test_host_h2_policy.py", "tests/support/edge_tls_harness.py", "scripts/host_h2_policy_proof.py",
    "scripts/host_lease_key_shape.py", "scripts/host_lease_feasibility.py", "scripts/host_ingress_proof.py",
    "deploy/host/ingress/runtime-lock.json", ".github/workflows/codeql.yml", "docs/saas/H2_POLICY_PROOF.md",
    "docs/saas/H2_POLICY_INSTALLATION.md",
)
UNCHANGED_SHA256 = {
    "deploy/host/h2_policy.py": "2511dae4352bbf2006fb638164375da1d80a097a4bb6117dc7ea96328b5b4af6",
    "docs/saas/H2_POLICY_INSTALLATION.md": "5253af83f800485822cd76a383fe99ffea2f53ad44cf215ad013b99396c20646",
    "deploy/host/authority.py": "4c9a1fc6078060c1fcea0a858be601c34a558517a25a7134ec8042134e6967a5",
    "deploy/host/profile.py": "e697da2bf90a5e5e3bdf80aac2c18c9a8ab53f9018a35f977de1c857915dab83",
    "deploy/host/cycle.py": "a991548afa98a3423e360eff634ae7251c2f31b2dffe1778c727616bf6ca0e64",
    # RC4 integration: accepted H2A 1e249fa5 mirrors the Worker disclosure-poll route family (2 KiB cap)
    # in the harness (was b8887b86..., RUNNER-RC3 GAP-4). Test-support bytes only; H2 closure moves; UNRUN.
    "tests/support/edge_tls_harness.py": "846bc9d401ae3b09759704ca9763f03d71ea2c961b18b0ed17bce3536176207d",
    "scripts/host_lease_key_shape.py": "83edee96607a1fad33d5bb7f00a230650dffb5d36f2fe4f13eb34c3ae3e3a61c",
    "scripts/host_authority_proof.py": "af27f68e033cce033a9b48a77dc26a73dc6176829b575476ae904b43b69cb76c",
    "scripts/host_lease_feasibility.py": "62e8bbd346e7b196bdb2946924b93fa59b0b09bfb914997bebd65d76b21eeb51",
    # H2-LINK-DIAGNOSTICS-R1: H0's default-disabled capture observer (was a1b32cc4...). A shared-helper
    # change: H0/H1F regressions and a fresh H0 qualification are required; it is not H2-only.
    "scripts/host_ingress_proof.py": "76958e1896110155aea9802996f00408c097a2a238b8c73ede138eafbccd4aa4",
    # RC5 pin refresh: only app.lockfile_sha256 changes (was e011c0cf..., RC4); the npm root version
    # is now 1.3.0-rc.5, so it names the tracked lockfile d942fca3.... H2 closure moves; UNRUN.
    "deploy/host/ingress/runtime-lock.json": "eb5c9d3ca2462df59dda2951cc600b7287f7aa5b8b6588ebc6faf2d969e9b77e",
}
RECORDED_PICK = {"targets": ("8.8.8.8", "8.8.4.4"), "unapproved_target": "1.1.1.1", "wrong_source": "9.9.9.9",
                 "dual_stack_ipv6": "2001:4860:4860::8888"}


def test_launcher_is_zero_argument_fixed_profile_and_reads_no_input():
    source = (ROOT / "scripts" / "host_h2_policy_proof.py").read_text(encoding="utf-8")
    assert LAUNCHER.main(["--profile", "x"]) == 2 and LAUNCHER.main([""]) == 2
    assert (LAUNCHER.PROFILE, LAUNCHER.REVIEWED_REF) == ("h2-policy-v1", "refs/heads/codex/self-serve-host-h2-policy-proof")
    assert LAUNCHER.TEST_MODULE == "tests/linux/test_host_h2_policy.py" and LAUNCHER.REQUIRED_ENV == "HEEL_REQUIRE_HOST_H2_POLICY_PROOF"
    assert LAUNCHER.ARTIFACT_DIR == ROOT / "host-h2-policy-proof"
    for forbidden in ("argparse", "getopt", "input(", "os.getenv", "shell=True", "urllib", "requests", "http.client"):
        assert forbidden not in source, forbidden
    # The only environment reads: the runner's temp root (location) and the reviewed ref (refusal only).
    assert re.findall(r"environ(?:\.get)?\(\"?([A-Z_]+)", source) == ["GITHUB_REF", "RUNNER_TEMP"]
    # The child is one fixed sudo argv; the suite argv is fixed; no test selector exists.
    assert source.count('subprocess.run(["sudo", "-n", "--", sys.executable, "-I", str(Path(__file__).resolve())]') == 1
    assert '"-k"' not in source and "--deselect" not in source and source.count('"-m", "pytest"') == 1


def test_staged_closure_is_the_design_list_plus_exactly_the_tracked_heel_tree(tmp_path):
    assert LAUNCHER.STAGE_FILES == DESIGN_STAGE_FILES
    tracked = subprocess.run(["git", "ls-files", "-z", "--", "heel"], cwd=ROOT, capture_output=True, check=True).stdout
    assert tuple(name for name in tracked.decode().split("\0") if name) == LAUNCHER.HEEL_TREE_FILES
    assert len(LAUNCHER.HEEL_TREE_FILES) == 113 and LAUNCHER.staged_files() == LAUNCHER.HEEL_TREE_FILES + DESIGN_STAGE_FILES
    # The staged copy is exactly the closure, byte for byte, and its digest moves with any one byte.
    source = LAUNCHER.stage_tree(tmp_path / "src")
    staged = sorted(str(path.relative_to(source)) for path in source.rglob("*") if path.is_file())
    assert staged == sorted(LAUNCHER.staged_files())
    hashes = {name: LAUNCHER._sha256(source / name) for name in LAUNCHER.HEEL_TREE_FILES}
    digest = LAUNCHER.closure_digest(hashes, LAUNCHER.STAGE_FILES, root=source)
    assert digest == LAUNCHER.closure_digest({name: LAUNCHER._sha256(ROOT / name) for name in LAUNCHER.HEEL_TREE_FILES},
                                             LAUNCHER.STAGE_FILES)
    (source / "docs/saas/H2_POLICY_PROOF.md").write_bytes(b"changed\n")
    assert LAUNCHER.closure_digest(hashes, LAUNCHER.STAGE_FILES, root=source) != digest
    assert LAUNCHER.closure_digest({**hashes, "heel/__init__.py": "0" * 64}, LAUNCHER.STAGE_FILES) != digest


PRIVATE_CODEC = "heel/saas/managed_authority_contracts.py"


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", "-c", "user.name=fixture", "-c", "user.email=fixture@invalid", "-c", "commit.gpgsign=false",
                           *args], cwd=cwd, capture_output=True, text=True, check=True).stdout


def test_private_codec_is_one_ordered_member_and_the_launcher_refuses_a_missing_or_extra_member(tmp_path, monkeypatch):
    """C4 P01 moved the commercial codec under heel/saas: the closure is 113 heel + 14 stage files. An
    owned git fixture (an exact staged copy, committed) shows the launcher's own provenance check refuses
    a missing or an unexpected tracked heel member, and that one byte of the new member moves the digest."""
    tree = LAUNCHER.HEEL_TREE_FILES
    assert tree.count(PRIVATE_CODEC) == 1 and "heel/managed_authority_contracts.py" not in tree
    index = tree.index(PRIVATE_CODEC)
    assert tree[index - 1:index + 2] == ("heel/saas/ledger.py", PRIVATE_CODEC, "heel/saas/migrate.py")
    assert len(tree) + len(LAUNCHER.STAGE_FILES) == 127 == len(set(LAUNCHER.staged_files()))
    fixture = LAUNCHER.stage_tree(tmp_path / "fixture")
    _git(fixture, "init", "-q")
    _git(fixture, "add", "--", ".")
    _git(fixture, "commit", "-q", "-m", "exact staged closure")
    monkeypatch.setattr(LAUNCHER, "ROOT", fixture)
    exact = LAUNCHER.candidate_provenance()
    assert exact["heel_tree_file_count"] == 113 and exact["proof_file_count"] == 14
    assert exact["heel_tree_files"][PRIVATE_CODEC] == LAUNCHER._sha256(ROOT / PRIVATE_CODEC)
    assert exact["staged_closure_sha256"] == LAUNCHER.closure_digest(
        {name: LAUNCHER._sha256(ROOT / name) for name in tree}, LAUNCHER.STAGE_FILES)

    # Missing member: the private codec is no longer tracked.
    _git(fixture, "rm", "-q", "--", PRIVATE_CODEC)
    _git(fixture, "commit", "-q", "-m", "missing member")
    with pytest.raises(LAUNCHER.ProofFailure, match="heel_tree_differs"):
        LAUNCHER.candidate_provenance()
    _git(fixture, "revert", "--no-edit", "HEAD")
    assert LAUNCHER.candidate_provenance()["staged_closure_sha256"] == exact["staged_closure_sha256"]

    # Extra member: the old public path (or any unlisted file) tracked again under heel/.
    shutil.copyfile(ROOT / PRIVATE_CODEC, fixture / "heel/managed_authority_contracts.py")
    _git(fixture, "add", "--", "heel/managed_authority_contracts.py")
    _git(fixture, "commit", "-q", "-m", "extra member")
    with pytest.raises(LAUNCHER.ProofFailure, match="heel_tree_differs"):
        LAUNCHER.candidate_provenance()
    _git(fixture, "revert", "--no-edit", "HEAD")

    # Member byte change: provenance still matches the tuple, but the member hash and digest move.
    codec = fixture / PRIVATE_CODEC
    codec.write_bytes(codec.read_bytes() + b"\n")
    _git(fixture, "commit", "-q", "-am", "member byte change")
    changed = LAUNCHER.candidate_provenance()
    assert changed["heel_tree_file_count"] == 113
    assert changed["heel_tree_files"][PRIVATE_CODEC] != exact["heel_tree_files"][PRIVATE_CODEC]
    assert {k: v for k, v in changed["heel_tree_files"].items() if k != PRIVATE_CODEC} == {
        k: v for k, v in exact["heel_tree_files"].items() if k != PRIVATE_CODEC}
    assert changed["staged_closure_sha256"] != exact["staged_closure_sha256"]


def test_wheel_closure_is_the_eight_h0_locked_wheels_and_a_changed_lock_fails():
    lock = json.loads(H0_LOCK.read_text(encoding="utf-8"))
    LAUNCHER.closure_matches_lock(lock)
    assert LAUNCHER.PYTEST_CLOSURE is LAUNCHER.h1f().PYTEST_CLOSURE
    assert [name for name, *_rest in LAUNCHER.PYTEST_CLOSURE] == ["iniconfig", "packaging", "pluggy", "pygments", "pytest"]
    assert [(name, version) for name, version, *_rest in LAUNCHER.CLIENT_CLOSURE] == [
        ("cryptography", "50.0.1"), ("cffi", "2.1.1"), ("pycparser", "3.11")]
    closure = LAUNCHER.wheel_closure(lock)
    by_file = {wheel["file"]: wheel for wheel in lock["python"]["wheels"]}
    assert len(closure) == 8 and all(by_file[file]["url"] == url and by_file[file]["sha256"] == digest
                                     for file, url, digest in closure)
    # No new dependency: cryptography 50.0.1 is the package's one declared runner dependency.
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert "cryptography==50.0.1" in project["optional-dependencies"]["runner"]
    for name, field, value in (("cryptography", "sha256", "0" * 64), ("cffi", "version", "2.1.2"),
                               ("pycparser", "file", "pycparser-3.12-py3-none-any.whl"), ("pytest", "sha256", "1" * 64)):
        changed = json.loads(json.dumps(lock))
        for wheel in changed["python"]["wheels"]:
            if wheel["name"] == name:
                wheel[field] = value
        with pytest.raises(LAUNCHER.ProofFailure):
            LAUNCHER.closure_matches_lock(changed)
    missing = json.loads(json.dumps(lock))
    missing["python"]["wheels"] = [wheel for wheel in missing["python"]["wheels"] if wheel["name"] != "cffi"]
    with pytest.raises(LAUNCHER.ProofFailure):
        LAUNCHER.closure_matches_lock(missing)


def _smoke(root: Path, env: str, version: str = LAUNCHER.CRYPTOGRAPHY_VERSION) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-I", "-c", LAUNCHER.IMPORT_SMOKE, str(root), env, version], cwd="/",
                          capture_output=True, text=True, timeout=300, env={"PATH": LAUNCHER.FIXED_PATH, "LC_ALL": "C"})


def test_isolated_import_smoke_sees_only_the_staged_root_and_rejects_a_missing_file_or_foreign_origin(tmp_path):
    """The same IMPORT_SMOKE the privileged child runs, against an exact staged copy. In ordinary CI the
    third-party wheels come from this test environment (``sys.prefix``); the closed eight-wheel venv
    exists only inside the Linux proof, which runs the smoke again there."""
    import cryptography

    if cryptography.__version__ != LAUNCHER.CRYPTOGRAPHY_VERSION:
        pytest.fail("the test environment must carry the locked cryptography " + LAUNCHER.CRYPTOGRAPHY_VERSION)
    source = LAUNCHER.stage_tree(tmp_path / "src")
    completed = _smoke(source, sys.prefix)
    assert completed.returncode == 0, completed.stdout[-2000:] + completed.stderr[-4000:]
    assert re.fullmatch(r"import_smoke ok root=[1-9][0-9]* env=[1-9][0-9]* stdlib=[1-9][0-9]*\n", completed.stdout)
    # A wrong environment root: cryptography is then from an unexpected origin.
    assert _smoke(source, str(tmp_path / "other-env")).returncode != 0
    assert _smoke(source, sys.prefix, "0.0").returncode != 0
    # A missing staged file: the import fails; there is no checkout fallback (-I, cwd "/").
    (source / "heel" / "runner" / "redaction.py").unlink()
    assert _smoke(source, sys.prefix).returncode != 0
    shutil.rmtree(source / "tests" / "support")
    assert _smoke(source, sys.prefix).returncode != 0
    # No staged heel/ at all: nothing falls back to the checkout or the environment.
    other = LAUNCHER.stage_tree(tmp_path / "src2")
    shutil.rmtree(other / "heel")
    assert _smoke(other, sys.prefix).returncode != 0


def _workflow_mutations(text: str) -> dict[str, str]:
    job = PROOF._job_block(text, "host-h2-policy-proof")
    lease_key = PROOF._job_block(text, "host-lease-key-shape")
    head = text[:PROOF.BASE_WORKFLOW_BYTES]
    assert text == head + "\n" + job

    def swap(old: str, new: str) -> str:  # a mutation inside the appended job only
        assert job.count(old) == 1, old
        return head + "\n" + job.replace(old, new)

    def old(name: str, before: str, after: str) -> str:  # a mutation inside one existing block only
        block = PROOF._job_block(text, name)
        assert block.count(before) == 1 and text.count(block) == 1, (name, before)
        return text.replace(block, block.replace(before, after))

    return {
        "wrong_branch": swap("refs/heads/codex/self-serve-host-h2-policy-proof", "refs/heads/main"),
        "branch_prefix_only": swap("github.ref == 'refs/heads/codex/self-serve-host-h2-policy-proof'",
                                   "startsWith(github.ref, 'refs/heads/codex/')"),
        "gate_without_dispatch": swap("github.event_name == 'workflow_dispatch' && ", ""),
        "gate_or_push": swap("github.event_name == 'workflow_dispatch' &&", "github.event_name == 'push' ||"),
        "push_branch_broadened": text.replace("  push:\n    branches: [main]", "  push:\n    branches: [main, 'codex/**']"),
        "pull_request_target": text.replace("  pull_request:\n", "  pull_request_target:\n"),
        "workflow_call": text.replace("  workflow_dispatch: {}", "  workflow_dispatch: {}\n  workflow_call: {}"),
        "dispatch_inputs": text.replace("workflow_dispatch: {}", "workflow_dispatch:\n    inputs:\n      x: {}"),
        "contents_write": swap("      contents: read\n", "      contents: write\n"),
        "id_token_added": swap("      contents: read\n", "      contents: read\n      id-token: write\n"),
        "actions_read_added": swap("      contents: read\n", "      contents: read\n      actions: read\n"),
        "head_permissions": text.replace("\npermissions: {}\n", "\npermissions: read-all\n"),
        "job_env": swap("    steps:\n", "    env:\n      X: y\n    steps:\n"),
        "step_env": swap("        run: python scripts/host_h2_policy_proof.py\n",
                         "        run: python scripts/host_h2_policy_proof.py\n        env:\n          X: y\n"),
        "secret_used": swap("run: python scripts/host_h2_policy_proof.py", "run: python scripts/host_h2_policy_proof.py "
                            "${{ secrets.TOKEN }}"),
        "service_added": swap("    steps:\n", "    services:\n      db:\n        image: postgres\n    steps:\n"),
        "container_added": swap("    runs-on: ubuntu-24.04\n", "    runs-on: ubuntu-24.04\n    container: ubuntu:24.04\n"),
        "environment_added": swap("    runs-on: ubuntu-24.04\n", "    runs-on: ubuntu-24.04\n    environment: proof\n"),
        "cache_step": swap("      - name: Upload allowlisted safe evidence\n", "      - uses: actions/cache@" + "2" * 40
                           + "\n      - name: Upload allowlisted safe evidence\n"),
        "bare_extra_run": swap("      - name: Upload allowlisted safe evidence", "      - run: echo hi\n"
                               "      - name: Upload allowlisted safe evidence"),
        "continue_on_error": swap("        timeout-minutes: 20\n", "        timeout-minutes: 20\n        continue-on-error: true\n"),
        "extra_artifact": swap("            host-h2-policy-proof/report.txt\n",
                               "            host-h2-policy-proof/report.txt\n            host-h2-policy-proof/raw.txt\n"),
        "artifact_glob": swap("            host-h2-policy-proof/summary.json\n", "            host-h2-policy-proof/*\n"),
        "retention_30": swap("retention-days: 3", "retention-days: 30"),
        "job_timeout_30": swap("timeout-minutes: 25", "timeout-minutes: 30"),
        "step_timeout_21": swap("timeout-minutes: 20", "timeout-minutes: 21"),
        "run_arguments": swap("run: python scripts/host_h2_policy_proof.py", "run: python scripts/host_h2_policy_proof.py -k p0"),
        "run_other_launcher": swap("run: python scripts/host_h2_policy_proof.py", "run: python scripts/host_lease_key_shape.py"),
        "checkout_tag": swap(PROOF.CHECKOUT, "actions/checkout@v4"),
        "checkout_other_sha": swap(PROOF.CHECKOUT, "actions/checkout@" + "1" * 40),
        "python_unpinned": swap('python-version: "3.13.5"', 'python-version: "3.13"'),
        "persist_credentials": swap("persist-credentials: false", "persist-credentials: true"),
        "ref_not_sha": swap("ref: ${{ github.sha }}", "ref: ${{ github.ref }}"),
        "runs_on_latest": swap("runs-on: ubuntu-24.04", "runs-on: ubuntu-latest"),
        "concurrency_removed": swap("    concurrency:\n      group: host-h2-policy-proof\n      cancel-in-progress: false\n", ""),
        "cancel_in_progress": swap("cancel-in-progress: false", "cancel-in-progress: true"),
        "always_removed": swap("        if: always()\n", ""),
        "h2_job_missing": head,
        "duplicate_h2_job": text + "\n" + job,
        "seventh_job": text + "\n  extra-job:\n    runs-on: ubuntu-24.04\n",
        "h2_before_lease_key": text[:text.index("  host-lease-key-shape:\n")] + job + "\n" + lease_key,
        "comment_between": head + "\n# note\n" + job,
        "trailing_bytes": text + "\n",
        "trailing_comment": text + "# trailing\n",
        "analyze_mutated": old("analyze", "queries: security-extended", "queries: security-and-quality"),
        "ingress_mutated": old("host-ingress-proof", "retention-days: 3", "retention-days: 4"),
        "feasibility_mutated": old("host-lease-feasibility", "timeout-minutes: 25", "timeout-minutes: 26"),
        "authority_mutated": old("host-authority-proof", "refs/heads/codex/self-serve-host-authority-proof", "refs/heads/main"),
        "lease_key_mutated": old("host-lease-key-shape", "contents: read", "contents: write"),
        "head_cron_mutated": text.replace("cron: '24 7 * * 1'", "cron: '25 7 * * 1'"),
    }


def test_workflow_is_the_five_recorded_jobs_plus_one_constrained_job_for_all_three_pinning_oracles():
    text = WORKFLOW.read_text(encoding="utf-8")
    base = text[:PROOF.BASE_WORKFLOW_BYTES]
    assert hashlib.sha256(base.encode()).hexdigest() == PROOF.BASE_WORKFLOW_SHA256 == UNCHANGED_SHA256_WORKFLOW_BASE
    for name, oracle in ORACLES.items():
        assert oracle(text) == [], name
    job = PROOF._job_block(text, "host-h2-policy-proof")
    assert job == PROOF.H2_POLICY_JOB and text == base + "\n" + job
    for module in (LEASE_KEY, AUTHORITY_PROOF):
        assert (module.H2_POLICY_JOB_BYTES, module.H2_POLICY_JOB_SHA256) == (
            len(job.encode()), hashlib.sha256(job.encode()).hexdigest())
    mutations = _workflow_mutations(text)
    assert len(mutations) >= 45
    for name, variant in mutations.items():
        assert variant != text, name
        for oracle_name, oracle in ORACLES.items():
            assert oracle(variant) != [], (name, oracle_name)


# Dependency refresh: the recorded prefix includes reviewed Action-pin upgrades;
# hosted-proof job bytes and all mutation checks remain unchanged.
UNCHANGED_SHA256_WORKFLOW_BASE = "191161826253623c1d971b64b26ebbac29e857f2897653e30948af4d8cda44d4"


def test_ordinary_ci_never_runs_the_privileged_proof():
    for path in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        assert LAUNCHER.REQUIRED_ENV not in text, path.name
        if path.name != "codeql.yml":
            assert "host_h2_policy_proof" not in text, path.name
    text = WORKFLOW.read_text(encoding="utf-8")
    assert text.count("python scripts/host_h2_policy_proof.py") == 1
    assert PROOF.H2_POLICY_GATE in PROOF._job_block(text, "host-h2-policy-proof")
    assert os.environ.get(LAUNCHER.REQUIRED_ENV) != "1" and PROOF.REQUIRED is False


def _junit(tmp_path: Path, skipped: tuple[str, ...] = (), extra: tuple[str, ...] = ()) -> Path:
    suite = ElementTree.Element("testsuite")
    for name in (*LAUNCHER.REQUIRED_CASES, *extra):
        case = ElementTree.SubElement(suite, "testcase", name=name)
        if name in skipped:
            ElementTree.SubElement(case, "skipped", message="skipped").text = (
                f"{LAUNCHER.TEST_MODULE}:801: requires the fixed h2-policy launcher on Linux")
    path = tmp_path / f"junit-{len(skipped)}-{len(extra)}.xml"
    ElementTree.ElementTree(suite).write(path)
    return path


def test_acceptance_rule_rejects_a_skipped_or_missing_case_an_unknown_case_and_a_leak(tmp_path):
    records = [{"case": case, "verdict": "pass", "control": item[1], "ints": {}, "tokens": {}}
               for case, item in LAUNCHER.RECORD_CASES.items()]
    profile = LAUNCHER.profile()
    major_minor = sorted(profile.SUPPORTED_KERNELS)[0]
    records[0]["tokens"] = {"kernel_major_minor": major_minor, "nft_version": profile.SUPPORTED_NFT[0], "selftest": "pass",
                            "readd_observation": profile.READD_EXPECTED[major_minor]}
    records[0]["ints"] = {"config_hz": profile.SUPPORTED_HZ[0]}
    cleanup, inner = {"host_fingerprints_unchanged": True}, {"pytest_exit": 0, "leftover_processes": 0, "import_smoke": "ok"}
    good = LAUNCHER.summarize_junit(_junit(tmp_path))
    assert good["collected"] == good["passed"] == len(LAUNCHER.REQUIRED_CASES) == 18
    assert LAUNCHER.evaluate(good, records, 0, cleanup, inner, 0)["result"] == "PASS"
    p4 = LAUNCHER.RECORD_CASES["p4"][0]
    skipped = LAUNCHER.summarize_junit(_junit(tmp_path, skipped=(p4,)))
    assert skipped["skipped"] == 1 and skipped["failing"] == [p4] and skipped["failure_locators"][0]["reason"] == "skipped"
    assert LAUNCHER.evaluate(skipped, records, 0, cleanup, inner, 0)["result"] == "FAIL"
    unknown = LAUNCHER.summarize_junit(_junit(tmp_path, extra=("test_p8_unreviewed_case",)))
    verdict = LAUNCHER.evaluate(unknown, records, 0, cleanup, inner, 0)
    assert verdict["result"] == "FAIL" and verdict["unexpected_cases"] == ["test_p8_unreviewed_case"]
    without_p4 = [record for record in records if record["case"] != "p4"]
    assert LAUNCHER.evaluate(good, without_p4, 0, cleanup, inner, 0)["missing_records"] == ["p4"]
    assert LAUNCHER.evaluate(good, records, 0, cleanup, {**inner, "import_smoke": "failed"}, 0)["result"] == "FAIL"
    assert LAUNCHER.evaluate(good, records, 0, cleanup, inner, 1)["result"] == "FAIL"
    # Artifact leak scan: the run token, a path, a traceback or raw nft error text suppresses the file.
    token = "0123456789abcdef0123456789abcdef"
    directory = tmp_path / "artifacts"
    directory.mkdir()
    (directory / "summary.json").write_text('{"result": "PASS"}\n')
    (directory / "cases.jsonl").write_text(f'{{"tokens": {{"x": "{token}"}}}}\n')
    (directory / "report.txt").write_text("failure /tmp/heel-h2-policy/src\n")
    (directory / "versions.txt").write_text("Error: Could not process rule\n")
    (directory / "cleanup.json").write_text("Traceback (most recent call last)\n")
    assert LAUNCHER.artifact_scan(directory, token) == ["cases.jsonl", "cleanup.json", "report.txt", "versions.txt"]
    for entry in ({"case": "p4", "verdict": "pass", "control": "client", "ints": {}, "tokens": {"peer": "8.8.4.4/32"}},
                  {"case": "p4", "verdict": "pass", "control": "client", "ints": {}, "tokens": {"raw": "Error: x"}},
                  {"case": "p4", "verdict": "skipped", "control": "client", "ints": {}, "tokens": {}}):
        assert LAUNCHER.sanitize_record(entry) is None, entry


def test_fixture_literals_are_the_recorded_pick_global_and_outside_the_deny_corpus():
    from heel.runner import http_transport as transport  # test-only: the unchanged validator

    assert set(PROOF.TARGETS) == set(RECORDED_PICK["targets"]) and PROOF.UNAPPROVED == RECORDED_PICK["unapproved_target"]
    assert PROOF.WRONG_SOURCE == RECORDED_PICK["wrong_source"] and PROOF.TARGET6 == RECORDED_PICK["dual_stack_ipv6"]
    literals = (*RECORDED_PICK["targets"], RECORDED_PICK["unapproved_target"], RECORDED_PICK["wrong_source"],
                RECORDED_PICK["dual_stack_ipv6"])
    for literal in literals:
        address = ipaddress.ip_address(literal)
        assert address.is_global and not [network for network in transport._DENY_CORPUS if address in network], literal
    assert tuple(map(str, transport.select_public_addresses(list(literals)))) == PROOF.RECORDED_TUPLE
    # The fixture-local addresses are never public targets.
    for local in (PROOF.SLOT_SRC, PROOF.SLOT_DST, PROOF.PEER6):
        assert not ipaddress.ip_address(local).is_global


def test_accepted_h2_1_inputs_and_refreshed_dependency_lock_match_recorded_hashes(tmp_path, monkeypatch):
    for name, digest in UNCHANGED_SHA256.items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest, name
    assert PROOF.H2_SOURCE_SHA256 == UNCHANGED_SHA256["deploy/host/h2_policy.py"]
    assert PROOF.HARNESS_SHA256 == UNCHANGED_SHA256["tests/support/edge_tls_harness.py"]

    # H0-APP-LOCK: the shared lock's app pin must equal the tracked lockfile it names, read through the
    # lock's own declared path. Missing data (key or file) is a failure, never a skip. This guard lives in
    # ordinary CI from a full checkout, never inside a staged capsule, so H0's STAGE_PATHS stay unchanged.
    spec = importlib.util.spec_from_file_location("h2_policy_proof_h0_app_lock_static", ROOT / "scripts" / "host_ingress_proof.py")
    h0 = importlib.util.module_from_spec(spec)  # a fresh copy of the real H0 launcher, never a shared module object
    spec.loader.exec_module(h0)
    lock = h0.load_lock(H0_LOCK)
    app = lock["app"]
    assert app["lockfile"] == "apps/heel-cloud/package-lock.json" and app["directory"] == "apps/heel-cloud"
    lockfile_bytes = (ROOT / app["lockfile"]).read_bytes()
    assert hashlib.sha256(lockfile_bytes).hexdigest() == app["lockfile_sha256"], "runtime-lock app.lockfile_sha256 is stale"

    # The real consumer (H0 stage_app) refuses a stale input before any subprocess: (a) the tracked lockfile
    # with the stale pin H0 run 42528823162 failed on, (b) the current pin with a one-byte-changed lockfile.
    # A matched copy is the control: the same call proceeds past the check to its first subprocess.
    calls = []

    class _Stop(Exception):
        pass

    def _record(*args, **kwargs):
        calls.append((args, kwargs))
        raise _Stop()

    stale_pin = "f1c1484a4287156e75b9d057ffc19b457ebae22379430399c69a8a0442e203fc"
    changed = bytearray(lockfile_bytes)
    changed[-1] ^= 0x01
    for label, pin, content in (("stale_pin", stale_pin, lockfile_bytes), ("changed_lockfile", app["lockfile_sha256"], bytes(changed)),
                                ("matched_control", app["lockfile_sha256"], lockfile_bytes)):
        fake_root = tmp_path / label / "root"
        (fake_root / app["lockfile"]).parent.mkdir(parents=True)
        (fake_root / app["lockfile"]).write_bytes(content)
        scratch = tmp_path / label / "scratch"
        calls.clear()
        with monkeypatch.context() as patch:
            patch.setattr(h0, "ROOT", fake_root)
            patch.setattr(h0.subprocess, "run", _record)
            patch.setattr(h0.subprocess, "Popen", _record)
            if label == "matched_control":
                with pytest.raises(_Stop):
                    h0.stage_app(dict(lock, app=dict(app, lockfile_sha256=pin)), scratch, "/nonexistent-node", 1e18, {})
                assert len(calls) == 1 and calls[0][0][0] == ["git", "ls-files", "-z", "apps/heel-cloud"], label
                assert calls[0][1]["cwd"] == fake_root, label
            else:
                with pytest.raises(h0.ProofFailure) as failure:
                    h0.stage_app(dict(lock, app=dict(app, lockfile_sha256=pin)), scratch, "/nonexistent-node", 1e18, {})
                assert failure.value.code == "app_lockfile_mismatch" and str(failure.value) == "app_lockfile_mismatch", label
                assert calls == [], label
        assert not scratch.exists(), label
    assert stale_pin != app["lockfile_sha256"]


def _replace(source: str, old: str, new: str) -> str:
    assert source.count(old) == 1, old
    return source.replace(old, new)


def test_linux_module_guards_reject_seam_assignment_fakes_skips_and_missing_cases():
    source = LINUX_MODULE_FILE.read_text(encoding="utf-8")
    assert PROOF.fixture_violations(source) == [] and PROOF.skip_violations(source) == [] and PROOF.case_violations(source) == []
    p1_install = ("        fx.install()\n        ready = fx.gate_ready()\n        ints.update(fx.facts_ints())\n"
                  "        tokens.update(fx.facts_tokens())\n        ints[\"ipv4")
    p0_guard = '''def test_p0_profile_is_captured_fresh_namespace_ruleset_is_empty_and_the_real_h1_self_test_passes():
    _require_runtime()
'''
    fixture = {
        # Any assignment or deletion of an H2 name is refused, private or public (H2-1's own guard keeps
        # its two private seam names out of every other tracked module, so they are not spelled here).
        "private_assigned": source + "\nH2._LOCK = None\n",
        "nft_redirected": source + "\nH2.NFT_PATH = '/bin/true'\n",
        "installer_replaced": source + "\nH2.install = lambda *arguments, **keywords: None\n",
        "public_deleted": source + "\ndel H2.render_table\n",
        "augmented": source + "\nH2.STATES += ('forged',)\n",
        "private_read": source + "\ndef _x():\n    return H2._INPUTS\n",
        "delattr_used": source + "\ndelattr(H2, 'NFT_PATH')\n",
        "authority_patched": source + "\nAUTHORITY.NFT_PATH = None\n",
        "setattr_used": source + "\nsetattr(H2, 'NFT_PATH', '/bin/true')\n",
        "monkeypatch_used": source + "\ndef _x(monkeypatch):\n    monkeypatch.undo()\n",
        "fake_nft": source + "\ndef fake_nft_script():\n    return None\n",
        "private_render": source + "\ndef _x():\n    return H2._receipt_document(None)\n",
        "client_socket_seam": _replace(source, "resolver=resolver,\n", "resolver=resolver, sockets=None,\n"),
        "client_clock_seam": _replace(source, "timeout_seconds=CLIENT_TIMEOUT_S)",
                                      "timeout_seconds=CLIENT_TIMEOUT_S, clock=time.monotonic)"),
        "netns_path": source + '\nNS = "/run/' + 'netns/x"\n',
        "other_key": _replace(source, "late = fx.domain.prepare(SLOT_SRC, SLOT_DST, LATE_MS)",
                              "late = fx.domain.prepare(SLOT_SRC, TARGETS[0], LATE_MS)"),
        "second_installer_entry": source + "\ndef _x(fd, policy):\n    return H2.install(fd, policy)\n",
        "fault_clock_elsewhere": _replace(source, p1_install, p1_install.replace("fx.install()", "fx.install(fault=('_install', 1, 1))")),
        "fixture_writes_table": source + '\ndef _x(fd):\n    return _run_in(fd, ["nft", "-f", "-"], "table inet heel_lease {}")\n',
    }
    for name, variant in fixture.items():
        assert variant != source and PROOF.fixture_violations(variant) != [], name
    skips = {
        "second_skip": source + "\ndef _x():\n    pytest.skip('x')\n",
        "skipif_marker": _replace(source, p0_guard, "@pytest.mark.skipif(True, reason='x')\n" + p0_guard),
        "xfail_marker": _replace(source, p0_guard, "@pytest.mark.xfail\n" + p0_guard),
        "unguarded_case": _replace(source, p0_guard, p0_guard.replace("    _require_runtime()\n", "    pass\n")),
        "required_ignored": _replace(source, "        if REQUIRED:\n            pytest.fail(reason)\n", ""),
    }
    for name, variant in skips.items():
        assert variant != source and PROOF.skip_violations(variant) != [], name
    p4 = LAUNCHER.RECORD_CASES["p4"][0]
    start = source.index(f"def {p4}():")
    end = source.index("\n\n\ndef _p5(", start)
    cases = {
        "p4_removed": source[:start] + source[end + 3:],
        "p4_record_missing": _replace(source, '    record("p4", ok, ints, tokens)\n', ""),
        "extra_case": source + "\ndef test_p8_extra():\n    _require_runtime()\n",
        "static_records": source + '\ndef test_static_extra():\n    record("p0", True, {}, {})\n',
    }
    for name, variant in cases.items():
        assert variant != source and PROOF.case_violations(variant) != [], name


# ---------------------------------------------------------------------------------------------
# H2-LINK-DIAGNOSTICS-R1: supplementary host-link diagnostics. Every case below is synthetic (a
# modeled host behind H0's real ``host_fingerprints``/``stable_fingerprints``, a modeled sysfs tree
# in tmp_path, or fixed bytes); none reproduces or explains the real run 41621515465 host delta.

import ast
import functools
import time
import tracemalloc
import types

H0 = LAUNCHER.h0()
_PARSE = LAUNCHER.parse_link_line  # unpatched, for the modeled host only
DIAG_KEY = bytes(range(32))
HOST_NS = (7, 4026531840)
GATE_SOURCE_SHA256 = {  # function source at the pinned base 945537376436 (the gate is not edited)
    ("scripts/host_h2_policy_proof.py", "evaluate"): "908c50b84b5bb7b33480946c3a033f1891557cd1946320caf10c9405ab2c0de8",
    ("scripts/host_h2_policy_proof.py", "sanitize_record"): "47f3755d4869a2bd8fc1c0bdacaec013e652b2543d1ac5982a627e705c119ba7",
    ("scripts/host_h2_policy_proof.py", "sanitize_records"): "735c1b174c373851fe8530585772d613716ee31317a305ddc92c47b594890a37",
    ("scripts/host_h2_policy_proof.py", "summarize_junit"): "53a0bf28437a078395c7fbbe445f3fa2f8c3e937465fcaf9cf0b4380d3dcb58c",
    ("scripts/host_h2_policy_proof.py", "index_records"): "a878323cb93535399f8ef39aaf47332992ba23eb15b2a851a8a31011cf601b27",
    ("scripts/host_h2_policy_proof.py", "closure_digest"): "2d57b062b0b9b677506ad7ee95a7e0e1adb911f8ad8974938920c82fcb045752",
    ("scripts/host_ingress_proof.py", "normalize_fingerprint_output"): "516baee8cc852eed0d0adc93aea1b02ec87ba9919f16c872387e583165306f1f",
    ("scripts/host_ingress_proof.py", "stable_fingerprints"): "dfa3f7bc885d43d025b9dd5383ea17ce5120e1eafecb29e587229019ff43ad6f",
}
LO = ("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000\\"
      "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00")
ETH0 = ("2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP mode DEFAULT group default qlen 1000\\"
        "    link/ether 7c:1e:52:10:20:30 brd ff:ff:ff:ff:ff:ff")
VF = ("3: enP7s1: <BROADCAST,MULTICAST,SLAVE,UP,LOWER_UP> mtu 1500 qdisc mq master eth0 state UP mode DEFAULT group default "
      "qlen 1000\\    link/ether 7c:1e:52:10:20:30 brd ff:ff:ff:ff:ff:ff\\    altname enP7p0s2")


def _endpoint(index: int, name: str, mac: str, peer: int) -> str:
    return (f"{index}: {name}@if{peer}: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT "
            f"group default qlen 1000\\    link/ether {mac} brd ff:ff:ff:ff:ff:ff link-netnsid 0")


def _text(*lines: str) -> str:
    return "".join(line + "\n" for line in lines)


BASE = _text(LO, ETH0)
DEVICES = {"lo": ("no", "none", "none"), "eth0": ("yes", "vmbus", "hv_netvsc"), "enP7s1": ("yes", "pci", "mlx5_core")}


class _ModelPath(type(Path())):
    def read_bytes(self):
        return b"modeled mountinfo\n" if str(self) == "/proc/self/mountinfo" else super().read_bytes()


class _Clock:
    def __init__(self):
        self.t0 = self.now = 5 * 10 ** 12
        self.sleeps: list[float] = []

    def __call__(self) -> int:
        self.now += 1_000_000
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += int(seconds * 1e9)


class _Host:
    """H0's fixed commands on a modeled host: per snapshot one links result ((returncode, stdout) or an
    exception); every other command answers one fixed text. Records each links completion object."""

    def __init__(self, monkeypatch, links, devices=None, kinds=None):
        self.links, self.completed, self.devices = list(links), [], dict(DEVICES, **(devices or {}))
        self.kind_names = kinds or {}
        self.current = ""
        monkeypatch.setattr(H0.subprocess, "run", self.run)
        monkeypatch.setattr(H0, "Path", _ModelPath)

    def run(self, argv, **_keywords):
        if tuple(argv) == H0.FINGERPRINT_COMMANDS["links"]:
            item = self.links.pop(0)
            if isinstance(item, BaseException):
                raise item
            completed = subprocess.CompletedProcess(argv, item[0], item[1], "")
            self.completed.append(completed)
            self.current = item[1]
            return completed
        return subprocess.CompletedProcess(argv, 0, "fixed " + " ".join(argv) + "\n", "")

    def kinds(self, deadline_ns, *, clock):
        entries = [_PARSE(line) for line in self.current.splitlines()]  # the modeled listing, not collector work
        return "ok", {f["ifindex"]: (f["name"], self.kind_names.get(f["name"], "veth" if "@" in f["line"] else "none"))
                      for f in entries if f}

    def metadata(self, name, ifindex, deadline_ns, *, clock):
        backed, bus, driver = self.devices.get(name, ("no", "none", "none"))
        return {"device_backed": backed, "bus": bus, "driver": driver, "status": "ok"}


def _registry(*endpoints, key=DIAG_KEY) -> bytes:
    """Fixture ownership lines: (fixture, side, namespace (dev, ino), name, mac, observed listing or None)."""
    lines = [LAUNCHER.ownership_record(key, n, side, ns, (7, 4026532000), name, mac, listing)
             for n, side, ns, name, mac, listing in endpoints]
    return "".join(json.dumps(line, sort_keys=True) + "\n" for line in lines).encode()


@functools.cache
def fixture_registry() -> bytes:
    return _registry(
        (1, "l", (7, 4026532101), "hp1l", "02:48:32:00:01:0a", _endpoint(2, "hp1l", "02:48:32:00:01:0a", 2)),
        (1, "r", (7, 4026532102), "hp1r", "02:48:32:00:01:0b", _endpoint(2, "hp1r", "02:48:32:00:01:0b", 2)),
        (3, "l", (7, 4026532301), "hp3l", "02:48:32:00:03:0a", _endpoint(2, "hp3l", "02:48:32:00:03:0a", 2)),
        (3, "r", (7, 4026532302), "hp3r", "02:48:32:00:03:0b", _endpoint(2, "hp3r", "02:48:32:00:03:0b", 2)))


_DEFAULT = object()


def _audit(monkeypatch, links, *, registry=_DEFAULT, namespace=None, devices=None, kinds=None, metadata=None,
           collector_hook=None):
    """The privileged child's host audit window, modeled: the stable baseline through H0 with the
    collector, then one final snapshot; the same ``differing`` rule and the parent's sanitizer."""
    registry = fixture_registry() if registry is _DEFAULT else registry
    host = _Host(monkeypatch, links, devices, kinds)
    clock = _Clock()
    monkeypatch.setattr(H0, "time", types.SimpleNamespace(monotonic_ns=clock))  # H0's capture bounds on the same clock
    collector = LAUNCHER.LinkCollector(DIAG_KEY, clock.t0, clock=clock, sleep=clock.sleep,
                                       namespace=namespace or (lambda: HOST_NS), kinds=host.kinds,
                                       metadata=metadata or host.metadata)
    if collector_hook:
        collector_hook(collector)
    before, unstable = H0.stable_fingerprints(snapshot=collector.snapshot(H0), pause=collector.pause)
    collector.enrich()
    after = differing = None
    if not unstable:
        after = collector.snapshot(H0)()
        differing = sorted(key for key in before if before[key] != after[key])
        collector.enrich()
    raw = collector.result(registry)
    return {"host": host, "clock": clock, "before": before, "after": after, "unstable": unstable, "differing": differing,
            "raw": raw, "clean": LAUNCHER.sanitize_link_diagnostics(json.loads(json.dumps(raw)))}


def _pair(result: dict, name: str = "audit") -> dict:
    return next(pair for pair in result["clean"]["pairs"] if pair["name"] == name)


def _gate(tmp_path: Path, unchanged: bool) -> str:
    """The unchanged acceptance rule on an otherwise passing run (pinned profile, 18 cases, 8 records)."""
    records = [{"case": case, "verdict": "pass", "control": item[1], "ints": {}, "tokens": {}}
               for case, item in LAUNCHER.RECORD_CASES.items()]
    profile = LAUNCHER.profile()
    major_minor = sorted(profile.SUPPORTED_KERNELS)[0]
    records[0]["tokens"] = {"kernel_major_minor": major_minor, "nft_version": profile.SUPPORTED_NFT[0], "selftest": "pass",
                            "readd_observation": profile.READD_EXPECTED[major_minor]}
    records[0]["ints"] = {"config_hz": profile.SUPPORTED_HZ[0]}
    junit = LAUNCHER.summarize_junit(_junit(tmp_path))
    inner = {"pytest_exit": 0, "leftover_processes": 0, "import_smoke": "ok"}
    return LAUNCHER.evaluate(junit, records, 0, {"host_fingerprints_unchanged": unchanged}, inner, 0)["result"]


def test_diag_gate_functions_are_byte_identical_to_the_pinned_base_and_h0_default_callers_pass_no_observer():
    for (path, name), digest in GATE_SOURCE_SHA256.items():
        source = (ROOT / path).read_text(encoding="utf-8")
        node = next(node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef) and node.name == name)
        assert hashlib.sha256(ast.get_source_segment(source, node).encode()).hexdigest() == digest, (path, name)
    assert LAUNCHER.ARTIFACT_FILES == ("summary.json", "cases.jsonl", "versions.txt", "cleanup.json", "report.txt")
    assert len(LAUNCHER.REQUIRED_CASES) == 18 and len(LAUNCHER.RECORD_CASES) == 8
    # H0's own child and the other launchers still call H0 with no observer (default-disabled).
    for path in ("scripts/host_ingress_proof.py", "scripts/host_lease_feasibility.py", "scripts/host_lease_key_shape.py",
                 "scripts/host_authority_proof.py"):
        source = (ROOT / path).read_text(encoding="utf-8")
        assert "observer=" not in source.replace("def host_fingerprints(observer=None)", "").replace(
            "_notify(observer,", "").replace("observer(name=name", ""), path
    assert re.findall(r"host_fingerprints\(([^)]*)\)", (ROOT / "scripts/host_h2_policy_proof.py").read_text()) == [
        "observer=self.observe"]
    # In H0 the observer is reached only through _notify, outside the capture's try (it cannot reach
    # the ``except (OSError, TimeoutExpired)`` that yields "unavailable").
    source = (ROOT / "scripts/host_ingress_proof.py").read_text(encoding="utf-8")
    function = next(node for node in ast.walk(ast.parse(source)) if isinstance(node, ast.FunctionDef) and node.name == "command")
    capture = next(node for node in function.body if isinstance(node, ast.Try))
    assert not [call for call in ast.walk(ast.Module(body=capture.body, type_ignores=[])) if isinstance(call, ast.Call)
                and getattr(call.func, "id", None) == "_notify"]
    assert [ast.unparse(node) for node in capture.body][-1].startswith("digest = hashlib.sha256((str(completed.returncode) + output)")


def test_diag_observer_on_or_off_or_failing_leaves_every_digest_identical_and_sees_the_exact_completion(monkeypatch):
    outputs = [(0, BASE), (1, ""), (0, ""), subprocess.TimeoutExpired(["ip"], 20), OSError("no ip")]
    seen = []

    def observer(**event):
        seen.append(event)

    def broken(**_event):
        raise OSError("observer failure must not become unavailable")

    for item in outputs:
        digests = []
        for hook in (None, observer, broken, lambda **_e: (_ for _ in ()).throw(ValueError("x"))):
            _Host(monkeypatch, [item])
            digests.append(H0.host_fingerprints() if hook is None else H0.host_fingerprints(observer=hook))
        assert digests[0] == digests[1] == digests[2] == digests[3], item
    links = [event for event in seen if event["name"] == "links"]
    assert [event["status"] for event in links] == ["ok", "nonzero", "ok", "timeout", "oserror"]
    assert [event["returncode"] for event in links] == [0, 1, 0, None, None]
    assert links[0]["digest"] == hashlib.sha256(("0" + BASE).encode()).hexdigest()
    # Successful empty, failing empty and timeout stay three distinct statuses and gate values.
    assert links[1]["digest"] == hashlib.sha256(b"1").hexdigest() != links[2]["digest"] == hashlib.sha256(b"0").hexdigest()
    assert links[3]["digest"] == links[4]["digest"] == "unavailable"
    # Provenance: the observer receives the very stdout object H0 hashed, not a second listing.
    host = _Host(monkeypatch, [(0, BASE)])
    received = []
    H0.host_fingerprints(observer=lambda **event: received.append(event) if event["name"] == "links" else None)
    assert received[0]["stdout"] is host.completed[0].stdout and len(host.completed) == 1
    assert received[0]["started_ns"] <= received[0]["ended_ns"]


def test_diag_invalid_utf8_still_aborts_the_capture_exactly_as_the_gate_does(monkeypatch):
    error = UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")
    for hook in (None, lambda **_event: None):
        _Host(monkeypatch, [error])
        with pytest.raises(UnicodeDecodeError):
            H0.host_fingerprints() if hook is None else H0.host_fingerprints(observer=hook)
    # The child would stop before writing cleanup.raw.json; the parent then records missing diagnostics.
    assert LAUNCHER.sanitize_link_diagnostics(None)["incomplete_reasons"] == ["diagnostics_missing"]
    result = _audit(monkeypatch, [(0, BASE), (0, BASE), (0, BASE)], collector_hook=None)
    assert result["clean"]["complete"] is True


def test_diag_identical_snapshots_keep_pass_and_the_baseline_order_and_two_second_pause(monkeypatch, tmp_path):
    result = _audit(monkeypatch, [(0, BASE), (0, BASE), (0, BASE)])
    clean = result["clean"]
    assert result["unstable"] == [] and result["differing"] == [] and clean["complete"] is True, clean["incomplete_reasons"]
    assert [capture["phase"] for capture in clean["captures"]] == list(LAUNCHER.DIAG_PHASES)
    assert {pair["name"]: pair["classes"] for pair in clean["pairs"]} == {"baseline": ["none"], "audit": ["none"]}
    assert _gate(tmp_path, True) == "PASS" and LAUNCHER.diagnostic_result("PASS", clean) == ("PASS", None)
    # The pause still totals two seconds: metadata for the first snapshot inside it, the remainder slept,
    # and the second snapshot starts after the pause.
    first, second = clean["captures"][0], clean["captures"][1]
    assert len(result["clock"].sleeps) == 1 and 1.9 < result["clock"].sleeps[0] <= 2.0
    assert second["start_ms"] - first["end_ms"] >= 2000 and clean["baseline_pause_ms"] >= 2000
    assert first["end_ms"] <= first["enrichment"]["start_ms"] <= first["enrichment"]["end_ms"] <= second["start_ms"]
    # The privileged child: both baseline snapshots before fork/unshare; the final one after the wait.
    source = (ROOT / "scripts/host_h2_policy_proof.py").read_text(encoding="utf-8")
    child = source[source.index("def privileged_child("):source.index("def main(")]
    order = [child.index(text) for text in ("helper.stable_fingerprints(snapshot=collector.snapshot(helper), "
                                            "pause=collector.pause)", "os.fork()", "os.unshare(", "os.waitpid(child, 0)",
                                            "after = collector.snapshot(helper)()",
                                            "differing = sorted(key for key in before if before[key] != after[key])")]
    assert order == sorted(order)


def test_diag_order_only_flag_mtu_and_hardware_addition_all_retain_fail(monkeypatch, tmp_path):
    reordered = _audit(monkeypatch, [(0, BASE), (0, BASE), (0, _text(ETH0, LO))])
    assert reordered["differing"] == ["links"] and _gate(tmp_path, False) == "FAIL"
    pair = _pair(reordered)
    assert pair["order_only"] is True and pair["classes"] == ["order_only_text_change"] and pair["changes"] == []
    assert reordered["clean"]["captures"][1]["multiset"] == reordered["clean"]["captures"][2]["multiset"]
    assert reordered["clean"]["captures"][1]["lines"] != reordered["clean"]["captures"][2]["lines"]

    down = ETH0.replace("<BROADCAST,MULTICAST,UP,LOWER_UP>", "<BROADCAST,MULTICAST>").replace("state UP", "state DOWN")
    flags = _audit(monkeypatch, [(0, BASE), (0, BASE), (0, _text(LO, down.replace("mtu 1500", "mtu 9000")))])
    change = _pair(flags)["changes"]
    assert flags["differing"] == ["links"] and [c["change"] for c in change] == ["changed"]
    assert change[0]["fields"] == ["flags", "mtu", "operstate"] and change[0]["hardware"] == "device_backed"
    assert _pair(flags)["classes"] == ["hardware_backed_change"] and change[0]["proof_identity"] == "unknown"

    added = _audit(monkeypatch, [(0, BASE), (0, BASE), (0, _text(LO, ETH0, VF))])
    entry = _pair(added)["changes"][0]
    assert added["differing"] == ["links"] and entry["change"] == "added" and entry["hardware"] == "device_backed"
    assert entry["proof_identity"] == "unknown" and _pair(added)["classes"] == ["hardware_backed_change"]
    link = added["clean"]["captures"][2]["links"][2]
    assert link["provenance"] == {"device_backed": "yes", "bus": "pci", "kind": "none", "driver": "mlx5_core",
                                  "scope": "host_verified"}
    assert link["master"] == added["clean"]["captures"][2]["links"][1]["id"]  # master is the keyed eth0 identity
    for result in (reordered, flags, added):  # the diagnostics never turn the gate's FAIL into anything else
        assert LAUNCHER.diagnostic_result("FAIL", result["clean"]) == ("FAIL", None)


def test_diag_proof_endpoint_leak_is_correlated_only_with_corroborated_ownership(monkeypatch, tmp_path):
    # R2: a corroborated name+MAC registry match is labelled as a correlation only; proof identity
    # stays unknown (no lifecycle witness), and hardware metadata is reported beside it, not hidden.
    leak = _endpoint(9, "hp3l", "02:48:32:00:03:0a", 10)
    matched = _audit(monkeypatch, [(0, BASE), (0, BASE), (0, _text(LO, ETH0, leak))],
                     devices={"hp3l": ("yes", "pci", "mlx5_core")})
    pair = _pair(matched)
    assert matched["differing"] == ["links"] and _gate(tmp_path, False) == "FAIL"
    assert (pair["changes"][0]["proof_identity"], pair["changes"][0]["correlation"]) == ("unknown", "fixture_name_mac")
    assert pair["classes"] == ["fixture_name_mac_correlation", "hardware_backed_change"]
    assert matched["clean"]["ownership"] == {"status": "valid", "endpoints": 4, "correlated": 1, "ambiguous": 0,
                                             "namespace_conflicts": 0}
    cases = {
        # A real-looking hp... name with no registry at all.
        "no_registry": dict(registry=None),
        # The name matches but the MAC does not.
        "mac_differs": dict(links=_text(LO, ETH0, _endpoint(9, "hp3l", "02:48:32:00:03:ff", 10))),
        # Index reuse: the leaked link carries a registered ifindex but another name and MAC.
        "index_reuse": dict(links=_text(LO, ETH0, _endpoint(2, "hp9x", "02:48:32:00:09:0a", 2))),
        # Two registry entries claim the same name and MAC.
        "ambiguous": dict(registry=fixture_registry() + _registry(
            (5, "l", (7, 4026532501), "hp3l", "02:48:32:00:03:0a", _endpoint(2, "hp3l", "02:48:32:00:03:0a", 2)))),
        # The registry claims the host namespace for an endpoint: never merged.
        "namespace_conflict": dict(registry=_registry(
            (3, "l", HOST_NS, "hp3l", "02:48:32:00:03:0a", _endpoint(2, "hp3l", "02:48:32:00:03:0a", 2)))),
        # The endpoint was never observed after creation (no corroborating listing).
        "unobserved": dict(registry=_registry((3, "l", (7, 4026532301), "hp3l", "02:48:32:00:03:0a", None))),
        # Not JSON / not closed: the whole registry is refused.
        "invalid": dict(registry=fixture_registry() + b"not json\n"),
    }
    for name, case in cases.items():
        result = _audit(monkeypatch, [(0, BASE), (0, BASE), (0, case.get("links", _text(LO, ETH0, leak)))],
                        registry=case.get("registry", fixture_registry()))
        pair = _pair(result)
        assert result["differing"] == ["links"], name
        assert [c["proof_identity"] for c in pair["changes"]] == ["unknown"] and pair["classes"] == ["unknown"], name
        assert [c["correlation"] for c in pair["changes"]] == ["ambiguous" if name == "ambiguous" else "none"], name
        assert "proof_identity_match" not in json.dumps(result["clean"]), name
    assert _audit(monkeypatch, [(0, BASE)] * 3, registry=cases["ambiguous"]["registry"])["clean"]["ownership"]["ambiguous"] == 0
    conflict = _audit(monkeypatch, [(0, BASE), (0, BASE), (0, _text(LO, ETH0, leak))], registry=cases["namespace_conflict"]["registry"])
    assert conflict["clean"]["ownership"]["namespace_conflicts"] == 1 and "namespace_mismatch" in conflict["clean"]["incomplete_reasons"]
    for name in ("no_registry", "unobserved", "invalid"):
        reasons = _audit(monkeypatch, [(0, BASE)] * 3, registry=cases[name]["registry"])["clean"]["incomplete_reasons"]
        assert reasons and set(reasons) <= {"ownership_missing", "ownership_invalid"}, (name, reasons)
    # A pre-existing host link with a fixture-like name that only changed is not the fixture's endpoint.
    old = _endpoint(9, "hp3l", "02:48:32:00:03:0a", 10)
    lifecycle = _audit(monkeypatch, [(0, _text(LO, old)), (0, _text(LO, old)), (0, _text(LO, old.replace("mtu 1500", "mtu 1400")))])
    assert [(c["change"], c["proof_identity"], c["correlation"]) for c in _pair(lifecycle)["changes"]] == [
        ("changed", "unknown", "none")]


def test_diag_driver_only_enrichment_change_is_diagnostic_evidence_never_a_fingerprint_delta(monkeypatch, tmp_path):
    drivers = iter(["hv_netvsc", "hv_netvsc", "mlx5_core"])
    state = {}

    def metadata(name, ifindex, deadline_ns, *, clock):
        if name == "eth0":
            state.setdefault("eth0", []).append(next(drivers))
            return {"device_backed": "yes", "bus": "vmbus", "driver": state["eth0"][-1], "status": "ok"}
        return {"device_backed": "no", "bus": "none", "driver": "none", "status": "ok"}

    result = _audit(monkeypatch, [(0, BASE), (0, BASE), (0, BASE)], metadata=metadata)
    pair = _pair(result)
    assert result["differing"] == [] and pair["gate_digest_equal"] is True and pair["classes"] == ["none"]
    assert pair["changes"] == [] and [e["fields"] for e in pair["enrichment_changes"]] == [["driver"]]
    assert _gate(tmp_path, True) == "PASS" and LAUNCHER.diagnostic_result("PASS", result["clean"]) == ("PASS", None)


def test_diag_command_status_successful_empty_failing_empty_and_timeout_stay_distinct(monkeypatch, tmp_path):
    failing = _audit(monkeypatch, [(0, BASE), (0, BASE), (1, "")])
    assert failing["differing"] == ["links"] and _pair(failing)["classes"] == ["command_status_change"]
    assert failing["clean"]["captures"][2]["status"] == "nonzero" and failing["clean"]["captures"][2]["returncode"] == 1
    assert "capture_not_ok" in failing["clean"]["incomplete_reasons"]
    timeout = _audit(monkeypatch, [(0, BASE), (0, BASE), subprocess.TimeoutExpired(["ip"], 20)])
    assert timeout["after"]["links"] == "unavailable" and timeout["differing"] == ["links"]
    assert timeout["clean"]["captures"][2]["status"] == "timeout" and timeout["clean"]["captures"][2]["gate_digest"] == "unavailable"
    empty = _audit(monkeypatch, [(0, ""), (0, ""), (0, "")])
    assert empty["differing"] == [] and empty["clean"]["captures"][2]["status"] == "ok"
    assert empty["clean"]["captures"][2]["line_count"] == 0 and empty["clean"]["captures"][2]["parse"] == "complete"
    # A stable failing baseline is still a stable baseline for the gate (unchanged), never hidden here.
    stable_failing = _audit(monkeypatch, [(1, ""), (1, ""), (1, "")])
    assert stable_failing["differing"] == [] and stable_failing["unstable"] == []
    assert stable_failing["clean"]["complete"] is False and "capture_not_ok" in stable_failing["clean"]["incomplete_reasons"]
    assert LAUNCHER.diagnostic_result("PASS", stable_failing["clean"]) == ("FAIL", "link_diagnostics_incomplete")
    digests = {item["clean"]["captures"][2]["gate_digest"] for item in (failing, timeout, empty)}
    assert len(digests) == 3
    # An unstable baseline stops before the namespace: two captures, the reason is explicit.
    unstable = _audit(monkeypatch, [(0, BASE), (0, _text(LO))])
    assert unstable["unstable"] == ["links"] and len(unstable["clean"]["captures"]) == 2
    assert [pair["name"] for pair in unstable["clean"]["pairs"]] == ["baseline"]
    assert "capture_missing" in unstable["clean"]["incomplete_reasons"]


def test_diag_unknown_syntax_caps_and_incompleteness_can_only_hold_a_pass(monkeypatch, tmp_path):
    odd = ETH0 + "\\    frobnicate 7"
    unknown = _audit(monkeypatch, [(0, _text(LO, odd))] * 3)
    assert unknown["differing"] == [] and unknown["clean"]["complete"] is False
    assert "unsupported_syntax" in unknown["clean"]["incomplete_reasons"]
    assert unknown["clean"]["captures"][0]["links"][1]["unknown"] == 1 and unknown["clean"]["captures"][0]["parse"] == "incomplete"
    assert _gate(tmp_path, True) == "PASS"
    assert LAUNCHER.diagnostic_result("PASS", unknown["clean"]) == ("FAIL", "link_diagnostics_incomplete")
    assert LAUNCHER.diagnostic_result("INCOMPLETE", unknown["clean"]) == ("INCOMPLETE", None)
    garbage = _audit(monkeypatch, [(0, BASE + "not a link line\n")] * 3)
    assert "unsupported_syntax" in garbage["clean"]["incomplete_reasons"] and garbage["clean"]["captures"][0]["line_count"] == 3
    many = _text(*[_endpoint(10 + i, f"vx{i}", "02:00:00:00:%02x:01" % i, 200 + i) for i in range(70)])
    capped = _audit(monkeypatch, [(0, BASE), (0, BASE), (0, BASE + many)], registry=fixture_registry())
    capture = capped["clean"]["captures"][2]
    # R2: the scan stops at 64 lines, so the total line/byte counts are unknown, never estimated.
    assert capture["line_count"] is None and capture["bytes"] is None and capture["scan"] == "truncated"
    assert capture["lines_scanned"] == len(capture["lines"]) == len(capture["links"]) == 64
    assert capture["chars"] == len(BASE + many)
    assert "line_cap" in capped["clean"]["incomplete_reasons"] and "changed_cap" not in capped["clean"]["incomplete_reasons"]
    pair = _pair(capped)
    assert len(pair["changes"]) == 62 and pair["added"] == 62 and "unknown" in pair["classes"]
    # 64 links replaced by 64 others: 128 changes, at most 64 exported, the cap named, the counts exact.
    old = _text(*[_endpoint(10 + i, f"va{i}", "02:00:00:00:%02x:01" % i, 300 + i) for i in range(64)])
    new = _text(*[_endpoint(10 + i, f"vb{i}", "02:00:00:00:%02x:02" % i, 300 + i) for i in range(64)])
    replaced = _audit(monkeypatch, [(0, old), (0, old), (0, new)])
    pair = _pair(replaced)
    assert (pair["added"], pair["removed"], len(pair["changes"])) == (64, 64, 64) and "unknown" in pair["classes"]
    assert "changed_cap" in replaced["clean"]["incomplete_reasons"] and replaced["clean"]["complete"] is False
    assert sum(len(p["changes"]) + len(p["enrichment_changes"]) for p in replaced["clean"]["pairs"]) <= 64
    # The original gate still hashes all 72 lines.
    assert capped["after"]["links"] == hashlib.sha256(("0" + BASE + many).encode()).hexdigest()
    # Payload cap: the details are dropped and the result is never complete.
    monkeypatch.setitem(LAUNCHER.DIAG_LIMITS, "payload_bytes", 2048)
    small = LAUNCHER.sanitize_link_diagnostics(_audit(monkeypatch, [(0, BASE)] * 3)["raw"])
    assert small["complete"] is False and "payload_cap" in small["incomplete_reasons"]
    assert all(c["links"] == [] and c["lines"] == [] for c in small["captures"])


def test_diag_parent_sanitizer_is_all_or_nothing(monkeypatch):
    good = _audit(monkeypatch, [(0, BASE), (0, BASE), (0, _text(LO, ETH0, VF))])["raw"]
    assert LAUNCHER.sanitize_link_diagnostics(json.loads(json.dumps(good))) == json.loads(json.dumps(good))

    def mutated(path, value):
        copy = json.loads(json.dumps(good))
        target = copy
        for part in path[:-1]:
            target = target[part]
        if value is KeyError:
            del target[path[-1]]
        else:
            target[path[-1]] = value
        return copy

    link = ("captures", 2, "links", 2)
    assert good["complete"] is True
    for path, value in ((("complete",), False), (("extra",), 1), (("schema",), "other"), (("captures", 0, "status"), "fine"),
                        (link + ("id",), "eth0"), (link + ("mac",), "7c:1e:52:10:20:30"), (link + ("mtu",), True),
                        (link + ("mtu",), 1.5), (link + ("id",), "A" * 64), (link + ("flags",), ["up", "broadcast"]),
                        (link + ("provenance", "driver"), "some_driver"), (link + ("name",), "enP7s1"),
                        (link + ("provenance",), KeyError), (("pairs", 1, "classes"), ["provider_owned"]),
                        (("pairs", 1, "changes", 0, "proof_identity"), "owned"), (("ownership", "status"), "trusted"),
                        (("captures", 0, "gate_digest"), "0" * 63), (("incomplete_reasons",), ["because"])):
        assert LAUNCHER.sanitize_link_diagnostics(mutated(path, value))["incomplete_reasons"] == ["diagnostics_invalid"], path
    for raw in ("text", [], {"schema": LAUNCHER.DIAG_SCHEMA}):
        assert LAUNCHER.sanitize_link_diagnostics(raw)["incomplete_reasons"] == ["diagnostics_invalid"]
    too_many = json.loads(json.dumps(good))
    too_many["captures"].append(too_many["captures"][0])
    assert LAUNCHER.sanitize_link_diagnostics(too_many)["incomplete_reasons"] == ["diagnostics_invalid"]
    # Every link object has exactly the sixteen bounded fields.
    assert all(len(entry) == LAUNCHER.DIAG_LIMITS["fields_per_link"] for c in good["captures"] for entry in c["links"])


def test_diag_secret_canaries_names_macs_aliases_and_the_key_never_reach_an_artifact(monkeypatch, tmp_path):
    canary_name, canary_mac, canary_alias = "cnry7Qz", "02:de:ad:be:ef:01", "alias-SECRET-c4nary"
    leak = (f"7: {canary_name}: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP mode DEFAULT group default "
            f"qlen 1000\\    link/ether {canary_mac} brd ff:ff:ff:ff:ff:ff permaddr {canary_mac}\\    alias {canary_alias}"
            f"\\    altname {canary_name}alt")
    result = _audit(monkeypatch, [(0, BASE), (0, BASE), (0, _text(LO, ETH0, leak))],
                    devices={canary_name: ("yes", "pci", "mlx5_core")})
    assert _pair(result)["changes"][0]["change"] == "added"
    summary = {"result": "FAIL", "gate_result": "FAIL", "diagnostic_hold": None}
    cleanup = {"host_fingerprints_unchanged": False, "link_diagnostics": result["clean"]}
    texts = [json.dumps(result["raw"]), json.dumps(result["clean"]),
             "\n".join(LAUNCHER.report_lines(summary, None, cleanup))]
    for text in texts:
        for secret in (canary_name, canary_mac, canary_alias, "SECRET", "dead", DIAG_KEY.hex(), "7c:1e:52", "eth0", "enP7",
                       "hp3l", "vmbus/", "/sys/"):
            assert secret not in text, secret
    directory = tmp_path / "artifacts"
    directory.mkdir()
    (directory / "cleanup.json").write_text(json.dumps(cleanup, indent=2, sort_keys=True) + "\n")
    assert LAUNCHER.artifact_scan(directory, DIAG_KEY.hex()) == []
    assert LAUNCHER.artifact_scan(directory, result["clean"]["captures"][0]["links"][0]["id"]) == ["cleanup.json"]  # scan works
    # The parent scans for the diagnostic key as well as the run token.
    source = (ROOT / "scripts/host_h2_policy_proof.py").read_text(encoding="utf-8")
    assert "artifact_scan(ARTIFACT_DIR, diagnostic_key)" in source and "artifact_scan(ARTIFACT_DIR, token)" in source
    # The keyed commitment depends on the key: an unkeyed or other-key hash cannot be compared.
    other = LAUNCHER.link_commitment(b"\x01" * 32, "name", canary_name)
    assert other != LAUNCHER.link_commitment(DIAG_KEY, "name", canary_name) != hashlib.sha256(canary_name.encode()).hexdigest()


def test_diag_observer_and_collector_failures_are_closed_reasons_never_gate_changes(monkeypatch):
    def failing_observe(collector):
        def observe(**_event):
            raise RuntimeError("observer exploded")
        collector.observe = observe

    plain = _audit(monkeypatch, [(0, BASE), (0, BASE), (0, _text(LO))])
    broken = _audit(monkeypatch, [(0, BASE), (0, BASE), (0, _text(LO))], collector_hook=failing_observe)
    assert (broken["before"], broken["after"], broken["differing"]) == (plain["before"], plain["after"], ["links"])
    assert broken["clean"]["complete"] is False and "capture_missing" in broken["clean"]["incomplete_reasons"]

    def exploding(name, ifindex, deadline_ns, *, clock):
        raise RuntimeError("metadata exploded")

    collector_failed = _audit(monkeypatch, [(0, BASE)] * 3, metadata=exploding)
    assert collector_failed["differing"] == [] and "collector_failed" in collector_failed["clean"]["incomplete_reasons"]
    assert {c["enrichment"]["status"] for c in collector_failed["clean"]["captures"]} == {"invalid"}
    identities = iter([HOST_NS, HOST_NS, (7, 99), (7, 99)] + [(7, 99)] * 40)
    moved = _audit(monkeypatch, [(0, BASE)] * 3, namespace=lambda: next(identities))
    assert moved["differing"] == [] and moved["clean"]["host_namespace"] is None
    assert "namespace_mismatch" in moved["clean"]["incomplete_reasons"]
    assert LAUNCHER.LinkCollector(DIAG_KEY, 0).result(b"\xff")["incomplete_reasons"] == [
        "capture_missing", "ownership_invalid"]
    # A result that cannot be built is a fixed reason, not an exception or a message.
    exploded = LAUNCHER.LinkCollector(DIAG_KEY, 0)
    exploded.phases = [None]
    assert exploded.result(None) == LAUNCHER.empty_diagnostics(["collector_failed"])


def _descriptor_path(descriptor: int) -> str:
    """The current path of an open descriptor (test-only: macOS F_GETPATH, Linux /proc/self/fd)."""
    if sys.platform == "darwin":
        import fcntl
        return fcntl.fcntl(descriptor, fcntl.F_GETPATH, bytes(1024)).rstrip(b"\0").decode()
    return os.readlink("/proc/self/fd/" + str(descriptor))


class _ModelMount:
    """SYNTHETIC model of the launcher's supported-mount contract over a fake tree, never mount proof:
    the fake root plays a verified sysfs mount root (mount 1), each path in ``over`` plays an overmount
    (mount 2) and anything else another filesystem (mount 3). It shows only how ``link_metadata`` uses
    the contract; whether a real /sys satisfies the contract is decided by ``SysfsMount`` on Linux."""

    def __init__(self, root: Path, over=(), supported: bool = True, drift: int | None = None):
        self.root, self.over = os.path.realpath(root), [os.path.realpath(path) for path in over]
        self.ok, self.drift, self.calls = supported, drift, 0
        self.paths: list[str] = []

    def descriptor(self, descriptor: int) -> int | None:
        self.calls += 1
        path = os.path.realpath(_descriptor_path(descriptor))
        self.paths.append(path)
        if self.drift is not None and self.calls > self.drift:
            return 4  # the mount id of the same path changes mid-walk
        if any(path == item or path.startswith(item + "/") for item in self.over):
            return 2
        return 1 if path == self.root or path.startswith(self.root + "/") else 3

    def supported(self, mount_id: int, device: int, root: str) -> bool:
        return self.ok and mount_id == 1 and root == self.root


def _meta(name: str, ifindex: int, deadline_ns: int, *, root, read=None, **model):
    """``link_metadata`` under the synthetic mount model (see ``_ModelMount``)."""
    extra = {} if read is None else {"read": read}
    return LAUNCHER.link_metadata(name, ifindex, deadline_ns, root=str(root), mount=_ModelMount(root, **model), **extra)


def _sysfs(tmp_path: Path, name: str, ifindex: int, *, bus: str | None = None, driver: str | None = None) -> Path:
    root = tmp_path / "sys"
    (root / "class" / "net").mkdir(parents=True, exist_ok=True)
    if bus is None:
        device_dir = root / "devices" / "virtual" / "net" / name
        device_dir.mkdir(parents=True)
    else:
        parent = root / "devices" / "pci0000:00" / f"0000:00:{ifindex:02x}.0"
        device_dir = parent / "net" / name
        device_dir.mkdir(parents=True)
        (root / "bus" / bus / "drivers").mkdir(parents=True, exist_ok=True)
        os.symlink(root / "bus" / bus, parent / "subsystem")
        os.symlink(parent, device_dir / "device")
        if driver:
            (root / "bus" / bus / "drivers" / driver).mkdir(exist_ok=True)
            os.symlink(root / "bus" / bus / "drivers" / driver, parent / "driver")
    (device_dir / "ifindex").write_text(f"{ifindex}\n")
    os.symlink(device_dir, root / "class" / "net" / name)
    return root


def test_diag_metadata_reads_are_fixed_bounded_inside_the_roots_and_unknown_on_races(tmp_path):
    far = time.monotonic_ns() + 10 ** 10
    root = _sysfs(tmp_path, "veth0", 4)
    assert _meta("veth0", 4, far, root=root) == {"device_backed": "no", "bus": "none", "driver": "none",
                                                                      "status": "ok"}
    _sysfs(tmp_path, "eth1", 3, bus="pci", driver="mlx5_core")
    assert _meta("eth1", 3, far, root=root) == {"device_backed": "yes", "bus": "pci",
                                                                     "driver": "mlx5_core", "status": "ok"}
    _sysfs(tmp_path, "eth2", 5, bus="pci", driver="vendor_secret_drv")
    assert _meta("eth2", 5, far, root=root)["driver"] == "unknown"
    unknown = {"device_backed": "unknown", "bus": "unknown", "driver": "unknown", "status": "unknown"}
    assert _meta("eth1", 4, far, root=root) == unknown  # another link now holds the name
    reads = iter(["3", "9"])
    assert _meta("eth1", 3, far, root=root, read=lambda _directory, _name, _verify: next(reads)) == unknown
    assert _meta("eth1", 3, 0, root=root) == unknown  # past the deadline
    assert _meta("gone0", 3, far, root=root) == unknown  # disappeared
    outside = tmp_path / "elsewhere" / "net" / "esc0"
    outside.mkdir(parents=True)
    (outside / "ifindex").write_text("6\n")
    os.symlink(outside, root / "class" / "net" / "esc0")
    assert _meta("esc0", 6, far, root=root) == unknown  # a symlink out of the devices tree
    for name in ("../x", "a/b", "", ".", "x" * 16, "eé0"):
        assert _meta(name, 1, far, root=root) == unknown, name
    (root / "class" / "net" / "big0").symlink_to(root / "devices" / "virtual" / "net" / "veth0")
    big = tmp_path / "big"
    big.write_text("1" * 65)
    directory = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(ValueError):
            LAUNCHER._sysfs_read(directory, "big", lambda _descriptor: None)
    finally:
        os.close(directory)


def test_diag_ancillary_command_is_the_one_fixed_read_only_listing_and_is_bounded(tmp_path):
    assert LAUNCHER.ANCILLARY_LINK_KINDS == ("ip", "-d", "-j", "link", "show")
    calls = []

    def run(argv, deadline_ns, *, clock):
        calls.append(argv)
        return "ok", json.dumps([{"ifindex": 1, "ifname": "lo"}, {"ifindex": 5, "ifname": "veth1", "linkinfo": {"info_kind": "veth"}},
                                 {"ifindex": 6, "ifname": "m0", "linkinfo": {"info_kind": "exotic"}}]).encode()

    assert LAUNCHER.link_kinds(0, run=run) == ("ok", {1: ("lo", "none"), 5: ("veth1", "veth"), 6: ("m0", "other")})
    assert calls == [LAUNCHER.ANCILLARY_LINK_KINDS]
    for payload in (b"{", b"{}", b'[{"ifindex": "1"}]', b"[NaN]"):
        assert LAUNCHER.link_kinds(0, run=lambda *a, **k: ("ok", payload))[0] == "invalid", payload
    assert LAUNCHER.link_kinds(0, run=lambda *a, **k: ("timeout", None)) == ("timeout", {})
    # The bounded runner itself: a cap, a deadline, a nonzero exit and a missing tool are statuses.
    soon = lambda seconds: time.monotonic_ns() + int(seconds * 1e9)  # noqa: E731
    python = sys.executable
    assert LAUNCHER.bounded_command((python, "-c", "print('x' * 70000)"), soon(20))[0] == "cap"
    assert LAUNCHER.bounded_command((python, "-c", "import time; time.sleep(5)"), soon(0.3))[0] == "timeout"
    assert LAUNCHER.bounded_command((python, "-c", "raise SystemExit(3)"), soon(20)) == ("nonzero", None)
    assert LAUNCHER.bounded_command((python, "-c", "print('ok')"), soon(20)) == ("ok", b"ok\n")
    assert LAUNCHER.bounded_command((str(tmp_path / "missing-tool"),), soon(5)) == ("oserror", None)
    # Static: the diagnostics run exactly one command (that listing), open files read-only, and use no
    # module loading, probing, mutation or network path.
    source = (ROOT / "scripts/host_h2_policy_proof.py").read_text(encoding="utf-8")
    section = source[source.index("# Supplementary host-link diagnostics"):source.index("# Parent: reviewed ref")]
    assert section.count("subprocess.Popen(") == 1 and "subprocess.run(" not in section
    assert re.findall(r"run\(([A-Z_]+), deadline_ns", section) == ["ANCILLARY_LINK_KINDS"]
    assert section.count("bounded_command") == 2  # the definition and the default ``run``
    assert sorted(set(re.findall(r"os\.O_[A-Z]+", section))) == ["os.O_CLOEXEC", "os.O_DIRECTORY", "os.O_NOFOLLOW",
                                                                 "os.O_NONBLOCK", "os.O_RDONLY"]
    for forbidden in ("modprobe", "insmod", "ethtool", "dmesg", "socket", "urllib", "write", "unlink", "rename", "chmod",
                      "setns", "unshare", "sysctl", "/proc/sys", '"w"', "netns exec", "link set", "link add", "link del"):
        assert forbidden not in section, forbidden
    # R2: the attribute read, the descriptor walk (anchor + component), the root and its recheck, the registry;
    # R3: the bounded /proc read of the mount contract and the child's cleanup file.
    assert not re.search(r"(?<![.\w])open\(", section) and section.count("os.open(") == 8
    assert sorted(set(re.findall(r'"/proc/[^"]*"', section))) == ['"/proc/self/fdinfo/%d"', '"/proc/self/mountinfo"',
                                                                       '"/proc/self/ns/net"']
    assert "os.path.realpath(f" not in section and "startswith(devices)" not in section  # no path-string containment


def test_diag_ownership_registry_records_are_closed_keyed_and_corroborated():
    listing = _endpoint(2, "hp1l", "02:48:32:00:01:0a", 2) + "\n"
    record = LAUNCHER.ownership_record(DIAG_KEY, 1, "l", (7, 11), (7, 12), "hp1l", "02:48:32:00:01:0A", listing)
    assert record["observed"] is True and record["name"] == record["requested_name"] and record["mac"] == record["requested_mac"]
    assert (record["ifindex"], record["iflink"]) == (2, 2) and "hp1l" not in json.dumps(record)
    for other in (None, "", listing + listing, _endpoint(2, "hp9l", "02:48:32:00:01:0a", 2), listing.replace("\\    link/", "\\    frob ")):
        assert LAUNCHER.ownership_record(DIAG_KEY, 1, "l", (7, 11), (7, 12), "hp1l", "02:48:32:00:01:0a", other)["observed"] is False
    assert LAUNCHER.sanitize_ownership(None) == ("missing", [])
    status, entries = LAUNCHER.sanitize_ownership(fixture_registry())
    assert status == "valid" and len(entries) == 4
    line = json.loads(fixture_registry().splitlines()[0])
    for bad in ({**line, "extra": 1}, {**line, "side": "x"}, {**line, "fixture": 0}, {**line, "name": "hp1l"},
                {**line, "ifindex": True}, {**line, "observed": 1}, {**line, "schema": "x"}):
        assert LAUNCHER.sanitize_ownership(json.dumps(bad).encode() + b"\n") == ("invalid", []), bad
    assert LAUNCHER.sanitize_ownership(fixture_registry() + fixture_registry().splitlines(keepends=True)[0])[0] == "invalid"
    many = b"".join(json.dumps({**line, "fixture": n}).encode() + b"\n" for n in range(1, 34))
    assert LAUNCHER.sanitize_ownership(many) == ("capped", [])
    assert LAUNCHER.sanitize_ownership(b" " * 70000) == ("invalid", [])
    assert LAUNCHER.sanitize_ownership(b"\xff") == ("invalid", [])


def test_diag_wiring_child_parent_and_fixture_channels():
    source = (ROOT / "scripts/host_h2_policy_proof.py").read_text(encoding="utf-8")
    child = source[source.index("def privileged_child("):source.index("def main(")]
    assert child.count('"link_diagnostics": collector.result(') == 2 and "read_ownership(out)" in child
    inside = source[source.index("def _inside("):source.index("def privileged_child(")]
    # R4: the original JUnit/records copy loop is byte-identical to 945537; the registry has its own
    # bounded transfer after it (see test_diag_r4_*).
    assert ('    for name in ("junit.xml", "records.raw.jsonl"):\n        if (out / name).exists():\n'
            '            h1f()._write_out(out_fd, name, (out / name).read_bytes(), request["uid"])\n'
            '    handoff_ownership(out, out_fd, request["uid"])\n    return 0\n') in inside
    assert "OWNERSHIP_FILE" not in inside and inside.count("read_bytes()") == 1
    assert 'DIAG_KEY_ENV: request["diagnostic_key"]' in inside
    parent = source[source.index("def parent("):source.index("# Privileged child:")]
    assert 'raw_cleanup, cleanup_capped = load_cleanup(out / "cleanup.raw.json")' in parent
    assert ('"link_diagnostics": empty_diagnostics(["diagnostics_invalid"]) if cleanup_capped\n'
            '            else sanitize_link_diagnostics(raw_cleanup.get("link_diagnostics"))})') in parent
    assert 'result, hold = diagnostic_result(verdict["result"], cleanup["link_diagnostics"])' in parent
    assert 'exit_code = 0 if result == "PASS" else 1' in parent and "secrets.token_hex(32)" in parent
    # The registry is written only by Fixture._register, beside the records, from a read-only listing.
    module = LINUX_MODULE_FILE.read_text(encoding="utf-8")
    register = module[module.index("    def _register("):module.index("    def _baseline(")]
    assert "name, mac, _endpoint_listing(fd, name)))" in register and "_run_in(" not in register
    listing = module[module.index("def _endpoint_listing("):module.index("def _fresh_namespace(")]
    assert "_in_netns(fd, lambda: LAUNCHER.bounded_command(" in listing
    assert '(AUTHORITY.IP_PATH, "-o", "link", "show", "dev", name)' in listing
    assert 'limit=limits["line_chars"] + 1' in listing and 'limits["ancillary_command_ms"] * 1_000_000' in listing
    assert "with_name(LAUNCHER.OWNERSHIP_FILE)" in register and module.count("LAUNCHER.OWNERSHIP_FILE") == 1
    assert module.count("self._register(") == 1 and not re.search(r"(?<![_\w])record\(", register)
    wire = module[module.index("    def _wire("):module.index("    def _register(")]
    assert wire.index("self._create_veth(a, mac_l, b, mac_r)") < wire.index("self._register(") < wire.index("steps = [")


# ---------------------------------------------------------------------------------------------
# H2-LINK-DIAGNOSTICS-R2: the review's three counterexamples (F1 early bounds, F2 correlation is not
# lifecycle identity, F3 descriptor-anchored sysfs traversal), each through the real collector.

def _counted(monkeypatch):
    """Count every parser invocation and every keyed commitment (with its input length)."""
    fixture_registry()  # the cached registry is built before counting starts
    parse, commit = LAUNCHER.parse_link_line, LAUNCHER.link_commitment
    parses, commits = [], []
    monkeypatch.setattr(LAUNCHER, "parse_link_line", lambda line: parses.append(len(line)) or parse(line))
    monkeypatch.setattr(LAUNCHER, "link_commitment",
                        lambda key, kind, value: commits.append((kind, len(value))) or commit(key, kind, value))
    return parses, commits


def _drive(texts, *, registry=None, status="ok"):
    """The collector alone over given links captures (no H0), with constant metadata."""
    clock = _Clock()
    collector = LAUNCHER.LinkCollector(
        DIAG_KEY, clock.t0, clock=clock, sleep=clock.sleep, namespace=lambda: HOST_NS,
        kinds=lambda deadline_ns, *, clock: ("ok", {}),
        metadata=lambda name, ifindex, deadline_ns, *, clock: {"device_backed": "no", "bus": "none", "driver": "none",
                                                               "status": "ok"})
    for text in texts:
        phase = collector.begin()
        collector.observe(name="links", status=status, returncode=0 if status == "ok" else 1, stdout=text,
                          digest="0" * 64, started_ns=clock(), ended_ns=clock())
        collector.end(phase)
    return collector


def test_diag_r2_capture_work_is_bounded_before_parsing_committing_encoding_or_sorting(monkeypatch, tmp_path):
    parses, commits = _counted(monkeypatch)
    cap, chars = LAUNCHER.DIAG_LIMITS["links_per_capture"], LAUNCHER.DIAG_LIMITS["line_chars"]
    # 128 distinct well-formed lines per capture: at most 64 parser invocations each, the rest unread.
    many = _text(*[_endpoint(10 + i, f"vx{i}", "02:00:00:00:%02x:01" % i, 300 + i) for i in range(128)])
    result = _audit(monkeypatch, [(0, many)] * 3)
    assert len(parses) <= 3 * cap, len(parses)
    assert len([kind for kind, _n in commits if kind == "line"]) <= 3 * 2 * cap
    assert result["differing"] == [] and result["after"]["links"] == hashlib.sha256(("0" + many).encode()).hexdigest()
    capture = result["clean"]["captures"][2]
    assert (capture["scan"], capture["line_count"], capture["bytes"], capture["multiset"]) == ("truncated", None, None, None)
    assert capture["chars"] == len(many) and capture["lines_scanned"] == len(capture["lines"]) == cap
    assert "line_cap" in result["clean"]["incomplete_reasons"] and result["clean"]["complete"] is False
    assert LAUNCHER.diagnostic_result("PASS", result["clean"]) == ("FAIL", "link_diagnostics_incomplete")
    # One oversized line (8 MiB, no newline): never copied into the parser or a commitment; the scan
    # stops there, explicitly, while the gate still digests the exact full capture.
    parses.clear(), commits.clear()
    huge = BASE + "9: big0: <UP> mtu 1500 " + "a" * (8 * 2 ** 20) + "\n" + _endpoint(11, "late0", "02:00:00:00:00:11", 12) + "\n"
    result = _audit(monkeypatch, [(0, huge)] * 3)
    assert max(parses) <= chars and max(n for _kind, n in commits) <= 2 * chars
    assert result["after"]["links"] == hashlib.sha256(("0" + huge).encode()).hexdigest() and result["differing"] == []
    capture = result["clean"]["captures"][0]
    assert (capture["scan"], capture["lines_scanned"], capture["bytes"], capture["chars"]) == ("truncated", 2, None, len(huge))
    assert "line_length_cap" in result["clean"]["incomplete_reasons"] and result["clean"]["complete"] is False
    # Repeated unknown lines (16 MiB): bounded parser calls and bounded allocation in enrich + result.
    parses.clear(), commits.clear()
    garbage = "not a link line\n" * 2 ** 20
    collector = _drive([garbage] * 3)
    tracemalloc.start()
    try:
        collector.enrich()
        raw = collector.result(None)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 2 ** 20, peak
    assert len(parses) <= 3 * cap and len(commits) <= 3 * (cap + 8)
    assert {c["scan"] for c in raw["captures"]} == {"truncated"} and "unsupported_syntax" in raw["incomplete_reasons"]
    # Unicode: exact UTF-8 byte counts when the scan completes; the aggregate scan bound counts
    # characters before any encoding; an unencodable lone surrogate is a closed reason, not a crash.
    small = _text(LO, ETH0 + "\\    alias café-été")
    capture = _audit(monkeypatch, [(0, small)] * 3)["clean"]["captures"][2]
    assert (capture["scan"], capture["bytes"], capture["chars"], capture["line_count"]) == (
        "complete", len(small.encode()), len(small), 2)
    wide = _text(LO, *[f"{10 + i}: u{i}: <UP> mtu 1500\\    alias " + "\U0001F600" * 3000 for i in range(40)])
    parses.clear()
    result = _audit(monkeypatch, [(0, wide)] * 3)
    capture = result["clean"]["captures"][2]
    assert capture["scan"] == "truncated" and capture["bytes"] is None and capture["chars"] == len(wide)
    assert "scan_cap" in result["clean"]["incomplete_reasons"]
    assert sum(parses) <= 3 * LAUNCHER.DIAG_LIMITS["scan_chars"]
    lone = _drive([_text(LO, "5: s0: <UP> mtu 1500\\    alias x\ud800y", ETH0)] * 3).result(None)
    assert len(lone["captures"]) == 3 and "collector_failed" not in lone["incomplete_reasons"]
    assert "unsupported_encoding" in lone["incomplete_reasons"] and lone["captures"][0]["lines_scanned"] == 1
    # Order-only is claimed only between two complete scans: a reorder past the scanned prefix is unknown.
    lines = [_endpoint(10 + i, f"vo{i}", "02:00:00:00:%02x:03" % i, 400 + i) for i in range(70)]
    swapped = lines[:68] + [lines[69], lines[68]]
    reordered = _audit(monkeypatch, [(0, _text(*lines))] * 2 + [(0, _text(*swapped))])
    pair = _pair(reordered)
    assert reordered["differing"] == ["links"] and _gate(tmp_path, False) == "FAIL"
    assert pair["order_only"] is False and "unknown" in pair["classes"] and "order_only_text_change" not in pair["classes"]
    # A reordered scanned prefix with different unscanned content is not order-only either.
    changed = [lines[1], lines[0]] + lines[2:69] + [_endpoint(99, "vz0", "02:00:00:00:99:03", 499)]
    prefix = _audit(monkeypatch, [(0, _text(*lines))] * 2 + [(0, _text(*changed))])
    pair = _pair(prefix)
    assert prefix["differing"] == ["links"] and pair["order_only"] is False and "order_only_text_change" not in pair["classes"]


def test_diag_r2_name_and_mac_are_correlation_only_never_lifecycle_identity(monkeypatch, tmp_path):
    # The review's case: created in a fixture namespace at index 2, a later separate host object at
    # 900/901 with the same name, MAC and hardware metadata. No move or lifetime witness joins them.
    mac = "02:48:32:00:03:0a"
    lookalike = _endpoint(900, "hp3l", mac, 901)
    hardware = {"hp3l": ("yes", "pci", "mlx5_core")}
    result = _audit(monkeypatch, [(0, BASE), (0, BASE), (0, _text(LO, ETH0, lookalike))], devices=hardware)
    assert "proof_identity_match" not in json.dumps(result["raw"]) + json.dumps(result["clean"])
    assert result["differing"] == ["links"] and _gate(tmp_path, False) == "FAIL"
    assert LAUNCHER.diagnostic_result("FAIL", result["clean"]) == ("FAIL", None)
    pair = _pair(result)
    change = pair["changes"][0]
    assert (change["change"], change["proof_identity"], change["correlation"], change["hardware"]) == (
        "added", "unknown", "fixture_name_mac", "device_backed")
    assert pair["classes"] == ["fixture_name_mac_correlation", "hardware_backed_change"]
    # Completeness of the captures is not attribution certainty.
    clean = result["clean"]
    assert clean["complete"] is True and clean["attribution"] == "correlation_only"
    assert clean["ownership"] == {"status": "valid", "endpoints": 4, "correlated": 1, "ambiguous": 0, "namespace_conflicts": 0}
    # The same ifindex/iflink as at creation is still no continuity witness.
    same_index = _audit(monkeypatch, [(0, BASE), (0, BASE), (0, _text(LO, ETH0, _endpoint(2, "hp3l", mac, 2)))])
    change = _pair(same_index)["changes"][0]
    assert (change["proof_identity"], change["correlation"], change["hardware"]) == ("unknown", "fixture_name_mac", "virtual")
    assert _pair(same_index)["classes"] == ["fixture_name_mac_correlation", "unknown"]
    # The same name and MAC registered by two fixtures in separate namespaces/lifetimes: ambiguous.
    twice = fixture_registry() + _registry((7, "l", (7, 4026532701), "hp3l", mac, _endpoint(2, "hp3l", mac, 2)))
    ambiguous = _audit(monkeypatch, [(0, BASE), (0, BASE), (0, _text(LO, ETH0, lookalike))], registry=twice, devices=hardware)
    change = _pair(ambiguous)["changes"][0]
    assert (change["proof_identity"], change["correlation"]) == ("unknown", "ambiguous")
    assert _pair(ambiguous)["classes"] == ["hardware_backed_change"]
    assert (ambiguous["clean"]["ownership"]["correlated"], ambiguous["clean"]["ownership"]["ambiguous"]) == (0, 1)
    # A stale/reused lookalike already present in both baselines that later changes: no correlation.
    changed = lookalike.replace("mtu 1500", "mtu 1400")
    stale = _audit(monkeypatch, [(0, _text(LO, lookalike))] * 2 + [(0, _text(LO, changed))], devices=hardware)
    change = _pair(stale)["changes"][0]
    assert (change["change"], change["proof_identity"], change["correlation"]) == ("changed", "unknown", "none")
    assert _pair(stale)["classes"] == ["hardware_backed_change"] and stale["differing"] == ["links"]
    # The baseline pair never correlates.
    assert {c["correlation"] for p in stale["clean"]["pairs"] if p["name"] == "baseline" for c in p["changes"]} <= {"not_applicable"}
    # The parent refuses a child payload that asserts lifecycle identity or an open attribution.
    good = result["raw"]
    for path, value in ((("pairs", 1, "changes", 0, "proof_identity"), "proof_identity_match"),
                        (("pairs", 1, "classes"), ["fixture_name_mac_correlation", "proof_identity_match"]),
                        (("pairs", 1, "changes", 0, "correlation"), "owned"), (("attribution",), "lifecycle_identity"),
                        (("ownership", "matched"), 1)):
        copy = json.loads(json.dumps(good))
        target = copy
        for part in path[:-1]:
            target = target[part]
        target[path[-1]] = value
        assert LAUNCHER.sanitize_link_diagnostics(copy)["incomplete_reasons"] == ["diagnostics_invalid"], path


class _Opens:
    """The launcher's ``os`` with ``open`` observed: the (device, inode) every successful open reached,
    and one callback on the nth open whose final component is ``component`` (the race timing). The
    candidate performs every actual open and read itself."""

    def __init__(self, monkeypatch, component: str | None = None, nth: int = 1, action=None, foreign=()):
        self.reached, self.count = [], 0
        outer, real = self, os

        class _Proxy:
            def __getattr__(self, attribute):
                return getattr(real, attribute)

            def fstat(self, descriptor):
                """``foreign`` inodes appear to sit on another filesystem (a mount inside the tree)."""
                info = real.fstat(descriptor)
                if info.st_ino in foreign:
                    return os.stat_result((info.st_mode, info.st_ino, info.st_dev + 1, *tuple(info)[3:10]))
                return info

            def open(self, path, flags, mode=None, *, dir_fd=None):
                if action is not None and real.path.basename(str(path)) == component:
                    outer.count += 1
                    if outer.count == nth:
                        action()
                if mode is None:
                    descriptor = real.open(path, flags, dir_fd=dir_fd)
                else:
                    descriptor = real.open(path, flags, mode, dir_fd=dir_fd)
                info = real.fstat(descriptor)
                outer.reached.append((info.st_dev, info.st_ino))
                return descriptor

        monkeypatch.setattr(LAUNCHER, "os", _Proxy())


def _real_sysfs(base: Path, name: str, ifindex: int, *, bus: str | None = None, driver: str | None = None,
                slot: str = "0000:00:02.0") -> tuple[Path, Path]:
    """A fake sysfs shaped like the real one: relative class/device/subsystem/driver links."""
    root = base / "sys"
    (root / "class" / "net").mkdir(parents=True, exist_ok=True)
    if bus is None:
        device_dir = root / "devices" / "virtual" / "net" / name
        device_dir.mkdir(parents=True)
    else:
        parent = root / "devices" / "pci0000:00" / slot
        device_dir = parent / "net" / name
        device_dir.mkdir(parents=True)
        (root / "bus" / bus / "drivers").mkdir(parents=True, exist_ok=True)
        os.symlink(os.path.relpath(root / "bus" / bus, parent), parent / "subsystem")
        os.symlink(os.path.relpath(parent, device_dir), device_dir / "device")
        if driver:
            (root / "bus" / bus / "drivers" / driver).mkdir(exist_ok=True)
            os.symlink(os.path.relpath(root / "bus" / bus / "drivers" / driver, parent), parent / "driver")
    (device_dir / "ifindex").write_text(f"{ifindex}\n")
    os.symlink(os.path.relpath(device_dir, root / "class" / "net"), root / "class" / "net" / name)
    return root, device_dir


def _identity(path: Path) -> tuple[int, int]:
    info = os.stat(path, follow_symlinks=False)
    return info.st_dev, info.st_ino


def test_diag_r2_sysfs_traversal_is_descriptor_anchored_contained_and_rechecked(monkeypatch, tmp_path):
    far = time.monotonic_ns() + 10 ** 10
    unknown = {"device_backed": "unknown", "bus": "unknown", "driver": "unknown", "status": "unknown"}

    def scratch(label: str) -> Path:
        path = tmp_path / label
        path.mkdir()
        return path

    def outside_tree(base: Path, ifindex: int = 7) -> Path:
        """A lookalike outside the fake sysfs root (never to be read)."""
        tree = base / "outside" / "virtual" / "net" / "mock0"
        tree.mkdir(parents=True)
        (tree / "ifindex").write_text(f"{ifindex}\n")
        return tree

    # Positive: real-sysfs-shaped relative links inside the root are followed, and only those.
    base = scratch("positive")
    root, _dir = _real_sysfs(base, "veth0", 4)
    _real_sysfs(base, "eth1", 3, bus="pci", driver="mlx5_core")
    _real_sysfs(base, "eth2", 5, bus="vmbus", driver="hv_netvsc", slot="vmbus-0")
    probe = _Opens(monkeypatch)
    assert _meta("veth0", 4, far, root=root) == {"device_backed": "no", "bus": "none", "driver": "none",
                                                                      "status": "ok"}
    assert _meta("eth1", 3, far, root=root) == {"device_backed": "yes", "bus": "pci",
                                                                     "driver": "mlx5_core", "status": "ok"}
    assert _meta("eth2", 5, far, root=root) == {"device_backed": "yes", "bus": "vmbus",
                                                                     "driver": "hv_netvsc", "status": "ok"}
    assert probe.reached
    monkeypatch.undo()

    # Parent replacement at the first attribute read (the review's timing): the checked parent becomes
    # a symlink to a lookalike outside the root. Unknown, and the outside object is never reached.
    base = scratch("parent")
    root, device_dir = _real_sysfs(base, "mock0", 7)
    outside = outside_tree(base)

    def replace_parent():
        device_dir.rename(device_dir.with_name("old"))
        device_dir.symlink_to(outside)

    probe = _Opens(monkeypatch, "ifindex", 1, replace_parent)
    assert _meta("mock0", 7, far, root=root) == unknown
    assert probe.count >= 1 and _identity(outside / "ifindex") not in probe.reached and _identity(outside) not in probe.reached
    monkeypatch.undo()

    # Nested parent substitution: an ancestor (devices/virtual) replaced by a symlink to a full
    # lookalike tree outside the root, at the first read; and the same substitution made beforehand.
    for when in ("during", "before"):
        base = scratch("nested-" + when)
        root, device_dir = _real_sysfs(base, "mock0", 7)
        outside = outside_tree(base)
        ancestor = root / "devices" / "virtual"

        def replace_ancestor(ancestor=ancestor, outside=outside):
            ancestor.rename(ancestor.with_name("virtual.old"))
            ancestor.symlink_to(outside.parent.parent)

        if when == "before":
            replace_ancestor()
        probe = _Opens(monkeypatch, "ifindex", 1, replace_ancestor if when == "during" else None)
        assert _meta("mock0", 7, far, root=root) == unknown, when
        assert _identity(outside / "ifindex") not in probe.reached, when
        monkeypatch.undo()

    # Static escapes: lexical, absolute, ancestor symlinks and metadata links that leave their trees.
    base = scratch("static")
    root, _dir = _real_sysfs(base, "ok0", 2, bus="pci", driver="mlx5_core")
    outside = outside_tree(base, 6)
    net = root / "class" / "net"
    os.symlink("../../../outside/virtual/net/mock0", net / "esc1")
    os.symlink("../../devices/../../outside/virtual/net/mock0", net / "esc2")
    os.symlink(str(outside), net / "esc3")
    (root / "devices" / "jump").symlink_to(outside.parent.parent)
    os.symlink("../../devices/jump/net/mock0", net / "esc4")
    _real_sysfs(base, "dev5", 8, bus="pci", driver="mlx5_core", slot="0000:00:05.0")
    (root / "devices" / "pci0000:00" / "0000:00:05.0" / "net" / "dev5" / "device").unlink()
    os.symlink("../../../../../outside", root / "devices" / "pci0000:00" / "0000:00:05.0" / "net" / "dev5" / "device")
    _real_sysfs(base, "dev6", 9, bus="pci", slot="0000:00:06.0")
    (root / "devices" / "pci0000:00" / "0000:00:06.0" / "subsystem").unlink()
    os.symlink("../../../class/net", root / "devices" / "pci0000:00" / "0000:00:06.0" / "subsystem")
    _real_sysfs(base, "dev7", 10, bus="pci", driver="mlx5_core", slot="0000:00:07.0")
    (root / "devices" / "pci0000:00" / "0000:00:07.0" / "driver").unlink()
    os.symlink("../../../../outside", root / "devices" / "pci0000:00" / "0000:00:07.0" / "driver")
    probe = _Opens(monkeypatch)
    for name, index in (("esc1", 6), ("esc2", 6), ("esc3", 6), ("esc4", 6), ("dev5", 8), ("dev6", 9), ("dev7", 10)):
        assert _meta(name, index, far, root=root) == unknown, name
    assert _identity(outside / "ifindex") not in probe.reached
    assert _meta("ok0", 2, far, root=root)["status"] == "ok"  # the contained neighbour still reads
    monkeypatch.undo()

    # Escapes that a weaker check would accept: a ``..`` above the root whose clamped form exists in
    # it; an absolute link into a sibling sharing the root's name prefix; in-root targets outside the
    # intended tree (a class link off devices/…/net/<name>, a driver link off bus/<bus>/drivers).
    base = scratch("lookalike")
    root, _dir = _real_sysfs(base, "x0", 11)
    escaped = base / "devices" / "virtual" / "net" / "up0"  # above the root: the real target
    escaped.mkdir(parents=True)
    (escaped / "ifindex").write_text("11\n")
    os.symlink("../../../devices/virtual/net/up0", root / "class" / "net" / "up0")
    (root / "devices" / "virtual" / "net" / "up0").mkdir()
    (root / "devices" / "virtual" / "net" / "up0" / "ifindex").write_text("11\n")
    sibling = Path(str(root) + "x") / "devices" / "virtual" / "net" / "sib0"
    sibling.mkdir(parents=True)
    (sibling / "ifindex").write_text("12\n")
    (root / "devices" / "virtual" / "net" / "sib0").mkdir()
    (root / "devices" / "virtual" / "net" / "sib0" / "ifindex").write_text("12\n")
    os.symlink(str(sibling), root / "class" / "net" / "sib0")
    (root / "misc" / "deep" / "odd0").mkdir(parents=True)
    (root / "misc" / "deep" / "odd0" / "ifindex").write_text("13\n")
    os.symlink("../../misc/deep/odd0", root / "class" / "net" / "odd0")
    _real_sysfs(base, "drv0", 14, bus="pci", driver="mlx5_core", slot="0000:00:0e.0")
    (root / "devices" / "pci0000:00" / "0000:00:0e.0" / "driver").unlink()
    (root / "bus" / "usb" / "drivers" / "ixgbe").mkdir(parents=True)  # a driver of another bus
    os.symlink("../../../bus/usb/drivers/ixgbe", root / "devices" / "pci0000:00" / "0000:00:0e.0" / "driver")
    probe = _Opens(monkeypatch)
    for name, index in (("up0", 11), ("sib0", 12), ("odd0", 13), ("drv0", 14)):
        assert _meta(name, index, far, root=root) == unknown, name
    assert _identity(escaped) not in probe.reached and _identity(sibling) not in probe.reached
    assert _meta("x0", 11, far, root=root)["status"] == "ok"
    monkeypatch.undo()

    # An object on another filesystem (a mount inside the tree) is refused.
    base = scratch("foreign")
    root, device_dir = _real_sysfs(base, "mnt0", 15)
    _Opens(monkeypatch, foreign={_identity(device_dir)[1]})
    assert _meta("mnt0", 15, far, root=root) == unknown
    monkeypatch.undo()
    assert _meta("mnt0", 15, far, root=root)["status"] == "ok"

    # The root itself replaced by a lookalike copy during the read: the anchor is no longer /sys.
    base = scratch("root")
    root, _dir = _real_sysfs(base, "mock0", 7)

    def replace_root():
        root.rename(root.with_name("sys.old"))
        shutil.copytree(root.with_name("sys.old"), root, symlinks=True)

    _Opens(monkeypatch, "ifindex", 1, replace_root)
    assert _meta("mock0", 7, far, root=root) == unknown
    monkeypatch.undo()

    # A value that flickers between the reads of one pass, though both passes begin alike.
    base = scratch("flicker")
    root, _dir = _real_sysfs(base, "mock0", 7)
    values = iter(["7", "7", "9", "7", "7", "7"])
    assert _meta("mock0", 7, far, root=root, read=lambda _directory, _name, _verify: next(values)) == unknown

    # The same ifindex on a replaced object (the name's directory recreated at the first read).
    base = scratch("reuse")
    root, device_dir = _real_sysfs(base, "mock0", 7)

    def recreate():
        device_dir.rename(device_dir.with_name("gone"))
        device_dir.mkdir()
        (device_dir / "ifindex").write_text("7\n")

    _Opens(monkeypatch, "ifindex", 1, recreate)
    assert _meta("mock0", 7, far, root=root) == unknown
    monkeypatch.undo()

    # The name's class link retargeted to another same-ifindex device, and the device link retargeted.
    base = scratch("retarget")
    root, _dir = _real_sysfs(base, "mock0", 7)
    other = root / "devices" / "pci0000:00" / "0000:00:03.0" / "net" / "mock0"
    other.mkdir(parents=True)
    (other / "ifindex").write_text("7\n")

    def retarget_class():
        (root / "class" / "net" / "mock0").unlink()
        os.symlink(os.path.relpath(other, root / "class" / "net"), root / "class" / "net" / "mock0")

    _Opens(monkeypatch, "ifindex", 1, retarget_class)
    assert _meta("mock0", 7, far, root=root) == unknown
    monkeypatch.undo()
    base = scratch("retarget-device")
    root, device_dir = _real_sysfs(base, "eth1", 3, bus="pci", driver="mlx5_core")
    _real_sysfs(base, "eth9", 9, bus="pci", driver="ixgbe", slot="0000:00:09.0")

    def retarget_device():
        (device_dir / "device").unlink()
        os.symlink("../../../0000:00:09.0", device_dir / "device")

    _Opens(monkeypatch, "ifindex", 2, retarget_device)
    assert _meta("eth1", 3, far, root=root) == unknown
    monkeypatch.undo()

    # Disappearance during enrichment.
    base = scratch("gone")
    root, _dir = _real_sysfs(base, "mock0", 7)
    _Opens(monkeypatch, "ifindex", 1, lambda: (root / "class" / "net" / "mock0").unlink())
    assert _meta("mock0", 7, far, root=root) == unknown
    monkeypatch.undo()


# ---------------------------------------------------------------------------------------------
# H2-LINK-DIAGNOSTICS-R3: early bounds on every remaining diagnostic path (fixture listing and
# registry, parent validation and cleanup loading, ancillary listing) and the supported-sysfs-mount
# contract. Inputs are plain JSON/str/bytes; work is observed with sys.setprofile (Python frames,
# generator resumes and C builtins called) and tracemalloc, never by instrumenting the input.

import collections  # noqa: E402


def _work(function, *args, **kwargs):
    """(result, Counter of profile events) for one call: ``py:<code name>`` and ``c:<builtin name>``."""
    events = collections.Counter()

    def hook(frame, event, arg):
        if event == "call":
            events["py:" + frame.f_code.co_name] += 1
        elif event == "c_call":
            events["c:" + getattr(arg, "__name__", "?")] += 1

    sys.setprofile(hook)
    try:
        result = function(*args, **kwargs)
    finally:
        sys.setprofile(None)
    return result, events


def _peak(function, *args):
    tracemalloc.start()
    try:
        result = function(*args)
        return result, tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


class _Reads:
    """The launcher's ``os`` with every ``read`` request size and every returned byte count recorded
    (the candidate does every read itself)."""

    def __init__(self, monkeypatch):
        self.requests, self.returned, real = [], [], os

        class _Proxy:
            def __getattr__(self, attribute):
                return getattr(real, attribute)

            def read(inner, descriptor, size):  # noqa: N805
                self.requests.append(size)
                data = real.read(descriptor, size)
                self.returned.append(len(data))
                return data

        monkeypatch.setattr(LAUNCHER, "os", _Proxy())

    def within(self, limit: int) -> bool:
        """No single request and no total of bytes read ever exceeds ``limit`` + 1."""
        return max(self.requests, default=0) <= limit + 1 and sum(self.returned) <= limit + 1

    def clear(self):
        self.requests.clear()
        self.returned.clear()


def _max_hex(n: int) -> str:
    return hashlib.sha256(str(n).encode()).hexdigest()


def _max_diagnostics() -> dict:
    """A largest valid child payload: 3 captures x 64 lines and 64 links with every field at its widest,
    every reason (complete false), 64 changes. Built by hand against the closed spec."""
    link = {"id": _max_hex(1), "ifindex": 2 ** 31 - 1, "iflink": 2 ** 31 - 1, "peer": _max_hex(2),
            "flags": sorted(LAUNCHER.LINK_FLAGS),
            "operstate": "lowerlayerdown", "link_type": "infiniband", "mtu": 2 ** 31 - 1, "qlen": 2 ** 32, "mac": _max_hex(3),
            "master": _max_hex(4), "netnsid": 2 ** 31 - 1, "line": _max_hex(5), "other": _max_hex(6), "unknown": 4096,
            "provenance": {"device_backed": "unknown", "bus": "auxiliary", "kind": "macvtap", "driver": "mlx5_core",
                           "scope": "host_verified"}}
    captures = [{"phase": phase, "ordinal": ordinal, "namespace_before": _max_hex(7), "namespace_after": _max_hex(7),
                 "start_ms": 10 ** 7, "end_ms": 10 ** 7, "status": "ok", "returncode": -255, "gate_digest": _max_hex(8),
                 "chars": 2 ** 62, "bytes": 4 * 65536 + 64, "line_count": 64, "lines_scanned": 64, "scan": "truncated",
                 "parse": "incomplete", "lines": [_max_hex(100 + i) for i in range(64)], "multiset": _max_hex(9),
                 "links": [dict(link, id=_max_hex(200 + i)) for i in range(64)],
                 "enrichment": {"status": "namespace_mismatch", "start_ms": 10 ** 7, "end_ms": 10 ** 7}}
                for ordinal, phase in enumerate(LAUNCHER.DIAG_PHASES)]
    change = {"id": _max_hex(10), "change": "changed", "fields": sorted(LAUNCHER.FIELD_LABELS), "proof_identity": "not_applicable",
              "correlation": "fixture_name_mac", "hardware": "device_backed"}
    pairs = [{"name": name, "from": LAUNCHER.DIAG_PHASES[first], "to": LAUNCHER.DIAG_PHASES[second], "gate_digest_equal": False,
              "status_change": True, "order_only": True, "added": 10 ** 6, "removed": 10 ** 6, "changed": 10 ** 6,
              "classes": sorted(LAUNCHER.DELTA_CLASSES), "changes": [dict(change, id=_max_hex(300 + i)) for i in range(32)],
              "enrichment_changes": []} for name, first, second in LAUNCHER.DIAG_PAIRS]
    return {"schema": LAUNCHER.DIAG_SCHEMA, "complete": False, "incomplete_reasons": sorted(LAUNCHER.DIAG_REASONS),
            "attribution": "correlation_only", "host_namespace": _max_hex(7), "baseline_pause_ms": 10 ** 7, "ancillary_ms": 10 ** 7,
            "captures": captures, "pairs": pairs,
            "ownership": {"status": "capped", "endpoints": 10 ** 6, "correlated": 10 ** 6, "ambiguous": 10 ** 6,
                          "namespace_conflicts": 10 ** 6}}


def _max_registry_line(fixture: int, side: str) -> bytes:
    entry = {"schema": LAUNCHER.OWNERSHIP_SCHEMA, "fixture": fixture, "side": side, "namespace": _max_hex(1), "outer": _max_hex(2),
             "requested_name": _max_hex(3), "requested_mac": _max_hex(4), "observed": True, "name": _max_hex(3),
             "mac": _max_hex(4), "ifindex": 2 ** 31 - 1, "iflink": 2 ** 31 - 1}
    return (json.dumps(entry, sort_keys=True) + "\n").encode()


def test_diag_r3_fixture_listing_and_registry_are_bounded_before_any_split_or_parse(monkeypatch, tmp_path):
    record = functools.partial(LAUNCHER.ownership_record, DIAG_KEY, 1, "l", (7, 1), (7, 2), "hp1l", "02:48:32:00:01:0a")
    # The review's counterexample with plain strings: a rejected multi-line listing costs neither a
    # split, a parse nor an allocation that grows with it.
    rows = []
    for lines in (4096, 32768):
        listing = ("x" * 64 + "\n") * lines
        (result, events), peak = _peak(lambda listing=listing: _work(record, listing))
        assert result["observed"] is False and events["c:splitlines"] == 0 and events["py:parse_link_line"] == 0, lines
        rows.append((peak, sum(events.values())))
    assert rows[0][1] == rows[1][1] and max(peak for peak, _ in rows) < 16384, rows
    # Positives at the bound: one real listing line (with or without its newline) is still observed.
    line = _endpoint(2, "hp1l", "02:48:32:00:01:0a", 2)
    assert record(line)["observed"] and record(line.rstrip("\n"))["observed"]
    padded = line.rstrip("\n").ljust(LAUNCHER.DIAG_LIMITS["line_chars"])  # trailing spaces: still one supported line
    assert len(padded) == 4096 and record(padded + "\n")["observed"] and not record(padded + " \n")["observed"]
    assert not record(line + line)["observed"] and not record(None)["observed"]
    for name, mac in (("x" * 16, "02:00:00:00:00:01"), ("hp1l", "0" * 65), ("hp1l", None), (None, "02:00:00:00:00:01")):
        with pytest.raises(ValueError):
            LAUNCHER.ownership_record(DIAG_KEY, 1, "l", (7, 1), (7, 2), name, mac, line)

    # sanitize_ownership: lines are counted and shaped before any decode or JSON parse.
    widest_33 = b"".join(_max_registry_line(n, "l") for n in range(1, 34))
    for raw, status in ((b"null\n" * 1024, "capped"), (b"{}\n" * 33, "capped"), (widest_33, "capped"),
                        (b"x" * 2049, "invalid"), (b"{}\r\n", "invalid"), (b"{}\n\n{}\n", "invalid"),
                        ("é".encode() + b"\n", "invalid"), (b"\x00\n", "invalid"), (b"\n" * 70000, "invalid")):
        (result, entries), events = _work(LAUNCHER.sanitize_ownership, raw)
        assert (result, entries) == (status, []) and events["py:loads"] == 0, raw[:16]
        assert events["c:decode"] == 0 and events["c:splitlines"] == 0, raw[:16]
    # Positive at the bound: 32 widest valid records (2 x 16 fixtures) are all parsed and kept.
    widest = b"".join(_max_registry_line(n, side) for n in range(4081, 4097) for side in ("l", "r"))
    assert len(_max_registry_line(4096, "r")) < LAUNCHER.DIAG_LIMITS["ownership_line_bytes"] and len(widest) < 65536
    (status, entries), events = _work(LAUNCHER.sanitize_ownership, widest)
    assert status == "valid" and len(entries) == 32 and events["py:loads"] == 32
    assert LAUNCHER.sanitize_ownership(widest.rstrip(b"\n"))[0] == "valid"  # the last newline is optional
    assert LAUNCHER.sanitize_ownership(fixture_registry())[0] == "valid" and LAUNCHER.sanitize_ownership(b"") == ("valid", [])
    assert LAUNCHER.sanitize_ownership(b'{"a": 1}\n')[0] == "invalid" and LAUNCHER.sanitize_ownership("{}")[0] == "invalid"

    # read_ownership: a regular file of at most 64 KiB by size; nothing else is read past the bound.
    out = tmp_path / "out"
    out.mkdir()
    target = out / LAUNCHER.OWNERSHIP_FILE
    target.write_bytes(fixture_registry())
    reads = _Reads(monkeypatch)
    assert LAUNCHER.read_ownership(out) == fixture_registry() and reads.within(65536)
    target.write_bytes(b"x" * 65537)
    reads.clear()
    with pytest.raises(ValueError):
        LAUNCHER.read_ownership(out)
    assert reads.requests == []  # refused by its size: not one byte read
    target.unlink()
    os.mkfifo(target)
    with pytest.raises(ValueError):  # a FIFO without a writer: refused before any (blocking) read
        LAUNCHER.read_ownership(out)
    target.unlink()
    target.symlink_to(tmp_path / "elsewhere")
    with pytest.raises(OSError):
        LAUNCHER.read_ownership(out)
    target.unlink()
    assert LAUNCHER.read_ownership(out) is None and reads.requests == []


def test_diag_r3_parent_validation_bounds_cardinality_type_and_length_before_traversal(monkeypatch):
    def check(mutate):
        raw = LAUNCHER.empty_diagnostics(["collector_failed"])
        mutate(raw)
        return _work(LAUNCHER.sanitize_link_diagnostics, raw)

    invalid = ["diagnostics_invalid"]
    # The review's counterexample with a plain list: n copies of an allowed reason. Rejection work is
    # the same for every n (no traversal, set or sort of the oversized list).
    counts = []
    for n in (24, 128, 8192, 65536):
        clean, events = check(lambda raw, n=n: raw.update(incomplete_reasons=["collector_failed"] * n))
        # one sort only: the closed empty result's own one-element reason list
        assert clean["incomplete_reasons"] == invalid and events["c:sorted"] == 1 and events["py:<genexpr>"] < 64, n
        counts.append(sum(events.values()))
    assert len(set(counts)) == 1, counts
    # One over-long reason string and an over-long key or hex value: rejected by length, at a constant cost.
    counts = []
    for size in (32, 1 << 20):
        for mutate in (lambda raw: raw.update(incomplete_reasons=["c" * size]),
                       lambda raw: raw.update(host_namespace="a" * size),
                       lambda raw: raw["ownership"].update({"s" * size: 0}) or raw["ownership"].pop("status")):
            clean, events = check(mutate)
            assert clean["incomplete_reasons"] == invalid
            counts.append(sum(events.values()))
    assert counts[:3] == counts[3:], counts
    # A plain dict with many extra keys: refused by its key count (no key set is built).
    rows = []
    for extra in (16, 65536):
        raw = LAUNCHER.empty_diagnostics(["collector_failed"])
        raw["ownership"] = {**raw["ownership"], **{f"k{i}": 0 for i in range(extra)}}
        (clean, events), peak = _peak(lambda raw=raw: _work(LAUNCHER.sanitize_link_diagnostics, raw))
        assert clean["incomplete_reasons"] == invalid
        rows.append((sum(events.values()), peak))
    assert rows[0][0] == rows[1][0] and rows[1][1] < 16384, rows
    # Only a JSON list is a list: an empty tuple is not an empty capture list.
    for name in ("captures", "pairs"):
        assert check(lambda raw, name=name: raw.update({name: ()}))[0]["incomplete_reasons"] == invalid, name
    # Oversized lists are refused by length before any item is visited.
    for path, value in ((("captures",), [{}] * 4), (("pairs",), [{}] * 3)):
        clean, events = check(lambda raw, path=path, value=value: raw.update({path[0]: value}))
        assert clean["incomplete_reasons"] == invalid and events["py:_spec_ok"] < 32, path
    # Only the exact JSON types are accepted (a subclass could misreport its length or items).
    class Lying(list):
        def __len__(self):
            return 1

    for value in (Lying(["collector_failed"] * 4), ("collector_failed",)):
        assert check(lambda raw, value=value: raw.update(incomplete_reasons=value))[0]["incomplete_reasons"] == invalid
    assert check(lambda raw: raw.update(schema=type("S", (str,), {})(LAUNCHER.DIAG_SCHEMA)))[0]["incomplete_reasons"] == invalid
    # Positives at every bound: the full reason set (23 distinct), and a widest whole payload.
    clean, _events = check(lambda raw: raw.update(incomplete_reasons=sorted(LAUNCHER.DIAG_REASONS)))
    assert clean["incomplete_reasons"] == sorted(LAUNCHER.DIAG_REASONS)
    widest = _max_diagnostics()
    clean = LAUNCHER.sanitize_link_diagnostics(json.loads(json.dumps(widest)))
    assert clean["incomplete_reasons"] == sorted(LAUNCHER.DIAG_REASONS) and len(clean["captures"]) == 3  # accepted, not emptied
    assert [len(pair["changes"]) for pair in clean["pairs"]] in ([32, 32], [0, 0])  # kept, or stripped by the payload cap
    assert len(json.dumps({"link_diagnostics": widest}).encode()) < LAUNCHER.DIAG_LIMITS["cleanup_bytes"]
    for duplicate in (["collector_failed", "collector_failed"], ["line_cap", "collector_failed"]):  # unique and sorted still
        assert check(lambda raw, duplicate=duplicate: raw.update(incomplete_reasons=duplicate))[0]["incomplete_reasons"] == invalid
    # End to end at the bounds: 64 links in each of 3 captures and 32 widest registry endpoints go
    # through the real collector and the parent's check complete and usable.
    text = _text(*(_endpoint(i + 2, f"v{i}", f"02:00:00:00:00:{i:02x}", i + 100) for i in range(64)))
    collector = _drive([text] * 3)
    for phase in collector.phases:
        collector.phases, keep = [phase], collector.phases
        collector.enrich()
        collector.phases = keep
    registry = b"".join(_max_registry_line(n, side) for n in range(1, 17) for side in ("l", "r"))
    clean = LAUNCHER.sanitize_link_diagnostics(json.loads(json.dumps(collector.result(registry))))
    assert [(c["lines_scanned"], c["scan"], c["parse"], len(c["links"]))
            for c in clean["captures"]] == [(64, "complete", "complete", 64)] * 3
    assert clean["ownership"]["status"] == "valid" and clean["ownership"]["endpoints"] == 32
    assert "diagnostics_invalid" not in clean["incomplete_reasons"] and "ownership_cap" not in clean["incomplete_reasons"]


def test_diag_r3_parent_cleanup_file_is_byte_bounded_before_decode_and_fails_closed(monkeypatch, tmp_path):
    path = tmp_path / "cleanup.raw.json"
    assert LAUNCHER.load_cleanup(path) == ({}, False)
    widest = {"namespace_child_exit": 0, "host_fingerprints_unchanged": True, "differing_fingerprints": [],
              "unstable_fingerprints": [], "kernel_modules_loaded": ["m" * 56] * 64, "link_diagnostics": _max_diagnostics()}
    path.write_text(json.dumps(widest), encoding="utf-8")  # exactly as the child's finish() writes it
    reads = _Reads(monkeypatch)
    assert LAUNCHER.load_cleanup(path) == (widest, False) and reads.within(LAUNCHER.DIAG_LIMITS["cleanup_bytes"])
    # Over the bound: refused by its size, before any read, decode or JSON parse.
    path.write_text(json.dumps({"host_fingerprints_unchanged": True, "pad": "x" * (4 << 20)}), encoding="utf-8")
    reads.clear()
    (result, events), peak = _peak(lambda: _work(LAUNCHER.load_cleanup, path))
    assert result == ({}, True) and reads.requests == [] and events["py:loads"] == 0 and peak < 16384
    monkeypatch.undo()
    for make in (lambda: os.mkfifo(path), lambda: path.symlink_to(tmp_path / "other"), lambda: path.mkdir()):
        if path.is_dir() and not path.is_symlink():
            path.rmdir()
        elif path.exists() or path.is_symlink():
            path.unlink()
        make()
        assert LAUNCHER.load_cleanup(path) == ({}, True)
    # The closed outcome: invalid diagnostics, and with no cleanup fields the gate itself fails closed.
    records = [{"case": case, "verdict": "pass", "control": item[1], "ints": {}, "tokens": {}}
               for case, item in LAUNCHER.RECORD_CASES.items()]
    junit = LAUNCHER.summarize_junit(_junit(tmp_path))
    inner = {"pytest_exit": 0, "leftover_processes": 0, "import_smoke": "ok"}
    assert LAUNCHER.evaluate(junit, records, 0, {}, inner, 0)["result"] == "FAIL"
    assert LAUNCHER.diagnostic_result("PASS", LAUNCHER.empty_diagnostics(["diagnostics_invalid"])) == (
        "FAIL", "link_diagnostics_incomplete")


def test_diag_r3_ancillary_listing_is_bounded_before_traversal(monkeypatch):
    def kinds(document):
        return _work(LAUNCHER.link_kinds, 0, run=lambda *a, **k: ("ok", json.dumps(document).encode()))

    exact = [{"ifindex": i, "ifname": f"l{i}"} for i in range(64)]
    (status, found), _events = kinds(exact)
    assert status == "ok" and len(found) == 64  # the positive bound
    for extra in (65, 4096):
        (status, found), events = kinds([{"ifindex": i, "ifname": "x"} for i in range(extra)])
        assert (status, found) == ("cap", {}) and events["c:get"] == 0, extra
    assert kinds([{"ifindex": 1, "ifname": "n" * 65}])[0] == ("invalid", {})
    # The runner never asks for more than limit + 1 bytes in all.
    reads = _Reads(monkeypatch)
    soon = time.monotonic_ns() + 20 * 10 ** 9
    assert LAUNCHER.bounded_command((sys.executable, "-c", "print('x' * 70000)"), soon, limit=4097)[0] == "cap"
    assert reads.within(4097)


def test_diag_r3_sysfs_mount_contract_parsers_and_platform_gate(monkeypatch, tmp_path):
    device = os.makedev(0, 22)
    line = b"23 1 0:22 / /sys rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw"
    other = b"24 1 0:5 / /dev rw,nosuid - devtmpfs udev rw,size=8g"
    assert LAUNCHER.sysfs_mount_supported(other + b"\n" + line + b"\n", 23, device, "/sys")
    assert LAUNCHER.sysfs_mount_supported(b"23 1 0:22 / /sys rw - sysfs sysfs rw\n", 23, device, "/sys")  # no optional fields
    for data, mount_id, dev, root in (
            (line.replace(b"- sysfs", b"- tmpfs"), 23, device, "/sys"),            # another filesystem type
            (line.replace(b" / /sys", b" /class /sys"), 23, device, "/sys"),      # a bind of a subdirectory
            (line.replace(b"/sys rw", b"/host/sys rw"), 23, device, "/sys"),      # another mount point
            (line, 23, os.makedev(0, 23), "/sys"),                                 # another device
            (line, 24, device, "/sys"), (line + b"\n" + line, 23, device, "/sys"),  # absent; duplicated
            (b"23 1 0:22 / /sys rw shared:7 sysfs sysfs rw", 23, device, "/sys"),  # no separator
            (b"23 1 0:22 / /sys", 23, device, "/sys"), (b"x " + line, 23, device, "/sys"), (b"", 23, device, "/sys")):
        assert not LAUNCHER.sysfs_mount_supported(data, mount_id, dev, root), data
    assert LAUNCHER.fdinfo_mount_id(b"pos:\t0\nflags:\t02104000\nmnt_id:\t23\nino:\t1\n") == 23
    for data in (b"pos:\t0\n", b"mnt_id:\t23\nmnt_id:\t23\n", b"mnt_id:\tx\n", b"mnt_id:\t" + b"9" * 11 + b"\n"):
        assert LAUNCHER.fdinfo_mount_id(data) is None, data

    # Non-Linux: no /proc is touched and the contract is unsupported.
    def no_proc(*_args):
        raise AssertionError("proc read off Linux")

    monkeypatch.setattr(LAUNCHER, "_proc_read", no_proc)
    monkeypatch.setattr(LAUNCHER, "sys", types.SimpleNamespace(platform="darwin"))
    assert LAUNCHER.SYSFS_MOUNT.descriptor(0) is None and LAUNCHER.SYSFS_MOUNT.supported(23, device, "/sys") is False
    # Linux (modelled /proc text): exactly the two fixed paths, each with its own byte bound.
    asked = []

    def proc(path, limit):
        asked.append((path, limit))
        return {"/proc/self/fdinfo/5": b"pos:\t0\nmnt_id:\t23\n", "/proc/self/mountinfo": other + b"\n" + line + b"\n"}.get(path)

    monkeypatch.setattr(LAUNCHER, "_proc_read", proc)
    monkeypatch.setattr(LAUNCHER, "sys", types.SimpleNamespace(platform="linux"))
    assert LAUNCHER.SYSFS_MOUNT.descriptor(5) == 23 and LAUNCHER.SYSFS_MOUNT.supported(23, device, "/sys")
    assert LAUNCHER.SYSFS_MOUNT.descriptor(6) is None and not LAUNCHER.SYSFS_MOUNT.supported(23, device, "/host/sys")
    assert asked[:2] == [("/proc/self/fdinfo/5", 1024), ("/proc/self/mountinfo", 65536)]
    monkeypatch.undo()

    # The bounded /proc reader itself, on a plain file: over the limit is None, never a longer read.
    sample = tmp_path / "text"
    sample.write_bytes(b"a" * 5000)
    reads = _Reads(monkeypatch)
    assert LAUNCHER._proc_read(str(sample), 4999) is None and reads.within(4999)
    reads.clear()
    assert LAUNCHER._proc_read(str(sample), 5000) == b"a" * 5000 and reads.within(5000)
    monkeypatch.undo()
    # The default contract never accepts a fake tree as sysfs (any platform: off Linux it is
    # unsupported outright; on Linux the tree is not a sysfs mount root at that path).
    root, _dir = _real_sysfs(tmp_path, "veth0", 4)
    far = time.monotonic_ns() + 10 ** 10
    assert LAUNCHER.link_metadata("veth0", 4, far, root=str(root))["status"] == "unknown"
    assert _meta("veth0", 4, far, root=root)["status"] == "ok"  # the same tree under the synthetic model


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the real fdinfo/mountinfo contract exists on Linux only")
def test_diag_r3_sysfs_mount_contract_refuses_a_real_non_sysfs_directory_on_linux(tmp_path):
    descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        mount_id = LAUNCHER.SYSFS_MOUNT.descriptor(descriptor)
        assert type(mount_id) is int
        assert not LAUNCHER.SYSFS_MOUNT.supported(mount_id, os.fstat(descriptor).st_dev, os.path.realpath(tmp_path))
    finally:
        os.close(descriptor)


def test_diag_r3_sysfs_ok_requires_every_descriptor_on_the_verified_mount(monkeypatch, tmp_path):
    far = time.monotonic_ns() + 10 ** 10
    unknown = {"device_backed": "unknown", "bus": "unknown", "driver": "unknown", "status": "unknown"}

    def scratch(label: str) -> Path:
        path = tmp_path / label
        path.mkdir()
        return path

    base = scratch("positive")
    root, veth = _real_sysfs(base, "veth0", 4)
    _sysfs_pci = _real_sysfs(base, "eth1", 3, bus="pci", driver="mlx5_core")[1]
    _real_sysfs(base, "eth2", 5, bus="vmbus", driver="hv_netvsc", slot="vmbus-0")
    positives = {"veth0": (4, ("no", "none", "none")), "eth1": (3, ("yes", "pci", "mlx5_core")),
                 "eth2": (5, ("yes", "vmbus", "hv_netvsc"))}
    for name, (index, facts) in positives.items():
        assert _meta(name, index, far, root=root) == dict(zip(("device_backed", "bus", "driver"), facts), status="ok"), name
        assert _meta(name, index, far, root=root, over=[root / "kernel"])["status"] == "ok"  # an unrelated overmount
    # An overmount anywhere on the walked path (a directory, an endpoint, the attribute file) or an
    # unsupported mount leaves the answer unknown.
    pci = _sysfs_pci.parent.parent
    for over in ([root / "class" / "net"], [root / "devices" / "virtual"], [veth], [veth / "ifindex"]):
        assert _meta("veth0", 4, far, root=root, over=over) == unknown, over
    for over in ([pci], [root / "bus" / "pci"], [root / "bus" / "pci" / "drivers" / "mlx5_core"]):
        assert _meta("eth1", 3, far, root=root, over=over) == unknown, over
    assert _meta("veth0", 4, far, root=root, supported=False) == unknown
    # A mount change at any single descriptor check of the walk: unknown every time.
    model = _ModelMount(root)
    assert LAUNCHER.link_metadata("eth1", 3, far, root=str(root), mount=model)["status"] == "ok"
    total = model.calls
    assert total > 20
    # The last two checks are the re-opened root and the anchor: a root re-bound over itself (same
    # device and inode, another mount) is refused, not only a replaced root object.
    assert model.paths[-2:] == [model.root, model.root] and model.paths[0] == model.root
    for drift in range(total):
        assert _meta("eth1", 3, far, root=root, drift=drift) == unknown, drift

    # The review's move-out-and-restore: the opened link directory moved outside the root right before
    # each attribute read, then put back. The attribute's own descriptor is no longer on the verified
    # mount, so nothing is read and the answer is unknown.
    base = scratch("move")
    root, link_dir = _real_sysfs(base, "mock0", 7)
    outside, calls = base / "outside", []

    def read(descriptor, name, verify):
        link_dir.rename(outside)
        try:
            calls.append(LAUNCHER._sysfs_read(descriptor, name, verify))
            return calls[-1]
        finally:
            outside.rename(link_dir)

    assert _meta("mock0", 7, far, root=root, read=read) == unknown and calls == []
    assert _meta("mock0", 7, far, root=root)["status"] == "ok"  # unmoved, the same tree reads

    # No descriptor leaks on positive, unsupported, overmounted and missing paths.
    active, real = set(), os

    class _Count:
        def __getattr__(self, attribute):
            return getattr(real, attribute)

        def open(self, *args, **kwargs):
            descriptor = real.open(*args, **kwargs)
            active.add(descriptor)
            return descriptor

        def close(self, descriptor):
            active.discard(descriptor)
            return real.close(descriptor)

    monkeypatch.setattr(LAUNCHER, "os", _Count())
    for _ in range(5):
        assert _meta("mock0", 7, far, root=root)["status"] == "ok"
        assert _meta("mock0", 7, far, root=root, supported=False) == unknown
        assert _meta("mock0", 7, far, root=root, over=[link_dir]) == unknown
        assert _meta("absent", 7, far, root=root) == unknown
        assert not active

# ---------------------------------------------------------------------------------------------
# H2-LINK-DIAGNOSTICS-R4: the third review's F1 (the namespace init copied the registry with an
# unbounded read_bytes before the later 64-KiB reader) and its M10 evidence defect.

class _HandoffOs:
    """The launcher's ``os`` with every read request and returned byte count recorded, and an
    optional one-shot hook that changes the real scratch file just before the first read."""

    def __init__(self, monkeypatch, hook=None, short=None):
        self.requests, self.returned, self.hook, self.short, real = [], [], hook, short, os
        outer = self

        class _Proxy:
            def __getattr__(self, attribute):
                return getattr(real, attribute)

            def read(self, descriptor, size):
                if outer.hook is not None:
                    hook, outer.hook = outer.hook, None
                    hook()
                outer.requests.append(size)
                data = real.read(descriptor, size)
                if outer.short is not None:  # modeled: the read ends early although the file is unchanged
                    data, outer.short = data[:outer.short], 0
                outer.returned.append(len(data))
                return data

        monkeypatch.setattr(LAUNCHER, "os", _Proxy())


def _handoff(monkeypatch, tmp_path, make, hook=None, short=None):
    """Run the real ``handoff_ownership`` (with its real writer, R5's ``deliver_ownership``, into a scratch destination)
    on a registry made by ``make(path)``. Returns (outcome, destination bytes or None, reads, peak)."""
    for name in ("src", "dst"):
        if (tmp_path / name).exists():
            shutil.rmtree(tmp_path / name)
    source, destination = tmp_path / "src", tmp_path / "dst"
    source.mkdir()
    destination.mkdir()
    make(source / LAUNCHER.OWNERSHIP_FILE)
    reads = _HandoffOs(monkeypatch, hook, short)
    out_fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY)
    try:
        tracemalloc.start()
        outcome = LAUNCHER.handoff_ownership(source, out_fd, os.getuid())
        _current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
    finally:
        os.close(out_fd)
        monkeypatch.undo()
    target = destination / LAUNCHER.OWNERSHIP_FILE
    copied = target.read_bytes() if target.exists() else None
    return outcome, copied, reads, peak


def test_diag_r4_ownership_handoff_is_bounded_regular_no_follow_and_stable_before_any_copy(monkeypatch, tmp_path):
    limit = LAUNCHER.DIAG_LIMITS["ownership_bytes"]
    assert limit == 65536 and LAUNCHER.OWNERSHIP_REJECTED == b"\xff"
    assert LAUNCHER.sanitize_ownership(LAUNCHER.OWNERSHIP_REJECTED) == ("invalid", [])  # never "missing"
    # Positives: an ordinary registry and an exact 64-KiB file are copied byte for byte, read within
    # the bound (64 KiB + 1 requested in all, the sentinel byte returning nothing).
    for data in (fixture_registry(), b"x" * limit):
        outcome, copied, reads, _peak = _handoff(monkeypatch, tmp_path, lambda path, data=data: path.write_bytes(data))
        assert (outcome, copied) == ("copied", data) and sum(reads.returned) == len(data)
        assert max(reads.requests) <= limit + 1 and sum(reads.returned) <= limit + 1
    # Absent: nothing is written, exactly as before (the host then reports ownership_missing).
    outcome, copied, reads, _peak = _handoff(monkeypatch, tmp_path, lambda path: None)
    assert (outcome, copied, reads.requests) == ("absent", None, [])
    # Oversized (65 KiB, 256 KiB and the review's 2 MiB): refused by size before one byte is read, so
    # no allocation or copy grows with the file; the destination holds only the invalid marker.
    for size in (65 * 1024, 256 * 1024, 2 * 1024 * 1024):
        outcome, copied, reads, peak = _handoff(monkeypatch, tmp_path, lambda path, size=size: path.write_bytes(b"x" * size))
        assert (outcome, copied) == ("rejected", LAUNCHER.OWNERSHIP_REJECTED), size
        assert reads.requests == [] and peak < 16384, (size, peak)  # the review measured 2,103,151 peak bytes
    # A symlink to owned scratch data is not followed: nothing of the target is read or copied.
    target = tmp_path / "scratch-target"
    target.write_bytes(b"scratch-canary")
    outcome, copied, reads, _peak = _handoff(monkeypatch, tmp_path, lambda path: path.symlink_to(target))
    assert (outcome, copied, reads.requests) == ("rejected", LAUNCHER.OWNERSHIP_REJECTED, [])
    # Non-regular entries: a FIFO without a writer (O_NONBLOCK: never a blocking open or read) and a
    # directory are refused before any read.
    for make in (os.mkfifo, os.mkdir):
        outcome, copied, reads, _peak = _handoff(monkeypatch, tmp_path, lambda path, make=make: make(path))
        assert (outcome, copied, reads.requests) == ("rejected", LAUNCHER.OWNERSHIP_REJECTED, []), make

    # Changing inputs, made by really changing the scratch file between the size check and the read.
    def grow(path, by):
        def append():
            with path.open("ab") as handle:
                handle.write(b"y" * by)
        return append

    def shrink(path):
        return lambda: os.truncate(path, 7)

    def rewrite(path):
        def change():
            path.write_bytes(b"z" * 100)  # the same size, other bytes and a later modification time
            os.utime(path, ns=(10 ** 18, 10 ** 18))
        return change

    for name, size, hook in (("grows within the bound", 100, lambda path: grow(path, 50)),
                             ("grows past the bound", limit, lambda path: grow(path, 10)),
                             ("short read", 100, shrink), ("rewritten in place", 100, rewrite)):
        path = tmp_path / "src" / LAUNCHER.OWNERSHIP_FILE
        outcome, copied, reads, _peak = _handoff(monkeypatch, tmp_path, lambda p, size=size: p.write_bytes(b"x" * size),
                                                 hook=lambda hook=hook, path=path: hook(path)())
        assert (outcome, copied) == ("rejected", LAUNCHER.OWNERSHIP_REJECTED), name
        assert reads.requests and max(reads.requests) <= limit + 1 and sum(reads.returned) <= limit + 1, name

    # A short read of an unchanged file (modeled at the read call: the file's size and times stay the
    # same, so only the bytes-read == size check can refuse it).
    outcome, copied, reads, _peak = _handoff(monkeypatch, tmp_path, lambda p: p.write_bytes(b"x" * 100), short=7)
    assert (outcome, copied, sum(reads.returned)) == ("rejected", LAUNCHER.OWNERSHIP_REJECTED, 7)

    # The host side of the handoff: the same stable reader refuses the same changes, and the child
    # turns any refusal into the same invalid marker (ownership_invalid, never ownership_missing).
    out = tmp_path / "host"
    out.mkdir()
    (out / LAUNCHER.OWNERSHIP_FILE).write_bytes(b"x" * 100)
    _HandoffOs(monkeypatch, grow(out / LAUNCHER.OWNERSHIP_FILE, 50))
    with pytest.raises(ValueError):
        LAUNCHER.read_ownership(out)
    monkeypatch.undo()
    (out / LAUNCHER.OWNERSHIP_FILE).write_bytes(LAUNCHER.OWNERSHIP_REJECTED)
    assert LAUNCHER.read_ownership(out) == LAUNCHER.OWNERSHIP_REJECTED
    source = (ROOT / "scripts/host_h2_policy_proof.py").read_text(encoding="utf-8")
    child = source[source.index("def privileged_child("):source.index("def main(")]
    assert "ownership = OWNERSHIP_REJECTED  # unreadable" in child and child.index("_inside(") < child.index("read_ownership(out)")


def test_diag_r4_inside_copy_out_keeps_legacy_transfers_and_bounds_only_the_registry(monkeypatch, tmp_path):
    """The actual statements of ``_inside`` after the suite (the unchanged JUnit/records loop and the
    registry transfer), AST-extracted and run against scratch files: no namespace, mount or host path."""
    source = (ROOT / "scripts/host_h2_policy_proof.py").read_text(encoding="utf-8")
    inside = next(node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef) and node.name == "_inside")
    loop = next(index for index, node in enumerate(inside.body)
                if isinstance(node, ast.For) and "junit.xml" in ast.unparse(node.iter))
    statements = inside.body[loop:loop + 2]
    assert ast.unparse(statements[1]) == "handoff_ownership(out, out_fd, request['uid'])"
    assert isinstance(inside.body[loop + 2], ast.Return)
    code = compile(ast.Module(body=statements, type_ignores=[]), "_inside", "exec")
    out, destination = tmp_path / "out", tmp_path / "dst"
    out.mkdir()
    destination.mkdir()
    big = 2 * 1024 * 1024
    (out / "junit.xml").write_bytes(b"j" * big)  # the original transfer: unchanged, whole-file semantics
    (out / "records.raw.jsonl").write_bytes(b"r" * 300)
    (out / LAUNCHER.OWNERSHIP_FILE).write_bytes(b"o" * big)
    out_fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY)
    try:
        exec(code, dict(vars(LAUNCHER), out=out, out_fd=out_fd, request={"uid": os.getuid()}))  # noqa: S102
    finally:
        os.close(out_fd)
    assert (destination / "junit.xml").read_bytes() == b"j" * big
    assert (destination / "records.raw.jsonl").read_bytes() == b"r" * 300
    assert (destination / LAUNCHER.OWNERSHIP_FILE).read_bytes() == LAUNCHER.OWNERSHIP_REJECTED
    # Legacy files that are absent stay absent, as before; an ordinary registry is copied.
    shutil.rmtree(destination)
    destination.mkdir()
    for name in ("junit.xml", "records.raw.jsonl"):
        (out / name).unlink()
    (out / LAUNCHER.OWNERSHIP_FILE).write_bytes(fixture_registry())
    out_fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY)
    try:
        exec(code, dict(vars(LAUNCHER), out=out, out_fd=out_fd, request={"uid": os.getuid()}))  # noqa: S102
    finally:
        os.close(out_fd)
    assert sorted(path.name for path in destination.iterdir()) == [LAUNCHER.OWNERSHIP_FILE]
    assert (destination / LAUNCHER.OWNERSHIP_FILE).read_bytes() == fixture_registry()


def test_diag_r4_set_guard_refuses_list_subclasses_before_any_visit():
    """M10's distinguishing oracle: the set branch's exact ``type(value) is list`` refuses list
    subclasses (an ``isinstance`` relaxation accepts a plain one), and a subclass that misreports its
    length is refused before any item is visited."""
    spec = ("set", LAUNCHER.DIAG_REASONS)
    assert LAUNCHER._spec_ok(["collector_failed"], spec) is True  # the native JSON list is accepted

    class Plain(list):
        pass

    assert LAUNCHER._spec_ok(Plain(["collector_failed"]), spec) is False

    class Lying(list):
        visits = 0

        def __len__(self):
            return 1

        def __iter__(self):
            for item in super().__iter__():
                type(self).visits += 1
                yield item

    for n in (128, 8192):
        Lying.visits = 0
        assert LAUNCHER._spec_ok(Lying(["collector_failed"] * n), spec) is False and Lying.visits == 0, n
    raw = LAUNCHER.empty_diagnostics(["collector_failed"])
    raw["incomplete_reasons"] = Plain(["collector_failed"])
    assert LAUNCHER.sanitize_link_diagnostics(raw)["incomplete_reasons"] == ["diagnostics_invalid"]


# ---------------------------------------------------------------------------------------------
# H2-LINK-DIAGNOSTICS-R5: the fourth review's F1 (a real kernel short write of the registry was
# returned as ``copied`` and its valid one-record prefix accepted as complete diagnostics) and F2
# (the refusal marker's open blocked on a writerless FIFO at the destination name).

import contextlib  # noqa: E402
import errno  # noqa: E402
import resource  # noqa: E402
import signal  # noqa: E402
import stat  # noqa: E402

H1F_WRITE_OUT_SHA256 = "701d58e43d56b2b9d36b345960d2ac0f73a9c6b58bd70308b4fd39d6721c70be"  # unchanged since 2cf90e6


class _Blocked(Exception):
    pass


@contextlib.contextmanager
def _must_not_block(seconds=5):
    """A destination open or write that waits (for a FIFO reader, say) fails the test instead of
    hanging it: the alarm interrupts the blocked call with ``_Blocked``."""
    def fire(*_args):
        raise _Blocked("blocked")

    previous = signal.signal(signal.SIGALRM, fire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


@contextlib.contextmanager
def _file_size_limit(limit):
    """A real kernel short write: this process's soft RLIMIT_FSIZE, restored before anything else runs
    (Python ignores SIGXFSZ, so the write past the limit returns short, then EFBIG)."""
    previous = resource.getrlimit(resource.RLIMIT_FSIZE)
    resource.setrlimit(resource.RLIMIT_FSIZE, (limit, previous[1]))
    try:
        yield
    finally:
        resource.setrlimit(resource.RLIMIT_FSIZE, previous)


def _inside_transfer():
    """The actual post-suite statements of ``_inside`` (legacy loop + registry handoff), compiled."""
    source = (ROOT / "scripts/host_h2_policy_proof.py").read_text(encoding="utf-8")
    inside = next(node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef) and node.name == "_inside")
    loop = next(index for index, node in enumerate(inside.body)
                if isinstance(node, ast.For) and "junit.xml" in ast.unparse(node.iter))
    assert ast.unparse(inside.body[loop + 1]) == "handoff_ownership(out, out_fd, request['uid'])"
    return compile(ast.Module(body=inside.body[loop:loop + 2], type_ignores=[]), "_inside", "exec")


class _Transfer:
    """Owned scratch ``src`` (the namespace's out) and ``dst`` (the host's out, by descriptor)."""

    def __init__(self, tmp_path):
        self.base = tmp_path
        self.src, self.dst = tmp_path / "src", tmp_path / "dst"
        self.reset()

    def reset(self):
        for path in (self.src, self.dst):
            if path.exists():
                shutil.rmtree(path)
            path.mkdir()
        self.source, self.target = self.src / LAUNCHER.OWNERSHIP_FILE, self.dst / LAUNCHER.OWNERSHIP_FILE

    def run(self, call):
        out_fd = os.open(self.dst, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with _must_not_block():
                return call(out_fd)
        finally:
            os.close(out_fd)

    def handoff(self):
        return self.run(lambda out_fd: LAUNCHER.handoff_ownership(self.src, out_fd, os.getuid()))

    def inside(self, code):
        return self.run(lambda out_fd: exec(code, dict(vars(LAUNCHER), out=self.src, out_fd=out_fd,  # noqa: S102
                                                        request={"uid": os.getuid()})))

    def host(self):
        """The host child's read of the destination (refusal -> marker), the collector and the
        parent's sanitizer on an unchanged modeled host, and the diagnostic rule on a passing gate."""
        try:
            raw = LAUNCHER.read_ownership(self.dst)
        except (OSError, ValueError):
            raw = LAUNCHER.OWNERSHIP_REJECTED
        with pytest.MonkeyPatch.context() as patch:
            clean = _audit(patch, [(0, BASE)] * 3, registry=raw)["clean"]
        return raw, clean["ownership"]["status"], clean["complete"], LAUNCHER.diagnostic_result("PASS", clean)


_PASSING = ("PASS", None)
_HELD = ("FAIL", "link_diagnostics_incomplete")


def test_diag_r5_real_short_write_fails_the_transfer_and_never_publishes_the_prefix(tmp_path):
    payload = fixture_registry()
    one_record = len(payload.splitlines(keepends=True)[0])
    assert (len(payload), one_record) == (2420, 605)
    run = _Transfer(tmp_path)
    # The ordinary positive: all four records, a complete diagnostic that does not hold the PASS.
    run.source.write_bytes(payload)
    assert run.handoff() == "copied"
    raw, status, complete, result = run.host()
    assert (raw, status, complete, result) == (payload, "valid", True, _PASSING)
    # The fourth review's witness at H2_POLICY 12b73e5: the same limit gave ``copied`` and one valid
    # record accepted as complete with ("PASS", None). Now the kernel's short write is continued, the
    # next write fails (EFBIG), the created file is emptied and removed, and the error propagates.
    run.reset()
    run.source.write_bytes(payload)
    with pytest.raises(OSError) as raised, _file_size_limit(one_record):
        run.handoff()
    assert raised.value.errno == errno.EFBIG and resource.getrlimit(resource.RLIMIT_FSIZE)[0] != one_record
    assert not run.target.exists() and run.source.read_bytes() == payload
    raw, status, complete, result = run.host()
    assert (raw, status, complete, result) == (None, "missing", False, _HELD)
    # The same through the actual ``_inside`` statements: the exception leaves ``_inside`` (whose
    # caller exits 70, so the gate's child_exit is nonzero) and no registry prefix is left behind.
    run.reset()
    run.source.write_bytes(payload)
    with pytest.raises(OSError), _file_size_limit(one_record):
        run.inside(_inside_transfer())
    assert not run.target.exists() and run.host()[1:] == ("missing", False, _HELD)
    # A short write that the next write completes is a complete copy (a limit above the payload).
    run.reset()
    run.source.write_bytes(payload)
    with _file_size_limit(len(payload)):
        assert run.handoff() == "copied"
    assert run.host() == (payload, "valid", True, _PASSING)
    # The refusal marker (an oversized source, never read) through the actual statements.
    run.reset()
    run.source.write_bytes(b"private-canary-" * 6000)
    run.inside(_inside_transfer())
    assert run.host() == (LAUNCHER.OWNERSHIP_REJECTED, "invalid", False, _HELD)
    source = (ROOT / "scripts/host_h2_policy_proof.py").read_text(encoding="utf-8")
    handoff = source[source.index("def handoff_ownership("):source.index("def _inside(")]
    assert "_write_out" not in handoff and handoff.count("deliver_ownership(out_fd, registry, uid)") == 1


def test_diag_r5_destination_entries_are_refused_at_a_nonblocking_open_and_left_untouched(tmp_path):
    """F2: any existing entry at the destination name (a writerless FIFO, a symlink, a directory or a
    regular file) is refused by O_CREAT|O_EXCL before it is opened, followed, truncated or waited on,
    for the copy and for the refusal marker alike; the host then refuses the entry it finds."""
    run = _Transfer(tmp_path)
    canary = tmp_path / "canary"
    code = _inside_transfer()

    def fifo(path):
        os.mkfifo(path)

    def link(path):
        canary.write_bytes(b"private-canary")
        path.symlink_to(canary)

    def directory(path):
        path.mkdir()

    def regular(path):
        path.write_bytes(fixture_registry())

    for name, make in (("fifo", fifo), ("symlink", link), ("directory", directory), ("regular", regular)):
        for source in (fixture_registry(), b"x" * (65 * 1024)):  # a copy, then the refusal marker
            run.reset()
            run.source.write_bytes(source)
            make(run.target)
            before = os.lstat(run.target)
            with pytest.raises(FileExistsError):
                run.handoff()
            with pytest.raises(FileExistsError):
                run.inside(code)
            after = os.lstat(run.target)
            assert (after.st_ino, after.st_mode, after.st_size) == (before.st_ino, before.st_mode, before.st_size), name
            if name == "symlink":
                assert canary.read_bytes() == b"private-canary"
            raw, status, complete, result = run.host()
            if name == "regular":  # a preexisting file is the host's to judge; the transfer still failed
                assert raw == fixture_registry()
            else:
                assert (raw, status, complete, result) == (LAUNCHER.OWNERSHIP_REJECTED, "invalid", False, _HELD), name
    # The payload itself is bounded before any entry is created: empty, oversized or non-bytes.
    run.reset()
    for payload in (b"", b"x" * (LAUNCHER.DIAG_LIMITS["ownership_bytes"] + 1), bytearray(b"x"), "x"):
        with pytest.raises(ValueError):
            run.run(lambda out_fd, payload=payload: LAUNCHER.deliver_ownership(out_fd, payload, os.getuid()))
        assert not run.target.exists()
    assert run.run(lambda out_fd: LAUNCHER.deliver_ownership(out_fd, b"x" * 65536, os.getuid())) is None
    assert run.target.read_bytes() == b"x" * 65536 and stat.S_IMODE(os.lstat(run.target).st_mode) == 0o600


class _WriteOs:
    """The launcher's ``os`` with ``write`` replaced by ``plan(real, descriptor, data, call)``; every
    other call is the real one (so the files and descriptors are real scratch objects)."""

    def __init__(self, monkeypatch, plan):
        self.calls, real, outer = 0, os, self

        class _Proxy:
            def __getattr__(self, attribute):
                return getattr(real, attribute)

            def write(self, descriptor, data):
                outer.calls += 1
                return plan(real, descriptor, bytes(data), outer.calls)

        monkeypatch.setattr(LAUNCHER, "os", _Proxy())


class _HandlerRaised(BaseException):
    """What a signal handler raising out of an interrupted write looks like to the writer."""


def test_diag_r5_partial_zero_interrupted_and_failed_writes_are_complete_or_failed(tmp_path):
    payload = fixture_registry()
    run = _Transfer(tmp_path)

    def attempt(plan):
        run.reset()
        run.source.write_bytes(payload)
        with pytest.MonkeyPatch.context() as patch:
            writes = _WriteOs(patch, plan)
            try:
                return run.handoff(), writes.calls
            except BaseException as error:  # noqa: BLE001 - returned for the assertion
                return error, writes.calls

    # Partial writes are continued from the next unwritten byte until every byte is delivered.
    for step in (1, 7, 604, 605, 2419):
        outcome, calls = attempt(lambda real, fd, data, call, step=step: real.write(fd, data[:step]))
        assert outcome == "copied" and run.target.read_bytes() == payload, step
        assert calls == -(-len(payload) // step) and run.host()[1:] == ("valid", True, _PASSING), step

    def after_prefix(fault):
        """One real write of the first record, then ``fault`` (a count or an exception)."""
        def plan(real, fd, data, call):
            if call == 1:
                return real.write(fd, data[:605])
            if isinstance(fault, int):
                return fault
            raise fault
        return plan

    faults = {"zero": (0, ValueError), "negative": (-1, ValueError), "over-count": (10 ** 6, ValueError),
              "interrupted": (InterruptedError(errno.EINTR, "interrupted"), InterruptedError),
              "handler raised": (_HandlerRaised(), _HandlerRaised),
              "no space": (OSError(errno.ENOSPC, "no space"), OSError), "io error": (OSError(errno.EIO, "io"), OSError),
              "too large": (OSError(errno.EFBIG, "too large"), OSError)}
    for name, (fault, kind) in faults.items():
        outcome, calls = attempt(after_prefix(fault))
        assert isinstance(outcome, kind) and calls == 2, name
        assert not run.target.exists() and run.host() == (None, "missing", False, _HELD), name
    # A write that reports more than it wrote: the final size check refuses the short file.
    outcome, _calls = attempt(lambda real, fd, data, call: real.write(fd, data[:605]) and len(data))
    assert isinstance(outcome, ValueError) and not run.target.exists()
    # The count itself is checked, not only the final size: a write that delivers every remaining
    # byte but reports zero or more than was asked still fails (the size check alone would pass it).
    for name, reported in (("zero", lambda count, data: 0), ("over-count", lambda count, data: len(data) + 1)):
        outcome, calls = attempt(lambda real, fd, data, call, reported=reported:
                                 real.write(fd, data[:605]) if call == 1 else reported(real.write(fd, data), data))
        assert isinstance(outcome, ValueError) and calls == 2 and not run.target.exists(), name
    # A failure on the first write (nothing delivered) also fails, and nothing is left behind.
    def fail_first(real, fd, data, call):
        raise OSError(errno.EIO, "io")

    outcome, calls = attempt(fail_first)
    assert isinstance(outcome, OSError) and calls == 1 and not run.target.exists()

    # The cleanup removes only its own file: if the name was replaced during the transfer, that
    # entry is left as it is and the created file is emptied through its own descriptor.
    moved = tmp_path / "moved-away"

    def swap(real, fd, data, call):
        real.write(fd, data[:605])
        os.rename(run.target, moved)
        run.target.write_bytes(b"someone else's file")
        raise OSError(errno.EIO, "io")

    if moved.exists():
        moved.unlink()
    outcome, _calls = attempt(swap)
    assert isinstance(outcome, OSError)
    assert run.target.read_bytes() == b"someone else's file" and moved.read_bytes() == b""
    # Without this writer, H1F's shared helper is unchanged (one unchecked write, still used by the
    # legacy JUnit/records loop and inner.json), and the registry no longer goes through it.
    source = (ROOT / "scripts/host_lease_feasibility.py").read_text(encoding="utf-8")
    node = next(node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef) and node.name == "_write_out")
    assert hashlib.sha256(ast.get_source_segment(source, node).encode()).hexdigest() == H1F_WRITE_OUT_SHA256
