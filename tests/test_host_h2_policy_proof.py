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
    "tests/support/edge_tls_harness.py": "779d21299de454ccae41674f7f9f1afb3853007ad870c50a7de1718ee156378f",
    "scripts/host_lease_key_shape.py": "83edee96607a1fad33d5bb7f00a230650dffb5d36f2fe4f13eb34c3ae3e3a61c",
    "scripts/host_authority_proof.py": "af27f68e033cce033a9b48a77dc26a73dc6176829b575476ae904b43b69cb76c",
    "scripts/host_lease_feasibility.py": "62e8bbd346e7b196bdb2946924b93fa59b0b09bfb914997bebd65d76b21eeb51",
    # H2-LINK-DIAGNOSTICS-R1: H0's default-disabled capture observer (was a1b32cc4...). A shared-helper
    # change: H0/H1F regressions and a fresh H0 qualification are required; it is not H2-only.
    "scripts/host_ingress_proof.py": "76958e1896110155aea9802996f00408c097a2a238b8c73ede138eafbccd4aa4",
    # Dependency refresh: only the cryptography wheel record changes in this lock.
    "deploy/host/ingress/runtime-lock.json": "c0ff9e8db82224715640881474e3fac89abe836ef2840409d100c262b2866ce1",
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
    assert len(LAUNCHER.HEEL_TREE_FILES) == 110 and LAUNCHER.staged_files() == LAUNCHER.HEEL_TREE_FILES + DESIGN_STAGE_FILES
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
    """C4 P01 moved the commercial codec under heel/saas: the closure is 110 heel + 14 stage files. An
    owned git fixture (an exact staged copy, committed) shows the launcher's own provenance check refuses
    a missing or an unexpected tracked heel member, and that one byte of the new member moves the digest."""
    tree = LAUNCHER.HEEL_TREE_FILES
    assert tree.count(PRIVATE_CODEC) == 1 and "heel/managed_authority_contracts.py" not in tree
    index = tree.index(PRIVATE_CODEC)
    assert tree[index - 1:index + 2] == ("heel/saas/ledger.py", PRIVATE_CODEC, "heel/saas/migrate.py")
    assert len(tree) + len(LAUNCHER.STAGE_FILES) == 124 == len(set(LAUNCHER.staged_files()))
    fixture = LAUNCHER.stage_tree(tmp_path / "fixture")
    _git(fixture, "init", "-q")
    _git(fixture, "add", "--", ".")
    _git(fixture, "commit", "-q", "-m", "exact staged closure")
    monkeypatch.setattr(LAUNCHER, "ROOT", fixture)
    exact = LAUNCHER.candidate_provenance()
    assert exact["heel_tree_file_count"] == 110 and exact["proof_file_count"] == 14
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
    assert changed["heel_tree_file_count"] == 110
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


def test_accepted_h2_1_inputs_and_refreshed_dependency_lock_match_recorded_hashes():
    for name, digest in UNCHANGED_SHA256.items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest, name
    assert PROOF.H2_SOURCE_SHA256 == UNCHANGED_SHA256["deploy/host/h2_policy.py"]
    assert PROOF.HARNESS_SHA256 == UNCHANGED_SHA256["tests/support/edge_tls_harness.py"]


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
import types

H0 = LAUNCHER.h0()
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
        entries = [LAUNCHER.parse_link_line(line) for line in self.current.splitlines()]
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


def test_diag_proof_endpoint_leak_is_matched_only_with_corroborated_ownership(monkeypatch, tmp_path):
    leak = _endpoint(9, "hp3l", "02:48:32:00:03:0a", 10)
    matched = _audit(monkeypatch, [(0, BASE), (0, BASE), (0, _text(LO, ETH0, leak))],
                     devices={"hp3l": ("yes", "pci", "mlx5_core")})  # hardware-like metadata does not outrank identity
    pair = _pair(matched)
    assert matched["differing"] == ["links"] and _gate(tmp_path, False) == "FAIL"
    assert pair["changes"][0]["proof_identity"] == "proof_identity_match" and pair["classes"] == ["proof_identity_match"]
    assert matched["clean"]["ownership"] == {"status": "valid", "endpoints": 4, "matched": 1, "ambiguous": 0,
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
    assert [(c["change"], c["proof_identity"]) for c in _pair(lifecycle)["changes"]] == [("changed", "unknown")]


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
    assert capture["line_count"] == 72 and len(capture["lines"]) == len(capture["links"]) == 64
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
    assert LAUNCHER.link_metadata("veth0", 4, far, root=str(root)) == {"device_backed": "no", "bus": "none", "driver": "none",
                                                                      "status": "ok"}
    _sysfs(tmp_path, "eth1", 3, bus="pci", driver="mlx5_core")
    assert LAUNCHER.link_metadata("eth1", 3, far, root=str(root)) == {"device_backed": "yes", "bus": "pci",
                                                                     "driver": "mlx5_core", "status": "ok"}
    _sysfs(tmp_path, "eth2", 5, bus="pci", driver="vendor_secret_drv")
    assert LAUNCHER.link_metadata("eth2", 5, far, root=str(root))["driver"] == "unknown"
    unknown = {"device_backed": "unknown", "bus": "unknown", "driver": "unknown", "status": "unknown"}
    assert LAUNCHER.link_metadata("eth1", 4, far, root=str(root)) == unknown  # another link now holds the name
    reads = iter(["3", "9"])
    assert LAUNCHER.link_metadata("eth1", 3, far, root=str(root), read=lambda _path: next(reads)) == unknown  # race
    assert LAUNCHER.link_metadata("eth1", 3, 0, root=str(root)) == unknown  # past the deadline
    assert LAUNCHER.link_metadata("gone0", 3, far, root=str(root)) == unknown  # disappeared
    outside = tmp_path / "elsewhere" / "net" / "esc0"
    outside.mkdir(parents=True)
    (outside / "ifindex").write_text("6\n")
    os.symlink(outside, root / "class" / "net" / "esc0")
    assert LAUNCHER.link_metadata("esc0", 6, far, root=str(root)) == unknown  # a symlink out of the devices tree
    for name in ("../x", "a/b", "", ".", "x" * 16, "eé0"):
        assert LAUNCHER.link_metadata(name, 1, far, root=str(root)) == unknown, name
    (root / "class" / "net" / "big0").symlink_to(root / "devices" / "virtual" / "net" / "veth0")
    with pytest.raises(ValueError):
        big = tmp_path / "big"
        big.write_text("1" * 65)
        LAUNCHER._sysfs_read(str(big))


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
    assert sorted(set(re.findall(r"os\.O_[A-Z]+", section))) == ["os.O_CLOEXEC", "os.O_NOFOLLOW", "os.O_NONBLOCK", "os.O_RDONLY"]
    for forbidden in ("modprobe", "insmod", "ethtool", "dmesg", "socket", "urllib", "write", "unlink", "rename", "chmod",
                      "setns", "unshare", "sysctl", "/proc/sys", '"w"', "netns exec", "link set", "link add", "link del"):
        assert forbidden not in section, forbidden
    assert not re.search(r"(?<![.\w])open\(", section) and section.count("os.open(") == 2


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
    assert 'for name in ("junit.xml", "records.raw.jsonl", OWNERSHIP_FILE):' in inside
    assert 'DIAG_KEY_ENV: request["diagnostic_key"]' in inside
    parent = source[source.index("def parent("):source.index("# Privileged child:")]
    assert '"link_diagnostics": sanitize_link_diagnostics(raw_cleanup.get("link_diagnostics"))' in parent
    assert 'result, hold = diagnostic_result(verdict["result"], cleanup["link_diagnostics"])' in parent
    assert 'exit_code = 0 if result == "PASS" else 1' in parent and "secrets.token_hex(32)" in parent
    # The registry is written only by Fixture._register, beside the records, from a read-only listing.
    module = LINUX_MODULE_FILE.read_text(encoding="utf-8")
    register = module[module.index("    def _register("):module.index("    def _baseline(")]
    assert '_run_in(fd, [AUTHORITY.IP_PATH, "-o", "link", "show", "dev", name])' in register
    assert "with_name(LAUNCHER.OWNERSHIP_FILE)" in register and module.count("LAUNCHER.OWNERSHIP_FILE") == 1
    assert module.count("self._register(") == 1 and not re.search(r"(?<![_\w])record\(", register)
    wire = module[module.index("    def _wire("):module.index("    def _register(")]
    assert wire.index("self._create_veth(a, mac_l, b, mac_r)") < wire.index("self._register(") < wire.index("steps = [")
