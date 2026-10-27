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
    "deploy/host/h2_policy.py": "0bd7d171fdb69e10d58d4422ef45ee16e57ad7319e77b90e518a70a2a38f0a8a",
    "docs/saas/H2_POLICY_INSTALLATION.md": "7808c5a6c5bab429c562dfe29f6e9dd3732cf16f9ce383bee83bf72c7b70bf29",
    "deploy/host/authority.py": "4c9a1fc6078060c1fcea0a858be601c34a558517a25a7134ec8042134e6967a5",
    "deploy/host/profile.py": "e697da2bf90a5e5e3bdf80aac2c18c9a8ab53f9018a35f977de1c857915dab83",
    "deploy/host/cycle.py": "a991548afa98a3423e360eff634ae7251c2f31b2dffe1778c727616bf6ca0e64",
    "tests/support/edge_tls_harness.py": "779d21299de454ccae41674f7f9f1afb3853007ad870c50a7de1718ee156378f",
    "scripts/host_lease_key_shape.py": "83edee96607a1fad33d5bb7f00a230650dffb5d36f2fe4f13eb34c3ae3e3a61c",
    "scripts/host_authority_proof.py": "af27f68e033cce033a9b48a77dc26a73dc6176829b575476ae904b43b69cb76c",
    "scripts/host_lease_feasibility.py": "62e8bbd346e7b196bdb2946924b93fa59b0b09bfb914997bebd65d76b21eeb51",
    "scripts/host_ingress_proof.py": "a1b32cc45d6395e1ee6d25014b05c5ccd2dbbfbfdadd658d7f38d27404a6f3a3",
    "deploy/host/ingress/runtime-lock.json": "6e26fa6646a66db24d171d10d263c5b43ac0724646f11684b94f2baf57db50ae",
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
    assert len(LAUNCHER.HEEL_TREE_FILES) == 109 and LAUNCHER.staged_files() == LAUNCHER.HEEL_TREE_FILES + DESIGN_STAGE_FILES
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


def test_wheel_closure_is_the_eight_h0_locked_wheels_and_a_changed_lock_fails():
    lock = json.loads(H0_LOCK.read_text(encoding="utf-8"))
    LAUNCHER.closure_matches_lock(lock)
    assert LAUNCHER.PYTEST_CLOSURE is LAUNCHER.h1f().PYTEST_CLOSURE
    assert [name for name, *_rest in LAUNCHER.PYTEST_CLOSURE] == ["iniconfig", "packaging", "pluggy", "pygments", "pytest"]
    assert [(name, version) for name, version, *_rest in LAUNCHER.CLIENT_CLOSURE] == [
        ("cryptography", "45.0.7"), ("cffi", "2.1.1"), ("pycparser", "3.11")]
    closure = LAUNCHER.wheel_closure(lock)
    by_file = {wheel["file"]: wheel for wheel in lock["python"]["wheels"]}
    assert len(closure) == 8 and all(by_file[file]["url"] == url and by_file[file]["sha256"] == digest
                                     for file, url, digest in closure)
    # No new dependency: cryptography 45.0.7 is the package's one declared runner dependency.
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert "cryptography==45.0.7" in project["optional-dependencies"]["runner"]
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


UNCHANGED_SHA256_WORKFLOW_BASE = "02d44aaca33da7c3a09ee4cd3fcc085c37ce8d7f2e1e8637cd0b6c75cd6db8fc"


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


def test_accepted_h2_1_source_old_launchers_lock_and_harness_are_unchanged():
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
        "platform_forced": source + "\nH2._PLATFORM_OK = True\n",
        "nft_redirected": source + "\nH2.NFT_PATH = '/bin/true'\n",
        "helper_replaced": source + "\nH2._HELPER_SOURCE = H2._HELPER_SOURCE.replace('setns', 'getpid')\n",
        "helper_deleted": source + "\ndel H2._HELPER_SOURCE\n",
        "authority_patched": source + "\nAUTHORITY.NFT_PATH = None\n",
        "setattr_used": source + "\nsetattr(H2, 'NFT_PATH', '/bin/true')\n",
        "monkeypatch_used": source + "\ndef _x(monkeypatch):\n    monkeypatch.undo()\n",
        "fake_nft": source + "\ndef fake_nft_script():\n    return None\n",
        "private_render": source + "\ndef _x():\n    return H2._receipt_document(None)\n",
        "client_socket_seam": _replace(source, "resolver=resolver,\n", "resolver=resolver, sockets=None,\n"),
        "client_clock_seam": _replace(source, "timeout_seconds=3.0)", "timeout_seconds=3.0, clock=time.monotonic)"),
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
