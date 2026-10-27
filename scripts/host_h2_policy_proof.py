#!/usr/bin/env python3
"""Fixed ``h2-policy-v1`` generation-policy proof launcher (H2-2).

SPDX-License-Identifier: LicenseRef-Heel-Commercial

Run from the repository root as exactly ``python scripts/host_h2_policy_proof.py``: one fixed
profile, no command, path, ref or test-selector inputs. The structure is H2K1's
(``scripts/host_lease_key_shape.py``); the reviewed helpers and the H0-locked pytest closure come from
H1F (``scripts/host_lease_feasibility.py``) and H0 by path and are never copied, and the
supported-kernel pin and ``kernel_profile`` come from the production ``deploy/host/profile.py``, also
by path. The unprivileged parent refuses any ref but the literal reviewed proof branch, verifies the
clean candidate checkout (``HEEL_TREE_FILES`` must equal ``git ls-files heel``) and the pinned Python,
confirms the host tools are already present, lints the workflow with H0's pinned actionlint and
fetches the eight H0-locked wheels (the pytest closure plus cryptography/cffi/pycparser for the
unchanged client and the TLS harness). One fixed privileged child (``sudo -n``) takes stable host
fingerprints, creates an outer network+mount+PID namespace with only loopback and a private tmpfs,
stages exactly ``HEEL_TREE_FILES`` + ``STAGE_FILES``, installs the closure offline, runs the isolated
import smoke (only the staged root and the closed venv on ``sys.path``) and then
``HEEL_REQUIRE_HOST_H2_POLICY_PROOF=1 python -m pytest -q tests/linux/test_host_h2_policy.py``.

Exit 0 only for PASS: every case ran (no skip), every record holds, cleanup left the host
fingerprints unchanged and the kernel is inside the pinned profile; a clean run on an unsupported
profile is INCOMPLETE. The question: does the real H2-1 ``install`` (real helper, real ``setns``,
real nft) write a table whose real readback the product accepts, and does that table together with
the real H1 ``prepare``/``activate`` let only the pinned IPv4 targets on TCP 443 through, for the
unchanged ``TargetHTTPSClient`` as well? It is an isolated L3/L4 + unchanged-client proof only: not
H3 composition, H6 host qualification, managed deployment, customer admission or launch.
"""
from __future__ import annotations

import datetime
import hashlib
import importlib.util
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ElementTree
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
H1F_LAUNCHER = ROOT / "scripts" / "host_lease_feasibility.py"
H0_LOCK = ROOT / "deploy" / "host" / "ingress" / "runtime-lock.json"
PROFILE = "h2-policy-v1"
REVIEWED_REF = "refs/heads/codex/self-serve-host-h2-policy-proof"
TEST_MODULE = "tests/linux/test_host_h2_policy.py"
ARTIFACT_DIR = ROOT / "host-h2-policy-proof"
ARTIFACT_FILES = ("summary.json", "cases.jsonl", "versions.txt", "cleanup.json", "report.txt")
CHILD_SCHEMA = "heel.host-h2-policy-proof.child.v1"
SCRATCH_PREFIX = "heel-host-h2-policy-"
REQUIRED_ENV = "HEEL_REQUIRE_HOST_H2_POLICY_PROOF"
RECORDS_ENV = "HEEL_HOST_H2_POLICY_RECORDS"
WORK_ENV = "HEEL_HOST_H2_POLICY_WORK"
TOKEN_ENV = "HEEL_HOST_H2_POLICY_TOKEN"
RUNTIME_ASSUMPTION = "running-kernel"
# The fixed tracked files the privileged child copies (byte for byte) into the namespace and hashes
# into summary.json, in addition to the whole tracked heel/ tree: the H1 domain and profile, the H2-1
# installer, this unit's files, the unchanged TLS harness, the H1F/H0 launchers and lock it imports
# and the H2 docs. A static test proves it covers every path the proof module and this launcher read.
STAGE_FILES = (
    "deploy/host/authority.py", "deploy/host/profile.py", "deploy/host/h2_policy.py", "tests/linux/__init__.py",
    "tests/linux/test_host_h2_policy.py", "tests/support/edge_tls_harness.py", "scripts/host_h2_policy_proof.py",
    "scripts/host_lease_key_shape.py", "scripts/host_lease_feasibility.py", "scripts/host_ingress_proof.py",
    "deploy/host/ingress/runtime-lock.json", ".github/workflows/codeql.yml", "docs/saas/H2_POLICY_PROOF.md",
    "docs/saas/H2_POLICY_INSTALLATION.md",
)
# Exactly ``git ls-files heel`` at the candidate (a static test and candidate_provenance compare it).
HEEL_TREE_FILES = (
    "heel/__init__.py", "heel/agents.py", "heel/agents_human.py", "heel/backtest.py", "heel/bench.py",
    "heel/blind.py", "heel/blind_eval.py", "heel/browser_review.py", "heel/business_rules.py",
    "heel/canary_contracts.py", "heel/chaining.py", "heel/classify.py", "heel/cli.py", "heel/cloud_auth.py",
    "heel/cloud_client.py", "heel/containment.py", "heel/contracts.py", "heel/control.py",
    "heel/control_simulator.py", "heel/crypto.py", "heel/economics.py", "heel/entitlements.py",
    "heel/findings_sync.py", "heel/heldout/targets.json", "heel/heldout/test_targets.json", "heel/heldout_eval.py",
    "heel/importers.py", "heel/incident.py", "heel/launch_review.py", "heel/local_projects.py", "heel/mcp_server.py",
    "heel/model.py", "heel/modes.py", "heel/openapi_import.py", "heel/openapi_model.py", "heel/orchestrator.py",
    "heel/product_model.py", "heel/profiles.py", "heel/reference_product.py", "heel/reference_rehearsal.py",
    "heel/regressions.py", "heel/rest.py", "heel/review_answers.py", "heel/review_contract.py",
    "heel/review_export.py", "heel/review_rules.py", "heel/review_service.py", "heel/runner/__init__.py",
    "heel/runner/adapters.py", "heel/runner/catalog.py", "heel/runner/companion.py", "heel/runner/compiler.py",
    "heel/runner/containment.py", "heel/runner/content_assertion.py", "heel/runner/control_client.py",
    "heel/runner/control_transport.py", "heel/runner/coordinator.py", "heel/runner/daemon.py",
    "heel/runner/execution.py", "heel/runner/http_transport.py", "heel/runner/identity.py",
    "heel/runner/openapi_routes.py", "heel/runner/plan_differential.py", "heel/runner/redaction.py",
    "heel/runner/runtime.py", "heel/runner/service.py", "heel/runner/store.py", "heel/runner/vault.py",
    "heel/saas/__init__.py", "heel/saas/auth.py", "heel/saas/billing.py", "heel/saas/canary_disclosure.py",
    "heel/saas/canary_reaper.py", "heel/saas/canary_runs.py", "heel/saas/canary_store.py", "heel/saas/catalog.py",
    "heel/saas/dashboard.py", "heel/saas/device_auth.py", "heel/saas/egress.py", "heel/saas/entitlement.py",
    "heel/saas/findings_sync.py", "heel/saas/host_authority.py", "heel/saas/host_snapshot.py",
    "heel/saas/http_api.py", "heel/saas/iana_root_tlds.py", "heel/saas/jobs.py", "heel/saas/ledger.py",
    "heel/saas/migrate.py", "heel/saas/network_guard.py", "heel/saas/ops.py", "heel/saas/projects.py",
    "heel/saas/reconcile.py", "heel/saas/runner_auth.py", "heel/saas/runner_contexts.py", "heel/saas/server.py",
    "heel/saas/site.py", "heel/saas/tenancy.py", "heel/saas/verification.py", "heel/scenario_validate.py",
    "heel/scenarios.py", "heel/scenarios_lib/community.json", "heel/scenarios_lib/research_owasp.json",
    "heel/scope.py", "heel/semantic.py", "heel/static_review.py", "heel/store.py", "heel/sync_queue.py",
    "heel/targets.py", "heel/web_export.py",
)
LAUNCHER_SECONDS = 1200
TESTS_SECONDS = 600
CLEANUP_RESERVE_SECONDS = 60
# The three wheels the unchanged client and the TLS harness add to the H0-locked pytest closure: name,
# version, file and SHA-256 pinned here AND equal to the H0 lock entry (whose URL is used). No other
# dependency: ``cryptography`` is the package's only declared runner dependency.
CLIENT_CLOSURE = (
    ("cryptography", "45.0.7", "cryptography-45.0.7-cp311-abi3-manylinux_2_34_x86_64.whl",
     "b6a0e535baec27b528cb07a119f321ac024592388c5681a5ced167ae98e9fff3"),
    ("cffi", "2.1.1", "cffi-2.1.1-cp313-cp313-manylinux2014_x86_64.manylinux_2_17_x86_64.whl",
     "a931079504ecc49efed7744c476a5c343a92fabf66dec2db95edb1b2fdc770e2"),
    ("pycparser", "3.11", "pycparser-3.11-py3-none-any.whl",
     "51d5a8ba2be0bbe440b99d2112604c95bbbc3c2748a64260186c541e1729cd80"),
)
CRYPTOGRAPHY_VERSION = "45.0.7"

# Every case function in the test module, in file order (a static test keeps this list exact).
REQUIRED_CASES = (
    "test_static_required_profile_cannot_skip",
    "test_static_launcher_requires_every_case_function_and_record_in_this_module",
    "test_static_launcher_has_one_fixed_profile_branch_budgets_and_no_inputs",
    "test_static_closure_profile_and_lock_are_imported_not_copied",
    "test_static_workflow_is_the_recorded_five_jobs_plus_one_fully_constrained_job",
    "test_static_launcher_stages_every_path_the_module_reads",
    "test_static_evidence_sanitizer_and_acceptance_rule",
    "test_static_fixture_uses_only_public_apis_fd_only_namespaces_and_never_assigns_h2_seams",
    "test_static_fixture_literals_are_the_recorded_public_pick",
    "test_static_doc_names_every_case_and_the_limits",
    "test_p0_profile_is_captured_fresh_namespace_ruleset_is_empty_and_the_real_h1_self_test_passes",
    "test_p1_install_readback_whole_ruleset_is_exactly_one_table_then_h1_prepare_activate_permit_only_pinned_ipv4_tcp_443",
    "test_p2_before_activation_wrong_source_unpinned_target_8443_udp_443_and_ipv6_are_denied",
    "test_p3_no_fresh_connection_after_expiry_and_late_activation_does_not_revive",
    "test_p4_unchanged_client_resolves_full_set_each_attempt_accepts_reorder_refuses_membership_or_unsafe_change_and_dials_ipv4_for_dual_stack_through_the_live_lease",
    "test_p5_ipv6_only_input_refuses_before_any_table_exists",
    "test_p6_install_readback_or_cleanup_fault_never_receipts_and_quarantines_without_host_rules",
    "test_p7_cleanup_is_fd_bound_whole_ruleset_is_empty_and_no_namespace_veth_helper_or_host_residue_remains",
)
# Each dynamic case writes exactly one record: id -> (case function, control class, expected verdict).
RECORD_CASES = {
    "p0": (REQUIRED_CASES[10], "provenance", "pass"),
    "p1": (REQUIRED_CASES[11], "admission", "pass"),
    "p2": (REQUIRED_CASES[12], "negative", "pass"),
    "p3": (REQUIRED_CASES[13], "expiry", "pass"),
    "p4": (REQUIRED_CASES[14], "client", "pass"),
    "p5": (REQUIRED_CASES[15], "negative", "pass"),
    "p6": (REQUIRED_CASES[16], "fault", "pass"),
    "p7": (REQUIRED_CASES[17], "cleanup", "pass"),
}
CONTROLS = ("provenance", "admission", "negative", "expiry", "client", "fault", "cleanup")
VERDICTS = ("pass", "fail")
SETUP_FAILURES = ("wheel_hash_mismatch", "pytest_version_mismatch", "cryptography_version_mismatch", "import_smoke_failed",
                  "suite_setup_failed")
# The one labelled controlled fault injection. Every other key, table, helper, nft run and packet is real.
SEAMS = ("FAULT-INJECTION p6 only: the public install/cleanup clock argument jumps forward at a fixed step and a fixture "
         "pre-seeds a conflicting heel_lease chain; real helper, real setns, real nft and kernel; it proves the "
         "fail-closed outcome only, never an unobserved kernel timeout",)
VERSION_TOKENS = ("kernel_release", "kernel_major_minor", "kernel_source_tag", "proc_version_sha256", "nft_version",
                  "nftables_package", "python", "pytest", "cryptography", "selftest", "readd_observation")
VERSION_INTS = ("config_hz", "tick_allowance_ms", "overflowuid", "cpu_count")

# The isolated import smoke (static oracle in ordinary CI and the privileged child before pytest):
# ``-I`` puts neither the cwd nor PYTHONPATH on sys.path, so only the staged root is inserted; every
# loaded module must come from the staged root, the closed environment or the interpreter's stdlib.
IMPORT_SMOKE = """\
import os, sys
root, env = os.path.realpath(sys.argv[1]), os.path.realpath(sys.argv[2])
sys.path.insert(0, root)
import heel.runner.http_transport as transport
import tests.support.edge_tls_harness as harness
import cryptography
bases = {os.path.realpath(p) for p in (sys.base_prefix, sys.base_exec_prefix)}
def under(path, base):
    return path == base or path.startswith(base + os.sep)
def origin(path):
    path = os.path.realpath(path)
    if under(path, root):
        return "root"
    if under(path, env):
        return "env"
    return "stdlib" if any(under(path, base) for base in bases) else "other"
assert origin(transport.__file__) == "root" and origin(harness.__file__) == "root", "staged_origin"
assert origin(cryptography.__file__) == "env" and cryptography.__version__ == sys.argv[3], "cryptography_origin"
assert all(p == root or origin(p) in ("env", "stdlib") for p in sys.path if p), "sys_path"
counts = {"root": 0, "env": 0, "stdlib": 0, "other": 0}
for name, module in sorted(sys.modules.items()):
    path = getattr(module, "__file__", None)
    if path:
        where = origin(path)
        counts[where] += 1
        assert where != "other", "module_origin"
        assert where == "root" or not (name == "heel" or name.startswith(("heel.", "tests."))), "project_origin"
print("import_smoke ok root=%d env=%d stdlib=%d" % (counts["root"], counts["env"], counts["stdlib"]))
"""


_H1F = None


def h1f():
    """H1F's launcher, imported by path for its reviewed closure and helpers (never edited)."""
    global _H1F
    if _H1F is None:
        spec = importlib.util.spec_from_file_location("host_lease_feasibility", H1F_LAUNCHER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _H1F = module
    return _H1F


_PROFILE = None


def profile():
    """The production runtime-profile module, imported by path (one module object per process)."""
    global _PROFILE
    if _PROFILE is None:
        spec = importlib.util.spec_from_file_location("heel_host_profile", ROOT / "deploy" / "host" / "profile.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _PROFILE = module
    return _PROFILE


def h0():
    return h1f().h0()


ProofFailure = h1f().ProofFailure
FIXED_PATH = h1f().FIXED_PATH
HOST_TOOLS = h1f().HOST_TOOLS
PYTHON_VERSION = h1f().PYTHON_VERSION
PYTEST_VERSION = h1f().PYTEST_VERSION
PYTEST_CLOSURE = h1f().PYTEST_CLOSURE
SUPPORTED_KERNELS = profile().SUPPORTED_KERNELS
kernel_profile = profile().kernel_profile
artifact_scan = h1f().artifact_scan
_env = h1f()._env
_sha256 = h1f()._sha256
WHEEL_FILES = tuple(item[2] for item in PYTEST_CLOSURE) + tuple(item[2] for item in CLIENT_CLOSURE)


# ---------------------------------------------------------------------------------------------
# Closed evidence grammar (the H1F grammar with this module's case table).

_KEY = re.compile(r"[a-z][a-z0-9_]{0,47}")
_TOKEN = re.compile(r"[a-z0-9][a-z0-9_.:-]{0,79}")
INT_LIMIT = 10 ** 12
RECORD_KEYS = {"case", "verdict", "control", "ints", "tokens"}


def sanitize_record(entry) -> dict | None:
    """All or nothing: one fixed case id, its control class, a verdict, and flat maps of bounded
    integers and closed tokens. Any other key, type, size or character drops the whole record."""
    if not isinstance(entry, dict) or set(entry) != RECORD_KEYS or entry["case"] not in RECORD_CASES:
        return None
    if entry["control"] != RECORD_CASES[entry["case"]][1] or entry["verdict"] not in VERDICTS:
        return None
    ints, tokens = entry["ints"], entry["tokens"]
    if not isinstance(ints, dict) or not isinstance(tokens, dict) or len(ints) > 64 or len(tokens) > 32:
        return None
    for key, value in ints.items():
        if not (isinstance(key, str) and _KEY.fullmatch(key) and type(value) is int and -INT_LIMIT <= value <= INT_LIMIT):
            return None
    for key, value in tokens.items():
        if not (isinstance(key, str) and _KEY.fullmatch(key) and isinstance(value, str) and _TOKEN.fullmatch(value)):
            return None
    return {"case": entry["case"], "verdict": entry["verdict"], "control": entry["control"],
            "ints": {key: ints[key] for key in sorted(ints)}, "tokens": {key: tokens[key] for key in sorted(tokens)}}


def _no_constant(name: str):
    raise ValueError("non-finite number")


def sanitize_records(raw: Path) -> tuple[list[dict], int]:
    records, dropped = [], 0
    if not raw.exists():
        return records, dropped
    for line in raw.read_text(encoding="utf-8").splitlines()[:512]:
        try:
            clean = sanitize_record(json.loads(line, parse_constant=_no_constant)) if len(line) <= 8192 else None
        except (ValueError, RecursionError):
            clean = None
        if clean is None:
            dropped += 1
        else:
            records.append(clean)
    return records, dropped


def profile_fields(by_case: dict) -> dict:
    """The production profile inputs, all from the P0 record (the real H1 self-test on this kernel)."""
    p0 = by_case.get("p0") or {"ints": {}, "tokens": {}}
    return {"kernel_major_minor": p0["tokens"].get("kernel_major_minor"), "nft_version": p0["tokens"].get("nft_version"),
            "config_hz": p0["ints"].get("config_hz"), "selftest": p0["tokens"].get("selftest"),
            "readd_observation": p0["tokens"].get("readd_observation")}


# ---------------------------------------------------------------------------------------------
# Parent: reviewed ref, candidate, dependencies, the fixed child, sanitized evidence.

def staged_files() -> tuple[str, ...]:
    return HEEL_TREE_FILES + STAGE_FILES


def check_ref(environ=os.environ) -> None:
    """The literal reviewed proof branch only (the workflow gate says the same; this refuses a copy)."""
    if environ.get("GITHUB_REF") != REVIEWED_REF:
        raise ProofFailure("ref_not_reviewed")


def candidate_provenance() -> dict:
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
    status = subprocess.run(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=ROOT,
                            capture_output=True, text=True, check=True).stdout
    tracked = subprocess.run(["git", "ls-files", "-z", "--", *STAGE_FILES], cwd=ROOT, capture_output=True, check=True).stdout
    tree = subprocess.run(["git", "ls-files", "-z", "--", "heel"], cwd=ROOT, capture_output=True, check=True).stdout
    names = {name for name in tracked.decode().split("\0") if name}
    heel = tuple(name for name in tree.decode().split("\0") if name)
    if status.strip() or names != set(STAGE_FILES) or not re.fullmatch(r"[0-9a-f]{40}", head):
        raise ProofFailure("candidate_not_clean")
    if heel != HEEL_TREE_FILES:
        raise ProofFailure("heel_tree_differs")
    tree_hashes = {name: _sha256(ROOT / name) for name in HEEL_TREE_FILES}
    return {"candidate_sha": head, "proof_files": {name: _sha256(ROOT / name) for name in STAGE_FILES},
            "proof_file_count": len(STAGE_FILES), "heel_tree_files": tree_hashes, "heel_tree_file_count": len(tree_hashes),
            "staged_closure_sha256": closure_digest(tree_hashes, STAGE_FILES)}


def closure_digest(tree_hashes: dict, stage_files: tuple, root: Path = ROOT) -> str:
    """One SHA-256 over ``path NUL sha256 LF`` for every staged file, in the fixed staged order."""
    lines = [f"{name}\0{tree_hashes[name]}\n" for name in HEEL_TREE_FILES]
    lines += [f"{name}\0{_sha256(root / name)}\n" for name in stage_files]
    return hashlib.sha256("".join(lines).encode()).hexdigest()


def closure_matches_lock(lock: dict) -> None:
    """The pytest closure through H1F's own check, then the three client wheels: each byte-identical
    to its H0 lock entry (name, version, file, SHA-256)."""
    h1f().closure_matches_lock(lock)
    wheels = {wheel["name"]: wheel for wheel in lock["python"]["wheels"]}
    for name, version, filename, digest in CLIENT_CLOSURE:
        entry = wheels.get(name)
        if entry is None or (entry["version"], entry["file"], entry["sha256"]) != (version, filename, digest):
            raise ProofFailure("closure_differs_from_h0_lock")


def wheel_closure(lock: dict) -> tuple[tuple[str, str, str], ...]:
    """(file, url, sha256) for the eight wheels, in fixed order; the client URLs come from the lock."""
    wheels = {wheel["name"]: wheel for wheel in lock["python"]["wheels"]}
    return (tuple((filename, url, digest) for _name, _version, filename, url, digest in PYTEST_CLOSURE)
            + tuple((filename, wheels[name]["url"], digest) for name, _version, filename, digest in CLIENT_CLOSURE))


def fetch_closure(lock: dict, scratch: Path) -> Path:
    wheels = scratch / "wheels"
    wheels.mkdir(mode=0o700)
    for filename, url, digest in wheel_closure(lock):
        h0().fetch(url, digest, wheels / filename)
    return wheels


LOCATOR_REASONS = h1f().LOCATOR_REASONS
LOCATOR_TOKENS = h1f().LOCATOR_TOKENS


def _failure_locator(base: str, kind: str, element) -> dict:
    text, message = element.text or "", element.get("message") or ""
    lines = [int(match.group(1)) for match in re.finditer(
        r"^(?:[^\n]*/)?" + re.escape(TEST_MODULE) + r":([0-9]{1,6}):(?: |$)", text, re.M)]
    if kind == "skipped":
        reason = "skipped"
    elif kind == "error" and re.match(r"failed on (setup|teardown) ", message):
        reason = message.split()[2] + "_error"
    else:
        crash = re.findall(r"^[^\n]*:[0-9]{1,6}: ([A-Za-z_][A-Za-z0-9_.]*)$", text, re.M)
        exception = crash[-1] if crash else (re.match(r"([A-Za-z_][A-Za-z0-9_.]*)(?::|$)", message) or [None, ""])[1]
        reason = LOCATOR_REASONS.get(exception.rsplit(".", 1)[-1], "other_exception")
    return {"case": base, "line": lines[-1] if lines else 0, "reason": reason}


def summarize_junit(path: Path) -> dict:
    counts = {"collected": 0, "passed": 0, "failed": 0, "errors": 0, "skipped": 0}
    functions, failing, locators = [], [], []
    if path.exists():
        for case in ElementTree.parse(path).iter("testcase"):
            base = case.get("name", "").split("[", 1)[0]
            if not re.fullmatch(r"test_[a-z0-9_]{1,200}", base):
                continue
            counts["collected"] += 1
            functions.append(base)
            for kind, counter in (("failure", "failed"), ("error", "errors"), ("skipped", "skipped")):
                element = case.find(kind)
                if element is not None:
                    counts[counter] += 1
                    failing.append(base)
                    locator = _failure_locator(base, kind, element)
                    if locator["reason"] in LOCATOR_TOKENS and 0 <= locator["line"] <= 100000:
                        locators.append(locator)
                    break
            else:
                counts["passed"] += 1
    return {**counts, "case_functions": functions, "failing": sorted(set(failing)), "failure_locators": locators[:128]}


def index_records(records: list[dict]) -> tuple[dict, list[str]]:
    by_case, duplicates = {}, set()
    for record in records:
        if record["case"] in by_case:
            duplicates.add(record["case"])
        else:
            by_case[record["case"]] = record
    return by_case, sorted(duplicates)


def evaluate(junit: dict, records: list[dict], dropped: int, cleanup: dict, inner: dict, child_exit: int | None) -> dict:
    """The fixed acceptance rule: PASS, INCOMPLETE (only the profile is unsupported) or FAIL."""
    by_case, duplicates = index_records(records)
    missing_cases = sorted(set(REQUIRED_CASES) - set(junit["case_functions"]))
    unexpected_cases = sorted(set(junit["case_functions"]) - set(REQUIRED_CASES))
    missing_records = sorted(set(RECORD_CASES) - set(by_case))
    record_failures = sorted(case for case, record in by_case.items() if record["verdict"] != RECORD_CASES[case][2])
    profile, reasons = kernel_profile(profile_fields(by_case))
    core = (child_exit == 0 and inner.get("pytest_exit") == 0 and junit["collected"] == len(REQUIRED_CASES)
            and junit["passed"] == len(REQUIRED_CASES) and junit["skipped"] == 0 and junit["failed"] == 0
            and junit["errors"] == 0 and not missing_cases and not unexpected_cases and not missing_records
            and not record_failures and not duplicates and dropped == 0 and inner.get("import_smoke") == "ok"
            and cleanup.get("host_fingerprints_unchanged") is True and inner.get("leftover_processes") == 0)
    result = "PASS" if core and profile == "pinned" else ("INCOMPLETE" if core else "FAIL")
    return {"result": result, "kernel_profile": profile, "profile_reasons": reasons, "missing_required_cases": missing_cases,
            "unexpected_cases": unexpected_cases, "missing_records": missing_records, "record_failures": record_failures,
            "duplicate_records": duplicates, "dropped_record_lines": dropped}


def version_lines(by_case: dict, profile: str) -> list[str]:
    p0 = by_case.get("p0") or {"ints": {}, "tokens": {}}
    lines = [f"{key} {p0['tokens'].get(key, 'unavailable')}" for key in VERSION_TOKENS]
    lines += [f"{key} {p0['ints'].get(key, 'unavailable')}" for key in VERSION_INTS]
    lines += [f"kernel_profile {profile}", f"runtime_assumption {RUNTIME_ASSUMPTION}"]
    return lines


def report_lines(summary: dict, failure: str | None, cleanup: dict) -> list[str]:
    tests = summary.get("tests") or {}
    report = [f"result {summary['result']}", f"failure {failure}", f"candidate {summary.get('candidate_sha')}",
              f"proof_file_count {summary.get('proof_file_count')}", f"heel_tree_file_count {summary.get('heel_tree_file_count')}",
              f"staged_closure_sha256 {summary.get('staged_closure_sha256')}", f"import_smoke {summary.get('import_smoke')}",
              f"kernel_profile {summary.get('kernel_profile')}", f"runtime_assumption {RUNTIME_ASSUMPTION}"]
    report += [f"profile_reason {reason}" for reason in summary.get("profile_reasons") or []]
    report += [f"{key} {tests.get(key)}" for key in ("collected", "passed", "failed", "errors", "skipped")]
    report += [f"failing {name}" for name in tests.get("failing") or []]
    report += [f"locator {item['case']} {TEST_MODULE}:{item['line']} {item['reason']}" for item in tests.get("failure_locators") or []]
    for key in ("missing_required_cases", "unexpected_cases", "missing_records", "record_failures", "duplicate_records"):
        report += [f"{key} {name}" for name in summary.get(key) or []]
    report += [f"case {record['case']} {record['control']} {record['verdict']}" for record in summary.get("records") or []]
    report.append(f"host_fingerprints_unchanged {cleanup.get('host_fingerprints_unchanged')}")
    report.append(f"leftover_processes {cleanup.get('leftover_processes')}")
    report += [f"missing_tool {name}" for name in cleanup.get("missing_tools") or []]
    report += [f"kernel_module_loaded {name}" for name in cleanup.get("kernel_modules_loaded") or []]
    return report


def parent() -> int:
    started = time.monotonic()
    deadline = started + LAUNCHER_SECONDS - CLEANUP_RESERVE_SECONDS
    timings: dict[str, float] = {}
    summary: dict = {"schema_version": "heel.host-h2-policy-proof.summary.v1", "profile": PROFILE, "reviewed_ref": REVIEWED_REF,
                     "utc_start": datetime.datetime.now(datetime.timezone.utc).isoformat(), "result": "FAIL",
                     "kernel_profile": None, "runtime_assumption": RUNTIME_ASSUMPTION, "seams": list(SEAMS),
                     "negative_controls": sorted(case for case, item in RECORD_CASES.items() if item[1] == "negative")}
    scratch = Path(tempfile.mkdtemp(prefix=SCRATCH_PREFIX, dir=os.environ.get("RUNNER_TEMP") or None))
    token = secrets.token_hex(16)
    exit_code, failure, cleanup, versions, by_case = 1, None, {}, [], {}
    try:
        check_ref()
        # Provenance first: the evidence directory below must not make the checkout look dirty.
        summary.update(candidate_provenance())
        ARTIFACT_DIR.mkdir(exist_ok=True)
        h1f().check_python()
        missing = h1f().missing_host_tools()
        if missing:
            cleanup["missing_tools"] = missing
            raise ProofFailure("host_tool_missing")
        lock = h0().load_lock(H0_LOCK)
        closure_matches_lock(lock)
        summary["h0_lock_sha256"] = _sha256(H0_LOCK)
        h0().lint_workflow(lock, scratch, timings)
        wheels = fetch_closure(lock, scratch)
        out = scratch / "out"
        out.mkdir(mode=0o700)
        remaining = int(deadline - time.monotonic())
        if remaining < 120:
            raise ProofFailure("budget_exhausted_before_tests")
        request = {"schema": CHILD_SCHEMA, "wheels": str(wheels), "out": str(out), "uid": os.getuid(),
                   "tests_seconds": min(TESTS_SECONDS, remaining - 60), "token": token}
        child_started = time.monotonic()
        child = subprocess.run(["sudo", "-n", "--", sys.executable, "-I", str(Path(__file__).resolve())],
                               input=json.dumps(request).encode(), capture_output=True, timeout=remaining,
                               env={"PATH": FIXED_PATH, "LC_ALL": "C"})
        timings["privileged_child"] = round(time.monotonic() - child_started, 3)
        inner = json.loads((out / "inner.json").read_text()) if (out / "inner.json").exists() else {}
        raw_cleanup = json.loads((out / "cleanup.raw.json").read_text()) if (out / "cleanup.raw.json").exists() else {}
        names = h0().FINGERPRINT_NAMES
        cleanup.update({
            "child_exit": child.returncode, "namespace_child_exit": raw_cleanup.get("namespace_child_exit"),
            "host_fingerprints_unchanged": raw_cleanup.get("host_fingerprints_unchanged") is True,
            "differing_fingerprints": sorted(set(raw_cleanup.get("differing_fingerprints") or []) & names),
            "unstable_fingerprints": sorted(set(raw_cleanup.get("unstable_fingerprints") or []) & names),
            "missing_tools": sorted(set(raw_cleanup.get("missing_tools") or []) & set(HOST_TOOLS)),
            "kernel_modules_loaded": sorted(name for name in raw_cleanup.get("kernel_modules_loaded") or []
                                            if isinstance(name, str) and re.fullmatch(r"[a-z0-9_]{1,56}", name))[:64],
            "leftover_processes": inner.get("leftover_processes"), "leftover_after_kill": inner.get("leftover_after_kill"),
            "leftover_records": h0().sanitize_leftovers(inner.get("leftover_records")),
            "reaped_before_count": inner.get("reaped_before_count")})
        if isinstance(inner.get("pytest_seconds"), (int, float)):
            timings["inner_pytest"] = round(float(inner["pytest_seconds"]), 3)
        junit = summarize_junit(out / "junit.xml")
        records, dropped = sanitize_records(out / "records.raw.jsonl")
        by_case, _duplicates = index_records(records)
        if inner.get("setup_failure") in SETUP_FAILURES:
            summary["setup_failure"] = inner["setup_failure"]
        summary["import_smoke"] = "ok" if inner.get("import_smoke") == "ok" else "not_ok"
        (ARTIFACT_DIR / "cases.jsonl").write_text("".join(json.dumps(record, sort_keys=True) + "\n" for record in records))
        verdict = evaluate(junit, records, dropped, cleanup, inner, child.returncode)
        summary.update(verdict, tests=junit, pytest_exit=inner.get("pytest_exit"), tests_timed_out=inner.get("timed_out"),
                       records=[{"case": r["case"], "control": r["control"], "verdict": r["verdict"]} for r in records])
        versions = version_lines(by_case, verdict["kernel_profile"])
        exit_code = 0 if verdict["result"] == "PASS" else 1
    except ProofFailure as error:
        failure = error.code
    except Exception as error:  # noqa: BLE001 - a fixed class name only, never a message
        failure = "unexpected_" + type(error).__name__
    finally:
        ARTIFACT_DIR.mkdir(exist_ok=True)
        versions = versions + ["launcher_python {}.{}.{}".format(*sys.version_info[:3]), h0().cpu_count_line(),
                               f"platform {sys.platform}"]
        summary.update(failure=failure, timings=timings, seconds=round(time.monotonic() - started, 3),
                       budgets={"launcher_seconds": LAUNCHER_SECONDS, "tests_seconds": TESTS_SECONDS})
        (ARTIFACT_DIR / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
        (ARTIFACT_DIR / "versions.txt").write_text("\n".join(versions) + "\n")
        (ARTIFACT_DIR / "cleanup.json").write_text(json.dumps(cleanup, indent=2, sort_keys=True) + "\n")
        report = report_lines(summary, failure, cleanup)
        (ARTIFACT_DIR / "report.txt").write_text("\n".join(report) + "\n")
        for name in ARTIFACT_FILES:
            (ARTIFACT_DIR / name).touch()
        flagged = artifact_scan(ARTIFACT_DIR, token)
        if flagged:
            for name in flagged:
                (ARTIFACT_DIR / name).write_text('{"suppressed":"artifact scan"}\n')
            exit_code = 1
        shutil.rmtree(scratch, ignore_errors=True)
        print("\n".join(report), flush=True)
    return exit_code


# ---------------------------------------------------------------------------------------------
# Privileged child: request validation, host fingerprints, the outer namespaces and the suite.

_CLONE_NEWNS, _CLONE_NEWNET, _CLONE_NEWPID = 0x00020000, 0x40000000, 0x20000000


def _owned_private_directory(path: str, uid: int, name: str) -> bool:
    """An absolute, symlink-free scratch directory of the invoking user that nobody else can write."""
    if not isinstance(path, str) or not os.path.isabs(path) or os.path.realpath(path) != path:
        return False
    target = Path(path)
    if target.name != name or not target.parent.name.startswith(SCRATCH_PREFIX):
        return False
    for directory in (target, target.parent):
        info = os.lstat(directory)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            return False
    return True


def validated_request(raw: str) -> dict | None:
    try:
        request = json.loads(raw, parse_constant=_no_constant)
    except (ValueError, RecursionError):
        return None
    if not isinstance(request, dict) or set(request) != {"schema", "wheels", "out", "uid", "tests_seconds", "token"}:
        return None
    if request["schema"] != CHILD_SCHEMA or type(request["uid"]) is not int or not 1 <= request["uid"] < 2 ** 31:
        return None
    if type(request["tests_seconds"]) is not int or not 60 <= request["tests_seconds"] <= TESTS_SECONDS:
        return None
    if not isinstance(request["token"], str) or not re.fullmatch(r"[0-9a-f]{32}", request["token"]):
        return None
    try:
        if not all(_owned_private_directory(request[key], request["uid"], key) for key in ("wheels", "out")):
            return None
        if sorted(os.listdir(request["wheels"])) != sorted(WHEEL_FILES):
            return None
    except OSError:
        return None
    return request


def stage_tree(destination: Path, root: Path = ROOT) -> Path:
    """Copy exactly HEEL_TREE_FILES + STAGE_FILES from this checkout (never .git, untracked state or scratch)."""
    for name in staged_files():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        for parent in target.relative_to(destination).parents:
            os.chmod(destination / parent, 0o755)
        shutil.copyfile(root / name, target)
        os.chmod(target, 0o644)
    return destination


def install_closure(wheel_bytes: dict[str, bytes], root: Path) -> Path:
    """Re-hash the in-memory wheels and install exactly the eight with no index into a private venv."""
    wheels = root / "wheels"
    wheels.mkdir(mode=0o755)
    files = []
    digests = {**{item[2]: item[4] for item in PYTEST_CLOSURE}, **{item[2]: item[3] for item in CLIENT_CLOSURE}}
    for filename in WHEEL_FILES:
        data = wheel_bytes[filename]
        if hashlib.sha256(data).hexdigest() != digests[filename]:
            raise ProofFailure("wheel_hash_mismatch")
        (wheels / filename).write_bytes(data)
        files.append(str(wheels / filename))
    venv = root / "venv"
    subprocess.run([sys.executable, "-I", "-m", "venv", "--copies", "--without-pip", str(venv)], check=True,
                   env=_env(), timeout=120, capture_output=True)
    subprocess.run([sys.executable, "-I", "-m", "pip", "--isolated", "--python", str(venv / "bin" / "python"), "install",
                    "--no-index", "--no-deps", "--no-cache-dir", "--no-compile", *files], check=True, timeout=300,
                   env=_env({"HOME": str(root / "home"), "PIP_CONFIG_FILE": "/dev/null", "PYTHONNOUSERSITE": "1",
                             "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PIP_ROOT_USER_ACTION": "ignore"}), capture_output=True)
    versions = subprocess.run([str(venv / "bin" / "python"), "-I", "-c",
                               "import pytest, cryptography; print(pytest.__version__, cryptography.__version__)"],
                              capture_output=True, text=True, timeout=60, env=_env()).stdout.split()
    if versions[:1] != [PYTEST_VERSION]:
        raise ProofFailure("pytest_version_mismatch")
    if versions[1:] != [CRYPTOGRAPHY_VERSION]:
        raise ProofFailure("cryptography_version_mismatch")
    return venv / "bin" / "python"


def import_smoke(python: Path, source: Path, env: Path) -> bool:
    """IMPORT_SMOKE with ``-I`` from ``/``: only the staged root and the closed environment. ``-B``
    because ``-I`` ignores PYTHONDONTWRITEBYTECODE: no bytecode may be written into the staged tree."""
    completed = subprocess.run([str(python), "-I", "-B", "-c", IMPORT_SMOKE, str(source), str(env), CRYPTOGRAPHY_VERSION],
                               cwd="/", capture_output=True, text=True, timeout=120, env={"PATH": FIXED_PATH, "LC_ALL": "C"})
    return completed.returncode == 0 and completed.stdout.startswith("import_smoke ok ")


def _inside(request: dict, wheel_bytes: dict[str, bytes], out_fd: int) -> int:
    """PID 1 of the outer PID namespace: private mounts, the fixed suite, then exit (kills all)."""
    helper = h0()
    libc = helper._libc()
    helper._mount(libc, None, "/", None, helper._MS_REC | helper._MS_PRIVATE)
    helper._mount(libc, "proc", "/proc", "proc", helper._MS_NOSUID | helper._MS_NODEV)
    helper._mount(libc, "tmpfs", "/tmp", "tmpfs", helper._MS_NOSUID | helper._MS_NODEV, "mode=0755,size=1g")
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True, env=_env(), timeout=10, capture_output=True)
    root = Path("/tmp/heel-h2-policy")
    for directory, mode in ((root, 0o755), (root / "home", 0o700), (root / "out", 0o700), (root / "work", 0o700)):
        directory.mkdir(mode=mode)
        os.chmod(directory, mode)
    try:
        source = stage_tree(root / "src")
        python = install_closure(wheel_bytes, root)
        if not import_smoke(python, source, root / "venv"):
            raise ProofFailure("import_smoke_failed")
    except (ProofFailure, OSError, subprocess.SubprocessError) as error:
        code = error.code if isinstance(error, ProofFailure) else "suite_setup_failed"
        h1f()._write_out(out_fd, "inner.json", json.dumps({"setup_failure": code}).encode(), request["uid"])
        return 1
    out = root / "out"
    env = {"PATH": FIXED_PATH, "LC_ALL": "C", "TZ": "UTC", "HOME": str(root / "home"), "TMPDIR": str(root / "home"),
           "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1", REQUIRED_ENV: "1",
           RECORDS_ENV: str(out / "records.raw.jsonl"), WORK_ENV: str(root / "work"), TOKEN_ENV: request["token"]}
    started = time.monotonic()
    process = subprocess.Popen([str(python), "-m", "pytest", "-q", "-p", "no:cacheprovider", "-o", "console_output_style=classic",
                                "-o", "xfail_strict=true", f"--junitxml={out / 'junit.xml'}", TEST_MODULE],
                               cwd=source, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, start_new_session=True)
    try:
        process.communicate(timeout=request["tests_seconds"])  # private; never written
        code, timed_out = process.returncode, False
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, 9)
        process.communicate()
        code, timed_out = 124, True
    pytest_seconds = round(time.monotonic() - started, 3)
    reaped = helper.reap_children()
    records = helper.leftover_records(Path("/proc"), os.getpid(), {os.path.realpath(python): "suite_python"})
    remaining = helper.kill_and_reap(records)
    result = {"pytest_exit": code, "timed_out": timed_out, "pytest_seconds": pytest_seconds, "reaped_before_count": reaped,
              "leftover_processes": len(records), "leftover_records": records[:helper.LEFTOVER_RECORD_LIMIT],
              "leftover_after_kill": remaining, "import_smoke": "ok"}
    h1f()._write_out(out_fd, "inner.json", json.dumps(result).encode(), request["uid"])
    for name in ("junit.xml", "records.raw.jsonl"):
        if (out / name).exists():
            h1f()._write_out(out_fd, name, (out / name).read_bytes(), request["uid"])
    return 0


def privileged_child() -> int:
    request = validated_request(sys.stdin.read(65536))
    if request is None:
        return 2
    out = Path(request["out"])

    def finish(cleanup: dict) -> None:
        target = out / "cleanup.raw.json"
        target.write_text(json.dumps(cleanup), encoding="utf-8")
        os.chown(target, request["uid"], request["uid"])

    missing = h1f().missing_host_tools()
    if missing:
        finish({"missing_tools": missing, "host_fingerprints_unchanged": False})
        return 1
    helper = h0()
    before, unstable = helper.stable_fingerprints()
    if unstable:
        finish({"namespace_child_exit": None, "host_fingerprints_unchanged": False, "differing_fingerprints": [],
                "unstable_fingerprints": unstable})
        return 1
    modules_before = h1f().loaded_modules()
    wheel_bytes = {filename: (Path(request["wheels"]) / filename).read_bytes() for filename in WHEEL_FILES}
    out_fd = os.open(out, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    child = os.fork()
    if child == 0:
        try:
            os.unshare(_CLONE_NEWNET | _CLONE_NEWNS | _CLONE_NEWPID)
            init = os.fork()
            if init == 0:
                try:
                    os._exit(_inside(request, wheel_bytes, out_fd))
                except BaseException:  # noqa: BLE001 - a fixed failure code only
                    os._exit(70)
            _pid, status = os.waitpid(init, 0)
            os._exit(os.waitstatus_to_exitcode(status) if os.WIFEXITED(status) else 71)
        except BaseException:  # noqa: BLE001
            os._exit(72)
    _pid, status = os.waitpid(child, 0)
    os.close(out_fd)
    inner_exit = os.waitstatus_to_exitcode(status)
    after = helper.host_fingerprints()
    differing = sorted(key for key in before if before[key] != after[key])
    finish({"namespace_child_exit": inner_exit, "host_fingerprints_unchanged": not differing,
            "differing_fingerprints": differing, "unstable_fingerprints": [],
            "kernel_modules_loaded": sorted(h1f().loaded_modules() - modules_before)[:64]})
    return 0 if inner_exit == 0 and not differing else 1


def main(argv: list[str]) -> int:
    if argv:
        print("usage: python scripts/host_h2_policy_proof.py (no arguments; fixed h2-policy-v1 profile)", file=sys.stderr)
        return 2
    if not sys.platform.startswith("linux"):
        print("result FAIL\nfailure platform_unavailable", flush=True)
        return 3
    if os.geteuid() == 0:
        return privileged_child()
    return parent()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
