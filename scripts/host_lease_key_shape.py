#!/usr/bin/env python3
"""Fixed ``lease-key-v1`` lease-key shape proof launcher (H2K1).

SPDX-License-Identifier: LicenseRef-Heel-Commercial

Run from the repository root as exactly ``python scripts/host_lease_key_shape.py``: one fixed
profile, no command, path, ref or test-selector inputs. The structure is H1A-1's
(``scripts/host_authority_proof.py``); the reviewed helpers and the H0-locked pytest closure come from
H1F (``scripts/host_lease_feasibility.py``) and H0 by path and are never copied, and the
supported-kernel pin, ``READD_EXPECTED`` and ``kernel_profile`` come from the production
``deploy/host/profile.py``, also by path. The unprivileged parent verifies the clean candidate
checkout and the pinned Python, confirms the host tools are already present, lints the workflow with
H0's pinned actionlint and fetches the H0-locked pytest closure. One fixed privileged child
(``sudo -n``) takes stable host fingerprints, creates an outer network+mount+PID namespace with only
loopback and a private tmpfs, stages exactly ``STAGE_FILES``, installs the closure offline and runs
``HEEL_REQUIRE_HOST_LEASE_KEY_PROOF=1 python -m pytest -q tests/linux/test_host_lease_key_shape.py``.

Exit 0 only for PASS: every case ran (no skip), every record holds, cleanup left the host
fingerprints unchanged and the kernel is inside the pinned profile; a clean run on an unsupported
profile is INCOMPLETE. The question is one primitive: whether the real H1 ``prepare``/``activate`` of
(SLOT_PEER, SLOT_ADDRESS) gates IPv4 TCP 443 packets to distinct approved targets through an
immediate-constant concatenation in both the activated-map lookup and the prepared-set membership.
It is an L3/L4 proof only and says nothing about Host/SNI/TLS/route/attempt enforcement, DNS, the
HostCycle-to-H3 handoff, H2, H3 or launch.
"""
from __future__ import annotations

import datetime
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
PROFILE = "lease-key-v1"
TEST_MODULE = "tests/linux/test_host_lease_key_shape.py"
ARTIFACT_DIR = ROOT / "host-lease-key-shape"
ARTIFACT_FILES = ("summary.json", "cases.jsonl", "versions.txt", "cleanup.json", "report.txt")
CHILD_SCHEMA = "heel.host-lease-key-shape.child.v1"
SCRATCH_PREFIX = "heel-host-lease-key-"
REQUIRED_ENV = "HEEL_REQUIRE_HOST_LEASE_KEY_PROOF"
RECORDS_ENV = "HEEL_HOST_LEASE_KEY_RECORDS"
WORK_ENV = "HEEL_HOST_LEASE_KEY_WORK"
TOKEN_ENV = "HEEL_HOST_LEASE_KEY_TOKEN"
RUNTIME_ASSUMPTION = "running-kernel"
# The fixed tracked files the privileged child copies (byte for byte) into the namespace and hashes
# into summary.json: the H1 domain and profile, this unit's files, and the H1F/H0 launchers and lock
# they import. A static test proves it covers every path the proof module and this launcher read.
STAGE_FILES = (
    "deploy/host/authority.py", "deploy/host/profile.py", "tests/linux/__init__.py",
    "tests/linux/test_host_lease_key_shape.py", "scripts/host_lease_key_shape.py", ".github/workflows/codeql.yml",
    "docs/saas/HOST_LEASE_KEY_SHAPE.md", "scripts/host_lease_feasibility.py", "scripts/host_ingress_proof.py",
    "deploy/host/ingress/runtime-lock.json",
)
LAUNCHER_SECONDS = 1200
TESTS_SECONDS = 600
CLEANUP_RESERVE_SECONDS = 60

# Every case function in the test module, in file order (a static test keeps this list exact).
REQUIRED_CASES = (
    "test_static_required_profile_cannot_skip",
    "test_static_launcher_requires_every_case_function_and_record_in_this_module",
    "test_static_launcher_has_one_fixed_profile_fixed_budgets_and_no_inputs",
    "test_static_profile_pin_and_closure_are_imported_not_copied",
    "test_static_workflow_is_the_recorded_four_jobs_plus_one_fully_constrained_job",
    "test_static_launcher_stages_every_path_the_module_reads",
    "test_static_evidence_sanitizer_and_acceptance_rule",
    "test_static_fixture_uses_only_the_public_domain_api_and_fd_only_namespaces",
    "test_static_gate_shape_and_readback_oracle",
    "test_static_gate_bytes_and_the_fixed_check_install_readback_sequence_are_unchanged",
    "test_static_installation_diagnostics_are_closed_and_carry_no_raw_text",
    "test_static_doc_names_every_case_and_the_limits",
    "test_k0_profile_is_captured_and_the_real_h1_self_test_passes",
    "test_k1_live_lease_admits_tcp_443_to_two_distinct_approved_targets",
    "test_k2_prepared_only_and_a_caller_supplied_mark_never_admit",
    "test_k3_no_fresh_connection_is_admitted_after_the_expiry_bound",
    "test_k4_late_activation_of_an_expired_key_does_not_revive_egress",
    "test_k5_live_lease_confines_source_target_port_protocol_and_family",
    "test_k6_every_owned_resource_is_resolved_and_the_outer_namespace_is_unchanged",
)
# Each dynamic case writes exactly one record: id -> (case function, control class, expected verdict).
RECORD_CASES = {
    "k0": ("test_k0_profile_is_captured_and_the_real_h1_self_test_passes", "provenance", "pass"),
    "k1": ("test_k1_live_lease_admits_tcp_443_to_two_distinct_approved_targets", "admission", "pass"),
    "k2": ("test_k2_prepared_only_and_a_caller_supplied_mark_never_admit", "negative", "pass"),
    "k3": ("test_k3_no_fresh_connection_is_admitted_after_the_expiry_bound", "expiry", "pass"),
    "k4": ("test_k4_late_activation_of_an_expired_key_does_not_revive_egress", "negative", "pass"),
    "k5": ("test_k5_live_lease_confines_source_target_port_protocol_and_family", "confinement", "pass"),
    "k6": ("test_k6_every_owned_resource_is_resolved_and_the_outer_namespace_is_unchanged", "cleanup", "pass"),
}
CONTROLS = ("provenance", "admission", "negative", "expiry", "confinement", "cleanup")
VERDICTS = ("pass", "fail")
SETUP_FAILURES = ("wheel_hash_mismatch", "pytest_version_mismatch", "suite_setup_failed")
SEAMS = ()  # no seam: every key is written by the real LeaseDomain API, every packet is real
VERSION_TOKENS = ("kernel_release", "kernel_major_minor", "kernel_source_tag", "proc_version_sha256", "nft_version",
                  "nftables_package", "python", "pytest", "selftest", "readd_observation")
VERSION_INTS = ("config_hz", "tick_allowance_ms", "overflowuid", "cpu_count")


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
READD_EXPECTED = profile().READD_EXPECTED
kernel_profile = profile().kernel_profile
artifact_scan = h1f().artifact_scan
_env = h1f()._env
_sha256 = h1f()._sha256


# ---------------------------------------------------------------------------------------------
# Closed evidence grammar (the H1F grammar with this module's case table).

_KEY = re.compile(r"[a-z][a-z0-9_]{0,47}")
_TOKEN = re.compile(r"[a-z0-9][a-z0-9_.:-]{0,79}")
INT_LIMIT = 10 ** 12
RECORD_KEYS = {"case", "verdict", "control", "ints", "tokens"}

# H2K1D1: closed diagnostics of the three fixed nft invocations on the gate text (check ``-c -f -``,
# install ``-f -``, readback ``-j list table``). Per phase: how the process ended (status), the normal
# exit code (-1 unless status is exit), the terminating signal (0 unless status is signal), a closed
# class, nft's own source locator (0/0 when absent) and the SHA-256 of stderr; never stderr itself.
# ``install_phase`` is the first phase whose class is not accepted (``none`` when all three are).
DIAG_PHASES = ("check", "install", "readback")
DIAG_STATUSES = ("exit", "signal", "timeout", "missing", "invalid")
DIAG_CLASSES = ("accepted", "parser_syntax", "parser_datatype", "parser_other", "netlink_einval", "netlink_eopnotsupp",
                "permission", "tool_missing", "timeout", "unknown")
DIAG_LINE_MAX, DIAG_COLUMN_MAX, DIAG_SIGNAL_MAX = 64, 512, 64
DIAG_TOKEN_KEYS = ("gate_input_sha256", "install_phase",
                   *(f"{phase}_{field}" for phase in DIAG_PHASES for field in ("status", "class", "stderr_sha256")))
DIAG_INT_KEYS = tuple(f"{phase}_{field}" for phase in DIAG_PHASES for field in ("exit", "signal", "line", "column"))
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


def _phase_valid(phase: str, ints: dict, tokens: dict) -> bool:
    status, kind = tokens[f"{phase}_status"], tokens[f"{phase}_class"]
    code, signal = ints[f"{phase}_exit"], ints[f"{phase}_signal"]
    line, column = ints[f"{phase}_line"], ints[f"{phase}_column"]
    if status not in DIAG_STATUSES or kind not in DIAG_CLASSES or not _SHA256_HEX.fullmatch(tokens[f"{phase}_stderr_sha256"]):
        return False
    if not (0 <= line <= DIAG_LINE_MAX and 0 <= column <= DIAG_COLUMN_MAX and (line == 0) == (column == 0)):
        return False
    if line and (status != "exit" or code == 0):  # a locator only ever comes from a rejecting exit
        return False
    if status == "exit":
        return 0 <= code <= 255 and signal == 0 and (code == 0) == (kind == "accepted") and kind not in ("timeout", "tool_missing")
    if code != -1 or kind == "accepted":
        return False
    if status == "signal":
        return 1 <= signal <= DIAG_SIGNAL_MAX and kind == "unknown"
    if signal != 0:
        return False
    return {"timeout": kind == "timeout", "missing": kind in ("tool_missing", "permission", "unknown"),
            "invalid": kind == "unknown"}[status]


def diagnostics_valid(ints: dict, tokens: dict) -> bool:
    """The H2K1D1 fields are all absent (a fixture that never reached the gate) or all present, in
    their own map, inside the closed grammar and mutually consistent."""
    if not any(key in ints or key in tokens for key in (*DIAG_TOKEN_KEYS, *DIAG_INT_KEYS)):
        return True
    if not (all(key in tokens and key not in ints for key in DIAG_TOKEN_KEYS)
            and all(key in ints and key not in tokens for key in DIAG_INT_KEYS)):
        return False
    if not _SHA256_HEX.fullmatch(tokens["gate_input_sha256"]) or not all(_phase_valid(phase, ints, tokens) for phase in DIAG_PHASES):
        return False
    first = next((phase for phase in DIAG_PHASES if tokens[f"{phase}_class"] != "accepted"), "none")
    return tokens["install_phase"] == first


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
    if not diagnostics_valid(ints, tokens):
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
    """The production profile inputs, all from the K0 record (the real H1 self-test on this kernel)."""
    k0 = by_case.get("k0") or {"ints": {}, "tokens": {}}
    return {"kernel_major_minor": k0["tokens"].get("kernel_major_minor"), "nft_version": k0["tokens"].get("nft_version"),
            "config_hz": k0["ints"].get("config_hz"), "selftest": k0["tokens"].get("selftest"),
            "readd_observation": k0["tokens"].get("readd_observation")}


# ---------------------------------------------------------------------------------------------
# Parent: candidate, dependencies, the fixed child, sanitized evidence.

def candidate_provenance() -> dict:
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
    status = subprocess.run(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=ROOT,
                            capture_output=True, text=True, check=True).stdout
    tracked = subprocess.run(["git", "ls-files", "-z", "--", *STAGE_FILES], cwd=ROOT, capture_output=True, check=True).stdout
    names = {name for name in tracked.decode().split("\0") if name}
    if status.strip() or names != set(STAGE_FILES) or not re.fullmatch(r"[0-9a-f]{40}", head):
        raise ProofFailure("candidate_not_clean")
    return {"candidate_sha": head, "proof_files": {name: _sha256(ROOT / name) for name in STAGE_FILES},
            "proof_file_count": len(STAGE_FILES)}


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
            if not re.fullmatch(r"test_[a-z0-9_]{1,160}", base):
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
            and not record_failures and not duplicates and dropped == 0
            and cleanup.get("host_fingerprints_unchanged") is True and inner.get("leftover_processes") == 0)
    result = "PASS" if core and profile == "pinned" else ("INCOMPLETE" if core else "FAIL")
    return {"result": result, "kernel_profile": profile, "profile_reasons": reasons, "missing_required_cases": missing_cases,
            "unexpected_cases": unexpected_cases, "missing_records": missing_records, "record_failures": record_failures,
            "duplicate_records": duplicates, "dropped_record_lines": dropped}


def version_lines(by_case: dict, profile: str) -> list[str]:
    k0 = by_case.get("k0") or {"ints": {}, "tokens": {}}
    lines = [f"{key} {k0['tokens'].get(key, 'unavailable')}" for key in VERSION_TOKENS]
    lines += [f"{key} {k0['ints'].get(key, 'unavailable')}" for key in VERSION_INTS]
    lines += [f"kernel_profile {profile}", f"runtime_assumption {RUNTIME_ASSUMPTION}"]
    return lines


def report_lines(summary: dict, failure: str | None, cleanup: dict) -> list[str]:
    tests = summary.get("tests") or {}
    report = [f"result {summary['result']}", f"failure {failure}", f"candidate {summary.get('candidate_sha')}",
              f"proof_file_count {summary.get('proof_file_count')}", f"kernel_profile {summary.get('kernel_profile')}",
              f"runtime_assumption {RUNTIME_ASSUMPTION}"]
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
    summary: dict = {"schema_version": "heel.host-lease-key-shape.summary.v1", "profile": PROFILE,
                     "utc_start": datetime.datetime.now(datetime.timezone.utc).isoformat(), "result": "FAIL",
                     "kernel_profile": None, "runtime_assumption": RUNTIME_ASSUMPTION, "seams": list(SEAMS),
                     "negative_controls": sorted(case for case, item in RECORD_CASES.items() if item[1] == "negative")}
    scratch = Path(tempfile.mkdtemp(prefix=SCRATCH_PREFIX, dir=os.environ.get("RUNNER_TEMP") or None))
    token = secrets.token_hex(16)
    exit_code, failure, cleanup, versions, by_case = 1, None, {}, [], {}
    try:
        # Provenance first: the evidence directory below must not make the checkout look dirty.
        summary.update(candidate_provenance())
        ARTIFACT_DIR.mkdir(exist_ok=True)
        h1f().check_python()
        missing = h1f().missing_host_tools()
        if missing:
            cleanup["missing_tools"] = missing
            raise ProofFailure("host_tool_missing")
        lock = h0().load_lock(H0_LOCK)
        h1f().closure_matches_lock(lock)
        summary["h0_lock_sha256"] = _sha256(H0_LOCK)
        h0().lint_workflow(lock, scratch, timings)
        wheels = h1f().fetch_closure(scratch)
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
        if sorted(os.listdir(request["wheels"])) != sorted(item[2] for item in PYTEST_CLOSURE):
            return None
    except OSError:
        return None
    return request


def stage_tree(destination: Path, root: Path = ROOT) -> Path:
    """Copy exactly STAGE_FILES from this checkout (never .git, untracked state or scratch)."""
    for name in STAGE_FILES:
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        for parent in target.relative_to(destination).parents:
            os.chmod(destination / parent, 0o755)
        shutil.copyfile(root / name, target)
        os.chmod(target, 0o644)
    return destination


def _inside(request: dict, wheel_bytes: dict[str, bytes], out_fd: int) -> int:
    """PID 1 of the outer PID namespace: private mounts, the fixed suite, then exit (kills all)."""
    helper = h0()
    libc = helper._libc()
    helper._mount(libc, None, "/", None, helper._MS_REC | helper._MS_PRIVATE)
    helper._mount(libc, "proc", "/proc", "proc", helper._MS_NOSUID | helper._MS_NODEV)
    helper._mount(libc, "tmpfs", "/tmp", "tmpfs", helper._MS_NOSUID | helper._MS_NODEV, "mode=0755,size=1g")
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True, env=_env(), timeout=10, capture_output=True)
    root = Path("/tmp/heel-lease-key")
    for directory, mode in ((root, 0o755), (root / "home", 0o700), (root / "out", 0o700), (root / "work", 0o700)):
        directory.mkdir(mode=mode)
        os.chmod(directory, mode)
    try:
        source = stage_tree(root / "src")
        python = h1f().install_closure(wheel_bytes, root)
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
              "leftover_after_kill": remaining}
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
    wheel_bytes = {item[2]: (Path(request["wheels"]) / item[2]).read_bytes() for item in PYTEST_CLOSURE}
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
        print("usage: python scripts/host_lease_key_shape.py (no arguments; fixed lease-key-v1 profile)", file=sys.stderr)
        return 2
    if not sys.platform.startswith("linux"):
        print("result FAIL\nfailure platform_unavailable", flush=True)
        return 3
    if os.geteuid() == 0:
        return privileged_child()
    return parent()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
