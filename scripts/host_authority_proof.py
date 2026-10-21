#!/usr/bin/env python3
"""Fixed ``authority-v1`` host-authority proof launcher (H1A-1).

SPDX-License-Identifier: LicenseRef-Heel-Commercial

Run from the repository root as exactly ``python scripts/host_authority_proof.py``: one fixed
profile, no command, path, ref or test-selector inputs. The structure is H1F's
(``scripts/host_lease_feasibility.py``), whose reviewed helpers, pytest closure, supported-kernel
pin and ``READD_EXPECTED`` are imported from it by path and never copied. The unprivileged parent
verifies the clean candidate checkout and the pinned Python, confirms the host tools are already
present, lints the workflow with H0's pinned actionlint and fetches the H0-locked pytest closure.
One fixed privileged child (``sudo -n``) takes stable host fingerprints, creates an outer
network+mount+PID namespace with only loopback and a private tmpfs, stages exactly
``STAGE_FILES``, installs the closure offline and runs
``HEEL_REQUIRE_HOST_AUTHORITY_PROOF=1 python -m pytest -q tests/linux/test_host_authority_proof.py``.

Exit 0 only for PASS: every case ran (no skip), every record holds, cleanup left the host
fingerprints unchanged and the kernel is inside the pinned profile; a clean run on an unsupported
profile is INCOMPLETE. The job runs under the running-kernel assumption (no suspend, hibernate,
pause, restore or clone during the job); it proves the H1A-1 domain and transport unit only and
says nothing about elapsed authority lifetime under gap modes M3-M6, the CP decision, the cycle,
H2, H3 or launch.
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
PROFILE = "authority-v1"
TEST_MODULE = "tests/linux/test_host_authority_proof.py"
ARTIFACT_DIR = ROOT / "host-authority-proof"
ARTIFACT_FILES = ("summary.json", "cases.jsonl", "versions.txt", "cleanup.json", "report.txt")
CHILD_SCHEMA = "heel.host-authority-proof.child.v1"
SCRATCH_PREFIX = "heel-host-authority-"
REQUIRED_ENV = "HEEL_REQUIRE_HOST_AUTHORITY_PROOF"
RECORDS_ENV = "HEEL_HOST_AUTHORITY_RECORDS"
WORK_ENV = "HEEL_HOST_AUTHORITY_WORK"
TOKEN_ENV = "HEEL_HOST_AUTHORITY_TOKEN"
RUNTIME_ASSUMPTION = "running-kernel"
# The fixed tracked files the privileged child copies (byte for byte) into the namespace and hashes
# into summary.json: the H1A-1 files plus the H1F/H0 launchers and lock they import. A static test
# proves it covers every path the proof module and this launcher read under ROOT.
STAGE_FILES = (
    "deploy/host/authority.py", "heel/saas/host_authority.py", "tests/test_host_authority.py",
    "tests/linux/__init__.py", "tests/linux/test_host_authority_proof.py", "scripts/host_authority_proof.py",
    ".github/workflows/codeql.yml", "docs/saas/HOST_AUTHORITY_PROOF.md", "scripts/host_lease_feasibility.py",
    "scripts/host_ingress_proof.py", "deploy/host/ingress/runtime-lock.json",
)
LAUNCHER_SECONDS = 1200
TESTS_SECONDS = 600
CLEANUP_RESERVE_SECONDS = 60

# Every case function in the test module, in file order (a static test keeps this list exact).
REQUIRED_CASES = (
    "test_static_required_profile_cannot_skip",
    "test_static_launcher_requires_every_case_function_and_record_in_this_module",
    "test_static_launcher_has_one_fixed_profile_fixed_budgets_and_no_inputs",
    "test_static_profile_pin_and_closure_are_imported_from_h1f_not_copied",
    "test_static_workflow_keeps_existing_blocks_and_fully_constrains_the_authority_job",
    "test_static_launcher_stages_every_path_the_module_reads",
    "test_static_evidence_sanitizer_and_acceptance_rule",
    "test_static_seams_are_labelled_and_confined_to_their_cases",
    "test_static_production_has_no_named_namespace_raw_mark_api_or_wrong_publication_order",
    "test_static_doc_names_every_case_and_the_limits",
    "test_k8_generation_self_test_and_namespace_isolation_on_the_captured_kernel",
    "test_d1_two_generations_same_mark_stale_writer_bound_to_its_own_namespace",
    "test_d2_named_namespace_re_resolution_revives_a_key",
    "test_d3_counter_bound_refuses_before_any_process_is_spawned",
    "test_d4_stopped_helper_outlives_its_generation_and_writes_only_its_own_namespace",
    "test_d5_no_path_descriptor_or_foreign_handle_is_adopted",
    "test_d6_forked_owner_copy_refuses_every_operation_and_spawns_nothing",
    "test_t1_external_pidns_listener_as_cp_uid_pid_one",
    "test_t2_shared_pidns_profile_refuses_outside_and_accepts_inside",
    "test_t3_startup_refusals",
    "test_t4_publication_has_no_refused_window",
    "test_t4n_wrong_order_publisher_shows_refused_window",
    "test_t4f_listen_failure_leaves_the_working_endpoint",
    "test_t4r_close_leaves_a_replaced_endpoint",
    "test_t4s_stale_socket_file_is_replaced_by_a_listening_inode",
    "test_c2_no_owned_namespace_process_socket_mount_or_link_survives",
)
# Each dynamic case writes exactly one record: id -> (case function, control class, expected verdict).
RECORD_CASES = {
    "k8": ("test_k8_generation_self_test_and_namespace_isolation_on_the_captured_kernel", "provenance", "pass"),
    "d1": ("test_d1_two_generations_same_mark_stale_writer_bound_to_its_own_namespace", "domain", "pass"),
    "d2": ("test_d2_named_namespace_re_resolution_revives_a_key", "negative", "pass"),
    "d3": ("test_d3_counter_bound_refuses_before_any_process_is_spawned", "domain", "pass"),
    "d4": ("test_d4_stopped_helper_outlives_its_generation_and_writes_only_its_own_namespace", "domain", "pass"),
    "d5": ("test_d5_no_path_descriptor_or_foreign_handle_is_adopted", "domain", "pass"),
    "d6": ("test_d6_forked_owner_copy_refuses_every_operation_and_spawns_nothing", "domain", "pass"),
    "t1": ("test_t1_external_pidns_listener_as_cp_uid_pid_one", "peer", "pass"),
    "t2": ("test_t2_shared_pidns_profile_refuses_outside_and_accepts_inside", "peer", "pass"),
    "t3": ("test_t3_startup_refusals", "peer", "pass"),
    "t4": ("test_t4_publication_has_no_refused_window", "listener", "pass"),
    "t4n": ("test_t4n_wrong_order_publisher_shows_refused_window", "negative", "pass"),
    "t4f": ("test_t4f_listen_failure_leaves_the_working_endpoint", "listener", "pass"),
    "t4r": ("test_t4r_close_leaves_a_replaced_endpoint", "listener", "pass"),
    "t4s": ("test_t4s_stale_socket_file_is_replaced_by_a_listening_inode", "listener", "pass"),
    "c2": ("test_c2_no_owned_namespace_process_socket_mount_or_link_survives", "cleanup", "pass"),
}
CONTROLS = ("provenance", "domain", "negative", "peer", "listener", "cleanup")
VERDICTS = ("pass", "fail")
SETUP_FAILURES = ("wheel_hash_mismatch", "pytest_version_mismatch", "suite_setup_failed")
SEAMS = ("SEAM-COUNTER-START d3 only: the counter's start value, never ownership or reservation",
         "SEAM-NAMED-NAMESPACE d2 negative only: a stale writer that resolves a namespace by name",
         "SEAM-WRONG-ORDER t4n negative only: the test's own bind-rename-listen publisher",
         "SEAM-LISTEN-FAILURE t4f only: an injected listen that raises")
VERSION_TOKENS = ("kernel_release", "kernel_major_minor", "kernel_source_tag", "proc_version_sha256", "nft_version",
                  "nftables_package", "python", "pytest", "selftest", "readd_observation")
VERSION_INTS = ("config_hz", "tick_allowance_ms", "overflowuid", "cpu_count")


_H1F = None


def h1f():
    """H1F's launcher, imported by path for its reviewed closure, profile pin and helpers (never edited)."""
    global _H1F
    if _H1F is None:
        spec = importlib.util.spec_from_file_location("host_lease_feasibility", H1F_LAUNCHER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _H1F = module
    return _H1F


def h0():
    return h1f().h0()


ProofFailure = h1f().ProofFailure
FIXED_PATH = h1f().FIXED_PATH
HOST_TOOLS = h1f().HOST_TOOLS
PYTHON_VERSION = h1f().PYTHON_VERSION
PYTEST_VERSION = h1f().PYTEST_VERSION
PYTEST_CLOSURE = h1f().PYTEST_CLOSURE
SUPPORTED_KERNELS = h1f().SUPPORTED_KERNELS
READD_EXPECTED = h1f().READD_EXPECTED
kernel_profile = h1f().kernel_profile
artifact_scan = h1f().artifact_scan
_env = h1f()._env
_sha256 = h1f()._sha256


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
    """The H1F profile inputs, all from the K8 record (the generation self-test on this kernel)."""
    k8 = by_case.get("k8") or {"ints": {}, "tokens": {}}
    return {"kernel_major_minor": k8["tokens"].get("kernel_major_minor"), "nft_version": k8["tokens"].get("nft_version"),
            "config_hz": k8["ints"].get("config_hz"), "selftest": k8["tokens"].get("selftest"),
            "readd_observation": k8["tokens"].get("readd_observation")}


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
    k8 = by_case.get("k8") or {"ints": {}, "tokens": {}}
    lines = [f"{key} {k8['tokens'].get(key, 'unavailable')}" for key in VERSION_TOKENS]
    lines += [f"{key} {k8['ints'].get(key, 'unavailable')}" for key in VERSION_INTS]
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
    summary: dict = {"schema_version": "heel.host-authority-proof.summary.v1", "profile": PROFILE,
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
    root = Path("/tmp/heel-authority")
    for directory, mode in ((root, 0o755), (root / "home", 0o700), (root / "out", 0o700), (root / "work", 0o755)):
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
        print("usage: python scripts/host_authority_proof.py (no arguments; fixed authority-v1 profile)", file=sys.stderr)
        return 2
    if not sys.platform.startswith("linux"):
        print("result FAIL\nfailure platform_unavailable", flush=True)
        return 3
    if os.geteuid() == 0:
        return privileged_child()
    return parent()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
