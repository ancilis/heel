#!/usr/bin/env python3
"""Fixed ``lease-v1`` host-lease feasibility launcher (H1F).

SPDX-License-Identifier: LicenseRef-Heel-Commercial

Run from the repository root as exactly ``python scripts/host_lease_feasibility.py``: one fixed
profile, no command, path, ref or test-selector inputs. The unprivileged parent verifies the clean
candidate checkout and the pinned Python, confirms that every host tool the proof runs is already
present (it never installs one), lints the workflow with H0's pinned actionlint and fetches the
pytest wheel closure that ``deploy/host/ingress/runtime-lock.json`` already pins for H0 (each URL
and SHA-256 must also equal the copy in ``PYTEST_CLOSURE``). It then starts one fixed privileged
child (``sudo -n``; the child mode is selected only by euid 0 plus a schema-checked JSON document
on stdin). The child re-checks the tools, takes stable host fingerprints and creates an outer
network+mount+PID namespace with only loopback and a private tmpfs. Inside, it copies the fixed
proof files from this checkout, re-hashes the wheels, installs them offline into a private venv and
runs ``HEEL_REQUIRE_HOST_LEASE_PROOF=1 python -m pytest -q tests/linux/test_host_lease_primitive.py``.
Every packet experiment runs in inner network namespaces the suite creates and destroys; nothing
touches the host's interfaces, rulesets or services. Raw test output stays in private memory; only
closed-grammar evidence is written and scanned for the run token. Exit 0 only for PASS: every case
ran (no skip), every oracle held, cleanup left the host fingerprints unchanged and the captured
kernel is inside the supported profile. A clean run on an unsupported profile is INCOMPLETE, never
PASS. This is a proof of kernel primitive and peer-credential facts only, not of H1A/H2/H3.
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
H0_LAUNCHER = ROOT / "scripts" / "host_ingress_proof.py"
H0_LOCK = ROOT / "deploy" / "host" / "ingress" / "runtime-lock.json"
PROFILE = "lease-v1"
TEST_MODULE = "tests/linux/test_host_lease_primitive.py"
ARTIFACT_DIR = ROOT / "host-lease-feasibility"
ARTIFACT_FILES = ("summary.json", "cases.jsonl", "versions.txt", "cleanup.json", "report.txt")
CHILD_SCHEMA = "heel.host-lease-feasibility.child.v1"
REQUIRED_ENV = "HEEL_REQUIRE_HOST_LEASE_PROOF"
RECORDS_ENV = "HEEL_HOST_LEASE_RECORDS"
WORK_ENV = "HEEL_HOST_LEASE_WORK"
TOKEN_ENV = "HEEL_HOST_LEASE_TOKEN"
# The fixed tracked files the privileged child copies (byte for byte, from this checkout) into the
# namespace. A static test proves it covers every path the test module reads under ROOT.
STAGE_FILES = (
    "tests/linux/__init__.py", "tests/linux/test_host_lease_primitive.py", "scripts/host_lease_feasibility.py",
    "scripts/host_ingress_proof.py", ".github/workflows/codeql.yml", "docs/saas/HOST_LEASE_FEASIBILITY.md",
    "deploy/host/ingress/runtime-lock.json",
)
PYTHON_VERSION = "3.13.5"
PYTEST_VERSION = "9.0.2"
# (name, version, file, url, sha256): exactly the pytest 9.0.2 install closure on CPython 3.13
# (pytest's other requirements are Windows- or <3.11-only), copied from H0's runtime lock.
PYTEST_CLOSURE = (
    ("iniconfig", "2.3.1", "iniconfig-2.3.1-py3-none-any.whl",
     "https://files.pythonhosted.org/packages/56/43/4ca9e49d27a1fcf6bece6f6aec0ea46bb9112489b93d4b688fb415457bdb/iniconfig-2.3.1-py3-none-any.whl",
     "9121e2c1fdb355232495be3194c8dfe87ccc2d5dee45947b78e68f499790d7a7"),
    ("packaging", "26.3", "packaging-26.3-py3-none-any.whl",
     "https://files.pythonhosted.org/packages/63/34/ba1c580383c9eada3711951fef0795c80b829a078d72188184bcab9dd527/packaging-26.3-py3-none-any.whl",
     "d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c"),
    ("pluggy", "1.7.0", "pluggy-1.7.0-py3-none-any.whl",
     "https://files.pythonhosted.org/packages/40/9e/2b38731e0fc536806f16490e1a12d7f0dc2a1235aa8cc07bcc75416a7daa/pluggy-1.7.0-py3-none-any.whl",
     "7dd7b0d8832ba3cb632c306926ded123429211b83641b35dc5c41ad2d34f9bec"),
    ("pygments", "2.21.0", "pygments-2.21.0-py3-none-any.whl",
     "https://files.pythonhosted.org/packages/71/46/17f022dd3e953bf20a04a028a21ec746d942f8d2af30fa0f124fa0e6a684/pygments-2.21.0-py3-none-any.whl",
     "2363c69b61c4a97c838da3b130dcd6468f4848992b21a82f2a63ec34377137d9"),
    ("pytest", "9.0.2", "pytest-9.0.2-py3-none-any.whl",
     "https://files.pythonhosted.org/packages/3b/ab/b3226f0bd7cdcf710fbede2b3548584366da3b19b5021e74f5bde2a8fa3f/pytest-9.0.2-py3-none-any.whl",
     "711ffd45bf766d5264d487b917733b453d917afd2b0ad65223959f59089f875b"),
)
FIXED_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
# Tools the proof itself runs; util-linux is recorded (A12) but not invoked: namespaces are entered
# with os.unshare/os.setns. Missing tools fail before any fingerprint or namespace is created.
HOST_TOOLS = ("nft", "ip", "iptables-save")
LAUNCHER_SECONDS = 1200
TESTS_SECONDS = 600
CLEANUP_RESERVE_SECONDS = 60
# The supported profile (H1DR section 3.4): the source tags whose cited functions were pinned, the
# nftables release, CONFIG_HZ, and the non-EXCL re-add behaviour each tag's source implies.
SUPPORTED_KERNELS = {"6.8": "v6.8", "6.17": "v6.17", "7.0": "v7.0"}
SUPPORTED_NFT = ("1.0.9",)
SUPPORTED_HZ = (100, 250, 1000)
READD_EXPECTED = {"6.8": "noop", "6.17": "refresh", "7.0": "refresh"}

# Every case function in the test module, in file order (a static test keeps this list exact).
REQUIRED_CASES = (
    "test_static_required_profile_cannot_skip",
    "test_static_launcher_requires_every_case_function_and_record_in_this_module",
    "test_static_launcher_has_one_fixed_profile_fixed_budgets_and_no_inputs",
    "test_static_pytest_closure_is_the_h0_locked_wheel_set_installed_offline",
    "test_static_workflow_existing_jobs_match_the_recorded_f04ab70_baseline",
    "test_static_workflow_lease_job_is_manual_literal_branch_read_only_and_pinned",
    "test_static_launcher_stages_every_path_the_module_reads",
    "test_static_gate_batches_never_rewrite_a_prepared_key_and_activation_carries_no_lifetime",
    "test_static_marks_are_distinct_nonzero_and_reuse_is_confined_to_named_controls",
    "test_static_oracles_reject_always_drop_stale_allow_and_rounded_violation_traces",
    "test_static_evidence_sanitizer_keeps_only_the_closed_grammar",
    "test_static_nft_readback_parsers_and_error_classes",
    "test_static_kernel_profile_needs_tag_nft_hz_selftest_and_matching_readd_semantics",
    "test_static_peer_cases_keep_production_permissions_outside_the_labelled_seam",
    "test_static_doc_names_every_case_and_the_limits",
    "test_a12_kernel_nft_provenance_recorded_and_compatibility_self_test",
    "test_n1_relative_ttl_post_delete_admits_packets_after_deadline_when_installer_dies",
    "test_n2_gate_without_mark_reset_admits_a_carried_mark",
    "test_n3_recreating_an_expired_key_revives_a_stale_reference",
    "test_a1_prepared_gate_composition_parses_and_installs",
    "test_a2_prepared_only_admits_nothing_even_with_a_carried_mark",
    "test_a3_prompt_activation_admits_live_authority_traffic",
    "test_a4_stale_activation_after_expiry_with_cleanup_withheld_admits_zero_packets",
    "test_a5_activation_then_supervisor_death_stops_at_prepared_expiry",
    "test_a6_renewal_swap_has_no_gap_and_old_mark_expiry_is_irrelevant",
    "test_a7_live_create_collision_fails_closed_and_expired_key_accepts_fresh_create",
    "test_a8_reference_to_expired_key_does_not_revive_and_live_readd_semantics_recorded",
    "test_a9_short_timeout_expires_no_later_than_prepare_return_plus_timeout",
    "test_a10_prepare_and_activate_bracket_distribution_under_concurrent_transactions",
    "test_a11_readback_expires_never_exceeds_requested_timeout",
    "test_a13_stale_reference_admits_nothing_while_a_different_fresh_key_is_live",
    "test_b1_meta_time_absolute_rule_informative",
    "test_p1_unix_peercred_is_mutual_under_the_production_permissions",
    "test_p2_checking_server_in_a_user_namespace_that_cannot_map_the_client_sees_overflowuid",
    "test_p3_server_in_a_child_pid_namespace_sees_the_root_uid_with_pid_zero",
    "test_c1_no_owned_namespace_process_socket_or_link_survives",
)
# Each dynamic case writes exactly one record: id -> (case function, control class, expected verdict).
RECORD_CASES = {
    "a12": ("test_a12_kernel_nft_provenance_recorded_and_compatibility_self_test", "provenance", "pass"),
    "n1": ("test_n1_relative_ttl_post_delete_admits_packets_after_deadline_when_installer_dies", "negative", "pass"),
    "n2": ("test_n2_gate_without_mark_reset_admits_a_carried_mark", "negative", "pass"),
    "n3": ("test_n3_recreating_an_expired_key_revives_a_stale_reference", "negative", "pass"),
    "a1": ("test_a1_prepared_gate_composition_parses_and_installs", "positive", "pass"),
    "a2": ("test_a2_prepared_only_admits_nothing_even_with_a_carried_mark", "positive", "pass"),
    "a3": ("test_a3_prompt_activation_admits_live_authority_traffic", "positive", "pass"),
    "a4": ("test_a4_stale_activation_after_expiry_with_cleanup_withheld_admits_zero_packets", "positive", "pass"),
    "a5": ("test_a5_activation_then_supervisor_death_stops_at_prepared_expiry", "positive", "pass"),
    "a6": ("test_a6_renewal_swap_has_no_gap_and_old_mark_expiry_is_irrelevant", "positive", "pass"),
    "a7": ("test_a7_live_create_collision_fails_closed_and_expired_key_accepts_fresh_create", "positive", "pass"),
    "a8": ("test_a8_reference_to_expired_key_does_not_revive_and_live_readd_semantics_recorded", "positive", "pass"),
    "a9": ("test_a9_short_timeout_expires_no_later_than_prepare_return_plus_timeout", "positive", "pass"),
    "a10": ("test_a10_prepare_and_activate_bracket_distribution_under_concurrent_transactions", "measurement", "pass"),
    "a11": ("test_a11_readback_expires_never_exceeds_requested_timeout", "positive", "pass"),
    "a13": ("test_a13_stale_reference_admits_nothing_while_a_different_fresh_key_is_live", "positive", "pass"),
    "b1": ("test_b1_meta_time_absolute_rule_informative", "informative", "info"),
    "p1": ("test_p1_unix_peercred_is_mutual_under_the_production_permissions", "peer", "pass"),
    "p2": ("test_p2_checking_server_in_a_user_namespace_that_cannot_map_the_client_sees_overflowuid", "peer", "pass"),
    "p3": ("test_p3_server_in_a_child_pid_namespace_sees_the_root_uid_with_pid_zero", "peer", "pass"),
    "c1": ("test_c1_no_owned_namespace_process_socket_or_link_survives", "cleanup", "pass"),
}
VERDICTS = ("pass", "fail", "info")
SETUP_FAILURES = ("wheel_hash_mismatch", "pytest_version_mismatch", "suite_setup_failed")
SEAMS = ("SEAM-PERMISSIVE-SOCKET p2 converse only: exposes kernel uid mapping, not the production profile",)
VERSION_TOKENS = ("kernel_release", "kernel_major_minor", "kernel_source_tag", "proc_version_sha256", "nft_version",
                  "nftables_package", "util_linux", "python", "pytest", "selftest")
VERSION_INTS = ("config_hz", "tick_allowance_ms", "overflowuid", "cpu_count")


class ProofFailure(RuntimeError):
    """A fixed, value-free failure label."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


_H0 = None


def h0():
    """H0's launcher, imported by path for its reviewed fetch/fingerprint/reaping helpers (never edited)."""
    global _H0
    if _H0 is None:
        spec = importlib.util.spec_from_file_location("host_ingress_proof", H0_LAUNCHER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _H0 = module
    return _H0


def _sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {"PATH": FIXED_PATH, "LC_ALL": "C", "LANG": "C", "TZ": "UTC", "HOME": os.environ.get("HOME", "/nonexistent")}
    env.update(extra or {})
    return env


# ---------------------------------------------------------------------------------------------
# Closed evidence grammar and the supported-profile rule (shared with the test module).

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
    """Sanitized records and the number of raw lines that were dropped."""
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


def kernel_profile(fields: dict) -> tuple[str, list[str]]:
    """``pinned`` only when the captured runtime is one the pinned sources describe and behaves as
    they say; otherwise ``unpinned`` with closed reasons (the run is then held, never PASS)."""
    reasons = []
    major_minor = fields.get("kernel_major_minor")
    if major_minor not in SUPPORTED_KERNELS:
        reasons.append("kernel_outside_pinned_tags")
    if fields.get("nft_version") not in SUPPORTED_NFT:
        reasons.append("nft_outside_pinned_release")
    if fields.get("config_hz") not in SUPPORTED_HZ:
        reasons.append("config_hz_unavailable_or_unsupported")
    if fields.get("selftest") != "pass":
        reasons.append("compatibility_self_test_failed")
    if fields.get("readd_observation") != READD_EXPECTED.get(major_minor, "unknown"):
        reasons.append("readd_semantics_differ_from_source_tag")
    return ("pinned" if not reasons else "unpinned"), reasons


def profile_fields(by_case: dict) -> dict:
    a12, a8 = by_case.get("a12") or {"ints": {}, "tokens": {}}, by_case.get("a8") or {"ints": {}, "tokens": {}}
    return {"kernel_major_minor": a12["tokens"].get("kernel_major_minor"), "nft_version": a12["tokens"].get("nft_version"),
            "config_hz": a12["ints"].get("config_hz"), "selftest": a12["tokens"].get("selftest"),
            "readd_observation": a8["tokens"].get("readd_observation")}


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
    return {"candidate_sha": head, "proof_files": {name: _sha256(ROOT / name) for name in STAGE_FILES}}


def check_python() -> None:
    if f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}" != PYTHON_VERSION:
        raise ProofFailure("python_version_mismatch")


def missing_host_tools(which=shutil.which) -> list[str]:
    return [tool for tool in HOST_TOOLS if which(tool, path=FIXED_PATH) is None]


def closure_matches_lock(lock: dict) -> None:
    """The fixed closure must be byte-identical to H0's pinned entries (URL, file, hash, version)."""
    wheels = {wheel["name"]: wheel for wheel in lock["python"]["wheels"]}
    if lock["python"]["version"] != PYTHON_VERSION:
        raise ProofFailure("lock_python_mismatch")
    for name, version, filename, url, digest in PYTEST_CLOSURE:
        entry = wheels.get(name)
        if entry is None or (entry["version"], entry["file"], entry["url"], entry["sha256"]) != (version, filename, url, digest):
            raise ProofFailure("closure_differs_from_h0_lock")


def fetch_closure(scratch: Path) -> Path:
    wheels = scratch / "wheels"
    wheels.mkdir(mode=0o700)
    for _name, _version, filename, url, digest in PYTEST_CLOSURE:
        h0().fetch(url, digest, wheels / filename)
    return wheels


LOCATOR_REASONS = {"AssertionError": "assertion_failed", "Failed": "explicit_fail", "TimeoutExpired": "timeout",
                   "Empty": "timeout", "TimeoutError": "timeout", "PermissionError": "permission_error",
                   "FileNotFoundError": "file_not_found", "OSError": "os_error", "KeyError": "lookup_error",
                   "IndexError": "lookup_error", "TypeError": "type_error", "ValueError": "value_error",
                   "AttributeError": "attribute_error", "CalledProcessError": "subprocess_error"}
LOCATOR_TOKENS = frozenset(LOCATOR_REASONS.values()) | {"other_exception", "setup_error", "teardown_error", "skipped"}


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
    """First record per case id, and the ids that were written more than once."""
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
    a12 = by_case.get("a12") or {"ints": {}, "tokens": {}}
    lines = [f"{key} {a12['tokens'].get(key, 'unavailable')}" for key in VERSION_TOKENS]
    lines += [f"{key} {a12['ints'].get(key, 'unavailable')}" for key in VERSION_INTS]
    a8 = by_case.get("a8") or {"tokens": {}}
    lines.append(f"readd_observation {a8['tokens'].get('readd_observation', 'unavailable')}")
    lines.append(f"kernel_profile {profile}")
    return lines


def report_lines(summary: dict, failure: str | None, cleanup: dict) -> list[str]:
    tests = summary.get("tests") or {}
    report = [f"result {summary['result']}", f"failure {failure}", f"candidate {summary.get('candidate_sha')}",
              f"kernel_profile {summary.get('kernel_profile')}"]
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


def artifact_scan(directory: Path, token: str) -> list[str]:
    """Public files must never carry the run token, a path, a traceback or raw tool output."""
    patterns = [rb"Traceback", rb"/tmp/", rb"/proc/", rb"/home/", rb"Error:", rb"File \"", rb"-----BEGIN"]
    flagged = []
    for path in sorted(directory.iterdir()):
        data = path.read_bytes()
        if token.encode() in data or any(pattern in data for pattern in patterns):
            flagged.append(path.name)
    return flagged


def parent() -> int:
    started = time.monotonic()
    deadline = started + LAUNCHER_SECONDS - CLEANUP_RESERVE_SECONDS
    timings: dict[str, float] = {}
    summary: dict = {"schema_version": "heel.host-lease-feasibility.summary.v1", "profile": PROFILE,
                     "utc_start": datetime.datetime.now(datetime.timezone.utc).isoformat(), "result": "FAIL",
                     "kernel_profile": None, "seams": list(SEAMS),
                     "negative_controls": sorted(case for case, item in RECORD_CASES.items() if item[1] == "negative"),
                     "informative_cases": sorted(case for case, item in RECORD_CASES.items() if item[1] == "informative")}
    scratch = Path(tempfile.mkdtemp(prefix="heel-host-lease-", dir=os.environ.get("RUNNER_TEMP") or None))
    token = secrets.token_hex(16)
    exit_code, failure, cleanup, versions, by_case = 1, None, {}, [], {}
    try:
        # Provenance first: the evidence directory below must not make the checkout look dirty.
        summary.update(candidate_provenance())
        ARTIFACT_DIR.mkdir(exist_ok=True)
        check_python()
        missing = missing_host_tools()
        if missing:
            cleanup["missing_tools"] = missing
            raise ProofFailure("host_tool_missing")
        lock = h0().load_lock(H0_LOCK)
        closure_matches_lock(lock)
        summary["h0_lock_sha256"] = _sha256(H0_LOCK)
        h0().lint_workflow(lock, scratch, timings)
        wheels = fetch_closure(scratch)
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
    if target.name != name or not target.parent.name.startswith("heel-host-lease-"):
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
        os.chmod(target.parent, 0o755)
        shutil.copyfile(root / name, target)
        os.chmod(target, 0o644)
    return destination


def install_closure(wheel_bytes: dict[str, bytes], root: Path) -> Path:
    """Re-hash the in-memory wheels and install them with no index into a private venv."""
    wheels = root / "wheels"
    wheels.mkdir(mode=0o755)
    files = []
    for _name, _version, filename, _url, digest in PYTEST_CLOSURE:
        data = wheel_bytes[filename]
        if hashlib.sha256(data).hexdigest() != digest:
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
    version = subprocess.run([str(venv / "bin" / "python"), "-I", "-c", "import pytest; print(pytest.__version__)"],
                             capture_output=True, text=True, timeout=60, env=_env()).stdout.strip()
    if version != PYTEST_VERSION:
        raise ProofFailure("pytest_version_mismatch")
    return venv / "bin" / "python"


def _write_out(out_fd: int, name: str, payload: bytes, uid: int) -> None:
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600, dir_fd=out_fd)
    try:
        os.write(descriptor, payload)
        os.fchown(descriptor, uid, uid)
    finally:
        os.close(descriptor)


def _inside(request: dict, wheel_bytes: dict[str, bytes], out_fd: int) -> int:
    """PID 1 of the outer PID namespace: private mounts, the fixed suite, then exit (kills all)."""
    helper = h0()
    libc = helper._libc()
    helper._mount(libc, None, "/", None, helper._MS_REC | helper._MS_PRIVATE)
    helper._mount(libc, "proc", "/proc", "proc", helper._MS_NOSUID | helper._MS_NODEV)
    helper._mount(libc, "tmpfs", "/tmp", "tmpfs", helper._MS_NOSUID | helper._MS_NODEV, "mode=0755,size=1g")
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True, env=_env(), timeout=10, capture_output=True)
    root = Path("/tmp/heel-lease")
    for directory, mode in ((root, 0o755), (root / "home", 0o700), (root / "out", 0o700), (root / "work", 0o755)):
        directory.mkdir(mode=mode)
        os.chmod(directory, mode)
    try:
        source = stage_tree(root / "src")
        python = install_closure(wheel_bytes, root)
    except (ProofFailure, OSError, subprocess.SubprocessError) as error:
        code = error.code if isinstance(error, ProofFailure) else "suite_setup_failed"
        _write_out(out_fd, "inner.json", json.dumps({"setup_failure": code}).encode(), request["uid"])
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
    _write_out(out_fd, "inner.json", json.dumps(result).encode(), request["uid"])
    for name in ("junit.xml", "records.raw.jsonl"):
        if (out / name).exists():
            _write_out(out_fd, name, (out / name).read_bytes(), request["uid"])
    return 0


def loaded_modules(path: Path = Path("/proc/modules")) -> set[str]:
    """Kernel module names (closed token set). Creating a veth or an nft object may autoload a
    module on the shared kernel; that is recorded as evidence, never hidden or graded away."""
    try:
        return {line.split(" ", 1)[0] for line in path.read_text().splitlines()
                if re.fullmatch(r"[a-z0-9_]{1,56}", line.split(" ", 1)[0])}
    except OSError:
        return set()


def privileged_child() -> int:
    request = validated_request(sys.stdin.read(65536))
    if request is None:
        return 2
    out = Path(request["out"])

    def finish(cleanup: dict) -> None:
        target = out / "cleanup.raw.json"
        target.write_text(json.dumps(cleanup), encoding="utf-8")
        os.chown(target, request["uid"], request["uid"])

    missing = missing_host_tools()
    if missing:
        finish({"missing_tools": missing, "host_fingerprints_unchanged": False})
        return 1
    helper = h0()
    before, unstable = helper.stable_fingerprints()
    if unstable:
        # A host baseline that changes on its own cannot show that cleanup left the host unchanged.
        finish({"namespace_child_exit": None, "host_fingerprints_unchanged": False, "differing_fingerprints": [],
                "unstable_fingerprints": unstable})
        return 1
    modules_before = loaded_modules()
    # Read the wheels and open the output directory before /tmp is replaced inside the namespace.
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
            "kernel_modules_loaded": sorted(loaded_modules() - modules_before)[:64]})
    return 0 if inner_exit == 0 and not differing else 1


def main(argv: list[str]) -> int:
    if argv:
        print("usage: python scripts/host_lease_feasibility.py (no arguments; fixed lease-v1 profile)", file=sys.stderr)
        return 2
    if not sys.platform.startswith("linux"):
        print("result FAIL\nfailure platform_unavailable", flush=True)
        return 3
    if os.geteuid() == 0:
        return privileged_child()
    return parent()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
