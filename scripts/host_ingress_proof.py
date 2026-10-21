#!/usr/bin/env python3
"""Fixed ``ingress-v1`` host-ingress proof launcher (H0B).

SPDX-License-Identifier: LicenseRef-Heel-Commercial

Run from the repository root as exactly ``python scripts/host_ingress_proof.py``: one fixed
profile, no command, URL, ref, path or test-selector inputs. The unprivileged parent verifies
the candidate checkout, fetches every runtime input named in
``deploy/host/ingress/runtime-lock.json`` into private scratch and checks its SHA-256, builds
QuickJS/nginx+njs privately, installs the pinned wheels into a private venv and builds the Worker
artifact. It then starts one fixed privileged child (``sudo -n``; the child mode is selected only
by euid 0 plus a schema-checked JSON document on an inherited stdin pipe). That child creates an
outer network+mount+PID namespace with no external interface, mounts a private tmpfs, and runs
``HEEL_REQUIRE_HOST_INGRESS=1 python -m pytest -q tests/test_host_ingress.py`` inside it. Raw test
output stays in private memory; only fixed-field evidence is written, and every artifact is
scanned for the run's synthetic canaries before the job may upload it. Host network, firewall,
resolver, hosts and trust-store fingerprints are compared before and after. Any missing platform,
runtime, capability, case, skip or cleanup failure exits nonzero.
"""
from __future__ import annotations

import ctypes
import datetime
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import xml.etree.ElementTree as ElementTree
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "deploy" / "host" / "ingress" / "runtime-lock.json"
TEST_MODULE = "tests/test_host_ingress.py"
ARTIFACT_DIR = ROOT / "host-ingress-proof"
CHILD_SCHEMA = "heel.host-ingress-proof.child.v1"
PROOF_PATHS = (
    "deploy/host/ingress/nginx.conf", "deploy/host/ingress/policy.js", "deploy/host/ingress/runtime-lock.json",
    "tests/test_host_ingress.py", "tests/support/host_ingress_harness.py", "apps/heel-cloud/tests/host-ingress.test.ts",
    "scripts/host_ingress_proof.py", ".github/workflows/codeql.yml", "docs/saas/HOST_INGRESS_PROOF.md",
)
ARTIFACT_FILES = ("summary.json", "cases.jsonl", "versions.txt", "cleanup.json", "report.txt", "build-manifest.json")
# The fixed allowlist of tracked paths copied into the namespace (a static test proves it covers
# every PROOF_PATHS entry and every path the test module and harness read).
STAGE_PATHS = (
    "heel", "tests", "deploy/host/ingress", "pyproject.toml", "apps/heel-cloud/tests/host-ingress.test.ts",
    "scripts/host_ingress_proof.py", ".github/workflows/codeql.yml", "docs/saas/HOST_INGRESS_PROOF.md",
)
# Every case function in tests/test_host_ingress.py (a static test keeps this list exact).
REQUIRED_CASES = (
    "test_static_nfc_tables_are_regenerated_exactly_from_the_pinned_unicodedata",
    "test_static_policy_never_depends_on_runtime_normalize_or_dynamic_code",
    "test_static_required_profile_cannot_skip",
    "test_static_policy_has_no_race_and_never_clears_a_fired_timer",
    "test_static_launcher_requires_every_case_function_in_this_module",
    "test_static_launcher_has_one_fixed_profile_and_fixed_budgets",
    "test_static_launcher_evidence_is_fixed_fields_and_canary_scanned",
    "test_static_runtime_lock_pins_the_reviewed_runtime_and_records_its_lifecycle_dependency",
    "test_static_fake_vpc_adapter_block_is_pinned_by_both_suites",
    "test_static_renderer_substitutes_only_reviewed_tokens_from_closed_grammars",
    "test_static_nginx_template_keeps_the_reviewed_limits_and_literal_backend",
    "test_static_workflow_proof_job_is_manual_reviewed_ref_read_only_and_pinned",
    "test_static_launcher_stages_every_path_the_proof_module_reads",
    "test_static_fingerprint_normaliser_strips_timestamps_and_counters",
    "test_static_namespace_init_reaps_orphans_and_publishes_closed_leftover_records",
    "test_static_report_carries_a_failure_locator_for_every_failing_case",
    "test_static_cap_timing_telemetry_is_closed_bounded_and_published_before_the_cap_assertions",
    "test_g0_runtime_has_no_native_normalize_and_policy_carries_pinned_tables",
    "test_g0_nfc_of_every_code_point_matches_the_pinned_unicodedata",
    "test_g0_nfc_of_composition_and_reordering_sequences_matches_the_pinned_unicodedata",
    "test_g0_request_scanner_unicode_and_canonical_cases",
    "test_g0_request_scanner_refuses_invalid_utf8",
    "test_g0_request_scanner_refuses_a_byte_order_mark",
    "test_g0_request_scanner_accepts_exactly_python_canonical_bytes",
    "test_g3_owner_signup_and_runner_pairing_over_both_listeners",
    "test_g3_signed_context_list_claim_and_projection_submission",
    "test_g3_human_run_approval_then_claim_passes_the_unchanged_grant_verifier",
    "test_g3_heartbeat_progress_resync_and_restart_with_the_retained_key",
    "test_g3_second_slot_pairs_and_claims_independently",
    "test_g1_worker_management_requests_use_name_h_at_the_fixed_private_destination",
    "test_g1_query_and_unrouted_paths_never_reach_the_binding",
    "test_g2_login_and_session_checks_continue_through_the_ingress",
    "test_g2_wrong_origin_and_duplicate_credentials_are_refused_before_any_binding_call",
    "test_g2_cross_workspace_human_action_is_refused_by_the_real_cp",
    "test_g2_management_listener_refuses_outside_the_worker_contract_without_cp_contact",
    "test_g2_management_control_with_the_correct_edge_secret_reaches_cp",
    "test_g4_wrong_trust_name_and_missing_sni_fail_the_handshake",
    "test_g4_wrong_name_or_expired_ingress_leaf_is_refused_by_the_real_runner_transport",
    "test_g4_validly_certified_alias_fails_ingress_name_policy",
    "test_g4_host_differing_from_sni_is_refused",
    "test_g4_second_valid_leaf_reload_keeps_the_same_origin_and_runner_authority",
    "test_g4_wrong_runner_key_proof_passes_ingress_syntax_and_fails_cp_without_state_change",
    "test_g5_identities_swapped_across_slots_are_refused_before_cp",
    "test_g5_slot_b_identity_presented_at_slot_a_listener_is_refused",
    "test_g5_well_formed_forgery_reaches_cp_and_fails_without_state_change",
    "test_g5_unusable_registry_denies_before_cp_contact",
    "test_g5_registry_owned_by_another_uid_denies",
    "test_g5_slot_phase_gates_runner_claims",
    "test_g5_unapproved_pairing_activation_reaches_cp_and_is_refused",
    "test_g6_reused_invitation_is_refused_by_ingress_phase_and_by_cp",
    "test_g6_exact_activation_retry_returns_the_original_receipt_without_a_second_action",
    "test_g6_mutated_claim_retries_fail_without_a_second_action",
    "test_g6_stale_unseen_request_fails_at_cp",
    "test_g6_request_from_a_superseded_generation_fails_after_resync",
    "test_g7_raw_wire_variant_is_refused_without_cp_contact",
    "test_g7_g7_cases_cover_the_whole_table",
    "test_g8_largest_contract_valid_projection_submission_stays_below_the_carried_cp_framing_cap",
    "test_g8_projection_boundaries_with_real_pop_reach_the_handler_then_cp_framing_then_ingress",
    "test_g8_truncated_body_never_forwards_and_extra_bytes_never_reach_a_second_action",
    "test_g8_slow_headers_are_cut_off_without_cp_contact",
    "test_g8_client_disconnect_mid_body_leaves_no_pending_work",
    "test_g8_dribbled_runner_body_is_refused_at_the_total_deadline",
    "test_g8_dribbled_management_body_is_refused_at_the_total_deadline",
    "test_g8_body_completed_either_side_of_the_deadline",
    "test_g8_late_body_never_produces_a_second_response_or_cp_contact",
    "test_g8_listener_connection_cap_holds_at_eight_and_releases_at_the_deadline",
    "test_g8_mixed_load_of_expiring_holds_and_valid_requests",
    "test_g3_owner_stop_then_runner_stop_ack_through_both_listeners",
    "test_g3_runner_signed_terminal_result_is_accepted_by_cp",
    "test_g3_registered_rotation_swaps_keys_and_the_old_key_fails",
    "test_g3_g6_sqlite_repeat_of_pairing_claim_and_replay",
    "test_g4_forged_grant_from_another_key_reaches_the_unchanged_verifier_and_fails",
    "test_g8_scripted_upstream_responses_become_fixed_refusals",
    "test_g8_slow_upstream_is_cut_at_the_total_budget_without_late_delivery",
    "test_g8_upstream_reply_inside_the_budget_is_delivered_unchanged",
    "test_g1_upstream_redirect_is_not_followed_by_the_worker",
    "test_g9_slot_a_cannot_reach_its_sibling_cp_or_management",
    "test_g9_namespaces_have_no_default_route_and_the_outer_namespace_has_only_loopback",
    "test_g9_runner_processes_have_no_capabilities",
    "test_g9_ingress_worker_survived_every_case",
    "test_g9_every_owned_process_and_namespace_is_removed",
)
FIXED_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
LAUNCHER_SECONDS = 1200
TESTS_SECONDS = 720
# Staging and tests end this long before LAUNCHER_SECONDS, so sanitized evidence, the canary scan
# and cleanup finish inside the workflow step's own 20-minute timeout.
CLEANUP_RESERVE_SECONDS = 60


class ProofFailure(RuntimeError):
    """A fixed, value-free failure label."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _run(argv: list[str], *, cwd: Path, env: dict[str, str], timeout: float, label: str) -> float:
    """Run one build step; its output is kept private (never printed or uploaded)."""
    started = time.monotonic()
    try:
        completed = subprocess.run(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, capture_output=True,
                                   timeout=max(1.0, timeout))
    except subprocess.TimeoutExpired:
        raise ProofFailure(f"{label}_timeout") from None
    if completed.returncode != 0:
        raise ProofFailure(f"{label}_failed")
    return round(time.monotonic() - started, 3)


def _build_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {"PATH": FIXED_PATH, "LC_ALL": "C", "LANG": "C", "HOME": os.environ.get("HOME", "/nonexistent")}
    env.update(extra or {})
    return env


def load_lock(path: Path = LOCK) -> dict:
    lock = json.loads(path.read_text(encoding="utf-8"))
    if lock.get("schema_version") != "heel.host-ingress-runtime-lock.v1" or lock.get("profile") != "ingress-v1":
        raise ProofFailure("lock_schema")
    for item in lock["sources"] + [lock["node"]] + lock["tools"] + lock["python"]["wheels"]:
        if (not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])
                or not re.fullmatch(r"https://(nginx\.org|codeload\.github\.com|bellard\.org|github\.com|nodejs\.org|files\.pythonhosted\.org)/[A-Za-z0-9._/+-]+", item["url"])):
            raise ProofFailure("lock_entry")
    if lock["budgets"] != {"launcher_seconds": LAUNCHER_SECONDS, "tests_seconds": TESTS_SECONDS, "job_minutes": 30}:
        raise ProofFailure("lock_budget")
    return lock


def fetch(url: str, expected: str, target: Path) -> str:
    if not url.startswith("https://"):
        raise ProofFailure("fetch_scheme")
    request = urllib.request.Request(url, headers={"User-Agent": "heel-host-ingress-proof/1"})
    digest = hashlib.sha256()
    with urllib.request.urlopen(request, timeout=120) as response, open(target, "wb") as handle:  # noqa: S310 - https only
        for block in iter(lambda: response.read(1 << 20), b""):
            digest.update(block)
            handle.write(block)
    if digest.hexdigest() != expected:
        target.unlink()
        raise ProofFailure("archive_hash_mismatch")
    return digest.hexdigest()


def _extract(archive: Path, destination: Path) -> None:
    with tarfile.open(archive) as bundle:
        bundle.extractall(destination, filter="data")


def lint_workflow(lock: dict, scratch: Path, timings: dict) -> dict:
    """The pinned actionlint against the checked-out workflow (output private, exit only)."""
    (tool,) = [item for item in lock["tools"] if item["name"] == "actionlint"]
    directory = scratch / "actionlint"
    directory.mkdir(mode=0o700)
    archive = directory / Path(tool["url"]).name
    verified = fetch(tool["url"], tool["sha256"], archive)
    with tarfile.open(archive) as bundle:
        bundle.extract(tool["member"], directory, filter="data")
    timings["actionlint"] = _run([str(directory / tool["member"]), "-no-color", ".github/workflows/codeql.yml"],
                                 cwd=ROOT, env=_build_env(), timeout=120, label="actionlint")
    return {"actionlint": verified}


def candidate_provenance() -> dict:
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
    status = subprocess.run(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=ROOT,
                            capture_output=True, text=True, check=True).stdout
    missing = [path for path in PROOF_PATHS if not (ROOT / path).is_file()]
    if status.strip() or missing or not re.fullmatch(r"[0-9a-f]{40}", head):
        raise ProofFailure("candidate_not_clean")
    tracked = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout
    names = sorted(name for name in tracked.decode().split("\0") if name)
    files = {name: _sha256(ROOT / name) for name in PROOF_PATHS}
    return {"candidate_sha": head, "tracked_files": len(names), "proof_files": files}


def stage_runtime(lock: dict, scratch: Path, deadline: float, timings: dict) -> dict:
    downloads, build = scratch / "downloads", scratch / "build"
    downloads.mkdir(mode=0o700)
    build.mkdir(mode=0o700)
    verified = {}
    for source in lock["sources"]:
        archive = downloads / Path(source["url"]).name
        started = time.monotonic()
        verified[source["name"]] = fetch(source["url"], source["sha256"], archive)
        _extract(archive, build)
        timings[f"fetch_{source['name']}"] = round(time.monotonic() - started, 3)
    directories = {source["name"]: build / source["directory"] for source in lock["sources"]}
    environment = _build_env(lock["build"]["environment"])
    jobs = str(max(2, os.cpu_count() or 2))
    timings["build_quickjs"] = _run(["make", "-j" + jobs, *lock["build"]["quickjs_make_targets"]],
                                    cwd=directories["quickjs"], env=environment, timeout=deadline - time.monotonic(),
                                    label="build_quickjs")
    prefix = scratch / "runtime" / "nginx"
    substitutions = {"prefix": str(prefix), "openssl": str(directories["openssl"]), "pcre2": str(directories["pcre2"]),
                     "njs": str(directories["njs"]), "quickjs": str(directories["quickjs"])}
    configure = [argument.format(**substitutions) for argument in lock["build"]["nginx_configure"]]
    nginx_env = dict(environment)
    nginx_env.pop("CFLAGS")
    timings["configure_nginx"] = _run(["./configure", *configure], cwd=directories["nginx"], env=nginx_env,
                                      timeout=deadline - time.monotonic(), label="configure_nginx")
    timings["build_nginx"] = _run(["make", "-j" + jobs], cwd=directories["nginx"], env=nginx_env,
                                  timeout=deadline - time.monotonic(), label="build_nginx")
    event_method = nginx_event_method((directories["nginx"] / "objs" / "ngx_auto_config.h").read_text(encoding="utf-8"))
    binary = scratch / "runtime" / "nginx" / "sbin" / "nginx"
    binary.parent.mkdir(parents=True)
    shutil.copy2(directories["nginx"] / "objs" / "nginx", binary)
    version = subprocess.run([str(binary), "-V"], capture_output=True, text=True, timeout=10, env=_build_env())
    lines = version.stderr.splitlines()
    for expected in lock["build"]["expected_version_lines"]:
        if expected not in lines:
            raise ProofFailure("nginx_version_mismatch")
    node = lock["node"]
    archive = downloads / Path(node["url"]).name
    verified["node"] = fetch(node["url"], node["sha256"], archive)
    _extract(archive, scratch / "runtime")
    node_root = scratch / "runtime" / node["directory"]
    node_version = subprocess.run([str(node_root / "bin" / "node"), "--version"], capture_output=True, text=True,
                                  timeout=10, env=_build_env()).stdout.strip()
    if node_version != "v" + node["version"]:
        raise ProofFailure("node_version_mismatch")
    return {"verified_sources": verified, "nginx": str(binary), "nginx_version_lines": lines,
            "node_root": str(node_root), "node_version": node_version, "nginx_sha256": _sha256(binary),
            "event_method": event_method}


def nginx_event_method(auto_config: str) -> str:
    """One fixed line from the built ``objs/ngx_auto_config.h``: whether configure enabled epoll."""
    enabled = re.search(r"^#define NGX_HAVE_EPOLL +1$", auto_config, re.M) is not None
    return f"NGX_HAVE_EPOLL {int(enabled)}"


def stage_python(lock: dict, scratch: Path, deadline: float, timings: dict) -> dict:
    if f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}" != lock["python"]["version"]:
        raise ProofFailure("python_version_mismatch")
    import unicodedata

    if unicodedata.unidata_version != lock["python"]["unicodedata"]:
        raise ProofFailure("unicodedata_version_mismatch")
    venv = scratch / "venv"
    started = time.monotonic()
    subprocess.run([sys.executable, "-I", "-m", "venv", "--copies", "--without-pip", str(venv)], check=True,
                   env=_build_env(), timeout=120, capture_output=True)
    wheels = scratch / "wheels"
    wheels.mkdir(mode=0o700)
    files = []
    for wheel in lock["python"]["wheels"]:
        target = wheels / wheel["file"]
        fetch(wheel["url"], wheel["sha256"], target)
        files.append(str(target))
    subprocess.run([sys.executable, "-I", "-m", "pip", "--isolated", "--python", str(venv / "bin" / "python"), "install",
                    "--no-index", "--no-deps", "--no-cache-dir", "--no-compile", *files],
                   check=True, env=_build_env({"PIP_CONFIG_FILE": "/dev/null", "PYTHONNOUSERSITE": "1"}),
                   timeout=max(1.0, deadline - time.monotonic()), capture_output=True)
    timings["python_venv"] = round(time.monotonic() - started, 3)
    return {"venv": str(venv), "python_version": lock["python"]["version"], "wheels": len(files)}


def stage_app(lock: dict, scratch: Path, node_root: str, deadline: float, timings: dict) -> dict:
    app = lock["app"]
    if _sha256(ROOT / app["lockfile"]) != app["lockfile_sha256"]:
        raise ProofFailure("app_lockfile_mismatch")
    tracked = subprocess.run(["git", "ls-files", "-z", app["directory"]], cwd=ROOT, capture_output=True, check=True).stdout
    destination = scratch / "app-src"
    for name in (item for item in tracked.decode().split("\0") if item):
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / name, target)
    # tests/fixtures referenced by the app tests sit beside the app in the repository layout.
    for name in (item for item in subprocess.run(["git", "ls-files", "-z", "tests/fixtures", "tests/support/host_ingress_harness.py",
                                                  "deploy/host/ingress"], cwd=ROOT, capture_output=True,
                                                 check=True).stdout.decode().split("\0") if item):
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / name, target)
    workdir = destination / app["directory"]
    env = _build_env({"PATH": f"{node_root}/bin:{FIXED_PATH}", "HOME": str(scratch / "npm-home"), "CI": "true",
                      "npm_config_cache": str(scratch / "npm-cache"), "npm_config_update_notifier": "false"})
    timings["app_install"] = _run(app["install"], cwd=workdir, env=env, timeout=deadline - time.monotonic(), label="app_install")
    timings["app_component_test"] = _run(app["component_test"], cwd=workdir, env=env,
                                         timeout=deadline - time.monotonic(), label="app_component_test")
    timings["app_build"] = _run(app["build"], cwd=workdir, env=dict(env, **app["build_environment"]),
                                timeout=deadline - time.monotonic(), label="app_build")
    dist = workdir / "dist"
    manifest = {str(path.relative_to(dist)): _sha256(path) for path in sorted(dist.rglob("*")) if path.is_file()}
    return {"dist": str(dist), "dist_files": len(manifest),
            "dist_manifest_sha256": hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest(),
            "server_index_sha256": manifest.get("server/index.js")}


def stage_tree(scratch: Path) -> Path:
    """Copy the tracked files under STAGE_PATHS (never .git, never untracked state)."""
    tracked = subprocess.run(["git", "ls-files", "-z", "--", *STAGE_PATHS], cwd=ROOT, capture_output=True, check=True).stdout
    names = [item for item in tracked.decode().split("\0") if item]
    if not set(PROOF_PATHS) <= set(names):
        raise ProofFailure("stage_incomplete")
    source = scratch / "stage" / "src"
    for name in names:
        target = source / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / name, target)
    return source


# ---------------------------------------------------------------------------------------------
# Privileged child: outer namespaces, private tmpfs, the fixed suite, host fingerprints.

_CLONE_NEWNS, _CLONE_NEWNET, _CLONE_NEWPID = 0x00020000, 0x40000000, 0x20000000
_MS_REC, _MS_PRIVATE, _MS_NOSUID, _MS_NODEV = 16384, 1 << 18, 2, 4


FINGERPRINT_COMMANDS = {
    "links": ("ip", "-o", "link", "show"), "addresses": ("ip", "-o", "addr", "show"),
    "routes4": ("ip", "-4", "route", "show", "table", "all"), "routes6": ("ip", "-6", "route", "show", "table", "all"),
    "netns": ("ip", "netns", "list"), "nft": ("nft", "-s", "list", "ruleset"), "iptables": ("iptables-save",),
}
FINGERPRINT_NAMES = frozenset(FINGERPRINT_COMMANDS) | {"hosts", "resolv", "trust_store", "sysctls", "mounts"}


def normalize_fingerprint_output(name: str, stdout: str) -> str:
    """Remove only volatile bytes: iptables-save's dated ``# Generated by``/``# Completed on`` lines and
    its chain packet/byte counters, and any nft counter values (``nft -s`` already omits them)."""
    if name == "iptables":
        lines = [line for line in stdout.splitlines(keepends=True)
                 if not re.fullmatch(r"# (Generated by|Completed on) [^\n]*\n?", line)]
        return "".join(re.sub(r"^(:\S+ \S+) \[[0-9]+:[0-9]+\](\n?)$", r"\1 [-:-]\2", line) for line in lines)
    if name == "nft":
        return re.sub(r"\bcounter packets [0-9]+ bytes [0-9]+", "counter", stdout)
    return stdout


def stable_fingerprints(snapshot=None, pause=time.sleep) -> tuple[dict, list[str]]:
    """Two snapshots two seconds apart; the keys that differ make the host baseline unusable."""
    snapshot = snapshot or host_fingerprints
    first = snapshot()
    pause(2)
    second = snapshot()
    return second, sorted(key for key in set(first) | set(second) if first.get(key) != second.get(key))


def host_fingerprints() -> dict:
    def command(name: str) -> str:
        try:
            completed = subprocess.run(list(FINGERPRINT_COMMANDS[name]), capture_output=True, text=True, timeout=20,
                                       env=_build_env())
            output = normalize_fingerprint_output(name, completed.stdout)
            return hashlib.sha256((str(completed.returncode) + output).encode()).hexdigest()
        except (OSError, subprocess.TimeoutExpired):
            return "unavailable"

    def file_digest(path: str) -> str:
        try:
            return _sha256(Path(path))
        except OSError:
            return "absent"

    sysctls = {}
    for name in ("net/ipv4/ip_forward", "net/ipv4/ip_unprivileged_port_start", "net/ipv6/conf/all/disable_ipv6"):
        try:
            sysctls[name] = Path("/proc/sys/" + name).read_text().strip()
        except OSError:
            sysctls[name] = "absent"
    return {
        **{name: command(name) for name in FINGERPRINT_COMMANDS},
        "hosts": file_digest("/etc/hosts"), "resolv": file_digest("/etc/resolv.conf"),
        "trust_store": file_digest("/etc/ssl/certs/ca-certificates.crt"), "sysctls": sysctls,
        "mounts": hashlib.sha256(Path("/proc/self/mountinfo").read_bytes()).hexdigest(),
    }


# Leftover evidence: namespace-local PID, state letter, PPID and a fixed role label only.
LEFTOVER_ROLES = ("ingress_nginx", "worker_node", "suite_python", "exited", "unreadable", "other")
LEFTOVER_RECORD_LIMIT = 32
_LEFTOVER_KEYS = {"pid", "state", "ppid", "role"}


def reap_children(waitpid=os.waitpid) -> int:
    """Collect every exited child of this process (PID 1 inherits orphans); never blocks."""
    reaped = 0
    while True:
        try:
            pid, _status = waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return reaped
        if pid == 0:
            return reaped
        reaped += 1


def leftover_records(proc: Path, self_pid: int, roles: dict[str, str]) -> list[dict]:
    """Every other process in this PID namespace. The role comes from comparing /proc/<pid>/exe with
    the staged binaries; the path itself, argv and environment are never read into evidence."""
    records = []
    for entry in proc.iterdir():
        if not entry.name.isdigit() or int(entry.name) == self_pid:
            continue
        try:
            fields = (entry / "stat").read_text().rsplit(")", 1)[1].split()
            state, ppid = fields[0], int(fields[1])
        except (OSError, IndexError, ValueError):
            continue  # exited and reaped while listing
        try:
            role = roles.get(os.readlink(entry / "exe"), "other")
        except OSError:
            role = "exited" if state in "ZX" else "unreadable"
        records.append({"pid": int(entry.name), "state": state, "ppid": ppid, "role": role})
    return sorted(records, key=lambda record: record["pid"])


def kill_and_reap(records: list[dict], *, kill=os.kill, count=None, waitpid=os.waitpid, pause=time.sleep) -> int:
    """SIGKILL every leftover, reap what reparents to this init, and return how many remain."""
    for record in records:
        try:
            kill(record["pid"], signal.SIGKILL)
        except OSError:
            pass
    count = count or (lambda: len(leftover_records(Path("/proc"), os.getpid(), {})))
    for _attempt in range(50):
        reap_children(waitpid)
        remaining = count()
        if remaining == 0:
            return 0
        pause(0.1)
    return remaining


def sanitize_leftovers(records) -> list[dict]:
    clean = []
    for record in records if isinstance(records, list) else []:
        if (not isinstance(record, dict) or set(record) != _LEFTOVER_KEYS
                or any(type(record[key]) is not int for key in ("pid", "ppid"))
                or not (1 <= record["pid"] <= 4194304 and 0 <= record["ppid"] <= 4194304)
                or not (isinstance(record["state"], str) and re.fullmatch(r"[RSDZTtXxKWPI]", record["state"]))
                or record["role"] not in LEFTOVER_ROLES):
            continue
        clean.append({key: record[key] for key in ("pid", "state", "ppid", "role")})
    return clean[:LEFTOVER_RECORD_LIMIT]


def _libc():
    return ctypes.CDLL(None, use_errno=True)


def _mount(libc, source: str | None, target: str, kind: str | None, flags: int, data: str | None = None) -> None:
    if libc.mount(None if source is None else source.encode(), target.encode(),
                  None if kind is None else kind.encode(), flags, None if data is None else data.encode()) != 0:
        raise OSError(ctypes.get_errno(), "mount " + target)


def _inside(request: dict) -> int:
    """PID 1 of the outer PID namespace: private mounts, the fixed suite, then exit (kills all)."""
    libc = _libc()
    _mount(libc, None, "/", None, _MS_REC | _MS_PRIVATE)
    _mount(libc, "proc", "/proc", "proc", _MS_NOSUID | _MS_NODEV)
    _mount(libc, "tmpfs", "/tmp", "tmpfs", _MS_NOSUID | _MS_NODEV, "mode=0755,size=4g")
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True, env=_build_env(), timeout=10)
    root = Path("/tmp/heel-ingress")
    shutil.copytree(request["stage"], root, symlinks=False)
    for directory, names, files in os.walk(root):
        os.chmod(directory, 0o755)
        for name in files:
            path = Path(directory) / name
            os.chmod(path, 0o755 if os.access(path, os.X_OK) else 0o644)
    out = root / "out"
    out.mkdir(mode=0o700)
    (root / "home").mkdir(mode=0o700)
    environment = {
        "root": str(root), "python": str(root / "venv" / "bin" / "python"), "nginx": str(root / "runtime" / "nginx" / "sbin" / "nginx"),
        "node": str(root / "runtime" / "node" / "bin" / "node"), "worker_dist": str(root / "dist"),
        "openapi_fixture": str(root / "src" / "tests" / "fixtures" / "canary" / "staging-openapi.json"),
        "verified": request["verified"],
    }
    (root / "environment.json").write_text(json.dumps(environment), encoding="utf-8")
    env = {"PATH": FIXED_PATH, "LC_ALL": "C", "HOME": str(root / "home"), "TMPDIR": str(root / "home"),
           "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1", "HEEL_REQUIRE_HOST_INGRESS": "1",
           "HEEL_HOST_INGRESS_ENVIRONMENT": str(root / "environment.json"),
           "HEEL_HOST_INGRESS_CASES": str(out / "cases.raw.jsonl"), "HEEL_HOST_INGRESS_CANARIES": str(out / "canaries.json")}
    roles = {os.path.realpath(environment["nginx"]): "ingress_nginx", os.path.realpath(environment["node"]): "worker_node",
             os.path.realpath(environment["python"]): "suite_python"}
    started = time.monotonic()
    process = subprocess.Popen([environment["python"], "-m", "pytest", "-q", "-p", "no:cacheprovider", "-o", "console_output_style=classic", "-o", "xfail_strict=true",
                                f"--junitxml={out / 'junit.xml'}", TEST_MODULE],
                               cwd=root / "src", env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, start_new_session=True)
    try:
        _output, _ = process.communicate(timeout=request["tests_seconds"])  # private; never written
        code = process.returncode
        timed_out = False
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.communicate()
        code, timed_out = 124, True
    pytest_seconds = round(time.monotonic() - started, 3)
    # PID 1 inherits every orphan: reap the exited ones first so a zombie is never counted as live,
    # then record, kill and reap whatever is still here. Any leftover still fails the run.
    reaped = reap_children()
    records = leftover_records(Path("/proc"), os.getpid(), roles)
    remaining = kill_and_reap(records)
    result = {"pytest_exit": code, "timed_out": timed_out, "pytest_seconds": pytest_seconds,
              "seconds": round(time.monotonic() - started, 3), "reaped_before_count": reaped,
              "leftover_processes": len(records), "leftover_records": records[:LEFTOVER_RECORD_LIMIT],
              "leftover_after_kill": remaining}
    (out / "inner.json").write_text(json.dumps(result), encoding="utf-8")
    target = Path(request["out"])
    for name in ("junit.xml", "cases.raw.jsonl", "canaries.json", "inner.json"):
        if (out / name).exists():
            shutil.copyfile(out / name, target / name)
            os.chown(target / name, request["uid"], request["uid"])
            os.chmod(target / name, 0o600)
    return 0


def privileged_child() -> int:
    raw = sys.stdin.read(65536)
    request = json.loads(raw)
    if set(request) != {"schema", "stage", "out", "uid", "verified", "tests_seconds"} or request["schema"] != CHILD_SCHEMA:
        return 2
    if not 1 <= request["tests_seconds"] <= TESTS_SECONDS or not Path(request["stage"]).is_dir():
        return 2
    before, unstable = stable_fingerprints()
    if unstable:
        # A host baseline that changes on its own cannot show that cleanup left the host unchanged.
        cleanup = {"namespace_child_exit": None, "host_fingerprints_unchanged": False, "differing_fingerprints": [],
                   "unstable_fingerprints": unstable, "fingerprint_names": sorted(before)}
        target = Path(request["out"]) / "cleanup.raw.json"
        target.write_text(json.dumps(cleanup), encoding="utf-8")
        os.chown(target, request["uid"], request["uid"])
        return 1
    child = os.fork()
    if child == 0:
        try:
            os.unshare(_CLONE_NEWNET | _CLONE_NEWNS | _CLONE_NEWPID)
            init = os.fork()
            if init == 0:
                try:
                    os._exit(_inside(request))
                except BaseException:  # noqa: BLE001 - a fixed failure code only
                    os._exit(70)
            _pid, status = os.waitpid(init, 0)
            os._exit(os.waitstatus_to_exitcode(status) if os.WIFEXITED(status) else 71)
        except BaseException:  # noqa: BLE001
            os._exit(72)
    _pid, status = os.waitpid(child, 0)
    inner_exit = os.waitstatus_to_exitcode(status)
    after = host_fingerprints()
    differing = sorted(key for key in before if before[key] != after[key])
    cleanup = {"namespace_child_exit": inner_exit, "host_fingerprints_unchanged": not differing,
               "differing_fingerprints": differing, "unstable_fingerprints": [], "fingerprint_names": sorted(before)}
    target = Path(request["out"]) / "cleanup.raw.json"
    target.write_text(json.dumps(cleanup), encoding="utf-8")
    os.chown(target, request["uid"], request["uid"])
    return 0 if inner_exit == 0 and not differing else 1


# ---------------------------------------------------------------------------------------------
# Parent: staging, the fixed child, sanitized evidence.

# Failure locators: case, repository-relative test file, line, and one token from this closed set.
# The exception type is read privately only to choose the token; no message, operand, traceback,
# path outside the repository or payload is ever published.
LOCATOR_REASONS = {
    "AssertionError": "assertion_failed", "Failed": "explicit_fail", "TimeoutExpired": "timeout",
    "TimeoutError": "timeout", "timeout": "timeout", "JSONDecodeError": "json_decode_error",
    "FileNotFoundError": "file_not_found", "PermissionError": "permission_error", "ConnectionRefusedError": "connection_error",
    "ConnectionResetError": "connection_error", "BrokenPipeError": "connection_error", "ConnectionError": "connection_error",
    "SSLError": "tls_error", "SSLCertVerificationError": "tls_error", "OSError": "os_error", "KeyError": "lookup_error",
    "IndexError": "lookup_error", "TypeError": "type_error", "ValueError": "value_error", "AttributeError": "attribute_error",
    "CalledProcessError": "subprocess_error", "StopIteration": "lookup_error",
}
LOCATOR_TOKENS = frozenset(LOCATOR_REASONS.values()) | {"other_exception", "setup_error", "teardown_error", "skipped"}
LOCATOR_LIMIT = 256
_LOCATOR_KEYS = {"case", "file", "line", "reason"}


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
    return {"case": base, "file": TEST_MODULE, "line": lines[-1] if lines else 0, "reason": reason}


def sanitize_locators(locators) -> list[dict]:
    clean = []
    for item in locators if isinstance(locators, list) else []:
        if (isinstance(item, dict) and set(item) == _LOCATOR_KEYS and isinstance(item["case"], str)
                and re.fullmatch(r"test_[a-z0-9_]{1,160}", item["case"]) and item["file"] == TEST_MODULE
                and type(item["line"]) is int and 0 <= item["line"] <= 100000 and item["reason"] in LOCATOR_TOKENS):
            entry = {key: item[key] for key in ("case", "file", "line", "reason")}
            if entry not in clean:
                clean.append(entry)
    return sorted(clean, key=lambda entry: (entry["case"], entry["line"], entry["reason"]))[:LOCATOR_LIMIT]


def summarize_junit(path: Path) -> dict:
    if not path.exists():
        return {"collected": 0, "passed": 0, "failed": 0, "errors": 0, "skipped": 0, "case_functions": [], "failing": [],
                "failure_locators": []}
    tree = ElementTree.parse(path)
    counts = {"collected": 0, "passed": 0, "failed": 0, "errors": 0, "skipped": 0}
    functions, failing, locators = set(), [], []
    for case in tree.iter("testcase"):
        name = case.get("name", "")
        base = name.split("[", 1)[0]
        if not re.fullmatch(r"test_[a-z0-9_]{1,160}", base):
            continue
        counts["collected"] += 1
        functions.add(base)
        for kind, counter in (("failure", "failed"), ("error", "errors"), ("skipped", "skipped")):
            element = case.find(kind)
            if element is not None:
                counts[counter] += 1
                failing.append(base)
                locators.append(_failure_locator(base, kind, element))
                break
        else:
            counts["passed"] += 1
    return {**counts, "case_functions": sorted(functions), "failing": sorted(set(failing)),
            "failure_locators": sanitize_locators(locators)}


_CASE_KEYS = {"case", "gate", "status", "reasons", "cp_contacted", "changed_tables", "seam", "telemetry"}
MAX_CASE_LINE = 4096
# The one optional telemetry object (H0BR2, G8 connection-cap timing): exactly these keys, each a plain
# int in its range (None only for the two envelope keys), plus the consistency rules below. Anything
# else -- bool, float, string, nesting, a missing or unknown key -- publishes "telemetry": null.
TELEMETRY_RANGES = {
    "holds": (0, 8), "holds_unmeasured": (0, 8), "holds_early": (0, 8), "holds_late": (0, 8),
    "first_byte_ms_min": (-120000, 120000), "first_byte_ms_max": (-120000, 120000),
    "probes": (0, 64), "probes_503": (0, 64), "probes_admitted": (0, 1),
}
TELEMETRY_NULLABLE = frozenset({"first_byte_ms_min", "first_byte_ms_max"})


def sanitize_telemetry(value) -> dict | None:
    if not isinstance(value, dict) or set(value) != set(TELEMETRY_RANGES):
        return None
    for key, (low, high) in TELEMETRY_RANGES.items():
        item = value[key]
        if not (item is None and key in TELEMETRY_NULLABLE) and not (type(item) is int and low <= item <= high):
            return None
    measured = value["holds"] - value["holds_unmeasured"]
    low, high = value["first_byte_ms_min"], value["first_byte_ms_max"]
    if not (measured >= 0 and value["holds_early"] + value["holds_late"] <= measured
            and (low is None) == (high is None) == (measured == 0) and (low is None or low <= high)
            and value["probes_503"] + value["probes_admitted"] <= value["probes"]):
        return None
    return {key: value[key] for key in sorted(TELEMETRY_RANGES)}


def _no_constant(name: str):
    raise ValueError("non-finite number")


def sanitize_cases(raw: Path) -> list[dict]:
    cases = []
    if not raw.exists():
        return cases
    for line in raw.read_text(encoding="utf-8").splitlines()[:5000]:
        if len(line) > MAX_CASE_LINE:
            continue
        try:
            entry = json.loads(line, parse_constant=_no_constant)
        except (ValueError, RecursionError):
            continue
        if (not isinstance(entry, dict) or not set(entry) <= _CASE_KEYS or not isinstance(entry.get("case"), str)
                or not re.fullmatch(r"[a-z0-9_.-]{1,160}", entry["case"])):
            continue
        gate = entry.get("gate")
        clean = {"case": entry["case"], "gate": gate if isinstance(gate, str) and re.fullmatch(r"G[0-9]", gate) else "?"}
        if isinstance(entry.get("status"), int) or entry.get("status") is None:
            clean["status"] = entry.get("status")
        clean["cp_contacted"] = entry.get("cp_contacted") if isinstance(entry.get("cp_contacted"), bool) else None
        reasons, tables = entry.get("reasons"), entry.get("changed_tables")
        clean["reasons"] = [r for r in (reasons if isinstance(reasons, list) else [])
                            if isinstance(r, str) and re.fullmatch(r"[a-z_]+:[a-z_:0-9-]{1,80}", r)]
        clean["changed_tables"] = [t for t in (tables if isinstance(tables, list) else [])
                                   if isinstance(t, str) and re.fullmatch(r"[a-z_]{1,64}", t)]
        clean["seam"] = entry.get("seam") if isinstance(entry.get("seam"), str) and re.fullmatch(r"[A-Za-z0-9 ,._-]{1,80}", entry["seam"]) else None
        if "telemetry" in entry:
            clean["telemetry"] = sanitize_telemetry(entry["telemetry"])
        cases.append(clean)
    return cases


def cpu_count_line(cpu_count=os.cpu_count) -> str:
    """Hosted-runner context for timing evidence (not causality): the CPU count, or a fixed unavailable."""
    value = cpu_count()
    return f"cpu_count {value}" if type(value) is int and 1 <= value <= 4096 else "cpu_count unavailable"


def report_lines(summary: dict, failure: str | None, cleanup: dict) -> list[str]:
    """The fixed report.txt lines (also printed to the job log)."""
    report = [f"result {summary['result']}", f"failure {failure}", f"candidate {summary.get('candidate_sha')}"]
    tests = summary.get("tests") or {}
    report += [f"{key} {tests.get(key)}" for key in ("collected", "passed", "failed", "errors", "skipped")]
    report += [f"failing {name}" for name in (tests.get("failing") or [])]
    report += [f"locator {item['case']} {item['file']}:{item['line']} {item['reason']}"
               for item in sanitize_locators(tests.get("failure_locators"))]
    report += [f"missing {name}" for name in summary.get("missing_required_cases", [])]
    if "leftover_processes" in cleanup:
        report.append(f"leftover_processes {cleanup['leftover_processes']}")
    report += [f"leftover {item['pid']} {item['state']} {item['ppid']} {item['role']}"
               for item in sanitize_leftovers(cleanup.get("leftover_records"))]
    report += [f"unstable_fingerprint {name}" for name in sorted(set(cleanup.get("unstable_fingerprints") or [])
                                                                 & FINGERPRINT_NAMES)]
    return report


def canary_scan(directory: Path, canaries: list[str]) -> list[str]:
    generic = [rb"-----BEGIN [A-Z ]*PRIVATE KEY-----", rb"heel_session=[A-Za-z0-9_-]{8,}", rb"invitation_token",
               rb"X-Heel-Edge-Auth: [A-Za-z0-9_-]{20,}"]
    flagged = []
    for path in sorted(directory.iterdir()):
        data = path.read_bytes()
        if any(canary and canary.encode() in data for canary in canaries) or any(re.search(p, data) for p in generic):
            flagged.append(path.name)
    return flagged


def parent() -> int:
    started = time.monotonic()
    deadline = started + LAUNCHER_SECONDS - CLEANUP_RESERVE_SECONDS
    timings: dict[str, float] = {}
    summary: dict = {"schema_version": "heel.host-ingress-proof.summary.v1", "profile": "ingress-v1",
                     "utc_start": datetime.datetime.now(datetime.timezone.utc).isoformat(), "result": "FAIL",
                     "seams": ["SEAM-TEST-CA", "SEAM-FAKE-VPC adapter (not Cloudflare/workerd)", "SEAM-REGISTRY fixture controller",
                               "SEAM-RUNNER-SECRET RAM backend", "SEAM-ENV-DNS", "SEAM-SCRIPTED-BACKEND (response negatives only)"]}
    scratch = Path(tempfile.mkdtemp(prefix="heel-host-ingress-", dir=os.environ.get("RUNNER_TEMP") or None))
    os.chmod(scratch, 0o711)
    exit_code = 1
    failure = None
    cleanup: dict = {}
    versions: list[str] = []
    try:
        # Provenance first: the evidence directory below must not make the checkout look dirty.
        summary.update(candidate_provenance())
        ARTIFACT_DIR.mkdir(exist_ok=True)
        lock = load_lock()
        summary["lock_sha256"] = _sha256(LOCK)
        tools = lint_workflow(lock, scratch, timings)
        runtime = stage_runtime(lock, scratch, deadline, timings)
        python = stage_python(lock, scratch, deadline, timings)
        app = stage_app(lock, scratch, runtime["node_root"], deadline, timings)
        source = stage_tree(scratch)
        stage = source.parent
        shutil.copytree(python["venv"], stage / "venv", symlinks=True)
        (stage / "runtime" / "nginx" / "sbin").mkdir(parents=True)
        shutil.copy2(runtime["nginx"], stage / "runtime" / "nginx" / "sbin" / "nginx")
        shutil.copytree(runtime["node_root"], stage / "runtime" / "node", symlinks=True)
        shutil.copytree(app["dist"], stage / "dist")
        os.chmod(scratch / "stage", 0o755)
        versions = runtime["nginx_version_lines"] + [runtime["event_method"], f"node {runtime['node_version']}",
                                                      f"python {python['python_version']}", f"kernel {os.uname().release}",
                                                      f"platform {sys.platform}", cpu_count_line()]
        build_manifest = {"nginx_sha256": runtime["nginx_sha256"], "verified_sources": runtime["verified_sources"],
                          "verified_tools": tools, "nginx_event_method": runtime["event_method"],
                          "wheels": python["wheels"], **{k: app[k] for k in ("dist_files", "dist_manifest_sha256", "server_index_sha256")}}
        (ARTIFACT_DIR / "build-manifest.json").write_text(json.dumps(build_manifest, indent=2, sort_keys=True) + "\n")
        remaining = int(deadline - time.monotonic())
        if remaining < 60:
            raise ProofFailure("budget_exhausted_before_tests")
        out = scratch / "out"
        out.mkdir(mode=0o700)
        request = {"schema": CHILD_SCHEMA, "stage": str(stage), "out": str(out), "uid": os.getuid(),
                   "verified": {"candidate_sha": summary["candidate_sha"], "sources": runtime["verified_sources"],
                                "lock_sha256": summary["lock_sha256"], "nginx_version_lines": runtime["nginx_version_lines"],
                                "node_version": runtime["node_version"], "python_version": python["python_version"]},
                   "tests_seconds": min(TESTS_SECONDS, remaining - 30)}
        child_started = time.monotonic()
        child = subprocess.run(["sudo", "-n", "--", sys.executable, "-I", str(Path(__file__).resolve())],
                               input=json.dumps(request).encode(), capture_output=True, timeout=remaining,
                               env={"PATH": FIXED_PATH, "LC_ALL": "C"})
        timings["privileged_child"] = round(time.monotonic() - child_started, 3)
        inner = json.loads((out / "inner.json").read_text()) if (out / "inner.json").exists() else {}
        cleanup = json.loads((out / "cleanup.raw.json").read_text()) if (out / "cleanup.raw.json").exists() else {}
        if isinstance(inner.get("pytest_seconds"), (int, float)):
            timings["inner_pytest"] = round(float(inner["pytest_seconds"]), 3)
        cleanup = {key: cleanup.get(key) for key in ("namespace_child_exit", "host_fingerprints_unchanged",
                                                     "differing_fingerprints", "unstable_fingerprints", "fingerprint_names")
                   if key in cleanup}
        for key in ("differing_fingerprints", "unstable_fingerprints", "fingerprint_names"):
            if key in cleanup:
                cleanup[key] = sorted(set(cleanup[key] or []) & FINGERPRINT_NAMES)
        cleanup.update(child_exit=child.returncode, leftover_processes=inner.get("leftover_processes"),
                       leftover_records=sanitize_leftovers(inner.get("leftover_records")),
                       leftover_after_kill=inner.get("leftover_after_kill"), reaped_before_count=inner.get("reaped_before_count"))
        if cleanup.get("unstable_fingerprints"):
            raise ProofFailure("fingerprint_unstable")
        junit = summarize_junit(out / "junit.xml")
        cases = sanitize_cases(out / "cases.raw.jsonl")
        canaries = json.loads((out / "canaries.json").read_text()) if (out / "canaries.json").exists() else []
        missing = sorted(set(REQUIRED_CASES) - set(junit["case_functions"]))
        summary.update(tests=junit, missing_required_cases=missing, pytest_exit=inner.get("pytest_exit"),
                       tests_timed_out=inner.get("timed_out"), case_records=len(cases))
        (ARTIFACT_DIR / "cases.jsonl").write_text("".join(json.dumps(case, sort_keys=True) + "\n" for case in cases))
        passed = (child.returncode == 0 and inner.get("pytest_exit") == 0 and not missing and junit["skipped"] == 0
                  and junit["failed"] == 0 and junit["errors"] == 0 and junit["collected"] > 0
                  and cleanup.get("host_fingerprints_unchanged") is True and inner.get("leftover_processes") == 0)
        summary["result"] = "PASS" if passed else "FAIL"
        exit_code = 0 if passed else 1
    except ProofFailure as error:
        failure = error.code
    except Exception as error:  # noqa: BLE001 - a fixed class name only, never a message
        failure = "unexpected_" + type(error).__name__
    finally:
        ARTIFACT_DIR.mkdir(exist_ok=True)
        summary.update(failure=failure, timings=timings, seconds=round(time.monotonic() - started, 3),
                       budgets={"launcher_seconds": LAUNCHER_SECONDS, "tests_seconds": TESTS_SECONDS})
        (ARTIFACT_DIR / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
        (ARTIFACT_DIR / "versions.txt").write_text("\n".join(versions) + "\n")
        (ARTIFACT_DIR / "cleanup.json").write_text(json.dumps(cleanup, indent=2, sort_keys=True) + "\n")
        report = report_lines(summary, failure, cleanup)
        (ARTIFACT_DIR / "report.txt").write_text("\n".join(report) + "\n")
        for name in ARTIFACT_FILES:
            (ARTIFACT_DIR / name).touch()
        canaries = locals().get("canaries") or []
        flagged = canary_scan(ARTIFACT_DIR, canaries)
        if flagged:
            for name in flagged:
                (ARTIFACT_DIR / name).write_text('{"suppressed":"canary scan"}\n')
            exit_code = 1
        shutil.rmtree(scratch, ignore_errors=True)
        print("\n".join(report), flush=True)
    return exit_code


def main(argv: list[str]) -> int:
    if argv:
        print("usage: python scripts/host_ingress_proof.py (no arguments; fixed ingress-v1 profile)", file=sys.stderr)
        return 2
    if not sys.platform.startswith("linux"):
        print("result FAIL\nfailure platform_unavailable", flush=True)
        return 3
    if os.geteuid() == 0:
        return privileged_child()
    return parent()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
