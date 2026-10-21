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
            "node_root": str(node_root), "node_version": node_version, "nginx_sha256": _sha256(binary)}


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
    """Copy tracked sources the proof imports (never .git, never untracked state)."""
    tracked = subprocess.run(["git", "ls-files", "-z", "heel", "tests", "deploy/host/ingress", "pyproject.toml"],
                             cwd=ROOT, capture_output=True, check=True).stdout
    source = scratch / "stage" / "src"
    for name in (item for item in tracked.decode().split("\0") if item):
        target = source / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / name, target)
    return source


# ---------------------------------------------------------------------------------------------
# Privileged child: outer namespaces, private tmpfs, the fixed suite, host fingerprints.

_CLONE_NEWNS, _CLONE_NEWNET, _CLONE_NEWPID = 0x00020000, 0x40000000, 0x20000000
_MS_REC, _MS_PRIVATE, _MS_NOSUID, _MS_NODEV = 16384, 1 << 18, 2, 4


def host_fingerprints() -> dict:
    def command(argv: list[str]) -> str:
        try:
            completed = subprocess.run(argv, capture_output=True, text=True, timeout=20, env=_build_env())
            return hashlib.sha256((str(completed.returncode) + completed.stdout).encode()).hexdigest()
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
        "links": command(["ip", "-o", "link", "show"]), "addresses": command(["ip", "-o", "addr", "show"]),
        "routes4": command(["ip", "-4", "route", "show", "table", "all"]), "routes6": command(["ip", "-6", "route", "show", "table", "all"]),
        "netns": command(["ip", "netns", "list"]), "nft": command(["nft", "list", "ruleset"]),
        "iptables": command(["iptables-save"]), "hosts": file_digest("/etc/hosts"), "resolv": file_digest("/etc/resolv.conf"),
        "trust_store": file_digest("/etc/ssl/certs/ca-certificates.crt"), "sysctls": sysctls,
        "mounts": hashlib.sha256(Path("/proc/self/mountinfo").read_bytes()).hexdigest(),
    }


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
    leftovers = 0
    for entry in Path("/proc").iterdir():
        if entry.name.isdigit() and int(entry.name) != os.getpid():
            leftovers += 1
            try:
                os.kill(int(entry.name), signal.SIGKILL)
            except OSError:
                pass
    result = {"pytest_exit": code, "timed_out": timed_out, "seconds": round(time.monotonic() - started, 3),
              "leftover_processes": leftovers}
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
    before = host_fingerprints()
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
               "differing_fingerprints": differing, "fingerprint_names": sorted(before)}
    target = Path(request["out"]) / "cleanup.raw.json"
    target.write_text(json.dumps(cleanup), encoding="utf-8")
    os.chown(target, request["uid"], request["uid"])
    return 0 if inner_exit == 0 and not differing else 1


# ---------------------------------------------------------------------------------------------
# Parent: staging, the fixed child, sanitized evidence.

def summarize_junit(path: Path) -> dict:
    if not path.exists():
        return {"collected": 0, "passed": 0, "failed": 0, "errors": 0, "skipped": 0, "case_functions": [], "failing": []}
    tree = ElementTree.parse(path)
    counts = {"collected": 0, "passed": 0, "failed": 0, "errors": 0, "skipped": 0}
    functions, failing = set(), []
    for case in tree.iter("testcase"):
        name = case.get("name", "")
        base = name.split("[", 1)[0]
        if not re.fullmatch(r"test_[a-z0-9_]{1,160}", base):
            continue
        counts["collected"] += 1
        functions.add(base)
        if case.find("failure") is not None:
            counts["failed"] += 1
            failing.append(base)
        elif case.find("error") is not None:
            counts["errors"] += 1
            failing.append(base)
        elif case.find("skipped") is not None:
            counts["skipped"] += 1
            failing.append(base)
        else:
            counts["passed"] += 1
    return {**counts, "case_functions": sorted(functions), "failing": sorted(set(failing))}


_CASE_KEYS = {"case", "gate", "status", "reasons", "cp_contacted", "changed_tables", "seam"}


def sanitize_cases(raw: Path) -> list[dict]:
    cases = []
    if not raw.exists():
        return cases
    for line in raw.read_text(encoding="utf-8").splitlines()[:5000]:
        entry = json.loads(line)
        if not set(entry) <= _CASE_KEYS or not re.fullmatch(r"[a-z0-9_.-]{1,160}", entry["case"]):
            continue
        clean = {"case": entry["case"], "gate": entry["gate"] if re.fullmatch(r"G[0-9]", entry.get("gate", "")) else "?"}
        if isinstance(entry.get("status"), int) or entry.get("status") is None:
            clean["status"] = entry.get("status")
        clean["cp_contacted"] = entry.get("cp_contacted") if isinstance(entry.get("cp_contacted"), bool) else None
        clean["reasons"] = [r for r in entry.get("reasons", []) if isinstance(r, str) and re.fullmatch(r"[a-z_]+:[a-z_:0-9-]{1,80}", r)]
        clean["changed_tables"] = [t for t in entry.get("changed_tables", []) if isinstance(t, str) and re.fullmatch(r"[a-z_]{1,64}", t)]
        clean["seam"] = entry.get("seam") if isinstance(entry.get("seam"), str) and re.fullmatch(r"[A-Za-z0-9 ,._-]{1,80}", entry["seam"]) else None
        cases.append(clean)
    return cases


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
        versions = runtime["nginx_version_lines"] + [f"node {runtime['node_version']}", f"python {python['python_version']}",
                                                      f"kernel {os.uname().release}", f"platform {sys.platform}"]
        build_manifest = {"nginx_sha256": runtime["nginx_sha256"], "verified_sources": runtime["verified_sources"],
                          "verified_tools": tools,
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
        cleanup.update(child_exit=child.returncode, leftover_processes=inner.get("leftover_processes"))
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
        report = [f"result {summary['result']}", f"failure {failure}", f"candidate {summary.get('candidate_sha')}"]
        tests = summary.get("tests") or {}
        report += [f"{key} {tests.get(key)}" for key in ("collected", "passed", "failed", "errors", "skipped")]
        report += [f"failing {name}" for name in (tests.get("failing") or [])]
        report += [f"missing {name}" for name in summary.get("missing_required_cases", [])]
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
