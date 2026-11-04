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
import hmac
import importlib.util
import json
import os
import re
import secrets
import select
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
DIAG_KEY_ENV = "HEEL_HOST_H2_POLICY_DIAG_KEY"
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
    "heel/saas/managed_authority_contracts.py",
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
    ("cryptography", "50.0.1", "cryptography-50.0.1-cp311-abi3-manylinux_2_34_x86_64.whl",
     "51afcfceb15597cf2635068e4ac9a56b2abde622edde17f37d85fd7b5306497a"),
    ("cffi", "2.1.1", "cffi-2.1.1-cp313-cp313-manylinux2014_x86_64.manylinux_2_17_x86_64.whl",
     "a931079504ecc49efed7744c476a5c343a92fabf66dec2db95edb1b2fdc770e2"),
    ("pycparser", "3.11", "pycparser-3.11-py3-none-any.whl",
     "51d5a8ba2be0bbe440b99d2112604c95bbbc3c2748a64260186c541e1729cd80"),
)
CRYPTOGRAPHY_VERSION = "50.0.1"

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
# Supplementary host-link diagnostics (H2-LINK-DIAGNOSTICS-R1, bounded correction R2). Never part of
# the acceptance rule: the gate still hashes H0's own capture exactly as before. This describes that
# same captured ``ip -o link show`` text, keyed with a run-private HMAC key and bounded before any
# work (at most 64 lines, 4096 characters per line and 65536 in all are ever scanned), as one closed
# object in cleanup.json. Incomplete diagnostics can only hold a PASS back, never make one; a change
# class is an observation class, never actor attribution, and a name/MAC match with a fixture
# registry entry is a correlation only: no capture witnesses lifecycle continuity.

DIAG_SCHEMA = "heel.host-h2-policy-proof.link-diagnostics.v2"
OWNERSHIP_SCHEMA = "heel.host-h2-policy-proof.ownership.v1"
OWNERSHIP_FILE = "ownership.raw.jsonl"
DIAG_PHASES = ("baseline_first", "baseline_second", "after_namespace_exit")
DIAG_PAIRS = (("baseline", 0, 1), ("audit", 1, 2))
DIAG_LIMITS = {"links_per_capture": 64, "captures": 3, "fixture_endpoints": 32, "changed_entries": 64,
               "fields_per_link": 16, "driver_token_chars": 64, "commitment_hex_chars": 64, "payload_bytes": 262144,
               "ancillary_read_bytes": 65536, "ancillary_command_ms": 2000, "ancillary_total_ms": 5000,
               "line_chars": 4096, "scan_chars": 65536, "tokens_per_line": 64, "ownership_bytes": 65536, "sysfs_read_bytes": 64,
               "sysfs_link_chars": 512, "sysfs_components": 32}
DIAG_REASONS = ("capture_missing", "capture_not_ok", "line_cap", "line_length_cap", "scan_cap", "unsupported_encoding",
                "unsupported_syntax", "field_cap", "enrichment_timeout",
                "enrichment_cap", "enrichment_budget", "enrichment_failed", "enrichment_unknown", "namespace_mismatch",
                "collector_failed", "observer_failed", "ownership_missing", "ownership_invalid", "ownership_cap",
                "changed_cap", "payload_cap", "diagnostics_missing", "diagnostics_invalid")
CAPTURE_STATUSES = ("ok", "nonzero", "timeout", "oserror", "missing")
ENRICH_STATUSES = ("ok", "timeout", "oserror", "nonzero", "cap", "invalid", "budget", "namespace_mismatch", "not_run")
PARSE_STATUSES = ("complete", "incomplete", "not_applicable")
SCAN_STATES = ("complete", "truncated")
LINK_FLAGS = ("allmulti", "automedia", "broadcast", "debug", "dormant", "dynamic", "echo", "loopback", "lower_up", "m_down",
              "master", "multicast", "no_carrier", "noarp", "notrailers", "pointopoint", "portsel", "promisc", "running",
              "slave", "up")
OPERSTATES = ("unknown", "notpresent", "down", "lowerlayerdown", "testing", "dormant", "up")
LINK_TYPES = ("ether", "loopback", "none", "void", "ipip", "sit", "gre", "tunnel6", "ip6gre", "infiniband", "can", "ppp")
LINK_KINDS = ("none", "veth", "bridge", "bond", "team", "vlan", "macvlan", "macvtap", "ipvlan", "vxlan", "geneve", "gre",
              "gretap", "ip6gre", "ipip", "sit", "ip6tnl", "vti", "wireguard", "tun", "dummy", "ifb", "macsec", "vrf",
              "netkit", "nlmon", "xfrm", "other", "unknown")
BUSES = ("pci", "vmbus", "usb", "virtio", "platform", "xen", "auxiliary", "mdio_bus", "none", "other", "unknown")
DRIVERS = ("mlx5_core", "mlx4_core", "mlx4_en", "hv_netvsc", "virtio_net", "ena", "gve", "ixgbevf", "igbvf", "iavf",
           "i40e", "ice", "ixgbe", "igb", "e1000", "e1000e", "vmxnet3", "bnxt_en", "tg3", "r8169", "none", "unknown")
FIELD_LABELS = ("ifindex", "iflink", "peer", "flags", "operstate", "link_type", "mtu", "qlen", "mac", "master", "netnsid",
                "netns", "qdisc", "mode", "group", "brd", "peer_address", "permaddr", "altname", "alias", "vf", "unknown",
                "line")
PROVENANCE_LABELS = ("device_backed", "bus", "kind", "driver")
CHANGE_KINDS = ("added", "removed", "changed")
PROOF_IDENTITY = ("unknown", "not_applicable")  # never asserted: no capture witnesses lifecycle continuity
CORRELATIONS = ("fixture_name_mac", "ambiguous", "none", "not_applicable")
ATTRIBUTION = ("correlation_only",)
HARDWARE = ("device_backed", "virtual", "unknown")
DELTA_CLASSES = ("none", "command_status_change", "order_only_text_change", "fixture_name_mac_correlation",
                 "hardware_backed_change", "unknown")
OWNERSHIP_STATUSES = ("valid", "missing", "invalid", "capped")
_MS = 1_000_000
_HEX64 = re.compile(r"[0-9a-f]{64}")
_LINK_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}")


def link_commitment(key: bytes, kind: str, value: str) -> str:
    """The run-private keyed commitment of one raw value (a name, MAC, line or other text). Without
    the key, which never leaves the run, a commitment cannot be tested against a guessed value."""
    return hmac.new(key, kind.encode("ascii") + b"\0" + value.encode("utf-8", "surrogateescape"), hashlib.sha256).hexdigest()


def namespace_commitment(key: bytes, device: int, inode: int) -> str:
    return link_commitment(key, "netns", f"{device}:{inode}")


_LINK_HEAD = re.compile(r"([0-9]{1,10}): ([^\s:/@]{1,64})(?:@([^\s:/]{1,64}))?: <([A-Za-z0-9_,-]{0,512})>(?: (.*))?")
_SEGMENT = re.compile(r"\s*\\\s+")
_HEAD_KEYS = {"mtu": "int", "qdisc": "text", "master": "text", "state": "text", "mode": "text", "group": "text", "qlen": "int"}
_TAIL_KEYS = {"brd": "text", "peer": "text", "link-netnsid": "int", "link-netns": "text", "permaddr": "text"}
_KEY_FIELDS = {"link-netnsid": "netnsid", "link-netns": "netns", "state": "operstate", "peer": "peer_address"}


def _pairs(fields: dict, words: list[str], keys: dict) -> None:
    for index in range(0, len(words), 2):
        name = words[index]
        value = words[index + 1] if index + 1 < len(words) else None
        field = _KEY_FIELDS.get(name, name)
        if name not in keys or value is None or fields.get(field) is not None or (
                keys[name] == "int" and not re.fullmatch(r"-?[0-9]{1,10}", value)):
            fields["unknown"].append(" ".join(words[index:index + 2]))
            continue
        fields[field] = int(value) if keys[name] == "int" else value


def parse_link_line(line: str) -> dict | None:
    """One ``ip -o link show`` line into raw fields, in memory only. Text outside the supported grammar
    is kept in ``unknown`` (it still reaches the keyed ``other`` commitment) and is never normalized
    away; None means the line head itself is unsupported."""
    if not isinstance(line, str) or len(line) > DIAG_LIMITS["line_chars"]:
        return None
    segments = _SEGMENT.split(line.rstrip())
    head = _LINK_HEAD.fullmatch(segments[0])
    if head is None:
        return None
    fields: dict = {"ifindex": int(head[1]), "name": head[2], "iflink": None, "peer": None, "flags": [], "operstate": None,
                    "link_type": None, "mtu": None, "qlen": None, "mac": None, "master": None, "netnsid": None, "netns": None,
                    "qdisc": None, "mode": None, "group": None, "brd": None, "peer_address": None, "permaddr": None,
                    "altname": [], "alias": None, "vf": [], "unknown": [], "line": line,
                    "tokens": len(line.split())}
    if head[3] is not None:
        if re.fullmatch(r"if[0-9]{1,10}", head[3]):
            fields["iflink"] = int(head[3][2:])
        else:
            fields["peer"] = head[3]
    for flag in head[4].split(",") if head[4] else []:
        token = flag.lower().replace("-", "_")
        if token in LINK_FLAGS and token not in fields["flags"]:
            fields["flags"].append(token)
        else:
            fields["unknown"].append("flag " + flag)
    fields["flags"].sort()
    _pairs(fields, (head[5] or "").split(), _HEAD_KEYS)
    if fields["operstate"] is not None and fields["operstate"].lower() not in OPERSTATES:
        fields["unknown"].append("state " + fields["operstate"])
        fields["operstate"] = None
    elif fields["operstate"] is not None:
        fields["operstate"] = fields["operstate"].lower()
    for segment in segments[1:]:
        if segment.startswith("link/") and fields["link_type"] is None:
            kind, _sep, rest = segment.partition(" ")
            words = rest.split()
            fields["link_type"] = kind[5:]
            if words and words[0] not in _TAIL_KEYS:
                fields["mac"] = words.pop(0).lower()
            _pairs(fields, words, _TAIL_KEYS)
        elif segment.startswith("altname ") and len(segment.split()) == 2:
            fields["altname"].append(segment.split()[1])
        elif segment.startswith("alias ") and fields["alias"] is None:
            fields["alias"] = segment[6:]
        elif segment.startswith("vf "):
            fields["vf"].append(segment)
        else:
            fields["unknown"].append(segment)
    if fields["link_type"] is not None and fields["link_type"] not in LINK_TYPES:
        fields["unknown"].append("link/" + fields["link_type"])
    return fields


def scan_capture(key: bytes, stdout, *, parse: bool) -> dict:
    """The only pass the diagnostics make over a captured text, bounded before any work: at most 64
    lines, each found by a newline search confined to 4096 characters past its start, and 65536
    characters in all; only such bounded slices are ever copied, encoded, committed or (for a
    successful capture) parsed. An oversized line, more output or an unencodable line ends the scan as
    ``truncated`` with a closed reason; the total byte and line counts are then unknown (None), never
    estimated. ``chars`` is the exact length of the captured text (no pass over it)."""
    limits = DIAG_LIMITS
    text = stdout if isinstance(stdout, str) else ""
    size, position, scanned, total_bytes = len(text), 0, 0, 0
    lines, commitments, reasons = [], [], set()
    while position < size:
        if len(lines) >= limits["links_per_capture"]:
            reasons.add("line_cap")
            break
        window = min(size, position + limits["line_chars"] + 1)
        newline = text.find("\n", position, window)
        stop = newline if newline >= 0 else window
        if newline < 0 and (window < size or stop - position > limits["line_chars"]):
            reasons.add("line_length_cap")
            break
        if scanned + (stop - position) > limits["scan_chars"]:
            reasons.add("scan_cap")
            break
        line = text[position:stop]
        try:
            encoded = len(line.encode("utf-8", "surrogateescape"))
        except UnicodeEncodeError:
            reasons.add("unsupported_encoding")
            break
        scanned += stop - position
        total_bytes += encoded + (1 if newline >= 0 else 0)
        commitments.append(link_commitment(key, "line", line))
        lines.append((line, parse_link_line(line) if parse else None))
        position = stop + 1 if newline >= 0 else stop
    complete = not reasons
    return {"state": "complete" if complete else "truncated", "reasons": reasons, "lines": lines,
            "commitments": commitments, "chars": size, "bytes": total_bytes if complete else None,
            "line_count": len(lines) if complete else None}


def _field_value(fields: dict, label: str):
    if label == "unknown":
        return tuple(fields["unknown"])
    if label in ("altname", "vf", "flags"):
        return tuple(fields[label])
    if label == "line":
        return fields["line"]
    return fields.get(label)


def changed_labels(before: dict, after: dict) -> list[str]:
    """The closed labels of the raw fields that differ between two observations of one link (by
    name); ``line`` alone means only text outside every labelled field moved (spacing, order)."""
    labels = [label for label in FIELD_LABELS if label != "line" and _field_value(before, label) != _field_value(after, label)]
    if not labels and before["line"] != after["line"]:
        labels.append("line")
    return sorted(set(labels))


def _bounded_int(value, low: int, high: int):
    return value if type(value) is int and low <= value <= high else None


def link_entry(fields: dict, key: bytes, provenance: dict) -> dict:
    """The exported, closed per-link object (exactly 16 fields): keyed commitments for every raw name,
    address and text value, bounded integers and closed enums for the rest."""
    def commit(kind: str, value):
        return None if value is None else link_commitment(key, kind, value)

    other = [(label, value) for label, value in (
        ("qdisc", fields["qdisc"]), ("mode", fields["mode"]), ("group", fields["group"]), ("brd", fields["brd"]),
        ("peer_address", fields["peer_address"]), ("permaddr", fields["permaddr"]), ("netns", fields["netns"]),
        ("altname", "\n".join(fields["altname"]) or None), ("alias", fields["alias"]), ("vf", "\n".join(fields["vf"]) or None),
        ("unknown", "\n".join(fields["unknown"]) or None)) if value is not None]
    link_type = fields["link_type"] if fields["link_type"] in LINK_TYPES else None
    return {"id": commit("name", fields["name"]), "ifindex": _bounded_int(fields["ifindex"], 0, 2 ** 31 - 1) or 0,
            "iflink": _bounded_int(fields["iflink"], 0, 2 ** 31 - 1), "peer": commit("name", fields["peer"]),
            "flags": list(fields["flags"]), "operstate": fields["operstate"], "link_type": link_type,
            "mtu": _bounded_int(fields["mtu"], 0, 2 ** 31 - 1), "qlen": _bounded_int(fields["qlen"], 0, 2 ** 32),
            "mac": commit("mac", fields["mac"]), "master": commit("name", fields["master"]),
            "netnsid": _bounded_int(fields["netnsid"], -1, 2 ** 31 - 1), "line": commit("line", fields["line"]),
            "other": commit("other", "\0".join(f"{label}={value}" for label, value in other)) if other else None,
            "unknown": min(len(fields["unknown"]), 4096), "provenance": provenance}


UNKNOWN_PROVENANCE = {"device_backed": "unknown", "bus": "unknown", "kind": "unknown", "driver": "unknown", "scope": "unknown"}


_SYSFS_DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _sysfs_read(directory: int, name: str, limit: int = DIAG_LIMITS["sysfs_read_bytes"]) -> str:
    """One small, fixed attribute of an already opened sysfs directory (O_NOFOLLOW, at most ``limit``)."""
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=directory)
    try:
        data = os.read(descriptor, limit + 1)
    finally:
        os.close(descriptor)
    if len(data) > limit:
        raise ValueError("sysfs_cap")
    return data.decode("ascii").strip()


def _sysfs_target(parts: tuple, directory: int, link: str, real_root: str) -> tuple | None:
    """One intended metadata link (read at its directory's descriptor), resolved lexically against
    that directory's components below the root. Lexical ``..`` is sound because every directory on
    the way was reached through real entries only (see ``_sysfs_open``). None for a target that is
    too long, leaves the root, or is absolute outside it; never a raw path out of this module."""
    target = os.readlink(link, dir_fd=directory)
    if not isinstance(target, str) or not target or len(target) > DIAG_LIMITS["sysfs_link_chars"] or "\0" in target:
        return None
    if target.startswith("/"):
        if not target.startswith(real_root + "/"):
            return None
        components, target = [], target[len(real_root) + 1:]
    else:
        components = list(parts)
    for component in target.split("/"):
        if component in ("", "."):
            continue
        if component == "..":
            if not components:
                return None
            components.pop()
        else:
            components.append(component)
    return tuple(components) if len(components) <= DIAG_LIMITS["sysfs_components"] else None


def _sysfs_open(root: int, parts: tuple) -> int:
    """A directory descriptor reached from the root descriptor one real component at a time
    (O_DIRECTORY | O_NOFOLLOW at each parent's descriptor): no symlink is ever followed on the way,
    so a substituted parent or ancestor fails instead of leading out of the root."""
    current = os.open(".", _SYSFS_DIRECTORY, dir_fd=root)
    try:
        for component in parts:
            if component in ("", ".", "..") or "/" in component:
                raise ValueError("sysfs_component")
            following = os.open(component, _SYSFS_DIRECTORY, dir_fd=current)
            os.close(current)
            current = following
        return current
    except BaseException:
        os.close(current)
        raise


def _sysfs_identity(descriptor: int, device: int) -> tuple[int, int]:
    info = os.fstat(descriptor)
    if info.st_dev != device:
        raise ValueError("sysfs_device")
    return info.st_dev, info.st_ino


def _sysfs_pass(root: int, device: int, real_root: str, name: str, ifindex: int, read) -> tuple | None:
    """One complete descriptor-anchored pass: the link's class entry, its directory (ifindex read at
    that descriptor before and after), and for a device-backed link its device, bus and driver, each
    reached only through those four intended links. Returns the facts plus every object identity and
    resolved location on the way, so a second pass can prove nothing moved; None when anything is
    outside its tree, missing or inconsistent."""
    opened = []
    try:
        def reach(parts: tuple) -> tuple[int, tuple]:
            descriptor = _sysfs_open(root, parts)
            opened.append(descriptor)
            return descriptor, (parts, _sysfs_identity(descriptor, device))

        def target(parts: tuple, directory: int, link: str):
            try:
                return _sysfs_target(parts, directory, link, real_root)
            except FileNotFoundError:
                return False

        net, net_id = reach(("class", "net"))
        base_parts = _sysfs_target(("class", "net"), net, name, real_root)
        if not base_parts or len(base_parts) < 3 or base_parts[0] != "devices" or base_parts[-2:] != ("net", name):
            return None
        base, base_id = reach(base_parts)
        if int(read(base, "ifindex")) != ifindex:
            return None
        trail = [net_id, base_id]
        device_parts = target(base_parts, base, "device")
        if device_parts is False:
            facts = ("no", "none", "none")
        else:
            if not device_parts or len(device_parts) < 2 or device_parts[0] != "devices":
                return None
            device_dir, device_id = reach(device_parts)
            subsystem_parts = target(device_parts, device_dir, "subsystem")
            if not subsystem_parts or len(subsystem_parts) != 2 or subsystem_parts[0] != "bus":
                return None
            trail += [device_id, reach(subsystem_parts)[1]]
            bus = subsystem_parts[1]
            driver_parts = target(device_parts, device_dir, "driver")
            if driver_parts is False:
                driver = "none"
            else:
                if not driver_parts or len(driver_parts) != 4 or driver_parts[:3] != ("bus", bus, "drivers"):
                    return None
                trail.append(reach(driver_parts)[1])
                token = driver_parts[3]
                driver = token if len(token) <= DIAG_LIMITS["driver_token_chars"] and token in DRIVERS else "unknown"
            facts = ("yes", bus if bus in BUSES else "other", driver)
        if int(read(base, "ifindex")) != ifindex:
            return None
        return facts, tuple(trail)
    finally:
        for descriptor in opened:
            os.close(descriptor)


def link_metadata(name: str, ifindex: int, deadline_ns: int, *, clock=time.monotonic_ns, root: str = "/sys",
                  read=_sysfs_read) -> dict:
    """Read-only device facts for one link observed in the host capture: whether a device backs it,
    that device's bus and an allowlisted driver token. Every read is anchored at one root directory
    descriptor and reached through real directories plus only the class/device/subsystem/driver links,
    each resolved inside its own tree and every object on one filesystem. A second full pass must find
    the same objects (device, inode), locations and facts, and the root must still be the same
    object; any substitution, race, reuse, escape, disappearance or deadline leaves the answer
    ``unknown``. Never a bus path, serial or raw path."""
    answer = {"device_backed": "unknown", "bus": "unknown", "driver": "unknown", "status": "unknown"}
    if not _LINK_NAME.fullmatch(name or "") or name in (".", ".."):
        return answer
    real_root = os.path.realpath(root)
    try:
        anchor = os.open(real_root, _SYSFS_DIRECTORY)
    except OSError:
        return answer
    try:
        device = os.fstat(anchor).st_dev
        first = _sysfs_pass(anchor, device, real_root, name, ifindex, read)
        if first is None or clock() > deadline_ns:
            return answer
        second = _sysfs_pass(anchor, device, real_root, name, ifindex, read)
        again = os.open(real_root, _SYSFS_DIRECTORY)
        try:
            same_root = os.fstat(again)[1:3] == os.fstat(anchor)[1:3]
        finally:
            os.close(again)
        if second != first or not same_root or clock() > deadline_ns:
            return answer
        backed, bus, driver = first[0]
        return {"device_backed": backed, "bus": bus, "driver": driver, "status": "ok"}
    except (OSError, ValueError):
        return answer
    finally:
        os.close(anchor)


def bounded_command(argv: tuple[str, ...], deadline_ns: int, *, clock=time.monotonic_ns,
                    limit: int = DIAG_LIMITS["ancillary_read_bytes"]) -> tuple[str, bytes | None]:
    """One fixed read-only ancillary command: stdout read at most ``limit`` bytes before the deadline
    (then killed), stderr discarded, no input. Returns (status, stdout or None)."""
    try:
        process = subprocess.Popen(list(argv), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   env=h0()._build_env())
    except OSError:
        return "oserror", None
    chunks, size, status = [], 0, None
    try:
        while status is None:
            remaining = (deadline_ns - clock()) / 1e9
            if remaining <= 0 or not select.select([process.stdout], [], [], remaining)[0]:
                status = "timeout"
                break
            chunk = os.read(process.stdout.fileno(), 65536)
            if not chunk:
                break
            size += len(chunk)
            if size > limit:
                status = "cap"
                break
            chunks.append(chunk)
        if status is None:
            try:
                code = process.wait(timeout=max(0.001, (deadline_ns - clock()) / 1e9))
                status = "ok" if code == 0 else "nonzero"
            except subprocess.TimeoutExpired:
                status = "timeout"
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        process.stdout.close()
    return status, (b"".join(chunks) if status == "ok" else None)


ANCILLARY_LINK_KINDS = ("ip", "-d", "-j", "link", "show")


def link_kinds(deadline_ns: int, *, clock=time.monotonic_ns, run=bounded_command) -> tuple[str, dict]:
    """The one fixed read-only metadata listing: ifindex -> (name, closed link kind)."""
    status, data = run(ANCILLARY_LINK_KINDS, deadline_ns, clock=clock)
    if status != "ok":
        return status, {}
    try:
        document = json.loads(data.decode("utf-8"), parse_constant=_no_constant)
    except (ValueError, RecursionError):
        return "invalid", {}
    if not isinstance(document, list):
        return "invalid", {}
    kinds = {}
    for item in document[:4096]:
        if not isinstance(item, dict) or type(item.get("ifindex")) is not int or not isinstance(item.get("ifname"), str):
            return "invalid", {}
        info = item.get("linkinfo")
        kind = info.get("info_kind") if isinstance(info, dict) else None
        kinds[item["ifindex"]] = (item["ifname"], "none" if kind is None else (kind if kind in LINK_KINDS else "other"))
    return "ok", kinds


def _host_namespace() -> tuple[int, int]:
    info = os.stat("/proc/self/ns/net")
    return info.st_dev, info.st_ino


def empty_diagnostics(reasons) -> dict:
    return {"schema": DIAG_SCHEMA, "complete": False, "incomplete_reasons": sorted(set(reasons) & set(DIAG_REASONS)),
            "attribution": "correlation_only", "host_namespace": None, "baseline_pause_ms": None, "ancillary_ms": 0,
            "captures": [], "pairs": [],
            "ownership": {"status": "missing", "endpoints": 0, "correlated": 0, "ambiguous": 0, "namespace_conflicts": 0}}


_OWNERSHIP_KEYS = {"schema", "fixture", "side", "namespace", "outer", "requested_name", "requested_mac", "observed", "name",
                   "mac", "ifindex", "iflink"}


def ownership_record(key: bytes, fixture: int, side: str, namespace: tuple[int, int], outer: tuple[int, int], name: str,
                     mac: str, listing: str | None) -> dict:
    """The fixture's registry entry for one endpoint it just created: the requested name/MAC and the
    read-only post-creation listing of that endpoint in its own namespace, keyed with the run key."""
    lines = listing.splitlines() if isinstance(listing, str) else []
    fields = parse_link_line(lines[0]) if len(lines) == 1 else None
    observed = fields is not None and fields["name"] == name and not fields["unknown"]
    return {"schema": OWNERSHIP_SCHEMA, "fixture": fixture, "side": side,
            "namespace": namespace_commitment(key, *namespace), "outer": namespace_commitment(key, *outer),
            "requested_name": link_commitment(key, "name", name), "requested_mac": link_commitment(key, "mac", mac.lower()),
            "observed": observed, "name": link_commitment(key, "name", fields["name"]) if observed else None,
            "mac": link_commitment(key, "mac", fields["mac"]) if observed and fields["mac"] else None,
            "ifindex": fields["ifindex"] if observed else None, "iflink": fields["iflink"] if observed else None}


def sanitize_ownership(raw: bytes | None) -> tuple[str, list[dict]]:
    """All or nothing: at most 32 closed registry entries, each a unique (fixture, side)."""
    if raw is None:
        return "missing", []
    if len(raw) > DIAG_LIMITS["ownership_bytes"]:
        return "invalid", []
    try:
        lines = raw.decode("utf-8").splitlines()
        entries = [json.loads(line, parse_constant=_no_constant) for line in lines]
    except (ValueError, RecursionError):
        return "invalid", []
    seen = set()
    for entry in entries:
        if (not isinstance(entry, dict) or set(entry) != _OWNERSHIP_KEYS or entry["schema"] != OWNERSHIP_SCHEMA
                or _bounded_int(entry["fixture"], 1, 4096) is None or entry["side"] not in ("l", "r")
                or type(entry["observed"]) is not bool
                or not all(isinstance(entry[name], str) and _HEX64.fullmatch(entry[name])
                           for name in ("namespace", "outer", "requested_name", "requested_mac"))
                or not all(entry[name] is None or (isinstance(entry[name], str) and _HEX64.fullmatch(entry[name]))
                           for name in ("name", "mac"))
                or not all(entry[name] is None or _bounded_int(entry[name], 0, 2 ** 31 - 1) is not None
                           for name in ("ifindex", "iflink"))
                or (entry["fixture"], entry["side"]) in seen):
            return "invalid", []
        seen.add((entry["fixture"], entry["side"]))
    if len(entries) > DIAG_LIMITS["fixture_endpoints"]:
        return "capped", []
    return "valid", entries


def read_ownership(out: Path) -> bytes | None:
    """The fixture registry the namespace init copied out (O_NOFOLLOW, bounded; absent -> None)."""
    try:
        descriptor = os.open(out / OWNERSHIP_FILE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    try:
        return os.read(descriptor, DIAG_LIMITS["ownership_bytes"] + 1)
    finally:
        os.close(descriptor)


class LinkCollector:
    """Links-only observer for H0 ``host_fingerprints``: it keeps the exact ``links`` capture the gate
    digested (in memory), its status, return code, digest and bounds, plus run-local namespace
    identities around each snapshot; read-only metadata is sampled next to (never atomically with)
    the capture. Every method swallows its own failure as a closed reason: the gate never sees it."""

    def __init__(self, key: bytes, anchor_ns: int, *, clock=time.monotonic_ns, sleep=time.sleep, namespace=_host_namespace,
                 kinds=link_kinds, metadata=link_metadata):
        self.key, self.anchor_ns, self.clock, self.sleep = key, anchor_ns, clock, sleep
        self.namespace, self.kinds, self.metadata = namespace, kinds, metadata
        self.phases: list[dict] = []
        self.failures: set[str] = set()
        self.budget_ns = DIAG_LIMITS["ancillary_total_ms"] * _MS
        self.pause_ms: int | None = None

    def _ms(self, value):
        return None if value is None else max(0, min(10 ** 7, (value - self.anchor_ns) // _MS))

    def _namespace_id(self):
        try:
            return namespace_commitment(self.key, *self.namespace())
        except Exception:  # noqa: BLE001 - an unknown identity, never a guessed one
            return None

    def begin(self):
        try:
            if len(self.phases) >= len(DIAG_PHASES):
                self.failures.add("collector_failed")
                return None
            phase = {"phase": DIAG_PHASES[len(self.phases)], "ordinal": len(self.phases), "namespace_before": self._namespace_id(),
                     "namespace_after": None, "capture": None, "enrichment": None, "scan": None}
            self.phases.append(phase)
            return phase
        except Exception:  # noqa: BLE001
            self.failures.add("collector_failed")
            return None

    def observe(self, *, name, status, returncode, stdout, digest, started_ns, ended_ns) -> None:
        if name != "links":
            return
        phase = self.phases[-1] if self.phases else None
        if phase is None or phase["capture"] is not None:
            self.failures.add("observer_failed")
            return
        phase["capture"] = {"status": status, "returncode": returncode, "stdout": stdout, "digest": digest,
                            "started_ns": started_ns, "ended_ns": ended_ns}

    def end(self, phase) -> None:
        if phase is not None:
            phase["namespace_after"] = self._namespace_id()

    def snapshot(self, helper):
        """The ``stable_fingerprints(snapshot=...)`` callable: H0's own snapshot with this observer."""
        def capture() -> dict:
            phase = self.begin()
            try:
                return helper.host_fingerprints(observer=self.observe)
            finally:
                self.end(phase)
        return capture

    def pause(self, seconds: float) -> None:
        """The ``stable_fingerprints(pause=...)`` callable: the first snapshot's metadata inside at most
        three quarters of the pause, then sleep the rest, so the second snapshot still starts no
        earlier than ``seconds`` after the first ended."""
        started = self.clock()
        try:
            self.enrich(limit_ns=int(seconds * 1e9 * 3 / 4))
        except Exception:  # noqa: BLE001
            self.failures.add("collector_failed")
        remaining = seconds - (self.clock() - started) / 1e9
        if remaining > 0:
            self.sleep(remaining)
        self.pause_ms = max(0, (self.clock() - started) // _MS)

    def _scan(self, phase) -> dict:
        """The one bounded scan of this phase's capture (cached); only a successful capture is parsed."""
        if phase["scan"] is None:
            capture = phase["capture"] or {}
            phase["scan"] = scan_capture(self.key, capture.get("stdout"), parse=capture.get("status") == "ok")
        return phase["scan"]

    def enrich(self, limit_ns: int | None = None) -> None:
        """Metadata for the latest snapshot: the fixed link-kind listing, then device facts per link,
        rechecking the namespace identity around both. Bounded by the 2 s command and 5 s total budgets."""
        phase = self.phases[-1] if self.phases else None
        if phase is None or phase["enrichment"] is not None:
            return
        started = self.clock()
        record = {"status": "ok", "started_ns": started, "ended_ns": None, "kinds": {}, "links": {}}
        phase["enrichment"] = record
        try:
            budget = self.budget_ns if limit_ns is None else min(self.budget_ns, limit_ns)
            deadline = started + max(0, budget)
            capture = phase["capture"]
            if capture is None or capture["status"] != "ok":
                record["status"] = "not_run"
                return
            identity = self._namespace_id()
            if identity is None or not (identity == phase["namespace_before"] == phase["namespace_after"]):
                record["status"] = "namespace_mismatch"
                return
            if budget <= 0:
                record["status"] = "budget"
                return
            status, kinds = self.kinds(min(deadline, started + DIAG_LIMITS["ancillary_command_ms"] * _MS), clock=self.clock)
            record["kinds"] = kinds if status == "ok" else {}
            if status != "ok":
                record["status"] = status
            for _line, fields in self._scan(phase)["lines"]:
                if fields is None:
                    continue
                if self.clock() >= deadline:
                    record["status"] = "budget" if record["status"] == "ok" else record["status"]
                    break
                record["links"][fields["ifindex"]] = self.metadata(fields["name"], fields["ifindex"], deadline, clock=self.clock)
            if self._namespace_id() != identity:
                record["status"], record["kinds"], record["links"] = "namespace_mismatch", {}, {}
        except Exception:  # noqa: BLE001
            record["status"], record["kinds"], record["links"] = "invalid", {}, {}
            self.failures.add("collector_failed")
        finally:
            record["ended_ns"] = self.clock()
            self.budget_ns -= max(0, record["ended_ns"] - started)

    def _provenance(self, phase, fields) -> dict:
        record = phase["enrichment"] or {}
        if record.get("status") not in ("ok", "budget", "timeout", "nonzero", "cap", "invalid", "oserror"):
            return dict(UNKNOWN_PROVENANCE)
        device = record.get("links", {}).get(fields["ifindex"])
        named = record.get("kinds", {}).get(fields["ifindex"])
        kind = named[1] if named and named[0] == fields["name"] else "unknown"
        if not device or device.get("status") != "ok":
            return {**UNKNOWN_PROVENANCE, "kind": kind}
        return {"device_backed": device["device_backed"], "bus": device["bus"], "kind": kind, "driver": device["driver"],
                "scope": "host_verified"}

    def result(self, ownership_raw: bytes | None) -> dict:
        try:
            return self._result(ownership_raw)
        except Exception:  # noqa: BLE001 - a closed reason, never a message
            return empty_diagnostics(["collector_failed"])

    def _result(self, ownership_raw: bytes | None) -> dict:
        key, reasons = self.key, set(self.failures)
        captures, views = [], []
        if len(self.phases) < len(DIAG_PHASES):
            reasons.add("capture_missing")
        for phase in self.phases:
            capture, enrichment = phase["capture"], phase["enrichment"] or {"status": "not_run", "started_ns": None,
                                                                              "ended_ns": None}
            status = capture["status"] if capture else "missing"
            scan = self._scan(phase) if capture else scan_capture(key, None, parse=False)
            described = scan["lines"] if status == "ok" else []  # a failed capture's text is committed, never read as links
            reasons |= scan["reasons"]
            if status != "ok":
                reasons.add("capture_missing" if status == "missing" else "capture_not_ok")
            if phase["namespace_before"] is None or phase["namespace_before"] != phase["namespace_after"]:
                reasons.add("namespace_mismatch")
            if status == "ok" and enrichment["status"] != "ok":
                reasons.add({"timeout": "enrichment_timeout", "cap": "enrichment_cap", "budget": "enrichment_budget",
                             "namespace_mismatch": "namespace_mismatch"}.get(enrichment["status"], "enrichment_failed"))
            line_commitments = scan["commitments"]
            scanned = scan["state"] == "complete"
            links, view, parse_ok = [], {}, status == "ok" and scanned
            for line, fields in described:
                if fields is None:
                    reasons.add("unsupported_syntax")
                    parse_ok = False
                    continue
                if fields["tokens"] > DIAG_LIMITS["tokens_per_line"]:
                    reasons.add("field_cap")
                    parse_ok = False
                if fields["unknown"]:
                    reasons.add("unsupported_syntax")
                    parse_ok = False
                provenance = self._provenance(phase, fields)
                if provenance["scope"] != "host_verified" and enrichment["status"] == "ok":
                    reasons.add("enrichment_unknown")
                entry = link_entry(fields, key, provenance)
                if entry["id"] in view:
                    reasons.add("unsupported_syntax")
                    parse_ok = False
                view[entry["id"]] = (fields, entry)
                links.append(entry)
            captures.append({
                "phase": phase["phase"], "ordinal": phase["ordinal"], "namespace_before": phase["namespace_before"],
                "namespace_after": phase["namespace_after"], "start_ms": self._ms(capture["started_ns"]) if capture else None,
                "end_ms": self._ms(capture["ended_ns"]) if capture else None, "status": status,
                "returncode": _bounded_int(capture["returncode"], -255, 255) if capture else None,
                "gate_digest": capture["digest"] if capture else None, "chars": scan["chars"], "bytes": scan["bytes"],
                "line_count": scan["line_count"], "lines_scanned": len(scan["lines"]), "scan": scan["state"],
                "parse": "not_applicable" if status != "ok" else ("complete" if parse_ok else "incomplete"),
                "lines": line_commitments,
                "multiset": link_commitment(key, "multiset", "\n".join(sorted(line_commitments)))
                if capture and scanned else None,
                "links": links, "enrichment": {"status": enrichment["status"], "start_ms": self._ms(enrichment["started_ns"]),
                                               "end_ms": self._ms(enrichment["ended_ns"])}})
            views.append({"status": status, "returncode": capture["returncode"] if capture else None,
                          "digest": capture["digest"] if capture else None, "lines": line_commitments, "view": view,
                          "complete": parse_ok, "scanned": scanned})
        identities = {phase["namespace_before"] for phase in self.phases} | {phase["namespace_after"] for phase in self.phases}
        host = next(iter(identities)) if len(identities) == 1 else None
        if self.phases and host is None:
            reasons.add("namespace_mismatch")
        ownership_status, registry = sanitize_ownership(ownership_raw)
        ownership = {"status": ownership_status, "endpoints": 0, "correlated": 0, "ambiguous": 0, "namespace_conflicts": 0}
        usable = []
        for entry in registry:
            if host is not None and host in (entry["namespace"], entry["outer"]):
                ownership["namespace_conflicts"] += 1
                reasons.add("namespace_mismatch")
            elif not (entry["observed"] and entry["name"] == entry["requested_name"] and entry["mac"] == entry["requested_mac"]):
                reasons.add("ownership_invalid")
            else:
                usable.append(entry)
        ownership["endpoints"] = len(usable)
        reasons.add({"missing": "ownership_missing", "invalid": "ownership_invalid", "capped": "ownership_cap"}.get(
            ownership_status, "ownership_missing" if not registry else None))
        reasons.discard(None)
        pairs, budget = [], DIAG_LIMITS["changed_entries"]
        for name, first, second in DIAG_PAIRS:
            if second >= len(views):
                continue
            pair, budget = self._pair(name, views, first, second, usable if ownership_status == "valid" else None,
                                      ownership, budget, reasons)
            pairs.append(pair)
        return {"schema": DIAG_SCHEMA, "complete": not reasons, "incomplete_reasons": sorted(reasons),
                "attribution": "correlation_only", "host_namespace": host,
                "baseline_pause_ms": None if self.pause_ms is None else min(self.pause_ms, 10 ** 7),
                "ancillary_ms": max(0, min(10 ** 7, (DIAG_LIMITS["ancillary_total_ms"] * _MS - self.budget_ns) // _MS)),
                "captures": captures, "pairs": pairs, "ownership": ownership}

    def _pair(self, name, views, first, second, registry, ownership, budget, reasons):
        a, b = views[first], views[second]
        gate_equal = a["digest"] is not None and a["digest"] == b["digest"]
        status_change = (a["status"], a["returncode"]) != (b["status"], b["returncode"])
        order_only = (not gate_equal and not status_change and a["scanned"] and b["scanned"]  # whole texts only
                      and sorted(a["lines"]) == sorted(b["lines"]) and a["lines"] != b["lines"])
        changes, enrichment_changes, counts = [], [], {"added": 0, "removed": 0, "changed": 0}
        comparable = a["status"] == b["status"] == "ok"  # links are compared only between two successful captures
        for link_id in sorted(set(a["view"]) | set(b["view"])) if comparable else []:
            before, after = a["view"].get(link_id), b["view"].get(link_id)
            if before and after:
                labels = changed_labels(before[0], after[0])
                kind = "changed" if labels else None
                if not labels and before[1]["provenance"]["scope"] == after[1]["provenance"]["scope"] == "host_verified":
                    moved = sorted(label for label in PROVENANCE_LABELS
                                   if before[1]["provenance"][label] != after[1]["provenance"][label])
                    if moved:
                        if budget <= 0:
                            reasons.add("changed_cap")
                        else:
                            enrichment_changes.append({"id": link_id, "fields": moved})
                            budget -= 1
            else:
                kind, labels = ("added", []) if after else ("removed", [])
            if kind is None:
                continue
            counts[kind] += 1
            if budget <= 0:
                reasons.add("changed_cap")
                continue
            observed = (after or before)[1]["provenance"]
            hardware = ("unknown" if observed["scope"] != "host_verified"
                        else {"yes": "device_backed", "no": "virtual"}.get(observed["device_backed"], "unknown"))
            # Proof identity is never asserted: the registry records creation in a fixture namespace,
            # and no capture witnesses that endpoint's later existence, move or teardown. A name/MAC
            # match with one registry entry is labelled as that correlation and nothing more.
            identity = "not_applicable" if name == "baseline" else "unknown"
            correlation = "not_applicable" if name == "baseline" else "none"
            if name == "audit" and kind == "added" and registry is not None and link_id not in views[0]["view"]:
                candidates = [entry for entry in registry if entry["name"] == link_id and entry["mac"] is not None
                              and entry["mac"] == after[1]["mac"]]
                if len(candidates) == 1:
                    correlation = "fixture_name_mac"
                    ownership["correlated"] += 1
                elif len(candidates) > 1:
                    correlation = "ambiguous"
                    ownership["ambiguous"] += 1
            changes.append({"id": link_id, "change": kind, "fields": labels, "proof_identity": identity,
                            "correlation": correlation, "hardware": hardware})
            budget -= 1
        if gate_equal:
            classes = {"none"}
        else:
            classes = set()
            if status_change:
                classes.add("command_status_change")
            elif order_only:
                classes.add("order_only_text_change")
            for change in changes:
                classes.add("hardware_backed_change" if change["hardware"] == "device_backed" else "unknown")
                if change["correlation"] == "fixture_name_mac":
                    classes.add("fixture_name_mac_correlation")
            if not classes or (comparable and not (a["complete"] and b["complete"])) or "changed_cap" in reasons:
                classes.add("unknown")
        return ({"name": name, "from": DIAG_PHASES[first], "to": DIAG_PHASES[second], "gate_digest_equal": gate_equal,
                 "status_change": status_change, "order_only": order_only, **counts, "classes": sorted(classes),
                 "changes": changes, "enrichment_changes": enrichment_changes}, budget)


def _spec_ok(value, spec) -> bool:
    kind = spec[0]
    if kind == "hex":
        return isinstance(value, str) and _HEX64.fullmatch(value) is not None
    if kind == "digest":
        return isinstance(value, str) and (value == "unavailable" or _HEX64.fullmatch(value) is not None)
    if kind == "int":
        return type(value) is int and spec[1] <= value <= spec[2]
    if kind == "bool":
        return type(value) is bool
    if kind == "enum":
        return isinstance(value, str) and value in spec[1]
    if kind == "opt":
        return value is None or _spec_ok(value, spec[1])
    if kind == "list":
        return isinstance(value, list) and len(value) <= spec[2] and all(_spec_ok(item, spec[1]) for item in value)
    if kind == "set":
        return (isinstance(value, list) and all(isinstance(item, str) and item in spec[1] for item in value)
                and value == sorted(set(value)))
    if kind == "dict":
        return isinstance(value, dict) and set(value) == set(spec[1]) and all(_spec_ok(value[k], s) for k, s in spec[1].items())
    return False


_HEX = ("hex",)
_MS_INT = ("opt", ("int", 0, 10 ** 7))
_INDEX = ("int", 0, 2 ** 31 - 1)
_PROVENANCE_SPEC = ("dict", {"device_backed": ("enum", ("yes", "no", "unknown")), "bus": ("enum", BUSES),
                             "kind": ("enum", LINK_KINDS), "driver": ("enum", DRIVERS),
                             "scope": ("enum", ("host_verified", "unknown"))})
_LINK_SPEC = ("dict", {"id": _HEX, "ifindex": _INDEX, "iflink": ("opt", _INDEX), "peer": ("opt", _HEX),
                       "flags": ("set", LINK_FLAGS), "operstate": ("opt", ("enum", OPERSTATES)),
                       "link_type": ("opt", ("enum", LINK_TYPES)), "mtu": ("opt", _INDEX), "qlen": ("opt", ("int", 0, 2 ** 32)),
                       "mac": ("opt", _HEX), "master": ("opt", _HEX), "netnsid": ("opt", ("int", -1, 2 ** 31 - 1)),
                       "line": _HEX, "other": ("opt", _HEX), "unknown": ("int", 0, 4096), "provenance": _PROVENANCE_SPEC})
_CAPTURE_SPEC = ("dict", {"phase": ("enum", DIAG_PHASES), "ordinal": ("int", 0, 2), "namespace_before": ("opt", _HEX),
                          "namespace_after": ("opt", _HEX), "start_ms": _MS_INT, "end_ms": _MS_INT,
                          "status": ("enum", CAPTURE_STATUSES), "returncode": ("opt", ("int", -255, 255)),
                          "gate_digest": ("opt", ("digest",)), "chars": ("int", 0, 2 ** 62),
                          "bytes": ("opt", ("int", 0, 4 * DIAG_LIMITS["scan_chars"] + DIAG_LIMITS["links_per_capture"])),
                          "line_count": ("opt", ("int", 0, DIAG_LIMITS["links_per_capture"])),
                          "lines_scanned": ("int", 0, DIAG_LIMITS["links_per_capture"]), "scan": ("enum", SCAN_STATES),
                          "parse": ("enum", PARSE_STATUSES), "lines": ("list", _HEX, DIAG_LIMITS["links_per_capture"]),
                          "multiset": ("opt", _HEX), "links": ("list", _LINK_SPEC, DIAG_LIMITS["links_per_capture"]),
                          "enrichment": ("dict", {"status": ("enum", ENRICH_STATUSES), "start_ms": _MS_INT, "end_ms": _MS_INT})})
_CHANGE_SPEC = ("dict", {"id": _HEX, "change": ("enum", CHANGE_KINDS), "fields": ("set", FIELD_LABELS),
                         "proof_identity": ("enum", PROOF_IDENTITY), "correlation": ("enum", CORRELATIONS),
                         "hardware": ("enum", HARDWARE)})
_COUNT = ("int", 0, 10 ** 6)
_PAIR_SPEC = ("dict", {"name": ("enum", ("baseline", "audit")), "from": ("enum", DIAG_PHASES), "to": ("enum", DIAG_PHASES),
                       "gate_digest_equal": ("bool",), "status_change": ("bool",), "order_only": ("bool",), "added": _COUNT,
                       "removed": _COUNT, "changed": _COUNT, "classes": ("set", DELTA_CLASSES),
                       "changes": ("list", _CHANGE_SPEC, DIAG_LIMITS["changed_entries"]),
                       "enrichment_changes": ("list", ("dict", {"id": _HEX, "fields": ("set", PROVENANCE_LABELS)}),
                                              DIAG_LIMITS["changed_entries"])})
DIAGNOSTICS_SPEC = ("dict", {"schema": ("enum", (DIAG_SCHEMA,)), "complete": ("bool",),
                             "incomplete_reasons": ("set", DIAG_REASONS), "attribution": ("enum", ATTRIBUTION),
                             "host_namespace": ("opt", _HEX),
                             "baseline_pause_ms": _MS_INT, "ancillary_ms": ("int", 0, 10 ** 7),
                             "captures": ("list", _CAPTURE_SPEC, DIAG_LIMITS["captures"]),
                             "pairs": ("list", _PAIR_SPEC, len(DIAG_PAIRS)),
                             "ownership": ("dict", {"status": ("enum", OWNERSHIP_STATUSES), "endpoints": _COUNT,
                                                    "correlated": _COUNT, "ambiguous": _COUNT, "namespace_conflicts": _COUNT})})


def sanitize_link_diagnostics(raw) -> dict:
    """The parent's own closed check of the child's diagnostics (all or nothing), then the payload cap.
    ``complete`` is honest only if it agrees with the reasons; a stripped payload is never complete."""
    if raw is None:
        return empty_diagnostics(["diagnostics_missing"])
    if not _spec_ok(raw, DIAGNOSTICS_SPEC) or raw["complete"] != (not raw["incomplete_reasons"]) or sum(
            len(pair["changes"]) + len(pair["enrichment_changes"]) for pair in raw["pairs"]) > DIAG_LIMITS["changed_entries"]:
        return empty_diagnostics(["diagnostics_invalid"])
    clean = json.loads(json.dumps(raw))
    if len(json.dumps(clean, sort_keys=True).encode()) > DIAG_LIMITS["payload_bytes"]:
        for capture in clean["captures"]:
            capture["lines"], capture["links"] = [], []
        for pair in clean["pairs"]:
            pair["changes"], pair["enrichment_changes"] = [], []
        clean["incomplete_reasons"] = sorted(set(clean["incomplete_reasons"]) | {"payload_cap"})
        clean["complete"] = False
    return clean


def diagnostic_result(gate_result: str, diagnostics: dict) -> tuple[str, str | None]:
    """Stricter only: a gate PASS with incomplete link diagnostics is held as FAIL; nothing else moves."""
    if gate_result == "PASS" and diagnostics.get("complete") is not True:
        return "FAIL", "link_diagnostics_incomplete"
    return gate_result, None


def diagnostic_report_lines(diagnostics: dict) -> list[str]:
    lines = [f"link_diagnostics_complete {diagnostics.get('complete') is True}"]
    lines += [f"link_diagnostics_reason {reason}" for reason in diagnostics.get("incomplete_reasons") or []]
    for pair in diagnostics.get("pairs") or []:
        lines += [f"link_delta {pair['name']} {name}" for name in pair["classes"]]
    return lines


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
    report += [f"gate_result {summary.get('gate_result')}", f"diagnostic_hold {summary.get('diagnostic_hold')}"]
    report += diagnostic_report_lines(cleanup.get("link_diagnostics") or {})
    return report


def parent() -> int:
    started, anchor_ns = time.monotonic(), time.monotonic_ns()
    deadline = started + LAUNCHER_SECONDS - CLEANUP_RESERVE_SECONDS
    timings: dict[str, float] = {}
    summary: dict = {"schema_version": "heel.host-h2-policy-proof.summary.v1", "profile": PROFILE, "reviewed_ref": REVIEWED_REF,
                     "utc_start": datetime.datetime.now(datetime.timezone.utc).isoformat(), "result": "FAIL",
                     "kernel_profile": None, "runtime_assumption": RUNTIME_ASSUMPTION, "seams": list(SEAMS),
                     "negative_controls": sorted(case for case, item in RECORD_CASES.items() if item[1] == "negative")}
    scratch = Path(tempfile.mkdtemp(prefix=SCRATCH_PREFIX, dir=os.environ.get("RUNNER_TEMP") or None))
    token = secrets.token_hex(16)
    diagnostic_key = secrets.token_hex(32)  # run-private HMAC key: sent to the child only, never written
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
                   "tests_seconds": min(TESTS_SECONDS, remaining - 60), "token": token, "diagnostic_key": diagnostic_key,
                   "anchor_ns": anchor_ns}
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
            "reaped_before_count": inner.get("reaped_before_count"),
            "link_diagnostics": sanitize_link_diagnostics(raw_cleanup.get("link_diagnostics"))})
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
        result, hold = diagnostic_result(verdict["result"], cleanup["link_diagnostics"])
        summary.update(verdict, tests=junit, pytest_exit=inner.get("pytest_exit"), tests_timed_out=inner.get("timed_out"),
                       records=[{"case": r["case"], "control": r["control"], "verdict": r["verdict"]} for r in records])
        summary.update(gate_result=verdict["result"], result=result, diagnostic_hold=hold,
                       link_diagnostics_complete=cleanup["link_diagnostics"]["complete"])
        versions = version_lines(by_case, verdict["kernel_profile"])
        exit_code = 0 if result == "PASS" else 1
    except ProofFailure as error:
        failure = error.code
    except Exception as error:  # noqa: BLE001 - a fixed class name only, never a message
        failure = "unexpected_" + type(error).__name__
    finally:
        ARTIFACT_DIR.mkdir(exist_ok=True)
        cleanup.setdefault("link_diagnostics", empty_diagnostics(["diagnostics_missing"]))
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
        flagged = sorted(set(artifact_scan(ARTIFACT_DIR, token)) | set(artifact_scan(ARTIFACT_DIR, diagnostic_key)))
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
    if not isinstance(request, dict) or set(request) != {"schema", "wheels", "out", "uid", "tests_seconds", "token",
                                                          "diagnostic_key", "anchor_ns"}:
        return None
    if request["schema"] != CHILD_SCHEMA or type(request["uid"]) is not int or not 1 <= request["uid"] < 2 ** 31:
        return None
    if type(request["tests_seconds"]) is not int or not 60 <= request["tests_seconds"] <= TESTS_SECONDS:
        return None
    if not isinstance(request["token"], str) or not re.fullmatch(r"[0-9a-f]{32}", request["token"]):
        return None
    if not isinstance(request["diagnostic_key"], str) or not _HEX64.fullmatch(request["diagnostic_key"]):
        return None
    if type(request["anchor_ns"]) is not int or not 0 <= request["anchor_ns"] < 2 ** 63:
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
            os.chmod(destination / parent, 0o700)
        shutil.copyfile(root / name, target)
        os.chmod(target, 0o600)
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
           RECORDS_ENV: str(out / "records.raw.jsonl"), WORK_ENV: str(root / "work"), TOKEN_ENV: request["token"],
           DIAG_KEY_ENV: request["diagnostic_key"]}
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
    for name in ("junit.xml", "records.raw.jsonl", OWNERSHIP_FILE):
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
    # The same stable baseline (two H0 snapshots, two seconds apart) observed by the links collector.
    collector = LinkCollector(bytes.fromhex(request["diagnostic_key"]), request["anchor_ns"])
    before, unstable = helper.stable_fingerprints(snapshot=collector.snapshot(helper), pause=collector.pause)
    collector.enrich()
    if unstable:
        finish({"namespace_child_exit": None, "host_fingerprints_unchanged": False, "differing_fingerprints": [],
                "unstable_fingerprints": unstable, "link_diagnostics": collector.result(None)})
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
    after = collector.snapshot(helper)()
    differing = sorted(key for key in before if before[key] != after[key])
    collector.enrich()
    try:
        ownership = read_ownership(out)
    except (OSError, ValueError):
        ownership = b"\xff"  # unreadable: the registry is invalid, never silently absent
    finish({"namespace_child_exit": inner_exit, "host_fingerprints_unchanged": not differing,
            "differing_fingerprints": differing, "unstable_fingerprints": [],
            "kernel_modules_loaded": sorted(h1f().loaded_modules() - modules_before)[:64],
            "link_diagnostics": collector.result(ownership)})
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
