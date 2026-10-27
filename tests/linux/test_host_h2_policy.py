"""H2-2: isolated Linux proof of the H2-1 generation policy (``h2-policy-v1``; DECISION revision 5, 6.2).

Static cases run everywhere. Dynamic cases need the fixed ``scripts/host_h2_policy_proof.py``
launcher: it runs this module as root inside an outer network+mount+PID namespace that has only
loopback, from a staged root holding exactly the tracked ``heel/`` tree plus ``STAGE_FILES`` and a
closed eight-wheel venv, with ``HEEL_REQUIRE_HOST_H2_POLICY_PROOF=1``. Under that switch a missing
platform, privilege, tool, launcher environment or namespace capability fails; outside it the dynamic
cases skip, so the ordinary suite never claims the proof.

The question: does the real, unmodified H2-1 ``install`` (``deploy/host/h2_policy.py``: the real
``Popen`` helper, the real ``setns`` into a descriptor-held generation namespace and the real nft)
write a table whose real readback the product oracle accepts, is that the only table in the
namespace, and do that table and the real H1 ``LeaseDomain.prepare``/``activate`` of the slot hop
together admit only fresh IPv4 TCP 443 connections to the pinned targets while the lease is live,
for the unchanged ``TargetHTTPSClient`` too? No installer, helper, nft, validator or socket layer is
replaced. The one labelled controlled fault injection (``LAUNCHER.SEAMS``, P6 only) drives the public
``clock`` argument of ``install``/``cleanup`` and pre-seeds a conflicting chain; it proves the
fail-closed outcome, never an unobserved kernel behaviour.

The peer namespace is created by ``unshare`` on a fixture thread and held only by descriptor; the
veth is created by raw rtnetlink with ``IFLA_NET_NS_FD`` (a dup the fixture closes), never by a
namespace name or PID. The recorded public numeric literals (FIXTURE-LITERALS.json) are assigned
only inside these disposable namespaces: there is no default route, uplink or DNS, so nothing leaves
them. The unchanged client resolves through its ``resolver`` seam (the injected tuple), verifies TLS
against the harness's ephemeral CA through the real ``TLSTransport`` and dials with its default
sockets.

This is component evidence under the running-kernel assumption. It is not H3 composition, H6 host
qualification, managed deployment, customer admission or launch.
"""
from __future__ import annotations

import ast
import contextlib
import errno
import hashlib
import importlib
import importlib.util
import inspect
import ipaddress
import json
import os
import re
import secrets
import select
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_FILE = ROOT / "scripts" / "host_h2_policy_proof.py"
AUTHORITY_FILE = ROOT / "deploy" / "host" / "authority.py"
H2_FILE = ROOT / "deploy" / "host" / "h2_policy.py"
HARNESS_FILE = ROOT / "tests" / "support" / "edge_tls_harness.py"
WORKFLOW = ROOT / ".github" / "workflows" / "codeql.yml"
DOC = ROOT / "docs" / "saas" / "H2_POLICY_PROOF.md"
H0_LOCK = ROOT / "deploy" / "host" / "ingress" / "runtime-lock.json"


def _load(name: str, path: Path):
    """One module object per file (the names ``h2_policy`` and the cycle load the H1 domain under, so
    the installer, the cycle and this fixture share one ``authority`` module and one registry)."""
    existing = sys.modules.get(name)
    if existing is not None and Path(getattr(existing, "__file__", "")).resolve() == path.resolve():
        return existing
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses resolve string annotations through sys.modules
    spec.loader.exec_module(module)
    return module


LAUNCHER = _load("host_h2_policy_proof", LAUNCHER_FILE)
AUTHORITY = _load("heel_host_authority_domain", AUTHORITY_FILE)
H2 = _load("heel_host_h2_policy", H2_FILE)
PROFILE = LAUNCHER.profile()
REQUIRED = os.environ.get(LAUNCHER.REQUIRED_ENV) == "1"

MS = 1_000_000
# The H1 slot hop (the H2 lease key src/dst): fixed documentation addresses, as in H2K1. SLOT_DST is
# the slot gateway: the typed key constant and (H2-3) the one control destination, held by R on the
# veth so the fixed control accept can be probed; GATEWAY6 is R's IPv6 gateway address (ULA), never admitted.
SLOT_SRC, SLOT_DST = "198.51.100.20", "192.0.2.1"
GATEWAY6 = "fd48:4b31::1"
# Astra's recorded pick (FIXTURE-LITERALS.json, validator-approved, no network operation used to choose
# them): assigned only inside the disposable namespaces, never contacted outside them.
TARGETS = ("8.8.4.4", "8.8.8.8")  # canonical (version, packed) order
UNAPPROVED, WRONG_SOURCE, TARGET6 = "1.1.1.1", "9.9.9.9", "2001:4860:4860::8888"
RECORDED_TUPLE = ("1.1.1.1", "8.8.4.4", "8.8.8.8", "9.9.9.9", "2001:4860:4860::8888")
PEER6 = "fd48:4b31::20"  # L's own IPv6 source (ULA), never a target
HOSTNAME = "h2-policy-proof.example.com"  # RFC 2606 name: the resolver seam answers it, no DNS exists
SLOT_ID = "h2-policy-proof"
PORT, WRONG_PORT = 443, 8443
LEASE_MS = 3000  # == AUTHORITY.MAX_PREPARE_TIMEOUT_MS (a static pins it)
SHORT_MS, LATE_MS = 1000, 300
PROBE_INTERVAL_NS = 100 * MS
CONNECT_TIMEOUT_S = 0.15
LIVE_PERCENT = 95
CLIENT_TIMEOUT_S = 1.0  # P4: a dropped SYN is retried by TCP until this deadline (tcp_connect drops the NF_DROP error)
DENIED = ("connect_error", "timeout")  # the unchanged client's two codes for a connection the policy dropped
NONCE_BYTES = 32
CLONE_NEWNET = 0x40000000
RECEIPT_SCHEMA = "heel.h2a.receipt.v1"
# The H2 source this proof runs unmodified (accepted H2-1 7dcad343 + 4bce9513 plus the H2-3 control
# accept candidate), its production helper (unchanged by H2-3), and the unmodified TLS harness: a
# static test and P0 compare the staged bytes with these.
H2_SOURCE_SHA256 = "2511dae4352bbf2006fb638164375da1d80a097a4bb6117dc7ea96328b5b4af6"
H2_HELPER_SHA256 = "c261a67fee245d58bbf59adcd8203f959209c6210f1c16b452315044a5a53866"
HARNESS_SHA256 = "779d21299de454ccae41674f7f9f1afb3853007ad870c50a7de1718ee156378f"
H2_PUBLIC = ("build_input", "cleanup", "install", "readback_matches", "render_table", "unresolved_helpers")
# The only non-function H2 names this module reads (public constants); it never reads or assigns a
# private H2 name. H2-1's own guard (tests/test_host_h2_policy.py) admits no other tracked module that
# names its two private seams, so the helper is pinned through the pinned file's AST (helper_sha256)
# and the platform guard through behaviour (P0's cleanup probe; every P1-P4/P7 receipt).
H2_READ = ("NFT_PATH", "STATES", "RECEIPT_SCHEMA")
FAULT_TRIGGERS = ("_install", "_drive")  # the H2-1 functions whose clock() calls P6's fault clock counts

# ---------------------------------------------------------------------------------------------
# The recorded parent .github/workflows/codeql.yml at 4bce951 (analyze + four proof jobs, fixed values
# so the staged copy checks them without git history), and the one job this unit appends.

BASE_WORKFLOW_BYTES = 7249
BASE_WORKFLOW_SHA256 = "02d44aaca33da7c3a09ee4cd3fcc085c37ce8d7f2e1e8637cd0b6c75cd6db8fc"
EXPECTED_JOBS = ["analyze", "host-ingress-proof", "host-lease-feasibility", "host-authority-proof", "host-lease-key-shape",
                 "host-h2-policy-proof"]
H2_POLICY_GATE = ("if: github.event_name == 'workflow_dispatch' && "
                  "github.ref == 'refs/heads/codex/self-serve-host-h2-policy-proof'")
CHECKOUT = "actions/checkout@11d5960a326750d5838078e36cf38b85af677262"
SETUP_PYTHON = "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065"
UPLOAD = "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
H2_POLICY_JOB = f"""  host-h2-policy-proof:
    # H2-2: the isolated generation-policy proof (real H2-1 installer, H1 lease, unchanged client) on a disposable VM.
    # Manual dispatch of the literal reviewed proof branch only; no parameters, credentials or saved state.
    # The fixed launcher (docs/saas/H2_POLICY_PROOF.md) owns every runtime input and its hash.
    name: host-h2-policy-proof (h2-policy-v1)
    {H2_POLICY_GATE}
    runs-on: ubuntu-24.04
    timeout-minutes: 25
    permissions:
      contents: read
    concurrency:
      group: host-h2-policy-proof
      cancel-in-progress: false
    steps:
      - uses: {CHECKOUT} # v4
        with:
          ref: ${{{{ github.sha }}}}
          persist-credentials: false
      - uses: {SETUP_PYTHON} # v5
        with:
          python-version: "3.13.5"
      - name: Fixed h2-policy-v1 launcher (20-minute budget, tests 10 minutes)
        timeout-minutes: 20
        run: python scripts/host_h2_policy_proof.py
      - name: Upload allowlisted safe evidence
        if: always()
        uses: {UPLOAD} # v4
        with:
          name: host-h2-policy-proof
          if-no-files-found: error
          retention-days: 3
          path: |
            host-h2-policy-proof/summary.json
            host-h2-policy-proof/cases.jsonl
            host-h2-policy-proof/versions.txt
            host-h2-policy-proof/cleanup.json
            host-h2-policy-proof/report.txt
"""


def _job_block(text: str, name: str) -> str:
    match = re.search(r"^  " + re.escape(name) + r":\n(?:.*\n)*?(?=^  [A-Za-z0-9_-]+:\n|\Z)", text, re.M)
    if match is None:
        return ""
    lines = match.group(0).split("\n")
    while lines and (lines[-1].strip() == "" or lines[-1].lstrip().startswith("#")):
        lines.pop()
    return "\n".join(lines) + "\n"


def _lines(pattern: str, text: str) -> list[str]:
    return re.findall(r"^" + pattern + r"$", text, re.M)


def h2_policy_job_violations(job: str) -> list[str]:
    """Every line form of the appended job, matched as full lines (no substring or bare-step gaps)."""
    checks = {
        "gate": _lines(r"\s*(?:- )?if: .*", job) == [f"    {H2_POLICY_GATE}", "        if: always()"],
        "runs_on": _lines(r"\s*runs-on: .*", job) == ["    runs-on: ubuntu-24.04"],
        "timeouts": _lines(r"\s*timeout-minutes: .*", job) == ["    timeout-minutes: 25", "        timeout-minutes: 20"],
        "permissions": re.search(r"^    permissions:\n      contents: read\n    concurrency:\n      group: "
                                 r"host-h2-policy-proof\n      cancel-in-progress: false\n    steps:\n", job, re.M) is not None
        and _lines(r"\s*permissions:.*", job) == ["    permissions:"] and _lines(r"\s*contents: .*", job) == ["      contents: read"],
        "steps": _lines(r"      - .*", job) == [f"      - uses: {CHECKOUT} # v4", f"      - uses: {SETUP_PYTHON} # v5",
                                                "      - name: Fixed h2-policy-v1 launcher (20-minute budget, tests 10 minutes)",
                                                "      - name: Upload allowlisted safe evidence"],
        "run": _lines(r"\s*(?:- )?run:.*", job) == ["        run: python scripts/host_h2_policy_proof.py"],
        "checkout": _lines(r"\s*ref: .*", job) == ["          ref: ${{ github.sha }}"]
        and _lines(r"\s*persist-credentials: .*", job) == ["          persist-credentials: false"],
        "python": _lines(r"\s*python-version: .*", job) == ['          python-version: "3.13.5"'],
        "uses": set(re.findall(r"uses: (\S+)", job)) == {CHECKOUT, SETUP_PYTHON, UPLOAD},
        "artifacts": tuple(re.findall(r"^            host-h2-policy-proof/(\S+)$", job, re.M)) == LAUNCHER.ARTIFACT_FILES
        and _lines(r"\s*path: .*", job) == ["          path: |"],
        "upload": _lines(r"\s*retention-days: .*", job) == ["          retention-days: 3"]
        and _lines(r"\s*if-no-files-found: .*", job) == ["          if-no-files-found: error"]
        and _lines(r"\s*name: host-h2-policy-proof.*", job) == ["    name: host-h2-policy-proof (h2-policy-v1)",
                                                                "          name: host-h2-policy-proof"],
    }
    found = [name for name, ok in checks.items() if not ok]
    for word in ("write", "id-token", "environment:", "cache", "env:", "secrets", "pull_request", "github.token", "inputs",
                 "services:", "container:", "workflow_call", "continue-on-error"):
        if word in job:
            found.append("forbidden_" + re.sub(r"[^a-z]", "_", word))
    return found


def workflow_violations(text: str) -> list[str]:
    """Empty iff codeql.yml is exactly the recorded five-job parent, one newline, and the one fully
    constrained h2-policy job, with no other byte anywhere."""
    found = []
    data = text.encode("utf-8")
    if not data.isascii() or hashlib.sha256(data[:BASE_WORKFLOW_BYTES]).hexdigest() != BASE_WORKFLOW_SHA256:
        found.append("prior_workflow")
    if text.count("\njobs:\n") != 1:
        return found + ["job_names"]
    names = re.findall(r"^  ([A-Za-z0-9_-]+):\n", text.split("\njobs:\n", 1)[1], re.M)  # keys under jobs: only
    if names != EXPECTED_JOBS:
        return found + ["job_names"]
    job = _job_block(text, "host-h2-policy-proof")
    if text != text[:BASE_WORKFLOW_BYTES] + "\n" + job:
        found.append("composition")
    if ("\npermissions: {}\n" not in text or "pull_request_target" in text or "secrets." in text or "inputs:" in text
            or "workflow_dispatch: {}" not in text):
        found.append("workflow_head_policy")
    if not all(re.fullmatch(r"[a-z-]+/[a-z-]+(?:/[a-z-]+)?@[0-9a-f]{40}", uses) for uses in re.findall(r"uses: (\S+)", text)):
        found.append("unpinned_action")
    found += h2_policy_job_violations(job)
    if job != H2_POLICY_JOB:
        found.append("h2_policy_job_text")
    return found


# ---------------------------------------------------------------------------------------------
# The whole-namespace ruleset check (a fixture assertion; the product readback judges the named
# table only and is checked separately with ``H2.readback_matches``).

def ruleset_shape(document, rules: int = 4) -> tuple[bool, str]:
    """``nft -j list ruleset`` holds exactly the metainfo and one ``inet heel_lease`` table with one
    set, one map, one chain and ``rules`` rules (four; three for H2-3's control-only shape), all
    inside that table, and nothing else."""
    if not isinstance(document, dict) or list(document) != ["nftables"] or not isinstance(document["nftables"], list):
        return False, "document"
    items = document["nftables"]
    if not items or not isinstance(items[0], dict) or list(items[0]) != ["metainfo"]:
        return False, "metainfo"
    kinds: dict[str, int] = {}
    for item in items[1:]:
        if not isinstance(item, dict) or len(item) != 1:
            return False, "item"
        (kind, body), = item.items()
        if kind not in ("table", "set", "map", "chain", "rule") or not isinstance(body, dict) or body.get("family") != "inet":
            return False, "foreign_object"
        if (body.get("name") if kind == "table" else body.get("table")) != AUTHORITY.TABLE:
            return False, "foreign_table"
        kinds[kind] = kinds.get(kind, 0) + 1
    if kinds != {"table": 1, "set": 1, "map": 1, "chain": 1, "rule": rules}:
        return False, "object_count"
    return True, "exact"


def ruleset_is_empty(document) -> bool:
    return (isinstance(document, dict) and list(document) == ["nftables"] and isinstance(document["nftables"], list)
            and len(document["nftables"]) == 1 and isinstance(document["nftables"][0], dict)
            and list(document["nftables"][0]) == ["metainfo"])


# ---------------------------------------------------------------------------------------------
# Raw rtnetlink veth creation (H2K1's form): the peer lands in R by IFLA_NET_NS_FD, never by a name.

NETLINK_ROUTE, RTM_NEWLINK, NLMSG_ERROR = 0, 16, 2
NLM_F_REQUEST, NLM_F_ACK, NLM_F_EXCL, NLM_F_CREATE = 0x1, 0x4, 0x200, 0x400
IFLA_ADDRESS, IFLA_IFNAME, IFLA_LINKINFO, IFLA_NET_NS_FD = 1, 3, 18, 28
IFLA_INFO_KIND, IFLA_INFO_DATA, VETH_INFO_PEER, NLA_F_NESTED = 1, 2, 1, 0x8000


def _nla(kind: int, payload: bytes) -> bytes:
    length = 4 + len(payload)
    return struct.pack("=HH", length, kind) + payload + b"\0" * (-length % 4)


def _ifinfo() -> bytes:
    return struct.pack("=BxHiII", socket.AF_UNSPEC, 0, 0, 0, 0)


def veth_message(seq: int, name: str, mac: bytes, peer_name: str, peer_mac: bytes, peer_descriptor: int) -> bytes:
    """RTM_NEWLINK (create, exclusive) of ``name`` here with its veth peer created in the namespace of
    ``peer_descriptor`` (IFLA_NET_NS_FD inside VETH_INFO_PEER)."""
    peer = (_ifinfo() + _nla(IFLA_IFNAME, peer_name.encode() + b"\0") + _nla(IFLA_ADDRESS, peer_mac)
            + _nla(IFLA_NET_NS_FD, struct.pack("=I", peer_descriptor)))
    info = _nla(IFLA_INFO_KIND, b"veth\0") + _nla(IFLA_INFO_DATA | NLA_F_NESTED, _nla(VETH_INFO_PEER | NLA_F_NESTED, peer))
    body = _ifinfo() + _nla(IFLA_IFNAME, name.encode() + b"\0") + _nla(IFLA_ADDRESS, mac) + _nla(IFLA_LINKINFO | NLA_F_NESTED, info)
    flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL
    return struct.pack("=IHHII", 16 + len(body), RTM_NEWLINK, flags, seq, 0) + body


def netlink_ack(reply: bytes, seq: int) -> int:
    """The NLMSG_ERROR code of the reply to ``seq`` (0 is the ack); -EPROTO for anything else."""
    if len(reply) < 20:
        return -errno.EPROTO
    _length, kind, _flags, reply_seq, _pid = struct.unpack_from("=IHHII", reply)
    if kind != NLMSG_ERROR or reply_seq != seq:
        return -errno.EPROTO
    return struct.unpack_from("=i", reply, 16)[0]


# ---------------------------------------------------------------------------------------------
# Probes and oracles (H2K1's measurement model).

@dataclass
class Probe:
    kind: str
    expect: str  # the listener label a delivery must reach
    t_before: int
    t_after: int
    admitted: bool
    nonce: bytes
    delivered: bool = False
    misdelivered: bool = False

    @property
    def accepted(self) -> bool:
        return self.admitted or self.delivered


def inside(probes: list[Probe], start_ns: int, end_ns: int) -> list[Probe]:
    return [probe for probe in probes if probe.t_before >= start_ns and probe.t_after <= end_ns]


def after(probes: list[Probe], bound_ns: int) -> list[Probe]:
    return [probe for probe in probes if probe.t_before > bound_ns]


def anomalies(probes: list[Probe]) -> int:
    return sum((probe.delivered and not probe.admitted) or probe.misdelivered for probe in probes)


def live(window: list[Probe], minimum: int) -> bool:
    return (len(window) >= minimum and 100 * sum(p.admitted for p in window) >= LIVE_PERCENT * len(window)
            and 100 * sum(p.delivered for p in window) >= LIVE_PERCENT * len(window))


def closed(window: list[Probe], minimum: int = 1) -> bool:
    """At least ``minimum`` probes, zero admissions or deliveries, no anomaly (no allowance)."""
    return len(window) >= minimum and not [p for p in window if p.accepted] and anomalies(window) == 0


def reachable(window: list[Probe]) -> set[str]:
    return {probe.kind for probe in window if probe.admitted and probe.delivered}


def record(case: str, ok: bool, ints: dict, tokens: dict) -> None:
    entry = {"case": case, "verdict": "pass" if ok else "fail", "control": LAUNCHER.RECORD_CASES[case][1],
             "ints": dict(ints), "tokens": dict(tokens)}
    assert LAUNCHER.sanitize_record(entry) is not None, f"record {case} is outside the closed grammar"
    with open(os.environ[LAUNCHER.RECORDS_ENV], "a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")


def error_token(error: BaseException) -> str:
    name = re.sub(r"[^a-z0-9]", "_", type(error).__name__.lower())[:40]
    code = getattr(error, "code", None)
    if not isinstance(code, str):
        code = error.args[0] if error.args and isinstance(error.args[0], str) else None
    token = f"{name}_{code}" if isinstance(code, str) and re.fullmatch(r"[a-z0-9_]{1,30}", code) else name
    return token if LAUNCHER._TOKEN.fullmatch(token) else "error"


# ---------------------------------------------------------------------------------------------
# Static source/config gates (run everywhere). Each source check is a function of the text, so the
# ordinary-CI oracle (tests/test_host_h2_policy_proof.py) can feed it in-memory mutations.

def _functions(source: str) -> dict[str, ast.FunctionDef]:
    return {node.name: node for node in ast.walk(ast.parse(source)) if isinstance(node, ast.FunctionDef)}


def _top_functions(source: str) -> dict[str, ast.FunctionDef]:
    return {node.name: node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef)}


def _calls(node: ast.AST, name: str) -> list[ast.Call]:
    return [call for call in ast.walk(node) if isinstance(call, ast.Call)
            and ((isinstance(call.func, ast.Name) and call.func.id == name)
                 or (isinstance(call.func, ast.Attribute) and call.func.attr == name))]


def skip_violations(source: str) -> list[str]:
    """One guarded skip path, unreachable with the required switch; every dynamic case calls the
    guard first; no other skip, expected-failure or conditional-collection form."""
    found = []
    if len(re.findall(r"^\s+pytest\.skip\(", source, re.M)) != 1:
        found.append("skip_count")
    if "if REQUIRED:\n            pytest.fail(reason)\n        pytest.skip(reason)" not in source:
        found.append("skip_guard")
    for forbidden in ("x" + "fail", "skip" + "if", "importor" + "skip", "pytest.mark." + "skip", "pytest." + "exit"):
        if forbidden in source:
            found.append("forbidden_" + forbidden.replace(".", "_"))
    for name, node in _top_functions(source).items():
        if name.startswith("test_") and not name.startswith("test_static_"):
            body = node.body[1:] if isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant) else node.body
            first = body[0]
            if not (isinstance(first, ast.Expr) and isinstance(first.value, ast.Call)
                    and getattr(first.value.func, "id", None) == "_require_runtime"):
                found.append("unguarded_" + name)
    return found


def case_violations(source: str) -> list[str]:
    """The test functions are exactly LAUNCHER.REQUIRED_CASES in order and each dynamic case writes
    exactly its one record."""
    functions = _top_functions(source)
    cases = tuple(name for name in functions if name.startswith("test_"))
    found = [] if cases == LAUNCHER.REQUIRED_CASES else ["case_list"]
    recorded: dict = {}
    for name in cases:
        calls = _calls(functions[name], "record")
        for call in calls:
            if not isinstance(call.args[0], ast.Constant) or call.args[0].value in recorded:
                found.append("record_" + name)
                continue
            recorded[call.args[0].value] = name
        if name.startswith("test_static_") and calls:
            found.append("static_record_" + name)
        elif not name.startswith("test_static_") and len(calls) != 1:
            found.append("record_count_" + name)
    if recorded != {case: item[0] for case, item in LAUNCHER.RECORD_CASES.items()}:
        found.append("record_map")
    return found


def fixture_violations(source: str) -> list[str]:
    """Public H1/H2 APIs only, the three H2 seams read but never assigned, no fake installer/helper/
    nft/socket layer, namespaces by descriptor only, every key the slot hop, the unchanged client."""
    tree = ast.parse(source)
    found = []
    used = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name) and node.value.id == "AUTHORITY" and not node.attr.startswith("__")}
    if not used <= set(AUTHORITY.__all__):
        found.append("authority_private")
    h2_used = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
               and isinstance(node.value, ast.Name) and node.value.id == "H2" and not node.attr.startswith("__")}
    if not h2_used <= set(H2_PUBLIC) | set(H2_READ):
        found.append("h2_private")
    # No assignment, deletion or setattr of anything on H2/AUTHORITY/LAUNCHER, and no patching library.
    for node in ast.walk(tree):
        targets = []
        if isinstance(node, (ast.Assign, ast.Delete)):
            targets = node.targets
        elif isinstance(node, (ast.AugAssign, ast.AnnAssign)):
            targets = [node.target]
        for target in targets:
            for part in ast.walk(target):
                if (isinstance(part, ast.Attribute) and isinstance(part.value, ast.Name)
                        and part.value.id in ("H2", "AUTHORITY", "LAUNCHER", "PROFILE")):
                    found.append("assigns_" + part.value.id + "_" + part.attr)
    names = ({node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
             | {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
             | {node.name for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.ClassDef))}
             | {node.arg for node in ast.walk(tree) if isinstance(node, ast.arg)})
    for forbidden in ("setattr", "delattr", "monkeypatch", "mock", "Mock", "MagicMock", "patch", "vars"):
        if forbidden in names:
            found.append("forbidden_name_" + forbidden)
    if [name for name in names if "fake" in name.lower() or "stub" in name.lower()]:
        found.append("fake_name")
    # No private attribute of anything but this module's own objects and the launcher's helpers.
    private = sorted({ast.unparse(node) for node in ast.walk(tree) if isinstance(node, ast.Attribute)
                      and node.attr.startswith("_") and not node.attr.startswith("__")
                      and not (isinstance(node.value, ast.Name) and node.value.id in ("self", "os", "LAUNCHER"))})
    if private:
        found.append("private_attribute")
    for forbidden in ("/run/" + "net" + "ns", "ns" + "enter", "ip " + "net" + "ns", "multi" + "processing", "_gate_table" + "_fixture",
                      "_seams" + "_for_tests", "Cycle" + "Seams", "TEST " + "HELPER", "/proc/" + "{"):
        if forbidden in source:
            found.append("forbidden_text_" + re.sub(r"[^a-z]", "_", forbidden.lower()))
    if re.search(r"\bsockets" + "=", source):  # the client's socket seam
        found.append("client_socket_seam")
    if [node for node in ast.walk(tree) if isinstance(node, ast.Constant) and node.value == "net" + "ns"]:
        found.append("netns_name")
    functions = _top_functions(source)
    every = _functions(source)
    # Every key is the slot hop: prepare(SLOT_SRC, SLOT_DST, <lifetime>) and nothing else.
    prepares = _calls(tree, "prepare")
    if not prepares or not all(len(call.args) == 3 and [ast.unparse(arg) for arg in call.args[:2]] == ["SLOT_SRC", "SLOT_DST"]
                               for call in prepares):
        found.append("prepare_key")
    if sorted({ast.unparse(call) for call in _calls(tree, "create")}) != ["AUTHORITY.LeaseDomain.create()"]:
        found.append("domain_create")
    # The real installer: H2.install only inside Fixture.install on the fixture's descriptor and input,
    # H2.cleanup only on a fixture's descriptor; the fixture writes nft input itself only for P6's seed.
    installs = [call for call in _calls(tree, "install") if ast.unparse(call.func) == "H2.install"]
    cleanups = [call for call in _calls(tree, "cleanup") if ast.unparse(call.func) == "H2.cleanup"]
    install_arguments = [ast.unparse(arg) for call in installs for arg in call.args]
    if (not installs or not cleanups or install_arguments != ["self.l_fd", "self.policy"] * len(installs)
            or not all(len(call.args) == 2 and (ast.unparse(call.args[0]).endswith(".l_fd") or ast.unparse(call.args[0]) == "probe_fd")
                       for call in cleanups)):
        found.append("installer_entry")
    if {name for name, node in functions.items() if '"-f"' in ast.get_source_segment(source, node)} - {"fixture_violations"} != {"_p6"}:
        found.append("fixture_nft_input")
    # The unchanged client: origin, the full preflight tuple, the resolver seam, the real TLSTransport
    # with the harness CA added, a timeout; never a socket or clock seam.
    clients = _calls(tree, "TargetHTTPSClient")
    if len(clients) != 1 or sorted(keyword.arg for keyword in clients[0].keywords) != [
            "origin", "preflight_addresses", "resolver", "timeout_seconds", "tls"] or clients[0].args:
        found.append("client_construction")
    tls = ast.get_source_segment(source, every["_tls_transport"]) if "_tls_transport" in every else ""
    if "transport.TLSTransport()" not in tls or "load_verify_locations(cafile=" not in tls:
        found.append("client_tls")
    # Namespaces: the peer is unshared on a thread and held by descriptor; the veth peer lands there by
    # IFLA_NET_NS_FD from a dup that is closed in a finally; tools enter by setns on a descriptor.
    fresh = ast.get_source_segment(source, functions["_fresh_namespace"]) if "_fresh_namespace" in functions else ""
    if "os.unshare(CLONE_NEWNET)" not in fresh or '"/proc/thread-self/ns/net"' not in fresh:
        found.append("fresh_namespace")
    wire = ast.get_source_segment(source, every["_create_veth"]) if "_create_veth" in every else ""
    if "peer_fd = os.dup(self.r_fd)" not in wire or "finally:\n            os.close(peer_fd)" not in wire:
        found.append("veth_descriptor")
    preexec = [ast.unparse(keyword.value) for call in ast.walk(tree) if isinstance(call, ast.Call)
               for keyword in call.keywords if keyword.arg == "preexec_fn"]
    if preexec != ["lambda: os.setns(fd, CLONE_NEWNET)"]:
        found.append("preexec")
    setns = sorted(ast.unparse(call) for call in _calls(tree, "setns"))
    if setns != ["os.setns(fd, CLONE_NEWNET)", "os.setns(fd, CLONE_NEWNET)"]:
        found.append("setns_form")
    descriptor_uses = sorted(ast.unparse(parent) for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)
                             if isinstance(child, ast.Attribute) and child.attr == "ns_fd")
    if descriptor_uses != ["domain.ns_fd", "os.dup(domain.ns_fd)", "os.dup(domain.ns_fd)"]:
        found.append("ns_fd_use")
    # The fault clock is used only by P6, only through the public ``clock`` keyword.
    users = re.compile(r"\bfault=|FaultClock\(")
    clock_users = {name for name, node in functions.items()
                   if name != "fixture_violations" and users.search(ast.get_source_segment(source, node))}
    if clock_users != {"_p6"}:
        found.append("fault_clock_users")
    clock_keywords = [ast.unparse(keyword.value) for call in ast.walk(tree) if isinstance(call, ast.Call)
                      for keyword in call.keywords if keyword.arg == "clock"]
    if not clock_keywords or not all(value in ("clock", "FaultClock(*fault)") for value in clock_keywords):
        found.append("clock_keyword")
    return found


def helper_sha256(source: str) -> str | None:
    """SHA-256 of the one module-level string constant of ``h2_policy.py`` holding the helper's
    ``os.setns`` -> ``os.execve`` sequence, located structurally (see H2_READ)."""
    found = [node.value.value for node in ast.parse(source).body if isinstance(node, ast.Assign) and len(node.targets) == 1
             and isinstance(node.targets[0], ast.Name) and isinstance(node.value, ast.Constant)
             and isinstance(node.value.value, str) and "os.setns(" in node.value.value and "os.execve(" in node.value.value]
    return hashlib.sha256(found[0].encode()).hexdigest() if len(found) == 1 else None


def test_static_required_profile_cannot_skip():
    assert skip_violations(Path(__file__).read_text(encoding="utf-8")) == []


def test_static_launcher_requires_every_case_function_and_record_in_this_module():
    assert case_violations(Path(__file__).read_text(encoding="utf-8")) == []
    assert LAUNCHER.REQUIRED_CASES[-1] == LAUNCHER.RECORD_CASES["p7"][0] and LAUNCHER.REQUIRED_CASES[-1].startswith("test_p7_")
    assert {item[1] for item in LAUNCHER.RECORD_CASES.values()} <= set(LAUNCHER.CONTROLS)
    assert sorted(case for case, item in LAUNCHER.RECORD_CASES.items() if item[1] == "negative") == ["p2", "p5"]
    assert {item[2] for item in LAUNCHER.RECORD_CASES.values()} == {"pass"}
    # P0-P7, each once, nothing optional; P4 (the unchanged client) is mandatory like every other case.
    assert list(LAUNCHER.RECORD_CASES) == ["p0", "p1", "p2", "p3", "p4", "p5", "p6", "p7"]
    assert LAUNCHER.RECORD_CASES["p4"][1] == "client" and "TargetHTTPSClient" not in LAUNCHER.REQUIRED_CASES[14]
    assert len(LAUNCHER.SEAMS) == 1 and LAUNCHER.SEAMS[0].startswith("FAULT-INJECTION p6 only")


def test_static_launcher_has_one_fixed_profile_branch_budgets_and_no_inputs(tmp_path, capsys):
    source = LAUNCHER_FILE.read_text(encoding="utf-8")
    assert LAUNCHER.main(["--anything"]) == 2
    capsys.readouterr()
    assert "argparse" not in source and source.replace(LAUNCHER.IMPORT_SMOKE, "").count("sys.argv") == 1
    assert sorted(re.findall(r"os\.environ\.get\(([^)]*)\)", source)) == ['"RUNNER_TEMP"']
    assert source.count("environ.get(") == 2 and 'environ.get("GITHUB_REF") != REVIEWED_REF' in source
    assert (LAUNCHER.LAUNCHER_SECONDS, LAUNCHER.TESTS_SECONDS, LAUNCHER.CLEANUP_RESERVE_SECONDS) == (1200, 600, 60)
    assert '["sudo", "-n", "--", sys.executable, "-I", str(Path(__file__).resolve())]' in source
    assert LAUNCHER.PROFILE == "h2-policy-v1" and LAUNCHER.RUNTIME_ASSUMPTION == "running-kernel"
    assert LAUNCHER.REVIEWED_REF == "refs/heads/codex/self-serve-host-h2-policy-proof"
    assert LAUNCHER.ARTIFACT_FILES == ("summary.json", "cases.jsonl", "versions.txt", "cleanup.json", "report.txt")
    assert LAUNCHER.TEST_MODULE == "tests/linux/test_host_h2_policy.py"
    for ref in (None, "refs/heads/main", "refs/heads/codex/self-serve-host-h2-policy-proof-x"):
        with pytest.raises(LAUNCHER.ProofFailure):
            LAUNCHER.check_ref({} if ref is None else {"GITHUB_REF": ref})
    LAUNCHER.check_ref({"GITHUB_REF": LAUNCHER.REVIEWED_REF})
    base = Path(os.path.realpath(tmp_path)) / "heel-host-h2-policy-static"
    wheels, out = base / "wheels", base / "out"
    for directory in (base, wheels, out):
        directory.mkdir(mode=0o700)
        os.chmod(directory, 0o700)
    for name in LAUNCHER.WHEEL_FILES:
        (wheels / name).write_bytes(b"")
    good = {"schema": LAUNCHER.CHILD_SCHEMA, "wheels": str(wheels), "out": str(out), "uid": os.getuid(),
            "tests_seconds": 600, "token": "0123456789abcdef0123456789abcdef"}
    if os.getuid() != 0:
        assert LAUNCHER.validated_request(json.dumps(good)) is not None
    for mutation in ({"extra": 1}, {"schema": "heel.host-lease-key-shape.child.v1"}, {"uid": True}, {"uid": 0},
                     {"tests_seconds": 601}, {"tests_seconds": 5.0}, {"token": "0123456789ABCDEF0123456789ABCDEF"},
                     {"out": str(base)}, {"wheels": str(wheels) + "/"}, {"out": "relative/out"}):
        assert LAUNCHER.validated_request(json.dumps({**good, **mutation})) is None, mutation
    assert LAUNCHER.validated_request("[]") is None and LAUNCHER.validated_request("{") is None
    (wheels / LAUNCHER.WHEEL_FILES[-1]).unlink()  # seven wheels: the client closure is incomplete
    assert LAUNCHER.validated_request(json.dumps(good)) is None


def test_static_closure_profile_and_lock_are_imported_not_copied():
    h1f = LAUNCHER.h1f()
    for name in ("PYTEST_CLOSURE", "PYTHON_VERSION", "PYTEST_VERSION", "FIXED_PATH", "HOST_TOOLS", "ProofFailure",
                 "LOCATOR_REASONS", "LOCATOR_TOKENS", "artifact_scan", "_env", "_sha256"):
        assert getattr(LAUNCHER, name) is getattr(h1f, name), name
    for name in ("SUPPORTED_KERNELS", "kernel_profile"):
        assert getattr(LAUNCHER, name) is getattr(LAUNCHER.profile(), name), name
    source = LAUNCHER_FILE.read_text(encoding="utf-8")
    module = Path(__file__).read_text(encoding="utf-8")
    for text in (source, module):
        for literal in ('"6.' + '17"', '"re' + 'fresh"', "files.python" + "hosted.org", "711ffd45" + "bf766d52", "az" + "ure"):
            assert literal not in text, literal
    assert '"no' + 'op"' not in source  # the READD pin (this module compares H2-1's own cleanup token of that name)
    lock = json.loads(H0_LOCK.read_text(encoding="utf-8"))
    LAUNCHER.closure_matches_lock(lock)
    closure = LAUNCHER.wheel_closure(lock)
    assert [item[0] for item in closure] == list(LAUNCHER.WHEEL_FILES) and len(closure) == 8
    assert {name for name, *_rest in LAUNCHER.CLIENT_CLOSURE} == {"cryptography", "cffi", "pycparser"}
    for text in (source, module):
        for forbidden in ("apt" + "-get", "apt" + " install", "dn" + "f ", "modpr" + "obe", "pip" + " install", "url" + "lib"):
            assert forbidden not in text, forbidden
    assert LEASE_MS == AUTHORITY.MAX_PREPARE_TIMEOUT_MS and LATE_MS < SHORT_MS < LEASE_MS


def test_static_workflow_is_the_recorded_five_jobs_plus_one_fully_constrained_job():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert workflow_violations(text) == []
    prior, job = text[:BASE_WORKFLOW_BYTES], _job_block(text, "host-h2-policy-proof")
    assert text == prior + "\n" + job and job == H2_POLICY_JOB


def _root_reads(source: str) -> set[str]:
    return {"/".join(re.findall(r'"([^"\n]+)"', chain)) for chain in re.findall(r'ROOT((?:\s*/\s*"[^"\n]+")+)', source)}


def test_static_launcher_stages_every_path_the_module_reads(tmp_path):
    """The child copies a fixed file list; everything this module and the launcher (and the H1F/H0
    launchers they import) read under ROOT is in it, and the static selection passes from an exact
    staged copy (no git, no other files)."""
    module = Path(__file__).read_text(encoding="utf-8")
    reads = _root_reads(module) | (_root_reads(LAUNCHER_FILE.read_text(encoding="utf-8")) - {"host-h2-policy-proof"})
    reads -= {".git", "heel"}  # probed below: the checkout vs the staged copy, and the staged heel/ tree
    assert reads <= set(LAUNCHER.STAGE_FILES), sorted(reads - set(LAUNCHER.STAGE_FILES))
    assert len(LAUNCHER.STAGE_FILES) == len(set(LAUNCHER.STAGE_FILES)) == 14
    assert len(LAUNCHER.HEEL_TREE_FILES) == len(set(LAUNCHER.HEEL_TREE_FILES))
    assert all(name.startswith("heel/") for name in LAUNCHER.HEEL_TREE_FILES)
    assert not set(LAUNCHER.HEEL_TREE_FILES) & set(LAUNCHER.STAGE_FILES)
    for name in ("deploy/host/h2_policy.py", "tests/support/edge_tls_harness.py", "heel/runner/http_transport.py",
                 "heel/saas/host_authority.py", "docs/saas/H2_POLICY_INSTALLATION.md"):
        assert name in LAUNCHER.staged_files(), name
    if not (ROOT / ".git").exists():
        assert [name for name in LAUNCHER.staged_files() if not (ROOT / name).is_file()] == []
        tree = sorted(str(path.relative_to(ROOT)) for path in (ROOT / "heel").rglob("*") if path.is_file())
        assert tree == sorted(LAUNCHER.HEEL_TREE_FILES)
        return
    tracked = subprocess.run(["git", "ls-files", "-z", "--", "heel"], cwd=ROOT, capture_output=True, check=True).stdout
    assert tuple(name for name in tracked.decode().split("\0") if name) == LAUNCHER.HEEL_TREE_FILES
    source = LAUNCHER.stage_tree(tmp_path / "src")
    staged = sorted(str(path.relative_to(source)) for path in source.rglob("*") if path.is_file())
    assert staged == sorted(LAUNCHER.staged_files())
    assert all((source / name).read_bytes() == (ROOT / name).read_bytes() for name in LAUNCHER.staged_files())
    # The launcher's own isolated smoke on this copy first, as the child runs it before pytest: it must
    # pass and leave the copy exactly as staged (no __pycache__ or any other entry, the same bytes).
    entries = sorted(str(path.relative_to(source)) for path in source.rglob("*"))
    assert LAUNCHER.import_smoke(Path(sys.executable), source, Path(sys.prefix))
    assert sorted(str(path.relative_to(source)) for path in source.rglob("*")) == entries
    assert sorted(str(path.relative_to(source)) for path in source.rglob("*") if path.is_file()) == staged
    assert all((source / name).read_bytes() == (ROOT / name).read_bytes() for name in LAUNCHER.staged_files())
    statics =[name for name in LAUNCHER.REQUIRED_CASES if name.startswith("test_static_")]
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-k", "static", LAUNCHER.TEST_MODULE],
        cwd=source, capture_output=True, text=True, timeout=600,
        env={"PATH": LAUNCHER.FIXED_PATH, "LC_ALL": "C", "HOME": str(tmp_path), "PYTHONDONTWRITEBYTECODE": "1"})
    assert completed.returncode == 0, completed.stdout[-4000:]
    expected = f"{len(statics)} passed, {len(LAUNCHER.REQUIRED_CASES) - len(statics)} deselected"
    assert completed.stdout.splitlines()[-1].startswith(expected), completed.stdout[-400:]


def test_static_evidence_sanitizer_and_acceptance_rule(tmp_path):
    good = {"case": "p2", "verdict": "pass", "control": "negative", "ints": {"no_key_accepted": 0},
            "tokens": {"h2_state": "receipt_ready"}}
    assert LAUNCHER.sanitize_record(good) == good
    for entry in ({**good, "extra": 1}, {**good, "case": "p8"}, {**good, "control": "admission"}, {**good, "verdict": "info"},
                  {**good, "ints": {"flag": True}}, {**good, "tokens": {"path": "/tmp/x"}}, {**good, "tokens": {"t": "a b"}},
                  {**good, "tokens": {"address": "8.8.8.8/32"}}, {**good, "ints": {f"k{i}": i for i in range(65)}},
                  "not a dict"):
        assert LAUNCHER.sanitize_record(entry) is None, entry
    raw = tmp_path / "records.raw.jsonl"
    raw.write_text(json.dumps(good) + "\nnot json\n", encoding="utf-8")
    assert LAUNCHER.sanitize_records(raw) == ([good], 1)
    records = [{"case": case, "verdict": "pass", "control": item[1], "ints": {}, "tokens": {}}
               for case, item in LAUNCHER.RECORD_CASES.items()]
    by = {r["case"]: r for r in records}
    major_minor = sorted(PROFILE.SUPPORTED_KERNELS)[0]
    by["p0"]["tokens"] = {"kernel_major_minor": major_minor, "nft_version": PROFILE.SUPPORTED_NFT[0], "selftest": "pass",
                          "readd_observation": PROFILE.READD_EXPECTED[major_minor]}
    by["p0"]["ints"] = {"config_hz": PROFILE.SUPPORTED_HZ[-1]}
    junit = {"collected": len(LAUNCHER.REQUIRED_CASES), "passed": len(LAUNCHER.REQUIRED_CASES), "failed": 0, "errors": 0,
             "skipped": 0, "case_functions": list(LAUNCHER.REQUIRED_CASES), "failing": [], "failure_locators": []}
    cleanup, inner = {"host_fingerprints_unchanged": True}, {"pytest_exit": 0, "leftover_processes": 0, "import_smoke": "ok"}
    assert LAUNCHER.evaluate(junit, records, 0, cleanup, inner, 0)["result"] == "PASS"
    by["p0"]["tokens"]["readd_observation"] = "unknown"
    assert LAUNCHER.evaluate(junit, records, 0, cleanup, inner, 0)["result"] == "INCOMPLETE"
    by["p0"]["tokens"]["readd_observation"] = PROFILE.READD_EXPECTED[major_minor]
    assert LAUNCHER.evaluate({**junit, "passed": junit["passed"] - 1, "skipped": 1}, records, 0, cleanup, inner, 0)["result"] == "FAIL"
    assert LAUNCHER.evaluate(junit, [r for r in records if r["case"] != "p4"], 0, cleanup, inner, 0)["result"] == "FAIL"
    assert LAUNCHER.evaluate(junit, records + [records[2]], 0, cleanup, inner, 0)["result"] == "FAIL"
    assert LAUNCHER.evaluate(junit, records, 1, cleanup, inner, 0)["result"] == "FAIL"
    assert LAUNCHER.evaluate(junit, records, 0, {"host_fingerprints_unchanged": False}, inner, 0)["result"] == "FAIL"
    assert LAUNCHER.evaluate(junit, records, 0, cleanup, {**inner, "leftover_processes": 1}, 0)["result"] == "FAIL"
    assert LAUNCHER.evaluate(junit, records, 0, cleanup, {**inner, "import_smoke": None}, 0)["result"] == "FAIL"
    by["p6"]["verdict"] = "fail"
    assert LAUNCHER.evaluate(junit, records, 0, cleanup, inner, 0)["result"] == "FAIL"
    lines = LAUNCHER.version_lines(by, "pinned") + LAUNCHER.report_lines({"result": "PASS", "records": records}, None, cleanup)
    assert "runtime_assumption running-kernel" in lines and "kernel_profile pinned" in lines
    assert all(re.fullmatch(r"[a-z0-9_]+ [A-Za-z0-9_.:/ -]*", line) for line in lines), lines
    assert all(LAUNCHER._TOKEN.fullmatch(error_token(error)) for error in (ValueError(), AUTHORITY.PrepareFailed("installer_refused")))
    assert error_token(AUTHORITY.PrepareFailed("installer_refused")) == "preparefailed_installer_refused"
    # The fixture's whole-ruleset oracle: exactly one heel_lease table of eight objects (seven for the
    # H2-3 control-only shape), else a named part.
    table = {"family": "inet", "name": AUTHORITY.TABLE}
    owned = {"family": "inet", "table": AUTHORITY.TABLE}
    inner_objects = [{"set": owned}, {"map": owned}, {"chain": owned}] + [{"rule": owned}] * 4
    exact = {"nftables": [{"metainfo": {}}, {"table": table}, *inner_objects]}
    assert ruleset_shape(exact) == (True, "exact") and not ruleset_is_empty(exact)
    control_only = {"nftables": exact["nftables"][:-1]}
    assert ruleset_shape(control_only, 3) == (True, "exact") and ruleset_shape(control_only)[1] == "object_count"
    assert ruleset_shape(exact, 3)[1] == "object_count"
    assert ruleset_is_empty({"nftables": [{"metainfo": {}}]})
    for extra, part in (({"table": {"family": "ip", "name": "x"}}, "foreign_object"),
                        ({"table": {"family": "inet", "name": "x"}}, "foreign_table")):
        assert ruleset_shape({"nftables": [*exact["nftables"], extra]})[1] == part
    assert ruleset_shape({"nftables": [{"metainfo": {}}, {"table": table}, *inner_objects[:-1]]})[1] == "object_count"
    assert ruleset_shape({"nftables": [{"table": table}]})[1] == "metainfo" and ruleset_shape([])[1] == "document"


def test_static_fixture_uses_only_public_apis_fd_only_namespaces_and_never_assigns_h2_seams():
    module = Path(__file__).read_text(encoding="utf-8")
    assert fixture_violations(module) == []
    # The staged H2-1 source is the accepted one, its production helper is the pinned one, and the
    # P6 fault clock's triggers are functions of that source that call ``clock()``.
    assert hashlib.sha256(H2_FILE.read_bytes()).hexdigest() == H2_SOURCE_SHA256
    assert helper_sha256(H2_FILE.read_text(encoding="utf-8")) == H2_HELPER_SHA256
    assert helper_sha256("X = 'os.setns( os.execve('\nY = 'os.setns( os.execve('\n") is None  # exactly one constant
    assert hashlib.sha256(HARNESS_FILE.read_bytes()).hexdigest() == HARNESS_SHA256
    h2_functions = _functions(H2_FILE.read_text(encoding="utf-8"))
    for name in FAULT_TRIGGERS:
        assert [ast.unparse(call) for call in _calls(h2_functions[name], "clock")], name
    assert tuple(sorted(H2.__all__)) == H2_PUBLIC
    assert H2.NFT_PATH is AUTHORITY.NFT_PATH and H2.RECEIPT_SCHEMA == RECEIPT_SCHEMA
    message = veth_message(7, "hp1l", b"\x02\0\0\0\0\x01", "hp1r", b"\x02\0\0\0\0\x02", 5)
    assert struct.unpack_from("=IHHII", message) == (len(message), RTM_NEWLINK, 0x605, 7, 0) and len(message) % 4 == 0
    assert struct.pack("=I", 5) in message and b"veth\0" in message
    assert netlink_ack(struct.pack("=IHHIIi", 36, NLMSG_ERROR, 0, 7, 0, 0) + b"\0" * 16, 7) == 0
    assert netlink_ack(struct.pack("=IHHIIi", 36, NLMSG_ERROR, 0, 7, 0, -17) + b"\0" * 16, 7) == -17
    assert netlink_ack(struct.pack("=IHHIIi", 36, NLMSG_ERROR, 0, 8, 0, 0) + b"\0" * 16, 7) == -errno.EPROTO


def test_static_fixture_literals_are_the_recorded_public_pick():
    transport = importlib.import_module("heel.runner.http_transport")
    assert tuple(str(address) for address in transport.select_public_addresses(list(reversed(RECORDED_TUPLE)))) == RECORDED_TUPLE
    for literal in RECORDED_TUPLE:
        assert ipaddress.ip_address(literal).is_global, literal
        assert transport.select_public_addresses([literal]) == (ipaddress.ip_address(literal),), literal
    assert set(TARGETS) | {UNAPPROVED, WRONG_SOURCE, TARGET6} == set(RECORDED_TUPLE)
    assert tuple(sorted(TARGETS, key=lambda value: ipaddress.ip_address(value).packed)) == TARGETS
    observed = transport.select_public_addresses([TARGET6, *reversed(TARGETS)])
    policy = H2.build_input(generation_id="0" * 32, namespace_identity=(1, 2), slot_id=SLOT_ID, slot_hop_src=SLOT_SRC,
                            slot_hop_dst=SLOT_DST, bootstrap_fence="1" * 32, egress_hostname=HOSTNAME, egress_port=PORT,
                            observed_public_addresses=observed)
    assert policy.observed_public_addresses == observed and len(observed) == 3  # the AAAA stays in the tuple
    assert tuple(map(str, policy.ipv4_egress_targets)) == TARGETS and str(observed[0]) == TARGETS[0]
    assert transport.normalize_target_origin("https://" + HOSTNAME) == "https://" + HOSTNAME
    for local in (SLOT_SRC, SLOT_DST, PEER6, GATEWAY6):  # documentation/ULA, never a target
        assert not ipaddress.ip_address(local).is_global, local


def test_static_doc_names_every_case_and_the_limits():
    doc = DOC.read_text(encoding="utf-8")
    for case in LAUNCHER.RECORD_CASES:
        assert f"**{case.upper()}**" in doc, case
    for phrase in ("INCOMPLETE", "kernel_profile pinned", "runtime_assumption running-kernel", "UNRUN", "FAULT-INJECTION",
                   "python scripts/host_h2_policy_proof.py", "IFLA_NET_NS_FD", "no fallback", "TargetHTTPSClient",
                   "L3/L4", "H3", "H6", "h2-policy-v1", "refs/heads/codex/self-serve-host-h2-policy-proof", "DNS",
                   "nft -j list ruleset", "readback_matches", "import smoke", "eight wheels", "O1",
                   "component evidence only", "ScriptedTLSServer"):
        assert phrase in doc, phrase


# ---------------------------------------------------------------------------------------------
# Runtime guard (the single skip path).

def _runtime_unavailable_reason() -> str | None:
    if not sys.platform.startswith("linux"):
        return "requires the fixed h2-policy launcher on Linux"
    if sys.version_info < (3, 12) or not hasattr(os, "setns") or not hasattr(os, "unshare"):
        return "requires the launcher's pinned Python with namespace support"
    if not hasattr(socket, "AF_NETLINK"):
        return "requires rtnetlink sockets"
    if os.geteuid() != 0:
        return "requires the launcher's isolated namespace driver"
    if not all(os.environ.get(name) for name in (LAUNCHER.RECORDS_ENV, LAUNCHER.WORK_ENV, LAUNCHER.TOKEN_ENV)):
        return "requires the fixed h2-policy launcher environment"
    if [name for _index, name in socket.if_nameindex() if name != "lo"]:
        return "refuses to run outside the launcher's loopback-only namespace"
    if AUTHORITY.NFT_PATH is None or AUTHORITY.IP_PATH is None:
        return "requires nft and ip at their fixed paths"
    return None


def _require_runtime() -> None:
    reason = _runtime_unavailable_reason()
    if reason is not None:
        if REQUIRED:
            pytest.fail(reason)
        pytest.skip(reason)


def _run_token() -> bytes:
    value = os.environ.get(LAUNCHER.TOKEN_ENV, "")
    return bytes.fromhex(value) if re.fullmatch(r"[0-9a-f]{32}", value) else os.urandom(16)


TOKEN = _run_token()


def sleep_until(target_ns: int) -> None:
    delay = target_ns - time.monotonic_ns()
    if delay > 0:
        time.sleep(delay / 1e9)


class ProfileUnavailable(RuntimeError):
    """P0 did not capture a pinned profile with a tick; every later bound would be unfounded."""


class InjectedFailure(RuntimeError):
    """P7's deliberate failure inside a live fixture."""


STATE: dict = {}  # p0: tick_ns, provenance and the outer-namespace fingerprint baseline
RESIDUALS: list[dict] = []
SOCKETS: list = []
OPEN_FIXTURES: set = set()
COUNTERS = {"fixtures": 0, "domains": 0, "sockets": 0, "probes": 0, "installs": 0, "client_requests": 0}


def _tick_ns() -> int:
    if "tick_ns" not in STATE:
        raise ProfileUnavailable("profile_unavailable")
    return STATE["tick_ns"]


def _thread(target, name: str) -> threading.Thread:
    return threading.Thread(target=target, name="heel-h2p-" + name, daemon=True)


def _in_netns(fd: int, function):
    """Run ``function`` on a fresh thread that entered the namespace of ``fd`` (setns is per thread;
    threads that thread starts inherit it)."""
    result: dict = {}

    def run() -> None:
        try:
            os.setns(fd, CLONE_NEWNET)
            result["value"] = function()
        except BaseException as error:  # noqa: BLE001 - re-raised on the caller's thread
            result["error"] = error

    thread = _thread(run, "enter")
    thread.start()
    thread.join(20)
    if "error" in result:
        raise result["error"]
    if "value" not in result:
        raise RuntimeError("netns_thread_timeout")
    return result["value"]


def _fresh_namespace() -> int:
    """A new network namespace held only by the returned descriptor: a fixture thread unshares its
    own network namespace, opens it once and exits (no helper process, no name, no PID)."""
    result: dict = {}

    def run() -> None:
        try:
            os.unshare(CLONE_NEWNET)
            result["fd"] = os.open("/proc/thread-self/ns/net", os.O_RDONLY | os.O_CLOEXEC)
        except BaseException as error:  # noqa: BLE001 - re-raised on the caller's thread
            result["error"] = error

    thread = _thread(run, "unshare")
    thread.start()
    thread.join(20)
    if "error" in result:
        raise result["error"]
    if "fd" not in result:
        raise RuntimeError("unshare_thread_timeout")
    return result["fd"]


def _identity(fd: int) -> tuple[int, int]:
    info = os.fstat(fd)
    return info.st_dev, info.st_ino


def _namespace_fds() -> set[str]:
    """The network-namespace inodes this process holds descriptors to (readlink text only)."""
    found = set()
    for entry in os.listdir("/proc/self/fd"):
        with contextlib.suppress(OSError):
            target = os.readlink("/proc/self/fd/" + entry)
            if target.startswith("net:["):
                found.add(target)
    return found


def _run_in(fd: int | None, argv: list[str], data: str | None = None) -> subprocess.CompletedProcess:
    """One fixed fixture tool in the namespace of ``fd`` (the outer namespace for None); output stays
    private. Never the installer: the H2 table is written only by ``H2.install``."""
    if fd is None:
        return subprocess.run(argv, input=data, capture_output=True, text=True, timeout=30, env=LAUNCHER._env())
    return subprocess.run(argv, input=data, capture_output=True, text=True, timeout=30, env=LAUNCHER._env(),
                          preexec_fn=lambda: os.setns(fd, CLONE_NEWNET))  # noqa: PLW1509


def _ruleset(fd: int) -> tuple[object, str]:
    """(``nft -j list ruleset`` document or None, SHA-256 of the raw listing) in the namespace of ``fd``."""
    listing = _run_in(fd, [AUTHORITY.NFT_PATH, "-j", "list", "ruleset"])
    try:
        document = json.loads(listing.stdout) if listing.returncode == 0 else None
    except ValueError:
        document = None
    return document, hashlib.sha256(listing.stdout.encode()).hexdigest()


def _named_table(fd: int) -> tuple[object, str]:
    """(``nft -j list table inet heel_lease`` document or None, SHA-256 of the raw listing)."""
    listing = _run_in(fd, [AUTHORITY.NFT_PATH, "-j", "list", "table", "inet", AUTHORITY.TABLE])
    try:
        document = json.loads(listing.stdout) if listing.returncode == 0 else None
    except ValueError:
        document = None
    return document, hashlib.sha256(listing.stdout.encode()).hexdigest()


def _empty_ruleset(fd: int) -> bool:
    plain = _run_in(fd, [AUTHORITY.NFT_PATH, "list", "ruleset"])
    document, _digest = _ruleset(fd)
    return plain.returncode == 0 and plain.stdout.strip() == "" and ruleset_is_empty(document)


def _outer_fingerprint() -> dict[str, str]:
    """Hashes of the outer namespace's links, addresses, routes and ruleset (raw text never kept)."""
    commands = {"links": [AUTHORITY.IP_PATH, "-o", "link", "show"], "addresses": [AUTHORITY.IP_PATH, "-o", "addr", "show"],
                "routes4": [AUTHORITY.IP_PATH, "-4", "route", "show", "table", "all"],
                "routes6": [AUTHORITY.IP_PATH, "-6", "route", "show", "table", "all"],
                "ruleset": [AUTHORITY.NFT_PATH, "-s", "list", "ruleset"]}
    digests = {}
    for name, argv in commands.items():
        completed = _run_in(None, argv)
        digests[name] = hashlib.sha256((str(completed.returncode) + completed.stdout).encode()).hexdigest()
    return digests


def _transport():
    """The unchanged client module from the staged ``heel/`` tree (P0 checks the origin)."""
    return importlib.import_module("heel.runner.http_transport")


def _harness():
    """The unmodified TLS harness from the staged tree (its CA and response builder only)."""
    return importlib.import_module("tests.support.edge_tls_harness")


def _observed(addresses) -> tuple:
    """The trusted-constructor precondition: the unchanged ``select_public_addresses`` output."""
    return _transport().select_public_addresses(list(addresses))


OBSERVED_LITERALS = (*TARGETS, TARGET6)  # the dual-stack A+AAAA answer every admitting case installs


def policy_input(fd: int, addresses, *, identity: tuple[int, int] | None = None, control_only: bool = False):
    """A fresh H2PolicyInput for the namespace of ``fd``: a new generation id and fence, the slot hop,
    the validated hostname and port, and the canonical full tuple (H2-3: the empty tuple and
    ``control_only`` for a binding generation)."""
    options = {"observed_public_addresses": (), "control_only": True} if control_only else {
        "observed_public_addresses": _observed(addresses)}
    return H2.build_input(generation_id=secrets.token_hex(16), namespace_identity=identity or _identity(fd),
                          slot_id=SLOT_ID, slot_hop_src=SLOT_SRC, slot_hop_dst=SLOT_DST,
                          bootstrap_fence=secrets.token_hex(16), egress_hostname=HOSTNAME, egress_port=PORT, **options)


def receipt_exact(outcome, policy) -> bool:
    """The receipt is the H2-A cycle's exact canonical document for this input, and only on success."""
    if outcome.state != "receipt_ready" or type(outcome.receipt) is not bytes:
        return False
    expected = {"schema": RECEIPT_SCHEMA, "generation_id": policy.generation_id,
                "namespace_dev": policy.namespace_identity[0], "namespace_ino": policy.namespace_identity[1],
                "bootstrap_fence": policy.bootstrap_fence, "installed": True}
    canonical = json.dumps(expected, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return outcome.receipt == canonical


def outcome_tokens(prefix: str, outcome) -> dict[str, str]:
    tokens = {f"{prefix}_state": outcome.state, f"{prefix}_receipt": "present" if outcome.receipt is not None else "absent"}
    for key, value in outcome.tokens.items():
        if re.fullmatch(r"[a-z]{1,12}", key) and isinstance(value, str) and LAUNCHER._TOKEN.fullmatch(value):
            tokens[f"{prefix}_{key}"] = value
    return tokens


class FaultClock:
    """CONTROLLED FAULT INJECTION (``LAUNCHER.SEAMS``; P6 only), passed through the public ``clock``
    argument of ``install``/``cleanup``: real monotonic time until the ``nth`` call made from the H2-1
    function named ``trigger``, then ``jump_ms`` later from that call on. Nothing else is substituted:
    the helper, ``setns``, nft and the kernel are real. It proves the fail-closed state machine's
    outcome on a real namespace, never a kernel timeout."""

    def __init__(self, trigger: str, nth: int, jump_ms: int):
        if trigger not in FAULT_TRIGGERS:
            raise ValueError("trigger")
        self.trigger, self.nth, self.jump_ns, self.calls, self.jumped = trigger, nth, jump_ms * MS, 0, False

    def __call__(self) -> int:
        caller = inspect.currentframe().f_back.f_code.co_name
        if not self.jumped and caller == self.trigger:
            self.calls += 1
            self.jumped = self.calls >= self.nth
        return time.monotonic_ns() + (self.jump_ns if self.jumped else 0)


# ---------------------------------------------------------------------------------------------
# The owned fixture: generation namespace L (the domain's own, via a dup of ns_fd), peer namespace R
# (fd-only), one veth, fixed listeners in R, a pre-table reachability baseline; the table itself is
# only ever written by H2.install.

LISTENERS = (("t1", socket.AF_INET, socket.SOCK_STREAM, (TARGETS[0], PORT)),
             ("t2", socket.AF_INET, socket.SOCK_STREAM, (TARGETS[1], PORT)),
             ("t3", socket.AF_INET, socket.SOCK_STREAM, (UNAPPROVED, PORT)),
             ("t1_wrong_port", socket.AF_INET, socket.SOCK_STREAM, (TARGETS[0], WRONG_PORT)),
             ("t1_udp", socket.AF_INET, socket.SOCK_DGRAM, (TARGETS[0], PORT)),
             ("t6", socket.AF_INET6, socket.SOCK_STREAM, (TARGET6, PORT)),
             # H2-3: the slot gateway's control listener and its negative twins.
             ("gw", socket.AF_INET, socket.SOCK_STREAM, (SLOT_DST, PORT)),
             ("gw_wrong_port", socket.AF_INET, socket.SOCK_STREAM, (SLOT_DST, WRONG_PORT)),
             ("gw_udp", socket.AF_INET, socket.SOCK_DGRAM, (SLOT_DST, PORT)),
             ("gw6", socket.AF_INET6, socket.SOCK_STREAM, (GATEWAY6, PORT)))
# The fixed probe kinds: kind -> (source, target, port, transport, listener label).
PLAN = {
    "t1": (SLOT_SRC, TARGETS[0], PORT, "tcp", "t1"),
    "t2": (SLOT_SRC, TARGETS[1], PORT, "tcp", "t2"),
    "wrong_source": (WRONG_SOURCE, TARGETS[0], PORT, "tcp", "t1"),
    "unapproved_target": (SLOT_SRC, UNAPPROVED, PORT, "tcp", "t3"),
    "wrong_port": (SLOT_SRC, TARGETS[0], WRONG_PORT, "tcp", "t1_wrong_port"),
    "udp": (SLOT_SRC, TARGETS[0], PORT, "udp", "t1_udp"),
    "ipv6": (PEER6, TARGET6, PORT, "tcp6", "t6"),
    "gateway": (SLOT_SRC, SLOT_DST, PORT, "tcp", "gw"),
    "gateway_wrong_source": (WRONG_SOURCE, SLOT_DST, PORT, "tcp", "gw"),
    "gateway_wrong_port": (SLOT_SRC, SLOT_DST, WRONG_PORT, "tcp", "gw_wrong_port"),
    "gateway_udp": (SLOT_SRC, SLOT_DST, PORT, "udp", "gw_udp"),
    "gateway_ipv6": (PEER6, GATEWAY6, PORT, "tcp6", "gw6"),
}
NEGATIVES = ("wrong_source", "unapproved_target", "wrong_port", "udp", "ipv6")
GATEWAY_NEGATIVES = ("gateway_wrong_source", "gateway_wrong_port", "gateway_udp", "gateway_ipv6")


def _listener(r_fd: int, family: int, kind: int, address: tuple) -> socket.socket:
    def create() -> socket.socket:
        sock = socket.socket(family, kind)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(address)
            if kind == socket.SOCK_STREAM:
                sock.listen(64)
            sock.setblocking(False)
        except BaseException:
            sock.close()
            raise
        return sock

    sock = _in_netns(r_fd, create)
    SOCKETS.append(sock)
    COUNTERS["sockets"] += 1
    return sock


class Peer:
    """The fixed nonce listeners in R and one thread that records which nonce reached which listener."""

    def __init__(self, r_fd: int):
        self.sockets: dict = {}
        self.seen: dict[bytes, str] = {}
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.thread: threading.Thread | None = None
        for label, family, kind, address in LISTENERS:
            self.sockets[_listener(r_fd, family, kind, address)] = (label, kind)

    def start(self) -> "Peer":
        self.thread = _thread(self._loop, "peer")
        self.thread.start()
        return self

    def _note(self, label: str, data: bytes) -> None:
        if len(data) >= NONCE_BYTES and data[:16] == TOKEN:
            with self.lock:
                self.seen.setdefault(bytes(data[:NONCE_BYTES]), label)

    def _loop(self) -> None:
        connections: dict = {}
        try:
            while not self.stop.is_set():
                readable, _w, _x = select.select([*self.sockets, *connections], [], [], 0.05)
                for sock in readable:
                    if sock in connections:
                        label, buffer = connections[sock]
                        chunk = b""
                        with contextlib.suppress(OSError):
                            chunk = sock.recv(64)
                        buffer += chunk
                        if not chunk or len(buffer) >= NONCE_BYTES:
                            self._note(label, buffer)
                            sock.close()
                            del connections[sock]
                        continue
                    label, kind = self.sockets[sock]
                    with contextlib.suppress(BlockingIOError, InterruptedError):
                        if kind == socket.SOCK_STREAM:
                            connection, _address = sock.accept()
                            connection.setblocking(False)
                            connections[connection] = (label, bytearray())
                        else:
                            self._note(label, sock.recv(64))
        except (OSError, ValueError):
            pass
        finally:
            for connection in connections:
                with contextlib.suppress(OSError):
                    connection.close()

    def delivered(self, nonce: bytes) -> str | None:
        with self.lock:
            return self.seen.get(nonce)

    def close(self) -> None:
        self.stop.set()
        if self.thread is not None:
            self.thread.join(5)
        for sock in self.sockets:
            with contextlib.suppress(OSError):
                sock.close()


TLS_LISTENERS = (("t1", socket.AF_INET, (TARGETS[0], PORT)), ("t2", socket.AF_INET, (TARGETS[1], PORT)),
                 ("t6", socket.AF_INET6, (TARGET6, PORT)))


class TLSPeer:
    """P4's TLS origin in R: one listener per pinned address (both IPv4 targets and the AAAA), the
    harness's ephemeral CA leaf for HOSTNAME, a fixed ``raw_json_response`` to every GET/HEAD. It is
    not ``ScriptedTLSServer``: that class binds 127.0.0.1 and answers POST only, and the harness stays
    unmodified (docs/saas/H2_POLICY_PROOF.md)."""

    def __init__(self, r_fd: int, ca):
        self.context = ca.server_context()
        self.response = _harness().raw_json_response(200, b"{}")
        self.sockets = {_listener(r_fd, family, socket.SOCK_STREAM, address): label for label, family, address in TLS_LISTENERS}
        self.accepted = {label: 0 for label, _family, _address in TLS_LISTENERS}
        self.served: list[tuple[str, str, str, str]] = []  # (label, request line, host header, local address)
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.thread: threading.Thread | None = None

    def start(self) -> "TLSPeer":
        self.thread = _thread(self._loop, "tls")
        self.thread.start()
        return self

    def _serve(self, label: str, connection: socket.socket) -> None:
        connection.setblocking(True)
        connection.settimeout(2)
        try:
            wrapped = self.context.wrap_socket(connection, server_side=True)
        except (ssl.SSLError, OSError):
            return  # a plain TCP reachability probe or a refused handshake: counted as accepted only
        try:
            data = b""
            while b"\r\n\r\n" not in data and len(data) < 16384:
                chunk = wrapped.recv(4096)
                if not chunk:
                    return
                data += chunk
            head = data.split(b"\r\n\r\n", 1)[0].decode("ascii", "replace").split("\r\n")
            host = next((line.split(":", 1)[1].strip() for line in head[1:] if line.lower().startswith("host:")), "")
            with self.lock:
                self.served.append((label, head[0], host, wrapped.getsockname()[0]))
            wrapped.sendall(self.response)
        except (ssl.SSLError, OSError):
            return
        finally:
            with contextlib.suppress(OSError):
                wrapped.close()

    def _loop(self) -> None:
        try:
            while not self.stop.is_set():
                readable, _w, _x = select.select(list(self.sockets), [], [], 0.05)
                for sock in readable:
                    label = self.sockets[sock]
                    with contextlib.suppress(BlockingIOError, InterruptedError):
                        connection, _address = sock.accept()
                        with self.lock:
                            self.accepted[label] += 1
                        try:
                            self._serve(label, connection)
                        finally:
                            with contextlib.suppress(OSError):
                                connection.close()
        except (OSError, ValueError):
            pass

    def counts(self) -> tuple[dict[str, int], int]:
        with self.lock:
            return dict(self.accepted), len(self.served)

    def delivered(self, _nonce: bytes) -> str | None:
        return None  # P4 grades connections, handshakes and requests, not nonces

    def close(self) -> None:
        self.stop.set()
        if self.thread is not None:
            self.thread.join(5)
        for sock in self.sockets:
            with contextlib.suppress(OSError):
                sock.close()


class Fixture:
    def __init__(self, domain, peer: str | None):
        COUNTERS["fixtures"] += 1
        self.n = COUNTERS["fixtures"]
        self.domain = domain
        self.l_fd: int | None = os.dup(domain.ns_fd)  # the process-owned dup of the public descriptor
        self.r_fd: int | None = None
        self.peer = None
        self.identities: set[str] = set()
        self.facts: dict = {}
        self.policy = None
        self.outcome = None
        OPEN_FIXTURES.add(self)
        try:
            outer = os.stat("/proc/self/ns/net")
            ids = {_identity(self.l_fd), (outer.st_dev, outer.st_ino)}
            if peer is not None:
                self.r_fd = _fresh_namespace()
                ids.add(_identity(self.r_fd))
            self.facts["namespaces_distinct"] = int(len(ids) == (2 if peer is None else 3))
            self.identities = {f"net:[{_identity(fd)[1]}]" for fd in (self.l_fd, self.r_fd) if fd is not None}
            self.facts["fresh_ruleset_empty"] = int(_empty_ruleset(self.l_fd))
            if peer is not None:
                self._wire()
            if peer == "nonce":
                self.peer = Peer(self.r_fd).start()
                self.facts.update(self._baseline())
            elif peer == "tls":
                self.ca = _harness().EphemeralCA(Path(os.environ[LAUNCHER.WORK_ENV]) / f"ca-{self.n}", names=(HOSTNAME,))
                self.peer = TLSPeer(self.r_fd, self.ca).start()
        except BaseException:
            self.close()
            raise

    def ip(self, fd: int, *arguments: str) -> bool:
        return _run_in(fd, [AUTHORITY.IP_PATH, *arguments]).returncode == 0

    def _create_veth(self, name: str, mac: bytes, peer_name: str, peer_mac: bytes) -> None:
        peer_fd = os.dup(self.r_fd)
        try:
            message = veth_message(self.n, name, mac, peer_name, peer_mac, peer_fd)

            def send() -> bytes:
                sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_ROUTE)
                try:
                    sock.settimeout(5)
                    sock.bind((0, 0))
                    sock.send(message)
                    return sock.recv(65536)
                finally:
                    sock.close()

            code = netlink_ack(_in_netns(self.l_fd, send), self.n)
        finally:
            os.close(peer_fd)
        if code != 0:
            raise OSError(-code, "rtnetlink veth")

    def _wire(self) -> None:
        a, b = f"hp{self.n}l", f"hp{self.n}r"
        mac_l, mac_r = bytes((2, 0x48, 0x32, 0, self.n & 255, 0x0a)), bytes((2, 0x48, 0x32, 0, self.n & 255, 0x0b))
        text_l, text_r = (":".join(f"{byte:02x}" for byte in mac) for mac in (mac_l, mac_r))
        self._create_veth(a, mac_l, b, mac_r)
        self.facts["peer_link_in_r"] = int(self.ip(self.r_fd, "link", "show", "dev", b))
        steps = [(self.l_fd, "link", "set", "lo", "up"), (self.r_fd, "link", "set", "lo", "up"),
                 (self.l_fd, "addr", "add", f"{SLOT_SRC}/32", "dev", a), (self.l_fd, "addr", "add", f"{WRONG_SOURCE}/32", "dev", a),
                 *[(self.r_fd, "addr", "add", f"{target}/32", "dev", b) for target in (*TARGETS, UNAPPROVED, SLOT_DST)],
                 (self.l_fd, "link", "set", a, "up"), (self.r_fd, "link", "set", b, "up"),
                 *[(self.l_fd, "route", "add", f"{target}/32", "dev", a, "src", SLOT_SRC)
                   for target in (*TARGETS, UNAPPROVED, SLOT_DST)],
                 *[(self.l_fd, "neigh", "replace", target, "lladdr", text_r, "dev", a, "nud", "permanent")
                   for target in (*TARGETS, UNAPPROVED, SLOT_DST)],
                 *[(self.r_fd, "route", "add", f"{source}/32", "dev", b) for source in (SLOT_SRC, WRONG_SOURCE)],
                 *[(self.r_fd, "neigh", "replace", source, "lladdr", text_l, "dev", b, "nud", "permanent")
                   for source in (SLOT_SRC, WRONG_SOURCE)],
                 # IPv6 is mandatory here: the dual-stack target and the IPv6 denial need it.
                 (self.l_fd, "-6", "addr", "add", f"{PEER6}/128", "dev", a, "nodad"),
                 *[(self.r_fd, "-6", "addr", "add", f"{target}/128", "dev", b, "nodad") for target in (TARGET6, GATEWAY6)],
                 *[(self.l_fd, "-6", "route", "add", f"{target}/128", "dev", a) for target in (TARGET6, GATEWAY6)],
                 (self.r_fd, "-6", "route", "add", f"{PEER6}/128", "dev", b),
                 *[(self.l_fd, "-6", "neigh", "replace", target, "lladdr", text_r, "dev", a, "nud", "permanent")
                   for target in (TARGET6, GATEWAY6)],
                 (self.r_fd, "-6", "neigh", "replace", PEER6, "lladdr", text_l, "dev", b, "nud", "permanent")]
        for fd, *arguments in steps:
            if not self.ip(fd, *arguments):
                raise RuntimeError("fixture_ip_" + arguments[0].lstrip("-"))
        # No default route and no other address in either namespace: the only reachable peers are R's.
        routes = _run_in(self.l_fd, [AUTHORITY.IP_PATH, "-4", "route", "show", "default"]).stdout.strip()
        routes6 = _run_in(self.l_fd, [AUTHORITY.IP_PATH, "-6", "route", "show", "default"]).stdout.strip()
        self.facts["default_routes"] = int(bool(routes)) + int(bool(routes6))

    def _baseline(self) -> dict:
        """Before any table exists every fixed probe kind connects/delivers, so a later denial is the
        policy's, not the topology's."""
        probes = self.settle([self.probe(kind) for kind in PLAN])
        return {"baseline_kinds": len(PLAN), "baseline_reachable": len(reachable(probes))}

    def install(self, addresses=OBSERVED_LITERALS, *, identity: tuple[int, int] | None = None, fault=None,
                control_only: bool = False):
        """The real installer on the fixture's descriptor (P6 alone passes its labelled fault clock;
        P5 alone the H2-3 control-only shape)."""
        self.policy = policy_input(self.l_fd, addresses, identity=identity, control_only=control_only)
        COUNTERS["installs"] += 1
        if fault is None:
            self.outcome = H2.install(self.l_fd, self.policy)
        else:
            self.outcome = H2.install(self.l_fd, self.policy, clock=FaultClock(*fault))
        return self.outcome

    def table_facts(self) -> dict:
        """The whole-namespace check and the product's own readback of the named table, separately."""
        whole, whole_sha = _ruleset(self.l_fd)
        named, named_sha = _named_table(self.l_fd)
        whole_ok, whole_part = ruleset_shape(whole, 3 if self.policy.control_only else 4)
        named_ok, named_tokens = H2.readback_matches(named, self.policy)
        return {"whole_ok": whole_ok, "named_ok": named_ok,
                "tokens": {"ruleset": whole_part, "readback": named_tokens["readback"], "readback_part": named_tokens["part"],
                           "ruleset_sha256": whole_sha, "readback_sha256": named_sha}}

    def gate_ready(self) -> bool:
        if self.outcome is None or self.policy is None:
            return False
        table = self.table_facts()
        self.facts.update(receipt_exact=int(receipt_exact(self.outcome, self.policy)), ruleset_exact=int(table["whole_ok"]),
                          readback_exact=int(table["named_ok"]))
        self.facts["table_tokens"] = table["tokens"]
        return (self.outcome.state == "receipt_ready" and self.facts["receipt_exact"] == 1 and table["whole_ok"]
                and table["named_ok"] and self.facts.get("fresh_ruleset_empty") == 1
                and self.facts.get("namespaces_distinct") == 1 and self.facts.get("default_routes", 0) == 0)

    def probe(self, kind: str) -> Probe:
        """One fresh connection (or datagram) of a fixed kind from L; admission is the client-side
        verdict inside its own CLOCK_MONOTONIC bracket, delivery only confirms it."""
        source, target, port, transport, expect = PLAN[kind]
        family = socket.AF_INET6 if transport == "tcp6" else socket.AF_INET
        kind_type = socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM
        nonce = TOKEN + os.urandom(NONCE_BYTES - len(TOKEN))
        COUNTERS["probes"] += 1

        def create() -> socket.socket:
            sock = socket.socket(family, kind_type)
            try:
                sock.bind((source, 0))
                sock.setblocking(False)
            except BaseException:
                sock.close()
                raise
            return sock

        sock = _in_netns(self.l_fd, create)
        try:
            t_before = time.monotonic_ns()
            if kind_type == socket.SOCK_DGRAM:
                try:
                    sock.sendto(nonce, (target, port))
                    admitted = True
                except OSError:
                    admitted = False
                t_after = time.monotonic_ns()
            else:
                status = sock.connect_ex((target, port))
                if status == errno.EINPROGRESS:
                    _r, writable, _x = select.select([], [sock], [], CONNECT_TIMEOUT_S)
                    status = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) if writable else errno.ETIMEDOUT
                admitted = status == 0
                t_after = time.monotonic_ns()
                if admitted:
                    with contextlib.suppress(OSError):
                        sock.setblocking(True)
                        sock.settimeout(0.2)
                        sock.sendall(nonce)
        finally:
            sock.close()
        return Probe(kind, expect, t_before, t_after, admitted, nonce)

    def series(self, kinds: list[str], start_ns: int, until_ns: int, *, limit: int = 120) -> list[Probe]:
        """Probes every PROBE_INTERVAL_NS from ``start_ns`` while the slot is not past ``until_ns``."""
        probes = []
        for index in range(limit):
            slot = start_ns + index * PROBE_INTERVAL_NS
            if slot > until_ns:
                break
            sleep_until(slot)
            probes.append(self.probe(kinds[index % len(kinds)]))
        return probes

    def settle(self, probes: list[Probe]) -> list[Probe]:
        time.sleep(0.3)  # in-flight bytes arrive; delivery only, never an admission time
        for probe in probes:
            label = self.peer.delivered(probe.nonce)
            probe.delivered = label == probe.expect
            probe.misdelivered = label is not None and label != probe.expect
        return probes

    def facts_ints(self) -> dict:
        return {key: value for key, value in self.facts.items() if type(value) is int}

    def facts_tokens(self) -> dict:
        tokens = dict(self.facts.get("table_tokens") or {})
        if self.outcome is not None:
            tokens.update(outcome_tokens("h2", self.outcome))
        return tokens

    def close(self) -> None:
        if self.peer is not None:
            self.peer.close()
        for fd in (self.l_fd, self.r_fd):
            if fd is not None:
                with contextlib.suppress(OSError):
                    os.close(fd)
        self.l_fd = self.r_fd = None
        OPEN_FIXTURES.discard(self)


def _domain_closed(domain) -> bool:
    try:
        domain.ns_fd
    except AUTHORITY.DomainClosed:
        return True
    return False


def _retire(domain) -> None:
    if not _domain_closed(domain):
        with contextlib.suppress(AUTHORITY.InstallerFailed):
            domain.close_generation()  # a table H2 already removed refuses the flush; the descriptor is released


@contextlib.contextmanager
def _fixture(case: str, peer: str | None = "nonce"):
    """One fresh domain and fixture per use; afterwards (also after a failure) the fixture, the domain
    and every descriptor to its namespaces are resolved and the residuals recorded for P7."""
    domain = AUTHORITY.LeaseDomain.create()
    COUNTERS["domains"] += 1
    fixture = None
    try:
        fixture = Fixture(domain, peer)
        yield fixture
    finally:
        if fixture is not None:
            fixture.close()
        _retire(domain)
        held = _namespace_fds() & (fixture.identities if fixture is not None else set())
        RESIDUALS.append({"case": case, "fixture_open": int(fixture in OPEN_FIXTURES), "domain_open": int(not _domain_closed(domain)),
                          "namespace_fds_held": len(held),
                          "peer_thread_alive": int(fixture is not None and fixture.peer is not None
                                                   and fixture.peer.thread is not None and fixture.peer.thread.is_alive()),
                          "sockets_open": sum(sock.fileno() != -1 for sock in SOCKETS)})


def _bounds(before_ns: int, after_prepare_ns: int, timeout_ms: int) -> tuple[int, int]:
    """(live_to, bound): the commit lies inside the prepare bracket, so the element is live until at
    least before + timeout - 2 ticks and expired by after + timeout + 2 ticks (jiffy granularity)."""
    tick = _tick_ns()
    return before_ns + timeout_ms * MS - 2 * tick, after_prepare_ns + timeout_ms * MS + 2 * tick


def _lease(fx, timeout_ms: int = LEASE_MS) -> tuple[object, int, int, int]:
    """prepare + activate of the slot hop through the public H1 API: (handle, live_to, bound, active_ns)."""
    before = time.monotonic_ns()
    handle = fx.domain.prepare(SLOT_SRC, SLOT_DST, timeout_ms)
    after_prepare = time.monotonic_ns()
    fx.domain.activate(handle)
    active = time.monotonic_ns()
    live_to, bound = _bounds(before, after_prepare, timeout_ms)
    return handle, live_to, bound, active


# ---------------------------------------------------------------------------------------------
# Dynamic cases (Linux, inside the launcher's namespaces only).

def _command(argv: list[str]) -> str:
    try:
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=20, env=LAUNCHER._env())
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return completed.stdout if completed.returncode == 0 else ""


def _under_root(path) -> bool:
    return Path(os.path.realpath(path)).is_relative_to(Path(os.path.realpath(ROOT)))


def _p0(ints: dict, tokens: dict) -> bool:
    STATE["namespace_fds_baseline"] = len(_namespace_fds())
    STATE["outer_fingerprint"] = _outer_fingerprint()
    STATE["outer_links_baseline"] = len(socket.if_nameindex())
    # Provenance: the staged, unmodified H2-1 source and helper, the system nft, and the unchanged
    # client and harness imported from the staged root only.
    transport, harness = _transport(), _harness()
    cryptography = importlib.import_module("cryptography")
    heel = importlib.import_module("heel")
    ints.update(h2_staged=int(_under_root(H2.__file__) and Path(H2.__file__).resolve() == H2_FILE.resolve()),
                h2_source_pinned=int(hashlib.sha256(H2_FILE.read_bytes()).hexdigest() == H2_SOURCE_SHA256),
                h2_helper_pinned=int(helper_sha256(H2_FILE.read_text(encoding="utf-8")) == H2_HELPER_SHA256),
                nft_is_system=int(H2.NFT_PATH is AUTHORITY.NFT_PATH and H2.NFT_PATH in ("/usr/sbin/nft", "/sbin/nft")),
                client_staged=int(_under_root(transport.__file__) and _under_root(heel.__file__)),
                harness_staged=int(_under_root(harness.__file__)),
                harness_pinned=int(hashlib.sha256(HARNESS_FILE.read_bytes()).hexdigest() == HARNESS_SHA256),
                cryptography_outside_root=int(not _under_root(cryptography.__file__)),
                staged_without_git=int(not (ROOT / ".git").exists()))
    tokens["cryptography"] = cryptography.__version__
    domain = AUTHORITY.LeaseDomain.create()
    COUNTERS["domains"] += 1
    try:
        probe_fd = os.dup(domain.ns_fd)
        try:
            outer = os.stat("/proc/self/ns/net")
            ints["create_namespace_fresh"] = int(_identity(probe_fd) != (outer.st_dev, outer.st_ino))
            ints["create_ruleset_empty"] = int(_empty_ruleset(probe_fd))
            # The computed platform guard, by behaviour: a cleanup of a never-installed input passes the
            # guard (else ``refused_platform``) and stops at the empty record without any child.
            guard = H2.cleanup(probe_fd, policy_input(probe_fd, OBSERVED_LITERALS))
            ints["h2_platform_ok"] = int(guard.state == "refused_input" and guard.tokens.get("cleanup") == "not_installed")
            try:
                report = AUTHORITY.generation_self_test(domain)
            except AUTHORITY.HostQuarantined as error:
                report = error.report
            ints["selftest_left_domain_empty"] = int(_empty_ruleset(probe_fd))
        finally:
            os.close(probe_fd)
    finally:
        _retire(domain)  # no table in this domain: the flush is refused, the descriptor is released
    grade, reasons = PROFILE.grade_self_test(report)
    for key in ("kernel_release", "kernel_major_minor", "nft_version", "selftest", "readd_observation"):
        if key in report.tokens:
            tokens[key] = report.tokens[key]
    tokens["kernel_source_tag"] = LAUNCHER.SUPPORTED_KERNELS.get(tokens.get("kernel_major_minor"), "none")
    tokens["proc_version_sha256"] = hashlib.sha256(Path("/proc/version").read_bytes()).hexdigest()
    package = _command(["dpkg-query", "-W", "-f=${Version}", "nftables"]).strip().lower()
    tokens["nftables_package"] = package if re.fullmatch(r"[0-9][a-z0-9.:-]{0,60}", package) else "unparsed"
    tokens["python"] = "{}.{}.{}".format(*sys.version_info[:3])
    tokens["pytest"] = pytest.__version__
    tokens["kernel_profile"] = grade
    for index, reason in enumerate(reasons[:5]):
        tokens[f"profile_reason_{index}"] = reason
    for index, failure in enumerate(report.failures[:5]):
        tokens[f"failure_{index}"] = failure
    for key in ("config_hz", "tick_allowance_ms", "overflowuid"):
        if type(report.ints.get(key)) is int:
            ints[key] = report.ints[key]
    ints["cpu_count"] = os.cpu_count() or 0
    try:
        tick = PROFILE.tick_ns(report)
    except KeyError:
        tick = None
    provenance = all(ints.get(key) == 1 for key in ("h2_staged", "h2_source_pinned", "h2_helper_pinned", "h2_platform_ok",
                                                    "nft_is_system", "client_staged", "harness_staged", "harness_pinned",
                                                    "cryptography_outside_root", "staged_without_git"))
    if grade == "pinned" and tick is not None and provenance:
        STATE["tick_ns"] = tick
        ints["tick_ns"] = tick
    return (report.result == "pass" and grade == "pinned" and tick is not None and provenance
            and ints["create_namespace_fresh"] == 1 and ints["create_ruleset_empty"] == 1
            and ints["selftest_left_domain_empty"] == 1)


def test_p0_profile_is_captured_fresh_namespace_ruleset_is_empty_and_the_real_h1_self_test_passes():
    _require_runtime()
    ints, tokens, ok = {}, {}, False
    try:
        ok = _p0(ints, tokens)
    except Exception as error:  # noqa: BLE001 - a fixed token only
        tokens["error"] = error_token(error)
    record("p0", ok, ints, tokens)
    assert ok, "the profile is not pinned, the H1 self-test failed, create() was not fresh and empty, or provenance differs"


def _p1(ints: dict, tokens: dict) -> bool:
    _tick_ns()  # fail closed before any fixture when P0 captured no pinned tick and provenance
    with _fixture("p1") as fx:
        if fx.facts["baseline_reachable"] != len(PLAN):
            ints.update(fx.facts_ints())
            return False
        fx.install()
        ready = fx.gate_ready()
        ints.update(fx.facts_ints())
        tokens.update(fx.facts_tokens())
        ints["ipv4_targets"] = len(fx.policy.ipv4_egress_targets)
        ints["observed_addresses"] = len(fx.policy.observed_public_addresses)
        if not ready:
            return False
        # H2-3: the fixed control accept admits the slot source to the gateway on TCP 443 with no key.
        no_key_gateway = fx.settle([fx.probe("gateway") for _ in range(4)])
        _handle, live_to, bound, active = _lease(fx)
        rounds = ["t1", "unapproved_target", "t2", "wrong_port", "gateway"]
        probes = fx.settle(fx.series(rounds, active, bound + 1000 * MS))  # five kinds: keep >= 4 target probes past the bound
    window, late = inside(probes, active, live_to), after(probes, bound)
    per_target = {kind: [p for p in window if p.kind == kind] for kind in ("t1", "t2")}
    others = [p for p in probes if p.kind not in ("t1", "t2", "gateway")]
    late_targets = [p for p in late if p.kind != "gateway"]
    gateway = no_key_gateway + [p for p in probes if p.kind == "gateway"]
    ints.update(live_probes=len(window), live_admitted_t1=sum(p.admitted and p.delivered for p in per_target["t1"]),
                live_admitted_t2=sum(p.admitted and p.delivered for p in per_target["t2"]),
                other_probes=len(others), other_accepted=sum(p.accepted for p in others),
                after_bound_probes=len(late_targets), after_bound_accepted=sum(p.accepted for p in late_targets),
                gateway_no_key_probes=len(no_key_gateway),
                gateway_no_key_admitted=sum(p.admitted and p.delivered for p in no_key_gateway),
                gateway_probes=len(gateway), gateway_admitted=sum(p.admitted and p.delivered for p in gateway),
                gateway_after_bound_probes=sum(p.kind == "gateway" for p in late),
                anomalies=anomalies(no_key_gateway + probes))
    return (all(live(per_target[kind], 4) for kind in per_target) and closed(others, 8) and closed(late_targets, 4)
            and len(gateway) >= 8 and ints["gateway_admitted"] == len(gateway) and ints["gateway_no_key_admitted"] == 4
            and ints["ipv4_targets"] == 2 and ints["observed_addresses"] == 3)


def test_p1_install_readback_whole_ruleset_is_exactly_one_table_then_h1_prepare_activate_permit_only_pinned_ipv4_tcp_443():
    _require_runtime()
    ints, tokens, ok = {}, {}, False
    try:
        ok = _p1(ints, tokens)
    except Exception as error:  # noqa: BLE001 - a fixed token only
        tokens["error"] = error_token(error)
    record("p1", ok, ints, tokens)
    assert ok, "the real install did not receipt an exact single table, or the live lease admitted other than the pinned targets"


def _p2(ints: dict, tokens: dict) -> bool:
    _tick_ns()
    with _fixture("p2") as fx:
        if fx.facts["baseline_reachable"] != len(PLAN):
            ints.update(fx.facts_ints())
            return False
        fx.install()
        ready = fx.gate_ready()
        ints.update(fx.facts_ints())
        tokens.update(fx.facts_tokens())
        if not ready:
            return False
        # Phase A: the table alone (no key) admits nothing but the H2-3 control accept, for every kind.
        no_key = fx.settle([fx.probe(kind) for kind in [*PLAN, *PLAN]])
        # Phase B: a prepared-only key admits nothing.
        before = time.monotonic_ns()
        handle = fx.domain.prepare(SLOT_SRC, SLOT_DST, LEASE_MS)
        after_prepare = time.monotonic_ns()
        live_to, _bound = _bounds(before, after_prepare, LEASE_MS)
        prepared_only = fx.series(["t1", "t2"], after_prepare, min(after_prepare + 300 * MS, live_to - 2000 * MS))
        # Phase C: activated; the controls admit while every other kind stays denied (the gateway
        # negatives once more under the live key).
        fx.domain.activate(handle)
        active = time.monotonic_ns()
        mixed = [fx.probe(kind) for kind in [*["t1", *NEGATIVES, "gateway", "t2"] * 2, "gateway", *GATEWAY_NEGATIVES]]
        fx.settle(prepared_only + mixed)
        # Phase D: the product removes its table; every kind reaches its listener again (the listeners
        # never died, so the denials above were the policy's).
        removed = H2.cleanup(fx.l_fd, fx.policy)
        tokens.update(outcome_tokens("cleanup", removed))
        ints["after_cleanup_empty"] = int(_empty_ruleset(fx.l_fd))
        restored = fx.settle([fx.probe(kind) for kind in PLAN])
    window = inside(mixed, active, live_to)
    controls = [p for p in window if p.kind in ("t1", "t2")]
    gateway = [p for p in no_key + mixed if p.kind == "gateway"]
    no_key_denied = [p for p in no_key if p.kind != "gateway"]
    for kind in (*NEGATIVES, *GATEWAY_NEGATIVES):
        ints[f"{kind}_probes"] = sum(p.kind == kind for p in window)
        ints[f"{kind}_accepted"] = sum(p.accepted for p in mixed if p.kind == kind)
    ints.update(gateway_probes=len(gateway), gateway_admitted=sum(p.admitted and p.delivered for p in gateway),
                no_key_gateway_negative_accepted=sum(p.accepted for p in no_key if p.kind in GATEWAY_NEGATIVES))
    ints.update(no_key_probes=len(no_key_denied), no_key_accepted=sum(p.accepted for p in no_key_denied),
                prepared_only_probes=len(inside(prepared_only, after_prepare, live_to)),
                prepared_only_accepted=sum(p.accepted for p in prepared_only), control_probes=len(controls),
                control_admitted=sum(p.admitted and p.delivered for p in controls), mixed_outside_live=len(mixed) - len(window),
                restored_reachable=len(reachable(restored)), anomalies=anomalies(no_key + prepared_only + mixed + restored))
    return (closed(no_key_denied, 2 * (len(PLAN) - 1)) and closed(inside(prepared_only, after_prepare, live_to), 3)
            and len(window) == len(mixed) and live(controls, 4)
            and all(closed([p for p in window if p.kind == kind], 2) for kind in NEGATIVES)
            and all(closed([p for p in window if p.kind == kind], 1) for kind in GATEWAY_NEGATIVES)
            and len(gateway) == 5 and ints["gateway_admitted"] == 5
            and removed.state == "cleaned" and ints["after_cleanup_empty"] == 1 and ints["restored_reachable"] == len(PLAN))


def test_p2_before_activation_wrong_source_unpinned_target_8443_udp_443_and_ipv6_are_denied():
    _require_runtime()
    ints, tokens, ok = {}, {}, False
    try:
        ok = _p2(ints, tokens)
    except Exception as error:  # noqa: BLE001 - a fixed token only
        tokens["error"] = error_token(error)
    record("p2", ok, ints, tokens)
    assert ok, "a packet was admitted before activation or outside source/target/port/protocol/family, or a control failed"


def _p3(ints: dict, tokens: dict) -> bool:
    _tick_ns()
    with _fixture("p3") as fx:
        fx.install()
        ready = fx.gate_ready()
        ints.update(fx.facts_ints())
        tokens.update(fx.facts_tokens())
        if not ready:
            return False
        # Expiry: a short key admits while live and no fresh connection after the conservative bound.
        _handle, live_to, bound, active = _lease(fx, SHORT_MS)
        expiry = fx.series(["t1", "t2"], active, bound + 1500 * MS)
        # Late activation: an expired prepared key activated after its bound revives nothing.
        before = time.monotonic_ns()
        late = fx.domain.prepare(SLOT_SRC, SLOT_DST, LATE_MS)
        after_prepare = time.monotonic_ns()
        _late_live, late_bound = _bounds(before, after_prepare, LATE_MS)
        sleep_until(late_bound + 50 * MS)
        late_start = time.monotonic_ns()
        try:
            fx.domain.activate(late)
            tokens["late_activation"] = "activated"
        except (AUTHORITY.InstallerFailed, AUTHORITY.HandleState) as error:
            tokens["late_activation"] = "refused_" + error_token(error)
        revived = fx.series(["t1", "t2"], time.monotonic_ns(), time.monotonic_ns() + 800 * MS)
        # Positive control: a fresh key admits; closing it denies again.
        fresh, fresh_live_to, _fresh_bound, fresh_active = _lease(fx)
        control = fx.series(["t1", "t2"], fresh_active, min(fresh_active + 500 * MS, fresh_live_to - 900 * MS))
        fx.domain.close(fresh)
        after_close = time.monotonic_ns()
        reclosed = fx.series(["t1", "t2"], after_close, min(after_close + 500 * MS, fresh_live_to))
        fx.settle(expiry + revived + control + reclosed)
    window, expired = inside(expiry, active, live_to), after(expiry, bound)
    controls = inside(control, fresh_active, fresh_live_to)
    ints.update(short_ms=SHORT_MS, late_ms=LATE_MS, live_probes=len(window),
                live_admitted=sum(p.admitted and p.delivered for p in window),
                after_bound_probes=len(expired), after_bound_accepted=sum(p.accepted for p in expired),
                activation_after_bound_ms=(late_start - late_bound) // MS, revived_probes=len(revived),
                revived_accepted=sum(p.accepted for p in revived), control_probes=len(controls),
                control_admitted=sum(p.admitted and p.delivered for p in controls), reclosed_probes=len(reclosed),
                reclosed_accepted=sum(p.accepted for p in reclosed), anomalies=anomalies(expiry + revived + control + reclosed))
    return (live(window, 3) and closed(expired, 8) and late_start > late_bound and closed(revived, 5)
            and live(controls, 3) and closed(reclosed, 3) and ints["anomalies"] == 0)


def test_p3_no_fresh_connection_after_expiry_and_late_activation_does_not_revive():
    _require_runtime()
    ints, tokens, ok = {}, {}, False
    try:
        ok = _p3(ints, tokens)
    except Exception as error:  # noqa: BLE001 - a fixed token only
        tokens["error"] = error_token(error)
    record("p3", ok, ints, tokens)
    assert ok, "a fresh connection was admitted after expiry, a late activation revived egress, or a control failed"


class Resolver:
    """The client's ``resolver`` seam: the injected answer for HOSTNAME, counted per attempt. No DNS."""

    def __init__(self, answer):
        self.answer, self.calls = list(answer), 0

    def __call__(self, hostname: str, *, deadline: float) -> list[str]:
        if hostname != HOSTNAME:
            raise RuntimeError("hostname")
        self.calls += 1
        return list(self.answer)


def _tls_transport(transport, ca):
    """The real ``TLSTransport`` (TLS 1.2+, CERT_REQUIRED, hostname check) trusting the harness CA too."""
    tls = transport.TLSTransport()
    tls.context.load_verify_locations(cafile=str(ca.ca_path))
    return tls


def _request(fx, client) -> str:
    """One authorized GET through the unchanged client from inside L: ``ok`` or the closed failure code."""
    transport = _transport()
    action = importlib.import_module("heel.runner.adapters").PreparedAction(
        scenario_id="anonymous_authenticated_read", adapter_version="1", method="GET", route="/health",
        semantic_auth_role="anonymous", auth_profile="anonymous", side_effect_class="read_only")
    redactor = importlib.import_module("heel.runner.redaction").Redactor(())
    COUNTERS["client_requests"] += 1

    def run():
        try:
            response = client.request(
                action, credential=None, cancellation=transport.CancellationToken(),
                retry_policy=transport.RetryPolicy(0, ("connect_error", "timeout")), remaining_requests=1,
                before_attempt=lambda _attempt, _previous: transport.AttemptPermit(time.monotonic() + 3.0),
                evidence_context=transport.EvidenceContext(0, "/health"),
                evidence_sink=lambda evidence: "ev1_" + hashlib.sha256(evidence.raw_body).hexdigest(), redactor=redactor)
        except transport.TransportFailure as failure:
            return failure.code
        return "ok" if (response.status_code, response.body_shape, response.requests_made) == (200, "json_object", 1) else "bad"

    return _in_netns(fx.l_fd, run)


def _p4(ints: dict, tokens: dict) -> bool:
    _tick_ns()
    transport = _transport()
    observed = _observed(OBSERVED_LITERALS)
    canonical = [str(address) for address in observed]
    with _fixture("p4", peer="tls") as fx:
        resolver = Resolver(canonical)
        client = transport.TargetHTTPSClient(origin="https://" + HOSTNAME, preflight_addresses=canonical, resolver=resolver,
                                             tls=_tls_transport(transport, fx.ca), timeout_seconds=CLIENT_TIMEOUT_S)
        # Positive reachability control before any table: the full client stack works in this topology,
        # and the AAAA listener accepts a plain IPv6 connection.
        results = {"baseline": _request(fx, client)}
        ints["baseline_ipv6_admitted"] = int(fx.probe("ipv6").admitted)
        baseline_counts, baseline_served = fx.peer.counts()
        fx.install(OBSERVED_LITERALS)
        ready = fx.gate_ready()
        ints.update(fx.facts_ints())
        tokens.update(fx.facts_tokens())
        ints.update(preflight_full_tuple=int(client.preflight_addresses == observed == fx.policy.observed_public_addresses),
                    ipv4_targets=len(fx.policy.ipv4_egress_targets))
        if not ready:
            return False
        results["no_key"] = _request(fx, client)
        fx.domain.prepare(SLOT_SRC, SLOT_DST, LEASE_MS)  # prepared only, never activated
        results["prepared_only"] = _request(fx, client)
        denied_counts, denied_served = fx.peer.counts()
        handle, live_to, _bound, _active = _lease(fx)  # a fresh key: the denials above may take the whole client timeout
        resolver.answer = list(reversed(canonical))  # order-only change: canonicalises equal
        results["reordered"] = _request(fx, client)
        resolver.answer = canonical
        results["canonical"] = _request(fx, client)
        admitted_counts, admitted_served = fx.peer.counts()
        changes = {"drop_aaaa": [*TARGETS], "add_member": [*canonical, UNAPPROVED],
                   "replace_member": [TARGETS[0], WRONG_SOURCE, TARGET6], "unsafe_private": [*canonical, "10.0.0.1"],
                   "unsafe_loopback": [*canonical, "::1"]}
        for name, answer in changes.items():
            resolver.answer = answer
            results[name] = _request(fx, client)
        changed_counts, changed_served = fx.peer.counts()
        live_end = time.monotonic_ns()
        fx.domain.close(handle)
        resolver.answer = canonical
        results["after_close"] = _request(fx, client)
        closed_counts, closed_served = fx.peer.counts()
        served = list(fx.peer.served)
    tokens.update({f"r_{name}": value for name, value in results.items()})
    admitted = served[baseline_served:admitted_served]
    ints.update(resolver_calls=resolver.calls, requests=len(results), within_live=int(live_end <= live_to),
                denied_new_connections=sum(denied_counts.values()) - sum(baseline_counts.values()),
                admitted_t1=admitted_counts["t1"] - denied_counts["t1"], admitted_t2=admitted_counts["t2"] - denied_counts["t2"],
                admitted_t6=admitted_counts["t6"] - denied_counts["t6"],
                changed_new_connections=sum(changed_counts.values()) - sum(admitted_counts.values()),
                closed_new_connections=sum(closed_counts.values()) - sum(changed_counts.values()),
                served_admitted=len(admitted),
                served_ipv4_selection=sum(label == "t1" and local == TARGETS[0] for label, _line, _host, local in admitted),
                served_exact_request=sum(line == "GET /health HTTP/1.1" and host == HOSTNAME for _l, line, host, _local in admitted))
    expected = {"baseline": ("ok",), "no_key": DENIED, "prepared_only": DENIED, "reordered": ("ok",), "canonical": ("ok",),
                "drop_aaaa": ("dns_changed",), "add_member": ("dns_changed",), "replace_member": ("dns_changed",),
                "unsafe_private": ("unsafe_dns",), "unsafe_loopback": ("unsafe_dns",), "after_close": DENIED}
    ints["results_expected"] = sum(results.get(name) in codes for name, codes in expected.items())
    # Every attempt resolved the full set again (one resolver call per request after the guard).
    return (set(results) == set(expected) and ints["results_expected"] == len(expected)
            and ints["baseline_ipv6_admitted"] == 1 and ints["preflight_full_tuple"] == 1 and ints["ipv4_targets"] == 2
            and resolver.calls == len(results) and ints["within_live"] == 1
            and ints["denied_new_connections"] == 0 and ints["admitted_t1"] == 2 and ints["admitted_t2"] == 0
            and ints["admitted_t6"] == 0 and ints["changed_new_connections"] == 0 and ints["closed_new_connections"] == 0
            and ints["served_admitted"] == 2 and ints["served_ipv4_selection"] == 2 and ints["served_exact_request"] == 2)


def test_p4_unchanged_client_resolves_full_set_each_attempt_accepts_reorder_refuses_membership_or_unsafe_change_and_dials_ipv4_for_dual_stack_through_the_live_lease():
    _require_runtime()
    ints, tokens, ok = {}, {}, False
    try:
        ok = _p4(ints, tokens)
    except Exception as error:  # noqa: BLE001 - a fixed token only
        tokens["error"] = error_token(error)
    record("p4", ok, ints, tokens)
    assert ok, "the unchanged client did not succeed only through the live lease on the IPv4 selection, or a DNS change passed"


def _p5(ints: dict, tokens: dict) -> bool:
    _tick_ns()
    with _fixture("p5") as fx:
        if fx.facts["baseline_reachable"] != len(PLAN):
            ints.update(fx.facts_ints())
            return False
        outcome = fx.install((TARGET6,))
        tokens.update(outcome_tokens("h2", outcome))
        ints.update(fx.facts_ints(), observed_addresses=len(fx.policy.observed_public_addresses),
                    ipv4_targets=len(fx.policy.ipv4_egress_targets), ruleset_empty_after=int(_empty_ruleset(fx.l_fd)),
                    unreaped_helpers=H2.unresolved_helpers()["unreaped"])
        # No table: the H1 prepare in this namespace is refused (nothing to hold the element).
        try:
            fx.domain.prepare(SLOT_SRC, SLOT_DST, LEASE_MS)
            tokens["prepare_without_table"] = "accepted"
        except AUTHORITY.InstallerFailed as error:
            tokens["prepare_without_table"] = error_token(error)
        # H2-3 binding generation in the same namespace: control_only with the empty tuple. The whole
        # ruleset is one table of seven objects with no target accept; the gateway is admitted and the
        # targets stay denied, with no key and under a live key.
        shape = fx.install(control_only=True)
        ready = fx.gate_ready()
        whole, _sha = _ruleset(fx.l_fd)
        objects = whole["nftables"][1:] if isinstance(whole, dict) and isinstance(whole.get("nftables"), list) else []
        tokens.update(outcome_tokens("shape", shape))
        tokens.update({f"shape_{key}": value for key, value in fx.facts["table_tokens"].items()})
        ints.update(shape_ready=int(ready), shape_receipt_exact=fx.facts["receipt_exact"],
                    shape_ruleset_exact=fx.facts["ruleset_exact"], shape_readback_exact=fx.facts["readback_exact"],
                    shape_items=len(objects), shape_ipv4_targets=len(fx.policy.ipv4_egress_targets),
                    shape_target_rules=sum("@" + AUTHORITY.PREPARED_SET in json.dumps(item) for item in objects
                                           if isinstance(item, dict) and "rule" in item))
        if not ready:
            return False
        no_key = fx.settle([fx.probe(kind) for kind in ["gateway", "t1", "t2"] * 2])
        _handle, live_to, _bound, active = _lease(fx)
        keyed = [fx.probe(kind) for kind in ["gateway", "t1", "t2"] * 2]
        fx.settle(keyed)
        removed = H2.cleanup(fx.l_fd, fx.policy)
        tokens.update(outcome_tokens("cleanup", removed))
        ints["after_cleanup_empty"] = int(_empty_ruleset(fx.l_fd))
    gateway = [p for p in no_key + keyed if p.kind == "gateway"]
    targets = [p for p in no_key + keyed if p.kind != "gateway"]
    ints.update(control_probes=len(gateway), control_admitted=sum(p.admitted and p.delivered for p in gateway),
                target_probes=len(targets), target_accepted=sum(p.accepted for p in targets),
                keyed_inside_live=len(inside(keyed, active, live_to)), anomalies=anomalies(no_key + keyed))
    return (outcome.state == "unsupported_ipv6_only" and outcome.receipt is None and ints["observed_addresses"] == 1
            and ints["ipv4_targets"] == 0 and ints["ruleset_empty_after"] == 1 and ints["fresh_ruleset_empty"] == 1
            and ints["unreaped_helpers"] == 0 and tokens["prepare_without_table"].startswith("preparefailed_")
            and shape.state == "receipt_ready" and ints["shape_items"] == 7 and ints["shape_target_rules"] == 0
            and ints["shape_ipv4_targets"] == 0 and ints["control_probes"] == 4 and ints["control_admitted"] == 4
            and closed(targets, 8) and ints["keyed_inside_live"] == len(keyed)
            and removed.state == "cleaned" and ints["after_cleanup_empty"] == 1)


def test_p5_ipv6_only_input_refuses_before_any_table_exists():
    _require_runtime()
    ints, tokens, ok = {}, {}, False
    try:
        ok = _p5(ints, tokens)
    except Exception as error:  # noqa: BLE001 - a fixed token only
        tokens["error"] = error_token(error)
    record("p5", ok, ints, tokens)
    assert ok, ("an IPv6-only input was not refused before any table existed, or the H2-3 control-only table was not "
                "exactly seven objects admitting the gateway and denying the targets")


def _p6(ints: dict, tokens: dict) -> bool:
    _tick_ns()
    outer = os.stat("/proc/self/ns/net")
    results = {}
    # (a) identity fault: the input names another namespace; nothing is launched, nothing installed.
    with _fixture("p6_identity", peer=None) as fx:
        outcome = fx.install(identity=(outer.st_dev, outer.st_ino))
        results["identity"] = (outcome, int(_empty_ruleset(fx.l_fd)))
    # (b) readback fault: a pre-seeded conflicting chain in the named table makes the real readback
    # differ; the product cleans its own table and nothing remains. The seed uses the product's script
    # grammar (each nested block newline-terminated); its exit code is recorded so a failed seed is a
    # clearly attributed FAIL, never a vacuous pass.
    with _fixture("p6_readback", peer=None) as fx:
        seed = f"table inet {AUTHORITY.TABLE} {{\n  chain conflict {{\n  }}\n}}\n"
        seeded = _run_in(fx.l_fd, [AUTHORITY.NFT_PATH, "-f", "-"], seed)
        ints["seed_exit"] = seeded.returncode
        ints["seeded"] = int(seeded.returncode == 0)
        outcome = fx.install()
        results["readback"] = (outcome, int(_empty_ruleset(fx.l_fd)))
    # (c) install-phase fault: the clock reads 4000 ms later from the readback step on, so the readback
    # child is never launched and the cleanup has no budget: quarantined, the table left in L only.
    with _fixture("p6_install_timeout", peer=None) as fx:
        fault = ("_install", 3, 4000)
        outcome = fx.install(fault=fault)
        whole, _sha = _ruleset(fx.l_fd)
        results["install_timeout"] = (outcome, int(ruleset_shape(whole)[0] or ruleset_is_empty(whole)))
        again = H2.cleanup(fx.l_fd, fx.policy)
        tokens.update(outcome_tokens("c_again", again))
    # (d) cleanup fault: after a real receipt, the cleanup child's first clock read is 2000 ms late:
    # killed and reaped, outcome unknown, quarantined; a second cleanup is a no-op without a child.
    with _fixture("p6_cleanup_timeout", peer=None) as fx:
        installed = fx.install()
        ints["d_installed"] = int(installed.state == "receipt_ready" and receipt_exact(installed, fx.policy))
        fault = ("_drive", 1, 2000)
        outcome = H2.cleanup(fx.l_fd, fx.policy, clock=FaultClock(*fault))
        whole, _sha = _ruleset(fx.l_fd)
        results["cleanup_timeout"] = (outcome, int(ruleset_shape(whole)[0] or ruleset_is_empty(whole)))
        repeat = H2.cleanup(fx.l_fd, fx.policy)
        tokens.update(outcome_tokens("d_again", repeat))
    for name, (outcome, contained) in results.items():
        prefix = {"identity": "a", "readback": "b", "install_timeout": "c", "cleanup_timeout": "d"}[name]
        tokens.update(outcome_tokens(prefix, outcome))
        ints[f"{prefix}_contained"] = contained
    ints["unreaped_helpers"] = H2.unresolved_helpers()["unreaped"]
    fingerprint = _outer_fingerprint()
    ints["outer_fingerprints_differing"] = sum(STATE.get("outer_fingerprint", {}).get(key) != value
                                               for key, value in fingerprint.items())
    a, b, c, d = (results[name][0] for name in ("identity", "readback", "install_timeout", "cleanup_timeout"))
    return (all(outcome.receipt is None for outcome in (a, b, c, d))
            and a.state == "identity_mismatch" and ints["a_contained"] == 1
            and ints["seeded"] == 1 and b.state == "cleaned" and b.tokens.get("cause") == "readback_mismatch"
            and ints["b_contained"] == 1
            and c.state == "quarantined" and c.tokens.get("cause") == "timeout" and c.tokens.get("cleanup") == "out_of_budget"
            and ints["c_contained"] == 1 and tokens["c_again_state"] == "quarantined" and tokens["c_again_receipt"] == "absent"
            and ints["d_installed"] == 1 and d.state == "quarantined" and ints["d_contained"] == 1
            and tokens["d_again_state"] == "quarantined" and tokens["d_again_receipt"] == "absent"
            and ints["unreaped_helpers"] == 0 and ints["outer_fingerprints_differing"] == 0)


def test_p6_install_readback_or_cleanup_fault_never_receipts_and_quarantines_without_host_rules():
    _require_runtime()
    ints, tokens, ok = {}, {}, False
    try:
        ok = _p6(ints, tokens)
    except Exception as error:  # noqa: BLE001 - a fixed token only
        tokens["error"] = error_token(error)
    record("p6", ok, ints, tokens)
    assert ok, "a faulted install or cleanup produced a receipt, was not cleaned/quarantined, or touched the outer namespace"


def _p7(ints: dict, tokens: dict) -> bool:
    # Fd-bound cleanup: two generations A and B with exact tables; cleaning A's input through B's
    # descriptor touches neither (identity refusal, A quarantined), B's own cleanup empties only B.
    with _fixture("p7_a", peer=None) as a, _fixture("p7_b", peer=None) as b:
        a.install()
        b.install()
        ints["a_ready"], ints["b_ready"] = int(a.gate_ready()), int(b.gate_ready())
        crossed = H2.cleanup(b.l_fd, a.policy)
        tokens.update(outcome_tokens("crossed", crossed))
        ints["a_intact_after_cross"] = int(ruleset_shape(_ruleset(a.l_fd)[0])[0])
        ints["b_intact_after_cross"] = int(ruleset_shape(_ruleset(b.l_fd)[0])[0]
                                           and H2.readback_matches(_named_table(b.l_fd)[0], b.policy)[0])
        cleaned = H2.cleanup(b.l_fd, b.policy)
        tokens.update(outcome_tokens("b_cleanup", cleaned))
        ints["b_empty"] = int(_empty_ruleset(b.l_fd))
        ints["a_intact_after_b"] = int(ruleset_shape(_ruleset(a.l_fd)[0])[0])
        repeat = H2.cleanup(b.l_fd, b.policy)
        tokens.update(outcome_tokens("b_repeat", repeat))
    # An injected failure inside a live fixture with the installed table and an active key resolves
    # like a normal exit.
    injected = None
    try:
        with _fixture("p7_injected") as fx:
            injected = fx
            fx.install()
            if fx.gate_ready():
                _lease(fx)
            raise InjectedFailure("injected")
    except InjectedFailure:
        tokens["injected"] = "raised"
    with contextlib.suppress(ChildProcessError):
        while os.waitpid(-1, os.WNOHANG)[0]:
            pass
    residual = {key: sum(entry[key] for entry in RESIDUALS) for key in
                ("fixture_open", "domain_open", "namespace_fds_held", "peer_thread_alive")}
    links = sorted(name for _index, name in socket.if_nameindex())
    others = [entry.name for entry in Path("/proc").iterdir() if entry.name.isdigit()
              and int(entry.name) not in (1, os.getpid())]
    threads = [thread for thread in threading.enumerate() if thread.name.startswith("heel-h2p-") and thread.is_alive()]
    unresolved = sum(AUTHORITY.unresolved_children().values())
    fingerprint = _outer_fingerprint()
    differing = sorted(key for key in fingerprint if STATE.get("outer_fingerprint", {}).get(key) != fingerprint[key])
    ints.update({f"residual_{key}": value for key, value in residual.items()})
    ints.update(fixtures_recorded=len(RESIDUALS), injected_recorded=int(any(e["case"] == "p7_injected" for e in RESIDUALS)),
                injected_namespace_fds_held=len(_namespace_fds() & (injected.identities if injected else set())),
                open_fixtures=len(OPEN_FIXTURES), open_sockets=sum(sock.fileno() != -1 for sock in SOCKETS),
                namespace_fds=len(_namespace_fds()), namespace_fds_baseline=STATE.get("namespace_fds_baseline", -1),
                outer_links=len(links), outer_links_baseline=STATE.get("outer_links_baseline", -1),
                owned_residual_links=len([name for name in links if name != "lo"]), other_processes=len(others),
                fixture_threads_alive=len(threads), registry_unresolved=unresolved,
                unreaped_helpers=H2.unresolved_helpers()["unreaped"], outer_fingerprints_differing=len(differing),
                fixtures_created=COUNTERS["fixtures"], domains_created=COUNTERS["domains"], installs=COUNTERS["installs"],
                sockets_created=COUNTERS["sockets"], probes_sent=COUNTERS["probes"], client_requests=COUNTERS["client_requests"])
    for index, name in enumerate(differing[:5]):
        tokens[f"differing_{index}"] = name
    return (ints["a_ready"] == 1 and ints["b_ready"] == 1 and crossed.state == "quarantined"
            and crossed.tokens.get("cleanup") == "identity_mismatch" and ints["a_intact_after_cross"] == 1
            and ints["b_intact_after_cross"] == 1 and cleaned.state == "cleaned" and ints["b_empty"] == 1
            and ints["a_intact_after_b"] == 1 and repeat.state == "cleaned" and repeat.tokens.get("cleanup") == "noop"
            and tokens.get("injected") == "raised" and injected is not None and ints["injected_recorded"] == 1
            and not any(residual.values()) and ints["injected_namespace_fds_held"] == 0 and not OPEN_FIXTURES
            and ints["open_sockets"] == 0 and ints["namespace_fds"] == ints["namespace_fds_baseline"]
            and links == ["lo"] and not others and not threads and unresolved == 0 and ints["unreaped_helpers"] == 0
            and not differing and "outer_fingerprint" in STATE)


def test_p7_cleanup_is_fd_bound_whole_ruleset_is_empty_and_no_namespace_veth_helper_or_host_residue_remains():
    _require_runtime()
    ints, tokens, ok = {}, {}, False
    try:
        ok = _p7(ints, tokens)
    except Exception as error:  # noqa: BLE001 - a fixed token only
        tokens["error"] = error_token(error)
    record("p7", ok, ints, tokens)
    assert ok, "cleanup crossed generations, left a table, or an owned namespace, veth, helper, socket or host residue survived"
