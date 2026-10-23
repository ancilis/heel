"""H2K1: Linux proof of the fixed logical lease-key shape (``lease-key-v1``; FableH2D Option A).

Static cases run everywhere. Dynamic cases need the fixed ``scripts/host_lease_key_shape.py``
launcher: it runs this module as root inside an outer network+mount+PID namespace that has only
loopback, with ``HEEL_REQUIRE_HOST_LEASE_KEY_PROOF=1``. Under that switch a missing platform,
privilege, tool, launcher environment or namespace capability fails; outside it the dynamic cases
skip, so the ordinary suite never claims the proof.

The question: can the real H1 ``LeaseDomain.prepare``/``activate`` of (SLOT_PEER, SLOT_ADDRESS) gate
IPv4 TCP 443 packets whose actual destination is one of two distinct approved targets (neither of
them SLOT_ADDRESS), when both the activated-map lookup and the prepared-set membership concatenate
the immediate constant SLOT_ADDRESS (``ip saddr . SLOT_ADDRESS``) instead of ``ip daddr``? There is
no fallback: a rejected or unrecognized shape is a FAIL, never a different semantics.

Every key is written by the public domain API (``LeaseDomain.create``, ``prepare``, ``activate``,
``close``, ``close_generation``) in the namespace ``create`` made; ``create`` installs nothing there,
so the proof fixture installs its own table/set/map/output chain under the exported names
(``TABLE``/``PREPARED_SET``/``ACTIVATED_MAP``/``GATE_CHAIN``) through a dup of the public ``ns_fd``. The
peer namespace is created by ``unshare`` on a fixture thread and held only by descriptor; the one
veth is created by raw rtnetlink with ``IFLA_NET_NS_FD`` (a dup the fixture closes), never by a
namespace name or PID. Probes are fresh TCP connections (and fixed UDP/IPv6 negatives) between fixed
documentation addresses inside those disposable namespaces; nothing leaves them.

This is an L3/L4 primitive proof under the running-kernel assumption. It is not Host/SNI/TLS,
method, route or attempt enforcement, not DNS, not the HostCycle-to-H3 handoff, and not H2, H3 or
launch.
"""
from __future__ import annotations

import ast
import contextlib
import errno
import hashlib
import importlib.util
import json
import os
import re
import select
import socket
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_FILE = ROOT / "scripts" / "host_lease_key_shape.py"
AUTHORITY_FILE = ROOT / "deploy" / "host" / "authority.py"
WORKFLOW = ROOT / ".github" / "workflows" / "codeql.yml"
DOC = ROOT / "docs" / "saas" / "HOST_LEASE_KEY_SHAPE.md"
H0_LOCK = ROOT / "deploy" / "host" / "ingress" / "runtime-lock.json"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


LAUNCHER = _load("host_lease_key_shape", LAUNCHER_FILE)
AUTHORITY = _load("heel_host_authority_domain_key_shape", AUTHORITY_FILE)
PROFILE = LAUNCHER.profile()
REQUIRED = os.environ.get(LAUNCHER.REQUIRED_ENV) == "1"

MS = 1_000_000
# Fixed documentation addresses (RFC 5737 / ULA), used only inside the disposable namespaces.
SLOT_PEER, WRONG_SOURCE = "198.51.100.20", "198.51.100.21"
SLOT_ADDRESS = "192.0.2.1"  # the logical gateway constant: assigned to no interface and never a destination
TARGETS = ("203.0.113.11", "203.0.113.12")  # the two distinct approved wire targets
UNAPPROVED = "203.0.113.13"
PEER6, TARGET6 = "fd48:4b31::20", "fd48:4b31::11"
PORT, WRONG_PORT = 443, 8443
LEASE_MS = 3000  # == AUTHORITY.MAX_PREPARE_TIMEOUT_MS (a static pins it)
SHORT_MS, LATE_MS = 1000, 300
PROBE_INTERVAL_NS = 100 * MS
CONNECT_TIMEOUT_S = 0.15
LIVE_PERCENT = 95
NONCE_BYTES = 32
CLONE_NEWNET = 0x40000000
SO_MARK = getattr(socket, "SO_MARK", 36)

# ---------------------------------------------------------------------------------------------
# The recorded parent .github/workflows/codeql.yml at bd21978 (analyze + three proof jobs, fixed
# values so the staged copy checks them without git history), and the one job this unit appends.

PRIOR_WORKFLOW_BYTES = 5598
PRIOR_WORKFLOW_SHA256 = "f30734710ad81081cd45bf428f85a263c88bd1c3fe5e598491a0b1534318964f"
EXPECTED_JOBS = ["analyze", "host-ingress-proof", "host-lease-feasibility", "host-authority-proof", "host-lease-key-shape"]
KEY_SHAPE_GATE = ("if: github.event_name == 'workflow_dispatch' && "
                  "github.ref == 'refs/heads/codex/self-serve-host-lease-key-shape-proof'")
CHECKOUT = "actions/checkout@11d5960a326750d5838078e36cf38b85af677262"
SETUP_PYTHON = "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065"
UPLOAD = "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
KEY_SHAPE_JOB = f"""  host-lease-key-shape:
    # H2K1: the isolated lease-key shape proof (immediate-constant logical key) on a disposable Linux VM.
    # Manual dispatch of the literal reviewed proof branch only; no parameters, credentials or saved state.
    # The fixed launcher (docs/saas/HOST_LEASE_KEY_SHAPE.md) owns every runtime input and its hash.
    name: host-lease-key-shape (lease-key-v1)
    {KEY_SHAPE_GATE}
    runs-on: ubuntu-24.04
    timeout-minutes: 25
    permissions:
      contents: read
    concurrency:
      group: host-lease-key-shape
      cancel-in-progress: false
    steps:
      - uses: {CHECKOUT} # v4
        with:
          ref: ${{{{ github.sha }}}}
          persist-credentials: false
      - uses: {SETUP_PYTHON} # v5
        with:
          python-version: "3.13.5"
      - name: Fixed lease-key-v1 launcher (20-minute budget, tests 10 minutes)
        timeout-minutes: 20
        run: python scripts/host_lease_key_shape.py
      - name: Upload allowlisted safe evidence
        if: always()
        uses: {UPLOAD} # v4
        with:
          name: host-lease-key-shape
          if-no-files-found: error
          retention-days: 3
          path: |
            host-lease-key-shape/summary.json
            host-lease-key-shape/cases.jsonl
            host-lease-key-shape/versions.txt
            host-lease-key-shape/cleanup.json
            host-lease-key-shape/report.txt
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


def key_shape_job_violations(job: str) -> list[str]:
    """Every line form of the appended job, matched as full lines (no substring or bare-step gaps)."""
    checks = {
        "gate": _lines(r"\s*(?:- )?if: .*", job) == [f"    {KEY_SHAPE_GATE}", "        if: always()"],
        "runs_on": _lines(r"\s*runs-on: .*", job) == ["    runs-on: ubuntu-24.04"],
        "timeouts": _lines(r"\s*timeout-minutes: .*", job) == ["    timeout-minutes: 25", "        timeout-minutes: 20"],
        "permissions": re.search(r"^    permissions:\n      contents: read\n    concurrency:\n      group: "
                                 r"host-lease-key-shape\n      cancel-in-progress: false\n    steps:\n", job, re.M) is not None
        and _lines(r"\s*permissions:.*", job) == ["    permissions:"] and _lines(r"\s*contents: .*", job) == ["      contents: read"],
        "steps": _lines(r"      - .*", job) == [f"      - uses: {CHECKOUT} # v4", f"      - uses: {SETUP_PYTHON} # v5",
                                                "      - name: Fixed lease-key-v1 launcher (20-minute budget, tests 10 minutes)",
                                                "      - name: Upload allowlisted safe evidence"],
        "run": _lines(r"\s*(?:- )?run:.*", job) == ["        run: python scripts/host_lease_key_shape.py"],
        "checkout": _lines(r"\s*ref: .*", job) == ["          ref: ${{ github.sha }}"]
        and _lines(r"\s*persist-credentials: .*", job) == ["          persist-credentials: false"],
        "python": _lines(r"\s*python-version: .*", job) == ['          python-version: "3.13.5"'],
        "uses": set(re.findall(r"uses: (\S+)", job)) == {CHECKOUT, SETUP_PYTHON, UPLOAD},
        "artifacts": tuple(re.findall(r"^            host-lease-key-shape/(\S+)$", job, re.M)) == LAUNCHER.ARTIFACT_FILES
        and _lines(r"\s*path: .*", job) == ["          path: |"],
        "upload": _lines(r"\s*retention-days: .*", job) == ["          retention-days: 3"]
        and _lines(r"\s*if-no-files-found: .*", job) == ["          if-no-files-found: error"]
        and _lines(r"\s*name: host-lease-key-shape.*", job) == ["    name: host-lease-key-shape (lease-key-v1)",
                                                                "          name: host-lease-key-shape"],
    }
    found = [name for name, ok in checks.items() if not ok]
    for word in ("write", "id-token", "environment:", "cache", "env:", "secrets", "pull_request", "github.token", "inputs",
                 "services:", "container:", "workflow_call", "continue-on-error"):
        if word in job:
            found.append("forbidden_" + re.sub(r"[^a-z]", "_", word))
    return found


def workflow_violations(text: str) -> list[str]:
    """Empty iff codeql.yml is exactly the recorded four-job parent, one newline, and the one fully
    constrained lease-key job, with no other byte anywhere."""
    found = []
    data = text.encode("utf-8")
    if not data.isascii() or hashlib.sha256(data[:PRIOR_WORKFLOW_BYTES]).hexdigest() != PRIOR_WORKFLOW_SHA256:
        found.append("prior_workflow")
    if text.count("\njobs:\n") != 1:
        return found + ["job_names"]
    names = re.findall(r"^  ([A-Za-z0-9_-]+):\n", text.split("\njobs:\n", 1)[1], re.M)  # keys under jobs: only
    if names != EXPECTED_JOBS:
        return found + ["job_names"]
    job = _job_block(text, "host-lease-key-shape")
    if text != text[:PRIOR_WORKFLOW_BYTES] + "\n" + job:
        found.append("composition")
    if ("\npermissions: {}\n" not in text or "pull_request_target" in text or "secrets." in text or "inputs:" in text
            or "workflow_dispatch: {}" not in text):
        found.append("workflow_head_policy")
    if not all(re.fullmatch(r"[a-z-]+/[a-z-]+(?:/[a-z-]+)?@[0-9a-f]{40}", uses) for uses in re.findall(r"uses: (\S+)", text)):
        found.append("unpinned_action")
    found += key_shape_job_violations(job)
    if job != KEY_SHAPE_JOB:
        found.append("key_shape_job_text")
    return found


# ---------------------------------------------------------------------------------------------
# The owned gate (proof fixture; H2 owns any production table) and its readback oracle.

def gate_table() -> str:
    """The candidate shape: clear the packet mark, look the mark up by ``ip saddr . SLOT_ADDRESS`` in
    the activated map, then admit only when ``ip saddr . SLOT_ADDRESS . meta mark`` is a live prepared
    element AND the destination is a fixed approved target AND the protocol is TCP to port 443. The
    only accept is that conjunction; the chain policy drops everything else."""
    t1, t2 = TARGETS
    return (f"table inet {AUTHORITY.TABLE} {{\n"
            f"  set {AUTHORITY.PREPARED_SET} {{ type ipv4_addr . ipv4_addr . mark ; flags timeout ; }}\n"
            f"  map {AUTHORITY.ACTIVATED_MAP} {{ type ipv4_addr . ipv4_addr : mark ; }}\n"
            f"  chain {AUTHORITY.GATE_CHAIN} {{\n"
            "    type filter hook output priority 0 ; policy drop ;\n"
            "    meta mark set 0\n"
            f"    meta mark set ip saddr . {SLOT_ADDRESS} map @{AUTHORITY.ACTIVATED_MAP}\n"
            f"    ip saddr . {SLOT_ADDRESS} . meta mark @{AUTHORITY.PREPARED_SET} ip daddr {{ {t1}, {t2} }} tcp dport {PORT} accept\n"
            "  }\n"
            "}\n")


NFT_ERRORS = (("syntax error", "syntax_error"), ("Could not process rule", "rule_not_processed"),
              ("Operation not supported", "eopnotsupp"), ("Invalid argument", "einval"), ("File exists", "eexist"),
              ("No such file or directory", "enoent"), ("Operation not permitted", "eperm"),
              ("Datatype mismatch", "datatype_mismatch"), ("not supported", "not_supported"))


def install_error_token(returncode: int | None, stderr: str) -> str:
    if returncode == 0:
        return "accepted"
    for needle, token in NFT_ERRORS:
        if needle in stderr:
            return token
    return "other"


# H2K1D1: closed diagnostics for the fixed check/install/readback invocations (grammar in the
# launcher's DIAG_*). The class is read only from nft 1.0.9's fixed texts: the located error line
# "<name>:<line>:<first>-<last>: Error: <msg>" (src/erec.c print_location/erec_print; stdin is named
# "/dev/stdin" by src/libnftables.c, the command line "<cmdline>"), the bison "syntax error" (parse.error
# verbose), the evaluator's "datatype mismatch", and the batch path's "Could not process rule: <strerror>"
# (src/libnftables.c, src/cmd.c). Anything else, including any system error text outside that path, is
# "unknown", never a parser claim. Only the class, a bounded locator and the stderr SHA-256 leave.
DIAG_SCAN_CHARS = 65536
READBACK_COMMAND = "list table inet " + AUTHORITY.TABLE  # the readback argv after "-j", as nft names it <cmdline>
_LOCATED = re.compile(r"(/dev/stdin|<cmdline>):([0-9]{1,6}):([0-9]{1,6})-[0-9]{1,6}: Error: (.*)")
_UNLOCATED = re.compile(r"(?:netlink: )?Error: (.*)")
BATCH_PREFIX = "Could not process rule: "
BATCH_ERRNO = {"Invalid argument": "netlink_einval", "Operation not supported": "netlink_eopnotsupp",
               "Operation not permitted": "permission", "Permission denied": "permission"}
# A kernel EOPNOTSUPP for a base chain is reported without its errno text (src/cmd.c nft_cmd_chain_error).
CHAIN_EOPNOTSUPP = 'Chain of type "filter" is not supported, perhaps kernel support is missing?'
# glibc strerror texts: an error line carrying one is a system/kernel error, never a parser one.
ERRNO_TEXTS = ("Operation not permitted", "No such file or directory", "Invalid argument", "Operation not supported",
               "File exists", "Device or resource busy", "No buffer space available", "Cannot allocate memory",
               "Numerical result out of range", "Message too long", "Protocol not supported", "Permission denied",
               "Address family not supported by protocol", "No space left on device", "Too many links",
               "Too many levels of symbolic links", "Resource temporarily unavailable", "Bad file descriptor",
               "Function not implemented", "Value too large for defined data type", "Protocol error",
               "Interrupted system call", "Too many open files", "Argument list too long", "Connection refused")


def nft_error_class(stderr: str, name: str, source: str) -> tuple[str, int, int]:
    """(class, line, column) of the first nft error line in ``stderr`` for a nonzero exit. The locator
    counts only when it names ``name`` and lies inside ``source``; otherwise it is (0, 0)."""
    message, line, column = None, 0, 0
    for text in stderr[:DIAG_SCAN_CHARS].splitlines():
        located = _LOCATED.fullmatch(text)
        if located is not None:
            message = located.group(4)
            if located.group(1) == name:
                rows = source.split("\n")
                row, col = int(located.group(2)), int(located.group(3))
                if 1 <= row <= min(len(rows), LAUNCHER.DIAG_LINE_MAX) and 1 <= col <= min(len(rows[row - 1]) + 1,
                                                                                         LAUNCHER.DIAG_COLUMN_MAX):
                    line, column = row, col
            break
        unlocated = _UNLOCATED.fullmatch(text)
        if unlocated is not None:
            message = unlocated.group(1)
            break
    if message is None:
        return "unknown", 0, 0
    if message.startswith(BATCH_PREFIX):
        kind = BATCH_ERRNO.get(message[len(BATCH_PREFIX):], "unknown")
    elif message.startswith("cache initialization failed: "):
        kind = "permission" if BATCH_ERRNO.get(message.split(": ", 1)[1]) == "permission" else "unknown"
    elif message == CHAIN_EOPNOTSUPP:
        kind = "netlink_eopnotsupp"
    elif any(errno_text in message for errno_text in ERRNO_TEXTS):
        kind = "unknown"
    elif message.startswith("syntax error"):
        kind = "parser_syntax"
    elif message.startswith("datatype mismatch"):
        kind = "parser_datatype"
    elif line:
        kind = "parser_other"  # a located evaluator/parser message with no system error text
    else:
        kind = "unknown"
    return kind, line, column


def phase_diagnostic(completed: subprocess.CompletedProcess | None, failure: BaseException | None, name: str,
                     source: str) -> dict:
    """The closed fields of one invocation. A negative return code is a signal (kept as such), never
    an exit; a missing return code or a raised failure is its own status with exit -1."""
    returncode = completed.returncode if completed is not None else None
    stderr = completed.stderr if completed is not None and isinstance(completed.stderr, str) else ""
    fields = {"status": "missing", "exit": -1, "signal": 0, "class": "unknown", "line": 0, "column": 0,
              "stderr_sha256": hashlib.sha256(stderr.encode("utf-8", "backslashreplace")).hexdigest()}
    if isinstance(failure, subprocess.TimeoutExpired):
        fields["status"], fields["class"] = "timeout", "timeout"
    elif isinstance(failure, FileNotFoundError):
        fields["class"] = "tool_missing"
    elif isinstance(failure, PermissionError):
        fields["class"] = "permission"
    elif failure is not None or type(returncode) is not int:
        pass
    elif 0 <= returncode <= 255:
        fields.update(status="exit", exit=returncode)
        if returncode == 0:
            fields["class"] = "accepted"
        else:
            fields["class"], fields["line"], fields["column"] = nft_error_class(stderr, name, source)
    elif -LAUNCHER.DIAG_SIGNAL_MAX <= returncode <= -1:
        fields.update(status="signal", signal=-returncode)
    else:
        fields["status"] = "invalid"
    return fields


def installation_diagnostics(gate: str, check, check_failure: BaseException | None, installed, readback) -> dict:
    """The record fields of the three phases, bound to the SHA-256 of the exact gate input."""
    phases = {"check": phase_diagnostic(check, check_failure, "/dev/stdin", gate),
              "install": phase_diagnostic(installed, None, "/dev/stdin", gate),
              "readback": phase_diagnostic(readback, None, "<cmdline>", READBACK_COMMAND)}
    ints = {f"{phase}_{key}": fields[key] for phase, fields in phases.items() for key in ("exit", "signal", "line", "column")}
    tokens = {f"{phase}_{key}": fields[key] for phase, fields in phases.items() for key in ("status", "class", "stderr_sha256")}
    tokens["gate_input_sha256"] = hashlib.sha256(gate.encode("utf-8")).hexdigest()
    tokens["install_phase"] = next((phase for phase in LAUNCHER.DIAG_PHASES if phases[phase]["class"] != "accepted"), "none")
    return {"ints": ints, "tokens": tokens}


_META_MARK = {"meta": {"key": "mark"}}
_SADDR = {"payload": {"protocol": "ip", "field": "saddr"}}


def _is_mark_value(value, mark: int) -> bool:
    return value == mark or (isinstance(value, str) and re.fullmatch(r"0x0*" + format(mark, "x"), value) is not None)


def readback_shape(document) -> tuple[bool, dict[str, str]]:
    """The structural oracle over ``nft -j list table`` (the kernel's own readback, parsed here; the
    raw listing never leaves the run). Required: the gate chain hooks output with policy drop; its
    first rule resets the mark to 0; a later rule sets the mark from @activated; exactly one rule
    carries a verdict, it is accept, and that same rule matches @prepared. Informative tokens say
    whether each concatenation reads back as ``ip saddr . SLOT_ADDRESS[ . meta mark]`` and whether
    the target pins and the TCP 443 match read back."""
    tokens = {"chain": "missing", "mark_reset_first": "no", "activated_lookup": "missing", "accept_rules": "0",
              "accept_has_prepared": "no", "activated_key": "other", "prepared_key": "other", "target_pins": "other",
              "tcp_dport": "other", "other_verdicts": "0"}
    items = document.get("nftables") if isinstance(document, dict) else None
    if not isinstance(items, list):
        return False, {**tokens, "chain": "unparsed"}
    chains = [item["chain"] for item in items if isinstance(item, dict) and isinstance(item.get("chain"), dict)
              and item["chain"].get("name") == AUTHORITY.GATE_CHAIN]
    rules = [item["rule"].get("expr") for item in items if isinstance(item, dict) and isinstance(item.get("rule"), dict)
             and item["rule"].get("chain") == AUTHORITY.GATE_CHAIN]
    if len(chains) == 1 and chains[0].get("hook") == "output" and chains[0].get("policy") == "drop" and chains[0].get("type") == "filter":
        tokens["chain"] = "output_drop"
    if not rules or not all(isinstance(rule, list) for rule in rules):
        return False, tokens
    first = rules[0][0] if len(rules[0]) == 1 and isinstance(rules[0][0], dict) else {}
    if isinstance(first.get("mangle"), dict) and first["mangle"].get("key") == _META_MARK and _is_mark_value(
            first["mangle"].get("value"), 0):
        tokens["mark_reset_first"] = "yes"
    for rule in rules[1:]:
        for expr in rule:
            mangle = expr.get("mangle") if isinstance(expr, dict) else None
            value = mangle.get("value") if isinstance(mangle, dict) and mangle.get("key") == _META_MARK else None
            lookup = value.get("map") if isinstance(value, dict) else None
            if isinstance(lookup, dict) and lookup.get("data") == "@" + AUTHORITY.ACTIVATED_MAP:
                tokens["activated_lookup"] = "present"
                if lookup.get("key") == {"concat": [_SADDR, SLOT_ADDRESS]}:
                    tokens["activated_key"] = "saddr_const"
    verdict_rules = [rule for rule in rules if any(isinstance(expr, dict) and set(expr) & {"accept", "drop", "jump", "goto", "queue",
                                                                                           "return", "continue"} for expr in rule)]
    accepts = [rule for rule in verdict_rules if any(isinstance(expr, dict) and "accept" in expr for expr in rule)]
    tokens["accept_rules"] = str(len(accepts))
    tokens["other_verdicts"] = str(len(verdict_rules) - len(accepts))
    if len(accepts) == 1:
        for expr in accepts[0]:
            match = expr.get("match") if isinstance(expr, dict) else None
            if not isinstance(match, dict) or match.get("op") not in ("==", "in"):
                continue
            if match.get("right") == "@" + AUTHORITY.PREPARED_SET:
                tokens["accept_has_prepared"] = "yes"
                if match.get("left") == {"concat": [_SADDR, SLOT_ADDRESS, _META_MARK]}:
                    tokens["prepared_key"] = "saddr_const_mark"
            elif match.get("left") == {"payload": {"protocol": "ip", "field": "daddr"}}:
                right = match.get("right")
                if isinstance(right, dict) and isinstance(right.get("set"), list) and sorted(map(str, right["set"])) == sorted(TARGETS):
                    tokens["target_pins"] = "approved_pair"
            elif match.get("left") == {"payload": {"protocol": "tcp", "field": "dport"}} and match.get("right") == PORT:
                tokens["tcp_dport"] = "443"
    ok = (tokens["chain"] == "output_drop" and tokens["mark_reset_first"] == "yes" and tokens["activated_lookup"] == "present"
          and tokens["accept_rules"] == "1" and tokens["other_verdicts"] == "0" and tokens["accept_has_prepared"] == "yes")
    return ok, tokens


# ---------------------------------------------------------------------------------------------
# Raw rtnetlink: one veth whose peer is created directly in the namespace of a descriptor.

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
# Probes and oracles.

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


def record(case: str, ok: bool, ints: dict, tokens: dict) -> None:
    entry = {"case": case, "verdict": "pass" if ok else "fail", "control": LAUNCHER.RECORD_CASES[case][1],
             "ints": dict(ints), "tokens": dict(tokens)}
    assert LAUNCHER.sanitize_record(entry) is not None, f"record {case} is outside the closed grammar"
    with open(os.environ[LAUNCHER.RECORDS_ENV], "a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")


def error_token(error: BaseException) -> str:
    name = re.sub(r"[^a-z0-9]", "_", type(error).__name__.lower())[:40]
    code = getattr(error, "code", None)
    token = f"{name}_{code}" if isinstance(code, str) and re.fullmatch(r"[a-z0-9_]{1,30}", code) else name
    return token if LAUNCHER._TOKEN.fullmatch(token) else "error"


# ---------------------------------------------------------------------------------------------
# Static source/config gates (run everywhere).

def _functions(source: str) -> dict[str, ast.FunctionDef]:
    return {node.name: node for node in ast.walk(ast.parse(source)) if isinstance(node, ast.FunctionDef)}


def _top_functions(source: str) -> dict[str, ast.FunctionDef]:
    return {node.name: node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef)}


def _calls(node: ast.AST, name: str) -> list[ast.Call]:
    return [call for call in ast.walk(node) if isinstance(call, ast.Call)
            and ((isinstance(call.func, ast.Name) and call.func.id == name)
                 or (isinstance(call.func, ast.Attribute) and call.func.attr == name))]


def test_static_required_profile_cannot_skip():
    """One guarded skip path, unreachable with HEEL_REQUIRE_HOST_LEASE_KEY_PROOF=1, and every dynamic
    case passes through it before doing anything."""
    module = Path(__file__).read_text(encoding="utf-8")
    assert len(re.findall(r"^\s+pytest\.skip\(", module, re.M)) == 1
    assert "if REQUIRED:\n            pytest.fail(reason)\n        pytest.skip(reason)" in module
    for forbidden in ("x" + "fail", "skip" + "if", "importor" + "skip", "pytest.mark." + "skip"):
        assert forbidden not in module, forbidden
    for name, node in _top_functions(module).items():
        if name.startswith("test_") and not name.startswith("test_static_"):
            body = node.body[1:] if isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant) else node.body
            first = body[0]
            assert (isinstance(first, ast.Expr) and isinstance(first.value, ast.Call)
                    and getattr(first.value.func, "id", None) == "_require_runtime"), name


def test_static_launcher_requires_every_case_function_and_record_in_this_module():
    module = Path(__file__).read_text(encoding="utf-8")
    functions = _top_functions(module)
    cases = tuple(name for name in functions if name.startswith("test_"))
    assert cases == LAUNCHER.REQUIRED_CASES
    assert cases[-1] == "test_k6_every_owned_resource_is_resolved_and_the_outer_namespace_is_unchanged"
    recorded = {}
    for name in cases:
        for call in _calls(functions[name], "record"):
            assert isinstance(call.args[0], ast.Constant), name
            assert call.args[0].value not in recorded, call.args[0].value
            recorded[call.args[0].value] = name
    assert recorded == {case: item[0] for case, item in LAUNCHER.RECORD_CASES.items()}
    for name in recorded.values():
        assert len(_calls(functions[name], "record")) == 1, name
    assert {item[1] for item in LAUNCHER.RECORD_CASES.values()} <= set(LAUNCHER.CONTROLS)
    assert sorted(case for case, item in LAUNCHER.RECORD_CASES.items() if item[1] == "negative") == ["k2", "k4"]
    assert {item[2] for item in LAUNCHER.RECORD_CASES.values()} == {"pass"}
    # H2K1: K0-K6, each once, nothing optional; no seam exists.
    assert list(LAUNCHER.RECORD_CASES) == ["k0", "k1", "k2", "k3", "k4", "k5", "k6"]
    assert LAUNCHER.SEAMS == ()


def test_static_launcher_has_one_fixed_profile_fixed_budgets_and_no_inputs(tmp_path, capsys):
    source = LAUNCHER_FILE.read_text(encoding="utf-8")
    assert LAUNCHER.main(["--anything"]) == 2
    capsys.readouterr()
    assert "argparse" not in source and source.count("sys.argv") == 1 and "os.environ.get(\"RUNNER_TEMP\")" in source
    assert (LAUNCHER.LAUNCHER_SECONDS, LAUNCHER.TESTS_SECONDS, LAUNCHER.CLEANUP_RESERVE_SECONDS) == (1200, 600, 60)
    assert '["sudo", "-n", "--", sys.executable, "-I", str(Path(__file__).resolve())]' in source
    assert LAUNCHER.PROFILE == "lease-key-v1" and LAUNCHER.RUNTIME_ASSUMPTION == "running-kernel"
    assert LAUNCHER.ARTIFACT_FILES == ("summary.json", "cases.jsonl", "versions.txt", "cleanup.json", "report.txt")
    assert LAUNCHER.TEST_MODULE == "tests/linux/test_host_lease_key_shape.py"
    base = Path(os.path.realpath(tmp_path)) / "heel-host-lease-key-static"
    wheels, out = base / "wheels", base / "out"
    for directory in (base, wheels, out):
        directory.mkdir(mode=0o700)
        os.chmod(directory, 0o700)
    for item in LAUNCHER.PYTEST_CLOSURE:
        (wheels / item[2]).write_bytes(b"")
    good = {"schema": LAUNCHER.CHILD_SCHEMA, "wheels": str(wheels), "out": str(out), "uid": os.getuid(),
            "tests_seconds": 600, "token": "0123456789abcdef0123456789abcdef"}
    if os.getuid() != 0:
        assert LAUNCHER.validated_request(json.dumps(good)) is not None
    for mutation in ({"extra": 1}, {"schema": "heel.host-authority-proof.child.v1"}, {"uid": True}, {"uid": 0},
                     {"tests_seconds": 601}, {"tests_seconds": 5.0}, {"token": "0123456789ABCDEF0123456789ABCDEF"},
                     {"out": str(base)}, {"wheels": str(wheels) + "/"}, {"out": "relative/out"}):
        assert LAUNCHER.validated_request(json.dumps({**good, **mutation})) is None, mutation
    assert LAUNCHER.validated_request("[]") is None and LAUNCHER.validated_request("{") is None
    os.chmod(out, 0o770)
    assert LAUNCHER.validated_request(json.dumps(good)) is None


def test_static_profile_pin_and_closure_are_imported_not_copied():
    h1f = LAUNCHER.h1f()
    for name in ("PYTEST_CLOSURE", "PYTHON_VERSION", "PYTEST_VERSION", "FIXED_PATH", "HOST_TOOLS", "ProofFailure",
                 "LOCATOR_REASONS", "LOCATOR_TOKENS", "artifact_scan", "_env", "_sha256"):
        assert getattr(LAUNCHER, name) is getattr(h1f, name), name
    for name in ("SUPPORTED_KERNELS", "READD_EXPECTED", "kernel_profile"):
        assert getattr(LAUNCHER, name) is getattr(LAUNCHER.profile(), name), name
    assert PROFILE.SUPPORTED_KERNELS == h1f.SUPPORTED_KERNELS and PROFILE.READD_EXPECTED == h1f.READD_EXPECTED
    source = LAUNCHER_FILE.read_text(encoding="utf-8")
    module = Path(__file__).read_text(encoding="utf-8")
    for text in (source, module):
        for literal in ('"6.' + '17"', '"re' + 'fresh"', '"no' + 'op"', "files.python" + "hosted.org", "711ffd45" + "bf766d52",
                        "az" + "ure"):
            assert literal not in text, literal
    LAUNCHER.h1f().closure_matches_lock(json.loads(H0_LOCK.read_text(encoding="utf-8")))
    for text in (source, module):
        for forbidden in ("apt" + "-get", "apt" + " install", "dn" + "f ", "modpr" + "obe", "pip" + " install", "url" + "lib"):
            assert forbidden not in text, forbidden
    assert LEASE_MS == AUTHORITY.MAX_PREPARE_TIMEOUT_MS and LATE_MS < SHORT_MS < LEASE_MS


def test_static_workflow_is_the_recorded_four_jobs_plus_one_fully_constrained_job():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert workflow_violations(text) == []
    prior, job = text[:PRIOR_WORKFLOW_BYTES], _job_block(text, "host-lease-key-shape")
    assert text == prior + "\n" + job and job == KEY_SHAPE_JOB

    def swap(old: str, new: str) -> str:  # a mutation inside the appended job only
        assert job.count(old) == 1, old
        return prior + "\n" + job.replace(old, new)

    mutations = {
        "prior_only": prior, "trailing_bytes": text + "\n", "trailing_comment": text + "# trailing\n",
        "comment_between": prior + "\n# note\n" + job, "duplicate_job": text + "\n" + job,
        "sixth_job": text + "\n  extra-job:\n    runs-on: ubuntu-24.04\n",
        "prior_mutated": text.replace("cron: '24 7 * * 1'", "cron: '25 7 * * 1'"),
        "authority_mutated": text.replace("run: python scripts/host_authority_proof.py",
                                          "run: python scripts/host_authority_proof.py -x"),
        "contents_write": swap("      contents: read\n", "      contents: write\n"),
        "gate_other_branch": swap("refs/heads/codex/self-serve-host-lease-key-shape-proof", "refs/heads/main"),
        "gate_without_dispatch": swap("github.event_name == 'workflow_dispatch' && ", ""),
        "checkout_tag": swap(CHECKOUT, "actions/checkout@v4"),
        "checkout_other_sha": swap(CHECKOUT, "actions/checkout@" + "1" * 40),
        "cache_step": swap("      - name: Upload allowlisted safe evidence\n", "      - uses: actions/cache@" + "2" * 40
                           + "\n      - name: Upload allowlisted safe evidence\n"),
        "job_timeout_30": swap("timeout-minutes: 25", "timeout-minutes: 30"),
        "step_timeout_21": swap("timeout-minutes: 20", "timeout-minutes: 21"),
        "run_changed": swap("run: python scripts/host_lease_key_shape.py", "run: python scripts/host_lease_key_shape.py -k x"),
        "bare_extra_run": swap("      - name: Upload allowlisted safe evidence", "      - run: echo hi\n"
                               "      - name: Upload allowlisted safe evidence"),
        "extra_artifact": swap("            host-lease-key-shape/report.txt\n",
                               "            host-lease-key-shape/report.txt\n            host-lease-key-shape/raw.txt\n"),
        "retention_30": swap("retention-days: 3", "retention-days: 30"),
        "persist_credentials": swap("persist-credentials: false", "persist-credentials: true"),
        "env_added": swap("    steps:\n", "    env:\n      X: y\n    steps:\n"),
        "ref_not_sha": swap("ref: ${{ github.sha }}", "ref: ${{ github.ref }}"),
        "always_removed": swap("        if: always()\n", ""),
        "concurrency_removed": swap("    concurrency:\n      group: host-lease-key-shape\n      cancel-in-progress: false\n", ""),
        "python_unpinned": swap('python-version: "3.13.5"', 'python-version: "3.13"'),
        "runs_on_latest": swap("runs-on: ubuntu-24.04", "runs-on: ubuntu-latest"),
        "dispatch_inputs": text.replace("workflow_dispatch: {}", "workflow_dispatch:\n    inputs:\n      x: {}"),
    }
    for name, variant in mutations.items():
        assert variant != text, name
        assert workflow_violations(variant) != [], name


def _root_reads(source: str) -> set[str]:
    return {"/".join(re.findall(r'"([^"\n]+)"', chain)) for chain in re.findall(r'ROOT((?:\s*/\s*"[^"\n]+")+)', source)}


def test_static_launcher_stages_every_path_the_module_reads(tmp_path):
    """The child copies a fixed file list; everything this module and the launcher (and the H1F/H0
    launchers they import) read under ROOT is in it, and the static selection passes from an exact
    staged copy (no git, no other files)."""
    module = Path(__file__).read_text(encoding="utf-8")
    reads = _root_reads(module) | (_root_reads(LAUNCHER_FILE.read_text(encoding="utf-8")) - {"host-lease-key-shape"})
    reads.discard(".git")  # only probed below, to tell the checkout from the staged copy
    assert reads <= set(LAUNCHER.STAGE_FILES), sorted(reads - set(LAUNCHER.STAGE_FILES))
    assert len(LAUNCHER.STAGE_FILES) == len(set(LAUNCHER.STAGE_FILES)) == 10
    for name in ("scripts/host_lease_feasibility.py", "scripts/host_ingress_proof.py", "deploy/host/ingress/runtime-lock.json"):
        assert name in LAUNCHER.STAGE_FILES, name
    if not (ROOT / ".git").exists():
        assert [name for name in LAUNCHER.STAGE_FILES if not (ROOT / name).is_file()] == []
        return
    source = LAUNCHER.stage_tree(tmp_path / "src")
    staged = sorted(str(path.relative_to(source)) for path in source.rglob("*") if path.is_file())
    assert staged == sorted(LAUNCHER.STAGE_FILES)
    assert all((source / name).read_bytes() == (ROOT / name).read_bytes() for name in LAUNCHER.STAGE_FILES)
    statics = [name for name in LAUNCHER.REQUIRED_CASES if name.startswith("test_static_")]
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-k", "static", LAUNCHER.TEST_MODULE],
        cwd=source, capture_output=True, text=True, timeout=600,
        env={"PATH": LAUNCHER.FIXED_PATH, "LC_ALL": "C", "HOME": str(tmp_path), "PYTHONDONTWRITEBYTECODE": "1"})
    assert completed.returncode == 0, completed.stdout[-4000:]
    expected = f"{len(statics)} passed, {len(LAUNCHER.REQUIRED_CASES) - len(statics)} deselected"
    assert completed.stdout.splitlines()[-1].startswith(expected), completed.stdout[-400:]


def test_static_evidence_sanitizer_and_acceptance_rule(tmp_path):
    good = {"case": "k2", "verdict": "pass", "control": "negative", "ints": {"prepared_only_admitted": 0},
            "tokens": {"activation": "activated"}}
    assert LAUNCHER.sanitize_record(good) == good
    for entry in ({**good, "extra": 1}, {**good, "case": "k7"}, {**good, "control": "admission"}, {**good, "verdict": "info"},
                  {**good, "ints": {"flag": True}}, {**good, "tokens": {"path": "/tmp/x"}}, {**good, "tokens": {"t": "a b"}},
                  {**good, "tokens": {"address": "203.0.113.11/32"}}, {**good, "ints": {f"k{i}": i for i in range(65)}},
                  "not a dict"):
        assert LAUNCHER.sanitize_record(entry) is None, entry
    raw = tmp_path / "records.raw.jsonl"
    raw.write_text(json.dumps(good) + "\nnot json\n", encoding="utf-8")
    assert LAUNCHER.sanitize_records(raw) == ([good], 1)
    records = [{"case": case, "verdict": "pass", "control": item[1], "ints": {}, "tokens": {}}
               for case, item in LAUNCHER.RECORD_CASES.items()]
    by = {r["case"]: r for r in records}
    major_minor = sorted(PROFILE.SUPPORTED_KERNELS)[0]
    by["k0"]["tokens"] = {"kernel_major_minor": major_minor, "nft_version": PROFILE.SUPPORTED_NFT[0], "selftest": "pass",
                          "readd_observation": PROFILE.READD_EXPECTED[major_minor]}
    by["k0"]["ints"] = {"config_hz": PROFILE.SUPPORTED_HZ[-1]}
    junit = {"collected": len(LAUNCHER.REQUIRED_CASES), "passed": len(LAUNCHER.REQUIRED_CASES), "failed": 0, "errors": 0,
             "skipped": 0, "case_functions": list(LAUNCHER.REQUIRED_CASES), "failing": [], "failure_locators": []}
    cleanup, inner = {"host_fingerprints_unchanged": True}, {"pytest_exit": 0, "leftover_processes": 0}
    assert LAUNCHER.evaluate(junit, records, 0, cleanup, inner, 0)["result"] == "PASS"
    by["k0"]["tokens"]["readd_observation"] = "unknown"
    assert LAUNCHER.evaluate(junit, records, 0, cleanup, inner, 0)["result"] == "INCOMPLETE"
    by["k0"]["tokens"]["readd_observation"] = PROFILE.READD_EXPECTED[major_minor]
    assert LAUNCHER.evaluate({**junit, "passed": junit["passed"] - 1, "skipped": 1}, records, 0, cleanup, inner, 0)["result"] == "FAIL"
    assert LAUNCHER.evaluate(junit, records[1:], 0, cleanup, inner, 0)["result"] == "FAIL"
    assert LAUNCHER.evaluate(junit, records + [records[2]], 0, cleanup, inner, 0)["result"] == "FAIL"
    assert LAUNCHER.evaluate(junit, records, 1, cleanup, inner, 0)["result"] == "FAIL"
    assert LAUNCHER.evaluate(junit, records, 0, {"host_fingerprints_unchanged": False}, inner, 0)["result"] == "FAIL"
    assert LAUNCHER.evaluate(junit, records, 0, cleanup, {**inner, "leftover_processes": 1}, 0)["result"] == "FAIL"
    by["k4"]["verdict"] = "fail"
    assert LAUNCHER.evaluate(junit, records, 0, cleanup, inner, 0)["result"] == "FAIL"
    lines = LAUNCHER.version_lines(by, "pinned") + LAUNCHER.report_lines({"result": "PASS", "records": records}, None, cleanup)
    assert "runtime_assumption running-kernel" in lines and "kernel_profile pinned" in lines
    assert all(re.fullmatch(r"[a-z0-9_]+ [A-Za-z0-9_.:/ -]*", line) for line in lines), lines
    # Record keys this module writes stay inside the closed key grammar.
    assert all(LAUNCHER._TOKEN.fullmatch(error_token(error)) for error in (ValueError(), AUTHORITY.PrepareFailed("installer_refused")))
    assert error_token(AUTHORITY.PrepareFailed("installer_refused")) == "preparefailed_installer_refused"


def test_static_fixture_uses_only_the_public_domain_api_and_fd_only_namespaces():
    module = Path(__file__).read_text(encoding="utf-8")
    tree = ast.parse(module)
    used = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name) and node.value.id == "AUTHORITY" and not node.attr.startswith("__")}
    assert used <= set(AUTHORITY.__all__), sorted(used - set(AUTHORITY.__all__))
    # No private attribute of anything but this module's own objects and the launcher's helpers.
    private = sorted({ast.unparse(node) for node in ast.walk(tree) if isinstance(node, ast.Attribute)
                      and node.attr.startswith("_") and not node.attr.startswith("__")
                      and not (isinstance(node.value, ast.Name) and node.value.id in ("self", "LAUNCHER", "os"))})
    assert private == [], private
    for forbidden in ("_gate_table" + "_fixture", "_seams" + "_for_tests", "Cycle" + "Seams", "_counter" + "=", "_ns" + "_fd",
                      "_hand" + "les", "_reser" + "vations", "_Mark" + "Counter", "_render" + "_", "/run/" + "net" + "ns",
                      "ns" + "enter", "ip " + "net" + "ns", "multi" + "processing"):
        assert forbidden not in module, forbidden
    assert not [node for node in ast.walk(tree) if isinstance(node, ast.Constant) and node.value == "net" + "ns"]
    # Every key is the fixed logical key: prepare(SLOT_PEER, SLOT_ADDRESS, <lifetime>) and nothing else.
    prepares = _calls(tree, "prepare")
    assert prepares and all(len(call.args) == 3 and [ast.unparse(arg) for arg in call.args[:2]] == ["SLOT_PEER", "SLOT_ADDRESS"]
                            for call in prepares), [ast.unparse(call) for call in prepares]
    assert [ast.unparse(call) for call in _calls(tree, "create")] == ["AUTHORITY.LeaseDomain.create()"] * 2
    # Namespaces: the peer is unshared on a thread and held by descriptor; the veth peer lands there by
    # IFLA_NET_NS_FD from a dup that is closed in a finally; commands enter by setns on a descriptor.
    functions = _top_functions(module)
    fresh = ast.get_source_segment(module, functions["_fresh_namespace"])
    assert "os.unshare(CLONE_NEWNET)" in fresh and '"/proc/thread-self/ns/net"' in fresh
    wire = ast.get_source_segment(module, _functions(module)["_create_veth"])
    assert "peer_fd = os.dup(self.r_fd)" in wire and "finally:\n            os.close(peer_fd)" in wire
    assert "socket.AF_NETLINK" in wire and "veth_message(" in wire
    preexec = [keyword for call in ast.walk(tree) if isinstance(call, ast.Call) for keyword in call.keywords
               if keyword.arg == "preexec_fn"]
    assert [ast.unparse(keyword.value) for keyword in preexec] == ["lambda: os.setns(fd, CLONE_NEWNET)"]
    # The public descriptor is only ever dup'ed (never closed, passed or setns'ed directly) or probed for closure.
    descriptor_uses = sorted(ast.unparse(parent) for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)
                             if isinstance(child, ast.Attribute) and child.attr == "ns_fd")
    assert descriptor_uses == ["domain.ns_fd", "os.dup(domain.ns_fd)", "os.dup(domain.ns_fd)"], descriptor_uses
    # SO_MARK is set only by the K2 caller-supplied-mark negative.
    users = {name for name, node in functions.items() if "mark=" in ast.get_source_segment(module, node)
             and name.startswith("_k")}
    assert users == {"_k2"}, users
    message = veth_message(7, "lk1l", b"\x02\0\0\0\0\x01", "lk1r", b"\x02\0\0\0\0\x02", 5)
    assert struct.unpack_from("=IHHII", message) == (len(message), RTM_NEWLINK, 0x605, 7, 0) and len(message) % 4 == 0
    assert struct.pack("=I", 5) in message and b"veth\0" in message
    assert netlink_ack(struct.pack("=IHHIIi", 36, NLMSG_ERROR, 0, 7, 0, 0) + b"\0" * 16, 7) == 0
    assert netlink_ack(struct.pack("=IHHIIi", 36, NLMSG_ERROR, 0, 7, 0, -17) + b"\0" * 16, 7) == -17
    assert netlink_ack(struct.pack("=IHHIIi", 36, NLMSG_ERROR, 0, 8, 0, 0) + b"\0" * 16, 7) == -errno.EPROTO


def _synthetic_readback() -> dict:
    """Oracle unit input only: the readback structure the oracle accepts. It is not a claim about
    what nft 1.0.9 prints; the dynamic cases parse the kernel's actual listing."""
    return {"nftables": [
        {"metainfo": {"json_schema_version": 1}},
        {"table": {"family": "inet", "name": AUTHORITY.TABLE}},
        {"chain": {"family": "inet", "table": AUTHORITY.TABLE, "name": AUTHORITY.GATE_CHAIN, "type": "filter",
                   "hook": "output", "prio": 0, "policy": "drop"}},
        {"rule": {"chain": AUTHORITY.GATE_CHAIN, "expr": [{"mangle": {"key": _META_MARK, "value": 0}}]}},
        {"rule": {"chain": AUTHORITY.GATE_CHAIN, "expr": [{"mangle": {"key": _META_MARK, "value": {"map": {
            "key": {"concat": [_SADDR, SLOT_ADDRESS]}, "data": "@" + AUTHORITY.ACTIVATED_MAP}}}}]}},
        {"rule": {"chain": AUTHORITY.GATE_CHAIN, "expr": [
            {"match": {"op": "==", "left": {"concat": [_SADDR, SLOT_ADDRESS, _META_MARK]}, "right": "@" + AUTHORITY.PREPARED_SET}},
            {"match": {"op": "==", "left": {"payload": {"protocol": "ip", "field": "daddr"}}, "right": {"set": list(TARGETS)}}},
            {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": PORT}},
            {"accept": None}]}},
    ]}


def test_static_gate_shape_and_readback_oracle():
    table = gate_table()
    assert SLOT_ADDRESS not in TARGETS and UNAPPROVED not in TARGETS and len(set(TARGETS)) == 2
    assert len({SLOT_PEER, WRONG_SOURCE, SLOT_ADDRESS, UNAPPROVED, *TARGETS}) == 6
    lines = [line.strip() for line in table.splitlines()]
    reset, lookup = "meta mark set 0", f"meta mark set ip saddr . {SLOT_ADDRESS} map @{AUTHORITY.ACTIVATED_MAP}"
    admit = (f"ip saddr . {SLOT_ADDRESS} . meta mark @{AUTHORITY.PREPARED_SET} ip daddr {{ {TARGETS[0]}, {TARGETS[1]} }} "
             f"tcp dport {PORT} accept")
    assert lines.index(reset) < lines.index(lookup) < lines.index(admit) == len(lines) - 3
    assert table.count("accept") == 1 and "policy drop" in table and "hook output" in table and "ip daddr ." not in table
    assert f"type ipv4_addr . ipv4_addr . mark ; flags timeout ;" in table and "type ipv4_addr . ipv4_addr : mark ;" in table
    assert install_error_token(0, "") == "accepted" and install_error_token(1, "Error: syntax error, unexpected") == "syntax_error"
    assert install_error_token(1, "something new") == "other" and install_error_token(None, "") == "other"
    ok, tokens = readback_shape(_synthetic_readback())
    assert ok and tokens["prepared_key"] == "saddr_const_mark" and tokens["activated_key"] == "saddr_const", tokens
    assert tokens["target_pins"] == "approved_pair" and tokens["tcp_dport"] == "443"
    assert all(LAUNCHER._TOKEN.fullmatch(value) for value in tokens.values())

    def mutated(change) -> dict:
        document = json.loads(json.dumps(_synthetic_readback()))
        change(document["nftables"])
        return document

    def second_accept(items):
        items.append({"rule": {"chain": AUTHORITY.GATE_CHAIN, "expr": [{"accept": None}]}})

    def accept_without_prepared(items):
        del items[5]["rule"]["expr"][0]

    def policy_accept(items):
        items[2]["chain"]["policy"] = "accept"

    def no_reset(items):
        del items[3]

    def reset_after_lookup(items):
        items[3], items[4] = items[4], items[3]

    def jump(items):
        items.insert(4, {"rule": {"chain": AUTHORITY.GATE_CHAIN, "expr": [{"jump": {"target": "x"}}]}})

    def other_hook(items):
        items[2]["chain"]["hook"] = "input"

    for change in (second_accept, accept_without_prepared, policy_accept, no_reset, reset_after_lookup, jump, other_hook):
        assert readback_shape(mutated(change))[0] is False, change.__name__
    assert readback_shape({})[0] is False and readback_shape([])[0] is False
    # The constant reads back in another form: still structurally gated, recorded as "other".
    def literal_hex(items):
        items[5]["rule"]["expr"][0]["match"]["left"]["concat"][1] = "0xc0000201"

    ok, tokens = readback_shape(mutated(literal_hex))
    assert ok and tokens["prepared_key"] == "other"


# H2K1D1: the parent c653e6b's gate input and acceptance sources, recorded as fixed values.
PARENT_GATE_BYTES = 409
PARENT_GATE_SHA256 = "3e08d90e91d71775a3f16e6a541f67cec356e0f051cf5112114ccdba0f758a48"
PARENT_SOURCE_SHA256 = {
    "gate_table": "09e8e8b31af628283e1d2ed2f316b51f22b07f1248b79e7a2451ce88cc79fa73",
    "install_error_token": "64e70241082c69e43b97079140d71ee6e63845fa6b4f2c82f7c16d53da72bf2b",
    "readback_shape": "6694f37589b73a0011131daa3be7cde5b8e2938849ca24f3dfb03d463e6c94b2",
    "gate_ready": "1bec7b8501fe0e0aed2dc9c6003436a43fdee3fb44af9dafa64d84965e341e75",
}
PARENT_LAUNCHER_SHA256 = {
    "evaluate": "d89ecaf1b916be0626e7ec72acfe9237dd4f2982c8adb22a632b2b4be5c108c5",
    "index_records": "a878323cb93535399f8ef39aaf47332992ba23eb15b2a851a8a31011cf601b27",
    "summarize_junit": "7619a21e106db305b4e7e6ac78e245cb18a18c8f2c7369b0fe13b13301631f16",
}
PARENT_NFT_ERRORS_SHA256 = "80d5a7221191fa3270fd778f06c45e714d1d895218ad8b1cb94ac1e3648a5700"
DYNAMIC_CASES = (
    "test_k0_profile_is_captured_and_the_real_h1_self_test_passes",
    "test_k1_live_lease_admits_tcp_443_to_two_distinct_approved_targets",
    "test_k2_prepared_only_and_a_caller_supplied_mark_never_admit",
    "test_k3_no_fresh_connection_is_admitted_after_the_expiry_bound",
    "test_k4_late_activation_of_an_expired_key_does_not_revive_egress",
    "test_k5_live_lease_confines_source_target_port_protocol_and_family",
    "test_k6_every_owned_resource_is_resolved_and_the_outer_namespace_is_unchanged",
)


def _segment_sha256(source: str, name: str) -> str:
    return hashlib.sha256(ast.get_source_segment(source, _functions(source)[name]).encode()).hexdigest()


def test_static_gate_bytes_and_the_fixed_check_install_readback_sequence_are_unchanged():
    module = Path(__file__).read_text(encoding="utf-8")
    launcher = LAUNCHER_FILE.read_text(encoding="utf-8")
    gate = gate_table().encode("utf-8")
    assert (len(gate), hashlib.sha256(gate).hexdigest()) == (PARENT_GATE_BYTES, PARENT_GATE_SHA256)
    for name, digest in PARENT_SOURCE_SHA256.items():
        assert _segment_sha256(module, name) == digest, name
    for name, digest in PARENT_LAUNCHER_SHA256.items():
        assert _segment_sha256(launcher, name) == digest, name
    assert hashlib.sha256(json.dumps([list(item) for item in NFT_ERRORS]).encode()).hexdigest() == PARENT_NFT_ERRORS_SHA256
    # The fixture runs exactly: fresh listing, one check of the gate, the unchanged install, the readback.
    init = next(node for node in ast.parse(module).body if isinstance(node, ast.ClassDef) and node.name == "Fixture").body[0]
    assert init.name == "__init__"
    runs = [ast.unparse(call) for call in sorted(_calls(init, "_run_in"), key=lambda call: (call.lineno, call.col_offset))]
    assert runs == ["_run_in(self.l_fd, [AUTHORITY.NFT_PATH, 'list', 'ruleset'])",
                    "_run_in(self.l_fd, [AUTHORITY.NFT_PATH, '-c', '-f', '-'], gate_table())",
                    "_run_in(self.l_fd, [AUTHORITY.NFT_PATH, '-f', '-'], gate_table())",
                    "_run_in(self.l_fd, [AUTHORITY.NFT_PATH, '-j', 'list', 'table', 'inet', AUTHORITY.TABLE])"], runs
    every = [ast.unparse(call) for call in _calls(ast.parse(module), "_run_in")]
    assert sum("'-c'" in text for text in every) == 1 and sum("'-f'" in text for text in every) == 2
    assert READBACK_COMMAND == " ".join(["list", "table", "inet", AUTHORITY.TABLE])
    # The check is alone inside a try whose handler only records the failure; the install is outside it.
    tries = [node for node in ast.walk(init) if isinstance(node, ast.Try) and _calls(node, "_run_in")]
    check_try = [node for node in tries if len(_calls(node, "_run_in")) == 1]
    assert len(check_try) == 1 and [ast.unparse(call) for call in _calls(check_try[0], "_run_in")] == [runs[1]]
    handler = check_try[0].handlers[0]
    assert ast.unparse(handler.type) == "Exception" and ast.unparse(handler.body) == "check_failure = error"
    init_text = ast.get_source_segment(module, init)
    assert "self.facts[\"install\"] = install_error_token(installed.returncode, installed.stderr)\n" in init_text
    assert init_text.index('"-c", "-f", "-"]') < init_text.index('installed = _run_in(self.l_fd, [AUTHORITY.NFT_PATH, "-f", "-"]')
    assert ("self.facts[\"diagnostics\"] = installation_diagnostics(gate_table(), checked, check_failure, installed, readback)"
            in init_text)
    # The required inventory: the dynamic cases and their records are exactly the parent's.
    assert tuple(name for name in LAUNCHER.REQUIRED_CASES if not name.startswith("test_static_")) == DYNAMIC_CASES
    assert [item[0] for item in LAUNCHER.RECORD_CASES.values()] == list(DYNAMIC_CASES)
    assert LAUNCHER.ARTIFACT_FILES == ("summary.json", "cases.jsonl", "versions.txt", "cleanup.json", "report.txt")


def _diag_record(diagnostics: dict, case: str = "k1") -> dict:
    """A K-record carrying the fixture's facts plus the diagnostic fields, as ``record`` would write it."""
    ints = {"namespaces_distinct": 1, "fresh_ruleset_empty": 1, "peer_link_in_r": 1, "outer_links_after_wire": 1,
            "ipv6_wired": 1, "baseline_kinds": 7, "baseline_reachable": 7, "baseline_ipv6_reachable": 1, **diagnostics["ints"]}
    tokens = {"install": "other", "readback_sha256": hashlib.sha256(b"").hexdigest(), **diagnostics["tokens"]}
    return {"case": case, "verdict": "fail", "control": LAUNCHER.RECORD_CASES[case][1], "ints": ints, "tokens": tokens}


def test_static_installation_diagnostics_are_closed_and_carry_no_raw_text():
    gate = gate_table()
    done = subprocess.CompletedProcess

    def located(line: int, first: int, message: str, name: str = "/dev/stdin") -> str:
        return f"{name}:{line}:{first}-{first + 3}: Error: {message}\n    some echoed line\n    ^^^^\n"

    # nft 1.0.9's own forms (src/erec.c, src/libnftables.c, src/cmd.c, src/evaluate.c, src/cache.c).
    cases = {
        located(7, 30, "syntax error, unexpected map, expecting end of file or newline or semicolon"): ("parser_syntax", 7, 30),
        located(8, 5, "datatype mismatch, expected concatenation of (IPv4 address, IPv4 address, packet mark), "
                      "expression has type IPv4 address"): ("parser_datatype", 8, 5),
        located(8, 5, "datatype mismatch: expected mark, expression has type integer"): ("parser_datatype", 8, 5),
        located(7, 5, "Use concatenations with sets and maps, not singleton values"): ("parser_other", 7, 5),
        located(8, 5, "Could not process rule: Invalid argument"): ("netlink_einval", 8, 5),
        located(7, 5, "Could not process rule: Operation not supported"): ("netlink_eopnotsupp", 7, 5),
        located(4, 9, CHAIN_EOPNOTSUPP): ("netlink_eopnotsupp", 4, 9),
        located(1, 1, "Could not process rule: Operation not permitted"): ("permission", 1, 1),
        "netlink: Error: cache initialization failed: Operation not permitted\n": ("permission", 0, 0),
        "netlink: Error: cache initialization failed: Permission denied\n": ("permission", 0, 0),
        "Error: Could not process rule: Invalid argument\n": ("netlink_einval", 0, 0),
        # Kernel/system errors that are neither of the two named errnos stay unknown, never parser_*.
        located(8, 5, "Could not process rule: No buffer space available"): ("unknown", 8, 5),
        located(8, 5, "Could not process rule: Message too long"): ("unknown", 8, 5),
        located(7, 43, "No such file or directory; did you mean table ‘x’ in family inet?"): ("unknown", 7, 43),
        located(2, 3, "Numerical result out of range"): ("unknown", 2, 3),
        "netlink: Error: cache initialization failed: No such file or directory\n": ("unknown", 0, 0),
        "netlink: Error: Unknown data type in set key 7\n": ("unknown", 0, 0),
        "netlink: Error: Cannot parse userdata\n": ("unknown", 0, 0),
        "": ("unknown", 0, 0), "Segmentation fault\n": ("unknown", 0, 0), "Warning: something\n": ("unknown", 0, 0),
        # Locators: only the expected name, inside the gate text, ever counts; the class survives without it.
        located(99, 5, "syntax error, unexpected x"): ("parser_syntax", 0, 0),
        located(7, 400, "syntax error, unexpected x"): ("parser_syntax", 0, 0),
        located(0, 5, "syntax error, unexpected x"): ("parser_syntax", 0, 0),
        located(7, 5, "syntax error, unexpected x", "<cmdline>"): ("parser_syntax", 0, 0),
        located(7, 5, "Use concatenations with sets and maps, not singleton values", "<cmdline>"): ("unknown", 0, 0),
        "/tmp/evil:7:30-33: Error: syntax error\n": ("unknown", 0, 0),
        "/dev/stdin:1234567:1-2: Error: syntax error\n": ("unknown", 0, 0),
        "/dev/stdin:7:5: Error: syntax error\n": ("unknown", 0, 0),
        "/dev/stdin:7:5-9: Error: syntax error\r\n": ("parser_syntax", 7, 5),
        " Error: syntax error\n": ("unknown", 0, 0),
        "x" * (DIAG_SCAN_CHARS + 10) + "\n" + located(7, 5, "syntax error"): ("unknown", 0, 0),
        "\n" * (DIAG_SCAN_CHARS + 10) + located(7, 5, "syntax error"): ("unknown", 0, 0),
    }
    for stderr, expected in cases.items():
        assert nft_error_class(stderr, "/dev/stdin", gate) == expected, (stderr[:120], expected)
    assert nft_error_class("<cmdline>:1:6-10: Error: syntax error, unexpected x\n", "<cmdline>", READBACK_COMMAND) == (
        "parser_syntax", 1, 6)
    assert nft_error_class("<cmdline>:2:1-2: Error: syntax error\n", "<cmdline>", READBACK_COMMAND) == ("parser_syntax", 0, 0)

    # Process outcomes: a negative return code stays a signal; nothing becomes a normal exit by default.
    def diag(returncode, stderr="", failure=None):
        completed = None if returncode == "absent" else done(["nft"], returncode, "", stderr)
        fields = phase_diagnostic(completed, failure, "/dev/stdin", gate)
        return fields["status"], fields["exit"], fields["signal"], fields["class"], fields["line"], fields["column"]

    syntax = located(7, 30, "syntax error, unexpected map")
    assert diag(0) == ("exit", 0, 0, "accepted", 0, 0)
    assert diag(0, syntax) == ("exit", 0, 0, "accepted", 0, 0)
    assert diag(1, syntax) == ("exit", 1, 0, "parser_syntax", 7, 30)
    assert diag(255) == ("exit", 255, 0, "unknown", 0, 0)
    assert diag(256) == ("invalid", -1, 0, "unknown", 0, 0)
    assert diag(-9, syntax) == ("signal", -1, 9, "unknown", 0, 0)
    assert diag(-1) == ("signal", -1, 1, "unknown", 0, 0)
    assert diag(-64) == ("signal", -1, 64, "unknown", 0, 0)
    assert diag(-65) == ("invalid", -1, 0, "unknown", 0, 0)
    assert diag(None) == ("missing", -1, 0, "unknown", 0, 0) and diag("absent") == diag(None)
    assert diag(True) == ("missing", -1, 0, "unknown", 0, 0) and diag(1.0) == diag(None)
    assert diag("absent", failure=subprocess.TimeoutExpired(["nft"], 30)) == ("timeout", -1, 0, "timeout", 0, 0)
    assert diag("absent", failure=FileNotFoundError(2, "No such file", "/usr/sbin/nft")) == ("missing", -1, 0, "tool_missing", 0, 0)
    assert diag("absent", failure=PermissionError(13, "denied")) == ("missing", -1, 0, "permission", 0, 0)
    assert diag("absent", failure=UnicodeDecodeError("utf-8", b"\xff", 0, 1, "bad")) == ("missing", -1, 0, "unknown", 0, 0)
    assert diag(0, failure=RuntimeError("/root/x 203.0.113.11")) == ("missing", -1, 0, "unknown", 0, 0)
    assert phase_diagnostic(done(["nft"], 1, "", b"bytes"), None, "/dev/stdin", gate)["stderr_sha256"] == hashlib.sha256(b"").hexdigest()
    assert phase_diagnostic(done(["nft"], 1, "", syntax), None, "/dev/stdin", gate)["stderr_sha256"] == hashlib.sha256(
        syntax.encode()).hexdigest()

    # Whole records: hostile stderr reaches only its hash; each record stays inside the closed grammar.
    hostile = ("/dev/stdin:8:5-9: Error: Could not process rule: Invalid argument\n"
               "    ip saddr . 192.0.2.1 . meta mark @prepared ip daddr { 203.0.113.11, 203.0.113.12 }\n"
               "/etc/shadow /proc/self/ns/net net:[4026531840] fd48:4b31::20 ghp_" + "A" * 36 + " AKIA" + "B" * 16
               + " password=hunter2 ‮\u0000\udcff " + "z" * 100000 + "\n")
    secrets_found = ("/etc/shadow", "4026531840", "fd48:4b31", "ghp_", "AKIA", "hunter2", "203.0.113", "192.0.2.1", "prepared",
                     "‮", "zzzz", "Invalid argument", "/dev/stdin")
    readback_missing = done(["nft"], 1, "", "Error: No such file or directory\nlist table inet " + AUTHORITY.TABLE + "\n")
    variants = {
        "install_rejected": (done(["nft"], 0, "", ""), None, done(["nft"], 1, "", hostile), readback_missing),
        "check_rejected": (done(["nft"], 1, "", hostile), None, done(["nft"], 1, "", hostile), readback_missing),
        "check_timeout": (None, subprocess.TimeoutExpired(["nft"], 30), done(["nft"], -9, "", hostile), readback_missing),
        "check_missing": (None, FileNotFoundError(2, "x", "/usr/sbin/nft"), done(["nft"], 0, "", ""), done(["nft"], 0, "{}", "")),
        "all_accepted": (done(["nft"], 0, "", ""), None, done(["nft"], 0, "", ""), done(["nft"], 0, "{}", "")),
    }
    phases = {}
    for name, (check, failure, installed, readback) in variants.items():
        diagnostics = installation_diagnostics(gate, check, failure, installed, readback)
        assert diagnostics["tokens"]["gate_input_sha256"] == PARENT_GATE_SHA256
        entry = _diag_record(diagnostics)
        clean = LAUNCHER.sanitize_record(entry)
        assert clean is not None, name
        text = json.dumps(clean, ensure_ascii=False)
        assert len(text) <= 8192 and not [item for item in secrets_found if item in text], name
        assert set(diagnostics["tokens"]) == set(LAUNCHER.DIAG_TOKEN_KEYS) and set(diagnostics["ints"]) == set(LAUNCHER.DIAG_INT_KEYS)
        phases[name] = (diagnostics["tokens"]["install_phase"], *(diagnostics["tokens"][f"{phase}_class"] for phase in LAUNCHER.DIAG_PHASES))
    assert phases == {"install_rejected": ("install", "accepted", "netlink_einval", "unknown"),
                      "check_rejected": ("check", "netlink_einval", "netlink_einval", "unknown"),
                      "check_timeout": ("check", "timeout", "unknown", "unknown"),
                      "check_missing": ("check", "tool_missing", "accepted", "accepted"),
                      "all_accepted": ("none", "accepted", "accepted", "accepted")}
    # The largest record any K case writes stays inside the per-record limits.
    good = _diag_record(installation_diagnostics(gate, *variants["install_rejected"]))
    worst_ints = {**good["ints"], **{f"x{index}": 10 ** 12 for index in range(64 - len(good["ints"]))}}
    worst_tokens = {**good["tokens"], **{f"rb_{index}": "z" * 80 for index in range(10)}, "late_activation": "z" * 80,
                    "error": "z" * 80}
    assert len(good["ints"]) + 14 <= 64 and len(worst_tokens) <= 32  # K5 adds 14 case ints; K4 adds two tokens
    worst = {**good, "case": "k4", "control": "negative", "ints": worst_ints, "tokens": worst_tokens}
    assert LAUNCHER.sanitize_record(worst) is not None and len(json.dumps(worst)) <= 8192
    # Records from a fixture that never reached the gate (no diagnostic field at all) remain valid.
    assert LAUNCHER.sanitize_record({**good, "ints": {}, "tokens": {"install": "not_reached", "error": "runtimeerror"}}) is not None

    def drop(change) -> None:
        entry = json.loads(json.dumps(good))
        change(entry["ints"], entry["tokens"])
        assert LAUNCHER.sanitize_record(entry) is None, json.dumps(entry, sort_keys=True)

    hex64 = "ab" * 32
    for change in (
            lambda i, t: t.update(install_class="Parser_syntax"), lambda i, t: t.update(install_class="kernel_rejected"),
            lambda i, t: t.update(install_class="203.0.113.11"), lambda i, t: t.update(check_status="exited"),
            lambda i, t: t.update(readback_class="other"), lambda i, t: i.update(install_exit=256),
            lambda i, t: i.update(install_exit=-2), lambda i, t: i.update(install_exit=0),
            lambda i, t: i.update(install_signal=9), lambda i, t: i.update(install_column=0),
            lambda i, t: i.update(check_line=1, check_column=1),
            lambda i, t: i.update(install_line=65, install_column=1), lambda i, t: i.update(install_column=513),
            lambda i, t: i.update(install_line=0), lambda i, t: i.update(check_exit=1),
            lambda i, t: t.update(install_stderr_sha256=hex64.upper()), lambda i, t: t.update(install_stderr_sha256=hex64[:63]),
            lambda i, t: t.update(install_stderr_sha256="invalid_argument"), lambda i, t: t.update(gate_input_sha256="192.0.2.1"),
            lambda i, t: t.update(install_phase="check"), lambda i, t: t.update(install_phase="none"),
            lambda i, t: t.pop("readback_status"), lambda i, t: i.pop("check_signal"),
            lambda i, t: i.update(check_class=1), lambda i, t: t.update(check_exit="0"),
            lambda i, t: t.update(install_status="signal"), lambda i, t: (i.update(install_exit=-1), t.update(install_status="signal")),
            lambda i, t: (i.update(install_exit=-1, install_signal=65), t.update(install_status="signal", install_class="unknown")),
            lambda i, t: (i.update(install_exit=-1, install_signal=9), t.update(install_status="signal")),
            lambda i, t: (i.update(install_exit=-1), t.update(install_status="timeout")),
            lambda i, t: (i.update(install_exit=-1, install_line=0, install_column=0), t.update(install_status="missing",
                                                                                                install_class="accepted")),
            lambda i, t: (i.update(install_exit=-1, install_line=0, install_column=0), t.update(install_status="invalid",
                                                                                                install_class="timeout")),
            lambda i, t: t.update(check_class="tool_missing"), lambda i, t: t.update(check_status="timeout", check_class="timeout"),
    ):
        drop(change)
    # The same fields with consistent signal/timeout/missing values are accepted.
    for change in (lambda i, t: (i.update(install_exit=-1, install_signal=9, install_line=0, install_column=0),
                                 t.update(install_status="signal", install_class="unknown")),
                   lambda i, t: (i.update(install_exit=-1, install_line=0, install_column=0),
                                 t.update(install_status="timeout", install_class="timeout")),
                   lambda i, t: (i.update(install_exit=-1, install_line=0, install_column=0),
                                 t.update(install_status="missing", install_class="tool_missing"))):
        entry = json.loads(json.dumps(good))
        change(entry["ints"], entry["tokens"])
        assert LAUNCHER.sanitize_record(entry) is not None, change


def test_static_doc_names_every_case_and_the_limits():
    doc = DOC.read_text(encoding="utf-8")
    for case in LAUNCHER.RECORD_CASES:
        assert f"**{case.upper()}**" in doc, case
    for phrase in ("INCOMPLETE", "kernel_profile pinned", "runtime_assumption running-kernel", "UNRUN",
                   "python scripts/host_lease_key_shape.py", "IFLA_NET_NS_FD", "immediate constant", "no fallback",
                   "L3/L4", "Host/SNI/TLS", "ten files", "_gate_table" + "_fixture", "HostCycle", "lease-key-v1",
                   "refs/heads/codex/self-serve-host-lease-key-shape-proof", "DNS"):
        assert phrase in doc, phrase


# ---------------------------------------------------------------------------------------------
# Runtime guard (the single skip path).

def _runtime_unavailable_reason() -> str | None:
    if not sys.platform.startswith("linux"):
        return "requires the fixed lease-key launcher on Linux"
    if sys.version_info < (3, 12) or not hasattr(os, "setns") or not hasattr(os, "unshare"):
        return "requires the launcher's pinned Python with namespace support"
    if not hasattr(socket, "AF_NETLINK"):
        return "requires rtnetlink sockets"
    if os.geteuid() != 0:
        return "requires the launcher's isolated namespace driver"
    if not all(os.environ.get(name) for name in (LAUNCHER.RECORDS_ENV, LAUNCHER.WORK_ENV, LAUNCHER.TOKEN_ENV)):
        return "requires the fixed lease-key launcher environment"
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
    """K0 did not capture a pinned profile with a tick; every later bound would be unfounded."""


class InjectedFailure(RuntimeError):
    """K6's deliberate failure inside a live fixture."""


STATE: dict = {}  # k0: tick_ns and the outer-namespace fingerprint baseline; residuals of every fixture
RESIDUALS: list[dict] = []
SOCKETS: list = []
OPEN_FIXTURES: set = set()
COUNTERS = {"fixtures": 0, "domains": 0, "sockets": 0, "probes": 0}


def _tick_ns() -> int:
    if "tick_ns" not in STATE:
        raise ProfileUnavailable("profile_unavailable")
    return STATE["tick_ns"]


def _thread(target, name: str) -> threading.Thread:
    return threading.Thread(target=target, name="heel-lk-" + name, daemon=True)


def _in_netns(fd: int, function):
    """Run ``function`` on a fresh thread that entered the namespace of ``fd`` (setns is per thread)."""
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
            target = os.readlink(f"/proc/self/fd/{entry}")
            if target.startswith("net:["):
                found.add(target)
    return found


def _run_in(fd: int | None, argv: list[str], data: str | None = None) -> subprocess.CompletedProcess:
    """One fixed tool in the namespace of ``fd`` (the outer namespace for None); output stays private."""
    if fd is None:
        return subprocess.run(argv, input=data, capture_output=True, text=True, timeout=30, env=LAUNCHER._env())
    return subprocess.run(argv, input=data, capture_output=True, text=True, timeout=30, env=LAUNCHER._env(),
                          preexec_fn=lambda: os.setns(fd, CLONE_NEWNET))  # noqa: PLW1509


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


# ---------------------------------------------------------------------------------------------
# The owned fixture: generation namespace L (the domain's own, via a dup of ns_fd), peer namespace R
# (fd-only), one veth, fixed listeners in R, a pre-gate reachability baseline, then the owned gate.

LISTENERS = (("t1", socket.AF_INET, socket.SOCK_STREAM, (TARGETS[0], PORT)),
             ("t2", socket.AF_INET, socket.SOCK_STREAM, (TARGETS[1], PORT)),
             ("t3", socket.AF_INET, socket.SOCK_STREAM, (UNAPPROVED, PORT)),
             ("t1_wrong_port", socket.AF_INET, socket.SOCK_STREAM, (TARGETS[0], WRONG_PORT)),
             ("t1_udp", socket.AF_INET, socket.SOCK_DGRAM, (TARGETS[0], PORT)))
LISTENER6 = ("t6", socket.AF_INET6, socket.SOCK_STREAM, (TARGET6, PORT))
# The fixed probe kinds: kind -> (source, target, port, transport, listener label).
PLAN = {
    "t1": (SLOT_PEER, TARGETS[0], PORT, "tcp", "t1"),
    "t2": (SLOT_PEER, TARGETS[1], PORT, "tcp", "t2"),
    "wrong_source": (WRONG_SOURCE, TARGETS[0], PORT, "tcp", "t1"),
    "unapproved_target": (SLOT_PEER, UNAPPROVED, PORT, "tcp", "t3"),
    "wrong_port": (SLOT_PEER, TARGETS[0], WRONG_PORT, "tcp", "t1_wrong_port"),
    "udp": (SLOT_PEER, TARGETS[0], PORT, "udp", "t1_udp"),
    "ipv6": (PEER6, TARGET6, PORT, "tcp6", "t6"),
}


class Peer:
    """The fixed listeners in R and one thread that records which nonce reached which listener."""

    def __init__(self, r_fd: int, *, ipv6: bool):
        self.sockets: dict = {}
        self.seen: dict[bytes, str] = {}
        self.lock = threading.Lock()
        self.stop = threading.Event()
        self.thread: threading.Thread | None = None
        for spec in LISTENERS + ((LISTENER6,) if ipv6 else ()):
            self._add(r_fd, *spec)

    def _add(self, r_fd: int, label: str, family: int, kind: int, address: tuple) -> None:
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
        self.sockets[sock] = (label, kind)

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


class Fixture:
    def __init__(self, domain):
        COUNTERS["fixtures"] += 1
        self.n = COUNTERS["fixtures"]
        self.domain = domain
        self.l_fd: int | None = os.dup(domain.ns_fd)  # the process-owned dup of the public descriptor
        self.r_fd: int | None = None
        self.peer: Peer | None = None
        self.identities: set[str] = set()
        self.facts: dict = {}
        OPEN_FIXTURES.add(self)
        try:
            self.r_fd = _fresh_namespace()
            outer = os.stat("/proc/self/ns/net")
            ids = {_identity(self.l_fd), _identity(self.r_fd), (outer.st_dev, outer.st_ino)}
            self.facts["namespaces_distinct"] = int(len(ids) == 3)
            self.identities = {f"net:[{_identity(fd)[1]}]" for fd in (self.l_fd, self.r_fd)}
            listing = _run_in(self.l_fd, [AUTHORITY.NFT_PATH, "list", "ruleset"])
            self.facts["fresh_ruleset_empty"] = int(listing.returncode == 0 and listing.stdout.strip() == "")
            self._wire()
            self.peer = Peer(self.r_fd, ipv6=bool(self.facts["ipv6_wired"])).start()
            self.facts.update(self._baseline())
            # H2K1D1: one non-mutating check of the same input first; its outcome never gates the install.
            checked, check_failure = None, None
            try:
                checked = _run_in(self.l_fd, [AUTHORITY.NFT_PATH, "-c", "-f", "-"], gate_table())
            except Exception as error:  # noqa: BLE001 - a closed status only
                check_failure = error
            installed = _run_in(self.l_fd, [AUTHORITY.NFT_PATH, "-f", "-"], gate_table())
            self.facts["install"] = install_error_token(installed.returncode, installed.stderr)
            readback = _run_in(self.l_fd, [AUTHORITY.NFT_PATH, "-j", "list", "table", "inet", AUTHORITY.TABLE])
            try:
                document = json.loads(readback.stdout) if readback.returncode == 0 else None
            except ValueError:
                document = None
            self.facts["readback_ok"], self.facts["readback"] = readback_shape(document)
            self.facts["readback_sha256"] = hashlib.sha256(readback.stdout.encode()).hexdigest()
            self.facts["diagnostics"] = installation_diagnostics(gate_table(), checked, check_failure, installed, readback)
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
        a, b = f"lk{self.n}l", f"lk{self.n}r"
        mac_l, mac_r = bytes((2, 0x4b, 0x31, 0, self.n & 255, 0x0a)), bytes((2, 0x4b, 0x31, 0, self.n & 255, 0x0b))
        text_l, text_r = (":".join(f"{byte:02x}" for byte in mac) for mac in (mac_l, mac_r))
        self._create_veth(a, mac_l, b, mac_r)
        self.facts["peer_link_in_r"] = int(self.ip(self.r_fd, "link", "show", "dev", b))
        self.facts["outer_links_after_wire"] = len(socket.if_nameindex())
        steps = [(self.l_fd, "link", "set", "lo", "up"), (self.r_fd, "link", "set", "lo", "up"),
                 (self.l_fd, "addr", "add", f"{SLOT_PEER}/32", "dev", a), (self.l_fd, "addr", "add", f"{WRONG_SOURCE}/32", "dev", a),
                 *[(self.r_fd, "addr", "add", f"{target}/32", "dev", b) for target in (*TARGETS, UNAPPROVED)],
                 (self.l_fd, "link", "set", a, "up"), (self.r_fd, "link", "set", b, "up"),
                 *[(self.l_fd, "route", "add", f"{target}/32", "dev", a, "src", SLOT_PEER) for target in (*TARGETS, UNAPPROVED)],
                 *[(self.l_fd, "neigh", "replace", target, "lladdr", text_r, "dev", a, "nud", "permanent")
                   for target in (*TARGETS, UNAPPROVED)],
                 *[(self.r_fd, "route", "add", f"{source}/32", "dev", b) for source in (SLOT_PEER, WRONG_SOURCE)],
                 *[(self.r_fd, "neigh", "replace", source, "lladdr", text_l, "dev", b, "nud", "permanent")
                   for source in (SLOT_PEER, WRONG_SOURCE)]]
        for fd, *arguments in steps:
            if not self.ip(fd, *arguments):
                raise RuntimeError("fixture_ip_" + arguments[0])
        # IPv6 is wired best effort; only K5 requires it (an IPv6-less kernel fails K5, nothing else).
        steps6 = [(self.l_fd, "-6", "addr", "add", f"{PEER6}/128", "dev", a, "nodad"),
                  (self.r_fd, "-6", "addr", "add", f"{TARGET6}/128", "dev", b, "nodad"),
                  (self.l_fd, "-6", "route", "add", f"{TARGET6}/128", "dev", a),
                  (self.r_fd, "-6", "route", "add", f"{PEER6}/128", "dev", b),
                  (self.l_fd, "-6", "neigh", "replace", TARGET6, "lladdr", text_r, "dev", a, "nud", "permanent"),
                  (self.r_fd, "-6", "neigh", "replace", PEER6, "lladdr", text_l, "dev", b, "nud", "permanent")]
        self.facts["ipv6_wired"] = int(all(self.ip(fd, *arguments) for fd, *arguments in steps6))

    def _baseline(self) -> dict:
        """Before the gate exists every fixed probe kind connects/delivers, so a later denial is the
        gate's, not the topology's."""
        kinds = [kind for kind in PLAN if kind != "ipv6" or self.facts["ipv6_wired"]]
        probes = self.settle([self.probe(kind) for kind in kinds])
        reachable = {probe.kind for probe in probes if probe.admitted and probe.delivered}
        return {"baseline_kinds": len(kinds), "baseline_reachable": len(reachable),
                "baseline_ipv6_reachable": int("ipv6" in reachable)}

    def probe(self, kind: str, *, mark: int | None = None) -> Probe:
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
                if mark is not None:
                    sock.setsockopt(socket.SOL_SOCKET, SO_MARK, mark)
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

    def series(self, kinds: list[str], start_ns: int, until_ns: int, *, mark: int | None = None,
               limit: int = 120) -> list[Probe]:
        """Probes every PROBE_INTERVAL_NS from ``start_ns`` while the slot is not past ``until_ns``."""
        probes = []
        for index in range(limit):
            slot = start_ns + index * PROBE_INTERVAL_NS
            if slot > until_ns:
                break
            sleep_until(slot)
            probes.append(self.probe(kinds[index % len(kinds)], mark=mark))
        return probes

    def settle(self, probes: list[Probe]) -> list[Probe]:
        time.sleep(0.3)  # in-flight bytes arrive; delivery only, never an admission time
        for probe in probes:
            label = self.peer.delivered(probe.nonce)
            probe.delivered = label == probe.expect
            probe.misdelivered = label is not None and label != probe.expect
        return probes

    def gate_ready(self) -> bool:
        return (self.facts.get("install") == "accepted" and self.facts.get("readback_ok") is True
                and self.facts.get("fresh_ruleset_empty") == 1 and self.facts.get("namespaces_distinct") == 1)

    def facts_ints(self) -> dict:
        ints = {key: value for key, value in self.facts.items() if type(value) is int}
        ints.update((self.facts.get("diagnostics") or {}).get("ints", {}))
        return ints

    def facts_tokens(self) -> dict:
        tokens = {"install": self.facts.get("install", "not_reached"),
                  "readback_sha256": self.facts.get("readback_sha256", "none")}
        tokens.update({f"rb_{key}": value for key, value in (self.facts.get("readback") or {}).items()})
        tokens.update((self.facts.get("diagnostics") or {}).get("tokens", {}))
        return tokens

    def close(self) -> None:
        if self.peer is not None:
            self.peer.close()
        for name in ("l_fd", "r_fd"):
            fd = getattr(self, name)
            if fd is not None:
                with contextlib.suppress(OSError):
                    os.close(fd)
                setattr(self, name, None)
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
            domain.close_generation()


@contextlib.contextmanager
def _fixture(case: str):
    """One fresh domain and fixture per case; afterwards (also after a failure) the fixture, the
    domain and every descriptor to its namespaces are resolved and the residuals recorded for K6."""
    domain = AUTHORITY.LeaseDomain.create()
    COUNTERS["domains"] += 1
    fixture = None
    try:
        fixture = Fixture(domain)
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


# ---------------------------------------------------------------------------------------------
# Dynamic cases (Linux, inside the launcher's namespaces only).

def _command(argv: list[str]) -> str:
    try:
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=20, env=LAUNCHER._env())
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return completed.stdout if completed.returncode == 0 else ""


def _k0(ints: dict, tokens: dict) -> bool:
    STATE["namespace_fds_baseline"] = len(_namespace_fds())
    STATE["outer_fingerprint"] = _outer_fingerprint()
    STATE["outer_links_baseline"] = len(socket.if_nameindex())
    domain = AUTHORITY.LeaseDomain.create()
    COUNTERS["domains"] += 1
    try:
        probe_fd = os.dup(domain.ns_fd)
        try:
            outer = os.stat("/proc/self/ns/net")
            empty = _run_in(probe_fd, [AUTHORITY.NFT_PATH, "list", "ruleset"])
            ints["create_namespace_fresh"] = int(_identity(probe_fd) != (outer.st_dev, outer.st_ino))
            ints["create_ruleset_empty"] = int(empty.returncode == 0 and empty.stdout.strip() == "")
            try:
                report = AUTHORITY.generation_self_test(domain)
            except AUTHORITY.HostQuarantined as error:
                report = error.report
            after = _run_in(probe_fd, [AUTHORITY.NFT_PATH, "list", "ruleset"])
            ints["selftest_left_domain_empty"] = int(after.returncode == 0 and after.stdout.strip() == "")
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
    if grade == "pinned" and tick is not None:
        STATE["tick_ns"] = tick
        ints["tick_ns"] = tick
    return (report.result == "pass" and grade == "pinned" and tick is not None and ints["create_namespace_fresh"] == 1
            and ints["create_ruleset_empty"] == 1 and ints["selftest_left_domain_empty"] == 1)


def test_k0_profile_is_captured_and_the_real_h1_self_test_passes():
    _require_runtime()
    ints, tokens, ok = {}, {}, False
    try:
        ok = _k0(ints, tokens)
    except Exception as error:  # noqa: BLE001 - a fixed token only
        tokens["error"] = error_token(error)
    record("k0", ok, ints, tokens)
    assert ok, "the captured profile is not pinned, the real H1 self-test failed, or create() was not fresh and empty"


def _k1(ints: dict, tokens: dict) -> bool:
    _tick_ns()  # fail closed before any fixture when K0 captured no pinned tick
    with _fixture("k1") as fx:
        ints.update(fx.facts_ints())
        tokens.update(fx.facts_tokens())
        if not fx.gate_ready():
            return False
        before = time.monotonic_ns()
        handle = fx.domain.prepare(SLOT_PEER, SLOT_ADDRESS, LEASE_MS)
        after_prepare = time.monotonic_ns()
        fx.domain.activate(handle)
        after_activate = time.monotonic_ns()
        live_to, bound = _bounds(before, after_prepare, LEASE_MS)
        probes = fx.settle(fx.series(["t1", "t2"], after_activate, bound + 800 * MS))
    window, late = inside(probes, after_activate, live_to), after(probes, bound)
    per_target = {kind: [p for p in window if p.kind == kind] for kind in ("t1", "t2")}
    ints.update(lease_ms=LEASE_MS, prepare_bracket_us=(after_prepare - before) // 1000,
                activate_bracket_us=(after_activate - after_prepare) // 1000, live_probes=len(window),
                live_admitted_t1=sum(p.admitted and p.delivered for p in per_target["t1"]),
                live_admitted_t2=sum(p.admitted and p.delivered for p in per_target["t2"]),
                after_bound_probes=len(late), after_bound_accepted=sum(p.accepted for p in late), anomalies=anomalies(probes),
                targets_distinct_from_slot=int(SLOT_ADDRESS not in TARGETS and TARGETS[0] != TARGETS[1]))
    return (all(live(per_target[kind], 5) for kind in per_target) and closed(late, 5) and anomalies(probes) == 0
            and ints["targets_distinct_from_slot"] == 1)


def test_k1_live_lease_admits_tcp_443_to_two_distinct_approved_targets():
    _require_runtime()
    ints, tokens, ok = {}, {}, False
    try:
        ok = _k1(ints, tokens)
    except Exception as error:  # noqa: BLE001 - a fixed token only
        tokens["error"] = error_token(error)
    record("k1", ok, ints, tokens)
    assert ok, "the immediate-constant key did not admit both approved targets only while the lease was valid"


def _k2(ints: dict, tokens: dict) -> bool:
    _tick_ns()  # fail closed before any fixture when K0 captured no pinned tick
    with _fixture("k2") as fx:
        ints.update(fx.facts_ints())
        tokens.update(fx.facts_tokens())
        if not fx.gate_ready():
            return False
        before = time.monotonic_ns()
        handle = fx.domain.prepare(SLOT_PEER, SLOT_ADDRESS, LEASE_MS)
        after_prepare = time.monotonic_ns()
        live_to, _bound = _bounds(before, after_prepare, LEASE_MS)
        plain = fx.series(["t1", "t2"], after_prepare, after_prepare + 400 * MS)
        # The caller-supplied packet mark equals the prepared element's own mark; without the reset and
        # the activated lookup it would satisfy the membership on its own.
        forged = fx.series(["t1", "t2", "wrong_source"], time.monotonic_ns(), time.monotonic_ns() + 400 * MS, mark=handle.mark)
        fx.domain.activate(handle)
        after_activate = time.monotonic_ns()
        control = fx.series(["t1", "t2"], after_activate, min(after_activate + 500 * MS, live_to - 200 * MS))
        fx.settle(plain + forged + control)
    prepared_only = inside(plain + forged, after_prepare, live_to)
    window = inside(control, after_activate, live_to)
    ints.update(prepared_only_probes=len(prepared_only), prepared_only_accepted=sum(p.accepted for p in prepared_only),
                forged_mark_probes=len(inside(forged, after_prepare, live_to)),
                forged_mark_accepted=sum(p.accepted for p in forged), control_probes=len(window),
                control_admitted=sum(p.admitted and p.delivered for p in window), anomalies=anomalies(plain + forged + control))
    return closed(prepared_only, 8) and len(inside(forged, after_prepare, live_to)) >= 5 and live(window, 3)


def test_k2_prepared_only_and_a_caller_supplied_mark_never_admit():
    _require_runtime()
    ints, tokens, ok = {}, {}, False
    try:
        ok = _k2(ints, tokens)
    except Exception as error:  # noqa: BLE001 - a fixed token only
        tokens["error"] = error_token(error)
    record("k2", ok, ints, tokens)
    assert ok, "a prepared-only key or a caller-supplied mark admitted a packet, or the activated control did not"


def _k3(ints: dict, tokens: dict) -> bool:
    _tick_ns()  # fail closed before any fixture when K0 captured no pinned tick
    with _fixture("k3") as fx:
        ints.update(fx.facts_ints())
        tokens.update(fx.facts_tokens())
        if not fx.gate_ready():
            return False
        before = time.monotonic_ns()
        handle = fx.domain.prepare(SLOT_PEER, SLOT_ADDRESS, SHORT_MS)
        after_prepare = time.monotonic_ns()
        fx.domain.activate(handle)
        after_activate = time.monotonic_ns()
        live_to, bound = _bounds(before, after_prepare, SHORT_MS)
        probes = fx.settle(fx.series(["t1", "t2"], after_activate, bound + 1500 * MS))
    window, late = inside(probes, after_activate, live_to), after(probes, bound)
    ints.update(lease_ms=SHORT_MS, tick_ns=_tick_ns(), bound_after_prepare_ms=(bound - after_prepare) // MS,
                live_probes=len(window), live_admitted=sum(p.admitted and p.delivered for p in window),
                after_bound_probes=len(late), after_bound_accepted=sum(p.accepted for p in late), anomalies=anomalies(probes))
    return live(window, 3) and closed(late, 8) and anomalies(probes) == 0


def test_k3_no_fresh_connection_is_admitted_after_the_expiry_bound():
    _require_runtime()
    ints, tokens, ok = {}, {}, False
    try:
        ok = _k3(ints, tokens)
    except Exception as error:  # noqa: BLE001 - a fixed token only
        tokens["error"] = error_token(error)
    record("k3", ok, ints, tokens)
    assert ok, "no positive before the bound, or a fresh connection was admitted after the conservative expiry bound"


def _k4(ints: dict, tokens: dict) -> bool:
    _tick_ns()  # fail closed before any fixture when K0 captured no pinned tick
    with _fixture("k4") as fx:
        ints.update(fx.facts_ints())
        tokens.update(fx.facts_tokens())
        if not fx.gate_ready():
            return False
        before = time.monotonic_ns()
        handle = fx.domain.prepare(SLOT_PEER, SLOT_ADDRESS, LATE_MS)
        after_prepare = time.monotonic_ns()
        _live_to, bound = _bounds(before, after_prepare, LATE_MS)
        sleep_until(bound + 50 * MS)
        late_start = time.monotonic_ns()
        try:
            fx.domain.activate(handle)
            tokens["late_activation"] = "activated"
        except (AUTHORITY.InstallerFailed, AUTHORITY.HandleState) as error:
            tokens["late_activation"] = "refused_" + error_token(error)
        revived = fx.series(["t1", "t2"], time.monotonic_ns(), time.monotonic_ns() + 800 * MS)
        # Positive control: a fresh key through the same API admits, so the closed window above is the
        # expired membership's doing; closing that key then denies again.
        fresh_before = time.monotonic_ns()
        fresh = fx.domain.prepare(SLOT_PEER, SLOT_ADDRESS, LEASE_MS)
        fresh_after = time.monotonic_ns()
        fx.domain.activate(fresh)
        fresh_active = time.monotonic_ns()
        fresh_live_to, _fresh_bound = _bounds(fresh_before, fresh_after, LEASE_MS)
        control = fx.series(["t1", "t2"], fresh_active, min(fresh_active + 500 * MS, fresh_live_to - 900 * MS))
        fx.domain.close(fresh)
        after_close = time.monotonic_ns()
        reclosed = fx.series(["t1", "t2"], after_close, min(after_close + 500 * MS, fresh_live_to))
        fx.settle(revived + control + reclosed)
    window = inside(control, fresh_active, fresh_live_to)
    ints.update(late_ms=LATE_MS, activation_after_bound_ms=(late_start - bound) // MS, revived_probes=len(revived),
                revived_accepted=sum(p.accepted for p in revived), control_probes=len(window),
                control_admitted=sum(p.admitted and p.delivered for p in window), reclosed_probes=len(reclosed),
                reclosed_accepted=sum(p.accepted for p in reclosed), anomalies=anomalies(revived + control + reclosed))
    return late_start > bound and closed(revived, 5) and live(window, 3) and closed(reclosed, 3)


def test_k4_late_activation_of_an_expired_key_does_not_revive_egress():
    _require_runtime()
    ints, tokens, ok = {}, {}, False
    try:
        ok = _k4(ints, tokens)
    except Exception as error:  # noqa: BLE001 - a fixed token only
        tokens["error"] = error_token(error)
    record("k4", ok, ints, tokens)
    assert ok, "activating an expired prepared key revived egress, or the fresh-key control did not admit"


NEGATIVES = ("wrong_source", "unapproved_target", "wrong_port", "udp", "ipv6")


def _k5(ints: dict, tokens: dict) -> bool:
    _tick_ns()  # fail closed before any fixture when K0 captured no pinned tick
    with _fixture("k5") as fx:
        ints.update(fx.facts_ints())
        tokens.update(fx.facts_tokens())
        if not fx.gate_ready() or fx.facts["baseline_reachable"] != len(PLAN):
            return False
        before = time.monotonic_ns()
        handle = fx.domain.prepare(SLOT_PEER, SLOT_ADDRESS, LEASE_MS)
        after_prepare = time.monotonic_ns()
        fx.domain.activate(handle)
        after_activate = time.monotonic_ns()
        live_to, _bound = _bounds(before, after_prepare, LEASE_MS)
        rounds = ["t1", *NEGATIVES, "t2"] * 2
        probes = fx.settle([fx.probe(kind) for kind in rounds])
    window = inside(probes, after_activate, live_to)
    controls = [p for p in window if p.kind in ("t1", "t2")]
    for kind in NEGATIVES:
        ints[f"{kind}_probes"] = sum(p.kind == kind for p in window)
        ints[f"{kind}_accepted"] = sum(p.accepted for p in probes if p.kind == kind)
    ints.update(control_probes=len(controls), control_admitted=sum(p.admitted and p.delivered for p in controls),
                probes_outside_live=len(probes) - len(window), anomalies=anomalies(probes))
    return (len(window) == len(probes) and live(controls, 4)
            and all(closed([p for p in window if p.kind == kind], 2) for kind in NEGATIVES))


def test_k5_live_lease_confines_source_target_port_protocol_and_family():
    _require_runtime()
    ints, tokens, ok = {}, {}, False
    try:
        ok = _k5(ints, tokens)
    except Exception as error:  # noqa: BLE001 - a fixed token only
        tokens["error"] = error_token(error)
    record("k5", ok, ints, tokens)
    assert ok, "with a live lease a wrong source, unapproved target, wrong port, UDP or IPv6 probe was admitted"


def _k6(ints: dict, tokens: dict) -> bool:
    # An injected failure inside a live fixture with an active key resolves like a normal exit.
    injected = None
    try:
        with _fixture("k6_injected") as fx:
            injected = fx
            if fx.gate_ready():
                key = fx.domain.prepare(SLOT_PEER, SLOT_ADDRESS, LEASE_MS)
                fx.domain.activate(key)
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
    threads = [thread for thread in threading.enumerate() if thread.name.startswith("heel-lk-") and thread.is_alive()]
    unresolved = sum(AUTHORITY.unresolved_children().values())
    fingerprint = _outer_fingerprint()
    differing = sorted(key for key in fingerprint if STATE.get("outer_fingerprint", {}).get(key) != fingerprint[key])
    ints.update({f"residual_{key}": value for key, value in residual.items()})
    ints.update(fixtures_recorded=len(RESIDUALS), injected_recorded=int(any(e["case"] == "k6_injected" for e in RESIDUALS)),
                injected_namespace_fds_held=len(_namespace_fds() & (injected.identities if injected else set())),
                open_fixtures=len(OPEN_FIXTURES), open_sockets=sum(sock.fileno() != -1 for sock in SOCKETS),
                namespace_fds=len(_namespace_fds()), namespace_fds_baseline=STATE.get("namespace_fds_baseline", -1),
                outer_links=len(links), outer_links_baseline=STATE.get("outer_links_baseline", -1),
                owned_residual_links=len([name for name in links if name != "lo"]), other_processes=len(others),
                fixture_threads_alive=len(threads), registry_unresolved=unresolved, outer_fingerprints_differing=len(differing),
                fixtures_created=COUNTERS["fixtures"], domains_created=COUNTERS["domains"],
                sockets_created=COUNTERS["sockets"], probes_sent=COUNTERS["probes"])
    for index, name in enumerate(differing[:5]):
        tokens[f"differing_{index}"] = name
    return (tokens.get("injected") == "raised" and injected is not None and ints["injected_recorded"] == 1
            and not any(residual.values()) and ints["injected_namespace_fds_held"] == 0 and not OPEN_FIXTURES
            and ints["open_sockets"] == 0 and ints["namespace_fds"] == ints["namespace_fds_baseline"]
            and links == ["lo"] and not others and not threads and unresolved == 0 and not differing
            and "outer_fingerprint" in STATE)


def test_k6_every_owned_resource_is_resolved_and_the_outer_namespace_is_unchanged():
    _require_runtime()
    ints, tokens, ok = {}, {}, False
    try:
        ok = _k6(ints, tokens)
    except Exception as error:  # noqa: BLE001 - a fixed token only
        tokens["error"] = error_token(error)
    record("k6", ok, ints, tokens)
    assert ok, "an owned namespace, descriptor, socket, thread, process or link survived, or the outer namespace changed"
