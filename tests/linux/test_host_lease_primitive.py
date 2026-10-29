"""H1F: Linux feasibility proof of the prepared-gate lease primitive (H1DR section 4 with the Astra
H1DR disposition corrections).

Static cases run everywhere. Dynamic cases need the fixed ``scripts/host_lease_feasibility.py``
launcher: it runs this module as root inside an outer network+mount+PID namespace that has only
loopback, with ``HEEL_REQUIRE_HOST_LEASE_PROOF=1``. Under that switch a missing platform, privilege,
tool, launcher environment or namespace capability fails; outside it the dynamic cases skip, so the
ordinary suite never claims lease proof. Every packet case uses a fresh pair of inner network
namespaces (L sends 198.51.100.10 -> R 203.0.113.10 over one veth) that is destroyed afterwards.

Measurement model. A probe is a 64-byte UDP datagram sent from L at 100 per second. The gate is a
filter hook on L's output path, which the kernel evaluates synchronously inside ``sendto``: an
accepted probe returns success and a dropped one returns EPERM. So each probe's admission instant
lies inside its own userspace bracket ``[t_before, t_after]`` (CLOCK_MONOTONIC around the syscall).
R's receive time only confirms delivery and is never an admission time, so receiver scheduling or a
queued old datagram cannot look like new authority. "Admitted after X" means a probe accepted or
delivered with ``t_before > X``; that is evidence of admission after X, not the exact kernel
instant. Expiry bounds are ``E_max = t_pq + T`` (``t_pq`` = the prepare batch's return) plus one
kernel tick; the tick is an expiry-granularity fact (H1DR section 4.3), never a measurement
allowance, and a stale activation is graded with no allowance at all. Positive delivery counts only
probes wholly inside an interval where the element was certainly live and activated.

The proof establishes kernel primitive and peer-credential facts only. Marks here are distinct
proof-run values: this module specifies no H1A allocator (no wrapping layout is accepted), no
service, no H2 network isolation, no H3 lifecycle and no product stop bound.
"""
from __future__ import annotations

import ast
import contextlib
import gzip
import hashlib
import importlib.util
import json
import math
import os
import queue
import random
import re
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCHER_FILE = ROOT / "scripts" / "host_lease_feasibility.py"
WORKFLOW = ROOT / ".github" / "workflows" / "codeql.yml"
DOC = ROOT / "docs" / "saas" / "HOST_LEASE_FEASIBILITY.md"
H0_LOCK = ROOT / "deploy" / "host" / "ingress" / "runtime-lock.json"


def _load_launcher():
    spec = importlib.util.spec_from_file_location("host_lease_feasibility", LAUNCHER_FILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


LAUNCHER = _load_launcher()
REQUIRED = os.environ.get(LAUNCHER.REQUIRED_ENV) == "1"

MS = 1_000_000
L_ADDR, R_ADDR, PORT = "198.51.100.10", "203.0.113.10", 47001
TUPLE = f"{L_ADDR} . {R_ADDR}"
PROBE_INTERVAL_NS = 10 * MS
PAYLOAD = struct.Struct("!4sIQ16s")
PAYLOAD_BYTES = 64
MAGIC = b"HL1P"
LIVE_PERCENT = 95
CP_UID, OUTSIDER_UID = 10001, 10002
CLONE_NEWNET = 0x40000000
SO_MARK = getattr(socket, "SO_MARK", 36)
SO_PEERCRED = getattr(socket, "SO_PEERCRED", 17)

# The recorded f04ab70 baseline of .github/workflows/codeql.yml: the whole file is a byte prefix of
# the candidate, and each existing job block keeps its hash. Fixed values, so a shallow checkout or
# the launcher's staged copy checks them without git history.
# Dependency refresh: the recorded prefix includes reviewed Action-pin upgrades;
# hosted-proof job bytes and all mutation checks remain unchanged.
BASELINE_WORKFLOW_BYTES = 2309
BASELINE_WORKFLOW_SHA256 = "0d2efed30d9985a93ffc21fc5b2cda0843d2cb46f3267cccabc2156f330d706e"
BASELINE_JOB_SHA256 = {
    "analyze": "2ae70cbd1c7bd1483b4e4a0534ecec3ebd97cbe6ac529d65ae17483c17666e99",
    "host-ingress-proof": "6c5f0f58d512a5e43df1648594b9d324aa88b561d95d3fa307901df63b296b70",
}
LEASE_BRANCH_GATE = ("if: github.event_name == 'workflow_dispatch' && "
                     "github.ref == 'refs/heads/codex/self-serve-host-lease-proof'")


# ---------------------------------------------------------------------------------------------
# Fixture shapes and batches (proof fixtures; H2 owns any production table layout).

def gate_table(*, gc_interval_hour: bool = False, mark_reset: bool = True) -> str:
    """H1DR section 4.1. ``gc_interval_hour`` keeps expired elements in memory (expired-key cases);
    ``mark_reset=False`` is only the N2 negative control."""
    options = " gc-interval 1h ;" if gc_interval_hour else ""
    reset = "    meta mark set 0\n" if mark_reset else ""
    return ("table inet heel_lease {\n"
            f"  set prepared {{ type ipv4_addr . ipv4_addr . mark ; flags timeout ;{options} }}\n"
            "  map activated { type ipv4_addr . ipv4_addr : mark ; }\n"
            "  chain gate {\n"
            "    type filter hook output priority 0 ; policy drop ;\n"
            f"{reset}"
            "    meta mark set ip saddr . ip daddr map @activated\n"
            "    ip saddr . ip daddr . meta mark @prepared accept\n"
            "  }\n"
            "}\n")


def prepare_batch(mark: int, timeout_ms: int) -> str:
    """The only write of a prepared key: ``create`` (NLM_F_EXCL), with its lifetime, before authority."""
    return f"create element inet heel_lease prepared {{ {TUPLE} . {mark:#010x} timeout {timeout_ms}ms }}\n"


def activate_batch(mark: int) -> str:
    """Activation writes only a reference into the timeout-free map; it carries no lifetime."""
    return (f"destroy element inet heel_lease activated {{ {TUPLE} }}\n"
            f"add element inet heel_lease activated {{ {TUPLE} : {mark:#010x} }}\n")


def readd_batch_informative(mark: int, timeout_ms: int) -> str:
    """A8 informative only: the non-EXCL re-add that the installer contract forbids."""
    return f"add element inet heel_lease prepared {{ {TUPLE} . {mark:#010x} timeout {timeout_ms}ms }}\n"


# N1 negative control: H1D's relative-TTL lease, a lifetime computed before a delayed write.
N1_TABLE = ("table inet heel_n1 {\n"
            "  set lease { type ipv4_addr . ipv4_addr ; flags timeout ; }\n"
            "  chain gate {\n"
            "    type filter hook output priority 0 ; policy drop ;\n"
            "    ip saddr . ip daddr @lease accept\n"
            "  }\n"
            "}\n")
N1_BATCH = f"add element inet heel_n1 lease {{ {TUPLE} timeout @TTL@ms }}\n"
CHURN_TABLE = "table inet heel_churn {\n  set churn { type ipv4_addr ; }\n}\n"


def meta_time_table(deadline_epoch_s: int) -> str:
    """B1 informative: an absolute CLOCK_REALTIME predicate (candidate B, H1DR section 4.6)."""
    stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(deadline_epoch_s))
    return ("table inet heel_meta_time {\n"
            f"  set pins {{ type ipv4_addr . ipv4_addr ; elements = {{ {TUPLE} }} ; }}\n"
            "  chain gate {\n"
            "    type filter hook output priority 0 ; policy drop ;\n"
            f'    ip saddr . ip daddr @pins meta time < "{stamp}" accept\n'
            "  }\n"
            "}\n")


class Marks:
    """Distinct nonzero 32-bit marks for one proof run, issued once each and never wrapped: the
    space is far larger than one run uses, and exhaustion fails closed. Not an H1A allocator."""

    def __init__(self, first: int = 0x00010001):
        self._next = first
        self.issued: set[int] = set()

    def fresh(self) -> int:
        mark = self._next
        if not 0 < mark <= 0xFFFFFFFF or mark in self.issued:
            raise RuntimeError("proof mark space exhausted")
        self._next += 1
        self.issued.add(mark)
        return mark


MARKS = Marks()
REUSE_PURPOSES = ("live_collision", "expired_recreate", "informative_readd")


def deliberate_reuse(mark: int, purpose: str, marks: Marks = MARKS) -> int:
    """The only way a key is written twice: a named collision, expired-key or informative control."""
    if mark not in marks.issued or purpose not in REUSE_PURPOSES:
        raise RuntimeError("reuse outside a named control")
    return mark


# ---------------------------------------------------------------------------------------------
# Readback parsers and error classes (raw tool output stays private; only these tokens escape).

_TIME_PART = re.compile(r"([0-9]+)(ms|d|h|m|s)")
_UNIT_MS = {"d": 86_400_000, "h": 3_600_000, "m": 60_000, "s": 1000, "ms": 1}
_MARK = r"(0x[0-9a-fA-F]+|[0-9]+)"
_ELEMENT = re.compile(re.escape(L_ADDR) + r" \. " + re.escape(R_ADDR) + r" \. " + _MARK
                      + r" timeout ([0-9dhms]+) expires ([0-9dhms]+)")
_ACTIVATED = re.compile(re.escape(L_ADDR) + r" \. " + re.escape(R_ADDR) + r" : " + _MARK)
NFT_ERRORS = (("File exists", "eexist"), ("No such file or directory", "enoent"), ("Operation not supported", "eopnotsupp"),
              ("Numerical result out of range", "erange"), ("Invalid argument", "einval"),
              ("Operation not permitted", "eperm"), ("Device or resource busy", "ebusy"), ("syntax error", "syntax_error"))


def parse_nft_time_ms(text: str) -> int | None:
    if not re.fullmatch(r"(?:[0-9]+(?:ms|d|h|m|s))+", text):
        return None
    return sum(int(number) * _UNIT_MS[unit] for number, unit in _TIME_PART.findall(text))


def _mark_value(text: str) -> int:
    return int(text, 16) if text.lower().startswith("0x") else int(text)


def parse_prepared(listing: str) -> dict[int, tuple[int, int]]:
    """mark -> (timeout_ms, expires_ms) for each live element of the fixed tuple."""
    elements = {}
    for mark, timeout, expires in _ELEMENT.findall(listing):
        timeout_ms, expires_ms = parse_nft_time_ms(timeout), parse_nft_time_ms(expires)
        if timeout_ms is not None and expires_ms is not None:
            elements[_mark_value(mark)] = (timeout_ms, expires_ms)
    return elements


def parse_activated(listing: str) -> list[int]:
    return [_mark_value(mark) for mark in _ACTIVATED.findall(listing)]


def classify_nft_error(stderr: str) -> str:
    for needle, token in NFT_ERRORS:
        if needle in stderr:
            return token
    return "other"


def parse_release(release: str) -> tuple[str, str]:
    """(bounded release token, major.minor) from ``uname -r``; anything else is ``unparsed``."""
    value = release.lower()
    match = re.fullmatch(r"([0-9]{1,3})\.([0-9]{1,3})\.[0-9]{1,4}(?:[-.+][a-z0-9.+-]{0,60})?", value)
    token = value if match and LAUNCHER._TOKEN.fullmatch(value) else "unparsed"
    return token, (f"{int(match.group(1))}.{int(match.group(2))}" if match else "unparsed")


# ---------------------------------------------------------------------------------------------
# Probes and the pure oracles (the dynamic cases and the mutant traces use the same functions).

@dataclass
class Probe:
    index: int
    t_before: int
    t_after: int
    admitted: bool  # sendto returned success: the output gate accepted it inside [t_before, t_after]
    error: str = "ok"
    recv_ns: int | None = None

    @property
    def delivered(self) -> bool:
        return self.recv_ns is not None

    @property
    def accepted(self) -> bool:
        return self.admitted or self.delivered


def admitted_after(probes: list[Probe], bound_ns: int) -> list[Probe]:
    """Probes accepted with their admission bracket wholly after ``bound_ns``."""
    return [probe for probe in probes if probe.accepted and probe.t_before > bound_ns]


def admitted_before(probes: list[Probe], bound_ns: int) -> list[Probe]:
    return [probe for probe in probes if probe.accepted and probe.t_after < bound_ns]


def inside(probes: list[Probe], start_ns: int, end_ns: int) -> list[Probe]:
    return [probe for probe in probes if probe.t_before >= start_ns and probe.t_after <= end_ns]


def anomalies(probes: list[Probe]) -> int:
    """Delivered although the sender saw a refusal: never possible for one gate on one path."""
    return sum(probe.delivered and not probe.admitted for probe in probes)


def live_delivery(probes: list[Probe], start_ns: int, end_ns: int, minimum: int) -> bool:
    """Attempted probes wholly inside a certainly-live interval: enough of them, >= 95 % admitted
    and delivered. Probes never attempted are not in the list, so they are never counted as loss."""
    window = inside(probes, start_ns, end_ns)
    return (len(window) >= minimum and 100 * sum(p.admitted for p in window) >= LIVE_PERCENT * len(window)
            and 100 * sum(p.delivered for p in window) >= LIVE_PERCENT * len(window))


def grade_hazard(probes: list[Probe], *, element_from_ns: int, deadline_bound_ns: int, minimum: int = 50) -> bool:
    """Negative control: nothing before the element exists, and the hazard shown after the deadline
    (a deny-all fixture fails this, so the control proves the fixture can see an open gate)."""
    return (not admitted_before(probes, element_from_ns) and len(admitted_after(probes, deadline_bound_ns)) >= minimum
            and anomalies(probes) == 0)


def grade_closed(window: list[Probe], control: list[Probe], *, control_from_ns: int, control_to_ns: int) -> bool:
    """Zero admissions over the whole window with no allowance, and a live positive control after it
    (so an always-drop fixture cannot pass a zero-traffic oracle)."""
    return (len(window) > 0 and not [p for p in window if p.accepted] and anomalies(window) == 0
            and live_delivery(control, control_from_ns, control_to_ns, minimum=10))


def grade_cutoff(probes: list[Probe], *, live_from_ns: int, live_to_ns: int, bound_ns: int, minimum: int) -> bool:
    return (live_delivery(probes, live_from_ns, live_to_ns, minimum) and not admitted_after(probes, bound_ns)
            and anomalies(probes) == 0)


def grade_renewal(probes: list[Probe], *, live_from_ns: int, live_to_ns: int, old_bound_ns: int, new_bound_ns: int,
                  minimum: int) -> bool:
    """No attempted probe lost across the swap, delivery past the old key's expiry, none past the new one's."""
    window = inside(probes, live_from_ns, live_to_ns)
    return (len(window) >= minimum and all(p.admitted and p.delivered for p in window)
            and len(admitted_after(probes, old_bound_ns)) >= 50 and not admitted_after(probes, new_bound_ns)
            and anomalies(probes) == 0)


def grade_revival(probes: list[Probe], *, live_to_ns: int, expired_bound_ns: int, recreate_from_ns: int,
                  recreate_to_ns: int, minimum: int = 50) -> bool:
    """N3 negative control: closed between expiry and recreation, then the stale reference revives."""
    gap = [p for p in probes if p.t_before > expired_bound_ns and p.t_after < recreate_from_ns]
    return (any(p.accepted for p in probes if p.t_after <= live_to_ns) and len(gap) >= 10
            and not [p for p in gap if p.accepted] and len(admitted_after(probes, recreate_to_ns)) >= minimum
            and anomalies(probes) == 0)


def ms_ceil(ns: int) -> int:
    return -(-ns // MS)


def ms_floor(ns: int) -> int:
    return ns // MS


def percentile(values: list[int], fraction: float) -> int:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(fraction * len(ordered)) - 1)]


# ---------------------------------------------------------------------------------------------
# Evidence: one closed-grammar record per dynamic case (the launcher re-sanitizes everything).

def record(case: str, ok: bool | None, ints: dict, tokens: dict) -> None:
    entry = {"case": case, "verdict": "info" if ok is None else ("pass" if ok else "fail"),
             "control": LAUNCHER.RECORD_CASES[case][1], "ints": dict(ints), "tokens": dict(tokens)}
    assert LAUNCHER.sanitize_record(entry) is not None, f"record {case} is outside the closed grammar"
    with open(os.environ[LAUNCHER.RECORDS_ENV], "a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")


# ---------------------------------------------------------------------------------------------
# Static source/config gates (run everywhere).

def _functions(source: str) -> dict[str, ast.FunctionDef]:
    return {node.name: node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef)}


def _calls(node: ast.AST, name: str) -> list[ast.Call]:
    return [call for call in ast.walk(node) if isinstance(call, ast.Call)
            and isinstance(call.func, ast.Name) and call.func.id == name]


def test_static_required_profile_cannot_skip():
    """One guarded skip path, unreachable with HEEL_REQUIRE_HOST_LEASE_PROOF=1, and every dynamic case
    passes through it before doing anything."""
    module = Path(__file__).read_text(encoding="utf-8")
    assert len(re.findall(r"^\s+pytest\.skip\(", module, re.M)) == 1
    assert "if REQUIRED:\n            pytest.fail(reason)\n        pytest.skip(reason)" in module
    for forbidden in ("x" + "fail", "skip" + "if", "importor" + "skip", "pytest.mark." + "skip"):
        assert forbidden not in module, forbidden
    for name, node in _functions(module).items():
        if name.startswith("test_") and not name.startswith("test_static_"):
            body = node.body[1:] if isinstance(node.body[0], ast.Expr) and isinstance(node.body[0].value, ast.Constant) else node.body
            first = body[0]
            assert (isinstance(first, ast.Expr) and isinstance(first.value, ast.Call)
                    and getattr(first.value.func, "id", None) == "_require_runtime"), name


def test_static_launcher_requires_every_case_function_and_record_in_this_module():
    functions = _functions(Path(__file__).read_text(encoding="utf-8"))
    cases = tuple(name for name in functions if name.startswith("test_"))
    assert cases == LAUNCHER.REQUIRED_CASES
    assert cases[-1] == "test_c1_no_owned_namespace_process_socket_or_link_survives"
    recorded = {}
    for name in cases:
        for call in _calls(functions[name], "record"):
            assert isinstance(call.args[0], ast.Constant), name
            assert call.args[0].value not in recorded, call.args[0].value
            recorded[call.args[0].value] = name
    assert recorded == {case: item[0] for case, item in LAUNCHER.RECORD_CASES.items()}
    assert {item[1] for item in LAUNCHER.RECORD_CASES.values()} <= {"provenance", "negative", "positive", "measurement",
                                                                    "informative", "peer", "cleanup"}
    assert [case for case, item in LAUNCHER.RECORD_CASES.items() if item[2] == "info"] == ["b1"]


def test_static_launcher_has_one_fixed_profile_fixed_budgets_and_no_inputs(tmp_path, capsys):
    source = LAUNCHER_FILE.read_text(encoding="utf-8")
    assert LAUNCHER.main(["--anything"]) == 2
    capsys.readouterr()
    assert "argparse" not in source and source.count("sys.argv") == 1 and "os.environ.get(\"RUNNER_TEMP\")" in source
    assert (LAUNCHER.LAUNCHER_SECONDS, LAUNCHER.TESTS_SECONDS, LAUNCHER.CLEANUP_RESERVE_SECONDS) == (1200, 600, 60)
    assert '["sudo", "-n", "--", sys.executable, "-I", str(Path(__file__).resolve())]' in source
    assert LAUNCHER.PROFILE == "lease-v1" and LAUNCHER.HOST_TOOLS == ("nft", "ip", "iptables-save")
    # The privileged child accepts exactly one request shape, from owned private scratch only.
    base = Path(os.path.realpath(tmp_path)) / "heel-host-lease-static"
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
    for mutation in ({"extra": 1}, {"schema": "other"}, {"uid": True}, {"uid": 0}, {"tests_seconds": 601},
                     {"tests_seconds": 5.0}, {"token": "0123456789ABCDEF0123456789ABCDEF"}, {"out": str(base)},
                     {"wheels": str(wheels) + "/"}, {"out": "relative/out"}):
        assert LAUNCHER.validated_request(json.dumps({**good, **mutation})) is None, mutation
    assert LAUNCHER.validated_request("[]") is None and LAUNCHER.validated_request("{") is None
    os.chmod(out, 0o770)
    assert LAUNCHER.validated_request(json.dumps(good)) is None
    os.chmod(out, 0o700)
    (wheels / "extra.whl").write_bytes(b"")
    assert LAUNCHER.validated_request(json.dumps(good)) is None


def test_static_pytest_closure_is_the_h0_locked_wheel_set_installed_offline():
    lock = json.loads(H0_LOCK.read_text(encoding="utf-8"))
    LAUNCHER.closure_matches_lock(lock)
    assert [item[0] for item in LAUNCHER.PYTEST_CLOSURE] == ["iniconfig", "packaging", "pluggy", "pygments", "pytest"]
    assert dict((item[0], item[1]) for item in LAUNCHER.PYTEST_CLOSURE)["pytest"] == LAUNCHER.PYTEST_VERSION
    assert LAUNCHER.PYTHON_VERSION == lock["python"]["version"]
    for item in LAUNCHER.PYTEST_CLOSURE:
        assert item[3].startswith("https://files.pythonhosted.org/") and item[3].endswith("/" + item[2])
        assert re.fullmatch(r"[0-9a-f]{64}", item[4])
    tampered = json.loads(json.dumps(lock))
    tampered["python"]["wheels"][-1]["sha256"] = "0" * 64
    with pytest.raises(LAUNCHER.ProofFailure):
        LAUNCHER.closure_matches_lock(tampered)
    source = LAUNCHER_FILE.read_text(encoding="utf-8")
    install = source[source.index("def install_closure"):source.index("def _write_out")]
    assert '"--no-index", "--no-deps"' in install and "hashlib.sha256(data).hexdigest() != digest" in install
    assert source.count('"pip"') == 1
    for module in (source, Path(__file__).read_text(encoding="utf-8")):
        for forbidden in ("apt" + "-get", "apt" + " install", "dn" + "f ", "systemc" + "tl", "modpr" + "obe", "pip" + " install"):
            assert forbidden not in module, forbidden


def _job_block(text: str, name: str) -> str:
    match = re.search(r"^  " + re.escape(name) + r":\n(?:.*\n)*?(?=^  [A-Za-z0-9_-]+:\n|\Z)", text, re.M)
    assert match is not None, name
    lines = match.group(0).split("\n")
    while lines and (lines[-1].strip() == "" or lines[-1].lstrip().startswith("#")):
        lines.pop()
    return "\n".join(lines) + "\n"


def test_static_workflow_existing_jobs_match_the_recorded_f04ab70_baseline():
    data = WORKFLOW.read_bytes()
    assert hashlib.sha256(data[:BASELINE_WORKFLOW_BYTES]).hexdigest() == BASELINE_WORKFLOW_SHA256
    assert data[BASELINE_WORKFLOW_BYTES:].startswith(b"\n  host-lease-feasibility:\n")
    text = data.decode("utf-8")
    for name, digest in BASELINE_JOB_SHA256.items():
        assert hashlib.sha256(_job_block(text, name).encode()).hexdigest() == digest, name


def test_static_workflow_lease_job_is_manual_literal_branch_read_only_and_pinned():
    text = WORKFLOW.read_text(encoding="utf-8")
    baseline, job = text[:BASELINE_WORKFLOW_BYTES], _job_block(text, "host-lease-feasibility")
    assert re.findall(r"^  ([A-Za-z0-9_-]+):\n", text, re.M).count("host-lease-feasibility") == 1
    assert "\npermissions: {}\n" in text and "pull_request_target" not in text and "secrets." not in text
    assert "inputs:" not in text and "workflow_dispatch: {}" in text
    for uses in re.findall(r"uses: (\S+)", text):
        assert re.fullmatch(r"[a-z-]+/[a-z-]+(?:/[a-z-]+)?@[0-9a-f]{40}", uses), uses
    assert set(re.findall(r"uses: (\S+)", job)) <= set(re.findall(r"uses: (\S+)", baseline))
    assert re.findall(r"^  ([A-Za-z0-9_-]+):\n", job, re.M) == ["host-lease-feasibility"]
    assert LEASE_BRANCH_GATE in job and "runs-on: ubuntu-24.04" in job
    assert re.search(r"permissions:\n      contents: read\n    concurrency:", job)
    for forbidden in ("write", "id-token", "environment:", "cache", "env:", "secrets", "pull_request", "github.token"):
        assert forbidden not in job, forbidden
    assert job.count("timeout-minutes: 25") == 1 and job.count("timeout-minutes: 20") == 1
    assert "ref: ${{ github.sha }}" in job and "persist-credentials: false" in job and 'python-version: "3.13.5"' in job
    assert re.findall(r"^\s+run: (.+)$", job, re.M) == ["python scripts/host_lease_feasibility.py"]
    assert tuple(re.findall(r"^\s+host-lease-feasibility/(\S+)$", job, re.M)) == LAUNCHER.ARTIFACT_FILES
    assert "retention-days: 3" in job and "if-no-files-found: error" in job and "if: always()" in job
    assert LAUNCHER.LAUNCHER_SECONDS == 20 * 60


def _root_reads(source: str) -> set[str]:
    """Every string-literal path joined onto ROOT in ``source``."""
    return {"/".join(re.findall(r'"([^"\n]+)"', chain)) for chain in re.findall(r'ROOT((?:\s*/\s*"[^"\n]+")+)', source)}


def test_static_launcher_stages_every_path_the_module_reads(tmp_path):
    """The child copies a fixed file list; everything this module and the launcher read under ROOT is
    in it, and the static selection passes from an exact staged copy (no git, no other files)."""
    module = Path(__file__).read_text(encoding="utf-8")
    reads = _root_reads(module) | (_root_reads(LAUNCHER_FILE.read_text(encoding="utf-8")) - {"host-lease-feasibility"})
    reads.discard(".git")  # only probed below, to tell the checkout from the staged copy
    assert reads <= set(LAUNCHER.STAGE_FILES), sorted(reads - set(LAUNCHER.STAGE_FILES))
    assert {"tests/linux/__init__.py", "tests/linux/test_host_lease_primitive.py"} <= set(LAUNCHER.STAGE_FILES)
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


DESIGN_SHAPE = """
table inet heel_lease {
  set prepared  { type ipv4_addr . ipv4_addr . mark ; flags timeout ; }
  map activated { type ipv4_addr . ipv4_addr : mark ; }
  chain gate {
    type filter hook output priority 0 ; policy drop ;
    meta mark set 0
    meta mark set ip saddr . ip daddr map @activated
    ip saddr . ip daddr . meta mark @prepared accept
  }
}
"""


def _squash(text: str) -> str:
    return " ".join(text.split())


def test_static_gate_batches_never_rewrite_a_prepared_key_and_activation_carries_no_lifetime():
    assert _squash(gate_table()) == _squash(DESIGN_SHAPE)
    assert gate_table(mark_reset=False) == gate_table().replace("    meta mark set 0\n", "")
    assert gate_table(gc_interval_hour=True) == gate_table().replace("flags timeout ; }", "flags timeout ; gc-interval 1h ; }")
    prepare = prepare_batch(0x00010001, 2850)
    assert prepare == ("create element inet heel_lease prepared "
                       "{ 198.51.100.10 . 203.0.113.10 . 0x00010001 timeout 2850ms }\n")
    activate = activate_batch(0x00010001)
    assert activate.splitlines() == ["destroy element inet heel_lease activated { 198.51.100.10 . 203.0.113.10 }",
                                     "add element inet heel_lease activated { 198.51.100.10 . 203.0.113.10 : 0x00010001 }"]
    for word in ("timeout", "expires", "prepared", "create"):
        assert word not in activate, word
    module = Path(__file__).read_text(encoding="utf-8")
    functions = _functions(module)
    needle = "add element inet heel_lease " + "prepared"
    assert module.count(needle) == 1 and needle in ast.get_source_segment(module, functions["readd_batch_informative"])
    functions = {name: node for name, node in functions.items() if not name.startswith("test_static_")}
    users = {name for name, node in functions.items() if _calls(node, "readd_batch_informative")}
    assert users == {"test_a8_reference_to_expired_key_does_not_revive_and_live_readd_semantics_recorded"}
    assert {name for name, node in functions.items() if "N1_BATCH" in ast.get_source_segment(module, node)} == {
        "test_n1_relative_ttl_post_delete_admits_packets_after_deadline_when_installer_dies"}
    no_reset = {name for name, node in functions.items()
                if any(k.arg == "mark_reset" for call in _calls(node, "gate_table") for k in call.keywords)}
    assert no_reset == {"test_n2_gate_without_mark_reset_admits_a_carried_mark"}


def test_static_marks_are_distinct_nonzero_and_reuse_is_confined_to_named_controls():
    marks = Marks()
    issued = [marks.fresh() for _ in range(2000)]
    assert len(set(issued)) == 2000 and all(0 < mark <= 0xFFFFFFFF for mark in issued) and issued == sorted(issued)
    edge = Marks(first=0xFFFFFFFF)
    assert edge.fresh() == 0xFFFFFFFF
    with pytest.raises(RuntimeError):
        edge.fresh()  # exhaustion fails closed: no wrap to a previously issued value
    with pytest.raises(RuntimeError):
        Marks(first=0).fresh()
    with pytest.raises(RuntimeError):
        deliberate_reuse(0x7FFFFFFF, "live_collision", marks)
    with pytest.raises(RuntimeError):
        deliberate_reuse(issued[0], "convenience", marks)
    module = Path(__file__).read_text(encoding="utf-8")
    allowed = {"test_n3_recreating_an_expired_key_revives_a_stale_reference": {"expired_recreate"},
               "test_a7_live_create_collision_fails_closed_and_expired_key_accepts_fresh_create": {"live_collision", "expired_recreate"},
               "test_a8_reference_to_expired_key_does_not_revive_and_live_readd_semantics_recorded": {"informative_readd"},
               "_compatibility_self_test": {"live_collision", "expired_recreate"}}
    seen = {}
    for name, node in _functions(module).items():
        for call in _calls(node, "deliberate_reuse"):
            if name == "test_static_marks_are_distinct_nonzero_and_reuse_is_confined_to_named_controls":
                continue
            assert isinstance(call.args[1], ast.Constant), name
            seen.setdefault(name, set()).add(call.args[1].value)
    assert seen == allowed


def _trace(start_ns: int, count: int, admit, *, delay_ns: int = 200_000) -> list[Probe]:
    """A synthetic probe trace: ``admit(t_before)`` decides each verdict; delivery follows admission."""
    probes = []
    for index in range(count):
        t_before = start_ns + index * PROBE_INTERVAL_NS
        admitted = bool(admit(t_before))
        probes.append(Probe(index, t_before, t_before + 50_000, admitted, "ok" if admitted else "eperm",
                            t_before + delay_ns if admitted else None))
    return probes


def test_static_oracles_reject_always_drop_stale_allow_and_rounded_violation_traces():
    """Mutant traces against the same oracles the Linux cases use. The kernel mutants themselves
    (a gate that always drops, a stale activation that admits) cannot run on macOS; these traces
    show which oracle each would fail, and the required Linux cases measure the real behaviour."""
    tick = 4 * MS
    # A5/A9 cutoff: prepared at 0 for 3000 ms, activated at 20 ms.
    live_from, live_to, bound = 20 * MS, 3000 * MS - 2 * tick, 3000 * MS + tick
    honest = _trace(0, 600, lambda t: 20 * MS <= t < 2999 * MS)
    assert grade_cutoff(honest, live_from_ns=live_from, live_to_ns=live_to, bound_ns=bound, minimum=200)
    always_drop = _trace(0, 600, lambda t: False)
    assert not grade_cutoff(always_drop, live_from_ns=live_from, live_to_ns=live_to, bound_ns=bound, minimum=200)
    stale_allow = _trace(0, 600, lambda t: t >= 20 * MS)
    assert not grade_cutoff(stale_allow, live_from_ns=live_from, live_to_ns=live_to, bound_ns=bound, minimum=200)
    # A violation 0.4 ms after the bound fails on nanoseconds; a floored millisecond would hide it,
    # so published lateness is always rounded up.
    rounded = honest + [Probe(600, bound + 400_000, bound + 450_000, True, "ok", bound + 600_000)]
    assert not grade_cutoff(rounded, live_from_ns=live_from, live_to_ns=live_to, bound_ns=bound, minimum=200)
    assert ms_floor(400_000) == 0 and ms_ceil(400_000) == 1
    # A queued old datagram (admitted early, received late) is not new authority.
    queued = [Probe(p.index, p.t_before, p.t_after, p.admitted, p.error, p.recv_ns) for p in honest]
    queued[290].recv_ns = bound + 500 * MS
    assert grade_cutoff(queued, live_from_ns=live_from, live_to_ns=live_to, bound_ns=bound, minimum=200)
    # Probes never attempted are absent, not lost.
    unsent = [p for p in honest if not 100 <= p.index < 110]
    assert grade_cutoff(unsent, live_from_ns=live_from, live_to_ns=live_to, bound_ns=bound, minimum=200)
    # Admitted but never delivered inside the live interval is loss.
    lossy = [Probe(p.index, p.t_before, p.t_after, p.admitted, p.error, None if p.index % 10 == 0 else p.recv_ns)
             for p in honest]
    assert not grade_cutoff(lossy, live_from_ns=live_from, live_to_ns=live_to, bound_ns=bound, minimum=200)
    # A3: deny-all cannot pass the positive oracle.
    assert not live_delivery(always_drop, live_from, live_to, minimum=150)
    # A4/A8/A13: zero over the window plus a live control; stale-allow and always-drop both fail.
    window = _trace(0, 1000, lambda t: False)
    control = _trace(10_100 * MS, 30, lambda t: True)
    assert grade_closed(window, control, control_from_ns=10_100 * MS, control_to_ns=10_500 * MS)
    assert not grade_closed(_trace(0, 1000, lambda t: t >= 5100 * MS), control, control_from_ns=10_100 * MS,
                            control_to_ns=10_500 * MS)
    assert not grade_closed(window, _trace(10_100 * MS, 30, lambda t: False), control_from_ns=10_100 * MS,
                            control_to_ns=10_500 * MS)
    assert not grade_closed([], control, control_from_ns=10_100 * MS, control_to_ns=10_500 * MS)
    # N1: the hazard trace passes the negative control; a deny-all fixture does not.
    hazard = _trace(0, 1200, lambda t: 7000 * MS <= t < 9000 * MS)
    assert grade_hazard(hazard, element_from_ns=7000 * MS, deadline_bound_ns=3000 * MS + tick)
    assert not grade_hazard(_trace(0, 1200, lambda t: False), element_from_ns=7000 * MS, deadline_bound_ns=3000 * MS + tick)
    assert not grade_hazard(_trace(0, 1200, lambda t: True), element_from_ns=7000 * MS, deadline_bound_ns=3000 * MS + tick)
    # A6 renewal: honest passes; a gap at the swap, a cutoff at the old expiry or a late admit fail.
    renewal = dict(live_from_ns=20 * MS, live_to_ns=4000 * MS - 2 * tick, old_bound_ns=3000 * MS + tick,
                   new_bound_ns=4020 * MS + tick, minimum=300)
    assert grade_renewal(_trace(0, 500, lambda t: 20 * MS <= t < 4000 * MS), **renewal)
    assert not grade_renewal(_trace(0, 500, lambda t: 20 * MS <= t < 4000 * MS and not 1000 * MS <= t < 1020 * MS), **renewal)
    assert not grade_renewal(_trace(0, 500, lambda t: 20 * MS <= t < 3000 * MS), **renewal)
    assert not grade_renewal(_trace(0, 500, lambda t: t >= 20 * MS), **renewal)
    # N3 revival: honest passes; no revival or an open gap fails.
    revival = dict(live_to_ns=500 * MS - 2 * tick, expired_bound_ns=500 * MS + tick, recreate_from_ns=1200 * MS,
                   recreate_to_ns=1210 * MS)
    assert grade_revival(_trace(0, 300, lambda t: t < 495 * MS or t > 1210 * MS), **revival)
    assert not grade_revival(_trace(0, 300, lambda t: t < 495 * MS), **revival)
    assert not grade_revival(_trace(0, 300, lambda t: True), **revival)
    # One gate on one path cannot deliver what the sender saw refused.
    assert anomalies([Probe(0, 0, 1, False, "eperm", 5)]) == 1


def test_static_evidence_sanitizer_keeps_only_the_closed_grammar(tmp_path):
    good = {"case": "a5", "verdict": "pass", "control": "positive", "ints": {"last_margin_ms": 3, "admitted": 280},
            "tokens": {"installer": "killed"}}
    assert LAUNCHER.sanitize_record(good) == good
    bad = [{**good, "extra": 1}, {**good, "case": "zz"}, {**good, "control": "negative"}, {**good, "verdict": "PASS"},
           {**good, "ints": {"flag": True}}, {**good, "ints": {"x": 1.5}}, {**good, "ints": {"x": 10 ** 13}},
           {**good, "ints": {"X": 1}}, {**good, "tokens": {"path": "/tmp/x"}}, {**good, "tokens": {"t": "Traceback"}},
           {**good, "tokens": {"t": "a b"}}, {**good, "tokens": {"t": {"nested": "x"}}},
           {**good, "ints": {f"k{i}": i for i in range(65)}}, {**good, "tokens": {"t": "x" * 81}}, "not a dict"]
    for entry in bad:
        assert LAUNCHER.sanitize_record(entry) is None, entry
    raw = tmp_path / "records.raw.jsonl"
    raw.write_text(json.dumps(good) + "\nnot json\n" + '{"case": NaN}\n', encoding="utf-8")
    assert LAUNCHER.sanitize_records(raw) == ([good], 2)
    public = tmp_path / "public"
    public.mkdir()
    (public / "a.txt").write_text("result PASS\n")
    (public / "b.txt").write_text("token 00112233445566778899aabbccddeeff\n")
    (public / "c.txt").write_text("Error: Could not process rule\n")
    (public / "d.txt").write_text("at /tmp/heel-lease/src\n")
    assert LAUNCHER.artifact_scan(public, "00112233445566778899aabbccddeeff") == ["b.txt", "c.txt", "d.txt"]
    # The acceptance rule: PASS, INCOMPLETE only for an unsupported profile, otherwise FAIL.
    records = [{"case": case, "verdict": item[2], "control": item[1], "ints": {}, "tokens": {}}
               for case, item in LAUNCHER.RECORD_CASES.items()]
    by = {r["case"]: r for r in records}
    by["a12"]["tokens"] = {"kernel_major_minor": "7.0", "nft_version": "1.0.9", "selftest": "pass"}
    by["a12"]["ints"] = {"config_hz": 1000}
    by["a8"]["tokens"] = {"readd_observation": "refresh"}
    junit = {"collected": len(LAUNCHER.REQUIRED_CASES), "passed": len(LAUNCHER.REQUIRED_CASES), "failed": 0, "errors": 0,
             "skipped": 0, "case_functions": list(LAUNCHER.REQUIRED_CASES), "failing": [], "failure_locators": []}
    cleanup, inner = {"host_fingerprints_unchanged": True}, {"pytest_exit": 0, "leftover_processes": 0}
    assert LAUNCHER.evaluate(junit, records, 0, cleanup, inner, 0)["result"] == "PASS"
    by["a12"]["ints"] = {}
    assert LAUNCHER.evaluate(junit, records, 0, cleanup, inner, 0)["result"] == "INCOMPLETE"
    by["a12"]["ints"] = {"config_hz": 1000}
    skipped = {**junit, "passed": junit["passed"] - 1, "skipped": 1}
    assert LAUNCHER.evaluate(skipped, records, 0, cleanup, inner, 0)["result"] == "FAIL"
    assert LAUNCHER.evaluate(junit, records, 1, cleanup, inner, 0)["result"] == "FAIL"
    assert LAUNCHER.evaluate(junit, records[1:], 0, cleanup, inner, 0)["result"] == "FAIL"
    assert LAUNCHER.evaluate(junit, records + records[:1], 0, cleanup, inner, 0)["result"] == "FAIL"
    assert LAUNCHER.evaluate(junit, records, 0, {"host_fingerprints_unchanged": False}, inner, 0)["result"] == "FAIL"
    assert LAUNCHER.evaluate(junit, records, 0, cleanup, {**inner, "leftover_processes": 1}, 0)["result"] == "FAIL"
    by["n1"]["verdict"] = "fail"
    assert LAUNCHER.evaluate(junit, records, 0, cleanup, inner, 0)["result"] == "FAIL"
    lines = LAUNCHER.version_lines(by, "pinned") + LAUNCHER.report_lines({"result": "PASS", "records": records}, None, cleanup)
    assert all(re.fullmatch(r"[a-z0-9_]+ [A-Za-z0-9_.:/ -]*", line) for line in lines), lines


LISTING = """table inet heel_lease {
	set prepared {
		type ipv4_addr . ipv4_addr . mark
		flags timeout
		elements = { 198.51.100.10 . 203.0.113.10 . 0x00010001 timeout 3s expires 2s996ms,
			     198.51.100.10 . 203.0.113.10 . 0x00010002 timeout 2s848ms expires 812ms }
	}
}
"""


def test_static_nft_readback_parsers_and_error_classes():
    assert [parse_nft_time_ms(text) for text in ("3s", "2s850ms", "1m30s", "850ms", "1d", "1h2m3s4ms")] == [
        3000, 2850, 90_000, 850, 86_400_000, 3_723_004]
    assert [parse_nft_time_ms(text) for text in ("", "5x", "ms", "3 s")] == [None, None, None, None]
    assert parse_prepared(LISTING) == {0x00010001: (3000, 2996), 0x00010002: (2848, 812)}
    assert parse_prepared("elements = { 198.51.100.10 . 203.0.113.10 . 65539 timeout 1s expires 1s }") == {65539: (1000, 1000)}
    assert parse_activated("elements = { 198.51.100.10 . 203.0.113.10 : 0x00010003 }") == [0x00010003]
    assert parse_activated("map activated {\n}\n") == []
    assert classify_nft_error("Error: Could not process rule: File exists\n") == "eexist"
    assert classify_nft_error("Error: syntax error, unexpected junk\n") == "syntax_error"
    assert classify_nft_error("Error: Could not process rule: Operation not supported\n") == "eopnotsupp"
    assert classify_nft_error("something new") == "other"
    assert parse_release("7.0.0-1017-azure") == ("7.0.0-1017-azure", "7.0")
    assert parse_release("6.17.0-1022-azure") == ("6.17.0-1022-azure", "6.17")
    assert parse_release("6.8.0-45-generic") == ("6.8.0-45-generic", "6.8")
    assert parse_release("weird release") == ("unparsed", "unparsed")


def test_static_kernel_profile_needs_tag_nft_hz_selftest_and_matching_readd_semantics():
    good = {"kernel_major_minor": "7.0", "nft_version": "1.0.9", "config_hz": 1000, "selftest": "pass",
            "readd_observation": "refresh"}
    assert LAUNCHER.kernel_profile(good) == ("pinned", [])
    assert LAUNCHER.kernel_profile({**good, "kernel_major_minor": "6.17", "config_hz": 250}) == ("pinned", [])
    assert LAUNCHER.kernel_profile({**good, "kernel_major_minor": "6.8", "readd_observation": "noop"}) == ("pinned", [])
    for change, reason in (({"kernel_major_minor": "6.8"}, "readd_semantics_differ_from_source_tag"),
                           ({"kernel_major_minor": "6.11"}, "kernel_outside_pinned_tags"),
                           ({"nft_version": "1.1.0"}, "nft_outside_pinned_release"),
                           ({"config_hz": None}, "config_hz_unavailable_or_unsupported"),
                           ({"config_hz": 300}, "config_hz_unavailable_or_unsupported"),
                           ({"selftest": "fail"}, "compatibility_self_test_failed"),
                           ({"readd_observation": "error"}, "readd_semantics_differ_from_source_tag")):
        profile, reasons = LAUNCHER.kernel_profile({**good, **change})
        assert profile == "unpinned" and reason in reasons, change


def test_static_peer_cases_keep_production_permissions_outside_the_labelled_seam():
    module = Path(__file__).read_text(encoding="utf-8")
    functions = _functions(module)
    assert "os.umask(0o177 if permission == \"private\" else 0o111)" in PEER
    seam_users = {name for name, node in functions.items()
                  if not name.startswith("test_static_") and '"seam"' in ast.get_source_segment(module, node)}
    assert seam_users == {"test_p2_checking_server_in_a_user_namespace_that_cannot_map_the_client_sees_overflowuid"}
    p2 = ast.get_source_segment(module, functions["test_p2_checking_server_in_a_user_namespace_that_cannot_map_the_client_sees_overflowuid"])
    assert '"seam": "permissive_socket_converse_only"' in p2
    for name in ("test_p1_unix_peercred_is_mutual_under_the_production_permissions",
                 "test_p3_server_in_a_child_pid_namespace_sees_the_root_uid_with_pid_zero"):
        body = ast.get_source_segment(module, functions[name])
        assert '"private"' in body and "_production_socket(" in body, name
    # No acceptance rule of the form "peer pid must be nonzero" exists in this proof: P3 records the
    # pid-0 view as a fact the H1A design must account for.
    assert "pid_nonzero_rule_rejects_this_topology" in ast.get_source_segment(
        module, functions["test_p3_server_in_a_child_pid_namespace_sees_the_root_uid_with_pid_zero"])
    assert ("os.chmod(" + "path") not in module and ("os.chmod(" + "socket") not in module


def test_static_doc_names_every_case_and_the_limits():
    doc = DOC.read_text(encoding="utf-8")
    for case in LAUNCHER.RECORD_CASES:
        assert f"**{case.upper()}**" in doc, case
    for phrase in ("INCOMPLETE", "kernel_profile", "t_before", "SEAM-PERMISSIVE-SOCKET", "pid 0", "not an H1A allocator",
                   "NOT RUN", "python scripts/host_lease_feasibility.py", "no allowance"):
        assert phrase in doc, phrase


# ---------------------------------------------------------------------------------------------
# Runtime guard (the single skip path).

def _runtime_unavailable_reason() -> str | None:
    """Why the dynamic profile cannot run here, or None inside the fixed launcher's namespaces."""
    if not sys.platform.startswith("linux"):
        return "requires the fixed host-lease launcher on Linux"
    if sys.version_info < (3, 12) or not hasattr(os, "setns") or not hasattr(os, "unshare"):
        return "requires the launcher's pinned Python with namespace support"
    if os.geteuid() != 0:
        return "requires the launcher's isolated namespace driver"
    if not all(os.environ.get(name) for name in (LAUNCHER.RECORDS_ENV, LAUNCHER.WORK_ENV, LAUNCHER.TOKEN_ENV)):
        return "requires the fixed host-lease launcher environment"
    if [name for _index, name in socket.if_nameindex() if name != "lo" and not re.fullmatch(r"hl[0-9]+[ab]", name)]:
        return "refuses to run outside the launcher's loopback-only namespace"
    import shutil

    if [tool for tool in ("nft", "ip") if shutil.which(tool, path=LAUNCHER.FIXED_PATH) is None]:
        return "requires nft and ip on the fixed PATH"
    return None


def _require_runtime() -> None:
    reason = _runtime_unavailable_reason()
    if reason is not None:
        if REQUIRED:
            pytest.fail(reason)
        pytest.skip(reason)


def _work() -> Path:
    return Path(os.environ[LAUNCHER.WORK_ENV])


def _run_token() -> bytes:
    value = os.environ.get(LAUNCHER.TOKEN_ENV, "")
    return bytes.fromhex(value) if re.fullmatch(r"[0-9a-f]{32}", value) else os.urandom(16)


TOKEN = _run_token()


def sleep_until(target_ns: int) -> None:
    delay = target_ns - time.monotonic_ns()
    if delay > 0:
        time.sleep(delay / 1e9)


# ---------------------------------------------------------------------------------------------
# Fixed child programs (no caller-supplied code; argv is fixed by the cases).

HOLDER = "import json, sys\nprint(json.dumps({'event': 'ready'}), flush=True)\nsys.stdin.read()\n"

INSTALLER = r'''
import json, subprocess, sys, time
def say(**fields):
    sys.stdout.write(json.dumps(fields) + "\n")
    sys.stdout.flush()
say(event="started")
config = json.loads(sys.stdin.readline())
text = config["batch"]
if config["deadline_ns"] is not None:
    t_pre = time.monotonic_ns()
    ttl_ms = (config["deadline_ns"] - t_pre) // 1000000
    text = text.replace("@TTL@", str(ttl_ms))
    say(event="computed", t_pre=t_pre, ttl_ms=ttl_ms)
with open(config["path"], "w") as handle:
    handle.write(text)
say(event="barrier", t=time.monotonic_ns())
if sys.stdin.readline().strip() != "release":
    sys.exit(3)
t_pp = time.monotonic_ns()
completed = subprocess.run(["nft", "-f", config["path"]], capture_output=True, text=True)
t_pq = time.monotonic_ns()
say(event="committed", rc=completed.returncode, t_pp=t_pp, t_pq=t_pq, stderr=completed.stderr[-400:])
sys.stdin.readline()
'''

CHURN = r'''
import json, select, subprocess, sys, time
path = sys.argv[1]
def say(**fields):
    sys.stdout.write(json.dumps(fields) + "\n")
    sys.stdout.flush()
count = failures = 0
first = last = None
say(event="started")
while count < 5000:
    if count >= 200 and select.select([sys.stdin], [], [], 0)[0]:
        break
    verb = "add" if count % 2 == 0 else "delete"
    with open(path, "w") as handle:
        handle.write("%s element inet heel_churn churn { 10.200.%d.%d }\n" % (verb, count // 500 % 250, count // 2 % 250 + 1))
    started = time.monotonic_ns()
    failures += subprocess.run(["nft", "-f", path], capture_output=True).returncode != 0
    first = started if first is None else first
    last = time.monotonic_ns()
    count += 1
    if count == 1:
        say(event="running")
say(event="done", count=count, failures=failures, first=first, last=last)
sys.stdin.readline()
'''

PEER = r'''
import json, os, socket, struct, sys
role, mode, uid, path, permission = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5]
CLONE_NEWUSER, CLONE_NEWPID = 0x10000000, 0x20000000
def say(**fields):
    sys.stdout.write(json.dumps(fields) + "\n")
    sys.stdout.flush()
def creds(sock):
    pid, peer_uid, gid = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    return {"pid": pid, "uid": peer_uid, "gid": gid}
if mode == "pidns":
    os.unshare(CLONE_NEWPID)
    child = os.fork()
    if child:
        say(event="forked", outer_pid=child)
        _pid, status = os.waitpid(child, 0)
        os._exit(0 if os.waitstatus_to_exitcode(status) == 0 else 1)
if mode == "userns":
    os.unshare(CLONE_NEWUSER)
    say(event="unshared", pid=os.getpid())
    if sys.stdin.readline().strip() != "mapped":
        os._exit(3)
    os.setgroups([])
    os.setresgid(0, 0, 0)
    os.setresuid(0, 0, 0)
else:
    os.setgroups([])
    os.setresgid(uid, uid, uid)
    os.setresuid(uid, uid, uid)
if role == "server":
    os.umask(0o177 if permission == "private" else 0o111)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(path)
    server.listen(1)
    server.settimeout(30)
    say(event="listening", pid=os.getpid(), uid=os.getuid())
    connection, _address = server.accept()
    say(event="peer", **creds(connection))
    connection.settimeout(30)
    connection.recv(1)
    connection.close()
    server.close()
else:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(30)
    try:
        client.connect(path)
    except PermissionError:
        say(event="refused", reason="eacces")
        sys.exit(0)
    except OSError:
        say(event="refused", reason="oserror")
        sys.exit(0)
    say(event="peer", **creds(client))
    client.close()
'''


CHILDREN: list = []
OPEN_PAIRS: set = set()
COUNTERS = {"pairs": 0, "children": 0, "sockets": 0}
SOCKETS: list = []


class Child:
    """One fixed child program speaking one JSON object per line on stdout."""

    def __init__(self, program: str, argv: tuple = (), *, preexec=None):
        self.process = subprocess.Popen([sys.executable, "-I", "-c", program, *argv], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=LAUNCHER._env(),
                                        preexec_fn=preexec, close_fds=True, text=True, bufsize=1)
        self.pid = self.process.pid
        self.events: queue.Queue = queue.Queue()
        self.backlog: list[dict] = []
        self.reader = threading.Thread(target=self._pump, daemon=True)
        self.reader.start()
        CHILDREN.append(self)
        COUNTERS["children"] += 1

    def _pump(self) -> None:
        with contextlib.suppress(OSError, ValueError):
            for line in self.process.stdout:
                try:
                    event = json.loads(line)
                except ValueError:
                    event = None
                self.events.put(event if isinstance(event, dict) else {"event": "garbled"})
        self.events.put({"event": "eof"})

    def expect(self, name: str, timeout: float = 30.0) -> dict:
        for index, event in enumerate(self.backlog):
            if event.get("event") == name:
                return self.backlog.pop(index)
        deadline = time.monotonic() + timeout
        while True:
            event = self.events.get(timeout=max(0.01, deadline - time.monotonic()))
            if event.get("event") == name:
                return event
            if event.get("event") in ("eof", "garbled"):
                raise AssertionError(f"fixed child ended before its {name} event")
            self.backlog.append(event)

    def send(self, line: str) -> None:
        self.process.stdin.write(line + "\n")
        self.process.stdin.flush()

    def kill(self) -> int | None:
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGKILL)
        with contextlib.suppress(subprocess.TimeoutExpired):
            self.process.wait(10)
        self.reader.join(5)
        for stream in (self.process.stdin, self.process.stdout):
            with contextlib.suppress(OSError, ValueError):
                stream.close()
        return self.process.returncode

    def wait(self, timeout: float = 30.0) -> int | None:
        with contextlib.suppress(subprocess.TimeoutExpired):
            self.process.wait(timeout)
        return self.kill()


def _in_netns(fd: int, function):
    """Run ``function`` on a fresh thread that has entered one inner network namespace (setns is per
    thread for CLONE_NEWNET); the socket it returns stays bound to that namespace."""
    result: dict = {}

    def run() -> None:
        try:
            os.setns(fd, CLONE_NEWNET)
            result["value"] = function()
        except BaseException as error:  # noqa: BLE001 - re-raised on the caller's thread
            result["error"] = error

    thread = threading.Thread(target=run)
    thread.start()
    thread.join(20)
    if "error" in result:
        raise result["error"]
    return result["value"]


@dataclass
class NftResult:
    rc: int
    t_before: int
    t_after: int
    error: str

    @property
    def ok(self) -> bool:
        return self.rc == 0


class Pair:
    """Two fresh inner network namespaces, L and R, joined by one veth with fixed MACs, /32 routes and
    permanent neighbours (no ARP timing in the measurements). Nothing is added to the outer
    namespace except the transient veth before it moves."""

    def __init__(self, work: Path):
        COUNTERS["pairs"] += 1
        self.n = COUNTERS["pairs"]
        self.dir = work / f"pair{self.n}"
        self.dir.mkdir(mode=0o700)
        self.links = (f"hl{self.n}a", f"hl{self.n}b")
        self.holders: dict = {}
        self.fds: dict = {}
        self.children: list = []
        self.sockets: list = []
        self.writes: list = []
        self.batches = 0
        OPEN_PAIRS.add(self)
        try:
            for side in ("l", "r"):
                holder = Child(HOLDER, preexec=lambda: os.unshare(CLONE_NEWNET))
                self.holders[side] = holder
                holder.expect("ready")
                self.fds[side] = os.open(f"/proc/{holder.pid}/ns/net", os.O_RDONLY | os.O_CLOEXEC)
            self._wire()
        except BaseException:
            self.close()
            raise

    def run(self, side: str | None, argv: list[str], timeout: float = 30.0) -> subprocess.CompletedProcess:
        fd = None if side is None else self.fds[side]
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=LAUNCHER._env(),
                              preexec_fn=None if fd is None else (lambda: os.setns(fd, CLONE_NEWNET)))  # noqa: PLW1509

    def ip(self, side: str | None, *arguments: str) -> None:
        completed = self.run(side, ["ip", *arguments])
        assert completed.returncode == 0, f"ip {arguments[0]} {arguments[1]} failed in the proof fixture"

    def _wire(self) -> None:
        a, b = self.links
        mac = {"l": "02:48:31:%02x:%02x:0a" % (self.n >> 8 & 255, self.n & 255),
               "r": "02:48:31:%02x:%02x:0b" % (self.n >> 8 & 255, self.n & 255)}
        self.ip(None, "link", "add", a, "address", mac["l"], "type", "veth", "peer", "name", b, "address", mac["r"])
        self.ip(None, "link", "set", a, "netns", str(self.holders["l"].pid))
        self.ip(None, "link", "set", b, "netns", str(self.holders["r"].pid))
        plan = (("l", a, L_ADDR, R_ADDR, mac["r"]), ("r", b, R_ADDR, L_ADDR, mac["l"]))
        for side, device, mine, _peer, _peer_mac in plan:
            self.ip(side, "link", "set", "lo", "up")
            self.ip(side, "addr", "add", f"{mine}/32", "dev", device)
            self.ip(side, "link", "set", device, "up")
        for side, device, mine, peer, peer_mac in plan:
            self.ip(side, "route", "add", f"{peer}/32", "dev", device, "src", mine)
            self.ip(side, "neigh", "replace", peer, "lladdr", peer_mac, "dev", device, "nud", "permanent")

    def nft(self, text: str, *, kind: str = "write") -> NftResult:
        """One ``nft -f`` transaction in L, bracketed by CLOCK_MONOTONIC (the commit is inside it)."""
        self.batches += 1
        path = self.dir / f"batch{self.batches}.nft"
        path.write_text(text, encoding="utf-8")
        t_before = time.monotonic_ns()
        completed = self.run("l", ["nft", "-f", str(path)])
        t_after = time.monotonic_ns()
        self.writes.append((t_before, t_after, kind))
        return NftResult(completed.returncode, t_before, t_after,
                         "ok" if completed.returncode == 0 else classify_nft_error(completed.stderr))

    def listing(self, *what: str) -> str:
        completed = self.run("l", ["nft", "list", *what])
        return completed.stdout if completed.returncode == 0 else ""

    def prepared(self) -> dict[int, tuple[int, int]]:
        return parse_prepared(self.listing("set", "inet", "heel_lease", "prepared"))

    def activated(self) -> list[int]:
        return parse_activated(self.listing("map", "inet", "heel_lease", "activated"))

    def writes_between(self, start_ns: int, end_ns: int) -> int:
        """Ruleset writes by this test process (not by an installer child) overlapping a window."""
        return sum(1 for t0, t1, _kind in self.writes if t1 >= start_ns and t0 <= end_ns)

    def child(self, program: str, argv: tuple = ()) -> Child:
        fd = self.fds["l"]
        child = Child(program, argv, preexec=lambda: os.setns(fd, CLONE_NEWNET))
        self.children.append(child)
        return child

    def socket(self, side: str, *, bind: tuple, mark: int | None = None) -> socket.socket:
        def create() -> socket.socket:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
                if mark is not None:
                    sock.setsockopt(socket.SOL_SOCKET, SO_MARK, mark)
                sock.bind(bind)
            except BaseException:
                sock.close()
                raise
            return sock

        sock = _in_netns(self.fds[side], create)
        self.sockets.append(sock)
        SOCKETS.append(sock)
        COUNTERS["sockets"] += 1
        return sock

    def stream(self, *, start_ns: int, count: int, mark: int | None = None) -> "ProbeStream":
        return ProbeStream(self, start_ns=start_ns, count=count, mark=mark)

    def close(self) -> None:
        for child in self.children:
            child.kill()
        for sock in self.sockets:
            with contextlib.suppress(OSError):
                sock.close()
        outer = {name for _index, name in socket.if_nameindex()}
        for link in self.links:
            if link in outer:  # a wiring failure left the veth here; remove only our own link
                self.run(None, ["ip", "link", "del", link])
        for holder in self.holders.values():
            with contextlib.suppress(OSError, ValueError):
                holder.process.stdin.close()
            holder.wait(5)
        for fd in self.fds.values():
            with contextlib.suppress(OSError):
                os.close(fd)
        self.fds.clear()
        OPEN_PAIRS.discard(self)


class ProbeStream:
    """100 probes per second from L to R; the sender records each syscall bracket and verdict."""

    def __init__(self, pair: Pair, *, start_ns: int, count: int, mark: int | None = None):
        self.start_ns, self.count = start_ns, count
        self.receiver = pair.socket("r", bind=(R_ADDR, PORT))
        self.receiver.settimeout(0.05)
        self.sender = pair.socket("l", bind=(L_ADDR, 0), mark=mark)
        self.probes: list = [None] * count
        self.received: dict[int, int] = {}
        self.stop = threading.Event()
        self.end_ns: int | None = None
        self.threads = [threading.Thread(target=self._receive, daemon=True), threading.Thread(target=self._send, daemon=True)]

    def start(self) -> "ProbeStream":
        for thread in self.threads:
            thread.start()
        return self

    def _send(self) -> None:
        for index in range(self.count):
            sleep_until(self.start_ns + index * PROBE_INTERVAL_NS)
            t_before = time.monotonic_ns()
            payload = PAYLOAD.pack(MAGIC, index, t_before, TOKEN).ljust(PAYLOAD_BYTES, b"\0")
            try:
                self.sender.sendto(payload, (R_ADDR, PORT))
                admitted, error = True, "ok"
            except PermissionError:
                admitted, error = False, "eperm"
            except OSError:
                admitted, error = False, "oserror"
            self.probes[index] = Probe(index, t_before, time.monotonic_ns(), admitted, error)
        self.end_ns = time.monotonic_ns()

    def _receive(self) -> None:
        while True:
            try:
                data = self.receiver.recv(256)
            except TimeoutError:
                if self.stop.is_set():
                    return
                continue
            except OSError:
                return
            now = time.monotonic_ns()
            if len(data) == PAYLOAD_BYTES:
                magic, index, _sent, token = PAYLOAD.unpack_from(data)
                if magic == MAGIC and token == TOKEN and 0 <= index < self.count:
                    self.received.setdefault(index, now)

    def join(self) -> list[Probe]:
        self.threads[1].join(self.count * PROBE_INTERVAL_NS / 1e9 + 60)
        time.sleep(0.3)  # in-flight datagrams arrive; delivery only, never an admission time
        self.stop.set()
        self.threads[0].join(5)
        for sock in (self.sender, self.receiver):
            with contextlib.suppress(OSError):
                sock.close()
        probes = [probe for probe in self.probes if probe is not None]
        assert len(probes) == self.count and self.end_ns is not None, "the sender did not attempt every probe"
        for probe in probes:
            probe.recv_ns = self.received.get(probe.index)
        return probes

    def run(self) -> list[Probe]:
        return self.start().join()


class Installer:
    """A separate installer process: an optional relative-TTL computation, a fixed pipe barrier (the
    stall), one ``nft -f`` commit, then it blocks until SIGKILL and never cleans up."""

    def __init__(self, pair: Pair):
        self.pair = pair
        self.child = pair.child(INSTALLER)
        self.child.expect("started")
        self.released_ns: int | None = None

    def configure(self, batch: str, deadline_ns: int | None = None) -> dict:
        path = self.pair.dir / f"installer{self.child.pid}.nft"
        self.child.send(json.dumps({"batch": batch, "deadline_ns": deadline_ns, "path": str(path)}))
        computed = self.child.expect("computed") if deadline_ns is not None else None
        return {"computed": computed, "barrier": self.child.expect("barrier")}

    def release(self) -> dict:
        self.released_ns = time.monotonic_ns()
        self.child.send("release")
        return self.child.expect("committed")

    def kill(self) -> int | None:
        return self.child.kill()


@contextlib.contextmanager
def _pair(table: str | None):
    pair = Pair(_work())
    try:
        if table is not None:
            installed = pair.nft(table, kind="setup")
            assert installed.ok, f"fixture table install failed: {installed.error}"
        yield pair
    finally:
        pair.close()


_PROVENANCE: dict = {}


def _command(argv: list[str]) -> str:
    try:
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=20, env=LAUNCHER._env())
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return completed.stdout if completed.returncode == 0 else ""


def _config_hz(release: str) -> int | None:
    texts = []
    with contextlib.suppress(OSError):
        texts.append(Path(f"/boot/config-{release}").read_text(encoding="utf-8", errors="replace"))
    with contextlib.suppress(OSError, EOFError, gzip.BadGzipFile):
        texts.append(gzip.decompress(Path("/proc/config.gz").read_bytes()).decode("utf-8", "replace"))
    for text in texts:
        match = re.search(r"^CONFIG_HZ=([0-9]{2,4})$", text, re.M)
        if match:
            return int(match.group(1))
    return None


def provenance() -> dict:
    """Bounded parsed fields and hashes of the captured runtime (raw text never leaves this process)."""
    if _PROVENANCE:
        return _PROVENANCE
    release_raw = os.uname().release
    release, major_minor = parse_release(release_raw)
    nft = re.search(r"nftables v([0-9]+\.[0-9]+\.[0-9]+)", _command(["nft", "--version"]))
    package = _command(["dpkg-query", "-W", "-f=${Version}", "nftables"]).strip().lower()
    util = re.search(r"util-linux ([0-9]+\.[0-9]+(?:\.[0-9]+)?)", _command(["unshare", "--version"]))
    hz = _config_hz(release_raw)
    overflowuid = None
    with contextlib.suppress(OSError, ValueError):
        overflowuid = _overflowuid()
    _PROVENANCE.update({
        "kernel_release": release, "kernel_major_minor": major_minor,
        "kernel_source_tag": LAUNCHER.SUPPORTED_KERNELS.get(major_minor, "none"),
        "proc_version_sha256": hashlib.sha256(Path("/proc/version").read_bytes()).hexdigest(),
        "nft_version": nft.group(1) if nft else "unparsed",
        "nftables_package": package if re.fullmatch(r"[0-9][a-z0-9.:-]{0,60}", package) else "unparsed",
        "util_linux": util.group(1) if util else "absent",
        "python": "{}.{}.{}".format(*sys.version_info[:3]), "pytest": pytest.__version__,
        "config_hz": hz, "overflowuid": overflowuid,
        # One kernel tick; unknown HZ uses the coarsest supported tick and marks the profile unpinned.
        "tick_ns": -(-1_000_000_000 // hz) if hz else 10 * MS,
    })
    return _PROVENANCE


def _tick_ns() -> int:
    return provenance()["tick_ns"]


def _compatibility_self_test(tick: int) -> tuple[bool, dict, str]:
    """H1DR section 3.4 corrected (Astra 2): 200 ms gate; duplicate ``create`` refused while the key
    is LIVE; traffic before expiry, none after; then a fresh ``create`` of the expired key succeeds,
    which is exactly why production must never reuse a key."""
    with _pair(gate_table()) as pair:
        mark = MARKS.fresh()
        prepared = pair.nft(prepare_batch(mark, 200))
        duplicate = pair.nft(prepare_batch(deliberate_reuse(mark, "live_collision"), 200))
        duplicate_while_live = duplicate.t_after <= prepared.t_before + 200 * MS - 2 * tick
        active = pair.nft(activate_batch(mark))
        probes = pair.stream(start_ns=active.t_after, count=60).run()
        live_to, bound = prepared.t_before + 200 * MS - 2 * tick, prepared.t_after + 200 * MS + tick
        before = [p for p in inside(probes, active.t_after, live_to) if p.admitted and p.delivered]
        after = admitted_after(probes, bound)
        sleep_until(bound + 2 * tick + 50 * MS)
        recreated = pair.nft(prepare_batch(deliberate_reuse(mark, "expired_recreate"), 200))
    passed = (prepared.ok and not duplicate.ok and duplicate.error == "eexist" and duplicate_while_live and active.ok
              and len(before) >= 1 and not after and anomalies(probes) == 0 and recreated.ok)
    return passed, {"selftest_admitted_before_expiry": len(before), "selftest_admitted_after_expiry": len(after),
                    "selftest_duplicate_while_live": int(duplicate_while_live),
                    "selftest_expired_recreate_ok": int(recreated.ok)}, duplicate.error


# ---------------------------------------------------------------------------------------------
# Dynamic cases (Linux, inside the launcher's namespaces only).

def test_a12_kernel_nft_provenance_recorded_and_compatibility_self_test():
    _require_runtime()
    fields = provenance()
    passed, selftest, duplicate_error = _compatibility_self_test(fields["tick_ns"])
    parsed = (fields["kernel_major_minor"] != "unparsed" and fields["nft_version"] != "unparsed"
              and isinstance(fields["overflowuid"], int))
    ints = {"tick_allowance_ms": ms_ceil(fields["tick_ns"]), "cpu_count": os.cpu_count() or 0, **selftest}
    if fields["config_hz"] is not None:
        ints["config_hz"] = fields["config_hz"]
    if isinstance(fields["overflowuid"], int):
        ints["overflowuid"] = fields["overflowuid"]
    tokens = {key: fields[key] for key in ("kernel_release", "kernel_major_minor", "kernel_source_tag", "proc_version_sha256",
                                           "nft_version", "nftables_package", "util_linux", "python", "pytest")}
    tokens.update(selftest="pass" if passed else "fail", selftest_duplicate_error=duplicate_error)
    profile, reasons = LAUNCHER.kernel_profile({**fields, "selftest": tokens["selftest"],
                                                "readd_observation": LAUNCHER.READD_EXPECTED.get(fields["kernel_major_minor"])})
    tokens["profile_without_readd"] = profile
    record("a12", passed and parsed, ints, tokens)
    assert parsed, "the captured kernel, nft or overflowuid could not be parsed"
    assert passed, "the compatibility self-test failed on the captured kernel"


def test_n1_relative_ttl_post_delete_admits_packets_after_deadline_when_installer_dies():
    """NEGATIVE CONTROL (H1D section 5.2): the installer computes R = D - t_pre, stalls 6 s, writes a
    relative lifetime and is killed before its post-delete. The hazard must be SHOWN."""
    _require_runtime()
    tick = _tick_ns()
    with _pair(N1_TABLE) as pair:
        installer = Installer(pair)
        t0 = time.monotonic_ns()
        deadline = t0 + 3000 * MS
        stream = pair.stream(start_ns=t0, count=1200).start()
        sleep_until(t0 + 1000 * MS)
        computed = installer.configure(N1_BATCH, deadline)["computed"]
        sleep_until(computed["t_pre"] + 6000 * MS)
        committed = installer.release()
        killed = installer.kill()  # immediately after nft returned: the post-delete never runs
        probes = stream.join()
        writes = pair.writes_between(installer.released_ns, stream.end_ns)
    hazard = admitted_after(probes, deadline + tick)
    ok = (committed["rc"] == 0 and killed == -signal.SIGKILL and writes == 0 and computed["ttl_ms"] > 0
          and grade_hazard(probes, element_from_ns=committed["t_pp"], deadline_bound_ns=deadline + tick))
    record("n1", ok, {"ttl_ms": computed["ttl_ms"], "stall_ms": ms_floor(installer.released_ns - computed["t_pre"]),
                      "commit_after_deadline_ms": ms_floor(committed["t_pp"] - deadline),
                      "hazard_admitted_after_deadline": len(hazard),
                      "admitted_before_element": len(admitted_before(probes, committed["t_pp"])),
                      "last_admitted_after_deadline_ms": ms_ceil(max(p.t_before for p in hazard) - deadline) if hazard else 0,
                      "writes_during_window": writes, "post_delete_executed": 0, "anomalies": anomalies(probes)},
           {"installer": "killed" if killed == -signal.SIGKILL else "not_killed", "commit": "ok" if committed["rc"] == 0 else "failed"})
    assert ok, "the relative-TTL negative control did not show its hazard (or the fixture is invalid)"


def test_n2_gate_without_mark_reset_admits_a_carried_mark():
    """NEGATIVE CONTROL: without ``meta mark set 0`` a socket mark equal to a live prepared key passes
    with no activation, so the reset rule is load-bearing (A2 exercises it)."""
    _require_runtime()
    tick = _tick_ns()
    with _pair(gate_table(mark_reset=False)) as pair:
        mark = MARKS.fresh()
        prepared = pair.nft(prepare_batch(mark, 3000))
        probes = pair.stream(start_ns=prepared.t_after, count=100, mark=mark).run()
        activated = pair.activated()
    live = inside(probes, prepared.t_after, prepared.t_before + 3000 * MS - 2 * tick)
    admitted = [p for p in live if p.admitted and p.delivered]
    ok = prepared.ok and activated == [] and len(live) >= 80 and len(admitted) >= 50 and anomalies(probes) == 0
    record("n2", ok, {"carried_mark_admitted": len(admitted), "probes_while_live": len(live), "activated_entries": len(activated)},
           {"gate": "without_mark_reset"})
    assert ok, "the carried-mark negative control did not show its hazard"


def test_n3_recreating_an_expired_key_revives_a_stale_reference():
    """NEGATIVE CONTROL (Astra 1): the map still references an expired key; recreating that same key
    (``create`` succeeds once it expired) revives the stale reference. This is why keys never repeat."""
    _require_runtime()
    tick = _tick_ns()
    with _pair(gate_table(gc_interval_hour=True)) as pair:
        mark = MARKS.fresh()
        prepared = pair.nft(prepare_batch(mark, 500))
        active = pair.nft(activate_batch(mark))
        stream = pair.stream(start_ns=active.t_after, count=300).start()
        bound = prepared.t_after + 500 * MS + tick
        sleep_until(bound + 700 * MS)
        recreated = pair.nft(prepare_batch(deliberate_reuse(mark, "expired_recreate"), 1500))
        probes = stream.join()
    ok = (prepared.ok and active.ok and recreated.ok
          and grade_revival(probes, live_to_ns=prepared.t_before + 500 * MS - 2 * tick, expired_bound_ns=bound,
                            recreate_from_ns=recreated.t_before, recreate_to_ns=recreated.t_after))
    gap = [p for p in probes if p.t_before > bound and p.t_after < recreated.t_before]
    record("n3", ok, {"gap_probes": len(gap), "gap_admitted": sum(p.accepted for p in gap),
                      "revived_admitted": len(admitted_after(probes, recreated.t_after)),
                      "recreate_after_expiry_ms": ms_floor(recreated.t_before - bound)},
           {"recreate": "ok" if recreated.ok else recreated.error})
    assert ok, "the expired-key reuse negative control did not show its hazard"


def test_a1_prepared_gate_composition_parses_and_installs():
    _require_runtime()
    with _pair(None) as pair:
        installed = pair.nft(gate_table(), kind="setup")
        mark = MARKS.fresh()
        prepared = pair.nft(prepare_batch(mark, 2850)) if installed.ok else NftResult(1, 0, 0, "not_attempted")
        element = pair.prepared().get(mark)
        chain = pair.listing("chain", "inet", "heel_lease", "gate")
    composition = ("map @activated" in chain and "@prepared accept" in chain and chain.count("meta mark set") >= 2)
    ok = installed.ok and prepared.ok and element is not None and element[0] <= 2850 and element[1] <= 2850 and composition
    record("a1", ok, {"readback_timeout_ms": element[0] if element else -1, "readback_expires_ms": element[1] if element else -1,
                      "composition_listed": int(composition)},
           {"install": installed.error, "prepare": prepared.error})
    assert ok, "the prepared-gate composition did not parse, install or read back within its timeout"


def test_a2_prepared_only_admits_nothing_even_with_a_carried_mark():
    _require_runtime()
    tick = _tick_ns()
    with _pair(gate_table()) as pair:
        mark = MARKS.fresh()
        prepared = pair.nft(prepare_batch(mark, 3000))
        live_to = prepared.t_before + 3000 * MS - 2 * tick
        plain = pair.stream(start_ns=prepared.t_after, count=80).run()
        carried = pair.stream(start_ns=time.monotonic_ns(), count=80, mark=mark).run()
        listed, activated = mark in pair.prepared(), pair.activated()
        active = pair.nft(activate_batch(mark))  # positive control: the same live element, now activated
        control = pair.stream(start_ns=active.t_after, count=20).run()
    certainly_live = all(p.t_after <= live_to for p in plain + carried)
    ok = (prepared.ok and certainly_live and listed and activated == [] and active.ok
          and grade_closed(plain, control, control_from_ns=active.t_after, control_to_ns=live_to)
          and grade_closed(carried, control, control_from_ns=active.t_after, control_to_ns=live_to))
    record("a2", ok, {"plain_admitted": sum(p.accepted for p in plain), "carried_mark_admitted": sum(p.accepted for p in carried),
                      "probes": len(plain) + len(carried), "control_delivered": sum(p.delivered for p in control),
                      "probes_certainly_live": int(certainly_live)}, {"carried_mark": "reset_to_zero"})
    assert ok, "a prepared-only element admitted traffic (or the fixture could not show a live control)"


def test_a3_prompt_activation_admits_live_authority_traffic():
    _require_runtime()
    tick = _tick_ns()
    with _pair(gate_table()) as pair:
        mark = MARKS.fresh()
        prepared = pair.nft(prepare_batch(mark, 3000))
        active = pair.nft(activate_batch(mark))
        probes = pair.stream(start_ns=active.t_after, count=200).run()
    live_to = prepared.t_before + 3000 * MS - 2 * tick
    window = inside(probes, active.t_after, live_to)
    ok = prepared.ok and active.ok and grade_cutoff(probes, live_from_ns=active.t_after, live_to_ns=live_to,
                                                    bound_ns=prepared.t_after + 3000 * MS + tick, minimum=150)
    record("a3", ok, {"live_probes": len(window), "live_delivered": sum(p.delivered for p in window),
                      "activation_latency_ms": ms_ceil(active.t_after - prepared.t_after)}, {"activation": active.error})
    assert ok, "prompt activation did not admit live-authority traffic"


def test_a4_stale_activation_after_expiry_with_cleanup_withheld_admits_zero_packets():
    _require_runtime()
    tick = _tick_ns()
    with _pair(gate_table()) as pair:
        mark = MARKS.fresh()
        prepared = pair.nft(prepare_batch(mark, 3000))
        bound = prepared.t_after + 3000 * MS + tick
        stream = pair.stream(start_ns=prepared.t_after, count=1000).start()
        installer = Installer(pair)
        barrier = installer.configure(activate_batch(mark))["barrier"]  # clock read, then the stall
        sleep_until(max(barrier["t"] + 5000 * MS, bound + 100 * MS))
        committed = installer.release()
        killed = installer.kill()
        probes = stream.join()
        writes = pair.writes_between(installer.released_ns, stream.end_ns)
        activated, listed = pair.activated(), mark in pair.prepared()
        fresh = MARKS.fresh()  # after the window: a fresh key proves the fixture still admits
        control_prepared = pair.nft(prepare_batch(fresh, 3000))
        control_active = pair.nft(activate_batch(fresh))
        control = pair.stream(start_ns=control_active.t_after, count=30).run()
    stale = committed["t_pp"] > bound
    ok = (prepared.ok and committed["rc"] == 0 and killed == -signal.SIGKILL and stale and writes == 0
          and activated == [mark] and not listed and control_prepared.ok and control_active.ok
          and grade_closed(probes, control, control_from_ns=control_active.t_after,
                           control_to_ns=control_prepared.t_before + 3000 * MS - 2 * tick))
    record("a4", ok, {"window_probes": len(probes), "window_admitted": sum(p.accepted for p in probes),
                      "activation_after_expiry_ms": ms_floor(committed["t_pp"] - bound),
                      "writes_during_window": writes, "map_points_to_stale_mark": int(activated == [mark]),
                      "stale_key_listed": int(listed), "control_delivered": sum(p.delivered for p in control)},
           {"installer": "killed" if killed == -signal.SIGKILL else "not_killed",
            "activation": "ok" if committed["rc"] == 0 else "failed", "cleanup": "withheld"})
    assert ok, "a stale activation after certain expiry admitted traffic (or the fixture is invalid)"


def test_a5_activation_then_supervisor_death_stops_at_prepared_expiry():
    _require_runtime()
    tick = _tick_ns()
    with _pair(gate_table()) as pair:
        mark = MARKS.fresh()
        prepared = pair.nft(prepare_batch(mark, 3000))
        stream = pair.stream(start_ns=prepared.t_after, count=600).start()
        installer = Installer(pair)
        installer.configure(activate_batch(mark))
        committed = installer.release()
        killed = installer.kill()
        probes = stream.join()
        writes = pair.writes_between(installer.released_ns, stream.end_ns)
    bound = prepared.t_after + 3000 * MS + tick
    accepted = [p for p in probes if p.accepted]
    ok = (prepared.ok and committed["rc"] == 0 and killed == -signal.SIGKILL and writes == 0
          and grade_cutoff(probes, live_from_ns=committed["t_pq"], live_to_ns=prepared.t_before + 3000 * MS - 2 * tick,
                           bound_ns=bound, minimum=200))
    last = max((p.t_before for p in accepted), default=None)
    record("a5", ok, {"admitted": len(accepted), "admitted_after_bound": len(admitted_after(probes, bound)),
                      "last_admitted_margin_ms": ms_floor(bound - last) if last is not None and last <= bound else -1,
                      "last_admitted_lateness_ms": ms_ceil(last - bound) if last is not None and last > bound else 0,
                      "writes_during_window": writes, "tick_allowance_ms": ms_ceil(tick)},
           {"installer": "killed" if killed == -signal.SIGKILL else "not_killed", "cleanup": "withheld"})
    assert ok, "traffic continued past the prepared expiry after the supervisor died"


def test_a6_renewal_swap_has_no_gap_and_old_mark_expiry_is_irrelevant():
    _require_runtime()
    tick = _tick_ns()
    with _pair(gate_table()) as pair:
        first, second = MARKS.fresh(), MARKS.fresh()
        prepared_1 = pair.nft(prepare_batch(first, 3000))
        active_1 = pair.nft(activate_batch(first))
        stream = pair.stream(start_ns=active_1.t_after, count=500).start()
        sleep_until(prepared_1.t_after + 1000 * MS)
        prepared_2 = pair.nft(prepare_batch(second, 3000))
        active_2 = pair.nft(activate_batch(second))
        probes = stream.join()
    old_bound, new_bound = prepared_1.t_after + 3000 * MS + tick, prepared_2.t_after + 3000 * MS + tick
    live_to = prepared_2.t_before + 3000 * MS - 2 * tick
    window = inside(probes, active_1.t_after, live_to)
    ok = (prepared_1.ok and active_1.ok and prepared_2.ok and active_2.ok
          and grade_renewal(probes, live_from_ns=active_1.t_after, live_to_ns=live_to, old_bound_ns=old_bound,
                            new_bound_ns=new_bound, minimum=300))
    record("a6", ok, {"window_probes": len(window), "window_lost": sum(not (p.admitted and p.delivered) for p in window),
                      "admitted_after_old_expiry": len(admitted_after(probes, old_bound)),
                      "admitted_after_new_expiry": len(admitted_after(probes, new_bound))}, {"swap": active_2.error})
    assert ok, "the renewal swap lost probes, stopped at the old expiry or ran past the new one"


def test_a7_live_create_collision_fails_closed_and_expired_key_accepts_fresh_create():
    _require_runtime()
    tick = _tick_ns()
    with _pair(gate_table()) as pair:
        current, colliding = MARKS.fresh(), MARKS.fresh()
        pair.nft(prepare_batch(current, 3000))
        pair.nft(activate_batch(current))
        prepared = pair.nft(prepare_batch(colliding, 3000))
        before = pair.activated()
        collision = pair.nft(prepare_batch(deliberate_reuse(colliding, "live_collision"), 3000) + activate_batch(colliding))
        after = pair.activated()
    live = collision.t_after <= prepared.t_before + 3000 * MS - 2 * tick
    with _pair(gate_table(gc_interval_hour=True)) as pair:  # the expired element stays in memory
        expired = MARKS.fresh()
        short = pair.nft(prepare_batch(expired, 200))
        sleep_until(short.t_after + 200 * MS + 2 * tick + 50 * MS)
        listed_after_expiry = expired in pair.prepared()
        recreated = pair.nft(prepare_batch(deliberate_reuse(expired, "expired_recreate"), 3000))
        element = pair.prepared().get(expired)
    ok_live = prepared.ok and not collision.ok and collision.error == "eexist" and before == after == [current] and live
    ok_expired = short.ok and recreated.ok and element is not None and 2000 < element[1] <= 3000
    record("a7", ok_live and ok_expired,
           {"collision_while_live": int(live), "map_unchanged": int(before == after == [current]),
            "expired_listed_before_recreate": int(listed_after_expiry), "recreated_expires_ms": element[1] if element else -1},
           {"collision": collision.error, "expired_recreate": recreated.error})
    assert ok_live, "a live duplicate create did not fail the whole batch with EEXIST and an unchanged map"
    assert ok_expired, "a fresh create of an expired key did not succeed (the reuse hazard is unrecorded)"


def test_a8_reference_to_expired_key_does_not_revive_and_live_readd_semantics_recorded():
    _require_runtime()
    tick = _tick_ns()
    with _pair(gate_table()) as pair:
        mark = MARKS.fresh()
        prepared = pair.nft(prepare_batch(mark, 800))
        sleep_until(prepared.t_after + 1500 * MS)
        active = pair.nft(activate_batch(mark))
        probes = pair.stream(start_ns=active.t_after, count=200).run()
        listed, activated = mark in pair.prepared(), pair.activated()
        fresh = MARKS.fresh()
        control_prepared = pair.nft(prepare_batch(fresh, 3000))
        control_active = pair.nft(activate_batch(fresh))
        control = pair.stream(start_ns=control_active.t_after, count=30).run()
        # Informative (not graded here): a non-EXCL re-add of a LIVE key with a different timeout.
        # The source tags say v6.8 leaves it unchanged and v6.17/v7.0 refresh it at commit; the
        # launcher holds the run (unpinned) if the captured kernel disagrees with its tag.
        probe_key = MARKS.fresh()
        pair.nft(prepare_batch(probe_key, 3000))
        time.sleep(0.5)
        first = pair.prepared().get(probe_key)
        readd = pair.nft(readd_batch_informative(deliberate_reuse(probe_key, "informative_readd"), 2900), kind="informative")
        second = pair.prepared().get(probe_key)
    if not readd.ok:
        observation = "error"
    elif first is None or second is None:
        observation = "unreadable"
    else:
        observation = "refresh" if second[1] > first[1] + 200 else ("noop" if second[1] <= first[1] else "other")
    ok = (prepared.ok and active.ok and activated == [mark] and not listed and control_prepared.ok and control_active.ok
          and grade_closed(probes, control, control_from_ns=control_active.t_after,
                           control_to_ns=control_prepared.t_before + 3000 * MS - 2 * tick))
    record("a8", ok, {"probes": len(probes), "admitted": sum(p.accepted for p in probes), "expired_key_listed": int(listed),
                      "readd_first_expires_ms": first[1] if first else -1, "readd_second_expires_ms": second[1] if second else -1},
           {"readd_observation": observation, "activation": active.error})
    assert ok, "a reference to an expired key admitted traffic"


def test_a9_short_timeout_expires_no_later_than_prepare_return_plus_timeout():
    _require_runtime()
    tick = _tick_ns()
    with _pair(gate_table()) as pair:
        mark = MARKS.fresh()
        prepared = pair.nft(prepare_batch(mark, 800))
        active = pair.nft(activate_batch(mark))
        probes = pair.stream(start_ns=active.t_after, count=300).run()
    bound = prepared.t_after + 800 * MS + tick
    accepted = [p.t_before for p in probes if p.accepted]
    last = max(accepted, default=None)
    ok = prepared.ok and active.ok and grade_cutoff(probes, live_from_ns=active.t_after,
                                                    live_to_ns=prepared.t_before + 800 * MS - 2 * tick,
                                                    bound_ns=bound, minimum=50)
    record("a9", ok, {"admitted": len(accepted), "admitted_after_bound": len(admitted_after(probes, bound)),
                      "last_admitted_margin_ms": ms_floor(bound - last) if last is not None and last <= bound else -1,
                      "last_admitted_lateness_ms": ms_ceil(last - bound) if last is not None and last > bound else 0},
           {"activation": active.error})
    assert ok, "an 800 ms prepared element admitted traffic past its bound"


def test_a10_prepare_and_activate_bracket_distribution_under_concurrent_transactions():
    """Liveness measurement for GUARD_MS (never authority): 200 prepare and 200 activation batch
    brackets while a sibling process commits unrelated transactions in another table."""
    _require_runtime()
    with _pair(gate_table()) as pair:
        churn_table = pair.nft(CHURN_TABLE, kind="setup")
        churn = pair.child(CHURN, (str(pair.dir / "churn.nft"),))
        churn.expect("running")
        prepares, activations, failures = [], [], 0
        for _ in range(200):
            mark = MARKS.fresh()
            prepared = pair.nft(prepare_batch(mark, 3000))
            active = pair.nft(activate_batch(mark))
            failures += (not prepared.ok) + (not active.ok)
            prepares.append(prepared)
            activations.append(active)
        churn.send("stop")
        done = churn.expect("done", timeout=120)
        churn.kill()
    overlapping = sum(1 for p, a in zip(prepares, activations) if done["first"] is not None
                      and p.t_before >= done["first"] and a.t_after <= done["last"])
    ok = churn_table.ok and failures == 0 and done["count"] >= 200 and done["failures"] == 0 and overlapping == 200
    ints = {"samples": len(prepares), "batch_failures": failures, "churn_transactions": done["count"],
            "churn_failures": done["failures"], "samples_during_churn": overlapping}
    for label, results in (("prepare", prepares), ("activate", activations)):
        values = [result.t_after - result.t_before for result in results]
        for name, fraction in (("p50", 0.5), ("p95", 0.95), ("p99", 0.99), ("max", 1.0)):
            ints[f"{label}_{name}_us"] = -(-percentile(values, fraction) // 1000)
            ints[f"{label}_{name}_ms"] = ms_ceil(percentile(values, fraction))
    record("a10", ok, ints, {"use": "guard_ms_liveness_only"})
    assert ok, "the bracket distribution could not be measured under concurrent transactions"


def test_a11_readback_expires_never_exceeds_requested_timeout():
    _require_runtime()
    rng = random.Random(0x48314631)
    violations, readbacks, worst = 0, 0, -10_000
    with _pair(gate_table()) as pair:
        for _ in range(100):
            timeout = rng.randint(500, 3000)
            mark = MARKS.fresh()
            prepared = pair.nft(prepare_batch(mark, timeout))
            element = pair.prepared().get(mark)
            if not prepared.ok or element is None:
                violations += 1
                continue
            readbacks += 1
            worst = max(worst, element[0] - timeout, element[1] - timeout)
            violations += element[0] > timeout or element[1] > timeout
    ok = violations == 0 and readbacks == 100
    record("a11", ok, {"readbacks": readbacks, "violations": violations, "max_readback_minus_requested_ms": worst},
           {"seed": "0x48314631"})
    assert ok, "a readback timeout or expires exceeded the requested timeout"


def test_a13_stale_reference_admits_nothing_while_a_different_fresh_key_is_live():
    """Astra 1 positive case: the map references an expired key while a DIFFERENT fresh key for the
    same tuple is live; nothing passes. Then a delayed activator overwrites a live activation with
    the stale key: traffic stops (fail-closed liveness blip, never authority)."""
    _require_runtime()
    tick = _tick_ns()
    with _pair(gate_table()) as pair:
        old, new = MARKS.fresh(), MARKS.fresh()
        prepared_old = pair.nft(prepare_batch(old, 600))
        pair.nft(activate_batch(old))
        sleep_until(prepared_old.t_after + 600 * MS + tick + 50 * MS)
        prepared_new = pair.nft(prepare_batch(new, 3000))
        start = time.monotonic_ns()
        stream = pair.stream(start_ns=start, count=350).start()
        sleep_until(start + 1000 * MS)
        stale_phase_map = pair.activated()
        active_new = pair.nft(activate_batch(new))
        installer = Installer(pair)
        installer.configure(activate_batch(old))
        sleep_until(active_new.t_after + 700 * MS)
        stale = installer.release()
        killed = installer.kill()
        final_map, live_keys = pair.activated(), pair.prepared()  # read-only, while the fresh key is live
        probes = stream.join()
    new_live_to = prepared_new.t_before + 3000 * MS - 2 * tick
    phase_1 = [p for p in probes if p.t_after < active_new.t_before]
    phase_3 = [p for p in probes if p.t_before > stale["t_pq"] and p.t_after <= new_live_to]
    live_to = min(stale["t_pp"], new_live_to)
    ok = (prepared_old.ok and prepared_new.ok and active_new.ok and stale["rc"] == 0 and killed == -signal.SIGKILL
          and stale_phase_map == [old] and final_map == [old] and new in live_keys and old not in live_keys
          and len(phase_1) >= 50 and not [p for p in phase_1 if p.accepted]
          and live_delivery(probes, active_new.t_after, live_to, minimum=40)
          and len(phase_3) >= 50 and not [p for p in phase_3 if p.accepted] and anomalies(probes) == 0)
    record("a13", ok, {"stale_reference_probes": len(phase_1), "stale_reference_admitted": sum(p.accepted for p in phase_1),
                       "current_delivered": sum(p.delivered for p in inside(probes, active_new.t_after, live_to)),
                       "after_stale_overwrite_probes": len(phase_3),
                       "after_stale_overwrite_admitted": sum(p.accepted for p in phase_3)},
           {"fresh_key": "live_not_referenced" if new in live_keys else "missing"})
    assert ok, "a stale reference admitted traffic while a different fresh key was live"


def test_b1_meta_time_absolute_rule_informative():
    """Informative only (H1DR section 4.6): never grades the run; it must still execute."""
    _require_runtime()
    results = {}
    for scenario, offset_s, stall_s in (("stale", 0, 2.0), ("future", 3, 0.0)):
        with _pair(None) as pair:
            deadline = int(time.time()) + offset_s
            time.sleep(stall_s)
            installed = pair.nft(meta_time_table(deadline), kind="setup")
            probes = pair.stream(start_ns=time.monotonic_ns(), count=100).run() if installed.ok else []
        results[scenario] = (installed.error, sum(p.accepted for p in probes), len(probes))
    record("b1", None, {"stale_rule_admitted": results["stale"][1], "future_rule_admitted": results["future"][1],
                        "stale_probes": results["stale"][2], "future_probes": results["future"][2]},
           {"stale_install": results["stale"][0], "future_install": results["future"][0]})
    assert set(results) == {"stale", "future"}


def _peer_dir(name: str, *, seam: bool = False) -> Path:
    base = _work() / "peer"
    base.mkdir(mode=0o755, exist_ok=True)
    os.chmod(base, 0o755)
    directory = base / name
    directory.mkdir()
    os.chmod(directory, 0o755 if seam else 0o700)
    os.chown(directory, CP_UID, CP_UID)
    return directory


def _production_socket(path: Path) -> bool:
    """The production profile (H1DR section 7): socket 0600 and parent 0700, both owned by the CP uid."""
    info, parent = os.lstat(path), os.lstat(path.parent)
    return (stat.S_ISSOCK(info.st_mode) and info.st_uid == CP_UID and stat.S_IMODE(info.st_mode) == 0o600
            and stat.S_ISDIR(parent.st_mode) and parent.st_uid == CP_UID and stat.S_IMODE(parent.st_mode) == 0o700)


def _root_connect(path: Path) -> tuple[socket.socket, dict]:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(30)
    client.connect(str(path))
    pid, uid, gid = struct.unpack("3i", client.getsockopt(socket.SOL_SOCKET, SO_PEERCRED, 12))
    SOCKETS.append(client)
    COUNTERS["sockets"] += 1
    return client, {"pid": pid, "uid": uid, "gid": gid}


def _write_id_maps(pid: int, outside: int) -> None:
    """Map inside uid/gid 0 to one outside id (written by root in the parent user namespace)."""
    Path(f"/proc/{pid}/uid_map").write_text(f"0 {outside} 1\n")
    Path(f"/proc/{pid}/gid_map").write_text(f"0 {outside} 1\n")


def _overflowuid() -> int:
    return int(Path("/proc/sys/kernel/overflowuid").read_text().strip())


def test_p1_unix_peercred_is_mutual_under_the_production_permissions():
    _require_runtime()
    path = _peer_dir("p1") / "authority.sock"
    server = outsider = client = None
    try:
        server = Child(PEER, ("server", "plain", str(CP_UID), str(path), "private"))
        server.expect("listening")
        production = _production_socket(path)
        outsider = Child(PEER, ("client", "plain", str(OUTSIDER_UID), str(path), "private"))
        refused = outsider.expect("refused")
        outsider.wait()
        client, client_view = _root_connect(path)
        server_view = server.expect("peer")
        client.close()
        server_exit = server.wait()
    finally:
        for child in (server, outsider):
            if child is not None:
                child.kill()
        if client is not None:
            client.close()
    ok = (production and refused["reason"] == "eacces" and server_view["uid"] == 0 and server_view["pid"] == os.getpid()
          and client_view["uid"] == CP_UID and client_view["pid"] == server.pid and server_exit == 0)
    record("p1", ok, {"server_view_uid": server_view["uid"], "server_view_pid_is_client": int(server_view["pid"] == os.getpid()),
                      "client_view_uid": client_view["uid"], "client_view_pid_is_listener": int(client_view["pid"] == server.pid),
                      "production_permissions": int(production)}, {"outsider_connect": refused["reason"]})
    assert ok, "SO_PEERCRED was not mutual under the production socket permissions"


def test_p2_checking_server_in_a_user_namespace_that_cannot_map_the_client_sees_overflowuid():
    """Astra 3: SO_PEERCRED maps the peer into the CHECKING side's user namespace. (i) A server whose
    namespace maps only its own uid sees the root client as overflowuid; the client still sees the
    server's real uid. (ii) Converse, through a labelled permissive seam socket (kernel mapping
    only, not the production profile): a client in such a namespace sees the server as overflowuid."""
    _require_runtime()
    overflow = _overflowuid()
    children, client = [], None
    try:
        path = _peer_dir("p2") / "authority.sock"
        server = Child(PEER, ("server", "userns", "0", str(path), "private"))
        children.append(server)
        server.expect("unshared")
        _write_id_maps(server.pid, CP_UID)
        server.send("mapped")
        server.expect("listening")
        production = _production_socket(path)
        client, client_view = _root_connect(path)
        server_view = server.expect("peer")
        client.close()
        server.wait()
        seam_path = _peer_dir("p2seam", seam=True) / "mapping.sock"
        seam_server = Child(PEER, ("server", "plain", str(CP_UID), str(seam_path), "seam"))
        children.append(seam_server)
        seam_server.expect("listening")
        seam_client = Child(PEER, ("client", "userns", "0", str(seam_path), "seam"))
        children.append(seam_client)
        seam_client.expect("unshared")
        _write_id_maps(seam_client.pid, OUTSIDER_UID)
        seam_client.send("mapped")
        converse_client_view = seam_client.expect("peer")
        converse_server_view = seam_server.expect("peer")
        seam_client.wait()
        seam_server.wait()
    finally:
        for child in children:
            child.kill()
        if client is not None:
            client.close()
    server_side = server_view["uid"] == overflow and client_view["uid"] == CP_UID and client_view["pid"] == server.pid
    converse = converse_client_view["uid"] == overflow and converse_server_view["uid"] == OUTSIDER_UID
    ok = production and server_side and converse and overflow != CP_UID
    record("p2", ok, {"overflowuid": overflow, "server_in_userns_view_uid": server_view["uid"],
                      "server_in_userns_view_pid_is_client": int(server_view["pid"] == os.getpid()),
                      "root_client_view_uid": client_view["uid"], "converse_client_view_uid": converse_client_view["uid"],
                      "converse_server_view_uid": converse_server_view["uid"], "production_permissions": int(production)},
           {"seam": "permissive_socket_converse_only", "checking_side": "server_then_client"})
    assert ok, "SO_PEERCRED did not map the peer into the checking side's user namespace"


def test_p3_server_in_a_child_pid_namespace_sees_the_root_uid_with_pid_zero():
    """Astra 3: a checking server in a child PID namespace (the host -> container direction) sees
    the correct root uid and pid 0 for a client outside it, so a blanket "pid != 0" rule would
    reject the intended topology. Recorded as a fact; no pid rule is accepted by this proof."""
    _require_runtime()
    server, client = None, None
    try:
        path = _peer_dir("p3") / "authority.sock"
        server = Child(PEER, ("server", "pidns", str(CP_UID), str(path), "private"))
        forked = server.expect("forked")
        listening = server.expect("listening")
        production = _production_socket(path)
        client, client_view = _root_connect(path)
        server_view = server.expect("peer")
        client.close()
        server_exit = server.wait()  # the pid-1 server exits on close, then its parent reaps it
    finally:
        if server is not None:
            server.kill()
        if client is not None:
            client.close()
    ok = (production and server_view["uid"] == 0 and server_view["pid"] == 0 and listening["pid"] == 1
          and client_view["uid"] == CP_UID and client_view["pid"] == forked["outer_pid"] and forked["outer_pid"] > 1
          and server_exit == 0)
    record("p3", ok, {"server_view_uid": server_view["uid"], "server_view_pid": server_view["pid"],
                      "server_inside_pid": listening["pid"], "client_view_uid": client_view["uid"],
                      "client_view_pid_is_outer_pid": int(client_view["pid"] == forked["outer_pid"]),
                      "pid_nonzero_rule_rejects_this_topology": int(server_view["pid"] == 0),
                      "production_permissions": int(production)}, {"identity": "uid_correct_pid_invisible"})
    assert ok, "the child-PID-namespace server did not see uid 0 with pid 0"


def test_c1_no_owned_namespace_process_socket_or_link_survives():
    _require_runtime()
    with contextlib.suppress(ChildProcessError):
        while os.waitpid(-1, os.WNOHANG)[0]:
            pass
    live_children = sum(child.process.poll() is None for child in CHILDREN)
    open_sockets = sum(sock.fileno() != -1 for sock in SOCKETS)
    links = sorted(name for _index, name in socket.if_nameindex())
    others = [entry.name for entry in Path("/proc").iterdir() if entry.name.isdigit()
              and int(entry.name) not in (1, os.getpid())]
    ok = not OPEN_PAIRS and live_children == 0 and open_sockets == 0 and links == ["lo"] and not others
    record("c1", ok, {"open_pairs": len(OPEN_PAIRS), "live_children": live_children, "open_sockets": open_sockets,
                      "outer_links": len(links), "other_processes": len(others), "pairs_created": COUNTERS["pairs"],
                      "children_spawned": COUNTERS["children"], "sockets_created": COUNTERS["sockets"]}, {})
    assert ok, "an owned namespace, process, socket or link survived the cases"
