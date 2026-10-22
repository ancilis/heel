"""H1A-1: Linux proof of the lease generation domain and the host-authority transport
(``authority-v1``; H1ADR sections 3.3 and 4.4, H1AD section 6.3).

Static cases run everywhere. Dynamic cases need the fixed ``scripts/host_authority_proof.py``
launcher: it runs this module as root inside an outer network+mount+PID namespace that has only
loopback, with ``HEEL_REQUIRE_HOST_AUTHORITY_PROOF=1``. Under that switch a missing platform,
privilege, tool, launcher environment or namespace capability fails; outside it the dynamic cases
skip, so the ordinary suite never claims authority proof.

Domain cases use the real ``deploy/host/authority.py`` API (``LeaseDomain.create``, ``prepare``,
``activate``, ``close_generation``) in namespaces it creates and holds by descriptor; the proof
fixture only installs the H1F gate table into them and wires one veth to a receiver namespace.
Probes are H1F's: a 64-byte UDP datagram every 10 ms whose admission is the ``sendto`` verdict of
the output gate inside its own CLOCK_MONOTONIC bracket; delivery only confirms admission. Process
spawns are counted by PID allocation inside the launcher's private PID namespace (every process
the suite or the domain creates takes the next PID there), so "no process was spawned" is a kernel
observation, not a counter the product keeps. Transport cases use the real
``heel/saas/host_authority.py`` listener, the real ``SO_PEERCRED`` reader and production
permissions.

The job runs under the running-kernel assumption (no suspend, hibernate, pause, restore or clone
during the job). It proves uniqueness U and the transport unit only; it says nothing about elapsed
authority lifetime L under gap modes M3-M6, the CP decision, the supervisor cycle, H2, H3 or launch.
"""
from __future__ import annotations

import ast
import contextlib
import copy
import ctypes
import hashlib
import importlib.util
import inspect
import json
import os
import queue
import re
import select
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
LAUNCHER_FILE = ROOT / "scripts" / "host_authority_proof.py"
AUTHORITY_FILE = ROOT / "deploy" / "host" / "authority.py"
LISTENER_FILE = ROOT / "heel" / "saas" / "host_authority.py"
UNIT_TESTS = ROOT / "tests" / "test_host_authority.py"
WORKFLOW = ROOT / ".github" / "workflows" / "codeql.yml"
DOC = ROOT / "docs" / "saas" / "HOST_AUTHORITY_PROOF.md"
H0_LOCK = ROOT / "deploy" / "host" / "ingress" / "runtime-lock.json"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


LAUNCHER = _load("host_authority_proof", LAUNCHER_FILE)
AUTHORITY = _load("heel_host_authority_domain", AUTHORITY_FILE)
LISTENER = _load("heel_host_authority_listener", LISTENER_FILE)
PROFILE = LAUNCHER.profile()
sys.modules.setdefault("heel_host_authority_domain", AUTHORITY)
sys.modules.setdefault("heel_host_profile", PROFILE)
sys.modules.setdefault("heel_host_authority_codec", LISTENER)
CYCLE = _load("heel_host_cycle_proof", ROOT / "deploy" / "host" / "cycle.py")
REQUIRED = os.environ.get(LAUNCHER.REQUIRED_ENV) == "1"

MS = 1_000_000
L_ADDR, R_ADDR, PORT = "198.51.100.10", "203.0.113.10", 47011
PROBE_INTERVAL_NS = 10 * MS
PAYLOAD = struct.Struct("!4sIQ16s")
PAYLOAD_BYTES = 64
MAGIC = b"HA1P"
LIVE_PERCENT = 95
CP_UID, OUTSIDER_UID = 10001, 10002
CLONE_NEWNET, CLONE_NEWUSER = 0x40000000, 0x10000000
MS_BIND, MNT_DETACH, PR_SET_CHILD_SUBREAPER = 4096, 2, 36
SO_PEERCRED = getattr(socket, "SO_PEERCRED", 17)

# ---------------------------------------------------------------------------------------------
# The recorded base of .github/workflows/codeql.yml at 1d2ae3d (fixed values, so a shallow checkout
# or the staged copy checks them without git history), and the one job this unit appends.

BASELINE_WORKFLOW_BYTES = 2309
BASELINE_WORKFLOW_SHA256 = "d56b36ee5e4deaa48b4c074f7456b940be6730ce7bc44ea3ac3cfc2168c906a6"
BASELINE_JOB_SHA256 = {
    "analyze": "3843172453a5a965f41b878766af9b2bb313efa5ac41221bb9d47284925e3a13",
    "host-ingress-proof": "6c5f0f58d512a5e43df1648594b9d324aa88b561d95d3fa307901df63b296b70",
    "host-lease-feasibility": "dc1653f586afaf5f86f473866be32d4d1f51426af271c56308ae26198f2bd0c5",
}
LEASE_BLOCK_BYTES = 1649
EXPECTED_JOBS = ["analyze", "host-ingress-proof", "host-lease-feasibility", "host-authority-proof"]
AUTHORITY_GATE = ("if: github.event_name == 'workflow_dispatch' && "
                  "github.ref == 'refs/heads/codex/self-serve-host-authority-proof'")
CHECKOUT = "actions/checkout@11d5960a326750d5838078e36cf38b85af677262"
SETUP_PYTHON = "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065"
UPLOAD = "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
AUTHORITY_JOB = f"""  host-authority-proof:
    # H1A-1: the isolated lease-domain and host-authority transport proof on a disposable Linux VM.
    # Manual dispatch of the literal reviewed proof branch only; no parameters, credentials or saved state.
    # The fixed launcher (docs/saas/HOST_AUTHORITY_PROOF.md) owns every runtime input and its hash.
    name: host-authority-proof (authority-v1)
    {AUTHORITY_GATE}
    runs-on: ubuntu-24.04
    timeout-minutes: 25
    permissions:
      contents: read
    concurrency:
      group: host-authority-proof
      cancel-in-progress: false
    steps:
      - uses: {CHECKOUT} # v4
        with:
          ref: ${{{{ github.sha }}}}
          persist-credentials: false
      - uses: {SETUP_PYTHON} # v5
        with:
          python-version: "3.13.5"
      - name: Fixed authority-v1 launcher (20-minute budget, tests 10 minutes)
        timeout-minutes: 20
        run: python scripts/host_authority_proof.py
      - name: Upload allowlisted safe evidence
        if: always()
        uses: {UPLOAD} # v4
        with:
          name: host-authority-proof
          if-no-files-found: error
          retention-days: 3
          path: |
            host-authority-proof/summary.json
            host-authority-proof/cases.jsonl
            host-authority-proof/versions.txt
            host-authority-proof/cleanup.json
            host-authority-proof/report.txt
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


def authority_job_violations(job: str, allowed_uses: set[str]) -> list[str]:
    """Every line form of the appended job, matched as full lines (no substring or bare-step gaps)."""
    found = []
    checks = {
        "gate": _lines(r"\s*(?:- )?if: .*", job) == [f"    {AUTHORITY_GATE}", "        if: always()"],
        "runs_on": _lines(r"\s*runs-on: .*", job) == ["    runs-on: ubuntu-24.04"],
        "timeouts": _lines(r"\s*timeout-minutes: .*", job) == ["    timeout-minutes: 25", "        timeout-minutes: 20"],
        "permissions": re.search(r"^    permissions:\n      contents: read\n    concurrency:\n      group: "
                                 r"host-authority-proof\n      cancel-in-progress: false\n    steps:\n", job, re.M) is not None
        and _lines(r"\s*permissions:.*", job) == ["    permissions:"] and _lines(r"\s*contents: .*", job) == ["      contents: read"],
        "steps": _lines(r"      - .*", job) == [f"      - uses: {CHECKOUT} # v4", f"      - uses: {SETUP_PYTHON} # v5",
                                                "      - name: Fixed authority-v1 launcher (20-minute budget, tests 10 minutes)",
                                                "      - name: Upload allowlisted safe evidence"],
        "run": _lines(r"\s*(?:- )?run:.*", job) == ["        run: python scripts/host_authority_proof.py"],
        "checkout": _lines(r"\s*ref: .*", job) == ["          ref: ${{ github.sha }}"]
        and _lines(r"\s*persist-credentials: .*", job) == ["          persist-credentials: false"],
        "python": _lines(r"\s*python-version: .*", job) == ['          python-version: "3.13.5"'],
        "uses": set(re.findall(r"uses: (\S+)", job)) <= allowed_uses
        and set(re.findall(r"uses: (\S+)", job)) == {CHECKOUT, SETUP_PYTHON, UPLOAD},
        "artifacts": tuple(re.findall(r"^            host-authority-proof/(\S+)$", job, re.M)) == LAUNCHER.ARTIFACT_FILES
        and _lines(r"\s*path: .*", job) == ["          path: |"],
        "upload": _lines(r"\s*retention-days: .*", job) == ["          retention-days: 3"]
        and _lines(r"\s*if-no-files-found: .*", job) == ["          if-no-files-found: error"]
        and _lines(r"\s*name: host-authority-proof.*", job) == ["    name: host-authority-proof (authority-v1)",
                                                                "          name: host-authority-proof"],
    }
    found += [name for name, ok in checks.items() if not ok]
    for word in ("write", "id-token", "environment:", "cache", "env:", "secrets", "pull_request", "github.token", "inputs",
                 "services:", "container:", "workflow_call", "continue-on-error"):
        if word in job:
            found.append("forbidden_" + re.sub(r"[^a-z]", "_", word))
    return found


def workflow_violations(text: str) -> list[str]:
    """Empty iff codeql.yml is exactly the recorded base, then the unchanged lease block, then the
    one fully constrained authority job, with no other byte anywhere."""
    found = []
    data = text.encode("utf-8")
    if not data.isascii() or hashlib.sha256(data[:BASELINE_WORKFLOW_BYTES]).hexdigest() != BASELINE_WORKFLOW_SHA256:
        found.append("baseline_head")
    if text.count("\njobs:\n") != 1:
        return found + ["job_names"]
    names = re.findall(r"^  ([A-Za-z0-9_-]+):\n", text.split("\njobs:\n", 1)[1], re.M)  # keys under jobs: only
    if names != EXPECTED_JOBS:
        return found + ["job_names"]
    blocks = {name: _job_block(text, name) for name in EXPECTED_JOBS}
    found += ["block_" + name for name, digest in BASELINE_JOB_SHA256.items()
              if hashlib.sha256(blocks[name].encode()).hexdigest() != digest]
    if len(blocks["host-lease-feasibility"].encode()) != LEASE_BLOCK_BYTES:
        found.append("lease_block_size")
    if text != text[:BASELINE_WORKFLOW_BYTES] + "\n" + blocks["host-lease-feasibility"] + "\n" + blocks["host-authority-proof"]:
        found.append("composition")
    if ("\npermissions: {}\n" not in text or "pull_request_target" in text or "secrets." in text or "inputs:" in text
            or "workflow_dispatch: {}" not in text):
        found.append("workflow_head_policy")
    if not all(re.fullmatch(r"[a-z-]+/[a-z-]+(?:/[a-z-]+)?@[0-9a-f]{40}", uses) for uses in re.findall(r"uses: (\S+)", text)):
        found.append("unpinned_action")
    allowed = set(re.findall(r"uses: (\S+)", text[:BASELINE_WORKFLOW_BYTES] + blocks["host-lease-feasibility"]))
    found += authority_job_violations(blocks["host-authority-proof"], allowed)
    if blocks["host-authority-proof"] != AUTHORITY_JOB:
        found.append("authority_job_text")
    return found


# ---------------------------------------------------------------------------------------------
# Probes and oracles (H1F's measurement model; the dynamic cases grade with these functions).

@dataclass
class Probe:
    index: int
    t_before: int
    t_after: int
    admitted: bool
    error: str = "ok"
    recv_ns: int | None = None

    @property
    def delivered(self) -> bool:
        return self.recv_ns is not None

    @property
    def accepted(self) -> bool:
        return self.admitted or self.delivered


def admitted_after(probes: list[Probe], bound_ns: int) -> list[Probe]:
    return [probe for probe in probes if probe.accepted and probe.t_before > bound_ns]


def admitted_before(probes: list[Probe], bound_ns: int) -> list[Probe]:
    return [probe for probe in probes if probe.accepted and probe.t_after < bound_ns]


def inside(probes: list[Probe], start_ns: int, end_ns: int) -> list[Probe]:
    return [probe for probe in probes if probe.t_before >= start_ns and probe.t_after <= end_ns]


def anomalies(probes: list[Probe]) -> int:
    return sum(probe.delivered and not probe.admitted for probe in probes)


def live_delivery(probes: list[Probe], start_ns: int, end_ns: int, minimum: int) -> bool:
    window = inside(probes, start_ns, end_ns)
    return (len(window) >= minimum and 100 * sum(p.admitted for p in window) >= LIVE_PERCENT * len(window)
            and 100 * sum(p.delivered for p in window) >= LIVE_PERCENT * len(window))


def closed(window: list[Probe]) -> bool:
    """A non-empty window with zero admissions and no anomaly (no allowance of any kind)."""
    return len(window) > 0 and not [p for p in window if p.accepted] and anomalies(window) == 0


def ms_ceil(ns: int) -> int:
    return -(-ns // MS)


def ms_floor(ns: int) -> int:
    return ns // MS


def record(case: str, ok: bool, ints: dict, tokens: dict) -> None:
    entry = {"case": case, "verdict": "pass" if ok else "fail", "control": LAUNCHER.RECORD_CASES[case][1],
             "ints": dict(ints), "tokens": dict(tokens)}
    assert LAUNCHER.sanitize_record(entry) is not None, f"record {case} is outside the closed grammar"
    with open(os.environ[LAUNCHER.RECORDS_ENV], "a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, sort_keys=True) + "\n")


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


def _keyword_users(source: str, keyword: str) -> set[str]:
    """Top-level functions (or "<module>") whose calls pass ``keyword=``."""
    tree = ast.parse(source)
    users = set()
    for node in tree.body:
        owner = node.name if isinstance(node, (ast.FunctionDef, ast.ClassDef)) else "<module>"
        if any(k.arg == keyword for call in ast.walk(node) if isinstance(call, ast.Call) for k in call.keywords):
            users.add(owner)
    return users


def test_static_required_profile_cannot_skip():
    """One guarded skip path, unreachable with HEEL_REQUIRE_HOST_AUTHORITY_PROOF=1, and every dynamic
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
    assert cases[-1] == "test_c2_no_owned_namespace_process_socket_mount_or_link_survives"
    recorded = {}
    for name in cases:
        for call in _calls(functions[name], "record"):
            assert isinstance(call.args[0], ast.Constant), name
            assert call.args[0].value not in recorded, call.args[0].value
            recorded[call.args[0].value] = name
    assert recorded == {case: item[0] for case, item in LAUNCHER.RECORD_CASES.items()}
    assert {item[1] for item in LAUNCHER.RECORD_CASES.values()} <= set(LAUNCHER.CONTROLS)
    assert "cycle" in LAUNCHER.CONTROLS
    assert sorted(case for case, item in LAUNCHER.RECORD_CASES.items() if item[1] == "negative") == ["d2", "t4n"]
    assert {item[2] for item in LAUNCHER.RECORD_CASES.values()} == {"pass"}
    # H1ADR: D1-D6, K8, T1-T3, the five-case T4 family and C2, nothing optional.
    assert set(LAUNCHER.RECORD_CASES) == {"k8", "d1", "d2", "d3", "d4", "d5", "d6", "t1", "t2", "t3", "t4", "t4n", "t4f",
                                          "t4r", "t4s", "s1", "s2", "s3", "s4", "s5", "s6", "c2"}
    # The T4-family connector: a success waits for the peer's EOF under one bounded drain, EAGAIN is
    # named before the catch-all, nothing sleeps, and the fixed workload is unchanged.
    program = ast.parse(CONNECTOR)
    kinds = [node.value for node in program.body if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", None) == "kinds"]
    assert [ast.literal_eval(value) for value in kinds] == [CONNECTOR_KINDS]
    (attempt,) = [node for node in ast.walk(program) if isinstance(node, ast.Try) and _calls(node, "connect")]
    assert [ast.unparse(statement) for statement in attempt.body] == ["client.connect(path)"]
    assert [ast.unparse(handler.type) for handler in attempt.handlers] == [
        "FileNotFoundError", "ConnectionRefusedError", "PermissionError", "BlockingIOError", "OSError"]
    assert [ast.unparse(statement) for statement in attempt.orelse] == [
        "cause = drain(client)", "kind = 'success' if cause is None else 'unanswered'"]
    drain = ast.get_source_segment(CONNECTOR, _functions(CONNECTOR)["drain"])
    assert "until, wrote = min(time.monotonic() + 2, deadline), False" in drain and "client.recv(64)" in drain
    assert "sleep" not in CONNECTOR and "deadline = time.monotonic() + 20" in CONNECTOR
    assert 'Child(CONNECTOR, (str(path), "2000", "20"))' in ast.get_source_segment(module, functions["_connector"])
    # Each case reads only reported keys, records all of them, and requires no EAGAIN, other or
    # unanswered outcome over the whole run and reconciled totals.
    for name in ("test_t4_publication_has_no_refused_window", "test_t4n_wrong_order_publisher_shows_refused_window",
                 "test_t4s_stale_socket_file_is_replaced_by_a_listening_inode"):
        node = functions[name]
        read = {sub.slice.value for sub in ast.walk(node) if isinstance(sub, ast.Subscript)
                and getattr(sub.value, "id", None) == "done"}
        assert read and read <= set(CONNECTOR_INTS), (name, read - set(CONNECTOR_INTS))
        assert len(_calls(node, "_connector_record")) == 1, name
        (call,) = _calls(node, "record")
        assert ast.unparse(call.args[2]).startswith("ints") and ast.unparse(call.args[3]).startswith("tokens"), name
        source = ast.get_source_segment(module, node)
        for term in ('done["n_eagain"] == 0', 'done["n_other"] == 0', 'done["n_unanswered"] == 0', 'ints["totals_reconciled"]'):
            assert term in source, (name, term)


def test_static_launcher_has_one_fixed_profile_fixed_budgets_and_no_inputs(tmp_path, capsys):
    source = LAUNCHER_FILE.read_text(encoding="utf-8")
    assert LAUNCHER.main(["--anything"]) == 2
    capsys.readouterr()
    assert "argparse" not in source and source.count("sys.argv") == 1 and "os.environ.get(\"RUNNER_TEMP\")" in source
    assert (LAUNCHER.LAUNCHER_SECONDS, LAUNCHER.TESTS_SECONDS, LAUNCHER.CLEANUP_RESERVE_SECONDS) == (1200, 600, 60)
    assert '["sudo", "-n", "--", sys.executable, "-I", str(Path(__file__).resolve())]' in source
    assert LAUNCHER.PROFILE == "authority-v1" and LAUNCHER.RUNTIME_ASSUMPTION == "running-kernel"
    assert LAUNCHER.ARTIFACT_FILES == ("summary.json", "cases.jsonl", "versions.txt", "cleanup.json", "report.txt")
    base = Path(os.path.realpath(tmp_path)) / "heel-host-authority-static"
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
    for mutation in ({"extra": 1}, {"schema": "heel.host-lease-feasibility.child.v1"}, {"uid": True}, {"uid": 0},
                     {"tests_seconds": 601}, {"tests_seconds": 5.0}, {"token": "0123456789ABCDEF0123456789ABCDEF"},
                     {"out": str(base)}, {"wheels": str(wheels) + "/"}, {"out": "relative/out"}):
        assert LAUNCHER.validated_request(json.dumps({**good, **mutation})) is None, mutation
    assert LAUNCHER.validated_request("[]") is None and LAUNCHER.validated_request("{") is None
    os.chmod(out, 0o770)
    assert LAUNCHER.validated_request(json.dumps(good)) is None


def test_static_profile_pin_and_closure_are_imported_from_h1f_not_copied():
    h1f = LAUNCHER.h1f()
    for name in ("PYTEST_CLOSURE", "PYTHON_VERSION", "PYTEST_VERSION", "FIXED_PATH", "HOST_TOOLS", "ProofFailure"):
        assert getattr(LAUNCHER, name) is getattr(h1f, name), name
    for name in ("SUPPORTED_KERNELS", "READD_EXPECTED", "kernel_profile"):
        assert getattr(LAUNCHER, name) is getattr(LAUNCHER.profile(), name), name
    assert PROFILE.SUPPORTED_KERNELS == h1f.SUPPORTED_KERNELS and PROFILE.READD_EXPECTED == h1f.READD_EXPECTED
    assert CYCLE.authority is AUTHORITY and CYCLE.profile is PROFILE and CYCLE.codec is LISTENER
    source = LAUNCHER_FILE.read_text(encoding="utf-8")
    for literal in ('"6.17"', '"refresh"', '"noop"', "files.pythonhosted.org", "711ffd45bf766d52"):
        assert literal not in source, literal
    LAUNCHER.h1f().closure_matches_lock(json.loads(H0_LOCK.read_text(encoding="utf-8")))
    for module in (source, Path(__file__).read_text(encoding="utf-8"), AUTHORITY_FILE.read_text(encoding="utf-8")):
        for forbidden in ("apt" + "-get", "apt" + " install", "dn" + "f ", "modpr" + "obe", "pip" + " install"):
            assert forbidden not in module, forbidden


def test_static_workflow_keeps_existing_blocks_and_fully_constrains_the_authority_job():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert workflow_violations(text) == []
    base = text[:BASELINE_WORKFLOW_BYTES] + "\n" + _job_block(text, "host-lease-feasibility")
    assert "job_names" in workflow_violations(base)
    assert "forbidden_write" in workflow_violations(text.replace("      contents: read\n    concurrency:\n      group: "
                                                                 "host-authority-proof", "      contents: write\n    concurrency:\n"
                                                                 "      group: host-authority-proof"))
    assert workflow_violations(text + "# trailing\n") != []
    assert workflow_violations(text.replace("\n  host-authority-proof:", "\n# between\n  host-authority-proof:")) != []


def _root_reads(source: str) -> set[str]:
    return {"/".join(re.findall(r'"([^"\n]+)"', chain)) for chain in re.findall(r'ROOT((?:\s*/\s*"[^"\n]+")+)', source)}


def test_static_launcher_stages_every_path_the_module_reads(tmp_path):
    """The child copies a fixed file list; everything this module and the launcher read under ROOT is
    in it, and the static selection passes from an exact staged copy (no git, no other files)."""
    module = Path(__file__).read_text(encoding="utf-8")
    reads = _root_reads(module) | (_root_reads(LAUNCHER_FILE.read_text(encoding="utf-8")) - {"host-authority-proof"})
    reads.discard(".git")  # only probed below, to tell the checkout from the staged copy
    assert reads <= set(LAUNCHER.STAGE_FILES), sorted(reads - set(LAUNCHER.STAGE_FILES))
    assert len(LAUNCHER.STAGE_FILES) == len(set(LAUNCHER.STAGE_FILES)) == 14
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


def test_static_evidence_sanitizer_and_acceptance_rule(tmp_path, monkeypatch):
    good = {"case": "d3", "verdict": "pass", "control": "domain", "ints": {"spawned_during_refusal": 0},
            "tokens": {"refusal": "domain_exhausted"}}
    assert LAUNCHER.sanitize_record(good) == good
    for entry in ({**good, "extra": 1}, {**good, "case": "a1"}, {**good, "control": "negative"}, {**good, "verdict": "info"},
                  {**good, "ints": {"flag": True}}, {**good, "tokens": {"path": "/tmp/x"}}, {**good, "tokens": {"t": "a b"}},
                  {**good, "ints": {f"k{i}": i for i in range(65)}}, "not a dict"):
        assert LAUNCHER.sanitize_record(entry) is None, entry
    raw = tmp_path / "records.raw.jsonl"
    raw.write_text(json.dumps(good) + "\nnot json\n", encoding="utf-8")
    assert LAUNCHER.sanitize_records(raw) == ([good], 1)
    records = [{"case": case, "verdict": "pass", "control": item[1], "ints": {}, "tokens": {}}
               for case, item in LAUNCHER.RECORD_CASES.items()]
    by = {r["case"]: r for r in records}
    by["k8"]["tokens"] = {"kernel_major_minor": "6.17", "nft_version": "1.0.9", "selftest": "pass", "readd_observation": "refresh"}
    by["k8"]["ints"] = {"config_hz": 1000}
    junit = {"collected": len(LAUNCHER.REQUIRED_CASES), "passed": len(LAUNCHER.REQUIRED_CASES), "failed": 0, "errors": 0,
             "skipped": 0, "case_functions": list(LAUNCHER.REQUIRED_CASES), "failing": [], "failure_locators": []}
    cleanup, inner = {"host_fingerprints_unchanged": True}, {"pytest_exit": 0, "leftover_processes": 0}
    assert LAUNCHER.evaluate(junit, records, 0, cleanup, inner, 0)["result"] == "PASS"
    by["k8"]["tokens"]["readd_observation"] = "noop"
    assert LAUNCHER.evaluate(junit, records, 0, cleanup, inner, 0)["result"] == "INCOMPLETE"
    by["k8"]["tokens"]["readd_observation"] = "refresh"
    assert LAUNCHER.evaluate({**junit, "passed": junit["passed"] - 1, "skipped": 1}, records, 0, cleanup, inner, 0)["result"] == "FAIL"
    assert LAUNCHER.evaluate(junit, records[1:], 0, cleanup, inner, 0)["result"] == "FAIL"
    assert LAUNCHER.evaluate(junit, records, 0, cleanup, {**inner, "leftover_processes": 1}, 0)["result"] == "FAIL"
    by["t4n"]["verdict"] = "fail"
    assert LAUNCHER.evaluate(junit, records, 0, cleanup, inner, 0)["result"] == "FAIL"
    lines = LAUNCHER.version_lines(by, "pinned") + LAUNCHER.report_lines({"result": "PASS", "records": records}, None, cleanup)
    assert "runtime_assumption running-kernel" in lines and "kernel_profile pinned" in lines
    assert all(re.fullmatch(r"[a-z0-9_]+ [A-Za-z0-9_.:/ -]*", line) for line in lines), lines
    # Every generation class the cycle can end with is recorded as a closed token (H1A3-2R S4: raw "A" was rejected).
    classes = set()
    for node in ast.walk(ast.parse((ROOT / "deploy" / "host" / "cycle.py").read_text(encoding="utf-8"))):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                pairs = (zip(target.elts, node.value.elts) if isinstance(target, ast.Tuple) and isinstance(node.value, ast.Tuple)
                         else [(target, node.value)])
                classes |= {value.value for slot, value in pairs if isinstance(slot, ast.Attribute) and slot.attr == "_class_end"
                            and isinstance(slot.value, ast.Name) and slot.value.id == "self" and isinstance(value, ast.Constant)}
        elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "_close_generation"
              and node.args and isinstance(node.args[0], ast.Constant)):
            classes.add(node.args[0].value)
    assert classes == {"none", "start_refused", "A", "B", "C"}, classes
    assert all(LAUNCHER._TOKEN.fullmatch(_class_token(value)) for value in classes), {v: _class_token(v) for v in classes}
    assert _class_token("A") == "a"
    path = tmp_path / "s4.jsonl"
    monkeypatch.setenv(LAUNCHER.RECORDS_ENV, str(path))
    s4_tokens = {"outcome": "key_revoked", "k9_path": "scripted", "context_end": "key_revoked", "third_tick": "closed"}
    write = record  # the real writer; a direct record("s4") call is the S4 case's own (inventory static)
    for value in sorted(classes):
        write("s4", True, {"after_close_probes": 1, "activated_entries": 0}, {**s4_tokens, "class_end": _class_token(value)})
    kept, dropped = LAUNCHER.sanitize_records(path)
    assert (len(kept), dropped) == (5, 0) and {r["tokens"]["class_end"] for r in kept} == {"none", "start_refused", "a", "b", "c"}
    assert LAUNCHER.sanitize_record({**kept[0], "tokens": {**kept[0]["tokens"], "class_end": "A"}}) is None
    # The real S4 emission goes through the helper; no S case records the raw class.
    functions = _top_functions(Path(__file__).read_text(encoding="utf-8"))
    s4 = [call for call in _calls(functions["test_s4_revocation_closes_the_generation_and_no_request_follows"], "record")
          if call.args and isinstance(call.args[0], ast.Constant) and call.args[0].value == "s4"]
    assert len(s4) == 1 and isinstance(s4[0].args[3], ast.Dict), s4
    end = dict(zip([key.value for key in s4[0].args[3].keys], s4[0].args[3].values))["class_end"]
    assert (isinstance(end, ast.Call) and isinstance(end.func, ast.Name) and end.func.id == "_class_token" and not end.keywords
            and len(end.args) == 1 and isinstance(end.args[0], ast.Subscript) and isinstance(end.args[0].value, ast.Name)
            and end.args[0].value.id == "status" and isinstance(end.args[0].slice, ast.Constant)
            and end.args[0].slice.value == "generation_class_end"), ast.dump(end)
    raw = [ast.dump(value) for name, node in functions.items() if re.match(r"test_s[1-6]_", name)
           for call in _calls(node, "record") if len(call.args) > 3 and isinstance(call.args[3], ast.Dict)
           for value in call.args[3].values if isinstance(value, ast.Subscript) and isinstance(value.slice, ast.Constant)
           and value.slice.value == "generation_class_end"]
    assert raw == [], raw


def test_static_seams_are_labelled_and_confined_to_their_cases():
    module = Path(__file__).read_text(encoding="utf-8")
    authority = AUTHORITY_FILE.read_text(encoding="utf-8")
    listener = LISTENER_FILE.read_text(encoding="utf-8")
    launcher = LAUNCHER_FILE.read_text(encoding="utf-8")
    unit = UNIT_TESTS.read_text(encoding="utf-8")
    for label in ("SEAM-COUNTER-START d3 only", "SEAM-NAMED-NAMESPACE d2 negative only", "SEAM-WRONG-ORDER t4n negative only",
                  "SEAM-LISTEN-FAILURE t4f only"):
        assert any(label in seam for seam in LAUNCHER.SEAMS) and label in module, label
    assert "SEAM-COUNTER-START d3 only" in authority and "SEAM-LISTEN-FAILURE t4f only" in listener
    # The counter seam: only the D3 case passes ``_counter=``, nothing in production or the unit tests.
    assert _keyword_users(module, "_counter") == {"test_d3_counter_bound_refuses_before_any_process_is_spawned"}
    for source in (authority, listener, launcher, unit):
        assert _keyword_users(source, "_counter") == set()
    # The listen seam: never passed by production code.
    for source in (authority, listener, launcher):
        assert _keyword_users(source, "_listen_for_tests") == set()
    assert _keyword_users(module, "_listen_for_tests") == {"test_t4f_listen_failure_leaves_the_working_endpoint"}
    functions = _top_functions(module)
    named = {name for name, node in functions.items() if not name.startswith("test_static_")
             and any(isinstance(arg, ast.Constant) and arg.value == "name" for call in _calls(node, "StaleWriter")
                     for arg in call.args)}
    assert named == {"test_d2_named_namespace_re_resolution_revives_a_key"}
    wrong = {name for name, node in functions.items() if not name.startswith("test_static_") and _calls(node, "_wrong_order_publisher")}
    assert wrong == {"test_t4n_wrong_order_publisher_shows_refused_window"}
    # The three cycle seams: labelled, passed only by the S-case fixture, which only the six S cases call.
    for label in ("SEAM-SCRIPTED-DECIDER s-cases only", "SEAM-CYCLE-SLEEP-REPORT s-cases only",
                  "SEAM-CYCLE-DOMAIN-REGISTER s-cases only"):
        assert any(label in seam for seam in LAUNCHER.SEAMS) and label in module, label
    assert _keyword_users(module, "_seams_for_tests") == {"_cycle_fixture"}
    fixture_users = {name for name, node in functions.items() if _calls(node, "_cycle_fixture")}
    assert fixture_users == {name for name in LAUNCHER.REQUIRED_CASES if re.match(r"test_s[1-6]_", name)}
    assert len(fixture_users) == 6
    for source in (authority, listener, launcher, unit):
        assert "_seams_for_tests" not in source


def test_static_production_has_no_named_namespace_raw_mark_api_or_wrong_publication_order():
    authority = AUTHORITY_FILE.read_text(encoding="utf-8")
    listener = LISTENER_FILE.read_text(encoding="utf-8")
    for source in (authority, listener):
        for forbidden in ("/run/netns", "ip netns", "nsenter", "multiprocessing", "pickle", "sqlite", "http_api", "canary_runs",
                          "os.environ", "getenv", "allow_"):
            assert forbidden not in source, forbidden
    assert "_for_tests" not in authority and "subprocess" not in ast.get_source_segment(authority, _functions(authority)["_spawn"])
    # Publication: the only rename in the listener follows listen in the only publication function.
    functions = _functions(listener)
    publish = ast.get_source_segment(listener, functions["_publish"])
    assert listener.count("os.rename(") == 1 and "os.rename(" in publish and "os.rename" not in authority
    assert publish.index("sock.bind(tmp)") < publish.index("os.chmod(tmp, 0o600)") < publish.index("sock.listen(BACKLOG)")
    assert publish.index("sock.listen(BACKLOG)") < publish.index("os.rename(tmp, path)") < publish.index("published = os.lstat(path)")
    # The prepared set is written only with create; the one non-EXCL re-add is the labelled self-test fixture.
    assert authority.count("create element") == 1 and "create element" in ast.get_source_segment(
        authority, _functions(authority)["_render_prepare"])
    add_prepared = [name for name, node in _functions(authority).items()
                    if "add element inet {TABLE} {PREPARED_SET}" in ast.get_source_segment(authority, node)]
    assert add_prepared == ["_selftest_readd_batch"]
    users = {name for name, node in _functions(authority).items() if _calls(node, "_selftest_readd_batch")}
    assert users == {"generation_self_test"}
    assert "timeout" not in ast.get_source_segment(authority, _functions(authority)["_render_activate"])
    # No public callable accepts a mark (PreparedKey refuses construction without the private seal);
    # the ownership check has no parameter but self.
    for name in AUTHORITY.__all__:
        target = getattr(AUTHORITY, name)
        if target is AUTHORITY.PreparedKey:
            continue
        members = [getattr(target, attr) for attr in dir(target) if not attr.startswith("_")] if isinstance(target, type) else [target]
        for member in members:
            if callable(member) and not isinstance(member, type):
                with contextlib.suppress(TypeError, ValueError):
                    assert "mark" not in inspect.signature(member).parameters, (name, member)
    assert "_MarkCounter" not in AUTHORITY.__all__
    assert [arg.arg for arg in _functions(authority)["_assert_owner"].args.args] == ["self"]


def test_static_doc_names_every_case_and_the_limits():
    doc = DOC.read_text(encoding="utf-8")
    for case in LAUNCHER.RECORD_CASES:
        assert f"**{case.upper()}**" in doc, case
    for phrase in ("INCOMPLETE", "kernel_profile pinned", "runtime_assumption running-kernel", "NOT RUN", "M3",
                   "python scripts/host_authority_proof.py", "bind, chmod and verify, listen, rename, verify",
                   "fourteen", "t_before", "STATE-MACHINE ONLY", "no allowance", *[seam.split(":")[0] for seam in LAUNCHER.SEAMS]):
        assert phrase in doc, phrase


# ---------------------------------------------------------------------------------------------
# Runtime guard (the single skip path).

def _runtime_unavailable_reason() -> str | None:
    if not sys.platform.startswith("linux"):
        return "requires the fixed host-authority launcher on Linux"
    if sys.version_info < (3, 12) or not hasattr(os, "setns") or not hasattr(os, "unshare"):
        return "requires the launcher's pinned Python with namespace support"
    if os.geteuid() != 0:
        return "requires the launcher's isolated namespace driver"
    if not all(os.environ.get(name) for name in (LAUNCHER.RECORDS_ENV, LAUNCHER.WORK_ENV, LAUNCHER.TOKEN_ENV)):
        return "requires the fixed host-authority launcher environment"
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


_TICK: list[int] = []


def _tick_ns() -> int:
    """One kernel tick (an expiry-granularity fact, never an allowance); unknown HZ uses 10 ms."""
    if not _TICK:
        hz = AUTHORITY._config_hz(os.uname().release)
        _TICK.append(-(-1_000_000_000 // hz) if hz else 10 * MS)
    return _TICK[0]


def _sentinel_pid() -> int:
    """Fork and reap one process: its PID is the next one the private PID namespace allocates, so
    the difference of two sentinels counts every process created between them."""
    pid = os.fork()
    if pid == 0:
        os._exit(0)
    os.waitpid(pid, 0)
    return pid


# ---------------------------------------------------------------------------------------------
# Fixed child programs (no caller-supplied code; argv is fixed by the cases).

HOLDER = "import json, sys\nprint(json.dumps({'event': 'ready'}), flush=True)\nsys.stdin.read()\n"

# A stale writer bound to a namespace. Mode "fd": it entered the namespace of an inherited
# descriptor at start (the production binding). Mode "name" (SEAM-NAMED-NAMESPACE d2 negative only):
# it resolves a path at write time, the re-resolution the FD rule forbids.
STALE_WRITER = r'''
import json, os, subprocess, sys, time
mode, target, nft = sys.argv[1], sys.argv[2], sys.argv[3]
def say(**fields):
    sys.stdout.write(json.dumps(fields) + "\n")
    sys.stdout.flush()
def identity():
    info = os.stat("/proc/self/ns/net")
    return [info.st_dev, info.st_ino]
if mode == "fd":
    os.setns(int(target), 0x40000000)  # keeps the inherited descriptor open, as a real helper does
say(event="ready", pid=os.getpid(), identity=identity())
line = sys.stdin.readline().split()
if len(line) != 2 or line[0] != "release":
    sys.exit(3)
if mode == "name":
    fd = os.open(target, os.O_RDONLY)
    os.setns(fd, 0x40000000)
    os.close(fd)
t_pp = time.monotonic_ns()
done = subprocess.run([nft, "-f", line[1]], capture_output=True)
t_pq = time.monotonic_ns()
listing = subprocess.run([nft, "list", "map", "inet", "heel_lease", "activated"], capture_output=True, text=True)
say(event="committed", rc=done.returncode, t_pp=t_pp, t_pq=t_pq, identity=identity(), listing=listing.stdout[-2000:])
sys.stdin.readline()
'''

# D4's first generation as its own process: the real API, then one stale helper holding its fd.
GENERATION = r'''
import importlib.util, json, os, subprocess, sys
authority_file, writer, nft = sys.argv[1], sys.argv[2], sys.argv[3]
def say(**fields):
    sys.stdout.write(json.dumps(fields) + "\n")
    sys.stdout.flush()
spec = importlib.util.spec_from_file_location("d4_authority", authority_file)
authority = importlib.util.module_from_spec(spec)
spec.loader.exec_module(authority)
domain = authority.LeaseDomain.create()
fd = domain.ns_fd
table = subprocess.run([nft, "-f", "-"], input=authority._gate_table_fixture(), capture_output=True,
                       preexec_fn=lambda: os.setns(fd, 0x40000000))
handle = domain.prepare("198.51.100.10", "203.0.113.10", 3000)
domain.activate(handle)
helper = subprocess.Popen([sys.executable, "-I", "-c", writer, "fd", str(fd), nft], pass_fds=(fd,), close_fds=True)
say(event="generation", identity=list(domain.ns_identity), mark=handle.mark, helper=helper.pid, fd=fd, table=table.returncode)
while True:
    os.pause()
'''

LISTENER_PROGRAM = r'''
import importlib.util, json, os, socket, struct, sys, threading
listener_file, path, profile, uid, request = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5]
def say(**fields):
    sys.stdout.write(json.dumps(fields) + "\n")
    sys.stdout.flush()
os.unshare(0x20000000)
child = os.fork()
if child:
    say(event="forked", outer_pid=child)
    _pid, status = os.waitpid(child, 0)
    os._exit(0 if os.waitstatus_to_exitcode(status) == 0 else 1)
go_r, go_w = os.pipe()
inside = os.fork()
if inside == 0:
    os.close(go_w)
    if os.read(go_r, 1) != b"g":
        os._exit(0)
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(10)
    client.connect(path)
    pid, peer_uid, _gid = struct.unpack("3i", client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    body = request.encode()
    data, outcome = b"", "eof"
    try:
        client.sendall(b"POST /host/v1/authority-snapshot HTTP/1.1\r\nContent-Type: application/json\r\n"
                       b"Content-Length: %d\r\n\r\n" % len(body) + body)
        while True:
            chunk = client.recv(65536)
            if not chunk:
                break
            data += chunk
    except ConnectionResetError:
        outcome = "reset"
    except BrokenPipeError:
        outcome = "reset"
    status = data.split(b"\r\n", 1)[0].decode("ascii", "replace") if data else "none"
    say(event="inside", self_pid=os.getpid(), view_pid=pid, view_uid=peer_uid, status=status, received=len(data),
        outcome=outcome)
    os._exit(0)
os.close(go_r)
os.setgroups([])
os.setresgid(uid, uid, uid)
os.setresuid(uid, uid, uid)
spec = importlib.util.spec_from_file_location("listener_under_test", listener_file)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
def decide(req):
    return {"schema_version": module.RESPONSE_SCHEMA, "decision": "inactive", "reason": "no_active_run",
            "sequence": req["sequence"], "request_digest": module.request_digest(req), "server_time_ms": 0,
            "kill_switch_generation": req["kill_switch_generation"]}
config = module.HostAuthorityConfig(path, 0, module.PeerProfile(profile))
listener = module.HostAuthorityListener(config, decide)
try:
    listener.start()
except module.HostAuthorityConfigurationError as error:
    say(event="refused_start", code=error.code)
    os._exit(1)
say(event="listening", pid=os.getpid(), uid=os.getuid(), inode=listener.own_inode[1])
thread = threading.Thread(target=listener.serve_forever, daemon=True)
thread.start()
for line in sys.stdin:
    if line.strip() == "inside":
        os.write(go_w, b"g")
    elif line.strip() == "stop":
        break
listener.close()
thread.join(5)
os.close(go_w)
os.waitpid(inside, 0)
say(event="stopped", **listener.counters)
os._exit(0)
'''

OUTSIDER = r'''
import json, os, socket, sys
uid, path = int(sys.argv[1]), sys.argv[2]
os.setgroups([])
os.setresgid(uid, uid, uid)
os.setresuid(uid, uid, uid)
client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    client.connect(path)
    reason = "connected"
except PermissionError:
    reason = "eacces"
except OSError:
    reason = "oserror"
print(json.dumps({"event": "refused" if reason != "connected" else "connected", "reason": reason}), flush=True)
'''

USERNS_CHECK = r'''
import importlib.util, json, os, sys
listener_file, path = sys.argv[1], sys.argv[2]
def say(**fields):
    sys.stdout.write(json.dumps(fields) + "\n")
    sys.stdout.flush()
os.unshare(0x10000000)
say(event="unshared", pid=os.getpid())
if sys.stdin.readline().strip() != "mapped":
    os._exit(3)
spec = importlib.util.spec_from_file_location("listener_userns", listener_file)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
try:
    module.check_startup(module.HostAuthorityConfig(path, 0, module.PeerProfile.EXTERNAL_PIDNS))
    say(event="result", code="accepted")
except module.HostAuthorityConfigurationError as error:
    say(event="result", code=error.code)
'''

CONNECTOR = r'''
import errno, json, re, socket, sys, time
path, minimum, need = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
# One mutually exclusive outcome per attempt; attempts is their sum. A connect counts as "success"
# only once the peer has accepted and closed it (EOF), otherwise "unanswered", so at most one of this
# program's connections ever waits in the listener's queue: the probe cannot fill the backlog it
# measures. Failed connects are not paced and sample the refused window as densely as before.
kinds = ("enoent", "econnrefused", "eacces", "eagain", "other", "success", "unanswered")
counts, after = dict.fromkeys(kinds, 0), dict.fromkeys(kinds, 0)
first = {"other": "none", "unanswered": "none"}
first_success, attempts, said = 0, 0, False
deadline = time.monotonic() + 20


def errno_token(error):
    if isinstance(error, socket.timeout) and error.errno is None:
        return "timeout"
    name = errno.errorcode.get(error.errno, "")
    return name.lower() if re.fullmatch(r"E[A-Z0-9]{1,30}", name) else "unknown"


def drain(client):
    # The T4-family peers close without writing (the real listener refuses this same-PID-namespace
    # peer before reading; the plain acceptors close on accept), so EOF is the acceptance signal.
    # Bounded reads, nothing kept, one absolute deadline: a peer that keeps writing cannot extend it.
    # Expiry is "deadline", or "deadline_after_data" if the peer wrote anything first.
    until, wrote = min(time.monotonic() + 2, deadline), False
    while True:
        left = until - time.monotonic()
        if left <= 0:
            return "deadline_after_data" if wrote else "deadline"
        client.settimeout(left)
        try:
            if not client.recv(64):
                return None
        except socket.timeout as error:
            if error.errno is None:
                return "deadline_after_data" if wrote else "deadline"
            return errno_token(error)
        except OSError as error:
            return errno_token(error)
        wrote = True


while time.monotonic() < deadline:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(2)
    cause = "none"
    try:
        client.connect(path)
    except FileNotFoundError:
        kind = "enoent"
    except ConnectionRefusedError:
        kind = "econnrefused"
    except PermissionError:
        kind = "eacces"
    except BlockingIOError as error:
        kind, cause = ("eagain", "none") if error.errno == errno.EAGAIN else ("other", errno_token(error))
    except OSError as error:
        kind, cause = "other", errno_token(error)
    else:
        cause = drain(client)
        kind = "success" if cause is None else "unanswered"
    finally:
        client.close()
    attempts += 1
    counts[kind] += 1
    if first_success:
        after[kind] += 1
    elif kind in ("success", "unanswered"):
        first_success = attempts
    if first.get(kind) == "none":
        first[kind] = cause
    if not said:
        sys.stdout.write(json.dumps({"event": "started"}) + "\n")
        sys.stdout.flush()
        said = True
    if attempts >= minimum and counts["success"] >= need:
        break
fields = {"event": "done", "attempts": attempts, "first_success": first_success}
fields.update({"n_" + k: v for k, v in counts.items()})
fields.update({"after_" + k: v for k, v in after.items()})
fields.update({"other_first_errno": first["other"], "unanswered_first": first["unanswered"]})
sys.stdout.write(json.dumps(fields) + "\n")
sys.stdout.flush()
'''
CONNECTOR_KINDS = ("enoent", "econnrefused", "eacces", "eagain", "other", "success", "unanswered")
CONNECTOR_INTS = ("attempts", "first_success", *(f"{prefix}_{kind}" for prefix in ("n", "after") for kind in CONNECTOR_KINDS))
CONNECTOR_TOKENS = ("other_first_errno", "unanswered_first")

STALE_SOCKET = "import socket, sys\nsocket.socket(socket.AF_UNIX, socket.SOCK_STREAM).bind(sys.argv[1])\n"

CHILDREN: list = []
OPEN_GATES: set = set()
DOMAINS: list = []
MOUNTS: list = []
SOCKETS: list = []
COUNTERS = {"gates": 0, "children": 0, "sockets": 0, "domains": 0, "cycles": 0, "deciders": 0}


class Child:
    """One fixed child program speaking one JSON object per line on stdout."""

    def __init__(self, program: str, argv: tuple = (), *, preexec=None, pass_fds: tuple = ()):
        self.process = subprocess.Popen([sys.executable, "-I", "-c", program, *argv], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=LAUNCHER._env(),
                                        preexec_fn=preexec, close_fds=True, pass_fds=pass_fds, text=True, bufsize=1)
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


def StaleWriter(mode: str, target: str, *, pass_fds: tuple = ()) -> Child:  # noqa: N802 - a fixture constructor
    child = Child(STALE_WRITER, (mode, target, AUTHORITY.NFT_PATH), pass_fds=pass_fds)
    return child


def _in_netns(fd: int, function):
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


def _domain(**seam) -> "AUTHORITY.LeaseDomain":
    domain = AUTHORITY.LeaseDomain.create(**seam)
    DOMAINS.append(domain)
    COUNTERS["domains"] += 1
    return domain


def _retire(domain) -> None:
    if not domain._closed:
        with contextlib.suppress(AUTHORITY.InstallerFailed):
            domain.close_generation()


class Gate:
    """The proof fixture around one domain: the H1F gate table installed into the domain's own
    namespace (by a dup of its descriptor) and one veth to a fresh receiver namespace R. The
    domain's API writes every element; the fixture never prepares or activates."""

    def __init__(self, domain):
        COUNTERS["gates"] += 1
        self.n = COUNTERS["gates"]
        self.domain = domain
        self.l_fd = os.dup(domain.ns_fd)
        self.r_fd: int | None = None
        self.holder: Child | None = None
        self.sockets: list = []
        self.batches = 0
        OPEN_GATES.add(self)
        try:
            self.holder = Child(HOLDER, preexec=lambda: os.unshare(CLONE_NEWNET))
            self.holder.expect("ready")
            self.r_fd = os.open(f"/proc/{self.holder.pid}/ns/net", os.O_RDONLY | os.O_CLOEXEC)
            self._wire()
            installed = self.nft(AUTHORITY._gate_table_fixture().decode())
            assert installed.returncode == 0, "fixture table install failed"
        except BaseException:
            self.close()
            raise

    def run(self, fd: int, argv: list[str], data: str | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(argv, input=data, capture_output=True, text=True, timeout=30, env=LAUNCHER._env(),
                              preexec_fn=lambda: os.setns(fd, CLONE_NEWNET))  # noqa: PLW1509

    def ip(self, fd: int, *arguments: str) -> None:
        completed = self.run(fd, [AUTHORITY.IP_PATH, *arguments])
        assert completed.returncode == 0, f"ip {arguments[0]} {arguments[1]} failed in the proof fixture"

    def _wire(self) -> None:
        a, b = f"ga{self.n}", f"gb{self.n}"
        mac = {"l": "02:48:41:%02x:%02x:0a" % (self.n >> 8 & 255, self.n & 255),
               "r": "02:48:41:%02x:%02x:0b" % (self.n >> 8 & 255, self.n & 255)}
        self.ip(self.l_fd, "link", "add", a, "address", mac["l"], "type", "veth", "peer", "name", b, "address", mac["r"])
        self.ip(self.l_fd, "link", "set", b, "netns", str(self.holder.pid))
        plan = ((self.l_fd, a, L_ADDR, R_ADDR, mac["r"]), (self.r_fd, b, R_ADDR, L_ADDR, mac["l"]))
        for fd, device, mine, _peer, _peer_mac in plan:
            self.ip(fd, "link", "set", "lo", "up")
            self.ip(fd, "addr", "add", f"{mine}/32", "dev", device)
            self.ip(fd, "link", "set", device, "up")
        for fd, device, mine, peer, peer_mac in plan:
            self.ip(fd, "route", "add", f"{peer}/32", "dev", device, "src", mine)
            self.ip(fd, "neigh", "replace", peer, "lladdr", peer_mac, "dev", device, "nud", "permanent")

    def nft(self, text: str) -> subprocess.CompletedProcess:
        return self.run(self.l_fd, [AUTHORITY.NFT_PATH, "-f", "-"], text)

    def prepared(self) -> dict[tuple[str, str, int], int]:
        listing = self.run(self.l_fd, [AUTHORITY.NFT_PATH, "list", "set", "inet", "heel_lease", "prepared"])
        return AUTHORITY._prepared_elements(listing.stdout) if listing.returncode == 0 else {}

    def activated(self) -> list[int]:
        listing = self.run(self.l_fd, [AUTHORITY.NFT_PATH, "list", "map", "inet", "heel_lease", "activated"])
        return parse_activated(listing.stdout) if listing.returncode == 0 else []

    def batch_file(self, data: bytes) -> str:
        self.batches += 1
        path = _work() / f"gate{self.n}-batch{self.batches}.nft"
        path.write_bytes(data)
        return str(path)

    def socket(self, side: str, *, bind: tuple) -> socket.socket:
        def create() -> socket.socket:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
                sock.bind(bind)
            except BaseException:
                sock.close()
                raise
            return sock

        sock = _in_netns(self.l_fd if side == "l" else self.r_fd, create)
        self.sockets.append(sock)
        SOCKETS.append(sock)
        COUNTERS["sockets"] += 1
        return sock

    def stream(self, *, start_ns: int, count: int) -> "ProbeStream":
        return ProbeStream(self, start_ns=start_ns, count=count)

    def close(self) -> None:
        for sock in self.sockets:
            with contextlib.suppress(OSError):
                sock.close()
        if self.holder is not None:
            with contextlib.suppress(OSError, ValueError):
                self.holder.process.stdin.close()
            self.holder.wait(5)
        for fd in (self.l_fd, self.r_fd):
            if fd is not None:
                with contextlib.suppress(OSError):
                    os.close(fd)
        self.l_fd = self.r_fd = None
        OPEN_GATES.discard(self)


_ACTIVATED = re.compile(re.escape(L_ADDR) + r" \. " + re.escape(R_ADDR) + r" : (0x[0-9a-fA-F]+|[0-9]+)")


def parse_activated(listing: str) -> list[int]:
    return [int(mark, 16) if mark.lower().startswith("0x") else int(mark) for mark in _ACTIVATED.findall(listing)]


class ProbeStream:
    """100 probes per second from L to R; the sender records each syscall bracket and verdict."""

    def __init__(self, gate: Gate, *, start_ns: int, count: int):
        self.start_ns, self.count = start_ns, count
        self.receiver = gate.socket("r", bind=(R_ADDR, PORT))
        self.receiver.settimeout(0.05)
        self.sender = gate.socket("l", bind=(L_ADDR, 0))
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


@contextlib.contextmanager
def _gates(*domains):
    gates = []
    try:
        for domain in domains:
            gates.append(Gate(domain))
        yield gates
    finally:
        for gate in gates:
            gate.close()
        for domain in domains:
            _retire(domain)


def _libc():
    return ctypes.CDLL(None, use_errno=True)


def _bind_name(path: Path, fd: int) -> None:
    """SEAM-NAMED-NAMESPACE d2 negative only: give a namespace a name (a bind mount of its nsfs file)."""
    if _libc().mount(f"/proc/self/fd/{fd}".encode(), str(path).encode(), None, MS_BIND, None) != 0:
        raise OSError(ctypes.get_errno(), "bind mount")
    MOUNTS.append(path)


def _unbind_name(path: Path) -> None:
    if _libc().umount2(str(path).encode(), MNT_DETACH) != 0:
        raise OSError(ctypes.get_errno(), "umount")
    MOUNTS.remove(path)


# ---------------------------------------------------------------------------------------------
# Dynamic cases: the generation domain (Linux, inside the launcher's namespaces only).

def _command(argv: list[str]) -> str:
    try:
        completed = subprocess.run(argv, capture_output=True, text=True, timeout=20, env=LAUNCHER._env())
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return completed.stdout if completed.returncode == 0 else ""


def test_k8_generation_self_test_and_namespace_isolation_on_the_captured_kernel():
    _require_runtime()
    domain = _domain()
    try:
        try:
            report = AUTHORITY.generation_self_test(domain)
        except AUTHORITY.HostQuarantined as error:
            report = error.report
    finally:
        with contextlib.suppress(AUTHORITY.InstallerFailed):
            domain.close_generation()  # no table was installed in this domain: the flush is refused
    tokens = {key: value for key, value in report.tokens.items()
              if key in ("kernel_release", "kernel_major_minor", "nft_version", "selftest", "readd_observation",
                         "selftest_duplicate_error")}
    tokens["kernel_source_tag"] = LAUNCHER.SUPPORTED_KERNELS.get(tokens.get("kernel_major_minor"), "none")
    tokens["proc_version_sha256"] = hashlib.sha256(Path("/proc/version").read_bytes()).hexdigest()
    package = _command(["dpkg-query", "-W", "-f=${Version}", "nftables"]).strip().lower()
    tokens["nftables_package"] = package if re.fullmatch(r"[0-9][a-z0-9.:-]{0,60}", package) else "unparsed"
    tokens["python"] = "{}.{}.{}".format(*sys.version_info[:3])
    tokens["pytest"] = pytest.__version__
    for index, failure in enumerate(report.failures[:8]):
        tokens[f"failure_{index}"] = failure
    ints = {**dict(report.ints), "cpu_count": os.cpu_count() or 0}
    parsed = (tokens.get("kernel_major_minor", "unparsed") != "unparsed" and tokens.get("nft_version", "unparsed") != "unparsed"
              and isinstance(ints.get("overflowuid"), int))
    ok = (report.result == "pass" and parsed and ints.get("k8_visible_in_own") == 1 and ints.get("k8_visible_in_other") == 0
          and ints.get("k8_identities_distinct") == 1)
    record("k8", ok, ints, tokens)
    assert ok, "the generation self-test failed or K8 isolation was not shown on the captured kernel"


def test_d1_two_generations_same_mark_stale_writer_bound_to_its_own_namespace():
    _require_runtime()
    tick = _tick_ns()
    g1, g2 = _domain(), _domain()
    writer = None
    try:
        with _gates(g1, g2) as (p1, p2):
            writer = StaleWriter("fd", str(p1.l_fd), pass_fds=(p1.l_fd,))
            ready = writer.expect("ready")
            before = time.monotonic_ns()
            h1 = g1.prepare(L_ADDR, R_ADDR, 1000)
            after = time.monotonic_ns()
            g1.activate(h1)
            live = p1.stream(start_ns=time.monotonic_ns(), count=30).run()
            bound = after + 1000 * MS + tick
            sleep_until(bound + 100 * MS)
            h2 = g2.prepare(L_ADDR, R_ADDR, 3000)  # same mark value, other domain, never activated here
            s1 = p1.stream(start_ns=time.monotonic_ns() + 50 * MS, count=100).start()
            s2 = p2.stream(start_ns=time.monotonic_ns() + 50 * MS, count=100).start()
            sleep_until(time.monotonic_ns() + 300 * MS)
            writer.send("release " + p1.batch_file(AUTHORITY._render_activate(L_ADDR, R_ADDR, h1.mark)))
            committed = writer.expect("committed")
            probes1, probes2 = s1.join(), s2.join()
            g2_activated_after_stale = p2.activated()
            h1b = g1.prepare(L_ADDR, R_ADDR, 1000)
            try:
                g1.activate(h1)
                refused = "accepted"
            except AUTHORITY.HandleState:
                refused = "handle_state"
            g2.activate(h2)
            control = p2.stream(start_ns=time.monotonic_ns(), count=30).run()
            control_window = (control[0].t_before, h2.prepared_monotonic_ns + 3000 * MS - 2 * tick)
    finally:
        if writer is not None:
            writer.kill()
    writer_marks = parse_activated(committed["listing"])
    ok = (h1.mark == h2.mark == 1 and live_delivery(live, live[0].t_before, before + 1000 * MS - 2 * tick, minimum=10)
          and committed["rc"] == 0 and committed["t_pp"] > bound and committed["identity"] == ready["identity"]
          and tuple(ready["identity"]) == g1.ns_identity and writer_marks == [h1.mark]
          and closed(probes1) and closed(probes2) and g2_activated_after_stale == []
          and h1b.mark == h1.mark + 1 and refused == "handle_state"
          and live_delivery(control, *control_window, minimum=10))
    record("d1", ok, {"g1_mark": h1.mark, "g2_mark": h2.mark, "g1_window_probes": len(probes1),
                      "g1_window_admitted": sum(p.accepted for p in probes1), "g2_window_probes": len(probes2),
                      "g2_window_admitted": sum(p.accepted for p in probes2),
                      "stale_write_after_expiry_ms": ms_floor(committed["t_pp"] - bound),
                      "g1_next_mark": h1b.mark, "control_delivered": sum(p.delivered for p in control),
                      "live_delivered": sum(p.delivered for p in live)},
           {"stale_write": "ok" if committed["rc"] == 0 else "failed", "stale_namespace": "g1_only"
            if committed["identity"] == ready["identity"] else "other", "reactivate_old_handle": refused})
    assert ok, "a stale writer of one generation reached another generation's key, or the API reissued a mark"


def test_d2_named_namespace_re_resolution_revives_a_key():
    """NEGATIVE CONTROL (SEAM-NAMED-NAMESPACE d2 negative only): the same stale writer, but it
    resolves a namespace by NAME at write time and the name now points at the second generation.
    The revival must be SHOWN; it is why the domain never names or re-resolves a namespace."""
    _require_runtime()
    tick = _tick_ns()
    g1, g2 = _domain(), _domain()
    writer, name = None, _work() / "netns-heel-gate"
    try:
        with _gates(g1, g2) as (p1, p2):
            name.write_bytes(b"")
            _bind_name(name, p1.l_fd)
            writer = StaleWriter("name", str(name))
            writer.expect("ready")
            after_prepare = time.monotonic_ns()
            h1 = g1.prepare(L_ADDR, R_ADDR, 500)
            g1.activate(h1)
            sleep_until(after_prepare + 500 * MS + tick + 100 * MS)
            h2 = g2.prepare(L_ADDR, R_ADDR, 3000)
            _unbind_name(name)
            _bind_name(name, p2.l_fd)  # the name is re-pointed at the second generation
            stream = p2.stream(start_ns=time.monotonic_ns() + 50 * MS, count=150).start()
            sleep_until(time.monotonic_ns() + 300 * MS)
            writer.send("release " + p2.batch_file(AUTHORITY._render_activate(L_ADDR, R_ADDR, h1.mark)))
            committed = writer.expect("committed")
            probes = stream.join()
            _unbind_name(name)
    finally:
        if writer is not None:
            writer.kill()
        if name in MOUNTS:
            _unbind_name(name)
        with contextlib.suppress(OSError):
            name.unlink()
    revived = admitted_after(probes, committed["t_pq"])
    ok = (h1.mark == h2.mark and committed["rc"] == 0 and tuple(committed["identity"]) == g2.ns_identity
          and not admitted_before(probes, committed["t_pp"]) and len(revived) >= 50 and anomalies(probes) == 0)
    record("d2", ok, {"revived_admitted": len(revived), "admitted_before_write": len(admitted_before(probes, committed["t_pp"])),
                      "anomalies": anomalies(probes), "shared_mark": h1.mark},
           {"resolution": "by_name", "landed_in": "second_generation"
            if tuple(committed["identity"]) == g2.ns_identity else "other"})
    assert ok, "the named-namespace negative control did not show its hazard (or the fixture is invalid)"


def test_d3_counter_bound_refuses_before_any_process_is_spawned():
    _require_runtime()
    tick = _tick_ns()
    domain = _domain(_counter=AUTHORITY._MarkCounter(start=0xFFFF_FFFE))  # SEAM-COUNTER-START d3 only
    with _gates(domain) as (gate,):
        first = domain.prepare(L_ADDR, R_ADDR, 3000)
        last = domain.prepare(L_ADDR, R_ADDR, 3000)
        domain.activate(last)
        live = gate.stream(start_ns=time.monotonic_ns(), count=30).run()
        listed_before = set(gate.prepared())  # keys only: the remaining lifetime moves
        refusals = []
        sentinel_before = _sentinel_pid()
        for _attempt in range(2):
            try:
                domain.prepare(L_ADDR, R_ADDR, 3000)
                refusals.append("issued")
            except AUTHORITY.DomainExhausted:
                refusals.append("domain_exhausted")
        sentinel_after = _sentinel_pid()
        listed_after = set(gate.prepared())
        states = {mark: state for mark, state in domain._reservations.items()}
    spawned = sentinel_after - sentinel_before - 1
    ok = (first.mark == 0xFFFF_FFFE and last.mark == 0xFFFF_FFFF
          and live_delivery(live, live[0].t_before, last.prepared_monotonic_ns + 3000 * MS - 2 * tick, minimum=10)
          and refusals == ["domain_exhausted", "domain_exhausted"] and spawned == 0 and listed_after == listed_before
          and (L_ADDR, R_ADDR, 0xFFFF_FFFF) in listed_after and set(states) == {0xFFFF_FFFE, 0xFFFF_FFFF})
    record("d3", ok, {"first_mark": first.mark, "last_mark": last.mark, "spawned_during_refusal": spawned,
                      "live_delivered": sum(p.delivered for p in live), "elements_changed": int(listed_after != listed_before)},
           {"refusal": refusals[0], "second_refusal": refusals[1]})
    assert ok, "the counter bound was not refused before any process, or the last mark did not work"


def test_d4_stopped_helper_outlives_its_generation_and_writes_only_its_own_namespace():
    _require_runtime()
    _libc().prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)  # the orphaned helper is reparented here and reaped
    generation, helper_pid, g2 = None, None, None
    try:
        generation = Child(GENERATION, (str(AUTHORITY_FILE), STALE_WRITER, AUTHORITY.NFT_PATH))
        born = generation.expect("generation")
        ready = generation.expect("ready")
        helper_pid = born["helper"]
        os.kill(helper_pid, signal.SIGSTOP)
        generation.process.send_signal(signal.SIGKILL)
        generation.process.wait(10)
        g2 = _domain()
        with _gates(g2) as (p2,):
            h2 = g2.prepare(L_ADDR, R_ADDR, 3000)  # the same key value in the new generation
            helper_ns = os.stat(f"/proc/{helper_pid}/fd/{born['fd']}")
            os.kill(helper_pid, signal.SIGCONT)
            generation.send("release " + p2.batch_file(AUTHORITY._render_activate(L_ADDR, R_ADDR, born["mark"])))
            committed = generation.expect("committed")
            g2_activated, g2_prepared = p2.activated(), p2.prepared()
    finally:
        if helper_pid is not None:
            with contextlib.suppress(ProcessLookupError):
                os.kill(helper_pid, signal.SIGKILL)
            with contextlib.suppress(ChildProcessError):
                os.waitpid(helper_pid, 0)
        if generation is not None:
            generation.kill()
    helper_identity = (helper_ns.st_dev, helper_ns.st_ino)
    ok = (born["table"] == 0 and born["mark"] == h2.mark == 1 and tuple(ready["identity"]) == tuple(born["identity"])
          and helper_identity == tuple(born["identity"]) and helper_identity != g2.ns_identity
          and committed["rc"] == 0 and parse_activated(committed["listing"]) == [born["mark"]]
          and tuple(committed["identity"]) == tuple(born["identity"]) and g2_activated == []
          and (L_ADDR, R_ADDR, h2.mark) in g2_prepared)
    record("d4", ok, {"helper_inode_differs_from_g2": int(helper_identity != g2.ns_identity),
                      "helper_write_rc": committed["rc"], "g2_activated_entries": len(g2_activated),
                      "g1_activated_entries": len(parse_activated(committed["listing"])), "shared_mark": h2.mark},
           {"helper": "stopped_then_continued", "first_generation": "killed"})
    assert ok, "a helper of a dead generation wrote outside its own namespace"


def test_d5_no_path_descriptor_or_foreign_handle_is_adopted():
    _require_runtime()
    tick = _tick_ns()
    g1, g2 = _domain(), _domain()
    with _gates(g1, g2) as (p1, p2):
        h1 = g1.prepare(L_ADDR, R_ADDR, 3000)
        g1.activate(h1)
        before = (set(p1.prepared()), p1.activated(), set(p2.prepared()), p2.activated())
        path = f"/proc/{os.getpid()}/fd/{p1.l_fd}"
        outcomes = {}
        sentinel_before = _sentinel_pid()
        for label, attempt in (
            ("construct_with_fd", lambda: AUTHORITY.LeaseDomain(ns_fd=p1.l_fd)),
            ("create_with_fd", lambda: AUTHORITY.LeaseDomain.create(ns_fd=p1.l_fd)),
            ("create_with_path", lambda: AUTHORITY.LeaseDomain.create(path)),
            ("activate_foreign", lambda: g2.activate(h1)),
            ("close_foreign", lambda: g2.close(h1)),
            ("activate_copy", lambda: g2.activate(copy.copy(h1))),
        ):
            try:
                attempt()
                outcomes[label] = "accepted"
            except TypeError:
                outcomes[label] = "type_error"
            except AUTHORITY.ForeignHandle:
                outcomes[label] = "foreign_handle"
        sentinel_after = _sentinel_pid()
        after = (set(p1.prepared()), p1.activated(), set(p2.prepared()), p2.activated())
        h2 = g2.prepare(L_ADDR, R_ADDR, 3000)
        g2.activate(h2)
        control = p2.stream(start_ns=time.monotonic_ns(), count=30).run()
    spawned = sentinel_after - sentinel_before - 1
    expected = {"construct_with_fd": "type_error", "create_with_fd": "type_error", "create_with_path": "type_error",
                "activate_foreign": "foreign_handle", "close_foreign": "foreign_handle", "activate_copy": "foreign_handle"}
    ok = (outcomes == expected and spawned == 0 and before == after and before[3] == []
          and live_delivery(control, control[0].t_before, h2.prepared_monotonic_ns + 3000 * MS - 2 * tick, minimum=10))
    record("d5", ok, {"spawned_during_attempts": spawned, "elements_changed": int(before != after),
                      "control_delivered": sum(p.delivered for p in control)},
           {key: value for key, value in outcomes.items()})
    assert ok, "a path, a foreign descriptor or a foreign handle was adopted"


def test_d6_forked_owner_copy_refuses_every_operation_and_spawns_nothing():
    """H1ADR section 4.4 D6: a non-exec forked copy of G1 attempts prepare, activate(H1),
    close_generation and the counter; each refuses before any lock or kernel action."""
    _require_runtime()
    tick = _tick_ns()
    g1 = _domain()
    with _gates(g1) as (gate,):
        after_prepare_before = time.monotonic_ns()
        h1 = g1.prepare(L_ADDR, R_ADDR, 3000)
        h1_after = time.monotonic_ns()
        g1.activate(h1)
        live = gate.stream(start_ns=time.monotonic_ns(), count=30).run()
        result_r, result_w = os.pipe()
        g1._lock.acquire()  # the copy inherits a held lock: refusal must come before any acquire
        child = os.fork()
        if child == 0:
            codes = 0
            try:
                os.close(result_r)
                operations = (lambda: g1.prepare(L_ADDR, R_ADDR, 3000), lambda: g1.activate(h1),
                              lambda: g1.close_generation(), lambda: g1._counter.next(), lambda: g1.close(h1),
                              lambda: AUTHORITY.LeaseDomain.create())
                for bit, operation in enumerate(operations):
                    try:
                        operation()
                    except AUTHORITY.ForeignProcess:
                        codes |= 1 << bit
                    except BaseException:  # noqa: BLE001 - any other outcome leaves the bit clear
                        pass
                sentinel = os.fork()
                if sentinel == 0:
                    os._exit(0)
                os.waitpid(sentinel, 0)
                os.write(result_w, json.dumps({"codes": codes, "sentinel": sentinel}).encode())
            finally:
                os._exit(codes)
        g1._lock.release()
        os.close(result_w)
        ready, _w, _x = select.select([result_r], [], [], 20)
        reported = json.loads(os.read(result_r, 4096) or b"{}") if ready else {}
        os.close(result_r)
        if not ready:
            os.kill(child, signal.SIGKILL)
        _pid, status = os.waitpid(child, 0)
        h2 = g1.prepare(L_ADDR, R_ADDR, 3000)
        listed, activated = gate.prepared(), gate.activated()
        sleep_until(h1_after + 3000 * MS + tick + 50 * MS)
        sentinel_before = _sentinel_pid()
        try:
            g1.activate(h1)
            reactivation = "accepted"
        except AUTHORITY.HandleState:
            reactivation = "handle_state"
        sentinel_after = _sentinel_pid()
        burst = gate.stream(start_ns=time.monotonic_ns(), count=30).run()
        h3 = g1.prepare(L_ADDR, R_ADDR, 3000)
        g1.activate(h3)
        control = gate.stream(start_ns=time.monotonic_ns(), count=30).run()
    all_bits = (1 << 6) - 1
    spawned_by_copy = reported.get("sentinel", 0) - child - 1
    ok = (reported.get("codes") == all_bits and os.waitstatus_to_exitcode(status) == all_bits and spawned_by_copy == 0
          and live_delivery(live, live[0].t_before, after_prepare_before + 3000 * MS - 2 * tick, minimum=10)
          and h2.mark == h1.mark + 1 and {key[2] for key in listed if key[:2] == (L_ADDR, R_ADDR)} == {h1.mark, h2.mark}
          and activated == [h1.mark] and reactivation == "handle_state" and sentinel_after - sentinel_before - 1 == 0
          and closed(burst) and live_delivery(control, control[0].t_before, h3.prepared_monotonic_ns + 3000 * MS - 2 * tick,
                                              minimum=10))
    record("d6", ok, {"refusal_bits": reported.get("codes", -1), "exit_status": os.waitstatus_to_exitcode(status),
                      "spawned_by_copy": spawned_by_copy, "next_mark": h2.mark, "first_mark": h1.mark,
                      "spawned_by_reactivation": sentinel_after - sentinel_before - 1,
                      "burst_admitted": sum(p.accepted for p in burst), "control_delivered": sum(p.delivered for p in control)},
           {"reactivation": reactivation, "copy": "forked_non_exec"})
    assert ok, "a forked copy reached the domain, spawned a process, or an old handle was re-activated"


# ---------------------------------------------------------------------------------------------
# Dynamic cases: the host-authority transport.

REQUEST = {"schema_version": "heel.host-authority-request.v1", "host_boot_epoch": "boot-proof-0001", "slot_id": "slot-a",
           "sequence": 1, "request_nonce": "0123456789abcdef0123456789abcdef", "generation_id": "fedcba9876543210fedcba9876543210",
           "workspace_id": "ws_0123456789abcdef", "project_id": "prj_" + "1" * 32, "environment_id": "env_" + "2" * 32,
           "verification_record_digest": "3" * 64, "runner_id": "runner-proof", "runner_key_id": "key-proof",
           "binding_id": "rcb_" + "4" * 32, "binding_digest": "5" * 64, "run_id": "crun_" + "6" * 32, "grant_id": "grant-proof",
           "grant_digest": "7" * 64, "kill_switch_generation": 0, "monotonic_ms": 1000}


def _peer_dir(name: str, *, owner: int = CP_UID, mode: int = 0o700) -> Path:
    base = _work() / "peer"
    base.mkdir(mode=0o755, exist_ok=True)
    os.chmod(base, 0o755)
    directory = base / name
    directory.mkdir()
    os.chmod(directory, mode)
    os.chown(directory, owner, owner)
    return directory


def _production_socket(path: Path, owner: int = CP_UID) -> bool:
    info, parent = os.lstat(path), os.lstat(path.parent)
    return (stat.S_ISSOCK(info.st_mode) and info.st_uid == owner and stat.S_IMODE(info.st_mode) == 0o600
            and stat.S_ISDIR(parent.st_mode) and parent.st_uid == owner and stat.S_IMODE(parent.st_mode) == 0o700)


def _http(path: Path) -> dict:
    """One request as the root client outside; the view of the peer and what came back."""
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(10)
    SOCKETS.append(client)
    COUNTERS["sockets"] += 1
    try:
        client.connect(str(path))
        pid, uid, _gid = struct.unpack("3i", client.getsockopt(socket.SOL_SOCKET, SO_PEERCRED, 12))
        body = LISTENER.canonical(REQUEST)
        data, outcome = b"", "eof"
        try:
            client.sendall(b"POST /host/v1/authority-snapshot HTTP/1.1\r\nContent-Type: application/json\r\n"
                           b"Content-Length: %d\r\n\r\n" % len(body) + body)
            while chunk := client.recv(65536):
                data += chunk
        except (ConnectionResetError, BrokenPipeError):
            outcome = "reset"
    finally:
        client.close()
    head, _sep, payload = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n") if data else []
    return {"view_pid": pid, "view_uid": uid, "status": lines[0].decode("ascii", "replace") if lines else "none",
            "no_store": b"Cache-Control: no-store" in lines, "payload": payload, "received": len(data), "outcome": outcome}


def _run_listener(name: str, profile: str, *, client_check: bool) -> dict:
    directory = _peer_dir(name)
    path = directory / "authority.sock"
    listener = Child(LISTENER_PROGRAM, (str(LISTENER_FILE), str(path), profile, str(CP_UID),
                                        LISTENER.canonical(REQUEST).decode()))
    try:
        forked = listener.expect("forked")
        listening = listener.expect("listening")
        production = _production_socket(path)
        outside = _http(path)
        verified = "not_run"
        if client_check:
            try:
                AUTHORITY.verify_cp_socket(str(path), CP_UID)
                verified = "ok"
            except AUTHORITY.ControlPlaneUnavailable as error:
                verified = error.code
        outsider = Child(OUTSIDER, (str(OUTSIDER_UID), str(path)))
        outsider_view = outsider.expect("refused")
        outsider.wait()
        listener.send("inside")
        inside_view = listener.expect("inside")
        listener.send("stop")
        stopped = listener.expect("stopped")
        exit_code = listener.wait()
        leftover = sorted(entry.name for entry in directory.iterdir())
    finally:
        listener.kill()
    return {"forked": forked, "listening": listening, "production": production, "outside": outside, "verified": verified,
            "outsider": outsider_view, "inside": inside_view, "stopped": stopped, "exit": exit_code, "leftover": leftover}


def _answered(view: dict) -> bool:
    if not view["status"] == "HTTP/1.1 200 OK" or not view["no_store"]:
        return False
    try:
        response = json.loads(view["payload"])
    except ValueError:
        return False
    return LISTENER.validate_response(response, REQUEST) and response["reason"] == "no_active_run"


def test_t1_external_pidns_listener_as_cp_uid_pid_one():
    _require_runtime()
    run = _run_listener("t1", "external-pidns", client_check=True)
    outside, inside_view = run["outside"], run["inside"]
    ok = (run["production"] and run["listening"]["pid"] == 1 and run["listening"]["uid"] == CP_UID
          and outside["view_uid"] == CP_UID and outside["view_pid"] == run["forked"]["outer_pid"] and _answered(outside)
          and run["verified"] == "ok" and run["outsider"]["reason"] == "eacces"
          and inside_view["view_uid"] == CP_UID and inside_view["view_pid"] == 1 and inside_view["self_pid"] != 0
          and inside_view["received"] == 0 and inside_view["status"] == "none"
          and run["stopped"]["refused_peer"] == 1 and run["stopped"]["answered"] == 1 and run["exit"] == 0
          and run["leftover"] == [])
    record("t1", ok, {"listener_inside_pid": run["listening"]["pid"], "listener_uid": run["listening"]["uid"],
                      "client_view_uid": outside["view_uid"],
                      "client_view_pid_is_outer_pid": int(outside["view_pid"] == run["forked"]["outer_pid"]),
                      "inside_client_bytes_received": inside_view["received"], "refused_peer": run["stopped"]["refused_peer"],
                      "answered": run["stopped"]["answered"], "production_permissions": int(run["production"])},
           {"outside_root": "answered" if _answered(outside) else "not_answered", "outsider_connect": run["outsider"]["reason"],
            "inside_root": "refused_no_body" if inside_view["received"] == 0 else "answered",
            "client_check": run["verified"] if LAUNCHER._TOKEN.fullmatch(run["verified"]) else "other"})
    assert ok, "the external-pidns listener did not answer only the outside root supervisor"


def test_t2_shared_pidns_profile_refuses_outside_and_accepts_inside():
    _require_runtime()
    run = _run_listener("t2", "shared-pidns", client_check=False)
    outside, inside_view = run["outside"], run["inside"]
    inside_answered = inside_view["status"] == "HTTP/1.1 200 OK"
    ok = (run["production"] and outside["received"] == 0 and outside["status"] == "none" and inside_answered
          and run["stopped"]["refused_peer"] == 1 and run["stopped"]["answered"] == 1 and run["exit"] == 0
          and run["outsider"]["reason"] == "eacces" and run["leftover"] == [])
    record("t2", ok, {"outside_bytes_received": outside["received"], "inside_answered": int(inside_answered),
                      "refused_peer": run["stopped"]["refused_peer"], "answered": run["stopped"]["answered"],
                      "production_permissions": int(run["production"])},
           {"outside_root": "refused_no_body" if outside["received"] == 0 else "answered"})
    assert ok, "the shared-pidns profile did not refuse the outside client and accept the inside client"


def _write_id_maps(pid: int) -> None:
    Path(f"/proc/{pid}/uid_map").write_text("0 0 1\n")
    Path(f"/proc/{pid}/gid_map").write_text("0 0 1\n")


def test_t3_startup_refusals():
    _require_runtime()
    overflow = int(Path("/proc/sys/kernel/overflowuid").read_text().strip())
    good = _peer_dir("t3good", owner=0)
    loose = _peer_dir("t3loose", owner=0, mode=0o755)
    linked = _work() / "peer" / "t3link"
    linked.symlink_to(good)
    outcomes = {}
    child = Child(USERNS_CHECK, (str(LISTENER_FILE), str(good / "authority.sock")))
    try:
        unshared = child.expect("unshared")
        _write_id_maps(unshared["pid"])
        child.send("mapped")
        outcomes["user_namespace"] = child.expect("result")["code"]
    finally:
        child.kill()
    configs = {
        "peer_is_overflowuid": LISTENER.HostAuthorityConfig(str(good / "authority.sock"), overflow, LISTENER.PeerProfile.EXTERNAL_PIDNS),
        "loose_directory": LISTENER.HostAuthorityConfig(str(loose / "authority.sock"), 0, LISTENER.PeerProfile.EXTERNAL_PIDNS),
        "symlinked_directory": LISTENER.HostAuthorityConfig(str(linked / "authority.sock"), 0, LISTENER.PeerProfile.EXTERNAL_PIDNS),
        "unknown_profile": LISTENER.HostAuthorityConfig(str(good / "authority.sock"), 0, "host-pidns"),
        "missing_peer_uid": LISTENER.HostAuthorityConfig(str(good / "authority.sock"), None, LISTENER.PeerProfile.EXTERNAL_PIDNS),
    }
    for label, config in configs.items():
        listener = LISTENER.HostAuthorityListener(config, lambda request: {})
        try:
            listener.start()
            outcomes[label] = "accepted"
            listener.close()
        except LISTENER.HostAuthorityConfigurationError as error:
            outcomes[label] = error.code
    control = LISTENER.HostAuthorityListener(
        LISTENER.HostAuthorityConfig(str(good / "authority.sock"), 0, LISTENER.PeerProfile.EXTERNAL_PIDNS), lambda request: {})
    control.start()
    control_published = _production_socket(good / "authority.sock", owner=0)
    control.close()
    leftovers = sorted(entry.name for directory in (good, loose) for entry in directory.iterdir())
    linked.unlink()
    expected = {"user_namespace": "user_namespace_translation_unsupported", "peer_is_overflowuid": "peer_uid_is_overflowuid",
                "loose_directory": "socket_directory_profile", "symlinked_directory": "socket_directory_not_directory",
                "unknown_profile": "profile_invalid", "missing_peer_uid": "peer_uid_invalid"}
    ok = outcomes == expected and control_published and leftovers == [] and overflow != 0
    record("t3", ok, {"overflowuid": overflow, "control_published": int(control_published), "leftover_files": len(leftovers)},
           {key: value if LAUNCHER._TOKEN.fullmatch(value) else "other" for key, value in outcomes.items()})
    assert ok, "a startup refusal of H1AD section 3.3 did not hold"


def _t4_dir(name: str) -> Path:
    return _peer_dir(name, owner=0)


def _listener(path: Path, **seam) -> "LISTENER.HostAuthorityListener":
    config = LISTENER.HostAuthorityConfig(str(path), 0, LISTENER.PeerProfile.EXTERNAL_PIDNS)
    return LISTENER.HostAuthorityListener(config, lambda request: {}, **seam)


def _serve(listener) -> threading.Thread:
    thread = threading.Thread(target=listener.serve_forever, kwargs={"poll_seconds": 0.05}, daemon=True)
    thread.start()
    return thread


def _plain_listener(path: Path) -> tuple[socket.socket, threading.Thread, threading.Event]:
    """A plain listening socket that accepts and closes (a working endpoint, not the product)."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(str(path))
    sock.listen(64)
    sock.settimeout(0.05)
    SOCKETS.append(sock)
    COUNTERS["sockets"] += 1
    stop = threading.Event()

    def accept() -> None:
        while not stop.is_set():
            try:
                connection, _address = sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            connection.close()

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    return sock, thread, stop


def _connect_once(path: Path) -> str:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(5)
    try:
        client.connect(str(path))
        return "success"
    except OSError:
        return "failed"
    finally:
        client.close()


def _tmp_files(directory: Path) -> list[str]:
    return sorted(entry.name for entry in directory.iterdir() if entry.name.endswith(".tmp"))


def _inode(path: Path) -> tuple[int, int] | None:
    with contextlib.suppress(OSError):
        info = os.lstat(path)
        return info.st_dev, info.st_ino
    return None


def _connector(path: Path) -> Child:
    connector = Child(CONNECTOR, (str(path), "2000", "20"))
    connector.expect("started")
    return connector


def _connector_record(done: dict) -> tuple[dict, dict]:
    """Every count and token the connector reports, plus whether its totals reconcile: attempts is
    the sum of the n_* outcomes and the after_* outcomes are exactly the attempts after first_success."""
    window = done["attempts"] - done["first_success"] if done["first_success"] else 0
    reconciled = (done["attempts"] == sum(done["n_" + kind] for kind in CONNECTOR_KINDS)
                  and sum(done["after_" + kind] for kind in CONNECTOR_KINDS) == window)
    return ({key: done[key] for key in CONNECTOR_INTS} | {"totals_reconciled": int(reconciled)},
            {key: done[key] for key in CONNECTOR_TOKENS})


def test_t4_publication_has_no_refused_window():
    _require_runtime()
    directory = _t4_dir("t4")
    path = directory / "authority.sock"
    listener, thread = _listener(path), None
    connector = _connector(path)
    try:
        listener.start()
        bound = _inode(path) == listener.own_inode
        published = bound and _production_socket(path, owner=0)
        thread = _serve(listener)
        done = connector.expect("done")
        tmp_during = _tmp_files(directory)
    finally:
        connector.kill()
        listener.close()
        if thread is not None:
            thread.join(5)
    ints, tokens = _connector_record(done)
    tmp_left, path_left = _tmp_files(directory), path.exists()
    ok = (done["n_econnrefused"] == 0 and done["n_eagain"] == 0 and done["n_other"] == 0 and done["n_unanswered"] == 0
          and done["n_enoent"] >= 1 and done["n_success"] >= 1 and done["attempts"] >= 2000 and ints["totals_reconciled"]
          and published and tmp_during == [] and tmp_left == [] and not path_left)
    record("t4", ok, ints | {"published_inode_is_bound_inode": int(bound), "published_production_socket": int(published),
                             "tmp_files_during": len(tmp_during), "tmp_files_left": len(tmp_left), "path_left": int(path_left)},
           tokens | {"order": "bind_chmod_listen_rename"})
    assert ok, "the published listener was observable before it listened, or left a temporary inode"


def _wrong_order_publisher(path: Path) -> tuple[socket.socket, threading.Thread, threading.Event]:
    """SEAM-WRONG-ORDER t4n negative only: bind a temporary name, rename it onto the final path,
    sleep 200 ms, then listen (the order H1ADR section 3.1 shows to be wrong)."""
    tmp = Path(f"{path}.wrong.tmp")
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(str(tmp))
    os.rename(tmp, path)
    time.sleep(0.2)
    sock.listen(64)
    sock.settimeout(0.05)
    SOCKETS.append(sock)
    COUNTERS["sockets"] += 1
    stop = threading.Event()

    def accept() -> None:
        while not stop.is_set():
            try:
                connection, _address = sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            connection.close()

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    return sock, thread, stop


def test_t4n_wrong_order_publisher_shows_refused_window():
    """NEGATIVE CONTROL: the same connector loop against bind -> rename -> listen must see
    ECONNREFUSED; a run where it shows 0 is a FAIL of the probe, not a pass of the product."""
    _require_runtime()
    directory = _t4_dir("t4n")
    path = directory / "authority.sock"
    connector = _connector(path)
    sock = thread = stop = None
    try:
        sock, thread, stop = _wrong_order_publisher(path)
        done = connector.expect("done")
    finally:
        connector.kill()
        if stop is not None:
            stop.set()
            thread.join(5)
            sock.close()
        with contextlib.suppress(OSError):
            path.unlink()
    ints, tokens = _connector_record(done)
    ok = (done["n_econnrefused"] >= 1 and done["n_enoent"] >= 1 and done["n_success"] >= 1 and done["attempts"] >= 2000
          and done["n_eagain"] == 0 and done["n_other"] == 0 and done["n_unanswered"] == 0 and ints["totals_reconciled"])
    record("t4n", ok, ints, tokens | {"order": "bind_rename_listen"})
    assert ok, "the wrong-order negative control showed no refused window: the probe cannot discriminate the order"


def test_t4f_listen_failure_leaves_the_working_endpoint():
    _require_runtime()
    directory = _t4_dir("t4f")
    path = directory / "authority.sock"
    working, thread, stop = _plain_listener(path)
    before = _inode(path)

    def refuse_listen(sock, backlog):  # SEAM-LISTEN-FAILURE t4f only
        raise OSError(98, "injected listen failure")

    listener = _listener(path, _listen_for_tests=refuse_listen)
    try:
        listener.start()
        raised = "none"
    except OSError:
        raised = "oserror"
    after = _inode(path)
    still_works = _connect_once(path)
    tmp = _tmp_files(directory)
    stop.set()
    thread.join(5)
    working.close()
    path.unlink()
    ok = raised == "oserror" and before is not None and after == before and still_works == "success" and tmp == []
    record("t4f", ok, {"final_inode_unchanged": int(after == before), "tmp_files_left": len(tmp)},
           {"listen": raised, "working_endpoint": still_works})
    assert ok, "a listen failure touched the final path or left a temporary inode"


def test_t4r_close_leaves_a_replaced_endpoint():
    _require_runtime()
    directory = _t4_dir("t4r")
    path = directory / "authority.sock"
    listener = _listener(path)
    listener.start()
    own = listener.own_inode
    replacement_tmp = directory / "replacement.sock"
    w2, thread, stop = _plain_listener(replacement_tmp)
    os.rename(replacement_tmp, path)
    w2_inode = _inode(path)
    listener.close()
    after = _inode(path)
    still_works = _connect_once(path)
    tmp = _tmp_files(directory)
    stop.set()
    thread.join(5)
    w2.close()
    path.unlink()
    ok = after == w2_inode and after != own and still_works == "success" and tmp == [] and sorted(directory.iterdir()) == []
    record("t4r", ok, {"replacement_kept": int(after == w2_inode), "tmp_files_left": len(tmp)},
           {"replacement_endpoint": still_works})
    assert ok, "close unlinked an endpoint that was no longer its own inode"


def test_t4s_stale_socket_file_is_replaced_by_a_listening_inode():
    _require_runtime()
    directory = _t4_dir("t4s")
    path = directory / "authority.sock"
    stale = subprocess.run([sys.executable, "-I", "-c", STALE_SOCKET, str(path)], capture_output=True, timeout=30,
                           env=LAUNCHER._env())
    stale_inode = _inode(path)
    listener, thread = _listener(path), None
    connector = _connector(path)
    try:
        listener.start()
        bound, not_stale = _inode(path) == listener.own_inode, _inode(path) != stale_inode
        thread = _serve(listener)
        done = connector.expect("done")
    finally:
        connector.kill()
        listener.close()
        if thread is not None:
            thread.join(5)
    ints, tokens = _connector_record(done)
    tmp_left, path_left = _tmp_files(directory), path.exists()
    ok = (stale.returncode == 0 and stale_inode is not None and bound and not_stale and done["n_success"] >= 1
          and done["after_econnrefused"] == 0 and done["after_eagain"] == 0 and done["after_other"] == 0
          and done["n_eagain"] == 0 and done["n_other"] == 0 and done["n_unanswered"] == 0 and done["attempts"] >= 2000
          and ints["totals_reconciled"] and tmp_left == [] and not path_left)
    record("t4s", ok, ints | {"stale_exit": stale.returncode, "stale_inode_present": int(stale_inode is not None),
                              "published_inode_is_bound_inode": int(bound), "published_inode_is_not_stale": int(not_stale),
                              "tmp_files_left": len(tmp_left), "path_left": int(path_left)}, tokens | {"stale": "replaced"})
    assert ok, "the stale socket file was not replaced by a listening inode in one step"


# ---------------------------------------------------------------------------------------------
# Dynamic cases: the H1A3-1 authorization cycle on this kernel (S1-S6). The real HostCycle with its
# real LeaseDomain, generation self-test, grading, clock witness, nft children, connect_cp and
# exchange, against the real listener as uid 10001, pid 1 of a child PID namespace (external-pidns,
# production permissions, as T1). Three labelled seams, passed only by _cycle_fixture:
# SEAM-SCRIPTED-DECIDER s-cases only (the listener's decide callable returns scripted replies; the
# listener still validates each one, so S6's deliberately stale reply never reaches the wire),
# SEAM-CYCLE-SLEEP-REPORT s-cases only (the fixed all-disabled report, only when the recorded real
# report fails K9) and SEAM-CYCLE-DOMAIN-REGISTER s-cases only (the real LeaseDomain.create,
# registered for c2). One coherent clock (time.monotonic_ns), the production budget and spacing.

SCRIPTED_LISTENER_PROGRAM = r'''
import importlib.util, json, os, sys, threading, time
listener_file, path, uid, grant = sys.argv[1], sys.argv[2], int(sys.argv[3]), json.loads(sys.argv[4])
def say(**fields):
    sys.stdout.write(json.dumps(fields) + "\n")
    sys.stdout.flush()
os.unshare(0x20000000)
child = os.fork()
if child:
    say(event="forked", outer_pid=child)
    _pid, status = os.waitpid(child, 0)
    os._exit(0 if os.waitstatus_to_exitcode(status) == 0 else 1)
script = []
for line in sys.stdin:
    if line.strip() == "go":
        break
    script.append(json.loads(line))
os.setgroups([])
os.setresgid(uid, uid, uid)
os.setresuid(uid, uid, uid)
spec = importlib.util.spec_from_file_location("listener_under_test", listener_file)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
names = ("workspace_id", "project_id", "environment_id", "verification_record_digest", "runner_id", "runner_key_id",
         "binding_id", "binding_digest", "run_id", "grant_id", "grant_digest")
tally = {"requests": 0, "answered_active": 0, "answered_inactive": 0, "stale_attempts": 0}
previous = []
def decide(req):
    # SEAM-SCRIPTED-DECIDER s-cases only: one scripted step per request, in order; past the script
    # the answer is inactive no_active_run.
    index = tally["requests"]
    tally["requests"] += 1
    step = script[index] if index < len(script) else {"delay_ms": 0, "decision": "inactive", "reason": "no_active_run",
                                                       "rem_ms": 0, "stale": False}
    if step["delay_ms"]:
        time.sleep(step["delay_ms"] / 1000)
    if step["stale"] and previous:
        tally["stale_attempts"] += 1
        return previous[-1]  # the previous request's reply, verbatim
    now = int(time.time() * 1000)
    reply = {"schema_version": module.RESPONSE_SCHEMA, "decision": step["decision"], "reason": step["reason"],
             "sequence": req["sequence"], "request_digest": module.request_digest(req), "server_time_ms": now,
             "kill_switch_generation": req["kill_switch_generation"]}
    if step["decision"] == "active":
        reply.update({name: req[name] for name in names})
        reply.update(public_key_digest=grant["public_key_digest"], egress_hostname=grant["egress_hostname"],
                     run_status="running", stop_reason="none", egress_port=443,
                     proof_expires_at_ms=now + step["rem_ms"], binding_expires_at_ms=now + step["rem_ms"],
                     grant_expires_at_ms=now + step["rem_ms"])
        tally["answered_active"] += 1
    else:
        tally["answered_inactive"] += 1
    previous.append(reply)
    return reply
config = module.HostAuthorityConfig(path, 0, module.PeerProfile("external-pidns"))
listener = module.HostAuthorityListener(config, decide)
try:
    listener.start()
except module.HostAuthorityConfigurationError as error:
    say(event="refused_start", code=error.code)
    os._exit(1)
say(event="listening", pid=os.getpid(), uid=os.getuid(), inode=listener.own_inode[1])
thread = threading.Thread(target=listener.serve_forever, daemon=True)
thread.start()
for line in sys.stdin:
    if line.strip() == "stop":
        break
listener.close()
thread.join(5)
say(event="stopped", **listener.counters, **tally)
os._exit(0)
'''

CYCLE_GRANT = {"public_key_digest": "8" * 64, "egress_hostname": "egress.proof.example"}
CONTEXT = CYCLE.CycleContext(**{name: REQUEST[name] for name in CYCLE.CONTEXT_STRINGS[:11]}, **CYCLE_GRANT,
                             kill_switch_generation=0, egress_port=443)
# SEAM-CYCLE-SLEEP-REPORT s-cases only: the fixed all-disabled A-1/A-2 report (never this host's).
K9_DISABLED = {**dict.fromkeys(CYCLE._SLEEP_UNITS, "masked"), "sleep_conf": "all_disabled",
               "hibernation": "disabled_cmdline", "power_state": "none", "enforcement": "none_in_h1a1"}
_S = {"installed": False, "last_start_ns": None, "k9": None}


class _CycleRefused(AssertionError):
    """The S-case fixture could not reach ``serving``; ``token`` is a fixed refusal token."""

    def __init__(self, token: str):
        super().__init__(token)
        self.token = token if LAUNCHER._TOKEN.fullmatch(token) else "other"


def _step(decision: str = "active", reason: str = "none", *, rem_ms: int = 60_000, delay_ms: int = 0,
          stale: bool = False) -> dict:
    return {"delay_ms": delay_ms, "decision": decision, "reason": reason, "rem_ms": rem_ms, "stale": stale}


def _cycle_domain():
    """SEAM-CYCLE-DOMAIN-REGISTER s-cases only: the real ``LeaseDomain.create``, registered for c2."""
    domain = AUTHORITY.LeaseDomain.create()
    DOMAINS.append(domain)
    COUNTERS["domains"] += 1
    return domain


def _k9_path() -> str:
    return "real" if _S["k9"] is not None and CYCLE._sleep_disabled(_S["k9"]) else "scripted"


def _registry_preflight() -> None:
    """Fail closed unless the process-wide cleanup registry is clear (at most 5 x 200 ms of drain)."""
    verdict = CYCLE.classify_children(AUTHORITY.sweep_unresolved_children())
    for _attempt in range(5):
        if verdict != "drain":
            break
        time.sleep(0.2)
        verdict = CYCLE.classify_children(AUTHORITY.sweep_unresolved_children())
    if verdict != "clear":
        raise _CycleRefused(f"registry_{verdict}")


def _scripted_listener(script: list[dict]) -> tuple[Child, Path]:
    COUNTERS["deciders"] += 1
    path = _peer_dir(f"cycle{COUNTERS['deciders']}") / "authority.sock"
    listener = Child(SCRIPTED_LISTENER_PROGRAM, (str(LISTENER_FILE), str(path), str(CP_UID), json.dumps(CYCLE_GRANT)))
    try:
        for step in script:
            listener.send(json.dumps(step))
        listener.send("go")
        listener.expect("forked")
        listening = listener.expect("listening")
        if not (listening["pid"] == 1 and listening["uid"] == CP_UID and _production_socket(path)):
            raise _CycleRefused("decider_profile")
    except BaseException:
        listener.kill()
        raise
    return listener, path


def _cycle_start(cycle):
    """Guard, start, stamp, then require ``ready`` and the one domain this start registered."""
    status = cycle.status()
    if status["generations"] >= CYCLE.MAX_GENERATIONS_PER_PROCESS or status["generation_phase"] == "quarantined":
        raise _CycleRefused("budget_guard")
    registered = len(DOMAINS)
    phase = cycle.start()
    _S["last_start_ns"] = time.monotonic_ns()  # after start() returned: later than the budget's own stamp
    if phase != "ready":
        raise _CycleRefused(f"start_{cycle.status()['last_reason']}")
    if len(DOMAINS) != registered + 1:
        raise _CycleRefused("domain_unregistered")
    return DOMAINS[-1]


def _refused(case: str, refused: _CycleRefused) -> None:
    record(case, False, {"generations": CYCLE._BUDGET.generations}, {"setup": refused.token, "k9_path": _k9_path()})


def _cycle_fixture(case: str, script: list[dict]):
    """One scripted listener and one ``HostCycle`` in ``serving`` with a gate on its registered domain:
    ``(cycle, gate, listener, domain)``. Everything it created is cleaned up if it does not return."""
    cycle = gate = listener = None
    first = len(DOMAINS)
    try:
        if not _S["installed"]:
            try:
                CYCLE.install_signal_context()
            except CYCLE.SignalContextInvalid as error:
                raise _CycleRefused(f"signal_{error.code}") from None
            _S["installed"] = True
        if _S["k9"] is None:
            _S["k9"] = AUTHORITY.sleep_capability_report()
        _registry_preflight()
        if _S["last_start_ns"] is not None:
            sleep_until(_S["last_start_ns"] + (CYCLE.MIN_GENERATION_SPACING_MS + 50) * MS)
        listener, path = _scripted_listener(script)
        seams = CYCLE.CycleSeams(domain_factory=_cycle_domain,
                                 sleep_report=None if _k9_path() == "real" else (lambda: dict(K9_DISABLED)))
        cycle = CYCLE.HostCycle("slot-a", str(path), CP_UID, slot_src=L_ADDR, slot_dst=R_ADDR,
                                admission=CYCLE.Enablement.NON_CUSTOMER, _seams_for_tests=seams)
        COUNTERS["cycles"] += 1
        domain = _cycle_start(cycle)
        gate = Gate(domain)
        cycle.install_context(CONTEXT)
        return cycle, gate, listener, domain
    except BaseException as error:
        _finish(cycle, [gate], listener, DOMAINS[first:])
        if isinstance(error, _CycleRefused):
            _refused(case, error)
        raise


def _start_again(case: str, cycle):
    """S5's restart on the same cycle and listener: registry, real spacing, guard, start, gate, context."""
    gate = None
    try:
        _registry_preflight()
        sleep_until(_S["last_start_ns"] + (CYCLE.MIN_GENERATION_SPACING_MS + 50) * MS)
        domain = _cycle_start(cycle)
        gate = Gate(domain)
        cycle.install_context(CONTEXT)
    except BaseException as error:
        if gate is not None:
            gate.close()
        if isinstance(error, _CycleRefused):
            _refused(case, error)
        raise
    return gate, domain


def _finish(cycle, gates: list, listener, domains: list) -> dict:
    """Stop an active generation, retire every domain the case registered, close the gates (and their
    probe sockets), stop the listener and return its final counters ({} if it did not report)."""
    stopped: dict = {}
    try:
        if cycle is not None and cycle.status()["generation_phase"] in ("ready", "serving", "draining"):
            cycle.stop()
    finally:
        for domain in domains:
            _retire(domain)
        for gate in gates:
            if gate is not None:
                gate.close()
        if listener is not None:
            try:
                listener.send("stop")
                stopped = listener.expect("stopped", 15)
            except (AssertionError, OSError, ValueError, queue.Empty):
                stopped = {}
            finally:
                listener.wait()
    return stopped


def _tick(cycle) -> tuple[int, str, int]:
    t_before = time.monotonic_ns()
    phase = cycle.tick()
    return t_before, phase, time.monotonic_ns()


def _e_lower_est(t_before: int, tick: int) -> int:
    """At or before the real E_lower (t_p0 >= t_before): a live window end."""
    return t_before + CYCLE.LEASE_MS * MS - 2 * tick


def _e_upper_est(t_after: int, tick: int) -> int:
    """At or after the real E_upper (t_p1 <= t_after): an admission bound."""
    return t_after + CYCLE.LEASE_MS * MS + tick


def _probes_after(probes: list[Probe], bound_ns: int) -> list[Probe]:
    return [probe for probe in probes if probe.t_before > bound_ns]


def _class_token(value: str) -> str:
    """The generation class end as a closed token: A/B/C are recorded lowercase, the rest verbatim."""
    return {"A": "a", "B": "b", "C": "c"}.get(value, value)


def _common(status: dict, before: int, stopped: dict, spawned: int, admitted: int) -> dict:
    return {"generations_before": before, "generations_after": status["generations"], "sequence": status["sequence"],
            "request_gap_ms": status["request_gap_ms"], "nft_spawns": spawned, "admitted_after_bound": admitted,
            "listener_requests": stopped.get("requests", -1), "listener_decide_failed": stopped.get("decide_failed", -1),
            "listener_answered": stopped.get("answered", -1), "listener_refused_peer": stopped.get("refused_peer", -1)}


def test_s1_positive_renewal_delivers_and_nothing_is_admitted_after_the_bound():
    _require_runtime()
    tick = _tick_ns()
    first, before = len(DOMAINS), CYCLE._BUDGET.generations
    cycle, gate, listener, _domain_s1 = _cycle_fixture("s1", [_step(), _step(), _step()])
    ticks, stopped = [], {}
    try:
        stream = gate.stream(start_ns=time.monotonic_ns() + 50 * MS, count=700).start()
        sleep_until(stream.start_ns + 100 * MS)  # probes run before tick 1
        sentinel_before = _sentinel_pid()
        for index in range(3):
            if ticks:
                sleep_until(ticks[0][0] + index * CYCLE.INTERVAL_MS * MS)
            t_before, phase, t_after = _tick(cycle)
            status = cycle.status()
            ticks.append((t_before, phase, t_after, status["last_reason"], status["authorized"], status["request_gap_ms"]))
        sentinel_after = _sentinel_pid()
        bound = _e_upper_est(ticks[-1][2], tick) + tick
        sleep_until(bound + 500 * MS)
        status = cycle.status()
        activated = gate.activated()
        probes = stream.join()
    finally:
        stopped = _finish(cycle, [gate], listener, DOMAINS[first:])
    deliveries = [live_delivery(probes, t_after, _e_lower_est(t_before, tick), LIVE_PERCENT)
                  for t_before, _phase, t_after, *_rest in ticks]
    margins = [(_e_upper_est(t_after, tick) - (t_before + 60_000 * MS)) // MS for t_before, _phase, t_after, *_rest in ticks]
    after = _probes_after(probes, bound)
    ok = (all(t[1] == "serving" and t[3] == "activated" and t[4] == "true" for t in ticks) and all(deliveries)
          and all(margin < 0 for margin in margins) and closed(after) and activated == [3] and status["sequence"] == 3
          and before == 0 and status["generations"] - before == 1 and stopped.get("requests") == 3)
    ints = _common(status, before, stopped, sentinel_after - sentinel_before - 1, len(admitted_after(probes, bound)))
    ints |= {"e_upper_minus_d_ms": margins[-1], "live_windows_held": sum(deliveries), "after_bound_probes": len(after),
             "activated_entries": len(activated), "max_request_gap_ms": max(t[5] for t in ticks)}
    k9 = {f"k9_{key}": value if LAUNCHER._TOKEN.fullmatch(value) else "other" for key, value in _S["k9"].items()}
    record("s1", ok, ints, {"outcome": status["last_reason"], "k9_path": _k9_path(),
                            "k9_satisfied": "yes" if _k9_path() == "real" else "no", **k9})
    assert ok, "three real renewals did not deliver, or a packet was admitted after the last key's bound"


def test_s2_listener_past_the_deadline_times_out_without_activation():
    _require_runtime()
    tick = _tick_ns()
    first, before = len(DOMAINS), CYCLE._BUDGET.generations
    cycle, gate, listener, _domain_s2 = _cycle_fixture("s2", [_step(delay_ms=1500)])
    stopped = {}
    try:
        stream = gate.stream(start_ns=time.monotonic_ns() + 50 * MS, count=600).start()
        sleep_until(stream.start_ns + 100 * MS)
        sentinel_before = _sentinel_pid()
        t_before, phase, t_after = _tick(cycle)
        sentinel_after = _sentinel_pid()
        status = cycle.status()
        activated = gate.activated()
        window_end = _e_upper_est(t_after, tick)
        sleep_until(window_end + 300 * MS)
        probes = stream.join()
    finally:
        stopped = _finish(cycle, [gate], listener, DOMAINS[first:])
    spawned = sentinel_after - sentinel_before - 1
    ok = (phase == "serving" and status["last_reason"] == "cp_timeout" and status["last_decision"] == "no_reply"
          and status["consecutive_unavailable"] == 1 and status["generation_phase"] == "serving"
          and status["authorized"] == "false" and spawned == 1 and activated == []
          and closed(inside(probes, t_before, window_end)) and admitted_after(probes, t_before) == []
          and status["sequence"] == 1 and status["generations"] - before == 1 and stopped.get("requests") == 1)
    ints = _common(status, before, stopped, spawned, len(admitted_after(probes, t_before)))
    ints |= {"reply_delay_ms": 1500, "request_budget_ms": CYCLE.REQUEST_BUDGET_MS, "tick_ms": (t_after - t_before) // MS,
             "window_probes": len(inside(probes, t_before, window_end)), "activated_entries": len(activated)}
    record("s2", ok, ints, {"outcome": status["last_reason"], "k9_path": _k9_path(), "last_decision": status["last_decision"]})
    assert ok, "a reply past the request deadline was not a cp_timeout without activation"


def test_s3_short_authority_is_refused_and_a_longer_one_activates():
    _require_runtime()
    tick = _tick_ns()
    first, before = len(DOMAINS), CYCLE._BUDGET.generations
    cycle, gate, listener, _domain_s3 = _cycle_fixture("s3", [_step(rem_ms=2000), _step(rem_ms=10_000)])
    stopped = {}
    try:
        stream = gate.stream(start_ns=time.monotonic_ns() + 50 * MS, count=600).start()
        sleep_until(stream.start_ns + 100 * MS)
        a_before, a_phase, a_after = _tick(cycle)
        status_a = cycle.status()
        activated_a = gate.activated()
        sleep_until(a_before + CYCLE.INTERVAL_MS * MS)
        b_before, b_phase, b_after = _tick(cycle)
        status = cycle.status()
        bound = _e_upper_est(b_after, tick) + tick
        sleep_until(bound + 500 * MS)
        probes = stream.join()
    finally:
        stopped = _finish(cycle, [gate], listener, DOMAINS[first:])
    margin_a = ((a_before + CYCLE.LEASE_MS * MS + tick) - (a_after + 2000 * MS)) // MS  # lower E_upper - upper D
    margin_b = (_e_upper_est(b_after, tick) - (b_before + 10_000 * MS)) // MS  # upper E_upper - lower D
    after = _probes_after(probes, bound)
    ok = (a_phase == "serving" and status_a["last_reason"] == "authority_too_short" and status_a["consecutive_unusable"] == 1
          and activated_a == [] and margin_a >= 500 and b_phase == "serving" and status["last_reason"] == "activated"
          and live_delivery(probes, b_after, _e_lower_est(b_before, tick), LIVE_PERCENT) and margin_b <= -500
          and status_a["request_gap_ms"] < 100 and status["request_gap_ms"] < 100 and closed(after)
          and status["sequence"] == 2 and status["generations"] - before == 1 and stopped.get("requests") == 2)
    ints = _common(status, before, stopped, -1, len(admitted_after(probes, bound)))
    ints |= {"e_upper_minus_d_ms_a": margin_a, "e_upper_minus_d_ms_b": margin_b, "request_gap_ms_a": status_a["request_gap_ms"],
             "consecutive_unusable_a": status_a["consecutive_unusable"], "after_bound_probes": len(after)}
    record("s3", ok, ints, {"outcome": status["last_reason"], "k9_path": _k9_path(), "outcome_a": status_a["last_reason"]})
    assert ok, "a reply shorter than the key's bound was activated, or a long enough one was not"


def test_s4_revocation_closes_the_generation_and_no_request_follows():
    _require_runtime()
    tick = _tick_ns()
    first, before = len(DOMAINS), CYCLE._BUDGET.generations
    cycle, gate, listener, _domain_s4 = _cycle_fixture("s4", [_step(), _step("inactive", "key_revoked")])
    stopped = {}
    try:
        stream = gate.stream(start_ns=time.monotonic_ns() + 50 * MS, count=300).start()
        sleep_until(stream.start_ns + 100 * MS)
        one_before, one_phase, one_after = _tick(cycle)
        status_1 = cycle.status()
        sleep_until(one_before + CYCLE.INTERVAL_MS * MS)
        two_before, two_phase, two_after = _tick(cycle)
        status = cycle.status()
        activated = gate.activated()  # read through the gate's own descriptor after the flush
        third = cycle.tick()
        probes = stream.join()
    finally:
        stopped = _finish(cycle, [gate], listener, DOMAINS[first:])
    after = _probes_after(probes, two_after + tick)
    ok = (one_phase == "serving" and status_1["last_reason"] == "activated"
          and live_delivery(probes, one_after, min(two_before, _e_lower_est(one_before, tick)), 50)
          and two_phase == "closed" and status["generation_phase"] == "closed" and status["generation_class_end"] == "A"
          and status["context_end_reason"] == "key_revoked" and status["context_state"] == "ended"
          and status["authorized"] == "false" and activated == [] and closed(after) and third == "closed"
          and status["sequence"] == 2 and stopped.get("requests") == 2 and status["generations"] - before == 1)
    ints = _common(status, before, stopped, -1, len(admitted_after(probes, two_after + tick)))
    ints |= {"after_close_probes": len(after), "activated_entries": len(activated)}
    record("s4", ok, ints, {"outcome": status["last_reason"], "k9_path": _k9_path(), "class_end": _class_token(status["generation_class_end"]),
                            "context_end": status["context_end_reason"], "third_tick": third})
    assert ok, "a revocation did not close the generation, flush the key and stop requests"


def test_s5_replayed_sequence_closes_and_a_new_generation_restarts_at_sequence_one():
    _require_runtime()
    tick = _tick_ns()
    first, before = len(DOMAINS), CYCLE._BUDGET.generations
    cycle, gate, listener, _domain_s5 = _cycle_fixture("s5", [_step(), _step("inactive", "replayed_sequence"), _step()])
    gate_2, stopped = None, {}
    try:
        stream = gate.stream(start_ns=time.monotonic_ns() + 50 * MS, count=300).start()
        sleep_until(stream.start_ns + 100 * MS)
        one_before, one_phase, one_after = _tick(cycle)
        status_1 = cycle.status()
        sleep_until(one_before + CYCLE.INTERVAL_MS * MS)
        two_before, two_phase, two_after = _tick(cycle)
        status_2 = cycle.status()
        activated_2 = gate.activated()
        probes = stream.join()
        gate_2, _domain_s5b = _start_again("s5", cycle)
        stream_2 = gate_2.stream(start_ns=time.monotonic_ns() + 50 * MS, count=250).start()
        sleep_until(stream_2.start_ns + 100 * MS)
        three_before, three_phase, three_after = _tick(cycle)
        status = cycle.status()
        probes_2 = stream_2.join()
    finally:
        stopped = _finish(cycle, [gate, gate_2], listener, DOMAINS[first:])
    changed = status["generation_id"] != status_1["generation_id"] and status_1["generation_id"] == status_2["generation_id"]
    ok = (one_phase == "serving" and status_1["last_reason"] == "activated"
          and live_delivery(probes, one_after, min(two_before, _e_lower_est(one_before, tick)), 50)
          and two_phase == "closed" and status_2["context_end_reason"] == "replayed_sequence" and activated_2 == []
          and closed(_probes_after(probes, two_after + tick)) and three_phase == "serving"
          and status["last_reason"] == "activated" and status["sequence"] == 1 and changed
          and live_delivery(probes_2, three_after, _e_lower_est(three_before, tick), 50)
          and status["generations"] - before == 2 and stopped.get("requests") == 3)
    ints = _common(status, before, stopped, -1, len(admitted_after(probes, two_after + tick)))
    ints |= {"sequence_before_restart": status_2["sequence"], "restart_delivered": sum(p.delivered for p in probes_2)}
    record("s5", ok, ints, {"outcome": status["last_reason"], "k9_path": _k9_path(),
                            "context_end": status_2["context_end_reason"], "generation_changed": "yes" if changed else "no"})
    assert ok, "a replayed sequence did not close the generation, or the restart did not begin a new one at sequence 1"


def test_s6_stale_decision_is_blocked_by_the_listener_and_a_fresh_one_activates():
    _require_runtime()
    tick = _tick_ns()
    first, before = len(DOMAINS), CYCLE._BUDGET.generations
    cycle, gate, listener, _domain_s6 = _cycle_fixture("s6", [_step(), _step(stale=True), _step()])
    stopped = {}
    try:
        stream = gate.stream(start_ns=time.monotonic_ns() + 50 * MS, count=500).start()
        sleep_until(stream.start_ns + 100 * MS)
        one_before, one_phase, one_after = _tick(cycle)
        status_1 = cycle.status()
        sleep_until(one_before + CYCLE.INTERVAL_MS * MS)
        two_before, two_phase, two_after = _tick(cycle)
        status_2 = cycle.status()
        activated_2 = gate.activated()
        sleep_until(one_before + 2 * CYCLE.INTERVAL_MS * MS)
        three_before, three_phase, three_after = _tick(cycle)
        status = cycle.status()
        activated = gate.activated()
        probes = stream.join()
    finally:
        stopped = _finish(cycle, [gate], listener, DOMAINS[first:])
    ok = (one_phase == "serving" and status_1["last_reason"] == "activated" and two_phase == "serving"
          and status_2["last_reason"] == "cp_unavailable" and status_2["consecutive_unavailable"] == 1
          and status_2["sequence"] == 2 and activated_2 == [1]
          and live_delivery(probes, one_after, _e_lower_est(one_before, tick), LIVE_PERCENT)
          and three_phase == "serving" and status["last_reason"] == "activated" and status["sequence"] == 3
          and activated == [3] and live_delivery(probes, three_after, _e_lower_est(three_before, tick), 50)
          and stopped.get("decide_failed") == 1 and stopped.get("stale_attempts") == 1 and stopped.get("requests") == 3
          and stopped.get("answered") == 2 and status["generations"] - before == 1)
    ints = _common(status, before, stopped, -1, -1)
    ints |= {"consecutive_unavailable_2": status_2["consecutive_unavailable"], "sequence_2": status_2["sequence"],
             "stale_attempts": stopped.get("stale_attempts", -1), "activated_entries_2": len(activated_2)}
    record("s6", ok, ints, {"outcome": status["last_reason"], "k9_path": _k9_path(), "outcome_2": status_2["last_reason"]})
    assert ok, "a stale decision reached the cycle, or the next fresh decision did not activate"


def test_c2_no_owned_namespace_process_socket_mount_or_link_survives():
    _require_runtime()
    with contextlib.suppress(ChildProcessError):
        while os.waitpid(-1, os.WNOHANG)[0]:
            pass
    live_children = sum(child.process.poll() is None for child in CHILDREN)
    open_sockets = sum(sock.fileno() != -1 for sock in SOCKETS)
    open_domains = sum(not domain._closed for domain in DOMAINS)
    links = sorted(name for _index, name in socket.if_nameindex())
    others = [entry.name for entry in Path("/proc").iterdir() if entry.name.isdigit()
              and int(entry.name) not in (1, os.getpid())]
    registry_unresolved = sum(AUTHORITY.unresolved_children().values())
    ok = (not OPEN_GATES and live_children == 0 and open_sockets == 0 and open_domains == 0 and not MOUNTS
          and links == ["lo"] and not others and registry_unresolved == 0)
    record("c2", ok, {"open_gates": len(OPEN_GATES), "live_children": live_children, "open_sockets": open_sockets,
                      "open_domains": open_domains, "mounts_left": len(MOUNTS), "outer_links": len(links),
                      "other_processes": len(others), "gates_created": COUNTERS["gates"],
                      "children_spawned": COUNTERS["children"], "sockets_created": COUNTERS["sockets"],
                      "domains_created": COUNTERS["domains"], "cycles_created": COUNTERS["cycles"],
                      "scripted_deciders": COUNTERS["deciders"], "registry_unresolved": registry_unresolved}, {})
    assert ok, "an owned namespace, process, socket, mount or link survived the cases"
