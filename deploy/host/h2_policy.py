"""H2-1 generation policy installer (H2-POLICY-FABLE-REFRESH revision 5, sections 4 and 6.1).

SPDX-License-Identifier: LicenseRef-Heel-Commercial

Status: source candidate, component evidence only. No runtime verdict, no customer enablement.

The future H3 bootstrap worker receives one generation namespace descriptor from the cycle (H2-A)
and calls ``install(fd, input)``. The installer writes one named table (``authority.TABLE``) into
that namespace: the chain clears the packet mark, looks it up by ``ip saddr . GATEWAY`` in the H1
``activated`` map, accepts the slot source to the slot gateway itself on TCP 443 (H2-3, the fixed
control path; no mark, set or lease), and accepts only a live ``prepared`` element to a fixed IPv4
target on TCP 443. A binding generation (``control_only``, empty tuple) has no target accept.
H1 alone writes elements, through its public API; this module never does. The receipt bytes exist
only on the one transition ``readback_ok -> receipt_ready`` inside ``install()``.

Every nft step is one fresh Python helper started by ``subprocess.Popen`` without ``preexec_fn``,
with ``close_fds=True`` and the one namespace duplicate in ``pass_fds``. The helper always enters
the namespace with ``setns``, closes the duplicate and ``execve``s nft; there is no mode or flag.
No DNS, network or resolver is used: ``observed_public_addresses`` is, by the trusted-constructor
precondition (H3), the unmodified ``select_public_addresses`` tuple, and the builder checks its
canonical shape only. ``authority.py`` and the codec of ``heel/saas/host_authority.py`` are loaded
by file path. Outcomes carry fixed tokens only: no nft text, address or path.

Private test seams (assigned only by ``tests/test_host_h2_policy.py``, never read from the
environment or from an input): ``NFT_PATH``, ``_PLATFORM_OK`` and ``_HELPER_SOURCE``.
"""
import dataclasses
import importlib.util
import ipaddress
import json
import os
import re
import select
import subprocess
import sys
import threading
import time
import types
from pathlib import Path

_HERE = Path(__file__).resolve().parent


def _load(name: str, path: Path):
    """One module object per file per process (the same module names the cycle loads them under, so
    the cleanup registry of ``authority.py`` stays one registry)."""
    existing = sys.modules.get(name)
    if existing is not None and Path(getattr(existing, "__file__", "")).resolve() == path:
        return existing
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_authority = _load("heel_host_authority_domain", _HERE / "authority.py")
_codec = _load("heel_host_authority_codec", _HERE.parents[1] / "heel" / "saas" / "host_authority.py")

__all__ = ("build_input", "cleanup", "install", "readback_matches", "render_table", "unresolved_helpers")

H2_INSTALL_BUDGET_MS = 2500  # check + install + readback, from install() entry
H2_WORKER_BUDGET_MS = 4000  # 2500 + 250 (last install child's reap grace) + 1000 + 250 (cleanup child)
CHILD_TIMEOUT_MS = _authority.PREPARE_CHILD_TIMEOUT_MS  # 1000, helper startup included
REAP_GRACE_MS = _authority.CHILD_REAP_GRACE_MS  # 250
MAX_BATCH_BYTES = _authority.MAX_BATCH_BYTES
MAX_OUTPUT_BYTES = _authority.MAX_OUTPUT_BYTES
MAX_ADDRESSES = 16  # MAX_DNS_ANSWERS of the unchanged client
EGRESS_PORT = 443
RECEIPT_SCHEMA = "heel.h2a.receipt.v1"  # cycle.RECEIPT_SCHEMA; the tests pin the equality
STATES = ("new", "identity_ok", "checked", "installed", "readback_ok", "receipt_ready", "refused_input",
          "refused_platform", "refused_reused_input", "unsupported_ipv6_only", "identity_mismatch",
          "helper_argv_invalid", "setns_failed", "helper_exec_failed", "check_refused", "install_refused",
          "readback_mismatch", "timeout", "cleaned", "quarantined")
HELPER_EXIT_CODES = {124: "helper_argv_invalid", 125: "setns_failed", 126: "helper_exec_failed"}

NFT_PATH = _authority.NFT_PATH  # TEST SEAM: tests point it at an owned fake nft
_PLATFORM_OK = (sys.platform.startswith("linux") and hasattr(os, "setns") and NFT_PATH is not None
                and os.path.isabs(sys.executable) and os.path.isfile(sys.executable))  # TEST SEAM

# The production helper: one unconditional setns -> close -> execve sequence. Exit codes are its
# only output: 124 argv, 125 setns, 126 close/exec. Imports os and sys only.
_HELPER_SOURCE = """\
import os
import sys
try:
    fd, nft, args = int(sys.argv[1]), sys.argv[2], sys.argv[3:]
    if fd < 3 or not nft.startswith("/") or not args:
        raise ValueError
except BaseException:
    os._exit(124)
try:
    os.setns(fd, os.CLONE_NEWNET)
except BaseException:
    os._exit(125)
try:
    os.close(fd)
    os.execve(nft, ["nft", *args], {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
except BaseException:
    pass
os._exit(126)
"""
_CHILD_ENV = (("PATH", _authority.CHILD_PATH), ("LC_ALL", "C"))
_CHECK_ARGS = ("-c", "-f", "-")
_INSTALL_ARGS = ("-f", "-")
_READBACK_ARGS = ("-j", "list", "table", "inet", _authority.TABLE)
_MS = 1_000_000
_SLICE_MS = 5
_HEX32 = re.compile(r"[0-9a-f]{32}")
_SLOT = re.compile(r"[a-z0-9][a-z0-9_.:-]{0,79}")
_HOSTNAME = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?")
_SEAL = object()
_LOCK = threading.Lock()
_INPUTS: dict[tuple[str, str], str] = {}  # (generation_id, bootstrap_fence) -> last state; never removed
_UNREAPED_HELPERS: list = []  # Popen objects SIGKILLed but not reaped within the grace; kept referenced


# ---------------------------------------------------------------------------------------------
# The local input (section 4.1). A worker type, not a wire schema: every field comes from the H2-A
# request or the validated CycleContext, except the trusted tuple and the derived IPv4 targets.

@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class H2PolicyInput:
    generation_id: str
    namespace_identity: tuple[int, int]
    slot_id: str
    slot_hop_src: str
    slot_hop_dst: str
    bootstrap_fence: str
    egress_hostname: str
    egress_port: int
    observed_public_addresses: tuple
    control_only: bool = False  # H2-3: a binding generation; True iff observed_public_addresses == ()
    ipv4_egress_targets: tuple = dataclasses.field(init=False)

    def __post_init__(self) -> None:
        for name in ("generation_id", "bootstrap_fence"):
            value = getattr(self, name)
            if type(value) is not str or not _HEX32.fullmatch(value):
                raise ValueError(f"{name}_invalid")
        identity = self.namespace_identity
        if (type(identity) is not tuple or len(identity) != 2
                or not all(type(part) is int and part >= 0 for part in identity)):
            raise ValueError("namespace_identity_invalid")
        if type(self.slot_id) is not str or not self.slot_id.isascii() or not _SLOT.fullmatch(self.slot_id):
            raise ValueError("slot_id_invalid")
        for name in ("slot_hop_src", "slot_hop_dst"):
            value = getattr(self, name)
            try:
                canonical = type(value) is str and value.isascii() and str(ipaddress.IPv4Address(value)) == value
            except ValueError:
                canonical = False
            if not canonical:
                raise ValueError(f"{name}_invalid")
        if self.slot_hop_src == self.slot_hop_dst:
            raise ValueError("slot_hop_invalid")
        if (type(self.egress_hostname) is not str or not self.egress_hostname.isascii()
                or not _HOSTNAME.fullmatch(self.egress_hostname)):
            raise ValueError("egress_hostname_invalid")
        if type(self.egress_port) is not int or self.egress_port != EGRESS_PORT:
            raise ValueError("egress_port_invalid")
        if type(self.control_only) is not bool:
            raise ValueError("control_only_invalid")
        addresses = self.observed_public_addresses
        if self.control_only:
            if type(addresses) is not tuple or addresses:
                raise ValueError("observed_public_addresses_invalid")
        elif (type(addresses) is not tuple or not 1 <= len(addresses) <= MAX_ADDRESSES
                or not all(type(a) in (ipaddress.IPv4Address, ipaddress.IPv6Address) for a in addresses)
                or any((a.version, a.packed) >= (b.version, b.packed) for a, b in zip(addresses, addresses[1:]))):
            raise ValueError("observed_public_addresses_invalid")
        object.__setattr__(self, "ipv4_egress_targets",
                           tuple(a for a in addresses if type(a) is ipaddress.IPv4Address))


def build_input(**fields) -> H2PolicyInput:
    """Pure validation of the local input; raises ``ValueError(token)``."""
    try:
        return H2PolicyInput(**fields)
    except TypeError:
        raise ValueError("input_fields_invalid") from None


# ---------------------------------------------------------------------------------------------
# The table (section 4.2) and its exact readback (section 4.4).

def render_table(policy: H2PolicyInput) -> bytes:
    """One table, four rules, two accepts (three and one under ``control_only``); both key uses carry
    the typed gateway of the slot's dst; the control accept names the slot hop itself, before the target accept."""
    if type(policy) is not H2PolicyInput:
        raise TypeError("input_invalid")
    if not policy.ipv4_egress_targets and not policy.control_only:
        raise ValueError("unsupported_ipv6_only")
    gateway = f"(ip daddr & 0.0.0.0 | {policy.slot_hop_dst})"
    targets = ", ".join(map(str, policy.ipv4_egress_targets))
    table, prepared, activated, gate = (_authority.TABLE, _authority.PREPARED_SET, _authority.ACTIVATED_MAP,
                                        _authority.GATE_CHAIN)
    admit = ("" if policy.control_only else
             f"    ip saddr . {gateway} . meta mark @{prepared} ip daddr {{ {targets} }} tcp dport {EGRESS_PORT} accept\n")
    text = (f"table inet {table} {{\n"
            f"  set {prepared} {{ type ipv4_addr . ipv4_addr . mark ; flags timeout ; }}\n"
            f"  map {activated} {{ type ipv4_addr . ipv4_addr : mark ; }}\n"
            f"  chain {gate} {{\n"
            "    type filter hook output priority 0 ; policy drop ;\n"
            "    meta mark set 0\n"
            f"    meta mark set ip saddr . {gateway} map @{activated}\n"
            f"    ip saddr {policy.slot_hop_src} ip daddr {policy.slot_hop_dst} tcp dport {EGRESS_PORT} accept\n"
            f"{admit}"
            "  }\n"
            "}\n").encode("ascii")
    if len(text) > MAX_BATCH_BYTES:
        raise ValueError("batch_too_large")
    return text


_META_MARK = {"meta": {"key": "mark"}}
_SADDR = {"payload": {"protocol": "ip", "field": "saddr"}}
_DADDR = {"payload": {"protocol": "ip", "field": "daddr"}}
_DPORT = {"payload": {"protocol": "tcp", "field": "dport"}}
_READBACK_PARTS = ("document", "metainfo", "items", "table", "prepared_set", "activated_map", "chain", "reset_rule",
                   "lookup_rule", "control_rule", "admit_rule")


def _same(value, expected) -> bool:
    """Exact JSON equality with exact types: no bool for an int, no float for an int, no extra key."""
    if type(value) is not type(expected):
        return False
    if isinstance(expected, dict):
        return value.keys() == expected.keys() and all(_same(value[key], expected[key]) for key in expected)
    if isinstance(expected, list):
        return len(value) == len(expected) and all(map(_same, value, expected))
    return value == expected


def _one_of(value, choices) -> bool:
    return any(_same(value, choice) for choice in choices)


def _body(item: object, kind: str) -> dict | None:
    """The object of a single-key ``{kind: {...}}`` item without its integer kernel ``handle``."""
    if not isinstance(item, dict) or list(item) != [kind] or not isinstance(item[kind], dict):
        return None
    body = dict(item[kind])
    if "handle" in body:
        if type(body["handle"]) is not int or body["handle"] < 0:
            return None
        del body["handle"]
    return body


def _match(op_choices, left, right) -> list:
    return [{"match": {"op": op, "left": left, "right": right}} for op in op_choices]


def readback_matches(document: object, policy: H2PolicyInput) -> tuple[bool, dict[str, str]]:
    """The exact oracle over ``nft -j list table inet heel_lease`` for this input: the metainfo, the
    table, the two H1 sets empty and typed, the output/drop chain and exactly the rules in order reset,
    lookup, control, admit (eight items; seven and no admit under ``control_only``), the typed gateway
    in both keys, the control rule exactly ``ip saddr <src> ip daddr <dst> tcp dport 443 accept``,
    exactly the input's IPv4 targets and TCP 443. Only the named table is judged. Enumerated encodings
    only (handles dropped; mark 0 as integer or 0x0 string; ``==`` or ``in`` for the two set lookups
    as the H2K1 oracle and for the control source; one target as a bare string or a one-member set);
    anything else is a mismatch. Total: never raises."""
    try:
        return _readback(document, policy)
    except (TypeError, ValueError, KeyError, AttributeError, IndexError, RecursionError):
        return False, {"readback": "mismatch", "part": "document"}


def _readback(document: object, policy: H2PolicyInput) -> tuple[bool, dict[str, str]]:
    def miss(part: str) -> tuple[bool, dict[str, str]]:
        return False, {"readback": "mismatch", "part": part}

    if type(policy) is not H2PolicyInput or bool(policy.ipv4_egress_targets) == policy.control_only:
        return miss("document")
    if not isinstance(document, dict) or list(document) != ["nftables"] or not isinstance(document["nftables"], list):
        return miss("document")
    items = document["nftables"]
    meta = items[0].get("metainfo") if items and isinstance(items[0], dict) and list(items[0]) == ["metainfo"] else None
    if not isinstance(meta, dict) or not _same(meta.get("json_schema_version"), 1):
        return miss("metainfo")
    items = items[1:]
    if len(items) != (7 if policy.control_only else 8):
        return miss("items")
    table, gate = _authority.TABLE, _authority.GATE_CHAIN
    if not _same(_body(items[0], "table"), {"family": "inet", "name": table}):
        return miss("table")
    sets = {kind: _body(item, kind) for item in items[1:3] for kind in ("set", "map") if isinstance(item, dict) and kind in item}
    prepared = {"family": "inet", "name": _authority.PREPARED_SET, "table": table,
                "type": ["ipv4_addr", "ipv4_addr", "mark"]}
    if not _one_of(sets.get("set"), [{**prepared, "flags": ["timeout"]}, {**prepared, "flags": "timeout"}]):
        return miss("prepared_set")
    if not _same(sets.get("map"), {"family": "inet", "name": _authority.ACTIVATED_MAP, "table": table,
                                   "type": ["ipv4_addr", "ipv4_addr"], "map": "mark"}):
        return miss("activated_map")
    if not _same(_body(items[3], "chain"), {"family": "inet", "table": table, "name": gate, "type": "filter",
                                            "hook": "output", "prio": 0, "policy": "drop"}):
        return miss("chain")
    rules = [_body(item, "rule") for item in items[4:]]
    if not all(isinstance(rule, dict) and rule.keys() == {"family", "table", "chain", "expr"}
               and _same([rule["family"], rule["table"], rule["chain"]], ["inet", table, gate])
               and isinstance(rule["expr"], list) for rule in rules):
        return miss("items")
    reset, lookup, control, *admit = (rule["expr"] for rule in rules)
    if not _one_of(reset, [[{"mangle": {"key": _META_MARK, "value": value}}] for value in (0, "0x00000000")]):
        return miss("reset_rule")
    dst = policy.slot_hop_dst
    gateway = {"|": [{"&": [_DADDR, dst]}, int.from_bytes(ipaddress.IPv4Address(dst).packed, "big")]}
    if not _same(lookup, [{"mangle": {"key": _META_MARK, "value": {"map": {
            "key": {"concat": [_SADDR, gateway]}, "data": "@" + _authority.ACTIVATED_MAP}}}}]):
        return miss("lookup_rule")
    if not _one_of(control, [[*_match((op,), _SADDR, policy.slot_hop_src), *_match(("==",), _DADDR, dst),
                              *_match(("==",), _DPORT, EGRESS_PORT), {"accept": None}] for op in ("==", "in")]):
        return miss("control_rule")
    if policy.control_only:
        return True, {"readback": "exact", "part": "none"}
    admit, = admit
    targets = [str(address) for address in policy.ipv4_egress_targets]
    if len(admit) != 4 or not _same(admit[3], {"accept": None}):
        return miss("admit_rule")
    if not _one_of(admit[0], _match(("==", "in"), {"concat": [_SADDR, gateway, _META_MARK]},
                                    "@" + _authority.PREPARED_SET)):
        return miss("admit_rule")
    pins = admit[1].get("match") if isinstance(admit[1], dict) and list(admit[1]) == ["match"] else None
    right = pins.get("right") if isinstance(pins, dict) and pins.keys() == {"op", "left", "right"} else None
    members = right["set"] if isinstance(right, dict) and list(right) == ["set"] else None
    if members is None and len(targets) == 1 and type(right) is str:
        members = [right]
    if (not isinstance(members, list) or not all(type(member) is str for member in members)
            or len(members) != len(targets) or sorted(members) != sorted(targets)
            or not _same(pins["left"], _DADDR) or pins["op"] not in ("==", "in")):
        return miss("admit_rule")
    if not _same(admit[2], {"match": {"op": "==", "left": _DPORT, "right": EGRESS_PORT}}):
        return miss("admit_rule")
    return True, {"readback": "exact", "part": "none"}


# ---------------------------------------------------------------------------------------------
# The sealed outcome and the private receipt (section 4.5).

@dataclasses.dataclass(frozen=True, slots=True)
class Outcome:
    """Constructed only inside this module. ``receipt`` is bytes iff ``state == "receipt_ready"``."""

    state: str
    receipt: bytes | None
    tokens: types.MappingProxyType
    _seal: object = dataclasses.field(default=None, repr=False, compare=False, kw_only=True)

    def __post_init__(self) -> None:
        if self._seal is not _SEAL:
            raise TypeError("unsealed_outcome")
        object.__setattr__(self, "_seal", None)
        if self.state not in STATES or (self.receipt is not None) != (self.state == "receipt_ready"):
            raise TypeError("outcome_invalid")


def _outcome(state: str, **tokens: str) -> Outcome:
    return Outcome(state, None, types.MappingProxyType(dict(tokens)), _seal=_SEAL)


def _receipt_document(policy: H2PolicyInput) -> dict:
    return {"schema": RECEIPT_SCHEMA, "generation_id": policy.generation_id,
            "namespace_dev": policy.namespace_identity[0], "namespace_ino": policy.namespace_identity[1],
            "bootstrap_fence": policy.bootstrap_fence, "installed": True}


# ---------------------------------------------------------------------------------------------
# One helper child (section 4.3): the duplicate is checked, passed and closed; stdin, output, exit
# and reap all run against the one deadline; a late exit is never a success.

class _Run:
    __slots__ = ("token", "status", "output", "reaped", "launched")

    def __init__(self, token: str, launched: bool = False):
        self.token, self.status, self.output, self.reaped, self.launched = token, None, b"", True, launched


def _platform_ok() -> bool:
    return (_PLATFORM_OK is True and isinstance(NFT_PATH, str) and os.path.isabs(NFT_PATH)
            and isinstance(sys.executable, str) and os.path.isabs(sys.executable))


def _identity_of(fd: int) -> tuple[int, int] | None:
    try:
        info = os.fstat(fd)
    except (OSError, ValueError, OverflowError):
        return None
    return info.st_dev, info.st_ino


def _helper(fd: int, policy: H2PolicyInput, nft_args: tuple, batch: bytes, deadline_ns: int, clock) -> _Run:
    try:
        dup = os.dup(fd)
    except (OSError, ValueError, OverflowError):
        return _Run("identity_mismatch")
    try:
        if _identity_of(dup) != policy.namespace_identity:  # the descriptor actually handed over
            return _Run("identity_mismatch")
        argv = [sys.executable, "-I", "-S", "-B", "-c", _HELPER_SOURCE, str(dup), NFT_PATH, *nft_args]
        try:
            child = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     close_fds=True, pass_fds=(dup,), cwd="/", env=dict(_CHILD_ENV),
                                     start_new_session=False)
        except (OSError, ValueError, subprocess.SubprocessError):
            return _Run("helper_exec_failed")
    finally:
        os.close(dup)  # the parent's one close of its duplicate; the caller's fd is never closed here
    return _drive(child, batch, deadline_ns, clock)


def _drive(child, batch: bytes, deadline_ns: int, clock) -> _Run:
    run, settled = _Run("exited", launched=True), False
    pending, chunks, size = memoryview(batch), [], 0
    pipes = [child.stdin, child.stdout]
    try:
        in_fd, out_fd = child.stdin.fileno(), child.stdout.fileno()
        os.set_blocking(in_fd, False)
        os.set_blocking(out_fd, False)
        poller = select.poll()
        poller.register(out_fd, select.POLLIN)
        if pending:
            poller.register(in_fd, select.POLLOUT)
        else:
            child.stdin.close()
        reading, now = True, deadline_ns
        while run.token == "exited":
            now = clock()
            if now >= deadline_ns:
                run.token = "timeout"
                break
            if not reading:
                code = child.poll()
                observed = clock()
                if code is not None:
                    settled, run.status = True, code if observed <= deadline_ns else None
                    run.token = "exited" if run.status is not None else "timeout"
                    break
                time.sleep(min(_SLICE_MS * _MS, max(deadline_ns - observed, 0)) / 1e9)
                continue
            for fd, _event in poller.poll(max(1, min(_SLICE_MS, (deadline_ns - now + _MS - 1) // _MS))):
                if fd == in_fd:
                    try:
                        pending = pending[os.write(in_fd, pending):]
                    except BlockingIOError:
                        continue
                    except OSError:  # the reader is gone; its exit status decides
                        pending = pending[:0]
                    if not pending:
                        poller.unregister(in_fd)
                        child.stdin.close()
                    continue
                try:
                    data = os.read(out_fd, 65536)
                except BlockingIOError:
                    continue
                if not data:
                    poller.unregister(out_fd)
                    reading = False
                    continue
                size += len(data)
                if size > MAX_OUTPUT_BYTES:
                    run.token, now = "overflow", clock()
                    break
                chunks.append(data)
        if not settled:
            run.reaped = _kill_and_reap(child, now, clock)
            settled = True
        run.output = b"".join(chunks)
        return run
    finally:
        if not settled:  # an escaped exception: kill, never wait past the grace
            _kill_and_reap(child, clock(), clock)
        for pipe in pipes:
            if not pipe.closed:
                pipe.close()


def _kill_and_reap(child, killed_ns: int, clock) -> bool:
    """SIGKILL unless already reaped, then poll for the reap until ``REAP_GRACE_MS`` after the
    observation that decided the kill; past it the child is recorded unreaped (outcome unknown)."""
    grace_deadline_ns = killed_ns + REAP_GRACE_MS * _MS
    if child.poll() is None:
        try:
            child.kill()
        except OSError:
            pass
    while child.poll() is None:
        observed = clock()
        if observed >= grace_deadline_ns:
            with _LOCK:
                _UNREAPED_HELPERS.append(child)
            return False
        time.sleep(min(_SLICE_MS * _MS, grace_deadline_ns - observed) / 1e9)
    return True


def _classify(run: _Run, refused: str) -> str:
    """``ok`` or the step's failure state. Helper exit codes are fixed; any other nonzero is nft's."""
    if run.token != "exited":
        return {"timeout": "timeout", "overflow": refused}.get(run.token, run.token)
    if run.status == 0:
        return "ok"
    return HELPER_EXIT_CODES.get(run.status, refused)


# ---------------------------------------------------------------------------------------------
# install / cleanup / unresolved_helpers (sections 4.4, 4.5, 4.7).

def _claim(policy: H2PolicyInput) -> bool:
    key = (policy.generation_id, policy.bootstrap_fence)
    with _LOCK:
        if key in _INPUTS:
            return False
        _INPUTS[key] = "new"
        return True


def _record(policy: H2PolicyInput, outcome: Outcome) -> Outcome:
    with _LOCK:
        _INPUTS[(policy.generation_id, policy.bootstrap_fence)] = outcome.state
    return outcome


def _remove_table(fd: int, policy: H2PolicyInput, deadline_ns: int, clock) -> str:
    """One bounded ``delete table``: ``cleaned`` only on a known exit 0 with the identity intact."""
    if _identity_of(fd) != policy.namespace_identity:
        return "identity_mismatch"
    run = _helper(fd, policy, _INSTALL_ARGS, f"delete table inet {_authority.TABLE}\n".encode("ascii"), deadline_ns,
                  clock)
    return "cleaned" if _classify(run, "refused") == "ok" else ("unreaped" if not run.reaped else "refused")


def install(fd: int, policy: H2PolicyInput, *, clock=time.monotonic_ns) -> Outcome:
    """Check, install and read back the table in the namespace of the borrowed ``fd`` (never
    closed here). Single-use per (generation_id, bootstrap_fence). Receipt only on an exact readback
    with the namespace identity intact; every other result carries none, and the cycle's deadline
    and revoke stay authoritative."""
    start = clock()
    if type(policy) is not H2PolicyInput or type(fd) is not int or fd < 0:
        return _outcome("refused_input", phase="entry")
    if not policy.ipv4_egress_targets and not policy.control_only:
        return _outcome("unsupported_ipv6_only", phase="entry")
    if not _platform_ok():
        return _outcome("refused_platform", phase="entry")
    if not _claim(policy):
        return _outcome("refused_reused_input", phase="entry")
    try:
        return _record(policy, _install(fd, policy, start, clock))
    except Exception:
        return _record(policy, _outcome("quarantined", phase="internal", cause="internal_error", cleanup="not_run"))


def _install(fd: int, policy: H2PolicyInput, start: int, clock) -> Outcome:
    if _identity_of(fd) != policy.namespace_identity:
        return _outcome("identity_mismatch", phase="entry", cleanup="not_run")
    phase_deadline = start + H2_INSTALL_BUDGET_MS * _MS
    batch = render_table(policy)
    attempted = False
    steps = (("check", _CHECK_ARGS, batch, "check_refused"), ("install", _INSTALL_ARGS, batch, "install_refused"),
             ("readback", _READBACK_ARGS, b"", "readback_mismatch"))
    for phase, nft_args, data, refused in steps:
        began = clock()
        deadline = min(began + CHILD_TIMEOUT_MS * _MS, phase_deadline)
        run = _Run("timeout") if began >= deadline else _helper(fd, policy, nft_args, data, deadline, clock)
        attempted = attempted or (phase == "install" and run.launched)
        state, part = _classify(run, refused), "none"
        if state == "ok" and phase == "readback":
            ok, tokens = readback_matches(_parse(run.output), policy)
            state, part = ("ok" if ok else "readback_mismatch"), tokens["part"]
        if state != "ok":
            if not run.reaped:
                return _outcome("quarantined", phase=phase, cause=state, cleanup="unknown_child")
            if not attempted:
                return _outcome(state, phase=phase, cleanup="not_run")
            return _after_failure(fd, policy, start, clock, phase, state, part)
    if _identity_of(fd) != policy.namespace_identity:
        return _after_failure(fd, policy, start, clock, "final_identity", "identity_mismatch")
    receipt = _codec.canonical(_receipt_document(policy))
    return Outcome("receipt_ready", receipt, types.MappingProxyType({"phase": "none", "readback": "exact"}), _seal=_SEAL)


def _after_failure(fd: int, policy: H2PolicyInput, start: int, clock, phase: str, cause: str,
                   part: str = "none") -> Outcome:
    """After an install was attempted: one bounded cleanup inside the worker budget."""
    now = clock()
    deadline = min(now + CHILD_TIMEOUT_MS * _MS, start + (H2_WORKER_BUDGET_MS - REAP_GRACE_MS) * _MS)
    result = "out_of_budget" if now >= deadline else _remove_table(fd, policy, deadline, clock)
    state = "cleaned" if result == "cleaned" else "quarantined"
    return _outcome(state, phase=phase, cause=cause, cleanup=result, readback=part)


def _parse(output: bytes) -> object:
    try:
        return json.loads(output.decode("ascii"), object_pairs_hook=_no_duplicates, parse_constant=_no_constant)
    except (UnicodeError, ValueError, RecursionError):
        return None


def _no_duplicates(pairs: list) -> dict:
    document = dict(pairs)
    if len(document) != len(pairs):
        raise ValueError("duplicate key")
    return document


def _no_constant(_name: str):
    raise ValueError("non-finite number")


def cleanup(fd: int, policy: H2PolicyInput, *, clock=time.monotonic_ns) -> Outcome:
    """Remove the table after a ``receipt_ready`` install of this input (H3 decides when). A
    cleaned or quarantined input, or one that never installed, is a no-op; a fault quarantines."""
    start = clock()
    if type(policy) is not H2PolicyInput or type(fd) is not int or fd < 0:
        return _outcome("refused_input", phase="cleanup")
    if not _platform_ok():
        return _outcome("refused_platform", phase="cleanup")
    key = (policy.generation_id, policy.bootstrap_fence)
    with _LOCK:
        recorded = _INPUTS.get(key)
        if recorded == "receipt_ready":
            _INPUTS[key] = "new"  # busy: a concurrent install or cleanup of this input is refused
    if recorded is None:
        return _outcome("refused_input", phase="cleanup", cleanup="not_installed")
    if recorded == "new":
        return _outcome("refused_reused_input", phase="cleanup", cleanup="busy")
    if recorded != "receipt_ready":
        return _outcome(recorded, phase="cleanup", cleanup="noop")
    try:
        result = _remove_table(fd, policy, start + CHILD_TIMEOUT_MS * _MS, clock)
    except Exception:
        result = "internal_error"
    return _record(policy, _outcome("cleaned" if result == "cleaned" else "quarantined", phase="cleanup",
                                    cleanup=result))


def unresolved_helpers() -> dict[str, int]:
    """Helpers SIGKILLed but not reaped within the grace; polled once each, never waited for."""
    with _LOCK:
        _UNREAPED_HELPERS[:] = [child for child in _UNREAPED_HELPERS if child.poll() is None]
        return {"unreaped": len(_UNREAPED_HELPERS)}
