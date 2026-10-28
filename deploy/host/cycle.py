"""Host supervisor authorization cycle (H1A3-1, H1A3DR design sections 2-7).

SPDX-License-Identifier: LicenseRef-Heel-Commercial

One ``HostCycle`` owns one generation at a time: one ``LeaseDomain`` (namespace held by
descriptor), one immutable ``CycleContext`` and one outstanding request. Every tick prepares a new
key before it asks the control plane, then activates it only if the key's certainly-live window has
not ended (``t_act < E_lower``) and the kernel's expiry bound lies inside the authority the reply
granted (``E_upper <= D``). Activation writes no lifetime, so no packet is admitted on the slot's
tuple after ``min(E_upper, D)`` of the cycle that proved it unless a later cycle proves it again.
Nothing is learned from a reply, no sequence is ever resent, and every context end closes the
generation; a new context needs a new domain. The transition table, the residual rule and the
signal contract are in ``docs/saas/HOST_AUTHORITY_CYCLE.md``.

A caller may register one ``BootstrapChannel`` per generation before ``start()`` (H2-A): the
generation then reaches ``ready`` only after the cycle armed the root controller, handed the
worker one namespace descriptor by ``SCM_RIGHTS`` and read the worker's exact receipt, all under
one monotonic deadline and outside the cycle lock; anything else revokes the operation and refuses
the start (``docs/saas/H2A_BOOTSTRAP_CONTRACT.md``). A cycle that never registers keeps the H1
behavior.

The only admission is ``Enablement.NON_CUSTOMER``: this module defines no environment variable,
flag or entry point, and enables no customer executor. ``authority.py``, ``profile.py`` and the
codec of ``heel/saas/host_authority.py`` are loaded by file path. Status and logs carry fixed
tokens and integers only.
"""
import array
import dataclasses
import enum
import errno
import hmac
import importlib.util
import json
import logging
import os
import secrets
import signal
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Callable

_HERE = Path(__file__).resolve().parent


def _load(name: str, path: Path):
    """One module object per file per process (the cleanup registry of ``authority.py`` is
    process-global state; a second copy would be a second, invisible registry)."""
    existing = sys.modules.get(name)
    if existing is not None and Path(getattr(existing, "__file__", "")).resolve() == path:
        return existing
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses resolve string annotations through sys.modules
    spec.loader.exec_module(module)
    return module


authority = _load("heel_host_authority_domain", _HERE / "authority.py")
profile = _load("heel_host_profile", _HERE / "profile.py")
codec = _load("heel_host_authority_codec", _HERE.parents[1] / "heel" / "saas" / "host_authority.py")

LEASE_MS = 3000  # T: the prepared element's timeout (<= authority.MAX_PREPARE_TIMEOUT_MS)
INTERVAL_MS = 1000  # the cadence H3 calls tick() at
REQUEST_BUDGET_MS = 1000  # one exchange, bounded further by E_lower
MAX_EFFECTIVE_REMAINING_MS = 86_400_000
MEMBER_BOUNDS_MS = (2_592_000_000, 86_400_000, 600_000)  # proof, binding, grant
MAX_CONSECUTIVE_UNAVAILABLE = 3
MAX_CONSECUTIVE_UNUSABLE = 3
MAX_CONSECUTIVE_KEY_FAILURES = 3
DRAIN_BUDGET_TICKS = 5
MAX_GENERATIONS_PER_PROCESS = 8
MIN_GENERATION_SPACING_MS = 10_000
MAX_CYCLES_PER_GENERATION = 2 ** 20
MAX_HEAD_BYTES = 1024
_MS = 1_000_000
_BOOT_ID = "/proc/sys/kernel/random/boot_id"
_EXPIRIES = ("proof_expires_at_ms", "binding_expires_at_ms", "grant_expires_at_ms")
_LOG = logging.getLogger("heel.host.cycle")


class CycleError(RuntimeError):
    """A refused cycle operation (fixed code only)."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class ExchangeFailed(CycleError):
    """No usable reply: ``cp_unavailable``, ``cp_timeout``, ``late_reply``, ``malformed_reply``,
    ``connect_failed`` or ``peer_identity``. The request's sequence is consumed either way."""


class SignalContextInvalid(CycleError):
    """The process signal picture is not the one this module requires."""


class Enablement(enum.Enum):
    """The only admission. A customer member needs a later reviewed change carrying the H6
    qualification; nothing here can create one."""

    NON_CUSTOMER = "non_customer"


# ---------------------------------------------------------------------------------------------
# The immutable context (R section 2).

CONTEXT_STRINGS = ("workspace_id", "project_id", "environment_id", "verification_record_digest", "runner_id",
                   "runner_key_id", "binding_id", "binding_digest", "run_id", "grant_id", "grant_digest",
                   "public_key_digest", "egress_hostname")
_REQUEST_STRINGS = CONTEXT_STRINGS[:11]
_GRANT_STRINGS = CONTEXT_STRINGS[11:]


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class CycleContext:
    """One run on one slot, from the CP claim (delivered by H3). Ids and digests only: no credential,
    token or key material. Validated against the request codec and the active-reply grammar."""

    workspace_id: str
    project_id: str
    environment_id: str
    verification_record_digest: str
    runner_id: str
    runner_key_id: str
    binding_id: str
    binding_digest: str
    run_id: str
    grant_id: str
    grant_digest: str
    public_key_digest: str
    egress_hostname: str
    kill_switch_generation: int
    egress_port: int

    def __post_init__(self) -> None:
        probe = {"schema_version": codec.REQUEST_SCHEMA, "host_boot_epoch": "context-check", "slot_id": "s",
                 "request_nonce": "0" * 32, "generation_id": "0" * 32, "sequence": 1, "monotonic_ms": 0,
                 "kill_switch_generation": self.kill_switch_generation,
                 **{name: getattr(self, name) for name in _REQUEST_STRINGS}}
        try:
            valid = codec.validate_request(codec.canonical(probe)) is not None
        except (TypeError, ValueError):
            valid = False
        valid = valid and all(isinstance(getattr(self, name), str)
                              and codec._ACTIVE_STRINGS[name].fullmatch(getattr(self, name)) for name in _GRANT_STRINGS)
        if not valid or type(self.egress_port) is not int or self.egress_port != 443:
            raise ValueError("context_invalid")


# ---------------------------------------------------------------------------------------------
# Signals (R section 5). The handler is one attribute store: no lock, event, log, callback or
# domain call, so it can never block the thread it interrupts. The owner thread polls the flag.

STOP_SIGNALS = (signal.SIGTERM, signal.SIGINT, signal.SIGHUP)


class _SignalState:
    __slots__ = ("stop_requested",)

    def __init__(self) -> None:
        self.stop_requested = False


_STATE = _SignalState()
_INSTALLED: dict | None = None  # the picture verified by install_signal_context()


# Exactly one store; nothing else may ever be added to this handler.
def _on_stop_signal(signum, _frame):
    _STATE.stop_requested = True


def _picture() -> dict:
    picture = {}
    for signum in sorted(signal.valid_signals()):
        try:
            picture[int(signum)] = signal.getsignal(signum)
        except (ValueError, OSError):
            picture[int(signum)] = None
    return picture


def _python_handler(handler) -> bool:
    return handler not in (signal.SIG_DFL, signal.SIG_IGN, None)


def install_signal_context() -> None:
    """Main thread only, before ``start()``. SIGCHLD must be the default (an ignored SIGCHLD makes
    the kernel reap children the domain must reap itself; a Python handler may raise). Every other
    signal must have no Python handler, except the three stop signals, whose default or interpreter
    handler is replaced by the one-store handler. Refuses before changing anything."""
    global _INSTALLED
    if threading.current_thread() is not threading.main_thread():
        raise SignalContextInvalid("not_main_thread")
    picture = _picture()
    sigchld = picture.get(int(signal.SIGCHLD))
    if sigchld == signal.SIG_IGN:
        raise SignalContextInvalid("sigchld_ignored")
    if _python_handler(sigchld):
        raise SignalContextInvalid("sigchld_custom_handler")
    stops = {int(signum) for signum in STOP_SIGNALS}
    for signum, handler in picture.items():
        replaceable = signum in stops and handler in (signal.default_int_handler, _on_stop_signal)
        if _python_handler(handler) and not replaceable:
            raise SignalContextInvalid("foreign_signal_handler")
    for signum in STOP_SIGNALS:
        signal.signal(signum, _on_stop_signal)
    _INSTALLED = _picture()


def verify_signal_context() -> None:
    """Every valid signal's disposition must still equal the installed picture."""
    if _INSTALLED is None or _picture() != _INSTALLED:
        raise SignalContextInvalid("signal_context_invalid")


# ---------------------------------------------------------------------------------------------
# The private client (prior sections 3.1-3.3): one connection per request, one absolute deadline.

def _refuse(code: str):
    raise ExchangeFailed(code)


def _content_length(head: bytes) -> int:
    lines = head.split(b"\r\n")
    if lines[0] != b"HTTP/1.1 200 OK":
        _refuse("cp_unavailable")
    seen: dict[bytes, bytes] = {}
    for line in lines[1:]:
        match = codec._HEADER.fullmatch(line)
        if match is None:
            _refuse("cp_unavailable")
        name, value = match.group(1).lower(), match.group(2) or b""
        if name == b"transfer-encoding" or (name in seen and name in (b"content-length", b"content-type", b"connection")):
            _refuse("cp_unavailable")
        seen[name] = value
    length = seen.get(b"content-length", b"")
    if not (length.isdigit() and len(length) <= 4 and (length == b"0" or not length.startswith(b"0"))):
        _refuse("cp_unavailable")
    if (int(length) > codec.MAX_RESPONSE_BYTES or seen.get(b"content-type") != b"application/json"
            or seen.get(b"connection") != b"close"):
        _refuse("cp_unavailable")
    return int(length)


def _reply(body: bytes, request: dict) -> dict:
    try:
        reply = json.loads(body.decode("ascii"), parse_constant=codec._no_constant)
    except (UnicodeDecodeError, ValueError, RecursionError):
        _refuse("malformed_reply")
    if not isinstance(reply, dict) or not codec.validate_response(reply, request) or codec.canonical(reply) != body:
        _refuse("malformed_reply")
    return reply


def exchange_on(sock, request: dict, deadline_ns: int, *, clock: Callable[[], int] = time.monotonic_ns) -> dict:
    """Write ``request`` on the connected ``sock`` and read one closed reply, every operation bounded
    by the monotonic ``deadline_ns``. Returns the validated reply or raises ``ExchangeFailed``."""
    body = codec.canonical(request)

    def remaining() -> float:
        left = deadline_ns - clock()
        if left <= 0:
            _refuse("cp_timeout")
        return left / 1e9

    try:
        sock.settimeout(remaining())
        sock.sendall(b"POST %s HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: %d\r\n"
                     b"Connection: close\r\n\r\n%s" % (codec.ROUTE.encode(), len(body), body))
        data = b""
        while b"\r\n\r\n" not in data:
            if len(data) > MAX_HEAD_BYTES:
                _refuse("cp_unavailable")
            sock.settimeout(remaining())
            chunk = sock.recv(4096)
            if not chunk:
                _refuse("cp_unavailable")
            data += chunk
        head, _separator, rest = data.partition(b"\r\n\r\n")
        if len(head) > MAX_HEAD_BYTES:
            _refuse("cp_unavailable")
        length = _content_length(head)
        while len(rest) < length:
            sock.settimeout(remaining())
            chunk = sock.recv(length - len(rest))
            if not chunk:
                _refuse("cp_unavailable")
            rest += chunk
        if len(rest) != length:
            _refuse("cp_unavailable")
    except TimeoutError:
        _refuse("cp_timeout")
    except OSError:
        _refuse("cp_unavailable")
    if clock() > deadline_ns:
        _refuse("late_reply")
    return _reply(rest, request)


class ControlPlaneClient:
    """``authority.connect_cp`` (path profile and peer checked on the request connection) plus
    ``exchange_on``. No TCP, no bearer, no header credential, nothing created or unlinked."""

    _TRANSPORT = ("peer_identity", "connect_failed", "cp_timeout")

    def __init__(self, socket_path: str, cp_uid: int):
        self._path, self._cp_uid = socket_path, cp_uid

    def exchange(self, request: dict, deadline_ns: int) -> dict:
        try:
            sock = authority.connect_cp(self._path, self._cp_uid, deadline_ns)
        except authority.ControlPlaneUnavailable as error:
            raise ExchangeFailed(error.code if error.code in self._TRANSPORT else "cp_unavailable") from None
        try:
            return exchange_on(sock, request, deadline_ns)
        finally:
            sock.close()


# ---------------------------------------------------------------------------------------------
# Timing (R sections 4.1-4.2), pure.

@dataclasses.dataclass(frozen=True, slots=True)
class AuthorityWindow:
    """One key's timing, all CLOCK_MONOTONIC nanoseconds: ``t_p0`` the handle's
    ``prepared_monotonic_ns`` (before the child), ``t_p1`` after ``prepare`` returned, ``t_start``
    before the request, ``tick_ns`` one jiffy, ``rem_ms`` the reply's effective remaining authority."""

    t_p0: int
    t_p1: int
    t_start: int
    tick_ns: int
    rem_ms: int

    @property
    def e_lower(self) -> int:
        """End of the measured certainly-live window: a liveness gate, never an availability claim."""
        return self.t_p0 + LEASE_MS * _MS - 2 * self.tick_ns

    @property
    def e_upper(self) -> int:
        """The latest instant the kernel can admit a packet on this key's element."""
        return self.t_p1 + LEASE_MS * _MS + self.tick_ns

    @property
    def deadline(self) -> int:
        """D, anchored at ``t_start`` (never at the reply)."""
        return self.t_start + self.rem_ms * _MS

    @property
    def bound(self) -> int:
        return min(self.e_upper, self.deadline)

    @property
    def gap_ns(self) -> int:
        return self.t_start - self.t_p1

    def verdict(self, t_act: int) -> str:
        if t_act >= self.e_lower:
            return "key_expiring"
        if self.e_upper > self.deadline:
            return "authority_too_short"
        return "activate"

    @staticmethod
    def remaining_ms(reply: dict) -> int:
        """``min(expires_i - server_time_ms)`` over proof, binding and grant of one reply, each in
        ``0 < rem_i <= bound_i`` and the minimum ``<= MAX_EFFECTIVE_REMAINING_MS``."""
        server = reply.get("server_time_ms")
        if type(server) is not int:
            raise CycleError("stale_durations")
        remaining = []
        for name, bound in zip(_EXPIRIES, MEMBER_BOUNDS_MS):
            value = reply.get(name)
            if type(value) is not int or not 0 < value - server <= bound:
                raise CycleError("stale_durations")
            remaining.append(value - server)
        if min(remaining) > MAX_EFFECTIVE_REMAINING_MS:
            raise CycleError("stale_durations")
        return min(remaining)


def classify_children(counts: dict) -> str:
    """The registry rule (R section 6.2): any owned, looking, sweeping, uncertain or unknown entry is
    uncertainty; otherwise any handed-off or reaped entry drains; otherwise clear."""
    if sum(counts.get(key, 0) for key in ("owned", "looking", "sweeping", "uncertain", "other")) >= 1:
        return "uncertain"
    if counts.get("handed_off", 0) + counts.get("reaped", 0) >= 1:
        return "drain"
    return "clear"


# ---------------------------------------------------------------------------------------------
# The generation bootstrap (H2-A, docs/saas/H2A_BOOTSTRAP_CONTRACT.md). The cycle owns the transport:
# two connected AF_UNIX datagram sockets, one to the H3 bootstrap worker and one to the H3 root
# controller. Every message is one canonical JSON datagram of a fixed schema; the only descriptor
# that ever crosses is the one-use namespace duplicate sent to the worker. No caller code runs.

BOOTSTRAP_DEADLINE_MS = 5000  # arm ack, hand-off and receipt: one absolute monotonic deadline
REVOKE_DEADLINE_MS = 1000  # the controller's revoke acknowledgement, from the cancellation
BOOTSTRAP_POLL_MS = 50  # the stop flags are read at least this often while a wait is outside the lock
MAX_BOOTSTRAP_BYTES = 1024
BOOTSTRAP_SCHEMA = "heel.h2a.bootstrap.v1"
RECEIPT_SCHEMA = "heel.h2a.receipt.v1"
CONTROLLER_SCHEMA = "heel.h2a.controller.v1"
_MAX_RECEIVED_FDS = 4  # any descriptor sent to the cycle is closed unread and refuses the message
_CLAIM_LOCK = threading.Lock()


class BootstrapChannel:
    """One generation's transport. The constructor adopts both sockets (the caller's objects are
    detached, so only this channel can close the descriptors): each must be a connected AF_UNIX
    ``SOCK_DGRAM`` socket, and they must be distinct sockets. The controller socket never reaches the
    worker; that the two peers are the H3 worker and root controller is H3's obligation."""

    __slots__ = ("_worker", "_controller", "_claimed")

    def __init__(self, *, worker: socket.socket, controller: socket.socket):
        for sock in (worker, controller):
            if not isinstance(sock, socket.socket) or sock.fileno() < 0:
                raise TypeError("bootstrap_channel_invalid")
            if sock.family != socket.AF_UNIX or sock.type != socket.SOCK_DGRAM:
                raise ValueError("bootstrap_channel_invalid")
            try:
                sock.getpeername()
            except OSError:
                raise ValueError("bootstrap_channel_invalid") from None
        identities = {(info.st_dev, info.st_ino) for info in map(os.fstat, (worker.fileno(), controller.fileno()))}
        if worker is controller or len(identities) != 2:
            raise ValueError("bootstrap_channel_invalid")
        self._worker = socket.socket(fileno=worker.detach())
        self._controller = socket.socket(fileno=controller.detach())
        self._claimed = False

    @property
    def closed(self) -> bool:
        return self._worker.fileno() < 0 and self._controller.fileno() < 0

    def close(self) -> None:
        self._worker.close()
        self._controller.close()


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class GenerationBootstrap:
    """What the worker learns about one generation, published as its request: no path, PID, domain,
    operation nonce or controller capability. ``bootstrap_fence`` is fresh per generation."""

    generation_id: str
    namespace_identity: tuple[int, int]
    slot_id: str
    slot_hop_src: str
    slot_hop_dst: str
    bootstrap_fence: str

    def request(self) -> dict:
        return {"schema": BOOTSTRAP_SCHEMA, "generation_id": self.generation_id,
                "namespace_dev": self.namespace_identity[0], "namespace_ino": self.namespace_identity[1],
                "slot_id": self.slot_id, "slot_hop_src": self.slot_hop_src, "slot_hop_dst": self.slot_hop_dst,
                "bootstrap_fence": self.bootstrap_fence}

    def receipt(self) -> dict:
        """The only success receipt: exactly these keys and values, as canonical bytes."""
        return {"schema": RECEIPT_SCHEMA, "generation_id": self.generation_id,
                "namespace_dev": self.namespace_identity[0], "namespace_ino": self.namespace_identity[1],
                "bootstrap_fence": self.bootstrap_fence, "installed": True}


def _no_duplicates(pairs: list) -> dict:
    document = dict(pairs)
    if len(document) != len(pairs):
        raise ValueError("duplicate key")
    return document


def _close_received(ancdata: list) -> int:
    """Close every descriptor in ``ancdata``; returns how many control messages there were."""
    for level, kind, data in ancdata:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            fds = array.array("i")
            fds.frombytes(data[:len(data) - len(data) % fds.itemsize])
            for fd in fds:
                try:
                    os.close(fd)
                except OSError:
                    pass
    return len(ancdata)


def _matches(data: bytes, expected: dict) -> bool:
    """Exact schema: the canonical bytes of exactly ``expected`` (types included), nothing else.
    Total: any input is True or False, never an exception (ASCII bytes may still escape non-ASCII
    or lone-surrogate strings, which no expected value contains)."""
    try:
        document = json.loads(data.decode("ascii"), object_pairs_hook=_no_duplicates,
                              parse_constant=codec._no_constant)
        if not isinstance(document, dict) or set(document) != set(expected) or codec.canonical(document) != data:
            return False
    except (UnicodeError, ValueError, TypeError, RecursionError):
        return False
    for key, value in expected.items():
        if type(document[key]) is not type(value):
            return False
        if isinstance(value, str):
            if not document[key].isascii() or not hmac.compare_digest(document[key].encode("ascii"),
                                                                       value.encode("ascii")):
                return False
        elif document[key] != value:
            return False
    return True


class _Handoff:
    """One generation's bootstrap, run by the ``start()`` caller outside the cycle lock. Once
    constructed it alone owns the channel and the one namespace duplicate (closed exactly once: right
    after its one send, or at cancellation). Tokens only: nothing received is logged, kept or raised."""

    def __init__(self, record: GenerationBootstrap, channel: BootstrapChannel, fd: int, deadline_ns: int):
        self.record, self.deadline_ns = record, deadline_ns
        self._channel, self._fd = channel, fd
        self._nonce = secrets.token_hex(16)  # the controller's operation nonce; never sent to the worker
        self.state, self.root, self.worker = "pending", "not_armed", "not_contacted"
        self.received = False  # the exact receipt was read; ``state`` stays pending until the commit

    def _identity(self) -> dict:
        record = self.record
        return {"schema": CONTROLLER_SCHEMA, "generation_id": record.generation_id,
                "bootstrap_fence": record.bootstrap_fence, "operation_nonce": self._nonce}

    def _take_fd(self) -> int:
        fd, self._fd = self._fd, -1
        if fd < 0:
            raise CycleError("bootstrap_capability_spent")
        return fd

    def _drop_fd(self) -> None:
        fd, self._fd = self._fd, -1
        if fd >= 0:
            os.close(fd)

    @staticmethod
    def _send(sock: socket.socket, document: dict, deadline_ns: int, clock, stopped, fds=()) -> bool:
        """One datagram, sent whole or not at all, before ``deadline_ns`` and while no stop is
        requested. A full peer queue may block the send or refuse it (ENOBUFS, EAGAIN); either way it
        is retried in ``BOOTSTRAP_POLL_MS`` slices, so the stop flags are read between attempts."""
        payload = codec.canonical(document)
        ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", fds))] if fds else []
        while True:
            left = deadline_ns - clock()
            if left <= 0 or stopped():
                return False
            slice_s = min(left, BOOTSTRAP_POLL_MS * _MS) / 1e9
            try:
                sock.settimeout(slice_s)
                sock.sendmsg([payload], ancillary)
            except TimeoutError:
                continue
            except OSError as error:
                if error.errno not in (errno.ENOBUFS, errno.EAGAIN):
                    return False
                time.sleep(slice_s)
                continue
            return True

    @staticmethod
    def _receive(sock: socket.socket, expected: tuple, deadline_ns: int, clock, stopped) -> tuple[str, int]:
        """Exactly one datagram before ``deadline_ns``: (``match``, index into ``expected``), or
        (``timeout``/``stopped``/``transport``/``late``/``malformed``, -1). Received descriptors are
        closed before anything else is looked at; nothing after the one datagram is ever read."""
        space = socket.CMSG_SPACE(_MAX_RECEIVED_FDS * array.array("i").itemsize)
        while True:
            left = deadline_ns - clock()
            if left <= 0:
                return "timeout", -1
            if stopped():
                return "stopped", -1
            try:
                sock.settimeout(min(left, BOOTSTRAP_POLL_MS * _MS) / 1e9)
                data, ancdata, flags, _address = sock.recvmsg(MAX_BOOTSTRAP_BYTES + 1, space)
            except TimeoutError:
                continue
            except OSError:
                return "transport", -1
            if _close_received(ancdata) or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC):
                return "malformed", -1
            if clock() > deadline_ns:
                return "late", -1
            if len(data) <= MAX_BOOTSTRAP_BYTES:
                for index, document in enumerate(expected):
                    if _matches(data, document):
                        return "match", index
            return "malformed", -1

    @property
    def settled(self) -> bool:
        """Owns nothing any more: committed or cancelled, and both sockets closed."""
        return self.state != "pending" and self._channel.closed

    def run(self, clock, stopped) -> None:
        """Arm, hand off, read the receipt; on any other result, cancel. Ends either ``received``
        (``state`` still pending, the channel still open for a revoke) or with ``state``
        ``cancelled`` (root ``absent`` or ``not_armed``) or ``unresolved``."""
        channel, record, deadline = self._channel, self.record, self.deadline_ns
        identity = self._identity()
        arm = {**identity, "op": "arm", "namespace_dev": record.namespace_identity[0],
               "namespace_ino": record.namespace_identity[1], "slot_id": record.slot_id,
               "deadline_monotonic_ns": deadline}
        outcome = "arm_unsent"
        if self._send(channel._controller, arm, deadline, clock, stopped):
            self.root = "armed"
            outcome, _index = self._receive(channel._controller, ({**identity, "op": "armed"},), deadline, clock,
                                            stopped)
        if outcome == "match":
            fd = self._take_fd()
            try:
                info = os.fstat(fd)
                sent = ((info.st_dev, info.st_ino) == record.namespace_identity
                        and self._send(channel._worker, record.request(), deadline, clock, stopped, (fd,)))
            finally:
                os.close(fd)  # the one close of the duplicate; the kernel holds the in-flight copy
            self.worker = "contacted" if sent else "unknown"
            outcome = "unsent"
            if sent:
                outcome, _index = self._receive(channel._worker, (record.receipt(),), deadline, clock, stopped)
        if outcome == "match" and not stopped():
            self.received = True  # the cycle decides under its lock: ``commit()`` or ``cancel()``
            return
        self.cancel(clock)

    def commit(self) -> None:
        """Under the cycle lock, the receipt's one use: both sockets closed (no later message on
        either is ever read), then ``receipted``. No send, receive or wait."""
        self._channel.close()
        self.state = "receipted"

    def cancel(self, clock) -> None:
        """Burn the capability, close the worker's socket, then ask the root controller to remove the
        slot's ``enabled`` marker and end the worker under this nonce. Without the exact ack the
        outcome stays unresolved; a worker the controller could not reap stays unresolved."""
        self._drop_fd()
        channel, self.state = self._channel, "unresolved"
        channel._worker.close()
        if self.root == "not_armed":
            self.state = "cancelled"
            channel.close()
            return
        identity, deadline = self._identity(), clock() + REVOKE_DEADLINE_MS * _MS
        revoke = {**identity, "op": "revoke", "namespace_dev": self.record.namespace_identity[0],
                  "namespace_ino": self.record.namespace_identity[1], "slot_id": self.record.slot_id}
        self.root = "unknown"
        if self.worker == "not_contacted":
            self.worker = "unknown"  # an arm the controller saw may have started one
        workers = ("reaped", "unresolved")
        acks = tuple({**identity, "op": "revoked", "enabled": "absent", "worker": worker} for worker in workers)
        result, index = "unsent", -1
        if self._send(channel._controller, revoke, deadline, clock, lambda: False):
            result, index = self._receive(channel._controller, acks, deadline, clock, lambda: False)
        channel.close()
        self._nonce = "burned"
        if result == "match":
            self.root, self.worker = "absent", workers[index]
            self.state = "cancelled" if self.worker == "reaped" else "unresolved"

    def abandon(self) -> None:
        """An escaped exception: close everything, claim nothing."""
        self._drop_fd()
        self._channel.close()
        self._nonce, self.state, self.root = "burned", "unresolved", "unknown"


# ---------------------------------------------------------------------------------------------
# Process-wide budget and the cycle.

class _GenerationBudget:
    """Process-wide, never reset by a new ``HostCycle``: generation starts and their spacing, the
    terminal quarantine, a lost child (an escaped exception) and the latest unproven residual."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.generations = 0
        self.last_start_ns: int | None = None
        self.quarantined = False
        self.lost_child = False
        self.unproven_residual_ns: int | None = None


_BUDGET = _GenerationBudget()


@dataclasses.dataclass(frozen=True, kw_only=True)
class CycleSeams:
    """Replacements for the cycle's tests; a production caller passes none."""

    clock: Callable[[], int] | None = None  # SEAM-CLOCK cycle tests only: the monotonic clock
    domain_factory: Callable[[], object] | None = None  # SEAM-DOMAIN cycle tests only: a recorded-installer domain
    self_test: Callable[[object], object] | None = None  # SEAM-SELFTEST cycle tests only: a scripted report
    sleep_report: Callable[[], dict] | None = None  # SEAM-SLEEP-REPORT cycle tests only: a scripted K9 report
    witness: object | None = None  # SEAM-WITNESS cycle tests only: a scripted clock witness
    exchange: Callable[[dict, int], dict] | None = None  # SEAM-EXCHANGE cycle tests only: a scripted exchange
    boot_epoch: str | None = None  # SEAM-BOOT-EPOCH cycle tests only: a fixed boot epoch


STATUS_KEYS = ("generation_phase", "generation_id", "generation_class_end", "context_state", "context_end_reason",
               "sequence", "cycles", "last_decision", "last_reason", "consecutive_unavailable", "consecutive_unusable",
               "consecutive_key_failures", "authorized", "deadline_remaining_ms", "residual", "residual_bound_ms",
               "request_gap_ms", "unresolved_children", "unresolved_handed_off", "unresolved_uncertain",
               "drain_ticks", "witness_gaps", "quarantine_code", "kernel_profile", "runtime_assumption",
               "exit_required", "generations", "enablement", "workspace_id", "run_id", "slot_id")
_SLEEP_UNITS = tuple("unit_" + unit.replace("-", "_").replace(".target", "") for unit in authority.SLEEP_TARGETS)


def _read_boot_epoch() -> str | None:
    try:
        value = Path(_BOOT_ID).read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError):
        return None
    return value if codec._STRINGS["host_boot_epoch"].fullmatch(value) else None


def _sleep_disabled(report: dict) -> bool:
    return (all(report.get(unit) == "masked" for unit in _SLEEP_UNITS) and report.get("sleep_conf") == "all_disabled"
            and report.get("hibernation") in ("disabled_cmdline", "disabled_sys_power"))


class HostCycle:
    """The authorization cycle of one slot. ``start()`` creates a generation (domain, self-test,
    grading, K9, witness) and reaches ``ready``; ``install_context()`` makes it ``serving``;
    ``tick()`` runs one cycle on the main thread; ``stop()`` and ``stop_context()`` end the
    generation in order; ``status()`` reads fixed tokens; ``on_transition(callback)`` is called with
    ``(event, status)`` after each transition, outside the cycle lock. One lock, never touched by a
    signal handler, serializes every method; the domain lock nests inside it.

    ``register_bootstrap(channel)`` (H2-A) puts the cycle in bootstrap mode for good: every later
    ``start()`` needs its own registration, holds the generation in ``bootstrapping`` while the
    hand-off runs outside the lock, and reaches ``ready`` only on the exact receipt."""

    def __init__(self, slot_id: str, cp_socket: str, cp_uid: int, *, slot_src: str, slot_dst: str,
                 admission: Enablement, _seams_for_tests: CycleSeams | None = None):
        if not isinstance(admission, Enablement) or admission is not Enablement.NON_CUSTOMER:
            raise TypeError("admission must be Enablement.NON_CUSTOMER")
        if not isinstance(slot_id, str) or not codec._STRINGS["slot_id"].fullmatch(slot_id):
            raise ValueError("slot_invalid")
        self._slot = slot_id
        self._src, self._dst = authority._ipv4(slot_src), authority._ipv4(slot_dst)
        seams = _seams_for_tests or CycleSeams()
        self._clock = seams.clock or time.monotonic_ns
        self._domain_factory = seams.domain_factory or authority.LeaseDomain.create
        self._self_test = seams.self_test or authority.generation_self_test
        self._sleep_report = seams.sleep_report or authority.sleep_capability_report
        self._witness = seams.witness or authority.ClockWitness()
        self._exchange = seams.exchange or ControlPlaneClient(cp_socket, cp_uid).exchange
        self._boot_seam = seams.boot_epoch
        self._lock = threading.Lock()
        self._callbacks: list = []
        self._pending: list = []
        self._phase = "created"
        self._residual_ns: int | None = None  # max min(E_upper, D) over every key handed to activate
        self._quarantine_code = "none"
        self._exit_required = False
        self._kernel_profile = "unknown"
        self._bootstrap_mode = False
        self._channel: BootstrapChannel | None = None  # registered for the next generation start
        self._reset_generation()

    def _reset_generation(self) -> None:
        self._domain = None
        self._context: CycleContext | None = None
        self._context_state, self._context_end = "none", "none"
        self._class_end, self._last_decision, self._last_reason = "none", "none", "none"
        self._boot = None
        self._sequence = self._cycles = self._retired = 0
        self._current = self._current_window = self._last_window = None
        self._current_late = False
        self._windows: list[AuthorityWindow] = []
        self._unavailable = self._unusable = self._key_failures = 0
        self._drain_ticks = self._witness_gaps = self._gap_ms = 0
        self._baseline = self._previous = None
        self._tick_ns: int | None = None
        self._stop_requested = self._replace_requested = False
        self._flush_attempted = self._zero_proven = False
        self._gen_channel: BootstrapChannel | None = None  # this generation's, until the hand-off owns it
        self._handoff: _Handoff | None = None

    @property
    def _current_bound(self) -> int | None:
        return None if self._current_window is None else self._current_window.bound

    # -- public API ---------------------------------------------------------------------------

    def on_transition(self, callback: Callable[[str, dict], None]) -> None:
        if not callable(callback):
            raise TypeError("callback must be callable")
        with self._lock:
            self._callbacks.append(callback)

    def register_bootstrap(self, channel: BootstrapChannel) -> None:
        """One channel for the next generation, only between generations and never after a
        quarantine. Refused registrations leave the channel with the caller."""
        if type(channel) is not BootstrapChannel:
            raise TypeError("channel must be a BootstrapChannel")
        with self._lock, _CLAIM_LOCK:
            if (self._phase not in ("created", "closed") or _BUDGET.quarantined or self._channel is not None
                    or channel._claimed or channel.closed):
                raise CycleError("bootstrap_registration_refused")
            channel._claimed = True
            self._channel, self._bootstrap_mode = channel, True

    def bootstrap_status(self) -> dict:
        """Fixed tokens: ``mode`` legacy|registered; ``state`` none|pending|receipted|cancelled|
        unresolved; ``root`` (the controller's word on the slot's ``enabled`` marker) none|not_armed|
        armed|absent|unknown; ``worker`` none|not_contacted|contacted|reaped|unresolved|unknown."""
        with self._lock:
            handoff = self._handoff
            return {"mode": "registered" if self._bootstrap_mode else "legacy",
                    "registered": self._channel is not None,
                    "state": handoff.state if handoff is not None else "none",
                    "root": handoff.root if handoff is not None else "none",
                    "worker": handoff.worker if handoff is not None else "none"}

    def start(self) -> str:
        phase = self._locked(self._start)
        return self._bootstrap(self._handoff) if phase == "bootstrapping" else phase

    def install_context(self, context: CycleContext) -> None:
        def install() -> None:
            if not isinstance(context, CycleContext) or self._phase != "ready" or self._context is not None:
                raise CycleError("context_refused")
            self._context, self._context_state, self._phase = context, "installed", "serving"
            self._event("serving")
        self._locked(install)

    def stop(self) -> str:
        """Request an orderly stop (row 23); it runs at once, as a poll point."""
        def stop() -> None:
            self._stop_requested = True
            self._poll_point()
        return self._locked(stop)

    def stop_context(self) -> str:
        """End the context for replacement (row 24); the next context needs ``start()`` again."""
        def replace() -> None:
            self._replace_requested = True
            self._poll_point()
        return self._locked(replace)

    def tick(self) -> str:
        return self._locked(self._tick)

    def status(self) -> dict:
        with self._lock:
            return self._status()

    # -- locking, escaped exceptions, events --------------------------------------------------

    def _locked(self, operation):
        try:
            with self._lock:
                try:
                    result = operation()
                except (authority.ForeignProcess, authority.ForeignHandle, authority.HandleState):
                    self._quarantine("domain_invariant")  # row 22
                    result = None
                except CycleError:
                    raise
                except BaseException:
                    self._interrupted()  # row 21: recorded, one best-effort flush, then re-raised
                    raise
                return self._phase if result is None else result
        finally:
            self._dispatch()

    def _interrupted(self) -> None:
        _BUDGET.lost_child = True  # a child may have escaped every registry: no zero claim from now on
        self._quarantine("operation_interrupted")

    def _event(self, event: str) -> None:
        status = self._status()
        _LOG.info(json.dumps({"event": event, **status}, separators=(",", ":")))
        self._pending.append((event, status))

    def _dispatch(self) -> None:
        with self._lock:
            pending, self._pending = self._pending, []
            callbacks = tuple(self._callbacks)
        for event, status in pending:
            for callback in callbacks:
                callback(event, status)

    # -- generation start (R section 7.3, row 26/27) ----------------------------------------

    def _start(self) -> None:
        if self._phase in ("ready", "serving", "draining", "closing", "bootstrapping"):
            raise CycleError("generation_active")
        if self._phase == "quarantined" or _BUDGET.quarantined:
            self._phase, self._exit_required = "quarantined", True
            if self._quarantine_code == "none":
                self._quarantine_code = "process_quarantined"
            self._close_unused_channel()
            return
        if self._bootstrap_mode and self._channel is None:
            raise CycleError("bootstrap_unregistered")  # never the legacy path once registered
        children = classify_children(authority.sweep_unresolved_children())
        if children == "uncertain":
            self._quarantine("child_uncertain")
            return
        if children == "drain":  # retried by H3 later; not a generation start
            self._last_reason = "children_draining"
            return
        now = self._clock()
        with _BUDGET.lock:
            spent = (_BUDGET.generations >= MAX_GENERATIONS_PER_PROCESS or (
                _BUDGET.last_start_ns is not None and now - _BUDGET.last_start_ns < MIN_GENERATION_SPACING_MS * _MS))
            if not spent:
                _BUDGET.generations += 1
                _BUDGET.last_start_ns = now
        if spent:
            self._quarantine("generation_budget")
            return
        self._reset_generation()
        self._gen_channel, self._channel = self._channel, None
        self._boot = self._boot_seam or _read_boot_epoch()
        if self._boot is None:
            return self._refuse_start("boot_epoch_unavailable")
        try:
            verify_signal_context()
        except SignalContextInvalid as error:
            return self._refuse_start(error.code)
        try:
            self._domain = self._domain_factory()
        except authority.DomainUnavailable as error:
            return self._refuse_start(str(error) if str(error) else "domain_unavailable")
        try:
            report = self._self_test(self._domain)
        except authority.HostQuarantined:
            return self._refuse_start("selftest_failed")
        graded = profile.grade_self_test(report)
        self._kernel_profile = graded[0]
        try:
            self._tick_ns = profile.tick_ns(report)
        except KeyError:
            graded = ("unpinned", ["config_hz_unavailable_or_unsupported"])
        if graded != ("pinned", []):
            self._kernel_profile = "unpinned"
            return self._refuse_start("profile_unpinned")
        if not _sleep_disabled(self._sleep_report()):
            return self._refuse_start("sleep_capable")
        try:
            self._baseline = self._previous = self._witness.sample()
        except authority.ClockUnavailable:
            return self._refuse_start("clock_unavailable")
        if self._gen_channel is None:
            self._phase = "ready"
            self._event("ready")  # legacy (no registration): H1 behavior unchanged
            return
        return self._open_bootstrap()

    # -- the generation bootstrap (H2-A) --------------------------------------------------------

    def _open_bootstrap(self) -> None:
        """Under the lock: duplicate the namespace descriptor once and hand it, with the channel, to
        the generation's ``_Handoff``; ``start()`` then runs it outside the lock. Until the hand-off
        is constructed this frame owns both: an exception building the record, its fence, the deadline
        or the hand-off closes the duplicate and the channel once here and is re-raised."""
        identity = tuple(self._domain.ns_identity)
        try:
            fd = os.dup(self._domain.ns_fd)
        except OSError:
            return self._refuse_start("h2_bootstrap_failed")
        channel, self._gen_channel = self._gen_channel, None
        try:
            record = GenerationBootstrap(generation_id=self._domain.generation_id, namespace_identity=identity,
                                         slot_id=self._slot, slot_hop_src=self._src, slot_hop_dst=self._dst,
                                         bootstrap_fence=secrets.token_hex(16))
            handoff = _Handoff(record, channel, fd, self._clock() + BOOTSTRAP_DEADLINE_MS * _MS)
        except BaseException:
            os.close(fd)
            channel.close()
            raise
        self._handoff, self._phase = handoff, "bootstrapping"  # the ownership transfer

    def _bootstrap_stopped(self) -> bool:
        return _STATE.stop_requested or self._stop_requested or self._replace_requested

    def _bootstrap(self, handoff: _Handoff) -> str:
        """The hand-off outside the lock, then the one decision under it (``_finish_bootstrap``). A
        stop recorded before that decision turns a received receipt into a revoke, run outside the
        lock over the still-open channel, and then a second decision on its outcome."""
        try:
            handoff.run(self._clock, self._bootstrap_stopped)
            phase = self._locked(lambda: self._finish_bootstrap(handoff))
            if phase == "revoke":
                handoff.cancel(self._clock)
                phase = self._locked(lambda: self._finish_bootstrap(handoff))
            return phase
        except BaseException:
            if not handoff.settled:  # it still owns a descriptor or a socket
                handoff.abandon()
                self._locked(self._interrupted)
            raise

    def _finish_bootstrap(self, handoff: _Handoff) -> str | None:
        """Under the lock. ``ready`` is committed here only if no stop (``stop``, ``stop_context``,
        the signal flag) is recorded when this lock is held; a stop recorded later is an ordinary stop
        of a ready generation. Returns ``revoke`` (phase still ``bootstrapping``) to cancel first."""
        if self._handoff is not handoff or self._phase != "bootstrapping":
            handoff.abandon()
            return self._quarantine("bootstrap_state")
        if handoff.state == "pending" and handoff.received:
            if self._bootstrap_stopped():
                return "revoke"
            handoff.commit()
            self._phase = "ready"
            self._event("ready")
        elif handoff.state == "cancelled":
            self._refuse_start("h2_bootstrap_failed")
        else:  # the root state or the worker is unknown: terminal, no zero claim, no new generation
            _BUDGET.lost_child = True
            self._quarantine("bootstrap_unresolved")

    def _close_unused_channel(self) -> None:
        for name in ("_channel", "_gen_channel"):
            channel = getattr(self, name)
            if channel is not None:
                setattr(self, name, None)
                channel.close()  # nothing was ever sent on it

    def _refuse_start(self, code: str) -> None:
        self._close_unused_channel()
        if self._domain is not None:
            self._flush_attempted = True
            try:
                self._domain.close_generation()
            except authority.InstallerFailed:
                pass  # never written (the self-test uses throwaway namespaces): no residual either way
        self._phase, self._class_end, self._last_reason = "closed", "start_refused", code
        self._event("start_refused")

    # -- one tick (R section 4.4) -------------------------------------------------------------

    def _poll_point(self) -> bool:
        if self._phase not in ("ready", "serving", "draining"):
            return False
        if _STATE.stop_requested or self._stop_requested:
            self._end_orderly("stop_requested")
            return True
        if self._replace_requested:
            self._end_orderly("context_replaced")
            return True
        return False

    def _tick(self) -> None:
        if self._phase not in ("ready", "serving", "draining") or self._poll_point() or self._phase == "ready":
            return
        if self._phase == "draining":
            return self._drain()
        if self._cycles >= MAX_CYCLES_PER_GENERATION:
            return self._end_orderly("generation_rotated")
        if self._admissible() and self._witness_ok():
            self._cycle()

    def _admissible(self) -> bool:
        verdict = classify_children(authority.unresolved_children())
        if verdict == "uncertain":
            self._quarantine("child_uncertain")
        elif verdict == "drain":
            self._phase, self._drain_ticks = "draining", 0
            self._event("draining")
        return verdict == "clear"

    def _drain(self) -> None:
        verdict = classify_children(authority.sweep_unresolved_children())  # the only call while draining
        if verdict == "uncertain":
            return self._quarantine("child_uncertain")
        if verdict == "drain":
            self._drain_ticks += 1
            if self._drain_ticks >= DRAIN_BUDGET_TICKS:
                self._quarantine("child_stranded")
            return
        self._phase, self._drain_ticks = "serving", 0
        self._event("serving")

    def _witness_ok(self) -> bool:
        try:
            sample = self._witness.sample()
        except authority.ClockUnavailable:
            gaps = ("clock_unavailable",)
        else:
            gaps = authority.detect_gap(self._baseline, self._previous, sample)
            self._previous = sample
        if gaps:
            self._witness_gaps += 1
            self._end_unproven("clock_gap_host")
        return not gaps

    def _cycle(self) -> None:
        domain, context = self._domain, self._context
        self._cycles += 1
        try:
            handle = domain.prepare(self._src, self._dst, LEASE_MS)
        except authority.PrepareFailed as error:
            if error.code == "installer_refused":  # generic: EEXIST, a missing table, anything (row 8)
                return self._end_orderly("prepare_refused")
            return self._outcome("key", "prepare_uncertain" if error.code == "installer_timeout" else "prepare_error")
        except authority.DomainExhausted:
            return self._end_orderly("domain_exhausted")
        t_p1 = self._clock()
        self._key_failures = 0
        if self._poll_point():
            return
        t_start = self._clock()
        self._sequence += 1  # consumed now: never resent, whatever happens to the reply
        request = {"schema_version": codec.REQUEST_SCHEMA, "host_boot_epoch": self._boot, "slot_id": self._slot,
                   "request_nonce": secrets.token_hex(16), "generation_id": domain.generation_id,
                   **{name: getattr(context, name) for name in _REQUEST_STRINGS},
                   "sequence": self._sequence, "monotonic_ms": t_start // _MS,
                   "kill_switch_generation": context.kill_switch_generation}
        e_lower = handle.prepared_monotonic_ns + LEASE_MS * _MS - 2 * self._tick_ns
        deadline_ns = min(t_start + REQUEST_BUDGET_MS * _MS, e_lower)
        self._gap_ms = (t_start - t_p1) // _MS
        try:
            reply = self._exchange(request, deadline_ns)
            if self._clock() > deadline_ns:
                raise ExchangeFailed("late_reply")
            if not isinstance(reply, dict) or not codec.validate_response(reply, request):
                raise ExchangeFailed("malformed_reply")
        except ExchangeFailed as error:
            return self._outcome("unavailable", error.code)
        self._unavailable, self._last_decision = 0, reply["decision"]
        if reply["decision"] == "inactive":
            return self._end_orderly(reply["reason"])
        if not (all(reply[name] == getattr(context, name) for name in CONTEXT_STRINGS)
                and reply["kill_switch_generation"] == context.kill_switch_generation
                and reply["egress_port"] == context.egress_port):
            return self._end_orderly("context_mismatch")
        try:
            rem_ms = AuthorityWindow.remaining_ms(reply)
        except CycleError:
            return self._end_orderly("stale_durations")
        if self._poll_point() or not self._admissible() or not self._witness_ok():
            return
        window = AuthorityWindow(handle.prepared_monotonic_ns, t_p1, t_start, self._tick_ns, rem_ms)
        self._last_window = window
        verdict = window.verdict(self._clock())
        if verdict != "activate":
            return self._outcome("unusable", verdict)
        # Handed to activate from here on: its window counts for the residual whatever the outcome.
        self._residual_ns = window.bound if self._residual_ns is None else max(self._residual_ns, window.bound)
        self._windows.append(window)
        try:
            domain.activate(handle)
        except authority.InstallerFailed as error:
            if error.code == "installer_refused":
                return self._end_orderly("activate_refused")
            return self._end_unproven("activation_uncertain" if error.code == "installer_timeout" else "activation_error")
        late = self._clock() >= window.e_lower
        if self._current is not None:
            self._retired += 1  # superseded by the swap; never closed (close destroys by tuple)
        self._current, self._current_window, self._current_late = handle, window, late
        self._unusable = 0
        self._context_state = "unknown" if late else "authorized"
        self._last_reason = "activation_late" if late else "activated"
        self._event(self._last_reason)

    def _outcome(self, kind: str, code: str) -> None:
        """A key outcome (class K): this cycle ends without activation; the previous window stands."""
        limit, end = {"key": (MAX_CONSECUTIVE_KEY_FAILURES, "key_failures"),
                      "unavailable": (MAX_CONSECUTIVE_UNAVAILABLE, "cp_unreachable"),
                      "unusable": (MAX_CONSECUTIVE_UNUSABLE, "authority_unusable")}[kind]
        if kind == "key":
            self._key_failures += 1
            count = self._key_failures
        elif kind == "unavailable":
            self._unavailable += 1
            count = self._unavailable
            self._last_decision = "no_reply"
        else:
            self._unusable += 1
            count = self._unusable
        self._last_reason = code
        if count >= limit:
            return self._end_orderly(end)
        self._event("not_activated")

    # -- ends (classes A, B, C) ---------------------------------------------------------------

    def _end_orderly(self, reason: str) -> None:
        """Class A: close the current handle (if any), then flush and close the generation."""
        self._phase = "closing"
        if self._current is not None:
            try:
                self._domain.close(self._current)
            except authority.InstallerFailed:
                return self._close_generation("B", "close_failed")  # row 16
        self._close_generation("A", reason)

    def _end_unproven(self, reason: str) -> None:
        """Class B: the kernel state is unproven; flush only, and never serve this namespace again."""
        self._phase = "closing"
        self._close_generation("B", reason)

    def _close_generation(self, kind: str, reason: str) -> None:
        self._context_end, self._last_reason = reason, reason
        if self._context is not None:
            self._context_state = "ended"
        self._flush_attempted = True
        try:
            self._domain.close_generation()
        except authority.InstallerFailed:
            return self._quarantine("flush_failed")  # row 17; the descriptor is already closed
        # Zero after the flush only with an orderly end, an empty process-global registry, no lost
        # child and no earlier unproven residual still running (rule R).
        empty = not any(authority.unresolved_children().values())
        earlier = _BUDGET.unproven_residual_ns
        self._zero_proven = (kind == "A" and empty and not _BUDGET.lost_child
                             and (earlier is None or self._clock() >= earlier))
        if not self._zero_proven:
            self._remember_unproven()
        self._phase, self._class_end = "closed", kind
        self._event("closed")

    def _quarantine(self, code: str) -> None:
        """Class C: at most one best-effort flush, then terminal for the process."""
        if self._phase == "quarantined":
            return
        self._close_unused_channel()
        if self._domain is not None and not self._flush_attempted:
            self._flush_attempted = True
            try:
                self._domain.close_generation()
            except BaseException:  # noqa: BLE001 - best effort only; the residual rule is the bound
                pass
        self._phase, self._class_end, self._quarantine_code = "quarantined", "C", code
        self._last_reason, self._exit_required, self._zero_proven = code, True, False
        if self._context is not None:
            self._context_state, self._context_end = "ended", code
        _BUDGET.quarantined = True
        self._remember_unproven()
        self._event("quarantined")

    def _remember_unproven(self) -> None:
        if self._residual_ns is not None:
            earlier = _BUDGET.unproven_residual_ns
            _BUDGET.unproven_residual_ns = self._residual_ns if earlier is None else max(earlier, self._residual_ns)

    # -- status ---------------------------------------------------------------------------------

    def _status(self) -> dict:
        now = self._clock()
        counts = authority.unresolved_children()
        bounds = [value for value in (self._residual_ns, _BUDGET.unproven_residual_ns) if value is not None]
        residual_ns = max(bounds) if bounds else None
        if residual_ns is None:
            residual = "none"
        elif self._phase == "closed" and self._zero_proven:
            residual = "zero"
        else:
            residual = "bounded" if now < residual_ns else "expired"
        window = self._current_window
        if self._phase in ("serving", "draining") and window is not None:
            authorized = "unknown" if self._current_late else "true" if now < window.bound else "false"
            remaining = (window.bound - now) // _MS if now < window.bound else 0
        else:
            authorized = "unknown" if residual == "bounded" and self._phase in ("closed", "quarantined") else "false"
            remaining = 0
        context = self._context
        values = {
            "generation_phase": self._phase,
            "generation_id": self._domain.generation_id if self._domain is not None else "none",
            "generation_class_end": self._class_end, "context_state": self._context_state,
            "context_end_reason": self._context_end, "sequence": self._sequence, "cycles": self._cycles,
            "last_decision": self._last_decision, "last_reason": self._last_reason,
            "consecutive_unavailable": self._unavailable, "consecutive_unusable": self._unusable,
            "consecutive_key_failures": self._key_failures, "authorized": authorized,
            "deadline_remaining_ms": remaining, "residual": residual,
            "residual_bound_ms": (residual_ns - now) // _MS if residual == "bounded" else 0,
            "request_gap_ms": self._gap_ms, "unresolved_children": counts,
            "unresolved_handed_off": counts["handed_off"],
            "unresolved_uncertain": sum(counts[key] for key in ("owned", "looking", "sweeping", "uncertain", "other")),
            "drain_ticks": self._drain_ticks, "witness_gaps": self._witness_gaps,
            "quarantine_code": self._quarantine_code, "kernel_profile": self._kernel_profile,
            "runtime_assumption": "running-kernel", "exit_required": self._exit_required,
            "generations": _BUDGET.generations, "enablement": Enablement.NON_CUSTOMER.value,
            "workspace_id": context.workspace_id if context is not None else "none",
            "run_id": context.run_id if context is not None else "none", "slot_id": self._slot,
        }
        return {key: values[key] for key in STATUS_KEYS}
