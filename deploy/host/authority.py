"""Host lease generation domain (H1A-1, H1ADR sections 2.5, 4.2 and 4.3).

SPDX-License-Identifier: LicenseRef-Heel-Commercial

One supervisor generation owns kernel-lifetime domains. A domain is a network namespace created by
this process and held only by file descriptor, plus a private in-memory mark counter that starts at
1, never wraps, is never persisted and is never handed to a caller. A key exists only through
``LeaseDomain.prepare``: the mark is reserved under the domain lock before any child is launched,
the frozen EXCL-create batch is written once, and every outcome other than a confirmed
prepare consumes the mark for good. ``activate`` accepts only the original handle object and writes
a reference with no lifetime. Every kernel write runs in a child that enters the namespace by
descriptor and executes ``nft -f -``; no Python runs after ``execve``.

Ownership: the creating process id plus a per-process token that ``os.register_at_fork`` re-mints
in every forked copy. Every public operation, and the counter itself, refuses in a forked copy
before any lock, counter or kernel action. There is no argument, environment variable or flag that
disables the check. A new generation after a fork needs a fresh interpreter (``execve``).

This unit installs no production rules or chains (H2), runs no cycle and makes no control-plane
request (H1A-3). ``ClockWitness``/``detect_gap`` and ``sleep_capability_report`` are diagnostic
readers only: nothing here enforces them. Missing OS capabilities fail closed.
"""
import contextlib
import dataclasses
import gzip
import ipaddress
import os
import re
import secrets
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
import types
from pathlib import Path

__all__ = (
    "ACTIVATED_MAP", "CLOCK_GAP_TOLERANCE_MS", "ClockSample", "ClockUnavailable", "ClockWitness",
    "ControlPlaneUnavailable", "DomainClosed", "DomainExhausted", "DomainUnavailable", "ForeignHandle",
    "ForeignProcess", "GATE_CHAIN", "HandleState", "HostQuarantined", "IP_PATH", "InstallerFailed", "LeaseDomain",
    "CHILD_REAP_GRACE_MS", "MARK_MAX", "MAX_PREPARE_TIMEOUT_MS", "NAMESPACE_READY_TIMEOUT_MS", "NFT_PATH",
    "PREPARED_SET", "PREPARE_CHILD_TIMEOUT_MS", "PrepareFailed",
    "PreparedKey", "SelfTestReport", "TABLE", "detect_gap", "generation_self_test", "sleep_capability_report",
    "verify_cp_socket",
)

TABLE, PREPARED_SET, ACTIVATED_MAP, GATE_CHAIN = "heel_lease", "prepared", "activated", "gate"
MARK_MAX = 0xFFFF_FFFF
PREPARE_CHILD_TIMEOUT_MS = 1000  # one deadline per installer child: output drained AND exit status collected
NAMESPACE_READY_TIMEOUT_MS = 2000  # a namespace helper reports ready within this or is killed
CHILD_REAP_GRACE_MS = 250  # finite reap wait after SIGKILL or a helper release; past it the outcome is uncertain
MAX_PREPARE_TIMEOUT_MS = 3000  # LEASE_MS bound of H1DR/H1F
CLOCK_GAP_TOLERANCE_MS = 200
MAX_BATCH_BYTES = 4096
MAX_OUTPUT_BYTES = 65536
CHILD_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
CLONE_NEWNET = getattr(os, "CLONE_NEWNET", 0x40000000)

# Reservation states (one-way): RESERVED -> PREPARED -> ACTIVATED -> CLOSED and
# {RESERVED, PREPARED, ACTIVATED} -> CONSUMED. No transition leads back.
RESERVED, PREPARED, ACTIVATED, CLOSED, CONSUMED = "reserved", "prepared", "activated", "closed", "consumed"


def _resolve_tool(candidates: tuple[str, ...]) -> str | None:
    """The first fixed absolute candidate that is an executable regular file (resolved once)."""
    for candidate in candidates:
        try:
            info = os.stat(candidate)
        except OSError:
            continue
        if stat.S_ISREG(info.st_mode) and info.st_mode & 0o111:
            return candidate
    return None


NFT_PATH = _resolve_tool(("/usr/sbin/nft", "/sbin/nft"))
IP_PATH = _resolve_tool(("/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"))


class DomainUnavailable(RuntimeError):
    """A required OS capability (Linux namespaces, nft) is missing; nothing was created."""


class DomainExhausted(RuntimeError):
    """The next mark would exceed 0xFFFF_FFFF. Refusal, never a wrap; no kernel write happened."""


class ForeignProcess(RuntimeError):
    """The caller is not the process that created the domain (a forked copy, or after a fork)."""


class ForeignHandle(RuntimeError):
    """The handle is not the object this domain issued (copy, replace, other domain, hand-built)."""


class HandleState(RuntimeError):
    """The handle's reservation is not in a state that allows the operation."""


class DomainClosed(HandleState):
    """``close_generation`` ran; the domain refuses every further operation."""


class InstallerFailed(RuntimeError):
    """An installer child failed, timed out or ended in an uncertain state (fixed code only)."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class PrepareFailed(InstallerFailed):
    """The prepare child did not confirm; the reserved mark is CONSUMED and never reissued."""


class HostQuarantined(RuntimeError):
    """The generation self-test failed; the report carries fixed tokens only."""

    def __init__(self, report: "SelfTestReport"):
        super().__init__("selftest_failed")
        self.report = report


class ControlPlaneUnavailable(RuntimeError):
    """A client-side control-plane socket check failed (fixed code only)."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


# ---------------------------------------------------------------------------------------------
# Ownership: a per-process token, re-minted in every forked copy.

_PROCESS_TOKEN = object()
_FORKED = False


def _remint() -> None:
    global _PROCESS_TOKEN, _FORKED, _REAP_LOCK, _UNREAPED
    _PROCESS_TOKEN = object()
    _FORKED = True
    _REAP_LOCK, _UNREAPED = threading.Lock(), set()  # never a held registry lock, nor the parent's children


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_remint)


class _MarkCounter:
    """Module-private: strictly increasing from ``start``, refuses past 0xFFFF_FFFF, never persisted.
    It checks its own owner first, so a forked copy cannot advance it through any path."""

    __slots__ = ("_next", "_owner_pid", "_process_token")

    def __init__(self, start: int = 1):
        if type(start) is not int or not 1 <= start <= MARK_MAX:
            raise ValueError("counter start outside 1..0xFFFF_FFFF")
        self._next = start
        self._owner_pid = os.getpid()
        self._process_token = _PROCESS_TOKEN

    def next(self) -> int:
        if os.getpid() != self._owner_pid or self._process_token is not _PROCESS_TOKEN or _FORKED:
            raise ForeignProcess("forked_process")
        value = self._next
        if value > MARK_MAX:
            raise DomainExhausted("domain_exhausted")
        self._next = value + 1
        return value


_SEAL = object()


@dataclasses.dataclass(frozen=True, slots=True)
class PreparedKey:
    """An opaque prepared handle. Only ``LeaseDomain.prepare`` creates one; the domain accepts it
    back only as the identical object it issued (an equal copy is foreign)."""

    domain_token: str
    ns_identity: tuple[int, int]
    src: str
    dst: str
    mark: int
    timeout_ms: int
    prepared_monotonic_ns: int  # sampled before the child was launched; the kernel commit is later
    handle_nonce: str
    _seal: object = dataclasses.field(default=None, repr=False, compare=False, kw_only=True)

    def __post_init__(self) -> None:
        if self._seal is not _SEAL:
            raise ForeignHandle("unsealed_handle")
        object.__setattr__(self, "_seal", None)  # the seal is checked, never kept or copied


# ---------------------------------------------------------------------------------------------
# Batches (frozen text; the prepared set is written only with ``create``, never ``add``).

def _ipv4(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("address must be a dotted IPv4 string")
    address = ipaddress.IPv4Address(value)
    if str(address) != value:
        raise ValueError("address must be canonical")
    return value


def _render_prepare(src: str, dst: str, mark: int, timeout_ms: int) -> bytes:
    return (f"create element inet {TABLE} {PREPARED_SET} "
            f"{{ {src} . {dst} . {mark:#010x} timeout {timeout_ms}ms }}\n").encode()


def _render_activate(src: str, dst: str, mark: int) -> bytes:
    return (f"destroy element inet {TABLE} {ACTIVATED_MAP} {{ {src} . {dst} }}\n"
            f"add element inet {TABLE} {ACTIVATED_MAP} {{ {src} . {dst} : {mark:#010x} }}\n").encode()


def _render_close(src: str, dst: str) -> bytes:
    return f"destroy element inet {TABLE} {ACTIVATED_MAP} {{ {src} . {dst} }}\n".encode()


def _render_flush() -> bytes:
    return f"flush map inet {TABLE} {ACTIVATED_MAP}\n".encode()


def _gate_table_fixture() -> bytes:
    """SELFTEST-FIXTURE: the H1F gate shape, installed only into throwaway self-test namespaces."""
    return ("table inet heel_lease {\n"
            "  set prepared { type ipv4_addr . ipv4_addr . mark ; flags timeout ; }\n"
            "  map activated { type ipv4_addr . ipv4_addr : mark ; }\n"
            "  chain gate {\n"
            "    type filter hook output priority 0 ; policy drop ;\n"
            "    meta mark set 0\n"
            "    meta mark set ip saddr . ip daddr map @activated\n"
            "    ip saddr . ip daddr . meta mark @prepared accept\n"
            "  }\n"
            "}\n").encode()


# ---------------------------------------------------------------------------------------------
# The exec child: setns by descriptor, the batch on stdin, execve. No Python API after the fork.

def _exec_child(ns_fd, path, argv, env, stdin_fd, sink_fd):
    """Runs only in the forked child; never returns (the caller ``_exit``s on any failure)."""
    if ns_fd is not None:
        os.setns(ns_fd, CLONE_NEWNET)
    os.dup2(stdin_fd, 0)
    os.dup2(sink_fd, 1)
    os.dup2(sink_fd, 2)
    os.execve(path, argv, env)


def _spawn(ns_fd: int | None, path: str, argv: list[str], data: bytes) -> tuple[int, int]:
    """Write the frozen bytes into a pipe, fork, and exec ``path`` in the namespace of ``ns_fd``.
    Returns (pid, read end of the child's combined stdout/stderr)."""
    if len(data) > MAX_BATCH_BYTES:
        raise ValueError("batch too large")
    env = {"PATH": CHILD_PATH, "LC_ALL": "C"}
    batch_r, batch_w = os.pipe()
    try:
        os.write(batch_w, data)
    finally:
        os.close(batch_w)
    try:
        sink_r, sink_w = os.pipe()
    except BaseException:
        os.close(batch_r)
        raise
    try:
        pid = os.fork()
    except BaseException:
        for fd in (batch_r, sink_r, sink_w):
            os.close(fd)
        raise
    if pid == 0:
        try:
            _exec_child(ns_fd, path, argv, env, batch_r, sink_w)
        finally:
            os._exit(127)
    os.close(batch_r)
    os.close(sink_w)
    return pid, sink_r


_UNREAPED: set[int] = set()  # owned children that outlived their reap grace; reaped later, never signalled again
_REAP_LOCK = threading.Lock()  # one critical section for a registry snapshot, its polls and removals


def _settle(pid: int, deadline_ns: int) -> tuple[bool, int | None]:
    """Poll the owned child ``pid`` (never a blocking wait) until it is reaped or the monotonic
    ``deadline_ns`` passes. Returns (reaped, exit code); the code is None unless the exit was
    observed by the deadline, so a late exit is never a success. A pid that is no longer this
    process's child counts as reaped with an unknown code."""
    pause = 0.0001
    while True:
        try:
            done, status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            return True, None
        observed = time.monotonic_ns()
        if done:
            return True, os.waitstatus_to_exitcode(status) if observed <= deadline_ns else None
        if observed >= deadline_ns:
            return False, None
        time.sleep(min(pause, (deadline_ns - observed) / 1e9))
        pause = min(pause * 2, 0.005)


def _kill_and_reap(pid: int) -> bool:
    """SIGKILL the owned child ``pid`` unless it is already reaped, then reap it within
    CHILD_REAP_GRACE_MS. A child still unreaped after the grace (for example stuck in the kernel)
    is recorded in ``_UNREAPED`` and False is returned: its outcome stays uncertain."""
    if _settle(pid, 0)[0]:
        return True
    with contextlib.suppress(ProcessLookupError):
        os.kill(pid, signal.SIGKILL)  # still unreaped, so the pid cannot have been reused
    reaped, _code = _settle(pid, time.monotonic_ns() + CHILD_REAP_GRACE_MS * 1_000_000)
    if not reaped:
        with _REAP_LOCK:
            _UNREAPED.add(pid)
    return reaped


def _sweep_unreaped() -> None:
    """Non-blocking: reap earlier unreaped children that have ended since (owned pids only). The
    snapshot, each poll and each removal share one critical section, so no sweep can poll a pid that
    another sweep already reaped (and the kernel may have reused for a new child)."""
    with _REAP_LOCK:
        for pid in tuple(_UNREAPED):
            if _settle(pid, 0)[0]:
                _UNREAPED.discard(pid)


def _await(pid: int, sink_r: int, timeout_ms: int) -> tuple[int | None, bytes]:
    """One monotonic deadline covers draining the child's output AND collecting its exit status;
    EOF alone completes nothing. On expiry the child is SIGKILLed and reaped (within the finite
    grace, or recorded as unreaped) and the status is None (uncertain), even if it exits 0 later.
    Output is bounded and private."""
    deadline = time.monotonic_ns() + timeout_ms * 1_000_000
    output = bytearray()
    poller = select.poll()
    poller.register(sink_r, select.POLLIN | select.POLLHUP | select.POLLERR)
    while True:
        remaining_ms = -(-(deadline - time.monotonic_ns()) // 1_000_000)
        if remaining_ms <= 0:
            _kill_and_reap(pid)
            return None, bytes(output)
        if not poller.poll(remaining_ms):
            continue
        chunk = os.read(sink_r, 4096)
        if not chunk:
            break
        if len(output) < MAX_OUTPUT_BYTES:
            output += chunk[:MAX_OUTPUT_BYTES - len(output)]
    reaped, status = _settle(pid, deadline)
    if not reaped:
        _kill_and_reap(pid)
    return status, bytes(output)


def _run(ns_fd: int | None, path: str | None, argv: list[str], data: bytes = b"",
         timeout_ms: int = PREPARE_CHILD_TIMEOUT_MS) -> tuple[int | None, bytes]:
    """One bounded child. Whatever happens in the parent, the child is reaped before returning
    or raising; a status of None means the outcome is uncertain."""
    if path is None:
        raise DomainUnavailable("tool_missing")
    _sweep_unreaped()
    pid, sink_r = _spawn(ns_fd, path, argv, data)
    reaped = False
    try:
        status, output = _await(pid, sink_r, timeout_ms)
        reaped = True
        return status, output
    finally:
        os.close(sink_r)
        if not reaped:
            _kill_and_reap(pid)


def _nft(ns_fd: int, data: bytes) -> tuple[int | None, bytes]:
    return _run(ns_fd, NFT_PATH, ["nft", "-f", "-"], data)


# ---------------------------------------------------------------------------------------------
# Namespaces held only by descriptor.

def _read_ready(ready_r: int, timeout_ms: int) -> bytes | None:
    """The helper's one ready byte (b"" at EOF) if it arrived by the monotonic deadline, else None."""
    deadline = time.monotonic_ns() + timeout_ms * 1_000_000
    poller = select.poll()
    poller.register(ready_r, select.POLLIN | select.POLLHUP | select.POLLERR)
    while True:
        remaining_ms = -(-(deadline - time.monotonic_ns()) // 1_000_000)
        if remaining_ms <= 0:
            return None
        if poller.poll(remaining_ms):
            ready = os.read(ready_r, 1)
            return ready if time.monotonic_ns() <= deadline else None


class _Namespace:
    """A fresh network namespace: a helper child unshares and blocks on a pipe while the parent
    opens ``/proc/<helper>/ns/net`` once; ``release`` lets the helper exit and reaps it. A helper
    that does not report ready within NAMESPACE_READY_TIMEOUT_MS is killed and nothing is opened."""

    def __init__(self) -> None:
        if not sys.platform.startswith("linux") or not hasattr(os, "unshare") or not hasattr(os, "setns"):
            raise DomainUnavailable("namespaces_unavailable")
        _sweep_unreaped()
        hold_r, hold_w = os.pipe()
        ready_r, ready_w = os.pipe()
        self.pid = os.fork()
        if self.pid == 0:
            try:
                os.close(hold_w)
                os.close(ready_r)
                os.unshare(CLONE_NEWNET)
                os.write(ready_w, b"u")
                os.read(hold_r, 1)
            finally:
                os._exit(0)
        os.close(hold_r)
        os.close(ready_w)
        self._hold_w: int | None = hold_w
        self._reaped = False
        self.fd: int | None = None
        try:
            ready = _read_ready(ready_r, NAMESPACE_READY_TIMEOUT_MS)
            if ready is None:
                raise DomainUnavailable("namespace_ready_timeout")
            if ready != b"u":
                raise DomainUnavailable("unshare_failed")
            self.fd = os.open(f"/proc/{self.pid}/ns/net", os.O_RDONLY | os.O_CLOEXEC)
            info, own = os.fstat(self.fd), os.stat("/proc/self/ns/net")
            if (info.st_dev, info.st_ino) == (own.st_dev, own.st_ino):
                raise DomainUnavailable("namespace_not_new")
            self.identity = (info.st_dev, info.st_ino)
        except BaseException:
            self.release(kill=True)
            if self.fd is not None:
                os.close(self.fd)
            raise
        finally:
            os.close(ready_r)

    def release(self, *, kill: bool = False) -> bool:
        """Close the hold pipe once; the helper then exits by itself within CHILD_REAP_GRACE_MS, or
        (at once with ``kill``) is SIGKILLed and given the same finite grace. True only when the
        helper was reaped; an unreaped helper is left to ``_UNREAPED`` and never signalled from here."""
        if self._hold_w is not None:
            os.close(self._hold_w)
            self._hold_w = None
            if not kill:
                self._reaped = _settle(self.pid, time.monotonic_ns() + CHILD_REAP_GRACE_MS * 1_000_000)[0]
            if not self._reaped:
                self._reaped = _kill_and_reap(self.pid)
        return self._reaped


class LeaseDomain:
    """One generation-owned network namespace with prepare-once reservations (H1ADR section 4.2).

    Every mutating operation holds the domain lock for its whole duration, including the bounded
    child wait, so reservation, child launch and the state transition are one serialized step:
    a concurrent second ``activate`` waits and then finds the handle no longer PREPARED, and
    ``close_generation`` cannot run between a child's commit and the state that records it."""

    def __init__(self, *, _seal: object, ns_fd: int):
        if _seal is not _SEAL:
            raise TypeError("use LeaseDomain.create()")
        if type(ns_fd) is not int:
            raise TypeError("namespace descriptor required")
        info = os.fstat(ns_fd)
        self._owner_pid = os.getpid()
        self._process_token = _PROCESS_TOKEN
        self._token = secrets.token_hex(16)
        self.generation_id = secrets.token_hex(16)  # logs and the request's generation_id only
        self._ns_fd = ns_fd
        self.ns_identity = (info.st_dev, info.st_ino)
        self._lock = threading.Lock()
        self._counter = _MarkCounter()
        self._reservations: dict[int, str] = {}
        self._handles: dict[int, PreparedKey] = {}
        self._closed = False

    @classmethod
    def create(cls, *, _counter: _MarkCounter | None = None) -> "LeaseDomain":
        """A new domain in a namespace this process just created. ``_counter`` is the one labelled
        seam (SEAM-COUNTER-START d3 only): it sets the counter's start value and nothing else."""
        if _FORKED:
            raise ForeignProcess("forked_process")
        if _counter is not None and type(_counter) is not _MarkCounter:
            raise TypeError("counter seam accepts only a private counter")
        if NFT_PATH is None:
            raise DomainUnavailable("nft_missing")
        namespace = _Namespace()
        if not namespace.release():
            os.close(namespace.fd)
            raise DomainUnavailable("namespace_helper_unreaped")
        domain = cls(_seal=_SEAL, ns_fd=namespace.fd)
        if domain.ns_identity != namespace.identity:
            os.close(namespace.fd)
            raise DomainUnavailable("namespace_identity_changed")
        if _counter is not None:
            domain._counter = _counter
        return domain

    def _assert_owner(self):
        if os.getpid() != self._owner_pid or self._process_token is not _PROCESS_TOKEN or _FORKED:
            raise ForeignProcess("forked_process")

    @property
    def ns_fd(self) -> int:
        """The namespace descriptor for H2/H3 consumers (``dup`` it; never a path)."""
        self._assert_owner()
        if self._closed:
            raise DomainClosed("domain_closed")
        return self._ns_fd

    def _check_handle(self, handle: object) -> PreparedKey:
        if type(handle) is not PreparedKey or handle is not self._handles.get(handle.mark):
            raise ForeignHandle("foreign_handle")
        if handle.domain_token != self._token:
            raise ForeignHandle("foreign_handle")
        if self._closed:
            raise DomainClosed("domain_closed")
        info = os.fstat(self._ns_fd)
        if (info.st_dev, info.st_ino) != handle.ns_identity:
            raise ForeignHandle("namespace_identity_changed")
        return handle

    def prepare(self, src: str, dst: str, timeout_ms: int) -> PreparedKey:
        self._assert_owner()
        src, dst = _ipv4(src), _ipv4(dst)
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= MAX_PREPARE_TIMEOUT_MS:
            raise ValueError("timeout_ms outside 1..3000")
        with self._lock:
            if self._closed:
                raise DomainClosed("domain_closed")
            mark = self._counter.next()
            self._reservations[mark] = RESERVED
            try:
                batch = _render_prepare(src, dst, mark, timeout_ms)
                started = time.monotonic_ns()
                status, _output = _nft(self._ns_fd, batch)
                if status != 0:
                    raise PrepareFailed("installer_timeout" if status is None else "installer_refused")
                handle = PreparedKey(self._token, self.ns_identity, src, dst, mark, timeout_ms, started,
                                     secrets.token_hex(16), _seal=_SEAL)
                self._handles[mark] = handle
                self._reservations[mark] = PREPARED
                return handle
            except BaseException as error:
                self._reservations[mark] = CONSUMED
                if isinstance(error, Exception) and not isinstance(error, PrepareFailed):
                    raise PrepareFailed("installer_error") from error
                raise

    def activate(self, handle: PreparedKey) -> None:
        self._assert_owner()
        with self._lock:
            handle = self._check_handle(handle)
            if self._reservations.get(handle.mark) != PREPARED:
                raise HandleState("not_prepared")
            try:
                status, _output = _nft(self._ns_fd, _render_activate(handle.src, handle.dst, handle.mark))
                if status != 0:
                    raise InstallerFailed("installer_timeout" if status is None else "installer_refused")
                self._reservations[handle.mark] = ACTIVATED
            except BaseException as error:
                self._reservations[handle.mark] = CONSUMED
                if isinstance(error, Exception) and not isinstance(error, InstallerFailed):
                    raise InstallerFailed("installer_error") from error
                raise

    def close(self, handle: PreparedKey) -> None:
        """Destroy the handle's activation reference. Idempotent; never frees the mark."""
        self._assert_owner()
        with self._lock:
            handle = self._check_handle(handle)
            state = self._reservations.get(handle.mark)
            if state == CLOSED:
                return
            try:
                status, _output = _nft(self._ns_fd, _render_close(handle.src, handle.dst))
                if status != 0:
                    raise InstallerFailed("installer_timeout" if status is None else "installer_refused")
                if state in (PREPARED, ACTIVATED):
                    self._reservations[handle.mark] = CLOSED
            except BaseException as error:
                self._reservations[handle.mark] = CONSUMED
                if isinstance(error, Exception) and not isinstance(error, InstallerFailed):
                    raise InstallerFailed("installer_error") from error
                raise

    def close_generation(self) -> None:
        """R-1: refuse everything from now on, consume every open handle, then one
        ``flush map activated`` in this domain's own namespace, then release the descriptor."""
        self._assert_owner()
        with self._lock:
            if self._closed:
                raise DomainClosed("domain_closed")
            self._closed = True
            for mark, state in self._reservations.items():
                if state != CLOSED:
                    self._reservations[mark] = CONSUMED
            try:
                status, _output = _nft(self._ns_fd, _render_flush())
            finally:
                os.close(self._ns_fd)
            if status != 0:
                raise InstallerFailed("flush_timeout" if status is None else "flush_refused")


# ---------------------------------------------------------------------------------------------
# Generation self-test (H1AD section 5.2 K1-K6 and K8, the A8-style re-add observation, and the
# CONFIG_HZ / overflowuid capture), through the same prepare/activate API, in throwaway namespaces.

_ST_L, _ST_R, _ST_PORT = "198.51.100.10", "203.0.113.10", 47002
_ST_K8 = ("192.0.2.10", "192.0.2.20")
_ST_LINKS = ("hst0", "hst1")
_ST_MACS = ("02:48:53:00:00:0a", "02:48:53:00:00:0b")
_ST_INTERVAL_NS = 5_000_000
_ST_MAGIC = b"HAST"
_MS = 1_000_000
_ELEMENT = re.compile(r"([0-9.]+) \. ([0-9.]+) \. (0x[0-9a-fA-F]+|[0-9]+) timeout ([0-9dhms]+) expires ([0-9dhms]+)")
_TIME_PART = re.compile(r"([0-9]+)(ms|d|h|m|s)")
_UNIT_MS = {"d": 86_400_000, "h": 3_600_000, "m": 60_000, "s": 1000, "ms": 1}
_TOKEN = re.compile(r"[a-z0-9][a-z0-9_.:-]{0,79}")


@dataclasses.dataclass(frozen=True)
class SelfTestReport:
    result: str  # "pass" or "fail"
    failures: tuple[str, ...]
    tokens: types.MappingProxyType
    ints: types.MappingProxyType


def _parse_nft_ms(text: str) -> int | None:
    if not re.fullmatch(r"(?:[0-9]+(?:ms|d|h|m|s))+", text):
        return None
    return sum(int(number) * _UNIT_MS[unit] for number, unit in _TIME_PART.findall(text))


def _prepared_elements(listing: str) -> dict[tuple[str, str, int], int]:
    """(src, dst, mark) -> expires_ms for each element of the prepared set listing."""
    found = {}
    for src, dst, mark, _timeout, expires in _ELEMENT.findall(listing):
        expires_ms = _parse_nft_ms(expires)
        if expires_ms is not None:
            found[(src, dst, int(mark, 16) if mark.lower().startswith("0x") else int(mark))] = expires_ms
    return found


def _listing(ns_fd: int) -> dict[tuple[str, str, int], int]:
    status, output = _run(ns_fd, NFT_PATH, ["nft", "list", "set", "inet", TABLE, PREPARED_SET])
    return _prepared_elements(output.decode("utf-8", "replace")) if status == 0 else {}


def _ip(ns_fd: int, *arguments: str) -> None:
    status, _output = _run(ns_fd, IP_PATH, ["ip", *arguments])
    if status != 0:
        raise InstallerFailed("fixture_ip_failed")


def _in_namespace(ns_fd: int, function):
    """Run ``function`` on a fresh thread that entered the namespace (setns is per thread)."""
    result: dict = {}

    def run() -> None:
        try:
            os.setns(ns_fd, CLONE_NEWNET)
            result["value"] = function()
        except BaseException as error:  # noqa: BLE001 - re-raised on the caller's thread
            result["error"] = error

    thread = threading.Thread(target=run)
    thread.start()
    thread.join(10)
    if "error" in result:
        raise result["error"]
    if "value" not in result:
        raise InstallerFailed("fixture_thread_timeout")
    return result["value"]


def _udp(ns_fd: int, address: tuple[str, int]) -> socket.socket:
    def create() -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(address)
        except BaseException:
            sock.close()
            raise
        return sock

    return _in_namespace(ns_fd, create)


def _probe_burst(sender: socket.socket, receiver: socket.socket, start_ns: int, count: int,
                 nonce: bytes) -> list[tuple[int, int, bool, bool]]:
    """(t_before, t_after, admitted, delivered) per probe; admission is the sendto verdict of the
    output gate inside its own CLOCK_MONOTONIC bracket, delivery only confirms it."""
    sent = []
    for index in range(count):
        delay = start_ns + index * _ST_INTERVAL_NS - time.monotonic_ns()
        if delay > 0:
            time.sleep(delay / 1e9)
        t_before = time.monotonic_ns()
        try:
            sender.sendto(_ST_MAGIC + struct.pack("!I", index) + nonce, (_ST_R, _ST_PORT))
            admitted = True
        except OSError:
            admitted = False
        sent.append((t_before, time.monotonic_ns(), admitted))
    time.sleep(0.05)
    delivered = set()
    receiver.setblocking(False)
    while True:
        try:
            data = receiver.recv(64)
        except (BlockingIOError, InterruptedError):
            break
        if len(data) == 24 and data[:4] == _ST_MAGIC and data[8:] == nonce:
            delivered.add(struct.unpack("!I", data[4:8])[0])
    return [(t0, t1, admitted, index in delivered) for index, (t0, t1, admitted) in enumerate(sent)]


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


def _versions() -> tuple[dict, dict]:
    release = os.uname().release.lower()
    match = re.fullmatch(r"([0-9]{1,3})\.([0-9]{1,3})\.[0-9]{1,4}(?:[-.+][a-z0-9.+-]{0,60})?", release)
    tokens = {"kernel_release": release if match and _TOKEN.fullmatch(release) else "unparsed",
              "kernel_major_minor": f"{int(match.group(1))}.{int(match.group(2))}" if match else "unparsed"}
    status, output = _run(None, NFT_PATH, ["nft", "--version"])
    nft = re.search(rb"nftables v([0-9]+\.[0-9]+\.[0-9]+)", output) if status == 0 else None
    tokens["nft_version"] = nft.group(1).decode() if nft else "unparsed"
    ints = {}
    hz = _config_hz(os.uname().release)
    if hz is not None:
        ints["config_hz"] = hz
    with contextlib.suppress(OSError, ValueError):
        ints["overflowuid"] = int(Path("/proc/sys/kernel/overflowuid").read_text().strip())
    return tokens, ints


def generation_self_test(domain: LeaseDomain) -> SelfTestReport:
    """Fail-closed behavioural gate at generation start; any failure raises ``HostQuarantined``.
    Uses two throwaway domains and a throwaway peer namespace; ``domain`` itself is never written."""
    domain._assert_owner()
    failures: list[str] = []
    tokens: dict[str, str] = {}
    ints: dict[str, int] = {}
    throwaway = second = peer = None
    sockets: list[socket.socket] = []
    try:
        tokens, ints = _versions()
        tick = -(-1_000_000_000 // ints["config_hz"]) if "config_hz" in ints else 10 * _MS
        ints["tick_allowance_ms"] = -(-tick // _MS)
        throwaway, second, peer = LeaseDomain.create(), LeaseDomain.create(), _Namespace()
        t_fd = throwaway.ns_fd
        _ip(t_fd, "link", "add", _ST_LINKS[0], "address", _ST_MACS[0], "type", "veth", "peer", "name", _ST_LINKS[1],
            "address", _ST_MACS[1])
        _ip(t_fd, "link", "set", _ST_LINKS[1], "netns", str(peer.pid))
        for fd, link, mine, other, other_mac in ((t_fd, _ST_LINKS[0], _ST_L, _ST_R, _ST_MACS[1]),
                                                 (peer.fd, _ST_LINKS[1], _ST_R, _ST_L, _ST_MACS[0])):
            _ip(fd, "link", "set", "lo", "up")
            _ip(fd, "addr", "add", f"{mine}/32", "dev", link)
            _ip(fd, "link", "set", link, "up")
            _ip(fd, "route", "add", f"{other}/32", "dev", link, "src", mine)
            _ip(fd, "neigh", "replace", other, "lladdr", other_mac, "dev", link, "nud", "permanent")
        for fd in (t_fd, second.ns_fd):
            status, _output = _nft(fd, _gate_table_fixture())
            if status != 0:
                raise InstallerFailed("fixture_table_failed")
        receiver = _udp(peer.fd, (_ST_R, _ST_PORT))
        sockets.append(receiver)
        sender = _udp(t_fd, (_ST_L, 0))
        sockets.append(sender)
        nonce = secrets.token_bytes(16)

        # K1/K2/K4/K5/K6 on one 200 ms key; K3 duplicate create while it is live.
        before_prepare = time.monotonic_ns()
        live = throwaway.prepare(_ST_L, _ST_R, 200)
        after_prepare = time.monotonic_ns()
        never_activated = throwaway.prepare(_ST_L, _ST_R, 200)
        never_activated_bound = time.monotonic_ns() + 200 * _MS + tick
        live_to, bound = before_prepare + 200 * _MS - 2 * tick, after_prepare + 200 * _MS + tick
        duplicate, duplicate_out = _nft(t_fd, _render_prepare(_ST_L, _ST_R, live.mark, 200))  # SELFTEST-FIXTURE k3
        duplicate_while_live = time.monotonic_ns() < live_to
        prepared_only = _probe_burst(sender, receiver, time.monotonic_ns(), 6, nonce)
        before_activate = time.monotonic_ns()
        throwaway.activate(live)
        after_activate = time.monotonic_ns()
        probes = _probe_burst(sender, receiver, after_activate, int((bound + 3 * tick + 100 * _MS - after_activate)
                                                                    // _ST_INTERVAL_NS), nonce)
        within = [p for p in probes if p[0] >= after_activate and p[1] <= live_to]
        admitted_live = [p for p in within if p[2] and p[3]]
        admitted_late = [p for p in probes if (p[2] or p[3]) and p[0] > bound]
        anomalies = sum(p[3] and not p[2] for p in prepared_only + probes)
        ints.update(selftest_prepared_only_admitted=sum(p[2] or p[3] for p in prepared_only),
                    selftest_admitted_before_expiry=len(admitted_live), selftest_live_probes=len(within),
                    selftest_admitted_after_expiry=len(admitted_late), selftest_anomalies=anomalies,
                    selftest_prepare_bracket_us=(after_prepare - before_prepare) // 1000,
                    selftest_activate_bracket_us=(after_activate - before_activate) // 1000,
                    selftest_duplicate_while_live=int(duplicate_while_live))
        if any(p[2] or p[3] for p in prepared_only):
            failures.append("k6_prepared_only_admitted")
        if not admitted_live or 100 * len(admitted_live) < 95 * len(within):
            failures.append("k1_no_live_delivery")
        if admitted_late:
            failures.append("k2_admitted_after_expiry")
        if anomalies:
            failures.append("probe_anomaly")
        tokens["selftest_duplicate_error"] = ("eexist" if duplicate not in (0, None) and b"File exists" in duplicate_out
                                              else "ok" if duplicate == 0 else "other")
        if tokens["selftest_duplicate_error"] != "eexist" or not duplicate_while_live:
            failures.append("k3_live_duplicate_not_refused")
        # K3: an expired, never-activated key accepts a fresh create (why marks never repeat).
        delay = never_activated_bound + 2 * tick + 20 * _MS - time.monotonic_ns()
        if delay > 0:
            time.sleep(delay / 1e9)
        recreate, _output = _nft(t_fd, _render_prepare(_ST_L, _ST_R, never_activated.mark, 200))  # SELFTEST-FIXTURE k3
        ints["selftest_expired_recreate_ok"] = int(recreate == 0)
        if recreate != 0:
            failures.append("k3_expired_recreate_refused")

        # A8-style observation (informative here; the launcher grades it against the source tag).
        observed = throwaway.prepare(_ST_L, _ST_R, 3000)
        time.sleep(0.5)
        first = _listing(t_fd).get((_ST_L, _ST_R, observed.mark))
        readd, _output = _nft(t_fd, _selftest_readd_batch(observed))
        second_read = _listing(t_fd).get((_ST_L, _ST_R, observed.mark))
        if readd != 0:
            tokens["readd_observation"] = "error"
        elif first is None or second_read is None:
            tokens["readd_observation"] = "unreadable"
        else:
            tokens["readd_observation"] = ("refresh" if second_read > first + 200
                                           else "noop" if second_read <= first else "other")

        # K8: a key created in a second throwaway namespace is not visible in the first.
        isolated = second.prepare(*_ST_K8, 3000)
        in_second = (*_ST_K8, isolated.mark) in _listing(second.ns_fd)
        leaked = any(key[:2] == _ST_K8 for key in _listing(t_fd))
        distinct = len({throwaway.ns_identity, second.ns_identity, domain.ns_identity, peer.identity}) == 4
        ints.update(k8_visible_in_own=int(in_second), k8_visible_in_other=int(leaked), k8_identities_distinct=int(distinct))
        if not in_second or leaked or not distinct:
            failures.append("k8_isolation")
    except Exception as error:  # noqa: BLE001 - a fixed token only
        failures.append("selftest_error_" + re.sub(r"[^a-z0-9]", "_", type(error).__name__.lower())[:40])
    finally:
        for sock in sockets:
            with contextlib.suppress(OSError):
                sock.close()
        for candidate in (throwaway, second):
            if candidate is not None and not candidate._closed:
                with contextlib.suppress(Exception):
                    candidate.close_generation()
        if peer is not None:
            with contextlib.suppress(OSError):
                os.close(peer.fd)
            if not peer.release():
                failures.append("peer_helper_unreaped")
    tokens = {key: value for key, value in tokens.items() if isinstance(value, str) and _TOKEN.fullmatch(value)}
    tokens["selftest"] = "fail" if failures else "pass"
    report = SelfTestReport("fail" if failures else "pass", tuple(failures), types.MappingProxyType(tokens),
                            types.MappingProxyType(dict(ints)))
    if failures:
        raise HostQuarantined(report)
    return report


def _selftest_readd_batch(handle: PreparedKey) -> bytes:
    """SELFTEST-FIXTURE a8 only: the non-EXCL re-add the installer contract forbids, written to a
    throwaway self-test namespace to observe the kernel's re-add semantics. Never used elsewhere."""
    return (f"add element inet {TABLE} {PREPARED_SET} "
            f"{{ {handle.src} . {handle.dst} . {handle.mark:#010x} timeout 2900ms }}\n").encode()


# ---------------------------------------------------------------------------------------------
# Client-side control-plane socket check (H1AD section 3.4).

def verify_cp_socket(path: str, cp_uid: int, *, uid_map_path: str = "/proc/self/uid_map") -> None:
    """The supervisor's mutual check before it writes a request. Never creates, unlinks or renames
    anything. Every failure is ``ControlPlaneUnavailable`` with a fixed code."""
    if not sys.platform.startswith("linux") or not hasattr(socket, "SO_PEERCRED"):
        raise ControlPlaneUnavailable("platform_unsupported")
    if type(cp_uid) is not int or not 0 <= cp_uid < 2 ** 32 - 1:
        raise ControlPlaneUnavailable("cp_uid_invalid")
    try:
        if Path(uid_map_path).read_text(encoding="ascii").split() != ["0", "0", "4294967295"]:
            raise ControlPlaneUnavailable("not_initial_user_namespace")
        if os.readlink("/proc/self/ns/pid") != os.readlink("/proc/1/ns/pid"):
            raise ControlPlaneUnavailable("not_initial_pid_namespace")
        target = Path(path)
        if not target.is_absolute():
            raise ControlPlaneUnavailable("path_not_absolute")
        info, parent = os.lstat(target), os.lstat(target.parent)
    except OSError as error:
        raise ControlPlaneUnavailable("socket_unreadable") from error
    if not (stat.S_ISSOCK(info.st_mode) and info.st_uid == cp_uid and stat.S_IMODE(info.st_mode) == 0o600):
        raise ControlPlaneUnavailable("socket_profile")
    if not (stat.S_ISDIR(parent.st_mode) and parent.st_uid == cp_uid and stat.S_IMODE(parent.st_mode) == 0o700):
        raise ControlPlaneUnavailable("directory_profile")
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.settimeout(5)
        client.connect(str(target))
        pid, uid, _gid = struct.unpack("3i", client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    except OSError as error:
        raise ControlPlaneUnavailable("connect_failed") from error
    finally:
        client.close()
    if uid != cp_uid or pid == 0:
        raise ControlPlaneUnavailable("peer_identity")


# ---------------------------------------------------------------------------------------------
# Diagnostic readers (H1ADR W-1/W-2 and A-1/A-2). Readers only: nothing in H1A-1 enforces them.

class ClockUnavailable(RuntimeError):
    """A clock the witness needs does not exist on this platform."""


@dataclasses.dataclass(frozen=True)
class ClockSample:
    monotonic_ns: int
    boottime_ns: int
    realtime_ns: int


class ClockWitness:
    """Samples CLOCK_MONOTONIC, CLOCK_BOOTTIME and CLOCK_REALTIME together (diagnostic only)."""

    def __init__(self, clock=None):
        self._clock = clock or time.clock_gettime_ns

    def sample(self) -> ClockSample:
        ids = [getattr(time, name, None) for name in ("CLOCK_MONOTONIC", "CLOCK_BOOTTIME", "CLOCK_REALTIME")]
        if None in ids:
            raise ClockUnavailable("clock_missing")
        return ClockSample(*(self._clock(clock_id) for clock_id in ids))


def detect_gap(start: ClockSample, previous: ClockSample, current: ClockSample,
               tolerance_ms: int = CLOCK_GAP_TOLERANCE_MS) -> tuple[str, ...]:
    """Fixed tokens: ``sleep_gap`` when boottime-monotonic moved more than the tolerance since the
    generation start (W-1), ``wall_gap`` when realtime and monotonic advanced by different amounts
    between two consecutive samples (W-2). Empty means no gap was seen. Detection, not safety."""
    tolerance = tolerance_ms * _MS
    gaps = []
    if abs((current.boottime_ns - current.monotonic_ns) - (start.boottime_ns - start.monotonic_ns)) > tolerance:
        gaps.append("sleep_gap")
    if abs((current.realtime_ns - previous.realtime_ns) - (current.monotonic_ns - previous.monotonic_ns)) > tolerance:
        gaps.append("wall_gap")
    return tuple(gaps)


SLEEP_TARGETS = ("sleep.target", "suspend.target", "hibernate.target", "hybrid-sleep.target",
                 "suspend-then-hibernate.target")
SLEEP_CONF = "/etc/systemd/sleep.conf.d/heel.conf"
SLEEP_CONF_KEYS = ("AllowSuspend", "AllowHibernation", "AllowHybridSleep", "AllowSuspendThenHibernate")
POWER_STATES = ("freeze", "standby", "mem", "disk")


def _read_bounded(path: str) -> str | None:
    try:
        with open(path, "rb") as handle:
            return handle.read(4096).decode("ascii", "replace")
    except OSError:
        return None


def _systemctl_is_enabled(unit: str) -> str:
    try:
        completed = subprocess.run(["/usr/bin/systemctl", "is-enabled", unit], capture_output=True, timeout=10,
                                   env={"PATH": CHILD_PATH, "LC_ALL": "C"})
    except (OSError, subprocess.SubprocessError):
        return ""
    return completed.stdout.decode("ascii", "replace")


def sleep_capability_report(*, systemctl=None, read=None) -> dict[str, str]:
    """A-1/A-2 as a reader: a fixed key set with fixed token values; raw text never escapes.
    ``systemctl(unit) -> stdout`` and ``read(path) -> text | None`` are injectable for fixtures."""
    systemctl = systemctl or _systemctl_is_enabled
    read = read or _read_bounded
    report = {}
    for unit in SLEEP_TARGETS:
        state = (systemctl(unit) or "").strip()
        report["unit_" + unit.replace("-", "_").replace(".target", "")] = (
            "masked" if state == "masked" else "not_masked" if re.fullmatch(r"[a-z-]{1,32}", state) else "unknown")
    conf = read(SLEEP_CONF)
    if conf is None:
        report["sleep_conf"] = "missing"
    else:
        values = dict(re.findall(r"^\s*([A-Za-z]+)\s*=\s*(\S+)\s*$", conf, re.M))
        report["sleep_conf"] = "all_disabled" if all(values.get(key) == "no" for key in SLEEP_CONF_KEYS) else "incomplete"
    cmdline, disk = read("/proc/cmdline"), read("/sys/power/disk")
    if cmdline is not None and "nohibernate" in cmdline.split():
        report["hibernation"] = "disabled_cmdline"
    elif disk is not None and disk.split() == ["[disabled]"]:
        report["hibernation"] = "disabled_sys_power"
    elif cmdline is None and disk is None:
        report["hibernation"] = "unknown"
    else:
        report["hibernation"] = "enabled"
    states = read("/sys/power/state")
    if states is None:
        report["power_state"] = "unreadable"
    else:
        words = states[:64].split()
        known = [word for word in POWER_STATES if word in words]
        report["power_state"] = ("_".join(known) or "none") + ("_other" if set(words) - set(POWER_STATES) else "")
    report["enforcement"] = "none_in_h1a1"
    return report
