"""H1A-1 unit and state-machine evidence for the lease domain and the host-authority listener.

Runs on any OS. Tests that inject an installer double, a ``(pid, uid)`` pair, a socket double or
clock samples say so with the docstring prefix ``STATE-MACHINE ONLY:`` and claim nothing about
namespaces, peer credentials, expiry or packets; the Linux job (tests/linux/test_host_authority_proof.py)
owns those. The installer double replaces only the code the forked child runs after ``fork``
(``_exec_child``): the real fork, pipes, bounded wait, SIGKILL and reaping in the parent all run.
Race tests are deterministic: a signalling lock and pipe barriers order the threads; no sleeps and
no clock patches decide an interleaving.
"""
from __future__ import annotations

import ast
import contextlib
import copy
import dataclasses
import importlib.util
import inspect
import json
import os
import pickle
import re
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
AUTHORITY_FILE = ROOT / "deploy" / "host" / "authority.py"
LISTENER_FILE = ROOT / "heel" / "saas" / "host_authority.py"
PROOF_FILE = ROOT / "tests" / "linux" / "test_host_authority_proof.py"
WORKFLOW = ROOT / ".github" / "workflows" / "codeql.yml"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses resolve string annotations through sys.modules
    spec.loader.exec_module(module)
    return module


authority = _load("heel_host_authority_domain_unit", AUTHORITY_FILE)
host_authority = _load("heel_host_authority_listener_unit", LISTENER_FILE)

L, R = "198.51.100.10", "203.0.113.10"
POSIX_FORK = pytest.mark.skipif(not hasattr(os, "fork"), reason="needs os.fork")


# ---------------------------------------------------------------------------------------------
# State-machine fixtures.

class Installer:
    """A recorded installer: the parent's batch bytes and child pids are recorded; the forked child
    runs ``plan[call]`` (an exit code, or ("sleep", seconds, code), or ("wait", fd), or ("eof", seconds,
    code): close its output first, then linger and exit) instead of nft."""

    def __init__(self, monkeypatch, plan=None, default=0):
        self.plan, self.default = list(plan or []), default
        self.batches: list[bytes] = []
        self.pids: list[int] = []
        real_spawn = authority._spawn

        def spawn(ns_fd, path, argv, data):
            self.batches.append(data)
            pid, sink = real_spawn(ns_fd, path, argv, data)
            self.pids.append(pid)
            return pid, sink

        monkeypatch.setattr(authority, "_spawn", spawn)
        monkeypatch.setattr(authority, "_exec_child", self._child)
        monkeypatch.setattr(authority, "NFT_PATH", "/nonexistent/nft-double")

    def _child(self, ns_fd, path, argv, env, stdin_fd, sink_fd):
        step = self.plan[len(self.batches) - 1] if len(self.batches) <= len(self.plan) else self.default
        if isinstance(step, tuple) and step[0] == "sleep":
            time.sleep(step[1])
            os._exit(step[2])
        if isinstance(step, tuple) and step[0] == "wait":
            os.read(step[1], 1)  # a pipe barrier released by the test
            os._exit(step[2] if len(step) > 2 else 0)
        if isinstance(step, tuple) and step[0] == "eof":
            os.close(sink_fd)  # the parent sees EOF while this child is still running
            time.sleep(step[1])
            os._exit(step[2])
        os._exit(step)

    def reaped(self) -> bool:
        for pid in self.pids:
            try:
                os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                continue
            return False
        return True


def state_machine_domain(tmp_path: Path):
    """A domain over a stand-in descriptor (no namespace); only the installer double writes."""
    fd = os.open(tmp_path / f"ns-stand-in-{len(list(tmp_path.iterdir()))}", os.O_RDONLY | os.O_CREAT | os.O_CLOEXEC, 0o600)
    return authority.LeaseDomain(_seal=authority._SEAL, ns_fd=fd)


class SignallingLock:
    """The domain lock, plus an event that fires when a second thread has to wait for it."""

    def __init__(self):
        self._lock = threading.Lock()
        self.contended = threading.Event()

    def acquire(self, *args):
        return self._lock.acquire(*args)

    def release(self):
        self._lock.release()

    def locked(self):
        return self._lock.locked()

    def __enter__(self):
        if not self._lock.acquire(blocking=False):
            self.contended.set()
            self._lock.acquire()
        return self

    def __exit__(self, *exc):
        self._lock.release()


class Barrier:
    """A pipe the double's child reads one byte from; ``started`` is written by the parent hook."""

    def __init__(self):
        self.read_fd, self.write_fd = os.pipe()

    def release(self):
        os.write(self.write_fd, b"g")

    def close(self):
        for fd in (self.read_fd, self.write_fd):
            try:
                os.close(fd)
            except OSError:
                pass


def _thread(target, results, key):
    def run():
        try:
            results[key] = ("ok", target())
        except BaseException as error:  # noqa: BLE001 - recorded for the assertion
            results[key] = ("raised", error)

    thread = threading.Thread(target=run)
    thread.start()
    return thread


def _wait_spawned(installer: Installer, count: int, timeout: float = 10.0) -> None:
    """Block until the parent has launched ``count`` children (an observable fact, not a delay)."""
    deadline = time.monotonic() + timeout
    while len(installer.pids) < count:
        assert time.monotonic() < deadline, "the installer child was not launched"
        time.sleep(0.001)


# ---------------------------------------------------------------------------------------------
# Batches.

def test_installer_prepare_uses_create_and_never_add():
    batch = authority._render_prepare(L, R, 7, 2850).decode()
    assert batch == "create element inet heel_lease prepared { 198.51.100.10 . 203.0.113.10 . 0x00000007 timeout 2850ms }\n"
    source = AUTHORITY_FILE.read_text(encoding="utf-8")
    assert source.count("create element") == 1
    tree = ast.parse(source)
    writers = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
               and "add element inet {TABLE} {PREPARED_SET}" in ast.get_source_segment(source, node)}
    assert writers == {"_selftest_readd_batch"}
    callers = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
               and any(isinstance(call, ast.Call) and getattr(call.func, "id", None) == "_selftest_readd_batch"
                       for call in ast.walk(node))}
    assert callers == {"generation_self_test"}


def test_activation_batch_carries_no_lifetime():
    batch = authority._render_activate(L, R, 7).decode()
    assert batch.splitlines() == ["destroy element inet heel_lease activated { 198.51.100.10 . 203.0.113.10 }",
                                  "add element inet heel_lease activated { 198.51.100.10 . 203.0.113.10 : 0x00000007 }"]
    for word in ("timeout", "expires", "prepared", "create"):
        assert word not in batch
    assert authority._render_close(L, R).decode() == "destroy element inet heel_lease activated { 198.51.100.10 . 203.0.113.10 }\n"
    assert authority._render_flush().decode() == "flush map inet heel_lease activated\n"


# ---------------------------------------------------------------------------------------------
# U-1 .. U-10 (H1ADR section 4.4) and the counter bound.

def test_prepare_has_no_raw_mark_parameter_and_counter_is_private():
    assert list(inspect.signature(authority.LeaseDomain.prepare).parameters) == ["self", "src", "dst", "timeout_ms"]
    assert "_MarkCounter" not in authority.__all__ and "MarkAllocator" not in dir(authority)
    for name in authority.__all__:
        target = getattr(authority, name)
        if target is authority.PreparedKey:
            with pytest.raises(authority.ForeignHandle):
                authority.PreparedKey("t", (1, 2), L, R, 1, 200, 0, "n")
            continue
        members = [getattr(target, attr) for attr in dir(target) if not attr.startswith("_")] if isinstance(target, type) else [target]
        for member in members:
            if callable(member) and not isinstance(member, type):
                try:
                    parameters = inspect.signature(member).parameters
                except (TypeError, ValueError):
                    continue
                assert "mark" not in parameters, (name, member)
    assert list(inspect.signature(authority.LeaseDomain.create).parameters) == ["_counter"]


@POSIX_FORK
def test_repeated_prepare_never_reissues_a_mark_after_expiry_or_close(monkeypatch, tmp_path):
    """STATE-MACHINE ONLY: marks 1, 2, 3; every handle closed (expiry needs no API call); next is 4."""
    installer = Installer(monkeypatch)
    domain = state_machine_domain(tmp_path)
    handles = [domain.prepare(L, R, 200) for _ in range(3)]
    assert [handle.mark for handle in handles] == [1, 2, 3]
    domain.activate(handles[0])
    for handle in handles:
        domain.close(handle)
        domain.close(handle)  # idempotent
    assert set(domain._reservations.values()) == {authority.CLOSED}
    assert domain.prepare(L, R, 200).mark == 4
    for name in ("reset", "release", "reopen", "free", "allocate", "seed"):
        assert not any(name in attr for attr in dir(domain) if not attr.startswith("__")), name
    assert installer.reaped()


@POSIX_FORK
def test_failed_prepare_consumes_mark_permanently(monkeypatch, tmp_path):
    """STATE-MACHINE ONLY: the double exits 1; the reserved mark is CONSUMED and never reissued."""
    installer = Installer(monkeypatch, plan=[1])
    domain = state_machine_domain(tmp_path)
    with pytest.raises(authority.PrepareFailed) as raised:
        domain.prepare(L, R, 200)
    assert raised.value.code == "installer_refused"
    assert domain._reservations == {1: authority.CONSUMED} and 1 not in domain._handles
    assert domain.prepare(L, R, 200).mark == 2
    assert installer.batches[0] == authority._render_prepare(L, R, 1, 200) and installer.reaped()


@POSIX_FORK
def test_timed_out_prepare_kills_child_and_consumes_mark(monkeypatch, tmp_path):
    """STATE-MACHINE ONLY: the double outlives PREPARE_CHILD_TIMEOUT_MS; it is killed and reaped."""
    installer = Installer(monkeypatch, plan=[("sleep", 30, 0)])
    domain = state_machine_domain(tmp_path)
    started = time.monotonic()
    with pytest.raises(authority.PrepareFailed) as raised:
        domain.prepare(L, R, 200)
    elapsed = time.monotonic() - started
    assert raised.value.code == "installer_timeout" and 1.0 <= elapsed < 10
    assert domain._reservations == {1: authority.CONSUMED}
    assert installer.reaped(), "a timed-out child was left as a zombie"
    assert domain.prepare(L, R, 200).mark == 2


@POSIX_FORK
def test_cancelled_or_uncertain_prepare_consumes_mark(monkeypatch, tmp_path):
    """STATE-MACHINE ONLY: an exception between fork and status (cancellation or an uncertain wait)
    consumes the mark, reaps the child and propagates; the next prepare gets the next mark."""
    installer = Installer(monkeypatch, plan=[("sleep", 30, 0), ("sleep", 30, 0)])
    domain = state_machine_domain(tmp_path)
    errors = iter([KeyboardInterrupt(), RuntimeError("uncertain")])

    def interrupted_wait(pid, sink, timeout_ms):
        raise next(errors)

    monkeypatch.setattr(authority, "_await", interrupted_wait)
    with pytest.raises(KeyboardInterrupt):
        domain.prepare(L, R, 200)
    with pytest.raises(authority.PrepareFailed) as raised:
        domain.prepare(L, R, 200)
    assert raised.value.code == "installer_error"
    assert domain._reservations == {1: authority.CONSUMED, 2: authority.CONSUMED} and domain._handles == {}
    assert installer.reaped()
    monkeypatch.undo()
    Installer(monkeypatch)
    assert domain.prepare(L, R, 200).mark == 3


# ---------------------------------------------------------------------------------------------
# Bounded completion and readiness (H1A1R1): one deadline covers output EOF AND the exit status; an
# exit observed after it is never a success; reaping has a finite grace; namespace readiness is bounded.
# Elapsed ceilings add scheduling slack to the budgets; they are measurements, not real-time guarantees.

DEADLINE_S = authority.PREPARE_CHILD_TIMEOUT_MS / 1000
READY_S = authority.NAMESPACE_READY_TIMEOUT_MS / 1000
GRACE_S = authority.CHILD_REAP_GRACE_MS / 1000
SLACK_S = 0.75


def _unreaped() -> set[tuple[int, str]]:
    """The cleanup registry as (pid, state) pairs."""
    return {(child.pid, child.state) for child in authority._UNREAPED}


def _gone(pid: int) -> bool:
    """True when ``pid`` is no longer a child of this process (it was reaped)."""
    try:
        os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        return True
    return False


@POSIX_FORK
def test_prepare_child_eof_before_exit_is_not_completion(monkeypatch, tmp_path):
    """STATE-MACHINE ONLY: the double closes its output (EOF) and lingers 4 s before exiting 0. The
    1000 ms deadline still covers its exit status, so prepare is refused as uncertain within the
    budget; the child is killed and reaped, the mark CONSUMED and no handle exists (the 12645a7
    build blocked 4 s under the domain lock and returned PREPARED)."""
    installer = Installer(monkeypatch, plan=[("eof", 4, 0)])
    domain = state_machine_domain(tmp_path)
    started = time.monotonic()
    with pytest.raises(authority.PrepareFailed) as raised:
        domain.prepare(L, R, 200)
    elapsed = time.monotonic() - started
    assert raised.value.code == "installer_timeout" and DEADLINE_S <= elapsed < DEADLINE_S + GRACE_S + SLACK_S, elapsed
    assert domain._reservations == {1: authority.CONSUMED} and domain._handles == {}
    assert installer.reaped() and not authority._UNREAPED
    assert domain.prepare(L, R, 200).mark == 2


@POSIX_FORK
def test_activate_close_and_flush_children_share_the_completion_deadline(monkeypatch, tmp_path):
    """STATE-MACHINE ONLY: EOF-then-linger children for activate, close and the generation flush are
    each refused as uncertain within the budget; activate and close consume their marks."""
    installer = Installer(monkeypatch, plan=[0, ("eof", 4, 0), 0, ("eof", 4, 0), ("eof", 4, 0)])
    domain = state_machine_domain(tmp_path)
    first = domain.prepare(L, R, 200)
    timings = []

    def timed(operation, error, code):
        started = time.monotonic()
        with pytest.raises(error) as raised:
            operation()
        timings.append(time.monotonic() - started)
        assert raised.value.code == code

    timed(lambda: domain.activate(first), authority.InstallerFailed, "installer_timeout")
    second = domain.prepare(L, R, 200)
    timed(lambda: domain.close(second), authority.InstallerFailed, "installer_timeout")
    timed(domain.close_generation, authority.InstallerFailed, "flush_timeout")
    assert all(DEADLINE_S <= elapsed < DEADLINE_S + GRACE_S + SLACK_S for elapsed in timings), timings
    assert domain._reservations == {1: authority.CONSUMED, 2: authority.CONSUMED} and domain._closed
    assert installer.reaped() and not authority._UNREAPED


@POSIX_FORK
def test_await_counts_an_exit_only_when_observed_by_the_deadline(monkeypatch):
    """OS-PROCESS: real forked children through the real ``_spawn``/``_await``. Positive controls:
    output then exit 3 is (3, output); EOF then exit 0 inside the budget is 0. EOF then exit 0
    after the budget is None (uncertain) and the child is killed and reaped. ``_settle`` never
    reports a code for an exit observed after its deadline."""
    def run(child, timeout_ms):
        monkeypatch.setattr(authority, "_exec_child", child)
        pid, sink = authority._spawn(None, "/nonexistent/child-double", ["double"], b"")
        started = time.monotonic()
        try:
            status, output = authority._await(authority._Child(pid), sink, timeout_ms)
        finally:
            os.close(sink)
        return status, output, time.monotonic() - started, pid

    def refuses(ns_fd, path, argv, env, stdin_fd, sink_fd):
        os.write(sink_fd, b"refused")
        os._exit(3)

    def eof_then_exit(delay):
        def child(ns_fd, path, argv, env, stdin_fd, sink_fd):
            os.close(sink_fd)
            time.sleep(delay)
            os._exit(0)
        return child

    status, output, _elapsed, pid = run(refuses, 1000)
    assert (status, output) == (3, b"refused") and _gone(pid)
    status, output, elapsed, pid = run(eof_then_exit(0.05), 1000)
    assert (status, output) == (0, b"") and elapsed < DEADLINE_S and _gone(pid)
    status, output, elapsed, pid = run(eof_then_exit(0.6), 200)
    assert status is None and 0.2 <= elapsed < 0.2 + GRACE_S + SLACK_S and _gone(pid), elapsed
    assert not authority._UNREAPED

    pid = os.fork()
    if pid == 0:
        os._exit(0)
    child = authority._Child(pid)
    deadline = time.monotonic() + 10
    while True:
        reaped, code = authority._settle(child, time.monotonic_ns() - 1)  # the deadline has already passed
        assert code is None
        if reaped:
            break
        assert time.monotonic() < deadline, "the exited child was never reaped"
        time.sleep(0.001)
    assert _gone(pid)


@POSIX_FORK
def test_kill_and_reap_never_signals_a_reaped_pid(monkeypatch):
    """OS-PROCESS: once this process has reaped a child its pid may be reused, so no signal is sent."""
    pid = os.fork()
    if pid == 0:
        os._exit(0)
    os.waitpid(pid, 0)
    sent = []
    monkeypatch.setattr(authority.os, "kill", lambda *arguments: sent.append(arguments))
    assert authority._kill_and_reap(authority._Child(pid)) is True and sent == []
    assert pid not in {child.pid for child in authority._UNREAPED}


@POSIX_FORK
def test_unreapable_child_is_uncertain_tracked_and_never_waited_on(monkeypatch, tmp_path):
    """STATE-MACHINE ONLY: SIGKILL is made ineffective for the double's own pid (a stand-in for a
    child stuck in the kernel). prepare still returns within deadline + reap grace as
    installer_timeout with the mark CONSUMED; the pid is tracked as unreaped, not waited on. After
    the test kills its own child, the non-blocking sweep reaps it and clears the record."""
    installer = Installer(monkeypatch, plan=[("sleep", 30, 0)])
    domain = state_machine_domain(tmp_path)
    real_kill, ignored = os.kill, []

    def kill(pid, signum):
        if pid in installer.pids and signum == signal.SIGKILL:
            ignored.append(pid)
            return
        real_kill(pid, signum)

    monkeypatch.setattr(authority.os, "kill", kill)
    started = time.monotonic()
    with pytest.raises(authority.PrepareFailed) as raised:
        domain.prepare(L, R, 200)
    elapsed = time.monotonic() - started
    assert raised.value.code == "installer_timeout"
    assert DEADLINE_S + GRACE_S <= elapsed < DEADLINE_S + GRACE_S + SLACK_S, elapsed
    assert ignored == installer.pids == [installer.pids[0]] and _unreaped() == {(installer.pids[0], "handed_off")}
    assert domain._reservations == {1: authority.CONSUMED} and domain._handles == {}
    monkeypatch.setattr(authority.os, "kill", real_kill)
    real_kill(installer.pids[0], signal.SIGKILL)
    deadline = time.monotonic() + 10
    while authority._UNREAPED:
        assert time.monotonic() < deadline, "the sweep never reaped the killed child"
        authority._sweep_unreaped()
        time.sleep(0.001)
    assert installer.reaped() and domain.prepare(L, R, 200).mark == 2



def test_concurrent_sweeps_never_consume_a_reused_pid_status(monkeypatch):
    """STATE-MACHINE ONLY: a fake process table for one fake pid stands in for the kernel (no real
    pid is reused, waited on or signalled). Sweep B snapshots the unreaped registry and is held at its
    first waitpid; sweep A then runs. If A could reap the old child and drop it while B kept its stale
    snapshot, the pid could be reused by a new owned child whose exit status B would then consume, so
    its owner would see an unknown status. Sweeps must serialize snapshot, poll and removal: the new
    child's owner always collects its own exit code."""
    fake_pid, real_waitpid = 0x7FFF_FFF0, os.waitpid
    table = {fake_pid: 9}  # the stuck child finally died (exit 9): a status is waiting
    held, release_b = threading.Event(), threading.Event()
    calls = []

    def waitpid(pid, options):
        if pid != fake_pid:
            return real_waitpid(pid, options)
        calls.append(threading.current_thread().name)
        if len(calls) == 1:
            held.set()  # sweep B has its snapshot and is about to poll
            assert release_b.wait(10)
        if pid not in table:
            raise ChildProcessError(10, "No child processes")
        return pid, table.pop(pid) << 8

    monkeypatch.setattr(authority.os, "waitpid", waitpid)
    monkeypatch.setattr(authority, "_UNREAPED", {authority._Child(fake_pid, authority._HANDED_OFF)})
    progressed = threading.Event()
    lock = getattr(authority, "_REAP_LOCK", None)
    if lock is not None:
        signalling = SignallingLock()
        signalling.contended = progressed  # A reports "blocked on the registry lock" through the same event
        monkeypatch.setattr(authority, "_REAP_LOCK", signalling)

    def sweep_a():
        authority._sweep_unreaped()
        progressed.set()

    b = threading.Thread(target=authority._sweep_unreaped, name="sweep-b")
    b.start()
    assert held.wait(10)
    a = threading.Thread(target=sweep_a, name="sweep-a")
    a.start()
    assert progressed.wait(10)
    reused_early = fake_pid not in table and fake_pid not in {child.pid for child in authority._UNREAPED}
    if reused_early:
        table[fake_pid] = 0  # A reaped and dropped the old child; the pid now names a new owned child that exited 0
    release_b.set()
    b.join(10)
    a.join(10)
    assert not b.is_alive() and not a.is_alive()
    if not reused_early:
        table[fake_pid] = 0  # the pid is reused only after the old child is reaped and dropped
    owner = authority._settle(authority._Child(fake_pid), time.monotonic_ns() + 1_000_000_000)
    assert owner == (True, 0), f"the new child's status was consumed by a stale sweep: owner saw {owner}, waits {calls}"
    assert not reused_early and authority._UNREAPED == set() and calls == ["sweep-b", "MainThread"]


@POSIX_FORK
def test_forked_copy_gets_a_free_registry_lock_and_no_parent_children(monkeypatch):
    """OS-PROCESS: the parent holds the registry lock and has an unreaped entry when it forks; the
    copy (still refused by every owner check) starts with an unheld lock and an empty registry, so
    its sweep returns at once; the parent's lock and entry are untouched."""
    entry = authority._Child(0x7FFF_FFF1, authority._HANDED_OFF)
    monkeypatch.setattr(authority, "_UNREAPED", {entry})
    monkeypatch.setattr(authority, "_REAP_LOCK", threading.Lock())
    result_r, result_w = os.pipe()
    with authority._REAP_LOCK:
        child = os.fork()
        if child == 0:
            outcome = {}
            try:
                os.close(result_r)
                outcome["locked"] = authority._REAP_LOCK.locked()
                outcome["registry"] = sorted(child.pid for child in authority._UNREAPED)
                authority._sweep_unreaped()
                outcome["forked"] = authority._FORKED
                os.write(result_w, json.dumps(outcome).encode())
            finally:
                os._exit(0)
        os.close(result_w)
        reported, status = _child_result(child, result_r)
        assert authority._REAP_LOCK.locked() and authority._UNREAPED == {entry}
    assert reported == {"locked": False, "registry": [], "forked": True} and status == 0
    assert not authority._FORKED


# ---------------------------------------------------------------------------------------------
# Terminal cleanup ownership (H1A1R2): once its owner has reaped a child or handed it to the sweep,
# nothing the owner runs later polls or signals that pid, even after the registry entry is gone and
# the number is reused; an interrupted look is recorded uncertain instead of being retried.

class FakeChildren:
    """A model process table for ONE fake pid (no real process is forked for it, reused, waited on or
    signalled); every other pid goes to the real ``os.waitpid``/``os.kill``. ``table[pid]`` is
    ("running", generation) or ("exited", code, generation). Generation 1 is the interrupted owner's
    child and ignores the first ``stuck`` SIGKILLs (a stand-in for a child stuck in the kernel);
    generation 2 is another operation's child that reuses the pid, and SIGKILL ends it.
    ``interrupt_after_reap`` makes the next reaping waitpid raise KeyboardInterrupt after the
    table entry is gone (the async exception lands after the syscall, before the caller records it)
    and then installs ``reuse`` for the pid."""

    PID = 0x7FFF_FFF5

    def __init__(self, monkeypatch, first, stuck=1_000_000):
        self.table, self.stuck = {self.PID: first}, stuck
        self.kills, self.waits = [], []
        self.interrupt_after_reap, self.reuse = False, None
        real_waitpid, real_kill = os.waitpid, os.kill

        def waitpid(pid, options):
            if pid != self.PID:
                return real_waitpid(pid, options)
            assert options == os.WNOHANG
            self.waits.append(threading.current_thread().name)
            entry = self.table.get(pid)
            if entry is None:
                raise ChildProcessError(10, "No child processes")
            if entry[0] == "running":
                return 0, 0
            del self.table[pid]
            if self.interrupt_after_reap:
                self.interrupt_after_reap = False
                if self.reuse is not None:
                    self.table[pid] = self.reuse
                raise KeyboardInterrupt
            return pid, entry[1] << 8

        def kill(pid, signum):
            if pid != self.PID:
                return real_kill(pid, signum)
            entry = self.table.get(pid)
            self.kills.append(entry[-1] if entry else None)
            if entry and entry[0] == "running" and (entry[-1] == 2 or self.kills.count(1) > self.stuck):
                self.table[pid] = ("exited", -signum, entry[-1])

        def spawn(ns_fd, path, argv, data):
            sink_r, sink_w = os.pipe()
            os.close(sink_w)  # the output drains at once; the deadline then covers the exit status
            return self.PID, sink_r

        monkeypatch.setattr(authority.os, "waitpid", waitpid)
        monkeypatch.setattr(authority.os, "kill", kill)
        monkeypatch.setattr(authority, "_spawn", spawn)
        monkeypatch.setattr(authority, "_UNREAPED", set())
        monkeypatch.setattr(authority, "_REAP_LOCK", threading.Lock())
        monkeypatch.setattr(authority, "CHILD_REAP_GRACE_MS", 20)

    def run(self):
        authority._run(None, "/nonexistent/nft-double", ["nft"], b"", timeout_ms=30)

    def victim(self):
        """The reused pid's own owner collects its child: (True, code) or (False, None) while it runs."""
        return authority._settle(authority._Child(self.PID), time.monotonic_ns() + 200_000_000)


@pytest.mark.parametrize("swept, reuse", [(False, None), (True, None), (True, ("exited", 0, 2)), (True, ("running", 2))],
                         ids=["no-sweep-no-reuse", "swept-no-reuse", "swept-reused-exited", "swept-reused-running"])
def test_interrupted_owner_never_polls_or_signals_a_handed_off_pid(monkeypatch, swept, reuse):
    """STATE-MACHINE ONLY (the H1A1R1F section 4 rows): the owner's stuck child outlives the deadline
    and the grace and is handed to the sweep; then an async exception lands in ``_run`` after
    ``_await`` returned. Optionally the stuck child dies and another thread's sweep reaps it and drops
    the entry (so a membership check finds nothing), and optionally the pid is reused by another
    operation's child. The interrupted owner's cleanup polls and signals nothing: one SIGKILL in
    total, to its own child; a reused child keeps its status and receives no signal."""
    fake = FakeChildren(monkeypatch, ("running", 1))
    real_await, seen = authority._await, []

    def interrupted(child, sink_r, timeout_ms):
        assert real_await(child, sink_r, timeout_ms) == (None, b"")
        assert _unreaped() == {(fake.PID, "handed_off")}
        if swept:
            fake.table[fake.PID] = ("exited", 9, 1)  # the stuck child finally dies
            sweep = threading.Thread(target=authority._sweep_unreaped, name="sweep")
            sweep.start()
            sweep.join(10)
            assert fake.PID not in fake.table and not authority._UNREAPED
        if reuse is not None:
            fake.table[fake.PID] = reuse
        seen.append(len(fake.waits))
        raise KeyboardInterrupt

    monkeypatch.setattr(authority, "_await", interrupted)
    with pytest.raises(KeyboardInterrupt):
        fake.run()
    assert fake.kills == [1], fake.kills
    assert len(fake.waits) == seen[0], "the interrupted owner polled a pid it had surrendered"
    if not swept:
        assert _unreaped() == {(fake.PID, "handed_off")} and fake.table == {fake.PID: ("running", 1)}
    elif reuse == ("exited", 0, 2):
        assert fake.victim() == (True, 0)
    elif reuse == ("running", 2):
        assert fake.victim() == (False, None) and fake.table == {fake.PID: ("running", 2)}


@pytest.mark.parametrize("reuse", [("exited", 0, 2), ("running", 2)], ids=["reused-exited", "reused-running"])
def test_interrupted_owner_never_polls_or_signals_a_pid_it_reaped(monkeypatch, reuse):
    """STATE-MACHINE ONLY: the owner's ``_await`` reaps its own exited child (status 0); the async
    exception lands before ``_run`` records it and the pid is reused. The owner's cleanup neither
    polls nor signals it; the reused child's owner collects its own status."""
    fake = FakeChildren(monkeypatch, ("exited", 0, 1))
    real_await, seen = authority._await, []

    def interrupted(child, sink_r, timeout_ms):
        assert real_await(child, sink_r, timeout_ms) == (0, b"")
        fake.table[fake.PID] = reuse
        seen.append(len(fake.waits))
        raise KeyboardInterrupt

    monkeypatch.setattr(authority, "_await", interrupted)
    with pytest.raises(KeyboardInterrupt):
        fake.run()
    assert fake.kills == [] and len(fake.waits) == seen[0] and not authority._UNREAPED
    assert fake.victim() == ((True, 0) if reuse[0] == "exited" else (False, None))


@pytest.mark.parametrize("reuse", [("exited", 0, 2), ("running", 2)], ids=["reused-exited", "reused-running"])
def test_interrupted_owner_look_is_recorded_uncertain_and_never_retried(monkeypatch, reuse):
    """STATE-MACHINE ONLY: the owner's own waitpid reaps its exited child and the async exception
    lands before the result is recorded; the pid is then reused. Whether its child was reaped is
    unknown to the owner, so the cleanup records it uncertain (kept in the registry for accounting)
    and never polls or signals the pid; the sweep skips it; the reused child keeps its status."""
    fake = FakeChildren(monkeypatch, ("exited", 0, 1))
    fake.interrupt_after_reap, fake.reuse = True, reuse
    with pytest.raises(KeyboardInterrupt):
        fake.run()
    authority._sweep_unreaped()
    assert fake.kills == [] and fake.waits == ["MainThread"], (fake.kills, fake.waits)
    assert _unreaped() == {(fake.PID, "uncertain")}
    assert fake.victim() == ((True, 0) if reuse[0] == "exited" else (False, None))


def test_interrupted_sweep_look_is_recorded_uncertain_and_never_retried(monkeypatch):
    """STATE-MACHINE ONLY: a sweep's waitpid reaps a handed-off child and the async exception lands
    before the removal; the pid is reused by another operation's child that exits 0. The next sweep
    records the entry uncertain and does not poll it; the reused child's owner gets status 0."""
    fake = FakeChildren(monkeypatch, ("exited", 9, 1))
    fake.interrupt_after_reap, fake.reuse = True, ("exited", 0, 2)
    authority._UNREAPED.add(authority._Child(fake.PID, authority._HANDED_OFF))
    with pytest.raises(KeyboardInterrupt):
        authority._sweep_unreaped()
    assert not authority._REAP_LOCK.locked()
    authority._sweep_unreaped()
    assert fake.waits == ["MainThread"] and fake.kills == [] and _unreaped() == {(fake.PID, "uncertain")}
    assert fake.victim() == (True, 0)


@pytest.mark.parametrize("stuck", [1, 2], ids=["dies-on-second-kill", "stays-stuck"])
def test_interrupt_before_hand_off_still_finishes_bounded_cleanup(monkeypatch, stuck):
    """STATE-MACHINE ONLY: the async exception lands in the reap grace after the first SIGKILL, before
    any reap or hand-off. The owner still holds its child (an unreaped pid cannot have been reused),
    so its cleanup runs once more within one more finite grace: SIGKILL to its own child, then reaped
    (dies-on-second-kill) or handed to the sweep (stays-stuck). Nothing is lost from the accounting."""
    fake = FakeChildren(monkeypatch, ("running", 1), stuck=stuck)
    real_sleep, fired = time.sleep, []

    def sleep(seconds):
        if fake.kills and not fired:
            fired.append(seconds)
            raise KeyboardInterrupt
        real_sleep(seconds)

    monkeypatch.setattr(authority.time, "sleep", sleep)
    started = time.monotonic()
    with pytest.raises(KeyboardInterrupt):
        fake.run()
    elapsed = time.monotonic() - started
    assert fired and fake.kills == [1, 1] and elapsed < 0.03 + 2 * 0.02 + SLACK_S, (fake.kills, elapsed)
    if stuck == 1:
        assert fake.table == {} and not authority._UNREAPED
    else:
        assert _unreaped() == {(fake.PID, "handed_off")} and fake.table == {fake.PID: ("running", 1)}


def test_interrupted_hand_off_is_completed_by_the_owner(monkeypatch):
    """STATE-MACHINE ONLY: the async exception lands inside the hand-off itself, after the registry
    insert. The owner still holds the child (only the sweep's own entries are polled by the sweep),
    so its cleanup re-runs on its own unreaped child and completes the hand-off exactly once."""
    fake = FakeChildren(monkeypatch, ("running", 1))

    class InterruptedAdd(set):
        fired = False

        def add(self, item):
            super().add(item)
            if not InterruptedAdd.fired:
                InterruptedAdd.fired = True
                raise KeyboardInterrupt

    monkeypatch.setattr(authority, "_UNREAPED", InterruptedAdd())
    with pytest.raises(KeyboardInterrupt):
        fake.run()
    assert InterruptedAdd.fired and fake.kills == [1, 1] and _unreaped() == {(fake.PID, "handed_off")}
    fake.table[fake.PID] = ("exited", 9, 1)
    authority._sweep_unreaped()
    assert not authority._UNREAPED and fake.table == {}


@POSIX_FORK
def test_interrupted_owner_never_resignals_its_handed_off_real_child(monkeypatch, tmp_path):
    """OS-PROCESS: a real installer child whose SIGKILL is made ineffective (stuck stand-in) is handed
    to the sweep; an async exception then lands after ``_await`` returned. The owner sends no second
    signal and no further poll; the mark is CONSUMED; once the test kills its own child, the sweep
    reaps it and clears the record."""
    installer = Installer(monkeypatch, plan=[("sleep", 30, 0)])
    domain = state_machine_domain(tmp_path)
    real_kill, real_await, signalled = os.kill, authority._await, []

    def kill(pid, signum):
        if pid in installer.pids and signum == signal.SIGKILL:
            signalled.append(pid)
            return
        real_kill(pid, signum)

    def interrupted(child, sink_r, timeout_ms):
        real_await(child, sink_r, timeout_ms)
        raise KeyboardInterrupt

    monkeypatch.setattr(authority.os, "kill", kill)
    monkeypatch.setattr(authority, "_await", interrupted)
    try:
        with pytest.raises(KeyboardInterrupt):
            domain.prepare(L, R, 200)
        assert signalled == installer.pids == [installer.pids[0]] and _unreaped() == {(installer.pids[0], "handed_off")}
        assert domain._reservations == {1: authority.CONSUMED} and domain._handles == {}
    finally:
        monkeypatch.setattr(authority.os, "kill", real_kill)
        real_kill(installer.pids[0], signal.SIGKILL)  # the test's own child: handed off, never reaped yet
        deadline = time.monotonic() + 10
        while authority._UNREAPED:
            assert time.monotonic() < deadline, "the sweep never reaped the killed child"
            authority._sweep_unreaped()
            time.sleep(0.001)
    assert installer.reaped()


def _owned_namespace_helper(monkeypatch, unshare):
    """The real ``_Namespace`` fork, pipes, deadline and cleanup; only the helper's ``unshare`` is
    replaced (inherited by the fork), so no namespace is created and no host network is touched.
    Returns the list of pids the parent forked (this test's own children)."""
    monkeypatch.setattr(authority.sys, "platform", "linux")
    monkeypatch.setattr(authority.os, "unshare", unshare, raising=False)
    if not hasattr(os, "setns"):
        monkeypatch.setattr(authority.os, "setns", lambda *arguments: None, raising=False)
    forked, real_fork = [], os.fork

    def fork():
        pid = real_fork()
        if pid:
            forked.append(pid)
        return pid

    monkeypatch.setattr(authority.os, "fork", fork)
    monkeypatch.setattr(authority, "NFT_PATH", "/nonexistent/nft-double")
    return forked


@POSIX_FORK
def test_silent_namespace_helper_times_out_and_is_killed(monkeypatch):
    """OS-PROCESS: ``LeaseDomain.create`` forks the real helper, whose unshare never returns (a
    controlled stand-in for a deadlocked helper). create refuses with namespace_ready_timeout within
    NAMESPACE_READY_TIMEOUT_MS + reap grace; the helper is killed and reaped; no domain exists (the
    12645a7 build blocked here until something outside killed the helper)."""
    forked = _owned_namespace_helper(monkeypatch, lambda flags: time.sleep(30))
    started = time.monotonic()
    with pytest.raises(authority.DomainUnavailable) as raised:
        authority.LeaseDomain.create()
    elapsed = time.monotonic() - started
    assert str(raised.value) == "namespace_ready_timeout" and READY_S <= elapsed < READY_S + GRACE_S + SLACK_S, elapsed
    assert len(forked) == 1 and _gone(forked[0]) and not authority._UNREAPED


@POSIX_FORK
def test_namespace_helper_early_failure_and_ready_controls(monkeypatch):
    """OS-PROCESS positive controls on the same path: a helper whose unshare is refused exits at once
    (EOF, unshare_failed); a helper that reports ready proceeds past readiness to the identity check,
    which refuses because it never left this namespace (no /proc off Linux), and the helper blocked
    on the hold pipe is killed and reaped. Neither waits for the readiness budget."""
    def refused(flags):
        raise PermissionError(1, "Operation not permitted")

    for unshare, expected in ((refused, {"DomainUnavailable:unshare_failed"}),
                              (lambda flags: None, {"DomainUnavailable:namespace_not_new", "FileNotFoundError"})):
        forked = _owned_namespace_helper(monkeypatch, unshare)
        started = time.monotonic()
        with pytest.raises(Exception) as raised:
            authority.LeaseDomain.create()
        elapsed = time.monotonic() - started
        outcome = f"{type(raised.value).__name__}" + (f":{raised.value}" if isinstance(raised.value, authority.DomainUnavailable) else "")
        assert outcome in expected and elapsed < GRACE_S + SLACK_S, (outcome, elapsed)
        assert len(forked) == 1 and _gone(forked[0]) and not authority._UNREAPED
        monkeypatch.undo()


@POSIX_FORK
def test_interrupted_helper_release_is_finished_not_abandoned(monkeypatch):
    """OS-PROCESS: a real owned helper blocked on its hold pipe, as ``_Namespace`` leaves it (it then
    lingers after EOF, so only SIGKILL ends it). The first release closes the pipe and an async
    exception lands in its grace wait, before any reap or hand-off. The next ``release(kill=True)``,
    as ``create`` and ``__init__`` cleanup call it, still kills and reaps the helper within the grace;
    a further release returns the recorded result without looking."""
    hold_r, hold_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(hold_w)
            os.read(hold_r, 1)
            time.sleep(30)
        finally:
            os._exit(0)
    os.close(hold_r)
    try:
        namespace = object.__new__(authority._Namespace)
        namespace.pid, namespace.fd, namespace._hold_w = pid, None, hold_w
        namespace._child = authority._Child(pid)
        real_sleep = time.sleep

        def sleep(seconds):
            monkeypatch.setattr(authority.time, "sleep", real_sleep)
            raise KeyboardInterrupt

        monkeypatch.setattr(authority.time, "sleep", sleep)
        with pytest.raises(KeyboardInterrupt):
            namespace.release()
        assert namespace._hold_w is None
        started = time.monotonic()
        assert namespace.release(kill=True) is True and time.monotonic() - started < GRACE_S + SLACK_S
        assert _gone(pid) and not authority._UNREAPED
        assert namespace.release() is True
    finally:
        if not _gone(pid):
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)


@pytest.mark.parametrize("outcome", ["unreaped", "interrupted"])
def test_create_finishes_helper_cleanup_and_closes_the_descriptor(monkeypatch, tmp_path, outcome):
    """STATE-MACHINE ONLY: a stand-in for ``_Namespace`` (a real descriptor on an owned temp file; no
    fork). A helper whose release cannot be reaped refuses with namespace_helper_unreaped; a release
    interrupted by an async exception propagates only after ``create`` asked for the finishing
    ``release(kill=True)``. Either way the descriptor is closed and no domain exists."""
    calls, helpers = [], []

    class Helper:
        def __init__(self):
            self.fd = os.open(tmp_path / "ns-stand-in", os.O_RDONLY | os.O_CREAT | os.O_CLOEXEC, 0o600)
            info = os.fstat(self.fd)
            self.identity, self.pid = (info.st_dev, info.st_ino), 0x7FFF_FFF6
            helpers.append(self)

        def release(self, *, kill=False):
            calls.append(kill)
            if outcome == "interrupted" and not kill:
                raise KeyboardInterrupt
            return outcome != "unreaped"

    monkeypatch.setattr(authority, "_Namespace", Helper)
    monkeypatch.setattr(authority, "NFT_PATH", "/nonexistent/nft-double")
    if outcome == "unreaped":
        with pytest.raises(authority.DomainUnavailable) as raised:
            authority.LeaseDomain.create()
        assert str(raised.value) == "namespace_helper_unreaped"
    else:
        with pytest.raises(KeyboardInterrupt):
            authority.LeaseDomain.create()
        assert calls == [False, True]
    with pytest.raises(OSError):
        os.fstat(helpers[0].fd)


def test_read_ready_is_bounded_and_reports_eof():
    """OS-PROCESS: nothing written -> None after the budget; a byte inside it -> the byte; EOF -> b""."""
    read_fd, write_fd = os.pipe()
    try:
        started = time.monotonic()
        assert authority._read_ready(read_fd, 100) is None and 0.1 <= time.monotonic() - started < 0.1 + SLACK_S
        os.write(write_fd, b"u")
        assert authority._read_ready(read_fd, 1000) == b"u"
        os.close(write_fd)
        write_fd = None
        assert authority._read_ready(read_fd, 1000) == b""
    finally:
        os.close(read_fd)
        if write_fd is not None:
            os.close(write_fd)


def test_child_waits_are_deadline_polled_never_blocking():
    """Static: every waitpid in the domain module is WNOHANG; no blocking reaper remains; the
    namespace readiness byte is read only through the bounded reader."""
    source = AUTHORITY_FILE.read_text(encoding="utf-8")
    tree = ast.parse(source)
    functions = {node.name: node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
    waits = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and ast.unparse(node.func) == "os.waitpid"]
    assert len(waits) == 1 and [ast.unparse(argument) for argument in waits[0].args] == ["child.pid", "os.WNOHANG"]
    assert "_reap" not in functions and "time.sleep" not in ast.get_source_segment(source, functions["_await"])
    namespace = next(node for node in ast.walk(tree) if isinstance(node, ast.ClassDef) and node.name == "_Namespace")
    init = ast.get_source_segment(source, next(node for node in namespace.body
                                               if isinstance(node, ast.FunctionDef) and node.name == "__init__"))
    assert "_read_ready(ready_r, NAMESPACE_READY_TIMEOUT_MS)" in init and "os.read(ready_r" not in init


@POSIX_FORK
def test_activate_requires_original_handle_identity_and_writes_no_lifetime(monkeypatch, tmp_path):
    """STATE-MACHINE ONLY: copies, replacements, other domains' and hand-built handles are refused
    before any child; the one activation batch carries no lifetime; a second activate is refused."""
    installer = Installer(monkeypatch)
    domain, other = state_machine_domain(tmp_path), state_machine_domain(tmp_path)
    handle, foreign = domain.prepare(L, R, 200), other.prepare(L, R, 200)
    launched = len(installer.batches)
    forged = [copy.copy(handle), pickle.loads(pickle.dumps(handle)), foreign]
    with pytest.raises(authority.ForeignHandle):
        dataclasses.replace(handle, mark=handle.mark)
    with pytest.raises(authority.ForeignHandle):
        authority.PreparedKey(*[getattr(handle, f.name) for f in dataclasses.fields(handle) if f.name != "_seal"], _seal=object())
    for candidate in forged + ["handle", handle.mark, None]:
        with pytest.raises(authority.ForeignHandle):
            domain.activate(candidate)
    assert len(installer.batches) == launched
    domain.activate(handle)
    activation = installer.batches[-1].decode()
    assert "destroy element" in activation and "add element" in activation and "timeout" not in activation
    with pytest.raises(authority.HandleState):
        domain.activate(handle)
    assert len(installer.batches) == launched + 1 and installer.reaped()


@POSIX_FORK
def test_stale_handle_cannot_reprepare_or_mutate(monkeypatch, tmp_path):
    """STATE-MACHINE ONLY: a handle has no operations and no mutable field; after close it is refused."""
    Installer(monkeypatch)
    domain = state_machine_domain(tmp_path)
    handle = domain.prepare(L, R, 200)
    assert not [name for name in dir(handle) if not name.startswith("_") and callable(getattr(handle, name))]
    for field in dataclasses.fields(handle):
        with pytest.raises(dataclasses.FrozenInstanceError):
            setattr(handle, field.name, 1)
    with pytest.raises(ValueError):
        domain.prepare(handle, R, 200)
    domain.close(handle)
    with pytest.raises(authority.HandleState):
        domain.activate(handle)


def _child_result(child: int, result_r: int, timeout: float = 20.0) -> tuple[dict, int]:
    ready, _w, _x = select.select([result_r], [], [], timeout)
    reported = json.loads(os.read(result_r, 4096) or b"{}") if ready else {}
    os.close(result_r)
    if not ready:
        os.kill(child, 9)
    _pid, status = os.waitpid(child, 0)
    return reported, os.waitstatus_to_exitcode(status)


@POSIX_FORK
def test_forked_child_cannot_prepare_activate_or_allocate(monkeypatch, tmp_path):
    """STATE-MACHINE ONLY: a real os.fork() copy refuses prepare, activate(parent_handle), the
    counter, close, close_generation, ns_fd, create and the self-test, each before taking the
    inherited (held) lock; the parent's counter is unchanged and its prepare still works."""
    Installer(monkeypatch)
    domain = state_machine_domain(tmp_path)
    parent_handle = domain.prepare(L, R, 200)
    result_r, result_w = os.pipe()
    domain._lock.acquire()  # the copy inherits a held lock
    child = os.fork()
    if child == 0:
        bits = 0
        try:
            os.close(result_r)
            operations = (lambda: domain.prepare(L, R, 200), lambda: domain.activate(parent_handle),
                          lambda: domain._counter.next(), lambda: domain.close(parent_handle),
                          lambda: domain.close_generation(), lambda: domain.ns_fd,
                          lambda: authority.LeaseDomain.create(), lambda: authority.generation_self_test(domain))
            for bit, operation in enumerate(operations):
                try:
                    operation()
                except authority.ForeignProcess:
                    bits |= 1 << bit
                except BaseException:  # noqa: BLE001
                    pass
            os.write(result_w, json.dumps({"bits": bits}).encode())
        finally:
            os._exit(bits & 0x7F)
    domain._lock.release()
    os.close(result_w)
    reported, status = _child_result(child, result_r)
    assert reported == {"bits": 0xFF} and status == 0x7F
    assert domain._counter._next == 2 and domain.prepare(L, R, 200).mark == 2


@POSIX_FORK
def test_inherited_registry_membership_is_not_ownership(monkeypatch, tmp_path):
    """STATE-MACHINE ONLY: the forked copy sees the parent's handle in the registry it inherited,
    by value and by identity, and is still refused."""
    Installer(monkeypatch)
    domain = state_machine_domain(tmp_path)
    parent_handle = domain.prepare(L, R, 200)
    result_r, result_w = os.pipe()
    child = os.fork()
    if child == 0:
        outcome = {}
        try:
            os.close(result_r)
            outcome["member"] = parent_handle in domain._handles.values()
            outcome["identical"] = domain._handles.get(parent_handle.mark) is parent_handle
            try:
                domain.activate(parent_handle)
                outcome["activate"] = "accepted"
            except authority.ForeignProcess:
                outcome["activate"] = "foreign_process"
            os.write(result_w, json.dumps(outcome).encode())
        finally:
            os._exit(0)
    os.close(result_w)
    reported, status = _child_result(child, result_r)
    assert reported == {"member": True, "identical": True, "activate": "foreign_process"} and status == 0
    assert domain._reservations[parent_handle.mark] == authority.PREPARED


def test_installer_child_path_is_exec_only_with_no_override():
    source = AUTHORITY_FILE.read_text(encoding="utf-8")
    tree = ast.parse(source)
    functions = {node.name: node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}

    def calls(node):
        names = set()
        for call in ast.walk(node):
            if isinstance(call, ast.Call):
                func = call.func
                names.add(func.id if isinstance(func, ast.Name) else f"{getattr(func.value, 'id', '?')}.{func.attr}")
        return names

    child_branch = [node for node in ast.walk(functions["_spawn"]) if isinstance(node, ast.If)
                    and ast.unparse(node.test) == "pid == 0"]
    assert len(child_branch) == 1
    assert calls(child_branch[0]) == {"_exec_child", "os._exit"}
    assert calls(functions["_exec_child"]) == {"os.setns", "os.dup2", "os.execve"}
    assert [arg.arg for arg in functions["_assert_owner"].args.args] == ["self"]
    assert not functions["_assert_owner"].args.kwonlyargs and functions["_assert_owner"].args.vararg is None
    owner = ast.get_source_segment(source, functions["_assert_owner"])
    assert "environ" not in owner and "getenv" not in owner
    for forbidden in ("allow_", "_for_tests", "os.environ", "getenv", "multiprocessing", "pickle"):
        assert forbidden not in source, forbidden
    assert "subprocess" not in ast.get_source_segment(source, functions["_spawn"])
    assert "subprocess" not in ast.get_source_segment(source, functions["_run"])
    assert "register_at_fork(after_in_child=_remint)" in source


def test_counter_private_refuses_at_32_bit_bound_without_wrapping():
    counter = authority._MarkCounter(start=0xFFFF_FFFE)
    assert [counter.next(), counter.next()] == [0xFFFF_FFFE, 0xFFFF_FFFF]
    for _attempt in range(3):
        with pytest.raises(authority.DomainExhausted):
            counter.next()
    for start in (0, -1, 0x1_0000_0000, True, 1.0):
        with pytest.raises(ValueError):
            authority._MarkCounter(start=start)
    plain = authority._MarkCounter()
    assert [plain.next() for _ in range(5)] == [1, 2, 3, 4, 5]
    assert not [name for name in dir(plain) if not name.startswith("_") and name != "next"]


# ---------------------------------------------------------------------------------------------
# Concurrency (Astra disposition 2): deterministic barrier tests, no sleeps deciding an order.

@POSIX_FORK
def test_concurrent_second_activate_cannot_pass_the_same_prepared_state(monkeypatch, tmp_path):
    """STATE-MACHINE ONLY: the first activation's child is held at a barrier; the second activate
    is shown to be waiting on the domain lock; when released exactly one activation was launched."""
    barrier = Barrier()
    installer = Installer(monkeypatch, plan=[0, ("wait", barrier.read_fd, 0)])
    domain = state_machine_domain(tmp_path)
    domain._lock = SignallingLock()
    handle = domain.prepare(L, R, 200)
    results: dict = {}
    first = _thread(lambda: domain.activate(handle), results, "first")
    _wait_spawned(installer, 2)
    second = _thread(lambda: domain.activate(handle), results, "second")
    assert domain._lock.contended.wait(10)
    barrier.release()
    first.join(10)
    second.join(10)
    barrier.close()
    assert results["first"] == ("ok", None)
    assert results["second"][0] == "raised" and type(results["second"][1]) is authority.HandleState
    assert len(installer.batches) == 2 and domain._reservations[handle.mark] == authority.ACTIVATED


@POSIX_FORK
def test_close_generation_racing_prepare_never_publishes_a_usable_handle(monkeypatch, tmp_path):
    """STATE-MACHINE ONLY: close_generation arrives while a prepare child is in flight. The prepare
    completes first (serialized), then close_generation consumes its handle; nothing reopens."""
    barrier = Barrier()
    installer = Installer(monkeypatch, plan=[("wait", barrier.read_fd, 0), 0])
    domain = state_machine_domain(tmp_path)
    domain._lock = SignallingLock()
    results: dict = {}
    preparing = _thread(lambda: domain.prepare(L, R, 200), results, "prepare")
    _wait_spawned(installer, 1)
    closing = _thread(domain.close_generation, results, "close")
    assert domain._lock.contended.wait(10)
    barrier.release()
    preparing.join(10)
    closing.join(10)
    barrier.close()
    status, handle = results["prepare"]
    assert status == "ok" and results["close"] == ("ok", None)
    assert installer.batches == [authority._render_prepare(L, R, 1, 200), authority._render_flush()]
    assert domain._reservations == {1: authority.CONSUMED} and domain._closed
    for operation in (lambda: domain.activate(handle), lambda: domain.prepare(L, R, 200), domain.close_generation,
                      lambda: domain.close(handle), lambda: domain.ns_fd):
        with pytest.raises(authority.DomainClosed):
            operation()
    assert domain._counter._next == 2 and len(installer.batches) == 2


@POSIX_FORK
def test_prepare_racing_close_generation_is_refused_without_reserving(monkeypatch, tmp_path):
    """STATE-MACHINE ONLY: a prepare that arrives while the flush child is in flight waits, then is
    refused without reserving a mark or launching a child."""
    barrier = Barrier()
    installer = Installer(monkeypatch, plan=[("wait", barrier.read_fd, 0)])
    domain = state_machine_domain(tmp_path)
    domain._lock = SignallingLock()
    results: dict = {}
    closing = _thread(domain.close_generation, results, "close")
    _wait_spawned(installer, 1)
    preparing = _thread(lambda: domain.prepare(L, R, 200), results, "prepare")
    assert domain._lock.contended.wait(10)
    barrier.release()
    closing.join(10)
    preparing.join(10)
    barrier.close()
    assert results["close"] == ("ok", None)
    assert results["prepare"][0] == "raised" and type(results["prepare"][1]) is authority.DomainClosed
    assert installer.batches == [authority._render_flush()] and domain._reservations == {} and domain._counter._next == 1


@POSIX_FORK
def test_concurrent_prepares_reserve_distinct_marks_and_a_failure_never_frees_one(monkeypatch, tmp_path):
    """STATE-MACHINE ONLY: two prepares race; the first child fails while the second waits; the
    marks are 1 (CONSUMED) and 2 (PREPARED) and 1 is never handed out again."""
    barrier = Barrier()
    installer = Installer(monkeypatch, plan=[("wait", barrier.read_fd, 1), 0, 0])
    domain = state_machine_domain(tmp_path)
    domain._lock = SignallingLock()
    results: dict = {}
    first = _thread(lambda: domain.prepare(L, R, 200), results, "first")
    _wait_spawned(installer, 1)
    second = _thread(lambda: domain.prepare(L, R, 200), results, "second")
    assert domain._lock.contended.wait(10)
    barrier.release()
    first.join(10)
    second.join(10)
    barrier.close()
    assert results["first"][0] == "raised" and type(results["first"][1]) is authority.PrepareFailed
    assert results["second"][0] == "ok" and results["second"][1].mark == 2
    assert domain._reservations == {1: authority.CONSUMED, 2: authority.PREPARED}
    assert domain.prepare(L, R, 200).mark == 3


@POSIX_FORK
def test_close_racing_activate_leaves_a_terminal_state(monkeypatch, tmp_path):
    """STATE-MACHINE ONLY: close waits for an in-flight activation, then closes it; no re-activation."""
    barrier = Barrier()
    installer = Installer(monkeypatch, plan=[0, ("wait", barrier.read_fd, 0), 0])
    domain = state_machine_domain(tmp_path)
    domain._lock = SignallingLock()
    handle = domain.prepare(L, R, 200)
    results: dict = {}
    activating = _thread(lambda: domain.activate(handle), results, "activate")
    _wait_spawned(installer, 2)
    closing = _thread(lambda: domain.close(handle), results, "close")
    assert domain._lock.contended.wait(10)
    barrier.release()
    activating.join(10)
    closing.join(10)
    barrier.close()
    assert results == {"activate": ("ok", None), "close": ("ok", None)}
    assert domain._reservations[handle.mark] == authority.CLOSED
    with pytest.raises(authority.HandleState):
        domain.activate(handle)
    assert installer.batches[-1] == authority._render_close(L, R)


def test_fresh_interpreter_is_not_a_forked_copy():
    """A new generation after a fork needs a fresh interpreter (execve): there the fork marker is
    clear and creation is limited only by OS capability, never refused as a forked copy."""
    program = ("import importlib.util, sys\n"
               "spec = importlib.util.spec_from_file_location('fresh_authority', sys.argv[1])\n"
               "m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)\n"
               "try:\n"
               "    m.LeaseDomain.create(); outcome = 'created'\n"
               "except Exception as error:\n"
               "    outcome = type(error).__name__\n"
               "print(m._FORKED, outcome)\n")
    completed = subprocess.run([sys.executable, "-I", "-c", program, str(AUTHORITY_FILE)], capture_output=True, text=True,
                               timeout=60)
    forked, outcome = completed.stdout.split()
    assert forked == "False" and outcome in {"created", "DomainUnavailable"}, completed.stdout


# ---------------------------------------------------------------------------------------------
# Peer rule and startup refusals.

def _config(profile=host_authority.PeerProfile.EXTERNAL_PIDNS, peer_uid=0, path="/srv/heel/authority.sock"):
    return host_authority.HostAuthorityConfig(path, peer_uid, profile)


def test_admit_peer_external_pidns_requires_pid_zero_and_configured_uid():
    """STATE-MACHINE ONLY: explicit (pid, uid) inputs; the Linux T1 case reads real SO_PEERCRED."""
    config = _config()
    assert host_authority.admit_peer(config, 0, 0, 65534)
    assert not host_authority.admit_peer(config, 1, 0, 65534)
    assert not host_authority.admit_peer(config, 4242, 0, 65534)
    assert not host_authority.admit_peer(config, 0, 10001, 65534)
    assert not host_authority.admit_peer(_config(peer_uid=7), 0, 0, 65534)
    assert host_authority.admit_peer(_config(peer_uid=7), 0, 7, 65534)


def test_admit_peer_shared_pidns_requires_nonzero_pid():
    """STATE-MACHINE ONLY: explicit (pid, uid) inputs; the Linux T2 case reads real SO_PEERCRED."""
    config = _config(host_authority.PeerProfile.SHARED_PIDNS)
    assert host_authority.admit_peer(config, 4242, 0, 65534)
    assert not host_authority.admit_peer(config, 0, 0, 65534)
    assert not host_authority.admit_peer(config, 4242, 1, 65534)


def test_admit_peer_refuses_overflowuid_even_when_configured():
    """STATE-MACHINE ONLY: an unmappable peer is overflowuid; it is never admitted."""
    for profile, pid in ((host_authority.PeerProfile.EXTERNAL_PIDNS, 0), (host_authority.PeerProfile.SHARED_PIDNS, 9)):
        assert not host_authority.admit_peer(_config(profile, peer_uid=65534), pid, 65534, 65534)
    bogus = host_authority.HostAuthorityConfig("/x", 0, "external-pidns")
    assert not host_authority.admit_peer(bogus, 0, 0, 65534)


def _proc_files(tmp_path: Path, uid_map: str, overflow: str = "65534\n") -> dict:
    (tmp_path / "uid_map").write_text(uid_map)
    (tmp_path / "overflowuid").write_text(overflow)
    return {"uid_map_path": str(tmp_path / "uid_map"), "overflowuid_path": str(tmp_path / "overflowuid")}


def test_check_startup_refuses_non_identity_uid_map(tmp_path):
    """STATE-MACHINE ONLY: fixture /proc files; the Linux T3 case uses a real user namespace."""
    for uid_map in ("         0      10001          1\n", "0 0 4294967294\n", "0 0 4294967295\n1 1 1\n", ""):
        with pytest.raises(host_authority.HostAuthorityConfigurationError) as raised:
            host_authority.check_startup(_config(), **_proc_files(tmp_path, uid_map))
        assert raised.value.code == "user_namespace_translation_unsupported", uid_map
    with pytest.raises(host_authority.HostAuthorityConfigurationError) as raised:
        host_authority.check_startup(_config(), uid_map_path=str(tmp_path / "missing"))
    assert raised.value.code == "uid_map_unreadable"
    with pytest.raises(host_authority.HostAuthorityConfigurationError) as raised:
        host_authority.check_startup(_config(peer_uid=65534), **_proc_files(tmp_path, "0 0 4294967295\n"))
    assert raised.value.code == "peer_uid_is_overflowuid"
    with pytest.raises(host_authority.HostAuthorityConfigurationError) as raised:
        host_authority.check_startup(_config(), **_proc_files(tmp_path, "0 0 4294967295\n", "nobody\n"))
    assert raised.value.code == "overflowuid_unreadable"
    if not sys.platform.startswith("linux"):
        with pytest.raises(host_authority.HostAuthorityConfigurationError) as raised:
            host_authority.check_startup(_config(), **_proc_files(tmp_path, "         0          0 4294967295\n"))
        assert raised.value.code == "platform_unsupported"


def test_check_startup_refuses_unknown_profile_and_missing_peer_uid(tmp_path):
    files = _proc_files(tmp_path, "0 0 4294967295\n")
    cases = {"profile_invalid": [host_authority.HostAuthorityConfig("/x/a.sock", 0, "external-pidns"),
                                 host_authority.HostAuthorityConfig("/x/a.sock", 0, None), "not a config"],
             "peer_uid_invalid": [_config(peer_uid=None), _config(peer_uid="0"), _config(peer_uid=True),
                                  _config(peer_uid=-1), _config(peer_uid=2 ** 32 - 1)],
             "socket_path_invalid": [_config(path="relative.sock"), _config(path=None), _config(path="/x/\0.sock")]}
    for code, configs in cases.items():
        for config in configs:
            with pytest.raises(host_authority.HostAuthorityConfigurationError) as raised:
                host_authority.check_startup(config, **files)
            assert raised.value.code == code, config
    assert {profile.value for profile in host_authority.PeerProfile} == {"external-pidns", "shared-pidns"}
    with pytest.raises(ValueError):
        host_authority.PeerProfile("host-pidns")


# ---------------------------------------------------------------------------------------------
# Codec.

REQUEST = {"schema_version": "heel.host-authority-request.v1", "host_boot_epoch": "boot-0001", "slot_id": "slot-a",
           "sequence": 1, "request_nonce": "0123456789abcdef0123456789abcdef", "generation_id": "fedcba9876543210fedcba9876543210",
           "workspace_id": "ws_0123456789abcdef", "project_id": "prj_" + "1" * 32, "environment_id": "env_" + "2" * 32,
           "verification_record_digest": "3" * 64, "runner_id": "runner-1", "runner_key_id": "key_1",
           "binding_id": "rcb_" + "4" * 32, "binding_digest": "5" * 64, "run_id": "crun_" + "6" * 32, "grant_id": "grant-1",
           "grant_digest": "7" * 64, "kill_switch_generation": 0, "monotonic_ms": 12345}
H1D_FIELDS = {"schema_version", "host_boot_epoch", "slot_id", "sequence", "request_nonce", "workspace_id", "project_id",
              "environment_id", "verification_record_digest", "runner_id", "runner_key_id", "binding_id", "binding_digest",
              "run_id", "grant_id", "grant_digest", "kill_switch_generation"}


def _encode(document) -> bytes:
    return host_authority.canonical(document)


def test_request_schema_is_closed_and_bounded():
    assert host_authority.validate_request(_encode(REQUEST)) == REQUEST
    assert host_authority.REQUEST_FIELDS == H1D_FIELDS | {"generation_id", "monotonic_ms"}
    mutations = [{"extra": 1}, {"schema_version": "heel.host-authority-request.v2"}, {"workspace_id": "ws_0123"},
                 {"project_id": "prj_" + "G" * 32}, {"run_id": "run_" + "6" * 32}, {"binding_digest": "5" * 63},
                 {"slot_id": "Slot-A"}, {"host_boot_epoch": "short"}, {"kill_switch_generation": -1},
                 {"kill_switch_generation": 1.0}, {"runner_id": "r" * 129}, {"verification_record_digest": "A" * 64}]
    for mutation in mutations:
        assert host_authority.validate_request(_encode({**REQUEST, **mutation})) is None, mutation
    missing = dict(REQUEST)
    del missing["grant_digest"]
    assert host_authority.validate_request(_encode(missing)) is None
    body = _encode(REQUEST)
    assert host_authority.validate_request(json.dumps(REQUEST).encode()) is None  # not canonical
    assert host_authority.validate_request(body.replace(b'"sequence":1', b'"sequence":1,"sequence":1')) is None
    assert host_authority.validate_request(body[:-1] + b',"pad":"' + b"x" * 2048 + b'"}') is None
    assert host_authority.validate_request(b"") is None and host_authority.validate_request(b"[]") is None
    assert host_authority.validate_request(body.replace(b'"monotonic_ms":12345', b'"monotonic_ms":NaN')) is None
    assert len(body) <= host_authority.MAX_REQUEST_BYTES


def test_request_schema_requires_generation_id_sequence_and_monotonic_ms():
    for name in ("generation_id", "sequence", "monotonic_ms"):
        without = {key: value for key, value in REQUEST.items() if key != name}
        assert host_authority.validate_request(_encode(without)) is None, name
    for mutation in ({"generation_id": "F" * 32}, {"generation_id": "f" * 31}, {"generation_id": 1},
                     {"sequence": 0}, {"sequence": 2 ** 53 + 1}, {"sequence": True}, {"sequence": "1"},
                     {"monotonic_ms": -1}, {"monotonic_ms": 2 ** 53 + 1}, {"monotonic_ms": 1.5}):
        assert host_authority.validate_request(_encode({**REQUEST, **mutation})) is None, mutation
    for mutation in ({"sequence": 2 ** 53}, {"monotonic_ms": 0}, {"monotonic_ms": 2 ** 53}):
        assert host_authority.validate_request(_encode({**REQUEST, **mutation})) is not None, mutation


H1D_REASONS = ("none, workspace_unknown, project_unknown, no_active_run, multiple_active_runs, run_not_active, "
               "stop_requested, grant_not_claimed, grant_expired, invalid_grant, proof_expired, proof_revoked, "
               "verification_digest_replaced, runner_revoked, key_revoked, binding_inactive, binding_expired, "
               "kill_switch_active, kill_switch_generation_changed, tuple_mismatch, malformed_request, cp_draining")


def _inactive(reason="no_active_run", request=REQUEST):
    return {"schema_version": host_authority.RESPONSE_SCHEMA, "decision": "inactive", "reason": reason,
            "sequence": request["sequence"], "request_digest": host_authority.request_digest(request),
            "server_time_ms": 1_700_000_000_000, "kill_switch_generation": 0}


def test_reason_set_includes_replayed_sequence_and_clock_gap_and_nothing_else_new():
    assert set(host_authority.REASONS) - set(H1D_REASONS.split(", ")) == {"replayed_sequence", "clock_gap"}
    assert set(H1D_REASONS.split(", ")) <= set(host_authority.REASONS) and len(set(host_authority.REASONS)) == 24
    for reason in ("replayed_sequence", "clock_gap", "no_active_run"):
        assert host_authority.validate_response(_inactive(reason), REQUEST)
    assert not host_authority.validate_response(_inactive("sleeping"), REQUEST)
    assert not host_authority.validate_response(_inactive("none"), REQUEST)
    assert not host_authority.validate_response({**_inactive(), "sequence": 2}, REQUEST)
    assert not host_authority.validate_response({**_inactive(), "request_digest": "0" * 64}, REQUEST)
    assert not host_authority.validate_response({**_inactive(), "grant_id": "g"}, REQUEST)
    active = {**_inactive("none"), "decision": "active", "workspace_id": REQUEST["workspace_id"],
              "project_id": REQUEST["project_id"], "environment_id": REQUEST["environment_id"],
              "verification_record_digest": "3" * 64, "proof_expires_at_ms": 1, "runner_id": "runner-1",
              "runner_key_id": "key_1", "public_key_digest": "8" * 64, "binding_id": REQUEST["binding_id"],
              "binding_digest": "5" * 64, "binding_expires_at_ms": 1, "run_id": REQUEST["run_id"], "run_status": "running",
              "stop_reason": "none", "grant_id": "grant-1", "grant_digest": "7" * 64, "grant_expires_at_ms": 1,
              "egress_hostname": "api.example.com", "egress_port": 443}
    assert host_authority.validate_response(active, REQUEST)
    for mutation in ({"egress_port": 80}, {"egress_hostname": "API.example.com"}, {"run_status": "finalizing"},
                     {"reason": "clock_gap"}):
        assert not host_authority.validate_response({**active, **mutation}, REQUEST), mutation


def test_only_production_peercred_reader_exists():
    source = LISTENER_FILE.read_text(encoding="utf-8")
    tree = ast.parse(source)
    readers = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
               and "getsockopt" in ast.get_source_segment(source, node)}
    attributes = [node for node in ast.walk(tree) if isinstance(node, ast.Attribute) and node.attr == "SO_PEERCRED"]
    assert readers == {"read_peer"} and len(attributes) == 1  # read inside read_peer only
    assert list(inspect.signature(host_authority.read_peer).parameters) == ["sock"]
    parameters = inspect.signature(host_authority.HostAuthorityListener).parameters
    assert list(parameters) == ["config", "decide", "_listen_for_tests"]
    assert "read_peer(connection)" in ast.get_source_segment(source, next(
        node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef) and node.name == "_handle"))
    for forbidden in ("http_api", "canary_runs", "sqlite3", "import heel", "from heel"):
        assert forbidden not in source, forbidden


def _string_constants(source: str) -> list[str]:
    """Every string constant that is not a docstring."""
    tree = ast.parse(source)
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                docstrings.add(id(first.value))
    return [node.value.decode("latin-1") if isinstance(node.value, bytes) else node.value for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)) and id(node) not in docstrings]


def _exchange(listener, raw: bytes) -> bytes:
    server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.sendall(raw)
        listener._serve_request(server)
        server.close()
        data = b""
        try:
            while chunk := client.recv(65536):
                data += chunk
        except ConnectionResetError:  # the handler closed with an unread body behind the response
            pass
        return data
    finally:
        client.close()


def _request_bytes(body: bytes, extra: bytes = b"") -> bytes:
    return (b"POST /host/v1/authority-snapshot HTTP/1.1\r\nContent-Type: application/json\r\n"
            b"Content-Length: %d\r\n" % len(body) + extra + b"\r\n" + body)


def test_listener_ignores_authorization_cookie_and_edge_auth_headers():
    """STATE-MACHINE ONLY: requests over a socketpair to the request handler; peer admission is the
    Linux job's. The three credential headers change nothing and are never looked up."""
    seen = []

    def decide(request):
        seen.append(request)
        return _inactive()

    listener = host_authority.HostAuthorityListener(_config(), decide)
    body = _encode(REQUEST)
    plain = _exchange(listener, _request_bytes(body))
    loaded = _exchange(listener, _request_bytes(body, b"Authorization: Bearer x\r\nCookie: session=abc\r\n"
                                                      b"X-Heel-Edge-Auth: secret\r\n"))
    assert plain == loaded and plain.startswith(b"HTTP/1.1 200 OK\r\n") and b"\r\nCache-Control: no-store\r\n" in plain
    assert json.loads(plain.split(b"\r\n\r\n", 1)[1]) == _inactive() and seen == [REQUEST, REQUEST]
    for constant in _string_constants(LISTENER_FILE.read_text(encoding="utf-8")):
        lowered = constant.lower()
        for header in ("authorization", "cookie", "x-heel-edge-auth"):
            assert header not in lowered, constant
    # Closed transport: wrong route, method, missing type, oversize, chunked and a broken decision.
    assert _exchange(listener, _request_bytes(body).replace(b"/host/v1/authority-snapshot", b"/v1/runs")).startswith(b"HTTP/1.1 404")
    assert _exchange(listener, _request_bytes(body).replace(b"POST ", b"GET ")).startswith(b"HTTP/1.1 404")
    assert _exchange(listener, _request_bytes(body).replace(b"application/json", b"text/plain")).startswith(b"HTTP/1.1 400")
    big = b"x" * 2049
    assert _exchange(listener, _request_bytes(big)).startswith(b"HTTP/1.1 413")
    assert _exchange(listener, _request_bytes(body, b"Transfer-Encoding: chunked\r\n")).startswith(b"HTTP/1.1 400")
    broken = host_authority.HostAuthorityListener(_config(), lambda request: {"decision": "active"})
    assert _exchange(broken, _request_bytes(body)) == (b"HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\n"
                                                       b"Content-Length: 0\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n")


# ---------------------------------------------------------------------------------------------
# Listener publication and ownership of the final path (real AF_UNIX on any POSIX OS).

@pytest.fixture
def socket_dir():
    directory = tempfile.mkdtemp(prefix="ha", dir="/tmp")  # short: AF_UNIX paths are bounded
    os.chmod(directory, 0o700)
    try:
        yield Path(directory)
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def _connects(path: Path) -> bool:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(5)
    try:
        client.connect(str(path))
        return True
    except OSError:
        return False
    finally:
        client.close()


def test_listener_publication_order_is_bind_listen_rename(monkeypatch, socket_dir):
    """STATE-MACHINE ONLY: a recording socket double and a recording rename; at the instant of the
    rename the bound temporary inode is already listening and the final path does not exist."""
    calls = []
    real_socket, real_rename = socket.socket, os.rename

    class Recording(real_socket):
        def bind(self, address):
            calls.append(("bind", Path(address).name))
            return super().bind(address)

        def listen(self, *args):
            calls.append(("listen",))
            result = super().listen(*args)
            calls.append(("listen_returned",))
            return result

    def rename(source, target):
        calls.append(("rename", Path(source).name, Path(target).name, _connects(Path(source)), Path(target).exists()))
        return real_rename(source, target)

    monkeypatch.setattr(host_authority.socket, "socket", Recording)
    monkeypatch.setattr(host_authority.os, "rename", rename)
    path = socket_dir / "a.sock"
    listener = host_authority.HostAuthorityListener(_config(path=str(path)), lambda request: {})
    listener._publish()
    monkeypatch.undo()
    try:
        names = [call[0] for call in calls if call[0] in ("bind", "listen", "listen_returned", "rename")]
        assert names[:4] == ["bind", "listen", "listen_returned", "rename"]
        bind, rename_call = calls[0], [call for call in calls if call[0] == "rename"][0]
        assert re.fullmatch(r"a\.sock\.[0-9]+\.[0-9a-f]{8}\.tmp", bind[1]) and rename_call[1] == bind[1]
        assert rename_call[2] == "a.sock" and rename_call[3] is True and rename_call[4] is False
        info = os.lstat(path)
        assert (info.st_dev, info.st_ino) == listener.own_inode and oct(info.st_mode & 0o777) == oct(0o600)
        assert sorted(entry.name for entry in socket_dir.iterdir()) == ["a.sock"] and _connects(path)
    finally:
        listener.close()
    assert not path.exists()


def test_listener_listen_failure_unlinks_only_temp_inode_and_never_final_path(socket_dir):
    path = socket_dir / "a.sock"
    working = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    working.bind(str(path))
    working.listen(4)
    before = os.lstat(path)

    def refuse(sock, backlog):  # the SEAM-LISTEN-FAILURE shape, injected only here and in T4F
        raise OSError(98, "injected")

    listener = host_authority.HostAuthorityListener(_config(path=str(path)), lambda request: {}, _listen_for_tests=refuse)
    try:
        with pytest.raises(OSError):
            listener._publish()
        after = os.lstat(path)
        assert (after.st_dev, after.st_ino) == (before.st_dev, before.st_ino) and _connects(path)
        assert sorted(entry.name for entry in socket_dir.iterdir()) == ["a.sock"]
        listener.close()  # never published: nothing to unlink
        assert path.exists()
    finally:
        working.close()


def test_listener_close_unlinks_only_own_inode(socket_dir):
    path = socket_dir / "a.sock"
    listener = host_authority.HostAuthorityListener(_config(path=str(path)), lambda request: {})
    listener._publish()
    listener.close()
    assert not path.exists()
    replaced = host_authority.HostAuthorityListener(_config(path=str(path)), lambda request: {})
    replaced._publish()
    other = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        other.bind(str(socket_dir / "w2.sock"))
        other.listen(4)
        os.rename(socket_dir / "w2.sock", path)
        w2 = os.lstat(path)
        replaced.close()
        assert path.exists() and (os.lstat(path).st_ino, os.lstat(path).st_dev) == (w2.st_ino, w2.st_dev) and _connects(path)
        stale = host_authority.HostAuthorityListener(_config(path=str(path)), lambda request: {})
        stale._publish()  # a stale or foreign endpoint at the final path is replaced by rename
        assert (os.lstat(path).st_dev, os.lstat(path).st_ino) == stale.own_inode
        stale.close()
        assert not path.exists()
    finally:
        other.close()


# The Linux T4-family connector program, run here on real AF_UNIX sockets against the test's own
# accept-and-close acceptor. Darwin reports a full accept queue as ECONNREFUSED (Linux: EAGAIN), so a
# connector that does not wait for acceptance fails the already-listening phase here for exactly that
# capacity reason; the bound-not-listening phase is the T4N shape and must still show the refusal.
CONNECTOR_FAILURES = ("n_enoent", "n_econnrefused", "n_eacces", "n_eagain", "n_other", "n_unanswered")
CONNECTOR_EXPECTED = {"listening": set(), "bound_not_listening": {"n_enoent", "n_econnrefused"},
                      "chatty_first_peer": {"n_unanswered"}}


def _slow_acceptor(sock: socket.socket, chatty_first: bool) -> tuple[threading.Thread, threading.Event]:
    """Accept and close, pausing 100 ms after every 50 accepts (the pause slows the acceptor; it
    decides no verdict). ``chatty_first``: the first connection instead gets one byte every 10 ms
    until the client goes away (capped at 10 s)."""
    sock.settimeout(0.05)
    stop = threading.Event()

    def run() -> None:
        accepted = 0
        while not stop.is_set():
            try:
                connection, _address = sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            with connection:
                end = time.monotonic() + 10 if chatty_first and accepted == 0 else 0
                try:
                    while time.monotonic() < end and not stop.is_set():
                        connection.sendall(b"x")
                        time.sleep(0.01)
                except OSError:
                    pass
            accepted += 1
            if accepted % 50 == 0:
                time.sleep(0.1)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, stop


def _run_connector(program: str, path: Path, scenario: str) -> dict:
    """The connector program with the T4 arguments; ``bound_not_listening`` publishes after its first
    attempt in the T4N order (bind a temporary name, rename, 200 ms, listen), the others listen first."""
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    thread = stop = None
    try:
        if scenario != "bound_not_listening":
            sock.bind(str(path))
            sock.listen(1)
            thread, stop = _slow_acceptor(sock, scenario == "chatty_first_peer")
        with subprocess.Popen([sys.executable, "-I", "-c", program, str(path), "2000", "20"], stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, text=True) as process:
            try:
                assert json.loads(process.stdout.readline()) == {"event": "started"}
                if scenario == "bound_not_listening":
                    tmp = path.with_name(path.name + ".wrong.tmp")
                    sock.bind(str(tmp))
                    os.rename(tmp, path)
                    time.sleep(0.2)
                    sock.listen(1)
                    thread, stop = _slow_acceptor(sock, False)
                output, _ = process.communicate(timeout=60)
            finally:
                if process.poll() is None:
                    process.kill()
    finally:
        if stop is not None:
            stop.set()
            thread.join(5)
        sock.close()
    done = json.loads(output.splitlines()[-1])
    assert done.pop("event") == "done"
    return done


def _check_connector(proof, done: dict, scenario: str) -> None:
    # The capacity/control property first: it reads only buckets an older connector also reports.
    failures = {key: done.get(key) for key in CONNECTOR_FAILURES}
    assert {key for key, value in failures.items() if value} == CONNECTOR_EXPECTED[scenario], failures
    assert done["attempts"] >= 2000 and done["n_success"] >= 20, done
    # Then the closed shape and the accounting: one mutually exclusive outcome per attempt.
    assert set(done) == set(proof.CONNECTOR_INTS) | set(proof.CONNECTOR_TOKENS)
    assert done["attempts"] == sum(done["n_" + kind] for kind in proof.CONNECTOR_KINDS)
    assert 1 <= done["first_success"] <= done["attempts"]
    assert sum(done["after_" + kind] for kind in proof.CONNECTOR_KINDS) == done["attempts"] - done["first_success"]
    assert done["other_first_errno"] == "none"
    assert done["unanswered_first"] == ("deadline_after_data" if scenario == "chatty_first_peer" else "none")
    if scenario == "chatty_first_peer":  # the drain deadline is absolute: a writing peer cannot hold it open
        assert done["n_unanswered"] == 1 and done["first_success"] == 1 and done["after_unanswered"] == 0
    entry = {"case": "t4", "verdict": "pass", "control": "listener",
             "ints": {key: done[key] for key in proof.CONNECTOR_INTS},
             "tokens": {key: done[key] for key in proof.CONNECTOR_TOKENS}}
    assert proof.LAUNCHER.sanitize_record(entry) is not None


@pytest.mark.parametrize("scenario", sorted(CONNECTOR_EXPECTED))
def test_t4_family_connector_paces_by_acceptance_and_still_sees_the_refused_window(socket_dir, scenario):
    """Real AF_UNIX on this OS, the test's own acceptor (not the product listener). The Linux T4,
    T4N and T4S cases own the publication claim; this pins the probe that measures it."""
    proof = _proof_module()
    _check_connector(proof, _run_connector(proof.CONNECTOR, socket_dir / "a.sock", scenario), scenario)


# ---------------------------------------------------------------------------------------------
# Diagnostic readers (no enforcement in H1A-1).

def test_clock_witness_detect_gap_flags_sleep_and_wall_gaps_within_tolerance():
    """STATE-MACHINE ONLY: pure clock samples; detection is a reader, never enforcement here."""
    sample = authority.ClockSample
    ms = 1_000_000
    start = sample(1_000 * ms, 5_000 * ms, 1_700_000_000_000 * ms)
    steady = sample(2_000 * ms, 6_000 * ms, 1_700_000_001_000 * ms)
    assert authority.detect_gap(start, start, steady) == ()
    within = sample(2_000 * ms, 6_200 * ms, 1_700_000_001_200 * ms)
    assert authority.detect_gap(start, start, within) == ()
    slept = sample(2_000 * ms, 6_201 * ms, 1_700_000_001_000 * ms)
    assert authority.detect_gap(start, start, slept) == ("sleep_gap",)
    stepped = sample(2_000 * ms, 6_000 * ms, 1_700_000_001_201 * ms)
    assert authority.detect_gap(start, start, stepped) == ("wall_gap",)
    backwards = sample(2_000 * ms, 6_000 * ms, 1_699_999_000_000 * ms)
    assert authority.detect_gap(start, start, backwards) == ("wall_gap",)
    frozen = sample(1_000 * ms + 5, 605_000 * ms, 1_700_000_600_000 * ms)  # a guest-cooperative sleep
    assert authority.detect_gap(start, start, frozen) == ("sleep_gap", "wall_gap")
    readings = iter([11, 22, 33])
    witness = authority.ClockWitness(clock=lambda clock_id: next(readings))
    if all(hasattr(time, name) for name in ("CLOCK_MONOTONIC", "CLOCK_BOOTTIME", "CLOCK_REALTIME")):
        assert witness.sample() == sample(11, 22, 33)
    else:
        with pytest.raises(authority.ClockUnavailable):
            witness.sample()
    source = AUTHORITY_FILE.read_text(encoding="utf-8")
    callers = {node.name for node in ast.walk(ast.parse(source)) if isinstance(node, ast.FunctionDef)
               and re.search(r"\bdetect_gap\(|\bsleep_capability_report\(", ast.get_source_segment(source, node))
               and node.name not in ("detect_gap", "sleep_capability_report")}
    assert callers == set(), "a diagnostic reader is enforced somewhere in H1A-1"


def test_sleep_capability_report_reads_fixtures_and_emits_fixed_tokens_only():
    """STATE-MACHINE ONLY: fixture systemctl and file readers; the report is fixed tokens."""
    files = {"/etc/systemd/sleep.conf.d/heel.conf": "[Sleep]\nAllowSuspend=no\nAllowHibernation=no\nAllowHybridSleep=no\n"
                                                    "AllowSuspendThenHibernate=no\n",
             "/proc/cmdline": "BOOT_IMAGE=/vmlinuz root=/dev/sda1 nohibernate quiet\n",
             "/sys/power/disk": "[disabled]\n", "/sys/power/state": "freeze mem disk\n"}
    report = authority.sleep_capability_report(systemctl=lambda unit: "masked\n", read=files.get)
    assert report == {"unit_sleep": "masked", "unit_suspend": "masked", "unit_hibernate": "masked",
                      "unit_hybrid_sleep": "masked", "unit_suspend_then_hibernate": "masked", "sleep_conf": "all_disabled",
                      "hibernation": "disabled_cmdline", "power_state": "freeze_mem_disk", "enforcement": "none_in_h1a1"}
    hostile = {"/etc/systemd/sleep.conf.d/heel.conf": "AllowSuspend=yes\n", "/proc/cmdline": "quiet /tmp/x Traceback\n",
               "/sys/power/disk": "[platform] shutdown\n", "/sys/power/state": "freeze mem secret-word\n"}
    report = authority.sleep_capability_report(systemctl=lambda unit: "enabled\n" if "suspend" in unit else "<b>", read=hostile.get)
    assert report["unit_suspend"] == "not_masked" and report["unit_sleep"] == "unknown"
    assert report["sleep_conf"] == "incomplete" and report["hibernation"] == "enabled" and report["power_state"] == "freeze_mem_other"
    missing = authority.sleep_capability_report(systemctl=lambda unit: "", read=lambda path: None)
    assert missing["sleep_conf"] == "missing" and missing["hibernation"] == "unknown" and missing["power_state"] == "unreadable"
    for value in list(report.values()) + list(missing.values()):
        assert re.fullmatch(r"[a-z0-9_]{1,40}", value), value


# ---------------------------------------------------------------------------------------------
# Workflow: the appended job (the full guard lives in the Linux proof module; this is its matrix).

def _proof_module():
    return _load("host_authority_proof_static", PROOF_FILE)


def test_new_job_block_is_additive_and_existing_blocks_match_recorded_hashes():
    proof = _proof_module()
    text = WORKFLOW.read_text(encoding="utf-8")
    assert proof.workflow_violations(text) == []
    lease = proof._job_block(text, "host-lease-feasibility")
    authority_job = proof._job_block(text, "host-authority-proof")
    lease_key_job = proof._job_block(text, "host-lease-key-shape")  # H2K1's job, bound by its recorded hash
    head = text[:proof.BASELINE_WORKFLOW_BYTES]
    assert text == head + "\n" + lease + "\n" + authority_job + "\n" + lease_key_job
    start = len(head) + 1 + len(lease) + 1
    assert text[start:start + len(authority_job)] == authority_job

    def swap(old: str, new: str) -> str:  # a mutation inside the authority job only, in place
        assert authority_job.count(old) == 1, old
        return text[:start] + authority_job.replace(old, new) + text[start + len(authority_job):]

    mutations = {
        "base_without_new_job": head + "\n" + lease,
        "authority_contents_write": text.replace("      contents: read\n    concurrency:\n      group: host-authority-proof",
                                                 "      contents: write\n    concurrency:\n      group: host-authority-proof"),
        "comment_between_blocks": text.replace("\n  host-authority-proof:", "\n# note\n  host-authority-proof:"),
        "trailing_bytes": text + "\n",
        "duplicate_lease_after_new_job": text + "\n" + lease,
        "duplicate_authority_job": text + "\n" + authority_job,
        "new_job_before_lease": head + "\n" + authority_job + "\n" + lease,
        "gate_other_branch": swap("refs/heads/codex/self-serve-host-authority-proof", "refs/heads/main"),
        "gate_without_dispatch": swap("if: github.event_name == 'workflow_dispatch' && github.ref == "
                                              "'refs/heads/codex/self-serve-host-authority-proof'",
                                              "if: github.ref == 'refs/heads/codex/self-serve-host-authority-proof'"),
        "checkout_tag": swap(proof.CHECKOUT, "actions/checkout@v4"),
        "checkout_other_sha": swap(proof.CHECKOUT, "actions/checkout@" + "1" * 40),
        "cache_step": swap("      - name: Upload allowlisted safe evidence\n", "      - uses: actions/cache@" + "2" * 40
                           + "\n      - name: Upload allowlisted safe evidence\n"),
        "job_timeout_30": swap("timeout-minutes: 25", "timeout-minutes: 30"),
        "step_timeout_21": swap("timeout-minutes: 20", "timeout-minutes: 21"),
        "run_changed": swap("run: python scripts/host_authority_proof.py", "run: python scripts/host_authority_proof.py -x"),
        "bare_extra_run": swap("      - name: Upload allowlisted safe evidence", "      - run: echo hi\n"
                               "      - name: Upload allowlisted safe evidence"),
        "extra_artifact": text + "            host-authority-proof/extra.txt\n",
        "retention_30": swap("retention-days: 3", "retention-days: 30"),
        "persist_credentials": swap("persist-credentials: false",
                                                                                  "persist-credentials: true"),
        "env_added": swap("    steps:\n", "    env:\n      X: y\n    steps:\n"),
        "ref_not_sha": swap("ref: ${{ github.sha }}", "ref: ${{ github.ref }}"),
        "always_removed": swap("        if: always()\n", ""),
        "concurrency_removed": swap("    concurrency:\n      group: host-authority-proof\n      cancel-in-progress: false\n", ""),
        "python_unpinned": swap('python-version: "3.13.5"', 'python-version: "3.13"'),
        "runs_on_latest": swap("runs-on: ubuntu-24.04", "runs-on: ubuntu-latest"),
        "dispatch_inputs": text.replace("workflow_dispatch: {}", "workflow_dispatch:\n    inputs:\n      x: {}"),
        "head_mutated": text.replace("cron: '24 7 * * 1'", "cron: '25 7 * * 1'"),
        "analyze_mutated": text.replace("queries: security-extended", "queries: security-and-quality"),
        "lease_permissions_write": text.replace(lease, lease.replace("contents: read", "contents: write")),
        "lease_run_changed": text.replace(lease, lease.replace("host_lease_feasibility.py", "host_lease_feasibility.py -k x")),
        # H2K1: the five-job composition is exact; the lease-key job is fixed in content and position.
        "four_jobs_without_lease_key": head + "\n" + lease + "\n" + authority_job,
        "extra_artifact_in_authority_job": swap("            host-authority-proof/report.txt\n",
                                                "            host-authority-proof/report.txt\n"
                                                "            host-authority-proof/extra.txt\n"),
        "duplicate_lease_key_job": text + "\n" + lease_key_job,
        "lease_key_before_authority": head + "\n" + lease + "\n" + lease_key_job + "\n" + authority_job,
        "lease_key_before_lease": head + "\n" + lease_key_job + "\n" + lease + "\n" + authority_job,
        "comment_before_lease_key": text.replace("\n  host-lease-key-shape:", "\n# note\n  host-lease-key-shape:"),
        "sixth_job": text + "\n  extra-job:\n    runs-on: ubuntu-24.04\n",
        "lease_key_branch": text.replace(lease_key_job, lease_key_job.replace(
            "refs/heads/codex/self-serve-host-lease-key-shape-proof", "refs/heads/main")),
        "lease_key_contents_write": text.replace(lease_key_job, lease_key_job.replace("contents: read", "contents: write")),
        "lease_key_run_changed": text.replace(lease_key_job, lease_key_job.replace("host_lease_key_shape.py",
                                                                                   "host_lease_key_shape.py -k x")),
        "lease_key_checkout_tag": text.replace(lease_key_job, lease_key_job.replace(proof.CHECKOUT, "actions/checkout@v4")),
    }
    for name, variant in mutations.items():
        assert variant != text, name
        assert proof.workflow_violations(variant) != [], name


# ---------------------------------------------------------------------------------------------
# H1A3-1 additions (H1A3DR design sections 3.1, 6.1-6.3 and 8.1): the process-global registry
# reader, the non-mutating sweep wrapper, the request-connection client and the unchanged check.

FAKE_PIDS = {state: 0x7FFF_FF00 + index for index, state in enumerate(
    ("owned", "looking", "reaped", "handed_off", "sweeping", "uncertain", "other"))}
REGISTRY_KEYS = ("owned", "looking", "reaped", "handed_off", "sweeping", "uncertain", "other")


def _fake_registry(monkeypatch, states, *, handed_off_status=None):
    """A fresh private registry of fake pids (no real process is forked, waited on or signalled for
    them) plus waitpid/kill recorders. ``handed_off_status`` is what waitpid reports for the handed-off
    pid: None = still running, an int = exited with that code."""
    registry, waits, kills = set(), [], []
    for state in states:
        registry.add(authority._Child(FAKE_PIDS[state], "bogus-state" if state == "other" else state))
    real_waitpid, real_kill = os.waitpid, os.kill

    def waitpid(pid, options):
        if pid not in FAKE_PIDS.values():
            return real_waitpid(pid, options)
        waits.append(pid)
        if pid != FAKE_PIDS["handed_off"] or handed_off_status is None:
            return 0, 0
        return pid, handed_off_status << 8

    def kill(pid, signum):
        if pid not in FAKE_PIDS.values():
            return real_kill(pid, signum)
        kills.append(pid)

    monkeypatch.setattr(authority, "_UNREAPED", registry)
    monkeypatch.setattr(authority, "_REAP_LOCK", threading.Lock())
    monkeypatch.setattr(authority.os, "waitpid", waitpid)
    monkeypatch.setattr(authority.os, "kill", kill)
    return registry, waits, kills


def _states(registry) -> dict[int, str]:
    return {child.pid: child.state for child in registry}


def test_sweep_polls_only_handed_off_entries_never_owned_looking_or_uncertain(monkeypatch):
    """STATE-MACHINE ONLY (the holder rule, mandatory on this authority.py edit): registry entries in
    owned, looking, uncertain and sweeping get zero waitpid calls from ``_sweep_unreaped``; a handed_off
    entry gets exactly one; a sweeping entry is converted to uncertain and kept; nothing is signalled."""
    registry, waits, kills = _fake_registry(
        monkeypatch, ("owned", "looking", "uncertain", "sweeping", "handed_off"))
    authority._sweep_unreaped()
    assert waits == [FAKE_PIDS["handed_off"]] and kills == []
    assert _states(registry) == {FAKE_PIDS["owned"]: "owned", FAKE_PIDS["looking"]: "looking",
                                 FAKE_PIDS["uncertain"]: "uncertain", FAKE_PIDS["sweeping"]: "uncertain",
                                 FAKE_PIDS["handed_off"]: "handed_off"}
    assert not authority._REAP_LOCK.locked()


def test_unresolved_children_and_sweep_wrapper_report_states_without_touching_pids(monkeypatch):
    """STATE-MACHINE ONLY: the reader returns the fixed seven keys (the six child states plus other)
    over the whole process registry under the registry lock, with no waitpid, no kill and no pid in
    the result. The wrapper is one sweep (one waitpid, for the handed-off entry only) then the reader."""
    _registry, waits, kills = _fake_registry(monkeypatch, ())
    assert authority.unresolved_children() == dict.fromkeys(REGISTRY_KEYS, 0)
    registry, waits, kills = _fake_registry(monkeypatch, REGISTRY_KEYS, handed_off_status=0)
    counts = authority.unresolved_children()
    assert tuple(counts) == REGISTRY_KEYS and counts == dict.fromkeys(REGISTRY_KEYS, 1)
    assert waits == [] and kills == [] and len(registry) == 7
    assert all(type(value) is int for value in counts.values())
    counts["owned"] = 99  # a fresh dict each call: the caller cannot reach the registry through it
    assert authority.unresolved_children()["owned"] == 1
    swept = authority.sweep_unresolved_children()
    # handed_off reaped (one look), reaped discarded without a look, sweeping -> uncertain (kept).
    assert waits == [FAKE_PIDS["handed_off"]] and kills == []
    assert swept == {"owned": 1, "looking": 1, "reaped": 0, "handed_off": 0, "sweeping": 0, "uncertain": 2, "other": 1}
    assert not authority._REAP_LOCK.locked()
    source = AUTHORITY_FILE.read_text(encoding="utf-8")
    for name in ("unresolved_children", "sweep_unresolved_children"):
        node = next(node for node in ast.walk(ast.parse(source)) if isinstance(node, ast.FunctionDef) and node.name == name)
        assert not [item for item in ast.walk(node) if isinstance(item, ast.Attribute) and item.attr in ("pid", "waitpid", "kill")]
        called = {ast.unparse(item.func) for item in ast.walk(node) if isinstance(item, ast.Call)}
        assert called <= {"dict.fromkeys", "tuple", "_sweep_unreaped", "unresolved_children"}, (name, called)
        assert name in authority.__all__


def _uid_map(tmp_path: Path, text: str = "0 0 4294967295\n", *, name: str = "uid_map") -> str:
    path = tmp_path / name
    path.write_text(text, encoding="ascii")
    return str(path)


def _initial_pid_namespace(monkeypatch):
    """The pid-1 namespace link needs privilege on an ordinary CI runner; the test reads both links as
    equal (the privileged T1 proof covers the real comparison). Nothing else is patched."""
    real_readlink = os.readlink

    def readlink(path, *args, **kwargs):
        if path in ("/proc/self/ns/pid", "/proc/1/ns/pid"):
            return "pid:[4026531836]"
        return real_readlink(path, *args, **kwargs)

    monkeypatch.setattr(authority.os, "readlink", readlink)


class _CpListener:
    """A real AF_UNIX listener at a 0600 socket in a 0700 directory, owned by this uid; it accepts
    connections and records the bytes each one sent until EOF."""

    def __init__(self):
        self.directory = tempfile.mkdtemp(prefix="cpc")
        self.path = os.path.join(self.directory, "cp.sock")
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(self.path)
        os.chmod(self.path, 0o600)
        self.sock.listen(8)
        self.sock.settimeout(0.2)
        self.received: list[bytes] = []
        self.done = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while not self.done.is_set():
            try:
                connection, _address = self.sock.accept()
            except (TimeoutError, OSError):
                continue
            with connection:
                connection.settimeout(5)
                data = b""
                with contextlib.suppress(OSError):
                    while chunk := connection.recv(4096):
                        data += chunk
                self.received.append(data)

    def listing(self):
        return sorted(os.listdir(self.directory))

    def close(self):
        self.done.set()
        self.thread.join(5)
        self.sock.close()
        shutil.rmtree(self.directory, ignore_errors=True)


class _PeerPidZeroSocket(socket.socket):
    """A peer-credential double: SO_PEERCRED reads pid 0 (a peer outside this PID namespace)."""

    def getsockopt(self, level, option, *args):
        if level == socket.SOL_SOCKET and option == getattr(socket, "SO_PEERCRED", None):
            return struct.pack("3i", 0, os.geteuid(), os.getegid())
        return super().getsockopt(level, option, *args)


def test_connect_cp_verifies_peer_on_the_request_connection_and_never_creates_paths(monkeypatch, tmp_path, capsys):
    """Static on every OS: ``connect_cp`` reads SO_PEERCRED on the very socket it returns and creates,
    unlinks, renames or binds nothing. Behaviour on Linux (a real AF_UNIX listener owned by this uid;
    STATE-MACHINE ONLY for the two pid-namespace links and for the pid-0 peer double): the bytes
    written on the returned socket reach the accepted connection whose peer was checked; a pid-0
    peer is refused peer_identity with nothing written; an exhausted deadline is cp_timeout; the
    directory listing never changes. Elsewhere the platform refusal is the only outcome."""
    source = AUTHORITY_FILE.read_text(encoding="utf-8")
    node = next(node for node in ast.walk(ast.parse(source)) if isinstance(node, ast.FunctionDef) and node.name == "connect_cp")
    segment = ast.get_source_segment(source, node)
    called = {ast.unparse(item.func).split(".")[-1] for item in ast.walk(node) if isinstance(item, ast.Call)}
    assert not called & {"unlink", "rename", "replace", "mkdir", "bind", "chmod", "symlink", "remove", "verify_cp_socket"}
    assert "client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED" in segment and "return client" in segment
    parameters = inspect.signature(authority.connect_cp).parameters
    assert list(parameters) == ["path", "cp_uid", "deadline_ns", "uid_map_path"]
    assert parameters["uid_map_path"].kind is inspect.Parameter.KEYWORD_ONLY
    deadline = time.monotonic_ns() + 2_000_000_000
    if not sys.platform.startswith("linux"):
        with pytest.raises(authority.ControlPlaneUnavailable) as raised:
            authority.connect_cp("/nonexistent/cp.sock", os.geteuid(), deadline)
        assert raised.value.code == "platform_unsupported"
        return
    uid_map = _uid_map(tmp_path)
    _initial_pid_namespace(monkeypatch)
    listener = _CpListener()
    try:
        before = listener.listing()
        client = authority.connect_cp(listener.path, os.geteuid(), deadline, uid_map_path=uid_map)
        try:
            client.sendall(b"request-on-the-checked-connection")
        finally:
            client.close()
        end = time.monotonic() + 5
        while not listener.received and time.monotonic() < end:
            time.sleep(0.01)
        assert listener.received == [b"request-on-the-checked-connection"]
        with pytest.raises(authority.ControlPlaneUnavailable) as raised:
            authority.connect_cp(listener.path, os.geteuid(), time.monotonic_ns() - 1, uid_map_path=uid_map)
        assert raised.value.code == "cp_timeout"
        with pytest.raises(authority.ControlPlaneUnavailable) as raised:
            authority.connect_cp(os.path.join(listener.directory, "absent.sock"), os.geteuid(), deadline,
                                 uid_map_path=uid_map)
        assert raised.value.code == "socket_unreadable"
        monkeypatch.setattr(authority.socket, "socket", _PeerPidZeroSocket)
        with pytest.raises(authority.ControlPlaneUnavailable) as raised:
            authority.connect_cp(listener.path, os.geteuid(), deadline, uid_map_path=uid_map)
        assert raised.value.code == "peer_identity"
        end = time.monotonic() + 5
        while len(listener.received) < 2 and time.monotonic() < end:
            time.sleep(0.01)
        assert listener.received[1:] == [b""]  # the refused connection carried no byte
        assert listener.listing() == before == ["cp.sock"]
    finally:
        listener.close()
    with capsys.disabled():
        print("\nH1A3-1L-E2E S24 PASS same_connection=checked pid0=refused deadline=refused paths=unchanged")


def test_verify_cp_socket_behaviour_unchanged(monkeypatch, tmp_path, capsys):
    """``verify_cp_socket`` keeps its signature, codes and order: the platform refusal first, then the
    uid, namespaces, path, socket and directory profiles, then a separate connection that only reads
    the peer. On Linux (real listener; STATE-MACHINE ONLY for the pid-namespace links and the pid-0
    peer double) every code is reached; elsewhere the platform refusal is the outcome."""
    signature = inspect.signature(authority.verify_cp_socket)
    assert str(signature) == "(path: str, cp_uid: int, *, uid_map_path: str = '/proc/self/uid_map') -> None"
    if not sys.platform.startswith("linux"):
        for cp_uid in (0, -1, True):
            with pytest.raises(authority.ControlPlaneUnavailable) as raised:
                authority.verify_cp_socket("/nonexistent/cp.sock", cp_uid)
            assert raised.value.code == "platform_unsupported"
        return
    uid_map = _uid_map(tmp_path)
    _initial_pid_namespace(monkeypatch)
    listener = _CpListener()

    def code(path=None, cp_uid=None, uid_map_path=uid_map):
        try:
            authority.verify_cp_socket(listener.path if path is None else path,
                                       os.geteuid() if cp_uid is None else cp_uid, uid_map_path=uid_map_path)
        except authority.ControlPlaneUnavailable as error:
            return error.code
        return "ok"

    try:
        assert code() == "ok"
        assert code(cp_uid=-1) == code(cp_uid=True) == code(cp_uid=2 ** 32 - 1) == "cp_uid_invalid"
        assert code(uid_map_path=_uid_map(tmp_path, "0 1000 1\n", name="translated_uid_map")) == "not_initial_user_namespace"
        assert code(uid_map_path=str(tmp_path / "missing")) == "socket_unreadable"
        assert code() == "ok"  # the default map is intact after the two map cases
        assert code(path="relative/cp.sock") == "path_not_absolute"
        assert code(path=os.path.join(listener.directory, "absent.sock")) == "socket_unreadable"
        assert code(cp_uid=os.geteuid() + 1) == "socket_profile"
        os.chmod(listener.path, 0o660)
        assert code() == "socket_profile"
        os.chmod(listener.path, 0o600)
        os.chmod(listener.directory, 0o750)
        assert code() == "directory_profile"
        os.chmod(listener.directory, 0o700)
        monkeypatch.setattr(authority.socket, "socket", _PeerPidZeroSocket)
        assert code() == "peer_identity"
        end = time.monotonic() + 5
        while len(listener.received) < 3 and time.monotonic() < end:
            time.sleep(0.01)
        assert listener.received == [b"", b"", b""]  # the check never writes a byte
    finally:
        listener.close()
    with capsys.disabled():
        print("\nH1A3-1L-E2E S21 PASS codes=13 connections=3")
