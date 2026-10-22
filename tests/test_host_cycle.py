"""H1A3-1 host supervisor authorization cycle (H1A3DR design sections 2-8).

Runs on any OS. The cycle drives the real ``LeaseDomain`` over a stand-in descriptor whose
installer children are the recorded double of ``tests/test_host_authority.py`` (the real fork,
pipes, bounded wait, SIGKILL and reaping run; only the code after ``fork`` is replaced). Tests that
use that recorded installer, injected clock samples, a scripted exchange or scripted self-test,
sleep and witness readers say so with the docstring prefix ``STATE-MACHINE ONLY:`` and claim nothing
about namespaces, nft, expiry in the kernel or packets; the Linux proof owns those. Seams, each for
these tests only and never passed by a production caller (``_seams_for_tests``, pinned by
``test_seams_are_test_only_and_no_production_module_passes_them``): SEAM-CLOCK, SEAM-DOMAIN,
SEAM-SELFTEST, SEAM-SLEEP-REPORT, SEAM-WITNESS, SEAM-EXCHANGE, SEAM-BOOT-EPOCH. The two Linux tests
run the real control plane (listener, decider, ledger) and the real client over AF_UNIX with the
real peer check; their domain is still the recorded installer.
"""
from __future__ import annotations

import ast
import dataclasses
import importlib.util
import inspect
import itertools
import json
import logging
import math
import os
import re
import secrets
import signal
import socket
import sys
import threading
import time
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CYCLE_FILE = ROOT / "deploy" / "host" / "cycle.py"
PROFILE_FILE = ROOT / "deploy" / "host" / "profile.py"
H1F_FILE = ROOT / "scripts" / "host_lease_feasibility.py"
DOC_FILE = ROOT / "docs" / "saas" / "HOST_AUTHORITY_CYCLE.md"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses resolve string annotations through sys.modules
    spec.loader.exec_module(module)
    return module


cycle = _load("heel_host_cycle_unit", CYCLE_FILE)
authority, codec, profile = cycle.authority, cycle.codec, cycle.profile

L, R = "198.51.100.10", "203.0.113.10"
MS = 1_000_000
T_NS = cycle.LEASE_MS * MS
POSIX_FORK = pytest.mark.skipif(not hasattr(os, "fork"), reason="needs os.fork")
LINUX = pytest.mark.skipif(sys.platform != "linux", reason="real AF_UNIX peer credentials and check_startup need Linux")
REGISTRY_KEYS = ("owned", "looking", "reaped", "handed_off", "sweeping", "uncertain", "other")
CTX = {
    "workspace_id": "ws_" + "1" * 16, "project_id": "prj_" + "1" * 32, "environment_id": "env_" + "1" * 32,
    "verification_record_digest": "a" * 64, "runner_id": "runr_1", "runner_key_id": "key_1",
    "binding_id": "rcb_" + "1" * 32, "binding_digest": "b" * 64, "run_id": "crun_" + "1" * 32, "grant_id": "cgr_1",
    "grant_digest": "c" * 64, "public_key_digest": "d" * 64, "egress_hostname": "canary.acme.dev",
    "kill_switch_generation": 0, "egress_port": 443,
}
NON_NONE_REASONS = tuple(reason for reason in codec.REASONS if reason != "none")


# ---------------------------------------------------------------------------------------------
# Fixtures (every one of them a test double; see the module docstring).

@pytest.fixture(autouse=True)
def isolated_process_state(monkeypatch):
    """A fresh process-wide generation budget and cleanup registry per test, and the signal picture
    restored afterwards (the budget is process-wide by design; tests replace it, never reset it)."""
    monkeypatch.setattr(cycle, "_BUDGET", cycle._GenerationBudget())
    monkeypatch.setattr(authority, "_UNREAPED", set())
    monkeypatch.setattr(authority, "_REAP_LOCK", threading.Lock())
    saved = {signum: signal.getsignal(signum) for signum in signal.valid_signals()}
    yield
    for signum, handler in saved.items():
        if signal.getsignal(signum) != handler and handler is not None:
            signal.signal(signum, handler)
    cycle._STATE.stop_requested = False
    cycle._INSTALLED = None


@pytest.fixture
def signals():
    cycle.install_signal_context()
    yield


class Installer:
    """The recorded installer of tests/test_host_authority.py: batches and child pids are recorded;
    the forked child runs ``plan[call]`` (an exit code, ("sleep", seconds, code)) instead of nft, and a
    ("raise",) step makes the spawn itself fail (an ordinary exception inside the domain call)."""

    def __init__(self, monkeypatch, plan=None, default=0):
        self.plan, self.default = list(plan or []), default
        self.batches: list[bytes] = []
        self.pids: list[int] = []
        real_spawn = authority._spawn

        def spawn(ns_fd, path, argv, data):
            self.batches.append(data)
            if self._step() == ("raise",):
                raise OSError("installer double: spawn failed")
            pid, sink = real_spawn(ns_fd, path, argv, data)
            self.pids.append(pid)
            return pid, sink

        monkeypatch.setattr(authority, "_spawn", spawn)
        monkeypatch.setattr(authority, "_exec_child", self._child)
        monkeypatch.setattr(authority, "NFT_PATH", "/nonexistent/nft-double")

    def _step(self):
        index = len(self.batches) - 1
        return self.plan[index] if index < len(self.plan) else self.default

    def _child(self, ns_fd, path, argv, env, stdin_fd, sink_fd):
        step = self._step()
        if isinstance(step, tuple) and step[0] == "sleep":
            time.sleep(step[1])
            os._exit(step[2])
        os._exit(step)

    def kinds(self) -> list[str]:
        names = []
        for batch in self.batches:
            text = batch.decode()
            names.append("prepare" if text.startswith("create element") else "activate" if "add element" in text
                         else "flush" if text.startswith("flush map") else "close")
        return names


class RecordingDomain:
    """Forwards to a real state-machine ``LeaseDomain`` and records every public call by name."""

    def __init__(self, domain):
        self._domain, self.calls = domain, []

    def __getattr__(self, name):
        value = getattr(self._domain, name)
        if callable(value) and name in ("prepare", "activate", "close", "close_generation"):
            def call(*args, **kwargs):
                self.calls.append(name)
                return value(*args, **kwargs)
            return call
        return value


class OffsetClock:
    """SEAM-CLOCK cycle tests only: the host monotonic clock plus a scripted forward offset, so the
    real ``prepared_monotonic_ns`` of the domain and the cycle's own samples share one timeline."""

    def __init__(self):
        self.offset = 0

    def __call__(self) -> int:
        return time.monotonic_ns() + self.offset

    def advance_ms(self, ms: int) -> None:
        self.offset += ms * MS


class Script:
    """SEAM-EXCHANGE cycle tests only: answers each request with the next scripted step (a callable
    of the request returning a reply dict, or ("fail", code)); records every request."""

    def __init__(self, clock: OffsetClock, steps=()):
        self.clock, self.steps, self.requests = clock, list(steps), []

    def __call__(self, request: dict, deadline_ns: int) -> dict:
        self.requests.append(dict(request))
        step = self.steps.pop(0) if self.steps else active()
        if isinstance(step, tuple):
            raise cycle.ExchangeFailed(step[1])
        return step(request)


def active(*, rem_ms: int = 60_000, delay_ms: int = 0, clock: OffsetClock | None = None, **changes):
    def reply(request: dict) -> dict:
        if delay_ms:
            clock.advance_ms(delay_ms)
        server = 1_700_000_000_000
        document = {
            "schema_version": codec.RESPONSE_SCHEMA, "decision": "active", "reason": "none",
            "sequence": request["sequence"], "request_digest": codec.request_digest(request),
            "server_time_ms": server, "kill_switch_generation": CTX["kill_switch_generation"],
            **{name: CTX[name] for name in cycle.CONTEXT_STRINGS}, "run_status": "running", "stop_reason": "none",
            "proof_expires_at_ms": server + rem_ms + 2000, "binding_expires_at_ms": server + rem_ms + 1000,
            "grant_expires_at_ms": server + rem_ms, "egress_port": 443,
        }
        document.update(changes)
        return document
    return reply


def inactive(reason: str):
    def reply(request: dict) -> dict:
        return {"schema_version": codec.RESPONSE_SCHEMA, "decision": "inactive", "reason": reason,
                "sequence": request["sequence"], "request_digest": codec.request_digest(request),
                "server_time_ms": 1_700_000_000_000, "kill_switch_generation": 0}
    return reply


def pinned_report(**ints) -> authority.SelfTestReport:
    """SEAM-SELFTEST cycle tests only: a synthetic passing self-test of the accepted 6.17 profile."""
    tokens = {"kernel_major_minor": "6.17", "nft_version": "1.0.9", "selftest": "pass", "readd_observation": "refresh"}
    values = {"config_hz": 1000, "tick_allowance_ms": 1, **ints}
    return authority.SelfTestReport("pass", (), types.MappingProxyType(tokens), types.MappingProxyType(values))


def compliant_sleep() -> dict:
    """SEAM-SLEEP-REPORT cycle tests only: the K9 picture the cycle requires."""
    report = {"unit_" + unit.replace("-", "_").replace(".target", ""): "masked" for unit in authority.SLEEP_TARGETS}
    report.update(sleep_conf="all_disabled", hibernation="disabled_cmdline", power_state="freeze_mem",
                  enforcement="none_in_h1a1")
    return report


class SteadyWitness:
    """SEAM-WITNESS cycle tests only: ``ClockWitness.sample`` with the three clocks derived from the
    monotonic clock (no gap), and a scripted BOOTTIME jump (a suspend the monotonic clock did not
    see) once ``armed``. The real witness needs CLOCK_BOOTTIME (Linux)."""

    def __init__(self):
        self.armed = False

    def sample(self) -> authority.ClockSample:
        now = time.monotonic_ns()
        return authority.ClockSample(now, now + (5_000_000_000 if self.armed else 0), now + 1_700_000_000_000_000_000)


class Harness:
    """One HostCycle with the recorded installer, a recording domain per generation, an offset clock,
    a scripted exchange and scripted generation-start readers."""

    def __init__(self, monkeypatch, tmp_path, *, plan=None, steps=(), report=None, sleep=None, witness=None,
                 exchange=None, counter=None):
        self.installer = Installer(monkeypatch, plan)
        self.clock = OffsetClock()
        self.script = Script(self.clock, steps)
        self.domains: list[RecordingDomain] = []
        self.tmp_path, self.counter = tmp_path, counter
        seams = cycle.CycleSeams(
            clock=self.clock, domain_factory=self._domain, self_test=lambda domain: report or pinned_report(),
            sleep_report=sleep or compliant_sleep, witness=witness or SteadyWitness(),
            exchange=exchange or self.script, boot_epoch="boot-0001",
        )
        self.cycle = cycle.HostCycle("slot-a", "/run/heel/cp.sock", 0, slot_src=L, slot_dst=R,
                                     admission=cycle.Enablement.NON_CUSTOMER, _seams_for_tests=seams)

    def _domain(self):
        fd = os.open(self.tmp_path / f"ns-stand-in-{len(self.domains)}", os.O_RDONLY | os.O_CREAT | os.O_CLOEXEC, 0o600)
        domain = authority.LeaseDomain(_seal=authority._SEAL, ns_fd=fd)
        if self.counter is not None:
            domain._counter = authority._MarkCounter(self.counter)
        self.domains.append(RecordingDomain(domain))
        return self.domains[-1]

    @property
    def domain(self) -> RecordingDomain:
        return self.domains[-1]

    def serve(self, **context) -> "Harness":
        assert self.cycle.start() == "ready", self.cycle.status()
        self.cycle.install_context(cycle.CycleContext(**{**CTX, **context}))
        return self

    def status(self) -> dict:
        return self.cycle.status()


def harness(monkeypatch, tmp_path, **kwargs) -> Harness:
    return Harness(monkeypatch, tmp_path, **kwargs).serve()


# ---------------------------------------------------------------------------------------------
# Context (R section 2).

def test_context_is_frozen_closed_and_validated_against_the_request_codec():
    context = cycle.CycleContext(**CTX)
    with pytest.raises(dataclasses.FrozenInstanceError):
        context.run_id = "crun_" + "2" * 32
    assert not hasattr(context, "__dict__")
    with pytest.raises(TypeError):
        cycle.CycleContext(*CTX.values())
    with pytest.raises(TypeError):
        cycle.CycleContext(**CTX, token="secret")
    for name, bad in [("workspace_id", "ws_XYZ"), ("run_id", "run_1"), ("grant_digest", "C" * 64),
                      ("public_key_digest", "d" * 63), ("egress_hostname", "Canary.acme.dev"),
                      ("egress_hostname", "localhost"), ("kill_switch_generation", True),
                      ("kill_switch_generation", -1), ("kill_switch_generation", 1.0), ("egress_port", 80),
                      ("egress_port", True), ("runner_id", "")]:
        with pytest.raises(ValueError) as raised:
            cycle.CycleContext(**{**CTX, name: bad})
        assert str(raised.value) == "context_invalid", name
    assert set(cycle.CONTEXT_STRINGS) == ({"public_key_digest", "egress_hostname"}
                                         | set(codec.REQUEST_FIELDS) - set(codec._INTEGERS)
                                         - {"schema_version", "host_boot_epoch", "slot_id", "request_nonce",
                                            "generation_id"})
    assert set(cycle.CONTEXT_STRINGS) == set(codec._ACTIVE_STRINGS) - {"run_status", "stop_reason"}
    assert [field.name for field in dataclasses.fields(cycle.CycleContext)] == [
        *cycle.CONTEXT_STRINGS, "kill_switch_generation", "egress_port"]


@POSIX_FORK
@pytest.mark.parametrize("field", [*cycle.CONTEXT_STRINGS, "kill_switch_generation", "egress_port"])
def test_context_carries_grant_key_digest_and_egress_hostname_and_every_active_reply_must_equal_them(
        monkeypatch, tmp_path, signals, field):
    """STATE-MACHINE ONLY: an ``active`` reply that differs from the installed context in any one of
    the context strings (the grant's ``public_key_digest`` and ``egress_hostname`` included) or in
    ``kill_switch_generation`` ends the context ``context_mismatch`` without activation; a reply with
    ``egress_port`` other than 443 is refused by the codec (``malformed_reply``) and never activates.
    Nothing is learned from a reply: the next request still carries the installed context."""
    changed = {
        "workspace_id": "ws_" + "2" * 16, "project_id": "prj_" + "2" * 32, "environment_id": "env_" + "2" * 32,
        "verification_record_digest": "e" * 64, "runner_id": "runr_2", "runner_key_id": "key_2",
        "binding_id": "rcb_" + "2" * 32, "binding_digest": "f" * 64, "run_id": "crun_" + "2" * 32,
        "grant_id": "cgr_2", "grant_digest": "0" * 64, "public_key_digest": "9" * 64,
        "egress_hostname": "other.acme.dev", "kill_switch_generation": 1, "egress_port": 80,
    }[field]
    h = Harness(monkeypatch, tmp_path)
    h.script.steps = [active(**{field: changed}), active()]
    h.serve()
    assert h.cycle.tick() in ("closed", "serving")
    assert "activate" not in h.domain.calls
    if field == "egress_port":
        assert h.status()["last_reason"] == "malformed_reply" and h.status()["generation_phase"] == "serving"
        h.cycle.tick()
        assert h.domain.calls.count("activate") == 1
        assert all(request[name] == CTX[name] for request in h.script.requests
                   for name in cycle.CONTEXT_STRINGS if name in request)
        return
    status = h.status()
    assert (status["generation_phase"], status["context_end_reason"], status["generation_class_end"]) == (
        "closed", "context_mismatch", "A")
    assert h.domain.calls == ["prepare", "close_generation"]


# ---------------------------------------------------------------------------------------------
# Timing (R section 4.1-4.2): pure arithmetic first, then the cycle.

def test_expiry_lower_gate_is_prepared_monotonic_plus_timeout_minus_two_ticks_and_upper_is_post_return_plus_tick():
    window = cycle.AuthorityWindow(t_p0=10_000, t_p1=7_000_000, t_start=9_000_000, tick_ns=4_000_000, rem_ms=60_000)
    assert window.e_lower == 10_000 + T_NS - 2 * 4_000_000
    assert window.e_upper == 7_000_000 + T_NS + 4_000_000
    assert window.deadline == 9_000_000 + 60_000 * MS
    assert window.bound == min(window.e_upper, window.deadline) == window.e_upper
    assert window.gap_ns == 2_000_000
    assert profile.tick_ns(pinned_report(config_hz=250)) == 4_000_000
    assert profile.tick_ns(pinned_report(config_hz=1000)) == 1_000_000
    assert profile.tick_ns(pinned_report(config_hz=300)) == 3_333_334  # ceil, never floor


@POSIX_FORK
def test_cycle_window_takes_t_p0_from_the_handle_and_t_p1_after_prepare_returned(monkeypatch, tmp_path, signals):
    """STATE-MACHINE ONLY: the recorded window of an activated key uses the handle's
    ``prepared_monotonic_ns`` (sampled before the child) as ``t_p0`` and a sample after ``prepare``
    returned as ``t_p1``; ``t_start`` follows ``t_p1``; the tick comes from the self-test's HZ."""
    h = Harness(monkeypatch, tmp_path, report=pinned_report(config_hz=250)).serve()
    assert h.cycle.tick() == "serving"
    (window,) = h.cycle._windows
    handle = h.cycle._current
    assert window.t_p0 == handle.prepared_monotonic_ns < window.t_p1 <= window.t_start
    assert window.tick_ns == 4_000_000
    assert h.cycle._residual_ns == window.bound


def test_activation_boundary_arithmetic_is_exact():
    """``rem = T + tick − gap`` activates, one millisecond less refuses; ``D`` is anchored at
    ``t_start``; dropping ``tick``, using ``t_p0`` for the upper bound or anchoring at the reply would
    each flip the refusal into an activation."""
    tick, t_p0, t_p1 = 1_000_000, 5_000_000, 9_000_000
    t_start = t_p1 + 2_000_000  # gap = 2 ms
    boundary = (T_NS + tick - 2_000_000) // MS
    assert boundary * MS == T_NS + tick - 2_000_000
    exact = cycle.AuthorityWindow(t_p0=t_p0, t_p1=t_p1, t_start=t_start, tick_ns=tick, rem_ms=boundary)
    short = cycle.AuthorityWindow(t_p0=t_p0, t_p1=t_p1, t_start=t_start, tick_ns=tick, rem_ms=boundary - 1)
    t_reply = t_start + 900 * MS  # a reply delayed by 900 ms
    assert exact.e_upper == exact.deadline and exact.verdict(t_reply) == "activate"
    assert short.verdict(t_reply) == "authority_too_short"
    assert short.deadline == t_start + (boundary - 1) * MS  # never t_reply + rem
    # The three wrong formulas each turn the refusal into an activation.
    assert t_p1 + T_NS <= short.deadline  # tick dropped
    assert t_p0 + T_NS + tick <= short.deadline  # t_p0 as the upper anchor
    assert short.e_upper <= t_reply + short.rem_ms * MS  # D anchored at the reply
    # The liveness gate: activation is attempted only strictly before E_lower.
    assert exact.verdict(exact.e_lower - 1) == "activate" and exact.verdict(exact.e_lower) == "key_expiring"


def test_short_authority_where_kernel_upper_bound_exceeds_deadline_never_activates():
    for gap_ms in (0, 1, 7, 100):
        t_p1 = 50_000_000
        boundary = (T_NS + 1_000_000 - gap_ms * MS) // MS
        for rem, expected in ((boundary, "activate"), (boundary - 1, "authority_too_short"), (1, "authority_too_short")):
            window = cycle.AuthorityWindow(t_p0=t_p1 - MS, t_p1=t_p1, t_start=t_p1 + gap_ms * MS, tick_ns=1_000_000,
                                           rem_ms=rem)
            assert window.verdict(window.t_start) == expected, (gap_ms, rem)


@POSIX_FORK
def test_authority_deadline_is_anchored_at_t_start_never_reply_time(monkeypatch, tmp_path, signals):
    """STATE-MACHINE ONLY: a reply delayed by 900 ms with ``rem = 2500`` ms: anchored at ``t_start``
    the authority ends before ``E_upper`` (refused); anchored at the reply it would have outlived it."""
    h = Harness(monkeypatch, tmp_path)
    h.script.steps = [active(rem_ms=2500, delay_ms=900, clock=h.clock)]
    h.serve()
    assert h.cycle.tick() == "serving"
    assert h.status()["last_reason"] == "authority_too_short" and "activate" not in h.domain.calls
    window = h.cycle._last_window
    assert window.deadline == window.t_start + 2500 * MS < window.e_upper < window.t_start + 900 * MS + 2500 * MS


@POSIX_FORK
def test_late_reply_after_key_lower_bound_never_activates(monkeypatch, tmp_path, signals):
    """STATE-MACHINE ONLY: a reply that completes after ``min(t_start + 1000 ms, E_lower)`` is
    ``late_reply`` (no activation; the previous window, if any, continues); a reply delivered in time
    but evaluated after ``E_lower`` is ``key_expiring``."""
    h = Harness(monkeypatch, tmp_path)
    h.script.steps = [active(delay_ms=1100, clock=h.clock)]
    h.serve()
    h.cycle.tick()
    assert h.status()["last_reason"] == "late_reply" and h.status()["consecutive_unavailable"] == 1
    assert "activate" not in h.domain.calls
    real_verdict = cycle.AuthorityWindow.verdict
    monkeypatch.setattr(cycle.AuthorityWindow, "verdict", lambda self, t_act: real_verdict(self, self.e_lower))
    h.cycle.tick()
    assert h.status()["last_reason"] == "key_expiring" and "activate" not in h.domain.calls


def test_member_bounds_minimum_and_sanity_ceiling_reject_hostile_durations():
    base = active()({**_request(), "sequence": 1})
    assert cycle.AuthorityWindow.remaining_ms(base) == 60_000
    server = base["server_time_ms"]
    hostile = [{"grant_expires_at_ms": server}, {"grant_expires_at_ms": server - 1},
               {"binding_expires_at_ms": server}, {"proof_expires_at_ms": server - 5},
               {"grant_expires_at_ms": server + 600_001}, {"binding_expires_at_ms": server + 86_400_001},
               {"proof_expires_at_ms": server + 2_592_000_001}, {"grant_expires_at_ms": True},
               {"grant_expires_at_ms": float(server + 1000)}, {"server_time_ms": "1"}]
    for change in hostile:
        with pytest.raises(cycle.CycleError) as raised:
            cycle.AuthorityWindow.remaining_ms({**base, **change})
        assert raised.value.code == "stale_durations", change
    assert cycle.MEMBER_BOUNDS_MS == (2_592_000_000, 86_400_000, 600_000)
    assert cycle.MAX_EFFECTIVE_REMAINING_MS == 86_400_000
    edge = {**base, "grant_expires_at_ms": server + 600_000, "binding_expires_at_ms": server + 86_400_000,
            "proof_expires_at_ms": server + 2_592_000_000}
    assert cycle.AuthorityWindow.remaining_ms(edge) == 600_000


def _request() -> dict:
    return {"schema_version": codec.REQUEST_SCHEMA, "host_boot_epoch": "boot-0001", "slot_id": "slot-a",
            "request_nonce": "0" * 32, "generation_id": "1" * 32,
            **{name: CTX[name] for name in cycle.CONTEXT_STRINGS if name in codec.REQUEST_FIELDS},
            "sequence": 1, "monotonic_ms": 0, "kill_switch_generation": 0}


# ---------------------------------------------------------------------------------------------
# The cycle: request shape, renewal, lost replies.

@POSIX_FORK
def test_request_fields_come_only_from_context_slot_boot_and_counters(monkeypatch, tmp_path, signals):
    """STATE-MACHINE ONLY: every request is the closed codec schema built from the context, the slot,
    the boot epoch, the domain's generation id, the generation's own sequence counter, a fresh nonce
    and ``t_start // 10**6``; nothing comes from a previous reply."""
    h = Harness(monkeypatch, tmp_path)
    samples = []
    real = h.clock.__call__
    h.cycle._clock = lambda: samples.append(real()) or samples[-1]
    h.serve()
    for _ in range(3):
        h.cycle.tick()
    first, second, third = h.script.requests
    for index, request in enumerate(h.script.requests, start=1):
        assert set(request) == codec.REQUEST_FIELDS
        assert codec.validate_request(codec.canonical(request)) == request
        assert request["sequence"] == index and request["generation_id"] == h.domain.generation_id
        assert (request["slot_id"], request["host_boot_epoch"]) == ("slot-a", "boot-0001")
        assert all(request[name] == CTX[name] for name in cycle.CONTEXT_STRINGS if name in codec.REQUEST_FIELDS)
        assert request["kill_switch_generation"] == CTX["kill_switch_generation"]
        assert any(sample // MS == request["monotonic_ms"] for sample in samples)
    assert len({first["request_nonce"], second["request_nonce"], third["request_nonce"]}) == 3


@POSIX_FORK
def test_activation_never_refreshes_lifetime_and_renewal_swaps_without_closing_the_retired_handle(
        monkeypatch, tmp_path, signals):
    """STATE-MACHINE ONLY: three renewals write one ``create … timeout 3000ms`` and one
    ``destroy; add`` (no lifetime) per cycle, each with a new mark; a superseded handle is retired and
    never closed (``close`` destroys by tuple and would remove the new activation)."""
    h = harness(monkeypatch, tmp_path)
    for _ in range(3):
        assert h.cycle.tick() == "serving"
    assert h.installer.kinds() == ["prepare", "activate"] * 3 and "close" not in h.domain.calls
    for index, batch in enumerate(h.installer.batches):
        mark = f"{index // 2 + 1:#010x}"
        if index % 2 == 0:
            assert batch == authority._render_prepare(L, R, index // 2 + 1, cycle.LEASE_MS)
        else:
            assert batch == authority._render_activate(L, R, index // 2 + 1) and b"timeout" not in batch
        assert mark.encode() in batch
    assert h.cycle._current.mark == 3 and h.cycle._retired == 2
    assert h.status()["authorized"] == "true"


@POSIX_FORK
def test_lost_reply_keeps_the_previous_proven_window_advances_sequence_and_never_replays(monkeypatch, tmp_path, signals):
    """STATE-MACHINE ONLY: after an activation, a lost reply proves no new window: the previous
    window continues to ``min(E_upper, D)`` (authorized stays true, same deadline), the next request
    uses ``sequence + 1`` (never the lost one again), and three consecutive non-replies end the
    context ``cp_unreachable`` (class A: close the current handle, flush the generation)."""
    h = Harness(monkeypatch, tmp_path)
    h.script.steps = [active(), ("fail", "cp_timeout"), active(), ("fail", "connect_failed"), ("fail", "late_reply"),
                      ("fail", "malformed_reply")]
    h.serve()
    h.cycle.tick()
    bound = h.cycle._windows[0].bound
    h.cycle.tick()
    status = h.status()
    assert (status["last_reason"], status["authorized"], status["consecutive_unavailable"]) == ("cp_timeout", "true", 1)
    assert h.cycle._current_bound == bound and len(h.cycle._windows) == 1
    h.cycle.tick()
    assert h.status()["consecutive_unavailable"] == 0 and len(h.cycle._windows) == 2
    for _ in range(3):
        h.cycle.tick()
    assert [request["sequence"] for request in h.script.requests] == [1, 2, 3, 4, 5, 6]
    assert len({request["request_nonce"] for request in h.script.requests}) == 6
    status = h.status()
    assert (status["generation_phase"], status["context_end_reason"]) == ("closed", "cp_unreachable")
    assert h.domain.calls[-2:] == ["close", "close_generation"]


# ---------------------------------------------------------------------------------------------
# Context ends, refusals and the transition table (R section 4.4).

def _ends(h: Harness, row: str) -> None:
    if row == "context_mismatch":
        h.script.steps = [active(), active(run_id="crun_" + "2" * 32)]
    elif row == "stale_durations":
        h.script.steps = [active(), active(grant_expires_at_ms=1_700_000_000_000)]
    elif row == "proof_revoked":
        h.script.steps = [active(), inactive("proof_revoked")]
    elif row == "cp_unreachable":
        h.script.steps = [active(), ("fail", "cp_timeout"), ("fail", "cp_unavailable"), ("fail", "peer_identity")]


@POSIX_FORK
@pytest.mark.parametrize("row", ["context_mismatch", "stale_durations", "proof_revoked", "cp_unreachable",
                                 "domain_exhausted", "stop_requested", "context_replaced", "generation_rotated"])
def test_every_context_end_closes_the_generation_and_a_replacement_needs_a_new_domain(monkeypatch, tmp_path, signals, row):
    """STATE-MACHINE ONLY (rows 4-7, 11, 23-25): every context end is class A: ``close(current)``
    when a handle was activated, then ``close_generation`` (flush, descriptor closed); the
    generation is ``closed``; the same generation refuses a second context; a new context needs
    ``start()`` again, which creates a new domain with a new generation id and sequence 1."""
    h = Harness(monkeypatch, tmp_path, counter=authority.MARK_MAX if row == "domain_exhausted" else None)
    _ends(h, row)
    if row == "generation_rotated":
        monkeypatch.setattr(cycle, "MAX_CYCLES_PER_GENERATION", 1)
    h.serve()
    h.cycle.tick()  # one activation first
    assert h.domain.calls == ["prepare", "activate"]
    if row == "stop_requested":
        h.cycle.stop()
    elif row == "context_replaced":
        h.cycle.stop_context()
    for _ in range(4):
        if h.status()["generation_phase"] == "closed":
            break
        h.cycle.tick()
    status = h.status()
    assert (status["generation_phase"], status["context_end_reason"], status["generation_class_end"]) == (
        "closed", row, "A"), status
    assert h.domain.calls[-2:] == ["close", "close_generation"] and h.domain.calls.count("close_generation") == 1
    assert h.installer.kinds()[-2:] == ["close", "flush"] and status["exit_required"] is False
    with pytest.raises(authority.DomainClosed):
        h.domain.ns_fd
    with pytest.raises(cycle.CycleError) as raised:
        h.cycle.install_context(cycle.CycleContext(**CTX))
    assert raised.value.code == "context_refused"
    first = h.domain
    h.clock.advance_ms(cycle.MIN_GENERATION_SPACING_MS)
    h.script.steps = []
    h.serve()
    assert h.domain is not first and h.domain.generation_id != first.generation_id
    h.cycle.tick()
    assert h.script.requests[-1]["sequence"] == 1 and h.script.requests[-1]["generation_id"] == h.domain.generation_id


@POSIX_FORK
@pytest.mark.parametrize("reason", NON_NONE_REASONS)
def test_inactive_reply_closes_current_handle_and_ends_context_with_the_reason(monkeypatch, tmp_path, signals, reason):
    """STATE-MACHINE ONLY: every one of the 23 non-``none`` reasons ends the context with that reason:
    the current handle is closed (one ``destroy`` by tuple), the generation is flushed and closed,
    and no further request is sent."""
    h = Harness(monkeypatch, tmp_path)
    h.script.steps = [active(), inactive(reason)]
    h.serve()
    h.cycle.tick()
    assert h.cycle.tick() == "closed"
    status = h.status()
    assert (status["context_end_reason"], status["last_decision"], status["generation_class_end"]) == (
        reason, "inactive", "A")
    assert h.installer.batches[-2:] == [authority._render_close(L, R), authority._render_flush()]
    h.cycle.tick()
    assert len(h.script.requests) == 2 and status["authorized"] in ("false", "unknown")


@POSIX_FORK
@pytest.mark.parametrize("reason", ["replayed_sequence", "clock_gap", "malformed_request", "tuple_mismatch",
                                    "kill_switch_generation_changed", "cp_draining"])
def test_generation_terminal_reasons_close_the_generation_and_flush_own_namespace(monkeypatch, tmp_path, signals, reason):
    """STATE-MACHINE ONLY: the ledger-terminal and CP-fault reasons flush the generation's own map in
    its own descriptor (``flush map inet heel_lease activated``) and close it; the domain refuses
    every later operation; a fresh generation supersedes with sequence 1."""
    h = Harness(monkeypatch, tmp_path)
    h.script.steps = [inactive(reason)]
    h.serve()
    assert h.cycle.tick() == "closed"
    assert h.installer.batches[-1] == authority._render_flush() and h.domain._closed
    assert h.domain.calls == ["prepare", "close_generation"]  # nothing was activated: no close
    with pytest.raises(authority.DomainClosed):
        h.domain.prepare(L, R, 100)


@POSIX_FORK
def test_prepare_and_activate_refusals_are_generation_terminal_and_key_failures_are_bounded_at_three(
        monkeypatch, tmp_path, signals):
    """STATE-MACHINE ONLY (rows 8-12): a refused prepare (``installer_refused`` is generic: EEXIST, a
    missing table or anything else) and a refused activate end the generation at once (class A); an
    uncertain prepare (timeout) and an erroring prepare are key outcomes counted together, and the
    third consecutive one ends the context ``key_failures``; ``DomainExhausted`` is terminal."""
    h = Harness(monkeypatch, tmp_path, plan=[1, 0]).serve()
    assert h.cycle.tick() == "closed"
    assert (h.status()["context_end_reason"], h.domain.calls) == ("prepare_refused", ["prepare", "close_generation"])
    monkeypatch.setattr(cycle, "_BUDGET", cycle._GenerationBudget())
    h = Harness(monkeypatch, tmp_path, plan=[0, 1, 0]).serve()
    assert h.cycle.tick() == "closed"
    assert (h.status()["context_end_reason"], h.domain.calls) == (
        "activate_refused", ["prepare", "activate", "close_generation"])
    monkeypatch.setattr(cycle, "_BUDGET", cycle._GenerationBudget())
    h = Harness(monkeypatch, tmp_path, plan=[("sleep", 1.6, 0), ("raise",), ("raise",), 0]).serve()
    h.cycle.tick()
    assert (h.status()["last_reason"], h.status()["consecutive_key_failures"]) == ("prepare_uncertain", 1)
    h.cycle.tick()
    assert (h.status()["last_reason"], h.status()["consecutive_key_failures"]) == ("prepare_error", 2)
    assert h.status()["generation_phase"] == "serving" and h.script.requests == []
    assert h.cycle.tick() == "closed" and h.status()["context_end_reason"] == "key_failures"
    monkeypatch.setattr(cycle, "_BUDGET", cycle._GenerationBudget())
    h = Harness(monkeypatch, tmp_path, plan=[("raise",), 0, 0, ("raise",), ("raise",), 0]).serve()
    h.cycle.tick()
    h.cycle.tick()  # a successful key resets the counter
    assert h.status()["consecutive_key_failures"] == 0
    h.cycle.tick()
    h.cycle.tick()
    assert h.status()["generation_phase"] == "serving" and h.status()["consecutive_key_failures"] == 2


@POSIX_FORK
def test_repeated_unusable_replies_end_the_context_authority_unusable(monkeypatch, tmp_path, signals):
    """STATE-MACHINE ONLY (rows 2, 3): three consecutive ``authority_too_short``/``key_expiring``
    outcomes end the context ``authority_unusable``; nothing was activated."""
    h = Harness(monkeypatch, tmp_path)
    h.script.steps = [active(rem_ms=2000), active(rem_ms=2000), active(rem_ms=2000)]
    h.serve()
    h.cycle.tick()
    h.cycle.tick()
    assert h.status()["consecutive_unusable"] == 2
    assert h.cycle.tick() == "closed" and h.status()["context_end_reason"] == "authority_unusable"
    assert "activate" not in h.domain.calls


@POSIX_FORK
@pytest.mark.parametrize("row", ["activation_uncertain", "activation_error", "close_failed", "flush_failed"])
def test_unknown_activation_outcome_and_close_failure_flush_and_never_serve_the_namespace_again(
        monkeypatch, tmp_path, signals, row):
    """STATE-MACHINE ONLY (rows 13, 14, 16, 17): an activation whose outcome is unknown (timeout) or
    errored is class B: no ``close``, one flush, the namespace never served again; a failed ``close``
    during an orderly end escalates to class B; a failed flush is class C (quarantine, exit
    required, no further domain call). The residual bound is reported, never zero."""
    plan = {"activation_uncertain": [0, ("sleep", 1.6, 0), 0], "activation_error": [0, ("raise",), 0],
            "close_failed": [0, 0, 0, 1, 0], "flush_failed": [0, 0, 0, 0, 1]}[row]
    h = Harness(monkeypatch, tmp_path, plan=plan)
    if row in ("close_failed", "flush_failed"):
        h.script.steps = [active(), inactive("stop_requested")]
    h.serve()
    for _ in range(2):
        if h.status()["generation_phase"] in ("closed", "quarantined"):
            break
        h.cycle.tick()
    status = h.status()
    expected = {"activation_uncertain": ("closed", "B", ["prepare", "activate", "close_generation"]),
                "activation_error": ("closed", "B", ["prepare", "activate", "close_generation"]),
                "close_failed": ("closed", "B", ["prepare", "activate", "prepare", "close", "close_generation"]),
                "flush_failed": ("quarantined", "C", ["prepare", "activate", "prepare", "close", "close_generation"])}[row]
    assert (status["generation_phase"], status["generation_class_end"], h.domain.calls) == expected, status
    assert status["context_end_reason" if row != "flush_failed" else "quarantine_code"] == row
    assert status["exit_required"] is (row == "flush_failed")
    assert status["residual"] == "bounded" and status["residual_bound_ms"] > 0
    assert status["authorized"] == "unknown"
    calls = list(h.domain.calls)
    h.cycle.tick()
    h.cycle.tick()
    assert h.domain.calls == calls
    with pytest.raises(cycle.CycleError):
        h.cycle.install_context(cycle.CycleContext(**CTX))


@POSIX_FORK
def test_residual_bound_is_the_max_over_all_activated_windows_and_is_reported_while_any_child_is_unresolved_even_after_a_flush(
        monkeypatch, tmp_path, signals):
    """STATE-MACHINE ONLY (row 13 and rule R): the second key's window outlives the first; its
    activation outcome is unknown (timeout), so the residual is ``max(min(E_upper_i, D_i))`` over
    both keys, the second one, even after the flush returned. Separately, a clean orderly end claims
    zero only while the process-global registry is empty: one ``handed_off`` entry from an unrelated
    domain keeps the residual bounded."""
    h = Harness(monkeypatch, tmp_path, plan=[0, 0, 0, ("sleep", 1.6, 0), 0])
    h.script.steps = [active(rem_ms=4000), active(rem_ms=60_000)]
    h.serve()
    h.cycle.tick()
    first = h.cycle._windows[0]
    assert first.bound == first.e_upper <= first.deadline  # activation requires E_upper <= D
    h.cycle.tick()
    second = h.cycle._windows[1]
    assert second.bound == second.e_upper > first.bound
    status = h.status()
    assert (status["generation_class_end"], status["context_end_reason"]) == ("B", "activation_uncertain")
    assert h.cycle._residual_ns == max(first.bound, second.bound) == second.bound
    now = h.clock()
    assert status["residual"] == "bounded" and 0 < status["residual_bound_ms"] <= (second.bound - now) // MS + 1
    # Clean orderly end, empty registry (a fresh process budget: no earlier unproven residual): zero.
    monkeypatch.setattr(cycle, "_BUDGET", cycle._GenerationBudget())
    clean = Harness(monkeypatch, tmp_path)
    clean.script.steps = [active(), inactive("stop_requested")]
    clean.serve()
    clean.cycle.tick()
    clean.cycle.tick()
    assert (clean.status()["residual"], clean.status()["residual_bound_ms"]) == ("zero", 0)
    # The same end with one unrelated handed-off child anywhere in the process: bounded.
    monkeypatch.setattr(cycle, "_BUDGET", cycle._GenerationBudget())
    other = Harness(monkeypatch, tmp_path)
    other.script.steps = [active(), inactive("stop_requested")]
    other.serve()
    other.cycle.tick()
    real_flush = other.domain._domain.close_generation

    def flush_then_unrelated_hand_off():
        real_flush()
        authority._UNREAPED.add(authority._Child(0x7FFF_FF42, "handed_off"))

    other.domain._domain.close_generation = flush_then_unrelated_hand_off
    other.cycle.tick()
    status = other.status()
    assert status["generation_phase"] == "closed" and status["residual"] == "bounded"
    assert status["unresolved_children"]["handed_off"] == 1 and status["residual_bound_ms"] > 0
    assert other.cycle._residual_ns == other.cycle._windows[0].bound


# ---------------------------------------------------------------------------------------------
# Signals (R section 5).

def test_signal_handler_is_one_attribute_store_and_a_real_sigterm_under_the_cycle_lock_returns(signals):
    source = CYCLE_FILE.read_text(encoding="utf-8")
    handler = next(node for node in ast.walk(ast.parse(source))
                   if isinstance(node, ast.FunctionDef) and node.name == "_on_stop_signal")
    assert len(handler.body) == 1 and isinstance(handler.body[0], ast.Assign)
    (target,) = handler.body[0].targets
    assert ast.unparse(target) == "_STATE.stop_requested" and ast.unparse(handler.body[0].value) == "True"
    assert cycle._SignalState.__slots__ == ("stop_requested",)
    for signum in cycle.STOP_SIGNALS:
        assert signal.getsignal(signum) is cycle._on_stop_signal
    lock = threading.Lock()
    with lock:
        os.kill(os.getpid(), signal.SIGTERM)
        deadline = time.monotonic() + 5
        while not cycle._STATE.stop_requested and time.monotonic() < deadline:
            pass
        assert cycle._STATE.stop_requested is True and lock.locked()
    cycle._STATE.stop_requested = False
    os.kill(os.getpid(), signal.SIGINT)  # no KeyboardInterrupt once installed
    deadline = time.monotonic() + 5
    while not cycle._STATE.stop_requested and time.monotonic() < deadline:
        pass
    assert cycle._STATE.stop_requested is True


@POSIX_FORK
def test_signal_context_sets_flags_never_raises_and_refuses_sigchld_ignore(monkeypatch, tmp_path, signals):
    """STATE-MACHINE ONLY: a real SIGTERM sent while a recorded prepare child runs only sets the flag;
    the cycle honours it at the poll point after ``prepare`` (before any request) with an orderly
    stop (class A, ``exit_required`` false); nothing raises."""
    h = Harness(monkeypatch, tmp_path, plan=[("sleep", 0.4, 0), 0]).serve()
    timer = threading.Timer(0.1, os.kill, (os.getpid(), signal.SIGTERM))
    timer.start()
    try:
        assert h.cycle.tick() == "closed"
    finally:
        timer.join()
    status = h.status()
    assert (status["context_end_reason"], status["exit_required"]) == ("stop_requested", False)
    assert h.script.requests == [] and h.domain.calls == ["prepare", "close_generation"]
    signal.signal(signal.SIGCHLD, signal.SIG_IGN)
    with pytest.raises(cycle.SignalContextInvalid) as raised:
        cycle.install_signal_context()
    assert raised.value.code == "sigchld_ignored"


def test_install_refuses_sigchld_ignore_or_custom_handler_and_any_foreign_python_handler():
    def foreign(_signum, _frame):
        raise RuntimeError("a handler that may raise")

    before = {signum: signal.getsignal(signum) for signum in cycle.STOP_SIGNALS}
    cases = [(signal.SIGCHLD, signal.SIG_IGN, "sigchld_ignored"), (signal.SIGCHLD, foreign, "sigchld_custom_handler"),
             (signal.SIGALRM, foreign, "foreign_signal_handler"), (signal.SIGUSR1, foreign, "foreign_signal_handler"),
             (signal.SIGTERM, foreign, "foreign_signal_handler")]
    for signum, handler, code in cases:
        previous = signal.signal(signum, handler)
        try:
            with pytest.raises(cycle.SignalContextInvalid) as raised:
                cycle.install_signal_context()
            assert raised.value.code == code
            assert {s: signal.getsignal(s) for s in cycle.STOP_SIGNALS if s != signum} == {
                s: h for s, h in before.items() if s != signum}  # nothing was installed
        finally:
            signal.signal(signum, previous)
    results = []
    thread = threading.Thread(target=lambda: results.append(_install_code()))
    thread.start()
    thread.join(5)
    assert results == ["not_main_thread"]
    cycle.install_signal_context()
    cycle.verify_signal_context()
    previous = signal.signal(signal.SIGUSR2, foreign)
    try:
        with pytest.raises(cycle.SignalContextInvalid) as raised:
            cycle.verify_signal_context()
        assert raised.value.code == "signal_context_invalid"
    finally:
        signal.signal(signal.SIGUSR2, previous)
    cycle.verify_signal_context()
    signal.signal(signal.SIGHUP, signal.SIG_DFL)
    with pytest.raises(cycle.SignalContextInvalid):
        cycle.verify_signal_context()


def _install_code() -> str:
    try:
        cycle.install_signal_context()
    except cycle.SignalContextInvalid as error:
        return error.code
    return "installed"


@POSIX_FORK
def test_generation_start_refuses_an_unverified_signal_context(monkeypatch, tmp_path):
    """STATE-MACHINE ONLY: without ``install_signal_context`` (or after a handler changed) a
    generation start is refused ``signal_context_invalid`` before any domain exists; it counts
    against the budget."""
    h = Harness(monkeypatch, tmp_path)
    assert h.cycle.start() == "closed"
    assert (h.status()["last_reason"], h.domains, cycle._BUDGET.generations) == ("signal_context_invalid", [], 1)


@POSIX_FORK
def test_escaped_base_exception_in_a_domain_call_quarantines_once_and_never_retries(monkeypatch, tmp_path, signals):
    """STATE-MACHINE ONLY (row 21): a ``KeyboardInterrupt`` injected inside a recorded ``prepare``
    escapes the domain call. The cycle records ``quarantined(operation_interrupted)``, makes exactly
    one best-effort ``close_generation``, sets ``exit_required`` and re-raises; afterwards no domain
    call happens, no new generation starts in this process and no zero residual is ever claimed."""
    h = harness(monkeypatch, tmp_path)
    real_await, fired = authority._await, []

    def interrupted(child, sink_r, timeout_ms):
        result = real_await(child, sink_r, timeout_ms)
        if not fired:
            fired.append(True)
            raise KeyboardInterrupt
        return result

    monkeypatch.setattr(authority, "_await", interrupted)
    with pytest.raises(KeyboardInterrupt):
        h.cycle.tick()
    status = h.status()
    assert (status["generation_phase"], status["quarantine_code"], status["exit_required"]) == (
        "quarantined", "operation_interrupted", True)
    assert h.domain.calls == ["prepare", "close_generation"] and h.installer.kinds() == ["prepare", "flush"]
    h.cycle.tick()
    h.cycle.stop()
    assert h.domain.calls == ["prepare", "close_generation"] and h.script.requests == []
    h.clock.advance_ms(cycle.MIN_GENERATION_SPACING_MS)
    assert h.cycle.start() == "quarantined" and len(h.domains) == 1
    fresh = Harness(monkeypatch, tmp_path)
    assert fresh.cycle.start() == "quarantined" and fresh.domains == []
    assert fresh.status()["exit_required"] is True and cycle._BUDGET.lost_child is True


# ---------------------------------------------------------------------------------------------
# Unresolved children (R section 6).

@pytest.mark.parametrize("state", REGISTRY_KEYS)
def test_registry_reader_reports_all_six_states_and_other_and_only_handed_off_or_reaped_may_drain(
        monkeypatch, tmp_path, signals, state):
    """STATE-MACHINE ONLY: a registry entry in any state is reported; ``owned``/``looking`` entries are
    constructed exactly as an interruption between ``_kill_and_reap``'s registry insert and its state
    store leaves them (and as the holder regression builds them). ``owned``, ``looking``, ``sweeping``,
    ``uncertain`` and any unknown state quarantine (``child_uncertain``); only ``handed_off`` and
    ``reaped`` enter ``draining``; no prepare happens in either case."""
    if not hasattr(os, "fork"):
        pytest.skip("needs os.fork")
    h = harness(monkeypatch, tmp_path)
    authority._UNREAPED.add(authority._Child(0x7FFF_FF10, "bogus-state" if state == "other" else state))
    counts = authority.unresolved_children()
    assert counts == {key: int(key == state) for key in REGISTRY_KEYS}
    assert cycle.classify_children(counts) == ("drain" if state in ("handed_off", "reaped") else "uncertain")
    phase = h.cycle.tick()
    assert h.domain.calls == ([] if state in ("handed_off", "reaped") else ["close_generation"])
    if state in ("handed_off", "reaped"):
        assert phase == "draining" and h.status()["exit_required"] is False
    else:
        status = h.status()
        assert (phase, status["quarantine_code"], status["exit_required"]) == ("quarantined", "child_uncertain", True)
        # The best-effort flush child's own sweep (``_run``) records an interrupted sweep look uncertain.
        assert status["unresolved_children"]["uncertain" if state == "sweeping" else state] == 1


@POSIX_FORK
def test_interrupted_hand_off_leaves_an_owned_or_looking_entry_that_quarantines(monkeypatch, tmp_path, signals):
    """STATE-MACHINE ONLY: the interruption lands between ``_UNREAPED.add(child)`` and the state store
    in ``_kill_and_reap`` (the registry insert raises after inserting): the entry stays ``looking``
    (the uncertain branch) in the registry; the cycle's next tick quarantines on it."""
    h = harness(monkeypatch, tmp_path)

    class InterruptedAdd(set):
        def add(self, item):
            super().add(item)
            raise KeyboardInterrupt

    registry = InterruptedAdd()
    monkeypatch.setattr(authority, "_UNREAPED", registry)
    child = authority._Child(0x7FFF_FF20, authority._LOOKING)
    with pytest.raises(KeyboardInterrupt):
        authority._kill_and_reap(child)
    assert child.state == "looking" and child in registry
    assert authority.unresolved_children()["looking"] == 1
    assert h.cycle.tick() == "quarantined" and h.status()["quarantine_code"] == "child_uncertain"


@POSIX_FORK
@pytest.mark.parametrize("outcome", ["stranded", "cleared"])
def test_draining_calls_only_sweep_unresolved_children_and_strands_after_five_ticks(monkeypatch, tmp_path, signals, outcome):
    """STATE-MACHINE ONLY: a real installer child whose SIGKILL is made ineffective (a stand-in for a
    child stuck in the kernel) times out in ``prepare`` and is handed to the sweep. The cycle then
    drains: each tick calls ``sweep_unresolved_children()`` once and nothing on the domain; five
    draining ticks with the child still present quarantine ``child_stranded``; if the child ends, the
    sweep reaps it and the generation serves again."""
    h = Harness(monkeypatch, tmp_path, plan=[("sleep", 30, 0)]).serve()
    real_kill = authority.os.kill

    def kill(pid, signum):
        if pid in h.installer.pids and signum == signal.SIGKILL:
            return
        real_kill(pid, signum)

    monkeypatch.setattr(authority.os, "kill", kill)
    sweeps = []
    real_sweep = authority.sweep_unresolved_children
    monkeypatch.setattr(authority, "sweep_unresolved_children", lambda: sweeps.append(1) or real_sweep())
    try:
        h.cycle.tick()
        assert h.status()["last_reason"] == "prepare_uncertain"
        assert authority.unresolved_children()["handed_off"] == 1
        assert h.cycle.tick() == "draining" and h.domain.calls == ["prepare"] and sweeps == []
        if outcome == "stranded":
            for count in range(1, 6):
                phase = h.cycle.tick()
                assert len(sweeps) == count and h.domain.calls[:1] == ["prepare"]
                if count < 5:
                    assert phase == "draining" and h.domain.calls == ["prepare"]
            assert phase == "quarantined" and h.status()["quarantine_code"] == "child_stranded"
            assert h.domain.calls == ["prepare", "close_generation"]
        else:
            h.cycle.tick()
            real_kill(h.installer.pids[0], signal.SIGKILL)
            time.sleep(0.2)
            deadline = time.monotonic() + 10
            while h.cycle.tick() == "draining":
                assert time.monotonic() < deadline and len(sweeps) < 5
                time.sleep(0.01)
            assert h.status()["generation_phase"] == "serving" and h.domain.calls == ["prepare"]
            h.cycle.tick()
            assert h.domain.calls == ["prepare", "prepare", "activate"]
    finally:
        with_pid = [pid for pid in h.installer.pids]
        monkeypatch.setattr(authority.os, "kill", real_kill)
        for pid in with_pid:
            try:
                real_kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        deadline = time.monotonic() + 10
        while authority._UNREAPED and any(child.state == "handed_off" for child in authority._UNREAPED):
            authority._sweep_unreaped()
            if time.monotonic() > deadline:
                break
            time.sleep(0.01)


@POSIX_FORK
def test_unresolved_children_block_admission_handed_off_drains_uncertain_quarantines(monkeypatch, tmp_path, signals):
    """STATE-MACHINE ONLY: the registry rule also runs between the reply and ``activate``: an entry
    that appears while the request is outstanding prevents the activation (drain) or quarantines."""
    for state, phase in (("handed_off", "draining"), ("uncertain", "quarantined")):
        monkeypatch.setattr(cycle, "_BUDGET", cycle._GenerationBudget())
        monkeypatch.setattr(authority, "_UNREAPED", set())
        h = Harness(monkeypatch, tmp_path)

        def appear(request, state=state):
            authority._UNREAPED.add(authority._Child(0x7FFF_FF30, state))
            return active()(request)

        h.script.steps = [appear]
        h.serve()
        assert h.cycle.tick() == phase
        assert "activate" not in h.domain.calls


# ---------------------------------------------------------------------------------------------
# Generation start (R section 7.3): budget, profile, K9, witness.

@POSIX_FORK
def test_generation_restarts_are_bounded_and_spaced(monkeypatch, tmp_path, signals):
    """STATE-MACHINE ONLY: the budget is process-wide (a new HostCycle does not reset it): a second
    generation less than 10 s after the first, or a ninth generation, is quarantine
    ``generation_budget`` with ``exit_required``; nothing is created for it."""
    h = Harness(monkeypatch, tmp_path)
    assert h.cycle.start() == "ready"
    h.cycle.stop()
    h.clock.advance_ms(cycle.MIN_GENERATION_SPACING_MS - 1000)  # under 10 s even with real time elapsed
    assert h.cycle.start() == "quarantined" and h.status()["quarantine_code"] == "generation_budget"
    assert len(h.domains) == 1 and h.status()["exit_required"] is True
    monkeypatch.setattr(cycle, "_BUDGET", cycle._GenerationBudget())
    created = 0
    for index in range(cycle.MAX_GENERATIONS_PER_PROCESS):
        h = Harness(monkeypatch, tmp_path)
        h.clock.advance_ms(index * cycle.MIN_GENERATION_SPACING_MS)
        assert h.cycle.start() == "ready"
        created += len(h.domains)
        h.cycle.stop()
    h = Harness(monkeypatch, tmp_path)
    h.clock.advance_ms(cycle.MAX_GENERATIONS_PER_PROCESS * cycle.MIN_GENERATION_SPACING_MS)
    assert h.cycle.start() == "quarantined" and h.domains == [] and created == 8
    assert h.status()["quarantine_code"] == "generation_budget"


@POSIX_FORK
@pytest.mark.parametrize("report, reason", [
    (pinned_report(), None),
    (authority.SelfTestReport("pass", (), types.MappingProxyType({"kernel_major_minor": "6.1", "nft_version": "1.0.9",
                                                                  "selftest": "pass", "readd_observation": "refresh"}),
                              types.MappingProxyType({"config_hz": 1000})), "profile_unpinned"),
    (authority.SelfTestReport("pass", (), types.MappingProxyType({"kernel_major_minor": "6.17", "nft_version": "1.1.0",
                                                                  "selftest": "pass", "readd_observation": "refresh"}),
                              types.MappingProxyType({"config_hz": 1000})), "profile_unpinned"),
    (pinned_report(config_hz=300), "profile_unpinned"),
    (authority.SelfTestReport("pass", (), types.MappingProxyType({"kernel_major_minor": "6.17", "nft_version": "1.0.9",
                                                                  "selftest": "pass", "readd_observation": "noop"}),
                              types.MappingProxyType({"config_hz": 1000})), "profile_unpinned"),
    (authority.SelfTestReport("pass", (), types.MappingProxyType({"kernel_major_minor": "6.17", "nft_version": "1.0.9",
                                                                  "selftest": "pass", "readd_observation": "refresh"}),
                              types.MappingProxyType({})), "profile_unpinned"),
    ("quarantined", "selftest_failed"),
], ids=["pinned", "kernel", "nft", "hz", "readd", "no-hz", "selftest"])
def test_profile_grading_requires_tag_nft_hz_selftest_and_readd_and_quarantines_unpinned(
        monkeypatch, tmp_path, signals, report, reason):
    """STATE-MACHINE ONLY (scripted self-test reports): a generation reaches ``ready`` only with the
    graded profile ``("pinned", [])``; anything else refuses the start (the domain created for it is
    closed and the attempt counts against the budget)."""
    if report == "quarantined":
        failed = authority.SelfTestReport("fail", ("k1_no_live_delivery",), types.MappingProxyType({}),
                                          types.MappingProxyType({}))

        def raising(_domain):
            raise authority.HostQuarantined(failed)

        h = Harness(monkeypatch, tmp_path)
        h.cycle._self_test = raising
    else:
        h = Harness(monkeypatch, tmp_path, report=report)
    phase = h.cycle.start()
    if reason is None:
        assert phase == "ready" and h.status()["kernel_profile"] == "pinned"
        return
    status = h.status()
    assert (phase, status["last_reason"], status["generation_class_end"]) == ("closed", reason, "start_refused")
    assert h.domain.calls == ["close_generation"] and cycle._BUDGET.generations == 1
    assert status["kernel_profile"] in ("unpinned", "unknown")


@POSIX_FORK
@pytest.mark.parametrize("change", [
    {"unit_suspend": "not_masked"}, {"unit_hibernate": "unknown"}, {"sleep_conf": "incomplete"},
    {"sleep_conf": "missing"}, {"hibernation": "enabled"}, {"hibernation": "unknown"}, {"unit_sleep": None},
])
def test_k9_sleep_enforcement_refuses_unmasked_units_incomplete_conf_or_enabled_hibernation(
        monkeypatch, tmp_path, signals, change):
    """STATE-MACHINE ONLY (scripted A-1/A-2 reports): every unit masked, the drop-in all disabled
    and hibernation disabled are required at generation start; anything else is ``sleep_capable``."""
    def report():
        values = compliant_sleep()
        for key, value in change.items():
            if value is None:
                values.pop(key)
            else:
                values[key] = value
        return values

    h = Harness(monkeypatch, tmp_path, sleep=report)
    assert h.cycle.start() == "closed" and h.status()["last_reason"] == "sleep_capable"
    assert Harness(monkeypatch, tmp_path).cycle.start() == "quarantined"  # spacing: same process, < 10 s


@POSIX_FORK
@pytest.mark.parametrize("where", ["before_prepare", "before_activate"])
def test_clock_gap_before_prepare_or_activate_closes_generation(monkeypatch, tmp_path, signals, where):
    """STATE-MACHINE ONLY (scripted witness): a witness gap seen before ``prepare`` or before
    ``activate`` ends the generation class B ``clock_gap_host`` (flush only); detection, not safety."""
    gap = SteadyWitness()
    h = Harness(monkeypatch, tmp_path, witness=gap)
    if where == "before_prepare":
        h.serve()
        gap.armed = True
    else:
        def arm(request):
            gap.armed = True
            return active()(request)
        h.script.steps = [arm]
        h.serve()
    assert h.cycle.tick() == "closed"
    status = h.status()
    assert (status["context_end_reason"], status["generation_class_end"]) == ("clock_gap_host", "B")
    assert h.domain.calls == (["close_generation"] if where == "before_prepare" else ["prepare", "close_generation"])
    assert status["witness_gaps"] == 1


@POSIX_FORK
def test_witness_unavailable_at_start_is_clock_unavailable(monkeypatch, tmp_path, signals):
    """STATE-MACHINE ONLY: a witness that cannot sample refuses the generation start."""
    class Missing:
        def sample(self):
            raise authority.ClockUnavailable("clock_missing")

    h = Harness(monkeypatch, tmp_path, witness=Missing())
    assert h.cycle.start() == "closed" and h.status()["last_reason"] == "clock_unavailable"


# ---------------------------------------------------------------------------------------------
# Profile module (R section 7.1-7.2).

def test_profile_grading_matches_h1f_over_the_full_vector_matrix():
    h1f = _load("heel_h1f_launcher_profile_drift", H1F_FILE)
    assert (profile.SUPPORTED_KERNELS, profile.SUPPORTED_NFT, profile.SUPPORTED_HZ, profile.READD_EXPECTED) == (
        h1f.SUPPORTED_KERNELS, h1f.SUPPORTED_NFT, h1f.SUPPORTED_HZ, h1f.READD_EXPECTED)
    vectors = 0
    for kernel, nft, hz, selftest, readd in itertools.product(
            ("6.8", "6.17", "7.0", "6.1", "unparsed", None), ("1.0.9", "1.1.0", "unparsed", None),
            (100, 250, 1000, 300, None), ("pass", "fail", None), ("noop", "refresh", "error", "unreadable", "other", None)):
        fields = {"kernel_major_minor": kernel, "nft_version": nft, "config_hz": hz, "selftest": selftest,
                  "readd_observation": readd}
        sparse = {key: value for key, value in fields.items() if value is not None}
        assert profile.kernel_profile(fields) == h1f.kernel_profile(fields), fields
        assert profile.kernel_profile(sparse) == h1f.kernel_profile(sparse), sparse
        report = authority.SelfTestReport(
            "pass", (), types.MappingProxyType({key: value for key, value in sparse.items() if key != "config_hz"}),
            types.MappingProxyType({"config_hz": hz} if hz is not None else {}))
        assert profile.profile_fields_of(report) == fields
        assert profile.grade_self_test(report) == h1f.kernel_profile(fields)
        vectors += 1
    assert vectors == 6 * 4 * 5 * 3 * 6
    source = PROFILE_FILE.read_text(encoding="utf-8")
    assert "scripts" not in source.replace("scripts/host_lease_feasibility.py", "") and "tests" not in source
    assert not [node for node in ast.walk(ast.parse(source)) if isinstance(node, (ast.Import, ast.ImportFrom))
                and any(alias.name.split(".")[0] not in ("math",) for alias in node.names)]
    with pytest.raises(KeyError):
        profile.tick_ns(authority.SelfTestReport("pass", (), types.MappingProxyType({}), types.MappingProxyType({})))


def test_profile_constants_equal_the_h1f_pin():
    """The production constants equal the H1F pin (the H1F launcher is not edited). The authority
    proof launcher still imports H1F's grading in this task; moving it to the production module is
    H1A3-2 (its static ``is h1f`` assertion stays true here)."""
    h1f = _load("heel_h1f_launcher_profile_pin", H1F_FILE)
    assert profile.SUPPORTED_KERNELS == h1f.SUPPORTED_KERNELS == {"6.8": "v6.8", "6.17": "v6.17", "7.0": "v7.0"}
    assert profile.READD_EXPECTED == h1f.READD_EXPECTED and profile.SUPPORTED_NFT == ("1.0.9",)
    assert profile.SUPPORTED_HZ == (100, 250, 1000)
    launcher = (ROOT / "scripts" / "host_authority_proof.py").read_text(encoding="utf-8")
    assert "deploy\" / \"host\" / \"profile.py" not in launcher


# ---------------------------------------------------------------------------------------------
# The private client (prior sections 3.1-3.3) over real AF_UNIX socket pairs.

def _reply_bytes(request: dict, *, status=b"HTTP/1.1 200 OK", headers=None, body=None) -> bytes:
    payload = codec.canonical(active()(request)) if body is None else body
    lines = headers if headers is not None else [b"Content-Type: application/json",
                                                  b"Content-Length: %d" % len(payload), b"Cache-Control: no-store",
                                                  b"Connection: close"]
    return status + b"\r\n" + b"\r\n".join(lines) + b"\r\n\r\n" + payload


def _serve_once(server: socket.socket, respond, received: list) -> threading.Thread:
    def run():
        with server:
            server.settimeout(5)
            data = b""
            try:
                while b"\r\n\r\n" not in data:
                    chunk = server.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                head, _sep, rest = data.partition(b"\r\n\r\n")
                length = int(re.search(rb"Content-Length: (\d+)", head).group(1)) if head else 0
                while len(rest) < length:
                    rest += server.recv(4096)
            except (OSError, AttributeError):
                received.append(None)
                return
            received.append((head, rest))
            if rest:
                respond(server, json.loads(rest))

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


def _exchange(respond, *, deadline_ms=1000, clock=time.monotonic_ns, request=None):
    request = request or {**_request(), "request_nonce": secrets.token_hex(16)}
    client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    received: list = []
    thread = _serve_once(server, respond, received)
    started = time.monotonic_ns()
    try:
        result = cycle.exchange_on(client, request, started + deadline_ms * MS, clock=clock)
    except cycle.ExchangeFailed as error:
        result = error.code
    elapsed_s = (time.monotonic_ns() - started) / 1e9  # the exchange alone, before the peer is joined
    client.close()
    thread.join(5)
    return result, received, request, elapsed_s


def _send(raw_of):
    def respond(server, request):
        with __import__("contextlib").suppress(OSError):
            server.sendall(raw_of(request))
    return respond


def test_client_bounds_connect_write_read_and_validate_under_one_absolute_deadline():
    """STATE-MACHINE ONLY (socket pairs stand in for the CP connection): one absolute deadline
    bounds every read: a silent peer, a peer that trickles a byte every 100 ms and a deadline that
    is already over all end ``cp_timeout`` within the deadline plus slack; a reply whose read
    completes after the deadline is ``late_reply``; a valid reply passes; the request on the wire
    is exactly the canonical body with the fixed head."""
    reply, received, request, _elapsed = _exchange(_send(lambda request: _reply_bytes(request)))
    assert reply == active()(request) and received[0][1] == codec.canonical(request)
    assert received[0][0] == (b"POST /host/v1/authority-snapshot HTTP/1.1\r\nContent-Type: application/json\r\n"
                              b"Content-Length: %d\r\nConnection: close" % len(codec.canonical(request)))
    code, _received, _request_sent, elapsed = _exchange(lambda server, request: time.sleep(1.0), deadline_ms=300)
    assert code == "cp_timeout" and 0.3 <= elapsed < 0.3 + 0.5

    def trickle(server, request):
        with __import__("contextlib").suppress(OSError):
            for byte in _reply_bytes(request):
                server.sendall(bytes([byte]))
                time.sleep(0.1)

    code, _received, _request_sent, elapsed = _exchange(trickle, deadline_ms=300)
    assert code == "cp_timeout" and 0.3 <= elapsed < 0.3 + 0.5
    code, received, _request_sent, _elapsed = _exchange(_send(lambda request: _reply_bytes(request)), deadline_ms=-1)
    assert code == "cp_timeout" and received in ([None], [(b"", b"")])  # nothing was written
    # A reply whose last byte is read after the deadline is late_reply (read, then discarded).
    request = {**_request(), "request_nonce": secrets.token_hex(16)}
    client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    thread = _serve_once(server, _send(lambda request: _reply_bytes(request)), [])
    expected = len(_reply_bytes(request))
    late = []

    class ReadThenLate:
        """Forwards to the client socket; the clock passes the deadline once the whole reply was read."""

        def __init__(self):
            self.read = 0

        def settimeout(self, value):
            client.settimeout(value)

        def sendall(self, data):
            client.sendall(data)

        def recv(self, size):
            chunk = client.recv(size)
            self.read += len(chunk)
            if self.read >= expected:
                late.append(True)
            return chunk

    deadline = time.monotonic_ns() + 1000 * MS
    try:
        with pytest.raises(cycle.ExchangeFailed) as raised:
            cycle.exchange_on(ReadThenLate(), request, deadline,
                              clock=lambda: deadline + 1 if late else time.monotonic_ns())
        assert raised.value.code == "late_reply" and late
    finally:
        client.close()
        thread.join(5)


@pytest.mark.parametrize("variant, code", [
    ("status_500", "cp_unavailable"), ("status_400_malformed", "cp_unavailable"), ("garbage", "cp_unavailable"),
    ("nothing", "cp_unavailable"), ("oversized_head", "cp_unavailable"), ("oversized_body", "cp_unavailable"),
    ("chunked", "cp_unavailable"), ("duplicate_length", "cp_unavailable"), ("no_connection_close", "cp_unavailable"),
    ("wrong_content_type", "cp_unavailable"), ("wrong_digest", "malformed_reply"), ("wrong_sequence", "malformed_reply"),
    ("non_canonical", "malformed_reply"), ("nan", "malformed_reply"), ("not_object", "malformed_reply"),
    ("short_body", "cp_unavailable"),
])
def test_client_refuses_wrong_uid_pid_zero_oversized_head_body_and_chunked(variant, code):
    """STATE-MACHINE ONLY (socket pairs): every malformed transport or body is one fixed code. The
    uid/pid-zero refusals belong to ``connect_cp`` (mapped by ``test_client_maps_connect_refusals``
    and proven on Linux by the authority tests)."""
    def raw(request):
        good = codec.canonical(active()(request))
        return {
            "status_500": lambda: _reply_bytes(request, status=b"HTTP/1.1 500 Internal Server Error", body=b""),
            "status_400_malformed": lambda: _reply_bytes(request, status=b"HTTP/1.1 400 Bad Request",
                                                         body=codec.canonical(codec.MALFORMED)),
            "garbage": lambda: b"\x00\xffnot http at all\r\n\r\n",
            "nothing": lambda: b"",
            "oversized_head": lambda: _reply_bytes(request, headers=[b"Content-Type: application/json",
                                                                      b"Content-Length: %d" % len(good),
                                                                      b"Connection: close", b"X-Pad: " + b"a" * 1100]),
            "oversized_body": lambda: _reply_bytes(request, body=good + b" " * 4096),
            "chunked": lambda: _reply_bytes(request, headers=[b"Content-Type: application/json",
                                                               b"Transfer-Encoding: chunked", b"Connection: close"]),
            "duplicate_length": lambda: _reply_bytes(request, headers=[b"Content-Type: application/json",
                                                                        b"Content-Length: %d" % len(good),
                                                                        b"Content-Length: %d" % len(good),
                                                                        b"Connection: close"]),
            "no_connection_close": lambda: _reply_bytes(request, headers=[b"Content-Type: application/json",
                                                                           b"Content-Length: %d" % len(good)]),
            "wrong_content_type": lambda: _reply_bytes(request, headers=[b"Content-Type: text/plain",
                                                                          b"Content-Length: %d" % len(good),
                                                                          b"Connection: close"]),
            "wrong_digest": lambda: _reply_bytes(request, body=codec.canonical(active(request_digest="0" * 64)(request))),
            "wrong_sequence": lambda: _reply_bytes(request, body=codec.canonical(active(sequence=9)(request))),
            "non_canonical": lambda: _reply_bytes(request, body=json.dumps(active()(request)).encode()),
            "nan": lambda: _reply_bytes(request, body=good.replace(b'"server_time_ms":1700000000000',
                                                                    b'"server_time_ms":NaN')),
            "not_object": lambda: _reply_bytes(request, body=b"[]"),
            "short_body": lambda: _reply_bytes(request, headers=[b"Content-Type: application/json",
                                                                  b"Content-Length: %d" % (len(good) + 10),
                                                                  b"Connection: close"]),
        }[variant]()

    assert _exchange(_send(raw))[0] == code


def test_client_maps_connect_refusals_to_fixed_codes(monkeypatch):
    """STATE-MACHINE ONLY: ``connect_cp`` refusals keep their transport codes (``peer_identity``,
    ``connect_failed``, ``cp_timeout``); every static path/profile refusal is ``cp_unavailable``."""
    client = cycle.ControlPlaneClient("/run/heel/cp.sock", 0)
    for raised, expected in (("peer_identity", "peer_identity"), ("connect_failed", "connect_failed"),
                             ("cp_timeout", "cp_timeout"), ("socket_profile", "cp_unavailable"),
                             ("platform_unsupported", "cp_unavailable"), ("not_initial_pid_namespace", "cp_unavailable")):
        def refuse(path, cp_uid, deadline_ns, *, uid_map_path="/proc/self/uid_map", code=raised):
            raise authority.ControlPlaneUnavailable(code)
        monkeypatch.setattr(authority, "connect_cp", refuse)
        with pytest.raises(cycle.ExchangeFailed) as error:
            client.exchange(_request(), time.monotonic_ns() + 10 ** 9)
        assert error.value.code == expected


@POSIX_FORK
@pytest.mark.parametrize("failures", [["garbage", "status_500", "wrong_digest"], ["nothing", "status_400", "silent"]])
def test_lost_malformed_and_non_200_replies_advance_sequence_never_replay_and_are_bounded(
        monkeypatch, tmp_path, signals, failures):
    """STATE-MACHINE ONLY: the cycle's exchange is the real protocol code over a real AF_UNIX socket
    pair per request (SEAM-EXCHANGE replaces only ``connect_cp``). After one activation, three
    consecutive failed exchanges each advance the sequence (no request is ever resent), keep the
    previous window, and the third ends the context ``cp_unreachable``."""
    behaviours = ["good", *failures]
    requests = []

    def exchange(request, deadline_ns):
        requests.append(request)
        kind = behaviours.pop(0)
        client, server = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)

        def respond(server, request):
            raw = {"good": lambda: _reply_bytes(request), "garbage": lambda: b"junk\r\n\r\n",
                   "status_500": lambda: _reply_bytes(request, status=b"HTTP/1.1 500 Internal Server Error", body=b""),
                   "wrong_digest": lambda: _reply_bytes(request, body=codec.canonical(
                       active(request_digest="0" * 64)(request))),
                   "nothing": lambda: b"",
                   "status_400": lambda: _reply_bytes(request, status=b"HTTP/1.1 400 Bad Request",
                                                      body=codec.canonical(codec.MALFORMED)),
                   "silent": None}[kind]
            if raw is None:
                time.sleep(1.2)
                return
            with __import__("contextlib").suppress(OSError):
                server.sendall(raw())

        thread = _serve_once(server, respond, [])
        try:
            return cycle.exchange_on(client, request, deadline_ns)
        finally:
            client.close()
            thread.join(5)

    h = Harness(monkeypatch, tmp_path, exchange=exchange).serve()
    h.cycle.tick()
    assert h.domain.calls == ["prepare", "activate"]
    for _ in range(3):
        h.cycle.tick()
    assert [request["sequence"] for request in requests] == [1, 2, 3, 4]
    assert len({request["request_nonce"] for request in requests}) == 4
    assert h.status()["context_end_reason"] == "cp_unreachable"
    assert h.domain.calls == ["prepare", "activate", "prepare", "prepare", "prepare", "close", "close_generation"]


# ---------------------------------------------------------------------------------------------
# Status, logs, enablement and static shape.

STATUS_TOKEN = re.compile(r"[A-Ca-z0-9][a-z0-9_.:-]{0,79}")


@POSIX_FORK
def test_status_and_logs_are_fixed_tokens_only(monkeypatch, tmp_path, signals, caplog):
    """STATE-MACHINE ONLY: ``status()`` has a fixed key set of fixed tokens, integers and booleans
    (plus the fixed seven-key registry counts); one JSON log line per transition on
    ``heel.host.cycle`` carries the same keys and never a body, nonce, digest, path, pid or
    exception text."""
    caplog.set_level(logging.INFO, logger="heel.host.cycle")
    h = Harness(monkeypatch, tmp_path)
    h.script.steps = [active(), ("fail", "cp_timeout"), inactive("proof_revoked")]
    events = []
    h.cycle.on_transition(lambda event, status: events.append((event, status)))
    h.serve()
    for _ in range(3):
        h.cycle.tick()
    status = h.status()
    assert tuple(status) == cycle.STATUS_KEYS
    for key, value in status.items():
        if key == "unresolved_children":
            assert tuple(value) == REGISTRY_KEYS and all(type(count) is int for count in value.values())
        elif isinstance(value, bool) or type(value) is int:
            continue
        else:
            assert isinstance(value, str) and STATUS_TOKEN.fullmatch(value), (key, value)
    assert status["authorized"] in ("true", "false", "unknown")
    assert (status["runtime_assumption"], status["enablement"]) == ("running-kernel", "non_customer")
    records = [record for record in caplog.records if record.name == "heel.host.cycle"]
    assert len(records) == len(events) >= 4
    secrets_seen = {request["request_nonce"] for request in h.script.requests} | {
        CTX["grant_digest"], CTX["binding_digest"], CTX["public_key_digest"], CTX["verification_record_digest"],
        "/run/heel/cp.sock", str(tmp_path), *map(str, h.installer.pids)}
    for record in records:
        line = record.getMessage()
        document = json.loads(line)
        assert tuple(document) == ("event", *cycle.STATUS_KEYS)
        assert not any(secret in line for secret in secrets_seen if len(secret) > 4), line
    assert [event for event, _status in events][:3] == ["ready", "serving", "activated"]
    assert events[-1][0] == "closed"


def test_no_customer_enablement_member_flag_or_entry_point_exists():
    assert [member.name for member in cycle.Enablement] == ["NON_CUSTOMER"]
    for source in (CYCLE_FILE.read_text(encoding="utf-8"), PROFILE_FILE.read_text(encoding="utf-8")):
        for forbidden in ("os.environ", "getenv", "argparse", "sys.argv", "__main__", "def main", "HEEL_"):
            assert forbidden not in source, forbidden
    parameters = inspect.signature(cycle.HostCycle).parameters
    assert parameters["admission"].kind is inspect.Parameter.KEYWORD_ONLY
    assert parameters["admission"].default is inspect.Parameter.empty
    for admission in ("non_customer", None, 1):
        with pytest.raises(TypeError):
            cycle.HostCycle("slot-a", "/run/heel/cp.sock", 0, slot_src=L, slot_dst=R, admission=admission)
    with pytest.raises(TypeError):
        cycle.HostCycle("slot-a", "/run/heel/cp.sock", 0, slot_src=L, slot_dst=R)
    for path in (ROOT / "heel").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        assert "deploy/host/cycle" not in text and "HostCycle" not in text, path


def test_seams_are_test_only_and_no_production_module_passes_them():
    source = CYCLE_FILE.read_text(encoding="utf-8")
    assert source.count("_seams_for_tests") == 2  # the parameter and its one read
    for name in ("SEAM-CLOCK", "SEAM-DOMAIN", "SEAM-SELFTEST", "SEAM-SLEEP-REPORT", "SEAM-WITNESS", "SEAM-EXCHANGE",
                 "SEAM-BOOT-EPOCH"):
        assert f"{name} cycle tests only" in source, name
    for path in [*(ROOT / "heel").rglob("*.py"), *(ROOT / "deploy").rglob("*.py"), *(ROOT / "scripts").rglob("*.py")]:
        if path != CYCLE_FILE:
            assert "_seams_for_tests" not in path.read_text(encoding="utf-8"), path


def test_cycle_module_has_no_wait_any_sig_ign_or_signal_outside_the_context():
    source = CYCLE_FILE.read_text(encoding="utf-8")
    tree = ast.parse(source)
    for forbidden in ("waitpid(-1", "subprocess", "threading.Event", "os.environ", "argparse", "os.fork", "fork(",
                      "os.kill", "waitpid", "KeyboardInterrupt"):
        assert forbidden not in source, forbidden
    functions = {node.name: node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
    setters = [name for name, node in functions.items()
               if any(isinstance(call, ast.Call) and ast.unparse(call.func) == "signal.signal" for call in ast.walk(node))]
    assert setters == ["install_signal_context"]
    module_level = [node for node in tree.body if not isinstance(node, (ast.FunctionDef, ast.ClassDef))]
    assert not any(isinstance(call, ast.Call) and ast.unparse(call.func) == "signal.signal"
                   for node in module_level for call in ast.walk(node))
    for call in ast.walk(tree):
        if isinstance(call, ast.Call) and ast.unparse(call.func) == "signal.signal":
            assert "SIG_IGN" not in ast.unparse(call) and "SIG_DFL" not in ast.unparse(call)
    install = ast.get_source_segment(source, functions["install_signal_context"])
    assert "_on_stop_signal" in install and "main_thread" in install
    # The handler touches no lock, event, logger, callback or domain.
    handler = ast.get_source_segment(source, functions["_on_stop_signal"])
    for forbidden in ("_lock", "Event", "log", "callback", "domain", "acquire"):
        assert forbidden not in handler
    # Imports by file path only: no package import of heel or of a test/script module.
    imports = [node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))]
    names = {alias.name.split(".")[0] for node in imports for alias in node.names} | {
        (node.module or "").split(".")[0] for node in imports if isinstance(node, ast.ImportFrom)}
    assert not names & {"heel", "tests", "scripts", "subprocess", "multiprocessing"}
    assert {"authority.py", "profile.py", "host_authority.py"} <= set(re.findall(r'"([a-z_]+\.py)"', source))


def test_doc_states_the_table_signal_contract_registry_rule_and_limits():
    text = DOC_FILE.read_text(encoding="utf-8")
    for phrase in ("E_lower = t_p0 + T − 2·tick", "E_upper = t_p1 + T + tick", "D = t_start + rem",
                   "by tuple", "one context", "residual", "R_bound", "process-global", "fork-to-record",
                   "repeated interruption", "running-kernel", "H1A3-A", "NON_CUSTOMER", "no availability claim",
                   "operation_interrupted", "child_uncertain", "child_stranded", "sigchld_ignored",
                   "foreign_signal_handler", "residual_bound_ms", "request_gap_ms", "generation_class_end",
                   "B1", "B2", "B3", "component evidence"):
        assert phrase in text, phrase
    rows = re.findall(r"^\| (\d+) \|", text, re.M)
    assert rows == [str(number) for number in range(1, 28)]
    for reason in NON_NONE_REASONS:
        assert f"`{reason}`" in text, reason


# ---------------------------------------------------------------------------------------------
# Linux: the real control plane over AF_UNIX (listener, decider, ledger), the real client and peer
# check. The domain is the recorded installer (STATE-MACHINE ONLY for the kernel side).

def _real_cp_context(authority_fixture) -> dict:
    grant = authority_fixture.grant
    ids = authority_fixture.ids
    return {"workspace_id": ids["workspace_id"], "project_id": ids["project_id"],
            "environment_id": ids["environment_id"], "verification_record_digest": ids["verification_record_digest"],
            "runner_id": ids["runner_id"], "runner_key_id": authority_fixture.runner.key_id,
            "binding_id": authority_fixture.binding_id, "binding_digest": authority_fixture.binding_digest,
            "run_id": authority_fixture.run_id, "grant_id": authority_fixture.grant_id,
            "grant_digest": authority_fixture.grant_digest,
            "public_key_digest": grant["runner_binding"]["public_key_digest"],
            "egress_hostname": grant["egress"]["hostname"], "kill_switch_generation": 0, "egress_port": 443}


def _real_cp_cycle(monkeypatch, tmp_path, socket_path: str) -> Harness:
    """The real client against ``socket_path``: SEAM-EXCHANGE is not passed. The two pid-namespace
    links read as equal (pid 1's link needs privilege on an ordinary runner; T1 proves the real one)."""
    real_readlink = os.readlink

    def readlink(path, *args, **kwargs):
        if path in ("/proc/self/ns/pid", "/proc/1/ns/pid"):
            return "pid:[4026531836]"
        return real_readlink(path, *args, **kwargs)

    monkeypatch.setattr(authority.os, "readlink", readlink)
    h = Harness(monkeypatch, tmp_path)
    h.cycle._exchange = cycle.ControlPlaneClient(socket_path, os.geteuid()).exchange
    return h


@LINUX
@POSIX_FORK
def test_cycle_against_real_control_plane_over_af_unix_with_recorded_domain(monkeypatch, tmp_path, signals):
    """The real control plane (``build_server``: listener, peer rule, decider, ledger, reaper) and
    the real client with the peer check on the request connection; the domain is the recorded
    installer (STATE-MACHINE ONLY on the kernel side). Positive: two cycles activate. An operator
    stop then ends the context with the CP's answer for a stopping run, ``no_active_run`` (close,
    flush), and the ledger row recorded all three requests."""
    from tests import test_host_snapshot as snapshot
    from heel.saas.server import ProductionConfiguration, build_server

    short = __import__("tempfile").mkdtemp(prefix="hc")
    try:
        env = snapshot.host_environment(short)
        config = ProductionConfiguration.from_environment(env)
        fixture = snapshot.build_authority(config.database_path, signing=config.grant_authority,
                                           base=math.floor(time.time()))
        server = build_server(config)
        try:
            h = _real_cp_cycle(monkeypatch, tmp_path, config.host_authority.socket_path)
            assert h.cycle.start() == "ready"
            h.cycle.install_context(cycle.CycleContext(**_real_cp_context(fixture)))
            assert h.cycle.tick() == "serving" and h.status()["authorized"] == "true", h.status()
            assert h.cycle.tick() == "serving" and h.domain.calls == ["prepare", "activate"] * 2
            conn = snapshot.open_db(config.database_path)
            try:
                fixture.runs(conn).request_stop(fixture.ids["workspace_id"], fixture.ids["project_id"], fixture.run_id,
                                                actor="user_owner", reason="cloud_stop", expected_kill_switch_generation=0)
                conn.commit()
            finally:
                conn.close()
            assert h.cycle.tick() == "closed"
            assert h.status()["context_end_reason"] == "no_active_run"
            assert h.domain.calls[-2:] == ["close", "close_generation"]
            row = snapshot.ledger_row(config.database_path, h.domain.generation_id)
            assert row is not None and row["last_sequence"] == 3
        finally:
            server.server_close()
    finally:
        __import__("shutil").rmtree(short, ignore_errors=True)


@LINUX
@POSIX_FORK
def test_real_cp_clock_gap_and_replayed_sequence_close_the_generation(monkeypatch, tmp_path, signals):
    """The real listener, decider and ledger with SEAM-CLOCK on the decider (snapshot tests' seam,
    labelled) and the real client; recorded domain (STATE-MACHINE ONLY on the kernel side). A second
    supervisor enrolling the same (boot, slot) supersedes: the cycle's next request is
    ``replayed_sequence`` and the generation closes; a fresh generation enrols with sequence 1. A CP
    clock jump of 10 s between two requests is ``clock_gap`` and closes that generation too;
    ``cp_draining`` ends the next context."""
    from tests import test_host_snapshot as snapshot
    from heel.saas.host_authority import HostAuthorityConfig, HostAuthorityListener, PeerProfile
    from heel.saas.host_snapshot import HostSnapshotDecider

    short = __import__("tempfile").mkdtemp(prefix="hc")
    draining = [False]
    try:
        fixture = snapshot.build_authority(os.path.join(short, "cp.db"), base=math.floor(time.time()) - 60)
        wall = snapshot.Clock(time.time_ns())
        decider = HostSnapshotDecider(fixture.path, signing=fixture.signing, draining=lambda: draining[0],
                                      _time_ns_for_tests=wall)
        listener = HostAuthorityListener(HostAuthorityConfig(os.path.join(short, "h.sock"), os.geteuid(),
                                                             PeerProfile.SHARED_PIDNS), decider)
        listener.start()
        serving = threading.Thread(target=listener.serve_forever, daemon=True)
        serving.start()
        try:
            h = _real_cp_cycle(monkeypatch, tmp_path, listener.config.socket_path)
            skew = [0]

            def paced():  # the decider's wall clock follows the host clock, plus a scripted CP jump
                now = h.clock()
                wall.ns = base_wall + (now - base_mono) + skew[0]
                return now

            base_wall, base_mono = wall.ns, h.clock()
            h.cycle._clock = paced
            context = cycle.CycleContext(**_real_cp_context(fixture))
            assert h.cycle.start() == "ready"
            h.cycle.install_context(context)
            assert h.cycle.tick() == "serving" and h.domain.calls == ["prepare", "activate"]
            # A cloned supervisor enrols the same (boot, slot): the older generation is superseded.
            status, _body = snapshot.post(listener.config.socket_path, snapshot.live_request(
                fixture, generation_id=secrets.token_hex(16), sequence=1, host_boot_epoch="boot-0001",
                monotonic_ms=paced() // MS))
            assert status == 200
            assert h.cycle.tick() == "closed" and h.status()["context_end_reason"] == "replayed_sequence"
            h.clock.advance_ms(cycle.MIN_GENERATION_SPACING_MS)
            assert h.cycle.start() == "ready"
            h.cycle.install_context(context)
            assert h.cycle.tick() == "serving" and h.status()["authorized"] == "true"
            skew[0] = 10_000 * MS  # the CP clock jumps 10 s relative to the host
            assert h.cycle.tick() == "closed" and h.status()["context_end_reason"] == "clock_gap"
            h.clock.advance_ms(cycle.MIN_GENERATION_SPACING_MS)
            assert h.cycle.start() == "ready"
            h.cycle.install_context(context)
            draining[0] = True
            assert h.cycle.tick() == "closed" and h.status()["context_end_reason"] == "cp_draining"
        finally:
            listener.close()
            serving.join(5)
    finally:
        __import__("shutil").rmtree(short, ignore_errors=True)
