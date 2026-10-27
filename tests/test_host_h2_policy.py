"""H2-1 generation policy installer (H2-POLICY-FABLE-REFRESH revision 5, sections 4 and 6.1).

Offline and unprivileged; importable on the pinned macOS Python, which has no ``os.setns``. A regular
file stands in for the namespace descriptor (the H2-A test pattern). Seams, assigned only here and
labelled: ``NFT_PATH`` -> an owned fake nft (``TEST FAKE nft``) that answers, hangs, exits nonzero,
never reads stdin, overflows or lists ``/dev/fd``; ``_HELPER_SOURCE`` -> ``TEST_HELPER``, the
production helper with only its ``setns`` line replaced; ``_PLATFORM_OK = True``; an injected
``clock``; and test-process wrappers around ``subprocess.Popen``/``os.dup``/``Popen.kill``. The
real launch, pipe, deadline, kill and reap paths run. Nothing here enters a namespace, runs a real
nft, touches the kernel's packet path or claims anything about it: H2-2 owns that proof. Ordinary
Linux CI runs the unmodified production helper to its ``setns`` failure.
"""
from __future__ import annotations

import ast
import dataclasses
import hashlib
import importlib.util
import inspect
import ipaddress
import json
import os
import resource
import secrets
import signal
import socket
import subprocess
import sys
import time
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
H2_FILE = ROOT / "deploy" / "host" / "h2_policy.py"
CYCLE_FILE = ROOT / "deploy" / "host" / "cycle.py"
DOC_FILE = ROOT / "docs" / "saas" / "H2_POLICY_INSTALLATION.md"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses resolve string annotations through sys.modules
    spec.loader.exec_module(module)
    return module


cycle = _load("heel_host_cycle_h2_unit", CYCLE_FILE)
h2 = _load("heel_host_h2_policy_unit", H2_FILE)
authority, codec = h2._authority, h2._codec

MS = 1_000_000
LINUX = pytest.mark.skipif(sys.platform != "linux", reason="the real setns(2) failure path needs Linux")
SETNS_LINE = "    os.setns(fd, os.CLONE_NEWNET)\n"
PRODUCTION_HELPER = h2._HELPER_SOURCE
TEST_HELPER = h2._HELPER_SOURCE.replace(SETNS_LINE, "    pass  # TEST HELPER - substitutes only the namespace step\n")
PRODUCTION_HELPER_SHA256 = "c261a67fee245d58bbf59adcd8203f959209c6210f1c16b452315044a5a53866"
SLOT_SRC, SLOT_DST = "198.51.100.10", "203.0.113.10"
TARGETS = ("1.1.1.1", "8.8.4.4", "8.8.8.8", "9.9.9.9")
DUAL_V6 = "2001:4860:4860::8888"
CTX = {
    "workspace_id": "ws_" + "1" * 16, "project_id": "prj_" + "1" * 32, "environment_id": "env_" + "1" * 32,
    "verification_record_digest": "a" * 64, "runner_id": "runr_1", "runner_key_id": "key_1",
    "binding_id": "rcb_" + "1" * 32, "binding_digest": "b" * 64, "run_id": "crun_" + "1" * 32, "grant_id": "cgr_1",
    "grant_digest": "c" * 64, "public_key_digest": "d" * 64, "egress_hostname": "canary.acme.dev",
    "kill_switch_generation": 0, "egress_port": 443,
}
_META = {"meta": {"key": "mark"}}
_SADDR = {"payload": {"protocol": "ip", "field": "saddr"}}
_DADDR = {"payload": {"protocol": "ip", "field": "daddr"}}


def addresses(*values: str) -> tuple:
    parsed = [ipaddress.ip_address(value) for value in values]
    return tuple(sorted(parsed, key=lambda a: (a.version, a.packed)))


def fields(identity=(1, 2), targets=TARGETS[1:3], **overrides) -> dict:
    return {"generation_id": secrets.token_hex(16), "namespace_identity": identity, "slot_id": "slot-1",
            "slot_hop_src": SLOT_SRC, "slot_hop_dst": SLOT_DST, "bootstrap_fence": secrets.token_hex(16),
            "egress_hostname": "canary.acme.dev", "egress_port": 443,
            "observed_public_addresses": addresses(*targets), **overrides}


def synthetic_readback(dst: str, targets, *, flags=("timeout",), mark=0, op="==", bare_single=False, handles=True):
    """Oracle unit input modelled on H2K1F1's ``_synthetic_readback`` plus the kernel handles and the
    two empty H1 sets. Not a claim about what nft 1.0.9 prints; H2-2 parses the real listing."""
    numbers = iter(range(1, 64))

    def item(kind: str, body: dict) -> dict:
        return {kind: {**body, "handle": next(numbers)} if handles else body}

    gateway = {"|": [{"&": [_DADDR, dst]}, int(ipaddress.IPv4Address(dst))]}
    pins = list(targets)[0] if bare_single else {"set": list(targets)}
    rule = {"family": "inet", "table": "heel_lease", "chain": "gate"}
    return {"nftables": [
        {"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak #3", "json_schema_version": 1}},
        item("table", {"family": "inet", "name": "heel_lease"}),
        item("set", {"family": "inet", "name": "prepared", "table": "heel_lease",
                     "type": ["ipv4_addr", "ipv4_addr", "mark"], "flags": list(flags) if isinstance(flags, tuple) else flags}),
        item("map", {"family": "inet", "name": "activated", "table": "heel_lease", "type": ["ipv4_addr", "ipv4_addr"],
                     "map": "mark"}),
        item("chain", {"family": "inet", "table": "heel_lease", "name": "gate", "type": "filter", "hook": "output",
                       "prio": 0, "policy": "drop"}),
        item("rule", {**rule, "expr": [{"mangle": {"key": _META, "value": mark}}]}),
        item("rule", {**rule, "expr": [{"mangle": {"key": _META, "value": {"map": {
            "key": {"concat": [_SADDR, gateway]}, "data": "@activated"}}}}]}),
        item("rule", {**rule, "expr": [
            {"match": {"op": op, "left": {"concat": [_SADDR, gateway, _META]}, "right": "@prepared"}},
            {"match": {"op": "==", "left": _DADDR, "right": pins}},
            {"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 443}},
            {"accept": None}]}),
    ]}


class StepClock:
    """An injected monotonic clock: every read advances ``step_ms``; ``jumps`` maps a read index
    (1-based) to an extra advance applied before that read returns."""

    def __init__(self, step_ms: int = 10, jumps: dict[int, int] | None = None):
        self.now, self.step, self.jumps, self.reads = 10 ** 12, step_ms * MS, dict(jumps or {}), []

    def __call__(self) -> int:
        self.now += self.step + self.jumps.pop(len(self.reads) + 1, 0) * MS
        self.reads.append(self.now)
        return self.now

    def advance(self, ms: int) -> None:
        self.now += ms * MS


# ---------------------------------------------------------------------------------------------
# Fixtures: the stand-in descriptor, the owned fake nft and the private seams.

@pytest.fixture
def stand_in(tmp_path):
    path = tmp_path / "namespace-stand-in"
    path.write_bytes(b"not a namespace")
    fd = os.open(path, os.O_RDONLY)
    info = os.fstat(fd)
    yield fd, (info.st_dev, info.st_ino)
    try:
        os.close(fd)
    except OSError:
        pass


class FakeNft:
    """``TEST FAKE nft``: a shell script that logs one line per call and acts per phase. The first
    ``-f`` call is the install, later ones are cleanups."""

    ACTIONS = {
        "ok": 'cat > "$D/$phase.in"; exit 0',
        "noread": "exit 0",
        "hang": "exec /bin/sleep 30",
        "garbage": "printf 'not json'; exit 0",
        "big": "head -c 70000 /dev/zero | tr '\\000' a; exit 0",
        "dupkeys": 'printf \'{"nftables": [], "nftables": []}\'; exit 0',
    }

    def __init__(self, directory: Path, **phases: str):
        self.dir = directory
        self.dir.mkdir(parents=True, exist_ok=True)
        self.path = self.dir / "nft"
        self.log = self.dir / "log"
        lines = ["#!/bin/sh", "# TEST FAKE nft (tests/test_host_h2_policy.py): never a real nft", f"D='{self.dir}'",
                 'case "$1" in', "  -c) phase=check ;;", "  -j) phase=readback ;;",
                 '  -f) n=$(cat "$D/fcount" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "$D/fcount"',
                 '      if [ "$n" -eq 1 ]; then phase=install; else phase=cleanup; fi ;;', "  *) phase=other ;;",
                 "esac", 'echo "$phase $*" >> "$D/log"', 'case "$phase" in']
        for phase in ("check", "install", "readback", "cleanup", "other"):
            action = phases.get(phase, "ok")
            if action.startswith("exit:"):
                body = f'cat > "$D/$phase.in"; exit {int(action[5:])}'
            elif phase == "readback" and action == "ok":
                body = 'cat "$D/readback.json"; exit 0'
            else:
                body = self.ACTIONS[action]
            lines.append(f"  {phase}) {body} ;;")
        lines.append("esac")
        self.path.write_text("\n".join(lines) + "\n")
        self.path.chmod(0o755)

    def set_readback(self, document) -> None:
        (self.dir / "readback.json").write_text(document if isinstance(document, str) else json.dumps(document))

    def calls(self) -> list[str]:
        return self.log.read_text().splitlines() if self.log.exists() else []

    def stdin_of(self, phase: str) -> bytes:
        return (self.dir / f"{phase}.in").read_bytes()


@pytest.fixture
def seams(monkeypatch):
    """The labelled private seams plus fresh process registries (tests replace, never reset)."""
    monkeypatch.setattr(h2, "_PLATFORM_OK", True)
    monkeypatch.setattr(h2, "_HELPER_SOURCE", TEST_HELPER)
    monkeypatch.setattr(h2, "_INPUTS", {})
    monkeypatch.setattr(h2, "_UNREAPED_HELPERS", [])
    yield monkeypatch


@pytest.fixture
def fake(seams, tmp_path):
    def make(**phases) -> FakeNft:
        nft = FakeNft(tmp_path / f"fake{secrets.token_hex(4)}", **phases)
        seams.setattr(h2, "NFT_PATH", str(nft.path))
        return nft
    return make


@pytest.fixture
def launches(monkeypatch):
    """Records every ``subprocess.Popen`` call; optional hooks before/after the launch."""
    real = subprocess.Popen
    record = types.SimpleNamespace(calls=[], children=[], before=None, after=None)

    def popen(*args, **kwargs):
        record.calls.append((list(args[0]), dict(kwargs)))
        if record.before:
            record.before(len(record.calls))
        child = real(*args, **kwargs)
        record.children.append(child)
        if record.after:
            record.after(len(record.calls), child)
        return child

    monkeypatch.setattr(subprocess, "Popen", popen)
    yield record
    for child in record.children:  # every test owns and ends its children
        if child.poll() is None:
            os.kill(child.pid, signal.SIGKILL)
            child.wait(5)


def ready_input(identity, fake_nft: FakeNft, **overrides):
    policy = h2.build_input(**fields(identity=identity, **overrides))
    if policy.ipv4_egress_targets:
        fake_nft.set_readback(synthetic_readback(policy.slot_hop_dst, map(str, policy.ipv4_egress_targets)))
    return policy


def open_fds() -> set[int]:
    return {int(name) for name in os.listdir("/dev/fd")}


# ---------------------------------------------------------------------------------------------
# The input (sections 3.E, 4.1, 4.6).

def test_builder_shape_check_accepts_every_select_public_addresses_output():
    from heel.runner.http_transport import TransportFailure, select_public_addresses  # test-only import
    cases = (["8.8.8.8", DUAL_V6, "1.1.1.1"], ["9.9.9.9", "8.8.4.4", "8.8.8.8", "1.1.1.1"],
             ["8.8.8.8", "8.8.8.8", DUAL_V6, DUAL_V6], ["8.8.8.8"], [DUAL_V6],
             [f"8.8.8.{n}" for n in range(1, 17)], [DUAL_V6, "2001:4860:4860::8844", "8.8.4.4"])
    for answers in cases:
        selected = select_public_addresses(answers)
        policy = h2.build_input(**fields(observed_public_addresses=selected))
        assert policy.observed_public_addresses == selected
        assert policy.ipv4_egress_targets == tuple(a for a in selected if a.version == 4)
        reordered = select_public_addresses(list(reversed(answers)))
        assert h2.build_input(**fields(observed_public_addresses=reordered)).observed_public_addresses == selected
    for bad in ([], [f"8.8.8.{n}" for n in range(1, 18)]):
        with pytest.raises(TransportFailure):
            select_public_addresses(bad)
    raw = tuple(ipaddress.ip_address(a) for a in ["8.8.8.8", "1.1.1.1"])  # unordered: not the function's output
    with pytest.raises(ValueError, match="observed_public_addresses_invalid"):
        h2.build_input(**fields(observed_public_addresses=raw))
    with pytest.raises(ValueError, match="observed_public_addresses_invalid"):
        h2.build_input(**fields(observed_public_addresses=list(select_public_addresses(["8.8.8.8"]))))


def test_builder_checks_canonical_shape_only_and_does_not_judge_public_ness():
    private = addresses("10.0.0.1", "192.168.1.1")  # sorted private tuple: shape passes (trusted-constructor precondition)
    assert h2.build_input(**fields(observed_public_addresses=private)).ipv4_egress_targets == private
    v4 = [ipaddress.IPv4Address(a) for a in ("8.8.4.4", "8.8.8.8")]
    v6 = ipaddress.IPv6Address(DUAL_V6)
    for bad in ((v4[1], v4[0]), (v4[0], v4[0]), (v6, v4[0]), (), tuple(ipaddress.IPv4Address(f"8.8.8.{n}") for n in range(1, 18)),
                ("8.8.4.4",), (int(v4[0]),), (ipaddress.ip_network("8.8.8.0/24"),), None):
        with pytest.raises(ValueError, match="observed_public_addresses_invalid"):
            h2.build_input(**fields(observed_public_addresses=bad))
    assert len(h2.build_input(**fields(observed_public_addresses=addresses(*(f"8.8.8.{n}" for n in range(1, 17)))))
               .ipv4_egress_targets) == 16
    for name, bad in (("generation_id", "G" * 32), ("generation_id", "0" * 31), ("bootstrap_fence", 7),
                      ("namespace_identity", (1, -1)), ("namespace_identity", [1, 2]), ("namespace_identity", (True, 2)),
                      ("namespace_identity", (1, 2, 3)), ("slot_id", ""), ("slot_id", "Slot"), ("slot_id", "s" * 81),
                      ("slot_hop_src", "198.051.100.10"), ("slot_hop_dst", "::1"), ("slot_hop_src", SLOT_DST),
                      ("egress_hostname", ""), ("egress_hostname", "Canary.acme.dev"), ("egress_hostname", "a b"),
                      ("egress_port", 8443), ("egress_port", 443.0), ("egress_port", True)):
        with pytest.raises(ValueError):
            h2.build_input(**fields(**{name: bad}))
    with pytest.raises(ValueError, match="input_fields_invalid"):
        h2.build_input(**fields(ipv4_egress_targets=()))
    with pytest.raises(ValueError, match="input_fields_invalid"):
        h2.build_input(**{k: v for k, v in fields().items() if k != "slot_id"})
    policy = h2.build_input(**fields())
    with pytest.raises(dataclasses.FrozenInstanceError):
        policy.slot_hop_dst = "203.0.113.99"


def test_full_dual_stack_pins_are_preserved_while_ipv4_targets_are_derived():
    full = addresses(*TARGETS, DUAL_V6)
    policy = h2.build_input(**fields(observed_public_addresses=full))
    assert policy.observed_public_addresses == full and len(full) == 5
    assert tuple(map(str, policy.ipv4_egress_targets)) == TARGETS
    table = h2.render_table(policy).decode()
    assert DUAL_V6 not in table and "ip6" not in table and "::" not in table
    assert f"ip daddr {{ {', '.join(TARGETS)} }}" in table


def test_ipv6_only_refuses_before_install_and_spawns_nothing(fake, stand_in, launches):
    fd, identity = stand_in
    nft = fake()
    policy = h2.build_input(**fields(identity=identity, observed_public_addresses=addresses(DUAL_V6)))
    assert policy.ipv4_egress_targets == () and policy.observed_public_addresses == addresses(DUAL_V6)
    with pytest.raises(ValueError, match="unsupported_ipv6_only"):
        h2.render_table(policy)
    outcome = h2.install(fd, policy)
    assert outcome.state == "unsupported_ipv6_only" and outcome.receipt is None
    assert launches.calls == [] and nft.calls() == []
    assert readback_ok(synthetic_readback(SLOT_DST, ["8.8.8.8"]), policy) is False


def readback_ok(document, policy) -> bool:
    return h2.readback_matches(document, policy)[0]


def test_builder_performs_no_dns_and_imports_no_resolver():
    tree = ast.parse(H2_FILE.read_text())
    imported = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
    imported |= {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert imported <= {"dataclasses", "importlib.util", "ipaddress", "json", "os", "re", "select", "subprocess", "sys",
                        "threading", "time", "types", "pathlib"}, imported
    assert "socket" not in imported and not any(name.startswith("heel") for name in imported)
    names = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    names |= {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    for forbidden in ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "create_connection", "BoundedResolver",
                      "select_public_addresses", "resolver", "dns", "http_transport", "TargetHTTPSClient"):
        assert forbidden not in names, forbidden
    strings = [node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and isinstance(node.value, str)]
    assert not any("heel.runner" in text or "http_transport" in text for text in strings)


def test_input_maps_only_real_generationbootstrap_and_cyclecontext_fields():
    record = cycle.GenerationBootstrap(generation_id=secrets.token_hex(16), namespace_identity=(11, 12), slot_id="slot-1",
                                       slot_hop_src=SLOT_SRC, slot_hop_dst=SLOT_DST, bootstrap_fence=secrets.token_hex(16))
    context = cycle.CycleContext(**CTX)
    request = record.request()
    selected = addresses("8.8.8.8", DUAL_V6)
    policy = h2.build_input(generation_id=request["generation_id"],
                            namespace_identity=(request["namespace_dev"], request["namespace_ino"]),
                            slot_id=request["slot_id"], slot_hop_src=request["slot_hop_src"],
                            slot_hop_dst=request["slot_hop_dst"], bootstrap_fence=request["bootstrap_fence"],
                            egress_hostname=context.egress_hostname, egress_port=context.egress_port,
                            observed_public_addresses=selected)
    names = [f.name for f in dataclasses.fields(h2.H2PolicyInput)]
    from_bootstrap = [f.name for f in dataclasses.fields(cycle.GenerationBootstrap)]
    assert names == [*from_bootstrap, "egress_hostname", "egress_port", "observed_public_addresses", "ipv4_egress_targets"]
    assert {"egress_hostname", "egress_port"} <= {f.name for f in dataclasses.fields(cycle.CycleContext)}
    assert [f.name for f in dataclasses.fields(h2.H2PolicyInput) if not f.init] == ["ipv4_egress_targets"]
    for name in from_bootstrap:
        assert getattr(policy, name) == getattr(record, name)
    assert (policy.egress_hostname, policy.egress_port) == (context.egress_hostname, 443)
    for absent in ("route", "method", "budget", "expires", "claim", "bundle", "nonce", "path", "pid", "capability", "deadline"):
        assert not any(absent in name for name in names), absent


# ---------------------------------------------------------------------------------------------
# The table and the readback (sections 4.2, 4.4).

ONE_TARGET = (b"table inet heel_lease {\n"
              b"  set prepared { type ipv4_addr . ipv4_addr . mark ; flags timeout ; }\n"
              b"  map activated { type ipv4_addr . ipv4_addr : mark ; }\n"
              b"  chain gate {\n"
              b"    type filter hook output priority 0 ; policy drop ;\n"
              b"    meta mark set 0\n"
              b"    meta mark set ip saddr . (ip daddr & 0.0.0.0 | 203.0.113.10) map @activated\n"
              b"    ip saddr . (ip daddr & 0.0.0.0 | 203.0.113.10) . meta mark @prepared ip daddr { 8.8.8.8 } tcp dport 443 accept\n"
              b"  }\n"
              b"}\n")
THREE_TARGETS = ONE_TARGET.replace(b"203.0.113.10", b"192.0.2.1").replace(
    b"{ 8.8.8.8 }", b"{ 1.1.1.1, 8.8.4.4, 8.8.8.8 }")


def test_rendered_table_is_exactly_one_table_three_rules_one_accept_with_typed_gateway_in_both_keys():
    assert (authority.TABLE, authority.PREPARED_SET, authority.ACTIVATED_MAP, authority.GATE_CHAIN) == (
        "heel_lease", "prepared", "activated", "gate")
    one = h2.build_input(**fields(observed_public_addresses=addresses("8.8.8.8", DUAL_V6)))
    three = h2.build_input(**fields(slot_hop_src="192.0.2.2", slot_hop_dst="192.0.2.1",
                                    observed_public_addresses=addresses("8.8.8.8", "1.1.1.1", "8.8.4.4")))
    assert h2.render_table(one) == ONE_TARGET
    assert h2.render_table(three) == THREE_TARGETS
    assert hashlib.sha256(ONE_TARGET).hexdigest() == hashlib.sha256(h2.render_table(one)).hexdigest()
    for policy in (one, three, h2.build_input(**fields(observed_public_addresses=addresses(*(f"8.8.8.{n}" for n in range(1, 17)))))):
        text = h2.render_table(policy).decode()
        gateway = f"(ip daddr & 0.0.0.0 | {policy.slot_hop_dst})"
        assert text.count("table ") == 1 and text.count("chain ") == 1 and text.count("accept") == 1
        assert text.count(gateway) == 2 and text.count(policy.slot_hop_dst) == 2 and policy.slot_hop_src not in text
        assert text.count("meta mark set") == 2 and "policy drop" in text and "hook output" in text
        for forbidden in ("nat", "redirect", "masquerade", "tproxy", "forward", "hook input", "ip6", "add element",
                          "elements", "jump", "goto", "flush", "delete", "dup", "fwd"):
            assert forbidden not in text, forbidden
        assert len(text) <= h2.MAX_BATCH_BYTES
    with pytest.raises(TypeError):
        h2.render_table(fields())


def test_readback_requires_exact_typed_gateway_targets_port_policy_and_nothing_else():
    policy = h2.build_input(**fields(observed_public_addresses=addresses("8.8.8.8", "8.8.4.4", DUAL_V6)))
    good = synthetic_readback(SLOT_DST, ["8.8.8.8", "8.8.4.4"])  # kernel order is not the input order
    assert h2.readback_matches(good, policy) == (True, {"readback": "exact", "part": "none"})
    for variant in (synthetic_readback(SLOT_DST, ["8.8.4.4", "8.8.8.8"], flags="timeout"),
                    synthetic_readback(SLOT_DST, ["8.8.4.4", "8.8.8.8"], mark="0x00000000"),
                    synthetic_readback(SLOT_DST, ["8.8.4.4", "8.8.8.8"], op="in"),
                    synthetic_readback(SLOT_DST, ["8.8.4.4", "8.8.8.8"], handles=False)):
        assert readback_ok(variant, policy)
    single = h2.build_input(**fields(observed_public_addresses=addresses("8.8.8.8")))
    assert readback_ok(synthetic_readback(SLOT_DST, ["8.8.8.8"], bare_single=True), single)
    assert readback_ok(synthetic_readback(SLOT_DST, ["8.8.8.8"]), single)
    assert not readback_ok(synthetic_readback(SLOT_DST, ["8.8.8.8", "8.8.4.4"], bare_single=True), policy)

    def mutated(change, document=good):
        copy = json.loads(json.dumps(document))
        change(copy["nftables"])
        return copy

    def admit(items):
        return items[7]["rule"]["expr"]

    def lookup_key(items):
        return items[6]["rule"]["expr"][0]["mangle"]["value"]["map"]["key"]["concat"]

    gateway_int = int(ipaddress.IPv4Address(SLOT_DST))
    changes = {
        "extra_rule": lambda items: items.append({"rule": {"family": "inet", "table": "heel_lease", "chain": "gate",
                                                           "handle": 99, "expr": [{"accept": None}]}}),
        "extra_target": lambda items: admit(items)[1]["match"]["right"]["set"].append("1.1.1.1"),
        "missing_target": lambda items: admit(items)[1]["match"]["right"]["set"].pop(),
        "duplicate_target": lambda items: admit(items)[1]["match"]["right"]["set"].__setitem__(1, "8.8.8.8"),
        "v6_target": lambda items: admit(items)[1]["match"]["right"]["set"].append(DUAL_V6),
        "bare_literal_lookup_key": lambda items: lookup_key(items).__setitem__(1, SLOT_DST),
        "bare_literal_prepared_key": lambda items: admit(items)[0]["match"]["left"]["concat"].__setitem__(1, SLOT_DST),
        "other_slot_gateway": lambda items: lookup_key(items).__setitem__(1, {"|": [{"&": [_DADDR, "192.0.2.1"]}, 3221225985]}),
        "gateway_as_string": lambda items: lookup_key(items)[1]["|"].__setitem__(1, SLOT_DST),
        "gateway_as_float": lambda items: lookup_key(items)[1]["|"].__setitem__(1, float(gateway_int)),
        "port_8443": lambda items: admit(items)[2]["match"].__setitem__("right", 8443),
        "port_bool": lambda items: admit(items)[2]["match"].__setitem__("right", True),
        "policy_accept": lambda items: items[4]["chain"].__setitem__("policy", "accept"),
        "hook_input": lambda items: items[4]["chain"].__setitem__("hook", "input"),
        "prio_float": lambda items: items[4]["chain"].__setitem__("prio", 0.0),
        "second_chain": lambda items: items.insert(5, {"chain": {"family": "inet", "table": "heel_lease", "name": "x",
                                                                 "handle": 98}}),
        "second_table": lambda items: items.insert(1, {"table": {"family": "inet", "name": "other", "handle": 97}}),
        "prepared_has_element": lambda items: items[2]["set"].__setitem__("elem", ["x"]),
        "activated_has_element": lambda items: items[3]["map"].__setitem__("elem", ["x"]),
        "map_data_other": lambda items: items[3]["map"].__setitem__("map", "verdict"),
        "set_not_timeout": lambda items: items[2]["set"].__setitem__("flags", ["interval"]),
        "rules_swapped": lambda items: items.__setitem__(slice(5, 7), [items[6], items[5]]),
        "no_reset": lambda items: items.pop(5),
        "reset_to_one": lambda items: items[5]["rule"]["expr"][0]["mangle"].__setitem__("value", 1),
        "accept_without_prepared": lambda items: admit(items).pop(0),
        "drop_verdict": lambda items: admit(items).__setitem__(3, {"drop": None}),
        "extra_expr": lambda items: admit(items).insert(3, {"counter": {"packets": 0, "bytes": 0}}),
        "nat": lambda items: admit(items).insert(3, {"dnat": {"addr": "8.8.8.8"}}),
        "rule_other_chain": lambda items: items[6]["rule"].__setitem__("chain", "other"),
        "rule_comment": lambda items: items[6]["rule"].__setitem__("comment", "x"),
        "handle_string": lambda items: items[1]["table"].__setitem__("handle", "1"),
        "handle_bool": lambda items: items[1]["table"].__setitem__("handle", True),
        "no_metainfo": lambda items: items.pop(0),
        "schema_2": lambda items: items[0]["metainfo"].__setitem__("json_schema_version", 2),
        "family_ip": lambda items: items[1]["table"].__setitem__("family", "ip"),
        "ip6_lookup": lambda items: lookup_key(items).__setitem__(0, {"payload": {"protocol": "ip6", "field": "saddr"}}),
        "op_neq": lambda items: admit(items)[0]["match"].__setitem__("op", "!="),
        "pins_op_neq": lambda items: admit(items)[1]["match"].__setitem__("op", "!="),
        "port_op_neq": lambda items: admit(items)[2]["match"].__setitem__("op", "!="),
        "two_kinds_one_item": lambda items: items[2].__setitem__("map", items[3]["map"]),
        "two_sets": lambda items: items.__setitem__(3, {"set": items[2]["set"]}),
    }
    for name, change in changes.items():
        ok, tokens = h2.readback_matches(mutated(change), policy)
        assert ok is False and tokens["readback"] == "mismatch" and tokens["part"] in h2._READBACK_PARTS, name
    other_dst = h2.build_input(**fields(slot_hop_dst="203.0.113.11", observed_public_addresses=policy.observed_public_addresses))
    assert not readback_ok(good, other_dst)
    for junk in (None, [], {}, {"nftables": None}, {"nftables": [None]}, {"nftables": [{"metainfo": {}}]}, "x", 3,
                 {"nftables": [{"metainfo": {"json_schema_version": 1}}, *[{"rule": None}] * 7]},
                 {"nftables": good["nftables"], "extra": 1}):
        assert h2.readback_matches(junk, policy)[0] is False
    deep = []
    for _ in range(100_000):
        deep = [deep]
    assert h2.readback_matches({"nftables": [{"metainfo": {"json_schema_version": 1}}, *[{"rule": deep}] * 7]}, policy)[0] is False
    assert h2.readback_matches(good, fields())[0] is False


# ---------------------------------------------------------------------------------------------
# The helper launch (section 4.3).

def test_install_uses_only_the_received_fd_fixed_argv_empty_env_and_rejects_identity_or_setns_failure(
        fake, stand_in, launches, tmp_path, seams):
    fd, identity = stand_in
    nft = fake()
    policy = ready_input(identity, nft)
    outcome = h2.install(fd, policy)
    assert outcome.state == "receipt_ready", dict(outcome.tokens)
    assert nft.calls() == ["check -c -f -", "install -f -", "readback -j list table inet heel_lease"]
    assert nft.stdin_of("check") == nft.stdin_of("install") == h2.render_table(policy)
    assert len(launches.calls) == 3
    for (argv, kwargs), nft_args in zip(launches.calls, (["-c", "-f", "-"], ["-f", "-"],
                                                         ["-j", "list", "table", "inet", "heel_lease"])):
        dup = int(argv[6])
        assert argv == [sys.executable, "-I", "-S", "-B", "-c", TEST_HELPER, str(dup), str(nft.path), *nft_args]
        assert dup != fd and dup >= 3
        assert kwargs == {"stdin": subprocess.PIPE, "stdout": subprocess.PIPE, "stderr": subprocess.STDOUT,
                          "close_fds": True, "pass_fds": (dup,), "cwd": "/",
                          "env": {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}, "start_new_session": False}
    os.fstat(fd)  # the caller's descriptor is still open: never closed by the installer
    other = tmp_path / "other"
    other.write_bytes(b"x")
    other_fd = os.open(other, os.O_RDONLY)
    try:
        before = len(launches.calls)
        mismatch = h2.install(other_fd, ready_input(identity, nft))
        assert mismatch.state == "identity_mismatch" and mismatch.receipt is None and len(launches.calls) == before
        assert dict(mismatch.tokens) == {"phase": "entry", "cleanup": "not_run"}  # refused before any dup
    finally:
        os.close(other_fd)
    seams.setattr(h2, "_HELPER_SOURCE", PRODUCTION_HELPER)  # the unmodified production helper
    assert h2._HELPER_SOURCE != TEST_HELPER
    calls_before = list(nft.calls())
    failed = h2.install(fd, ready_input(identity, nft))
    assert failed.state == "setns_failed" and failed.receipt is None and dict(failed.tokens) == {
        "phase": "check", "cleanup": "not_run"}
    assert nft.calls() == calls_before  # no nft was executed


def test_helper_launch_is_popen_without_preexec_with_close_fds_pass_fds_fixed_argv_and_no_os_fork():
    tree = ast.parse(H2_FILE.read_text())
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]

    def dotted(node) -> str:
        if isinstance(node, ast.Attribute):
            return dotted(node.value) + "." + node.attr
        return node.id if isinstance(node, ast.Name) else "?"

    popens = [call for call in calls if dotted(call.func) == "subprocess.Popen"]
    assert len(popens) == 1
    keywords = {kw.arg: kw.value for kw in popens[0].keywords}
    assert set(keywords) == {"stdin", "stdout", "stderr", "close_fds", "pass_fds", "cwd", "env", "start_new_session"}
    assert isinstance(keywords["close_fds"], ast.Constant) and keywords["close_fds"].value is True
    assert isinstance(keywords["start_new_session"], ast.Constant) and keywords["start_new_session"].value is False
    assert ast.unparse(keywords["pass_fds"]) == "(dup,)" and ast.unparse(keywords["cwd"]) == "'/'"
    assert ast.unparse(keywords["env"]) == "dict(_CHILD_ENV)"
    assert ast.unparse(popens[0].args[0]) == "argv"
    assert h2._CHILD_ENV == (("PATH", authority.CHILD_PATH), ("LC_ALL", "C"))
    called = {dotted(call.func) for call in calls}
    for forbidden in ("os.fork", "os.forkpty", "os.posix_spawn", "os.posix_spawnp", "os.system", "os.popen", "os.execv",
                      "os.execve", "os.spawnv", "subprocess.run", "subprocess.call", "subprocess.check_output",
                      "os.setns", "os.kill", "os.killpg", "os.waitpid", "os.register_at_fork"):
        assert forbidden not in called, forbidden
    source = H2_FILE.read_text()
    assert "preexec_fn" not in source.replace("without ``preexec_fn``", "") and "shell=" not in source
    argv = next(node for node in ast.walk(tree) if isinstance(node, ast.Assign)
                and any(isinstance(t, ast.Name) and t.id == "argv" for t in node.targets))
    assert ast.unparse(argv.value) == ("[sys.executable, '-I', '-S', '-B', '-c', _HELPER_SOURCE, str(dup), NFT_PATH, "
                                       "*nft_args]")
    assert (h2._CHECK_ARGS, h2._INSTALL_ARGS, h2._READBACK_ARGS) == (
        ("-c", "-f", "-"), ("-f", "-"), ("-j", "list", "table", "inet", "heel_lease"))


_FORK_EVENTS: list[str] = []
_FORK_WATCH = {"on": False}


def _fork_hook(event: str):
    def hook():
        if _FORK_WATCH["on"]:
            _FORK_EVENTS.append(event)
    return hook


def test_no_python_at_fork_handler_fires_during_a_helper_launch(fake, stand_in):
    if not getattr(test_no_python_at_fork_handler_fires_during_a_helper_launch, "registered", False):
        os.register_at_fork(before=_fork_hook("before"), after_in_parent=_fork_hook("parent"),
                            after_in_child=_fork_hook("child"))
        test_no_python_at_fork_handler_fires_during_a_helper_launch.registered = True
    fd, identity = stand_in
    nft = fake()
    _FORK_EVENTS.clear()
    _FORK_WATCH["on"] = True
    try:
        outcome = h2.install(fd, ready_input(identity, nft))
        during = list(_FORK_EVENTS)
        subprocess.run(["/bin/sh", "-c", "exit 0"], preexec_fn=lambda: None, check=True)  # control: hooks are live
        control = list(_FORK_EVENTS[len(during):])
    finally:
        _FORK_WATCH["on"] = False
    assert outcome.state == "receipt_ready" and during == []
    assert control == ["before", "parent"]


def _listing_fake(directory: Path, out_name: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "nft-listfd"
    out = directory / out_name
    path.write_text(f"#!{sys.executable} -I\n# TEST FAKE nft (tests/test_host_h2_policy.py): lists its descriptors\n"
                    "import json, os\n"
                    "seen = sorted(int(n) for n in os.listdir('/dev/fd'))  # before this fake opens anything\n"
                    f"open({str(out)!r}, 'w').write(json.dumps(seen))\n"
                    "raise SystemExit(1)\n")
    path.chmod(0o755)
    return path


@pytest.fixture
def high_fd_limit():
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if hard != resource.RLIM_INFINITY and hard < 1100:
        pytest.skip("RLIMIT_NOFILE hard limit below 1100")
    if soft != resource.RLIM_INFINITY and soft < 1100:
        resource.setrlimit(resource.RLIMIT_NOFILE, (2048, hard))
    yield
    resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))


def test_fake_nft_after_exec_sees_only_stdio_and_its_own_listing_fd_never_the_passed_dup_even_with_inheritable_borrowed_unrelated_and_high_numbered_fds(
        seams, stand_in, launches, tmp_path, high_fd_limit):
    fd, identity = stand_in
    seams.setattr(h2, "NFT_PATH", str(_listing_fake(tmp_path / "list", "after-exec.json")))
    high = os.dup2(fd, 1000)  # the borrowed descriptor at a high number, inheritable
    unrelated_r, unrelated_w = os.pipe()
    os.set_inheritable(unrelated_r, True)
    os.set_inheritable(unrelated_w, True)
    try:
        assert os.get_inheritable(high) and os.get_inheritable(unrelated_r)
        outcome = h2.install(high, h2.build_input(**fields(identity=identity)))
        assert outcome.state == "check_refused" and outcome.receipt is None
        dup = int(launches.calls[0][0][6])
        seen = set(json.loads((tmp_path / "list" / "after-exec.json").read_text()))
        assert {0, 1, 2} <= seen and len(seen - {0, 1, 2}) == 1, seen  # stdio + the listing's own directory fd
        assert dup not in seen and high not in seen and unrelated_r not in seen and unrelated_w not in seen
        assert dup != high and fd not in (dup,)
        os.fstat(high)
    finally:
        os.close(high)
        os.close(unrelated_r)
        os.close(unrelated_w)


def test_test_helper_before_exec_sees_exactly_stdio_the_passed_dup_and_its_listing_fd(
        seams, fake, stand_in, launches, tmp_path, high_fd_limit):
    fd, identity = stand_in
    fake(check="exit:1")
    out = tmp_path / "before-close.json"
    probe = ("    import json\n    seen = sorted(int(n) for n in os.listdir('/dev/fd'))\n"
             f"    open({str(out)!r}, 'w').write(json.dumps(seen))\n    os.close(fd)\n")
    listing_helper = TEST_HELPER.replace("    os.close(fd)\n", probe)
    assert listing_helper.count("os.listdir") == 1
    seams.setattr(h2, "_HELPER_SOURCE", listing_helper)
    high = os.dup2(fd, 1000)
    unrelated_r, unrelated_w = os.pipe()
    os.set_inheritable(unrelated_r, True)
    try:
        h2.install(high, h2.build_input(**fields(identity=identity)))
        dup = int(launches.calls[0][0][6])
        seen = set(json.loads(out.read_text()))
        extra = seen - {0, 1, 2, dup}
        assert {0, 1, 2, dup} <= seen and len(extra) == 1, (seen, dup)
        assert high not in seen and unrelated_r not in seen and unrelated_w not in seen
    finally:
        os.close(high)
        os.close(unrelated_r)
        os.close(unrelated_w)


def _run_helper(source: str, *argv: str, pass_fds=()) -> int:
    return subprocess.run([sys.executable, "-I", "-S", "-B", "-c", source, *argv], pass_fds=pass_fds, close_fds=True,
                          cwd="/", env={"PATH": authority.CHILD_PATH, "LC_ALL": "C"}, timeout=10,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode


def test_helper_source_imports_only_os_and_sys_and_exits_124_125_126_on_argv_setns_exec_failure(stand_in, tmp_path):
    fd, _identity = stand_in
    source = h2._HELPER_SOURCE
    assert hashlib.sha256(source.encode()).hexdigest() == PRODUCTION_HELPER_SHA256
    tree = ast.parse(source)
    assert {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names} == {"os", "sys"}
    assert not [node for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
    assert len(source.splitlines()) <= 40 and source.isascii()
    exits = sorted(node.args[0].value for node in ast.walk(tree) if isinstance(node, ast.Call)
                   and ast.unparse(node.func) == "os._exit")
    assert exits == [124, 125, 126]
    dup = os.dup(fd)
    try:
        for argv in ((), ("x",), ("2", "/nft", "-f"), (str(dup), "nft", "-f"), (str(dup), "/nft"), ("-5", "/nft", "-f")):
            assert _run_helper(source, *argv, pass_fds=(dup,)) == 124, argv
        # Real setns on a regular-file descriptor: EINVAL on Linux; no os.setns at all on macOS. Both 125.
        assert _run_helper(source, str(dup), str(tmp_path / "never"), "-f", pass_fds=(dup,)) == 125
        # 126 needs a setns success, which only the labelled test helper (setns line replaced) reaches here.
        assert _run_helper(TEST_HELPER, str(dup), str(tmp_path / "missing-nft"), "-f", pass_fds=(dup,)) == 126
        assert _run_helper(TEST_HELPER, str(dup + 50), "/bin/true", "-f") == 126  # close of an absent fd
    finally:
        os.close(dup)
    assert TEST_HELPER.replace("    pass  # TEST HELPER - substitutes only the namespace step\n", SETNS_LINE) == source


def test_unavailable_platform_refuses_before_any_launch_and_no_public_input_can_override_it(
        monkeypatch, stand_in, launches, tmp_path):
    fd, identity = stand_in
    computed = (sys.platform.startswith("linux") and hasattr(os, "setns") and authority.NFT_PATH is not None
                and os.path.isabs(sys.executable) and os.path.isfile(sys.executable))
    assert h2._PLATFORM_OK == computed and h2.NFT_PATH == authority.NFT_PATH
    if sys.platform == "darwin":
        assert h2._PLATFORM_OK is False and not hasattr(os, "setns")
    monkeypatch.setattr(h2, "_INPUTS", {})
    nft = FakeNft(tmp_path / "fake")
    monkeypatch.setenv("HEEL_H2_PLATFORM_OK", "1")
    monkeypatch.setenv("HEEL_NFT_PATH", str(nft.path))
    for platform_ok, nft_path in ((False, str(nft.path)), (1, str(nft.path)), ("True", str(nft.path)),
                                  (True, None), (True, "relative/nft")):
        monkeypatch.setattr(h2, "_PLATFORM_OK", platform_ok)
        monkeypatch.setattr(h2, "NFT_PATH", nft_path)
        policy = h2.build_input(**fields(identity=identity))
        assert h2.install(fd, policy).state == "refused_platform"
        assert h2.cleanup(fd, policy).state == "refused_platform"
        assert h2.install(fd, policy).state == "refused_platform"  # not consumed by a refusal
    monkeypatch.setattr(h2, "_PLATFORM_OK", True)
    monkeypatch.setattr(sys, "executable", "python3")
    assert h2.install(fd, h2.build_input(**fields(identity=identity))).state == "refused_platform"
    assert launches.calls == [] and nft.calls() == []
    with pytest.raises(ValueError):
        h2.build_input(**fields(platform_ok=True))


@LINUX
def test_linux_real_helper_setns_on_a_regular_file_exits_125_and_launches_no_nft(monkeypatch, stand_in, launches, tmp_path):
    fd, identity = stand_in
    nft = FakeNft(tmp_path / "fake")
    monkeypatch.setattr(h2, "_PLATFORM_OK", True)
    monkeypatch.setattr(h2, "NFT_PATH", str(nft.path))
    monkeypatch.setattr(h2, "_INPUTS", {})
    assert hasattr(os, "setns") and h2._HELPER_SOURCE.count(SETNS_LINE) == 1
    assert hashlib.sha256(h2._HELPER_SOURCE.encode()).hexdigest() == PRODUCTION_HELPER_SHA256
    outcome = h2.install(fd, h2.build_input(**fields(identity=identity)))
    assert outcome.state == "setns_failed" and outcome.receipt is None
    assert len(launches.calls) == 1 and nft.calls() == []
    dup = os.dup(fd)
    try:
        assert _run_helper(h2._HELPER_SOURCE, str(dup), str(nft.path), "-f", "-", pass_fds=(dup,)) == 125
    finally:
        os.close(dup)
    assert nft.calls() == []


def test_production_helper_source_is_one_unconditional_setns_close_exec_sequence_with_pinned_hash():
    tree = ast.parse(h2._HELPER_SOURCE)
    body = tree.body
    assert [type(node).__name__ for node in body] == ["Import", "Import", "Try", "Try", "Try", "Expr"]
    argv_try, setns_try, exec_try, final = body[2:]
    assert [ast.unparse(node) for node in setns_try.body] == ["os.setns(fd, os.CLONE_NEWNET)"]
    assert [ast.unparse(node) for node in setns_try.handlers[0].body] == ["os._exit(125)"]
    assert [ast.unparse(node) for node in exec_try.body] == [
        "os.close(fd)", "os.execve(nft, ['nft', *args], {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})"]
    assert ast.unparse(final) == "os._exit(126)"
    branches = [node for node in ast.walk(tree) if isinstance(node, (ast.If, ast.IfExp, ast.While, ast.For, ast.Match))]
    assert len(branches) == 1 and branches[0] in argv_try.body and ast.unparse(branches[0].body[0]) == "raise ValueError"
    assert [ast.unparse(node) for node in argv_try.handlers[0].body] == ["os._exit(124)"]
    assert "mode" not in h2._HELPER_SOURCE and "noset" not in h2._HELPER_SOURCE and "environ" not in h2._HELPER_SOURCE
    assert h2._HELPER_SOURCE.count("setns") == 1
    assert hashlib.sha256(h2._HELPER_SOURCE.encode()).hexdigest() == PRODUCTION_HELPER_SHA256
    assert authority.CHILD_PATH == "/usr/sbin:/usr/bin:/sbin:/bin"


def test_platform_seam_default_is_computed_and_only_tests_assign_helper_source_or_platform():
    tree = ast.parse(H2_FILE.read_text())
    assigned: dict[str, list] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            for target in (node.targets if isinstance(node, ast.Assign) else [node.target]):
                if isinstance(target, ast.Name):
                    assigned.setdefault(target.id, []).append(node)
        assert not isinstance(node, (ast.Global, ast.Nonlocal)), ast.unparse(node)
    for seam in ("_PLATFORM_OK", "_HELPER_SOURCE", "NFT_PATH"):
        assert len(assigned[seam]) == 1 and assigned[seam][0] in tree.body, seam
    assert not isinstance(assigned["_PLATFORM_OK"][0].value, ast.Constant)
    assert "sys.platform.startswith('linux')" in ast.unparse(assigned["_PLATFORM_OK"][0].value)
    assert "hasattr(os, 'setns')" in ast.unparse(assigned["_PLATFORM_OK"][0].value)
    assert isinstance(assigned["_HELPER_SOURCE"][0].value, ast.Constant)
    assert ast.unparse(assigned["NFT_PATH"][0].value) == "_authority.NFT_PATH"
    attributes = {ast.unparse(node) for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    assert not attributes & {"os.environ", "os.environb", "os.getenv", "os.getenvb", "os.putenv", "sys.argv",
                             "sys.flags", "sys.orig_argv"}  # nothing outside the module can steer a seam
    tracked = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True).stdout.split(b"\0")
    mentions = set()
    for name in {path.decode() for path in tracked if path} | {"deploy/host/h2_policy.py", "tests/test_host_h2_policy.py"}:
        path = ROOT / name
        if path.suffix != ".py" or not path.is_file():
            continue
        text = path.read_text(errors="replace")
        if "_HELPER_SOURCE" in text or "_PLATFORM_OK" in text:
            mentions.add(name)
    assert mentions == {"deploy/host/h2_policy.py", "tests/test_host_h2_policy.py"}, mentions


# ---------------------------------------------------------------------------------------------
# Deadlines, descriptors and reaping (sections 4.3, 4.7).

def test_popen_duration_is_charged_to_the_phase_budget(fake, stand_in, launches):
    fd, identity = stand_in
    nft = fake()
    clock = StepClock(step_ms=1)
    launches.before = lambda n: clock.advance(2600) if n == 1 else None  # a slow process creation
    outcome = h2.install(fd, ready_input(identity, nft), clock=clock)
    assert outcome.state == "timeout" and dict(outcome.tokens) == {"phase": "check", "cleanup": "not_run"}
    assert len(launches.calls) == 1 and launches.children[0].returncode is not None


def _kill_recorder(clock, record, advance_ms=0):
    def after(n, child):
        real_kill = child.kill

        def kill():
            record.append((n, clock.now))
            real_kill()
            child.wait(5)  # the reap happens; only the simulated time it took is charged below
            clock.advance(advance_ms)
        child.kill = kill
    return after


def test_each_child_is_bounded_startup_included_and_the_phase_budget_is_2500_ms(fake, stand_in, launches):
    assert (h2.CHILD_TIMEOUT_MS, h2.REAP_GRACE_MS, h2.H2_INSTALL_BUDGET_MS) == (1000, 250, 2500)
    assert (h2.CHILD_TIMEOUT_MS, h2.REAP_GRACE_MS) == (authority.PREPARE_CHILD_TIMEOUT_MS, authority.CHILD_REAP_GRACE_MS)
    fd, identity = stand_in
    hanging = fake(check="hang")
    clock, kills = StepClock(), []
    launches.after = _kill_recorder(clock, kills)
    start = clock.now + clock.step
    outcome = h2.install(fd, ready_input(identity, hanging), clock=clock)
    assert outcome.state == "timeout" and dict(outcome.tokens) == {"phase": "check", "cleanup": "not_run"}
    (n, killed_at), = kills
    assert n == 1 and start + 1000 * MS < killed_at <= start + 1000 * MS + 2 * clock.step  # began one read after entry
    # The phase deadline, not the child's own 1000 ms, bounds a readback that starts late.
    late = fake(readback="hang")
    clock, kills = StepClock(jumps={2: 1600}), []
    launches.after = _kill_recorder(clock, kills)
    launches.calls.clear()
    start = clock.now + clock.step
    outcome = h2.install(fd, ready_input(identity, late), clock=clock)
    assert outcome.state == "cleaned" and dict(outcome.tokens) == {
        "phase": "readback", "cause": "timeout", "cleanup": "cleaned", "readback": "none"}
    (n, killed_at), = kills
    assert n == 3 and start + 2500 * MS <= killed_at <= start + 2500 * MS + clock.step
    assert late.calls()[-1] == "cleanup -f -" and late.stdin_of("cleanup") == b"delete table inet heel_lease\n"


def test_worst_case_install_return_is_4000_ms_with_every_grace_charged(fake, stand_in, launches):
    assert h2.H2_WORKER_BUDGET_MS == 4000 == h2.H2_INSTALL_BUDGET_MS + h2.REAP_GRACE_MS + h2.CHILD_TIMEOUT_MS + h2.REAP_GRACE_MS
    fd, identity = stand_in
    nft = fake(readback="hang", cleanup="hang")
    clock, kills = StepClock(jumps={2: 1600}), []
    launches.after = _kill_recorder(clock, kills, advance_ms=240)  # each reap charged most of its grace
    start = clock.now + clock.step
    outcome = h2.install(fd, ready_input(identity, nft), clock=clock)
    assert outcome.state == "quarantined" and outcome.receipt is None
    assert dict(outcome.tokens) == {"phase": "readback", "cause": "timeout", "cleanup": "refused", "readback": "none"}
    assert [n for n, _ in kills] == [3, 4]
    assert kills[0][1] == start + 2500 * MS and kills[1][1] <= start + 3750 * MS
    assert max(clock.reads) - start <= 4000 * MS and clock.now - start <= 4000 * MS, (clock.now - start) / MS
    assert len(launches.calls) == 4  # nothing scheduled past the cleanup
    # A reap that overruns its grace (OS assumption b) cannot push the cleanup past the worker budget.
    late_reap = fake(readback="hang", cleanup="hang")
    clock, kills = StepClock(jumps={2: 1600}), []
    launches.after = _kill_recorder(clock, kills, advance_ms=800)
    launches.calls.clear()
    start = clock.now + clock.step
    outcome = h2.install(fd, ready_input(identity, late_reap), clock=clock)
    assert outcome.state == "quarantined" and [n for n, _ in kills] == [3, 4]
    assert kills[1][1] == start + 3750 * MS  # the cleanup deadline is capped at budget minus its grace


def test_late_exit_is_never_a_success(fake, stand_in, launches):
    fd, identity = stand_in
    nft = fake()
    clock = StepClock(step_ms=1)

    def after(n, child):
        real_poll = child.poll

        def poll():
            code = real_poll()
            if code is not None and not getattr(child, "late", False):
                child.late = True
                clock.advance(5000)  # the exit is observed after the deadline
            return code
        child.poll = poll
    launches.after = after
    outcome = h2.install(fd, ready_input(identity, nft), clock=clock)
    assert outcome.state == "timeout" and dict(outcome.tokens) == {"phase": "check", "cleanup": "not_run"}
    assert launches.children[0].returncode == 0 and len(launches.calls) == 1


class OsProxy(types.SimpleNamespace):
    """Test-process mutation: replaces ``h2.os`` only, so the installer's own ``dup``/``close`` calls are
    seen (``subprocess`` keeps the real module). ``wrong_dup_at`` substitutes another file's descriptor
    for that ``dup`` call: a borrowed fd closed and its number reused between the check and the dup."""

    def __init__(self, substitute: Path | None = None, wrong_dup_at: int = 0):
        super().__init__(events=[], dups=0, substitute=substitute, wrong_dup_at=wrong_dup_at)

    def __getattr__(self, name):
        return getattr(os, name)

    def dup(self, fd):
        self.dups += 1
        new = os.open(self.substitute, os.O_RDONLY) if self.dups == self.wrong_dup_at else os.dup(fd)
        self.events.append(("dup", new))
        return new

    def close(self, fd):
        self.events.append(("close", fd))
        return os.close(fd)


def test_every_descriptor_and_pipe_is_closed_exactly_once_on_success_timeout_and_exec_failure(
        fake, stand_in, launches, monkeypatch, tmp_path):
    fd, identity = stand_in
    for phases, expected in (({}, "receipt_ready"), ({"check": "hang"}, "timeout"), ({"check": "exit:127"}, "check_refused"),
                             ({"check": "noread"}, "receipt_ready"), ({"install": "noread", "readback": "big"}, "cleaned"),
                             ({"check": "missing"}, "helper_exec_failed")):
        nft = fake(**{k: v for k, v in phases.items() if v != "missing"})
        if phases.get("check") == "missing":
            monkeypatch.setattr(h2, "NFT_PATH", str(tmp_path / "no-such-nft"))
        policy = ready_input(identity, nft)
        launches.children.clear()
        proxy = OsProxy()
        before = open_fds()
        clock = StepClock() if phases.get("check") == "hang" else time.monotonic_ns
        monkeypatch.setattr(h2, "os", proxy)
        try:
            outcome = h2.install(fd, policy, clock=clock)
        finally:
            monkeypatch.setattr(h2, "os", os)
        assert outcome.state == expected, (phases, dict(outcome.tokens))
        assert open_fds() == before, phases
        events = proxy.events
        assert [kind for kind, _ in events] == ["dup", "close"] * len(launches.children), (phases, events)
        assert all(events[i][1] == events[i + 1][1] != fd for i in range(0, len(events), 2)), phases
        for child in launches.children:
            assert child.returncode is not None and child.stdin.closed and child.stdout.closed
        os.fstat(fd)


def test_install_is_single_use_per_input_and_cleanup_is_idempotent(fake, stand_in, launches):
    fd, identity = stand_in
    nft = fake()
    policy = ready_input(identity, nft)
    never = ready_input(identity, nft)
    assert h2.cleanup(fd, never).state == "refused_input" and launches.calls == []
    assert h2.install(fd, policy).state == "receipt_ready"
    count = len(launches.calls)
    again = h2.install(fd, policy)
    assert again.state == "refused_reused_input" and again.receipt is None and len(launches.calls) == count
    twin = h2.build_input(**{**{f.name: getattr(policy, f.name) for f in dataclasses.fields(policy) if f.init},
                             "observed_public_addresses": addresses("1.1.1.1")})
    assert h2.install(fd, twin).state == "refused_reused_input" and len(launches.calls) == count
    first = h2.cleanup(fd, policy)
    assert first.state == "cleaned" and first.receipt is None and len(launches.calls) == count + 1
    second = h2.cleanup(fd, policy)
    assert second.state == "cleaned" and dict(second.tokens)["cleanup"] == "noop" and len(launches.calls) == count + 1
    assert nft.calls().count("cleanup -f -") == 1
    assert h2.install(fd, policy).state == "refused_reused_input"
    refused = ready_input(identity, fake(check="exit:1"))
    assert h2.install(fd, refused).state == "check_refused"
    assert h2.cleanup(fd, refused).state == "check_refused" and dict(h2.cleanup(fd, refused).tokens)["cleanup"] == "noop"


def test_unreaped_helper_is_recorded_in_unresolved_helpers_and_the_outcome_is_quarantined(fake, stand_in, launches):
    fd, identity = stand_in
    nft = fake(check="hang")
    clock = StepClock()

    def after(n, child):
        child.kill = lambda: None  # the SIGKILL is lost: the child outlives the grace
    launches.after = after
    assert h2.unresolved_helpers() == {"unreaped": 0}
    outcome = h2.install(fd, ready_input(identity, nft), clock=clock)
    assert outcome.state == "quarantined" and outcome.receipt is None
    assert dict(outcome.tokens) == {"phase": "check", "cause": "timeout", "cleanup": "unknown_child"}
    child, = launches.children
    assert h2._UNREAPED_HELPERS == [child] and child not in getattr(subprocess, "_active", [])
    assert h2.unresolved_helpers() == {"unreaped": 1} and child.returncode is None
    os.kill(child.pid, signal.SIGKILL)
    deadline = time.monotonic() + 5
    while h2.unresolved_helpers() != {"unreaped": 0} and time.monotonic() < deadline:
        time.sleep(0.01)
    assert h2.unresolved_helpers() == {"unreaped": 0} and child.returncode is not None


def test_failure_after_install_cleans_only_when_identity_and_exit_are_known_else_quarantines(
        fake, stand_in, launches, tmp_path):
    fd, identity = stand_in
    cases = (
        ({"readback": "garbage"}, "cleaned", {"phase": "readback", "cause": "readback_mismatch", "cleanup": "cleaned",
                                              "readback": "document"}),
        ({"readback": "dupkeys"}, "cleaned", {"phase": "readback", "cause": "readback_mismatch", "cleanup": "cleaned",
                                              "readback": "document"}),
        ({"readback": "big"}, "cleaned", {"phase": "readback", "cause": "readback_mismatch", "cleanup": "cleaned",
                                          "readback": "none"}),
        ({"readback": "exit:1"}, "cleaned", {"phase": "readback", "cause": "readback_mismatch", "cleanup": "cleaned",
                                             "readback": "none"}),
        ({"install": "exit:1"}, "cleaned", {"phase": "install", "cause": "install_refused", "cleanup": "cleaned",
                                            "readback": "none"}),
        ({"install": "exit:1", "cleanup": "exit:1"}, "quarantined", {
            "phase": "install", "cause": "install_refused", "cleanup": "refused", "readback": "none"}),
        ({"check": "exit:1"}, "check_refused", {"phase": "check", "cleanup": "not_run"}),
    )
    for phases, state, tokens in cases:
        nft = fake(**phases)
        outcome = h2.install(fd, ready_input(identity, nft))
        assert (outcome.state, dict(outcome.tokens)) == (state, tokens), phases
        assert outcome.receipt is None
        assert ("cleanup -f -" in nft.calls()) == (tokens["cleanup"] != "not_run"), phases
    wrong_mismatch = fake()
    policy = ready_input(identity, wrong_mismatch)
    wrong_mismatch.set_readback(synthetic_readback(SLOT_DST, ["1.1.1.1"]))
    outcome = h2.install(fd, policy)
    assert outcome.state == "cleaned" and dict(outcome.tokens)["readback"] == "admit_rule"
    # The namespace identity changes under the caller's fd after the readback: no cleanup, quarantine.
    other = tmp_path / "other-namespace"
    other.write_bytes(b"y")
    swapped = fake()
    policy = ready_input(identity, swapped)
    saved = os.dup(fd)

    def swap(n, child):
        if n == 3:
            replacement = os.open(other, os.O_RDONLY)
            os.dup2(replacement, fd)
            os.close(replacement)
    launches.after = swap
    launches.calls.clear()
    try:
        outcome = h2.install(fd, policy)
    finally:
        os.dup2(saved, fd)
        os.close(saved)
        launches.after = None
    assert outcome.state == "quarantined" and dict(outcome.tokens) == {
        "phase": "final_identity", "cause": "identity_mismatch", "cleanup": "identity_mismatch", "readback": "none"}
    assert "cleanup -f -" not in swapped.calls()
    # A readback child that cannot be reaped: its exit is unknown, so no cleanup runs.
    stuck = fake(readback="hang")
    launches.after = lambda n, child: setattr(child, "kill", lambda: None) if n == 3 else None
    launches.calls.clear()
    outcome = h2.install(fd, ready_input(identity, stuck), clock=StepClock())
    assert outcome.state == "quarantined" and dict(outcome.tokens) == {
        "phase": "readback", "cause": "timeout", "cleanup": "unknown_child"}
    assert "cleanup -f -" not in stuck.calls() and h2.unresolved_helpers() == {"unreaped": 1}


def test_wrong_duplicate_identity_is_refused_before_the_handoff(fake, stand_in, launches, monkeypatch, tmp_path):
    fd, identity = stand_in
    other = tmp_path / "substituted"
    other.write_bytes(b"z")
    for wrong_at, state, tokens, launched in (  # launched: helpers started, cleanup included
            (1, "identity_mismatch", {"phase": "check", "cleanup": "not_run"}, 0),
            (2, "identity_mismatch", {"phase": "install", "cleanup": "not_run"}, 1),
            (3, "cleaned", {"phase": "readback", "cause": "identity_mismatch", "cleanup": "cleaned", "readback": "none"}, 3)):
        nft = fake()
        policy = ready_input(identity, nft)
        proxy = OsProxy(other, wrong_dup_at=wrong_at)
        launches.calls.clear()
        monkeypatch.setattr(h2, "os", proxy)
        try:
            outcome = h2.install(fd, policy)
        finally:
            monkeypatch.setattr(h2, "os", os)
        assert (outcome.state, dict(outcome.tokens)) == (state, tokens), wrong_at
        assert outcome.receipt is None and len(launches.calls) == launched, wrong_at
        kind, wrong = proxy.events[2 * (wrong_at - 1)]
        assert kind == "dup" and proxy.events[2 * (wrong_at - 1) + 1] == ("close", wrong)  # closed, never handed over
        assert ("cleanup -f -" in nft.calls()) == (wrong_at == 3)
        os.fstat(fd)


# ---------------------------------------------------------------------------------------------
# The sealed outcome and the receipt (section 4.5).

def test_no_state_other_than_receipt_ready_carries_receipt_bytes_and_outcome_cannot_be_forged(fake, stand_in):
    fd, identity = stand_in
    nft = fake()
    success = h2.install(fd, ready_input(identity, nft))
    assert success.state == "receipt_ready" and isinstance(success.receipt, bytes)
    for attempt in (lambda: h2.Outcome("receipt_ready", b"{}", {}),
                    lambda: h2.Outcome("receipt_ready", b"{}", {}, _seal=object()),
                    lambda: h2.Outcome("timeout", None, {}, _seal=None),
                    lambda: dataclasses.replace(success, state="timeout"),
                    lambda: dataclasses.replace(success, receipt=b"forged"),
                    lambda: h2._outcome("receipt_ready"),
                    lambda: h2.Outcome("timeout", b"x", {}, _seal=h2._SEAL),
                    lambda: h2.Outcome("receipt_ready", None, {}, _seal=h2._SEAL),
                    lambda: h2.Outcome("made_up", None, {}, _seal=h2._SEAL)):
        with pytest.raises(TypeError):
            attempt()
    for state in h2.STATES:
        if state != "receipt_ready":
            assert h2._outcome(state).receipt is None
    with pytest.raises(dataclasses.FrozenInstanceError):
        success.state = "timeout"
    with pytest.raises(TypeError):
        success.tokens["phase"] = "x"
    tree = ast.parse(H2_FILE.read_text())
    sites = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and ast.unparse(node.func) == "Outcome"]
    assert len(sites) == 2  # _outcome (receipt None) and the one receipt_ready transition in _install
    receipt_sites = [node for node in sites if ast.unparse(node.args[1]) != "None"]
    assert len(receipt_sites) == 1 and ast.unparse(receipt_sites[0].args[0]) == "'receipt_ready'"
    install_fn = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_install")
    assert receipt_sites[0] in list(ast.walk(install_fn))
    body = ast.unparse(install_fn)
    assert body.index("readback_matches(") < body.index("_identity_of(fd) != policy.namespace_identity:\n        return "
                                                          "_after_failure(fd, policy, start, clock, 'final_identity'") < body.index(
        "Outcome('receipt_ready'")


def test_private_receipt_document_canonicalises_to_the_cycle_receipt_and_matches_total_matcher(fake, stand_in):
    fd, identity = stand_in
    assert h2.RECEIPT_SCHEMA == cycle.RECEIPT_SCHEMA
    record = cycle.GenerationBootstrap(generation_id=secrets.token_hex(16), namespace_identity=identity, slot_id="slot-1",
                                       slot_hop_src=SLOT_SRC, slot_hop_dst=SLOT_DST, bootstrap_fence=secrets.token_hex(16))
    request = record.request()
    nft = fake()
    policy = h2.build_input(generation_id=request["generation_id"],
                            namespace_identity=(request["namespace_dev"], request["namespace_ino"]),
                            slot_id=request["slot_id"], slot_hop_src=request["slot_hop_src"],
                            slot_hop_dst=request["slot_hop_dst"], bootstrap_fence=request["bootstrap_fence"],
                            egress_hostname="canary.acme.dev", egress_port=443,
                            observed_public_addresses=addresses("8.8.8.8"))
    nft.set_readback(synthetic_readback(SLOT_DST, ["8.8.8.8"]))
    expected = codec.canonical(record.receipt())
    assert h2._receipt_document(policy) == record.receipt()
    assert codec.canonical(h2._receipt_document(policy)) == expected
    outcome = h2.install(fd, policy)
    assert outcome.state == "receipt_ready" and outcome.receipt == expected
    assert cycle._matches(outcome.receipt, record.receipt()) is True
    assert len(outcome.receipt) <= cycle.MAX_BOOTSTRAP_BYTES
    for index in range(len(expected)):
        for replacement in {(expected[index] + 1) % 256, ord(" ")} - {expected[index]}:
            changed = expected[:index] + bytes([replacement]) + expected[index + 1:]
            assert cycle._matches(changed, record.receipt()) is False, index
    assert cycle._matches(expected + b" ", record.receipt()) is False and cycle._matches(expected[:-1], record.receipt()) is False


def test_public_surface_is_exactly_six_names():
    functions = {name for name, value in vars(h2).items() if not name.startswith("_") and inspect.isfunction(value)
                 and value.__module__ == h2.__name__}
    assert functions == {"build_input", "render_table", "readback_matches", "install", "cleanup", "unresolved_helpers"}
    assert set(h2.__all__) == functions and len(h2.__all__) == 6
    classes = {name for name, value in vars(h2).items() if not name.startswith("_") and inspect.isclass(value)
               and value.__module__ == h2.__name__}
    assert classes == {"H2PolicyInput", "Outcome"}  # record types, no operations
    assert not [name for name in vars(h2) if "receipt" in name.lower() and not name.startswith("_")
                and name != "RECEIPT_SCHEMA"]
    assert [name for name, value in vars(h2.Outcome).items() if inspect.isfunction(value) and not name.startswith("_")] == []
    for name in ("install", "cleanup"):
        parameters = inspect.signature(getattr(h2, name)).parameters
        assert list(parameters) == ["fd", "policy", "clock"] and parameters["clock"].kind is inspect.Parameter.KEYWORD_ONLY


def test_a_failed_send_after_receipt_is_final_cleanup_runs_once_and_nothing_is_resent(fake, stand_in, launches):
    """Seam-level only: the H3 worker that does this does not exist; H3 proves it against the real cycle."""
    fd, identity = stand_in
    nft = fake()
    policy = ready_input(identity, nft)
    outcome = h2.install(fd, policy)
    assert outcome.state == "receipt_ready"
    worker, cycle_end = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    cycle_end.close()  # the cycle cancelled: its end is gone
    with pytest.raises(OSError):
        worker.send(outcome.receipt)
    worker.close()
    assert h2.cleanup(fd, policy).state == "cleaned"
    assert h2.install(fd, policy).state == "refused_reused_input"  # no second install, no second receipt
    assert h2.cleanup(fd, policy).state == "cleaned"
    assert nft.calls() == ["check -c -f -", "install -f -", "readback -j list table inet heel_lease", "cleanup -f -"]
    assert len(launches.calls) == 4


def test_module_uses_only_public_authority_names_and_no_cycle_or_fixture_private_attribute():
    tree = ast.parse(H2_FILE.read_text())
    used = {(node.value.id, node.attr) for node in ast.walk(tree)
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in ("_authority", "_codec")}
    assert used, "the module reads the authority constants"
    for module_name, attribute in used:
        assert not attribute.startswith("_"), (module_name, attribute)
    assert {attribute for name, attribute in used if name == "_authority"} <= {
        "TABLE", "PREPARED_SET", "ACTIVATED_MAP", "GATE_CHAIN", "NFT_PATH", "PREPARE_CHILD_TIMEOUT_MS",
        "CHILD_REAP_GRACE_MS", "MAX_BATCH_BYTES", "MAX_OUTPUT_BYTES", "CHILD_PATH"}
    assert {attribute for name, attribute in used if name == "_codec"} == {"canonical"}
    for name, attribute in used:
        assert hasattr(authority if name == "_authority" else codec, attribute)
    source = H2_FILE.read_text()
    for forbidden in ("cycle.py", "_gate_table_fixture", "_spawn", "_nft(", "_ipv4", "_settle", "_UNREAPED.",
                      "_STRINGS", "_ACTIVE_STRINGS", "SELFTEST", "generation_self_test", "LeaseDomain", "prepare(", "activate("):
        assert forbidden not in source.replace("``prepared``", "").replace("``activated``", ""), forbidden
    loads = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and ast.unparse(node.func) == "_load"]
    assert [ast.unparse(node.args[0]) for node in loads] == ["'heel_host_authority_domain'", "'heel_host_authority_codec'"]
    assert h2._authority is cycle.authority and h2._codec is cycle.codec  # one registry per process


def test_doc_names_every_state_token_and_the_non_goals():
    text = DOC_FILE.read_text()
    assert text.splitlines()[2].startswith("Status: source candidate, component evidence only.")
    for state in h2.STATES:
        assert f"`{state}`" in text, state
    for phrase in ("**Trust precondition (H3, trusted constructor):** `observed_public_addresses` is the tuple the unchanged "
                   "`select_public_addresses` returned for the preflight of the validated `egress_hostname`, unmodified.",
                   "no `Enablement` member", "no customer mode", "no environment variable", "H2 remains HOLD",
                   "not an IPv6 coverage claim", "H2-2", "H3", "H6", "fresh Fable", "no negative receipt",
                   "`H2_WORKER_BUDGET_MS`", "4000", "2500", "`refused_platform`", "`_HELPER_SOURCE`", "`_PLATFORM_OK`",
                   "`NFT_PATH`", "test_worker_sends_receipt_once_only_from_receipt_ready",
                   "test_worker_reports_unresolved_when_unresolved_helpers_is_nonzero", "C3"):
        assert phrase in text, phrase
    for token in ("124", "125", "126"):
        assert token in text
