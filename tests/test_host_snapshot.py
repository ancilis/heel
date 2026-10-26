"""H1A-2 control-plane host-authority snapshot decision and private listener service.

Real SQLite through ``CONTROL_PLANE_MIGRATIONS``; the active fixture is reached through the
product's own paths (binding create, runner submission, approval, claim). Rows altered by hand to
reach a state the product does not produce are labelled ``STATE-INJECTION`` in the test docstring
or at the statement. Seams used here, each for the snapshot tests only and never passed by a
production caller (pinned by ``test_seams_are_labelled_and_unused_by_production_modules``):
SEAM-CLOCK, SEAM-RECORDING-CONNECTION, SEAM-CAPACITY, SEAM-LISTENER, SEAM-SERVE-FAILURE,
SEAM-THREAD-START, SEAM-STOP-HANG. Unit seams never claim end to end; only S-20 (Linux) runs the
real ``check_startup`` and peer rule path.
"""
from __future__ import annotations

import contextlib
import errno
import fcntl
import json
import logging
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from unittest import mock

import pytest

from heel.canary_contracts import canonical_bytes, canonical_digest
from heel.crypto import SigningAuthority
from heel.saas import host_snapshot
from heel.saas.canary_runs import CanaryRunService
from heel.saas.catalog import CATALOG_VERSION
from heel.saas.host_authority import (
    REQUEST_SCHEMA, HostAuthorityConfig, HostAuthorityListener, PeerProfile, canonical,
)
from heel.saas.host_snapshot import (
    HostAuthorityService, HostAuthorityServiceError, HostSnapshotDecider, HostSnapshotError, StopResult,
)
from heel.saas.migrate import CONTROL_PLANE_MIGRATIONS, Migrator
from heel.saas.runner_auth import RunnerAuthStore, initialize_runner_auth_schema
from heel.saas.runner_contexts import RunnerContextBindingService
from tests.canary_test_support import NOW, VERIFICATION_DIGEST, approval_projection, operational_projection

REPO_ROOT = Path(__file__).resolve().parents[1]
RUNNER_PEPPER = b"r" * 32
HOST_THREAD = "heel-host-authority"


# ---------------------------------------------------------------------------------------------
# Fixture: a claimed run with a claimed grant and an active binding, through product paths.

class Clock:
    """SEAM-CLOCK snapshot tests only: the decider's single wall-clock sample, counted."""

    def __init__(self, ns: int):
        self.ns = ns
        self.calls = 0

    def __call__(self) -> int:
        self.calls += 1
        return self.ns

    def advance_ms(self, ms: int) -> None:
        self.ns += ms * 1_000_000


class SecondsClock:
    def __init__(self, value: float):
        self.value = value

    def __call__(self) -> float:
        return self.value


def _ids(index: int) -> dict[str, str]:
    char = "123456789abcdef"[index]
    return {
        "workspace_id": "ws_" + char * 16, "project_id": "prj_" + char * 32,
        "environment_id": "env_" + char * 32, "runner_id": "runr_" + char,
        "verification_record_digest": VERIFICATION_DIGEST if index == 0 else "acde"[index % 4] * 64,
    }


def open_db(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _resign(value: dict, signer: SigningAuthority, **changes) -> dict:
    unsigned = {
        key: item for key, item in value.items()
        if key not in {"projection_digest", "signing_key_id", "signature_b64"}
    }
    unsigned.update(changes)
    signed = dict(unsigned)
    signed["projection_digest"] = canonical_digest(unsigned)
    signed.update(signer.sign(canonical_bytes(unsigned)))
    return signed


def _seed_workspace(conn: sqlite3.Connection, ids: dict, base: float) -> SigningAuthority:
    base_ms = int(base * 1000)
    org = "org_" + ids["workspace_id"][3:]
    conn.execute("INSERT INTO orgs VALUES(?,?,?)", (org, "Org", base))
    conn.execute(
        "INSERT INTO workspaces VALUES(?,?,?,?,?,?)", (ids["workspace_id"], org, "WS", "free", CATALOG_VERSION, base),
    )
    conn.execute(
        "INSERT INTO projects VALUES(?,?,?,?,?)", (ids["workspace_id"], ids["project_id"], "P", "user_owner", base),
    )
    conn.execute("INSERT OR IGNORE INTO users VALUES(?,?,?)", ("user_owner", "owner@snapshot.test", base))
    conn.execute("INSERT INTO memberships VALUES(?,?,?,?)", (ids["workspace_id"], "user_owner", "owner", base))
    signer = SigningAuthority.generate()
    conn.execute(
        "INSERT INTO canary_environments("
        "environment_id,workspace_id,project_ref,origin,environment_class,status,created_at,"
        "attestation_text,attestation_version,attestation_acknowledgement,attested_by,attested_at,"
        "proof_method,proof_version,normalization_version,challenge_generation,last_check_at,"
        "verified_at,proof_expires_at,verification_record_digest) "
        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            ids["environment_id"], ids["workspace_id"], ids["project_id"], "https://canary.acme.dev", "staging",
            "verified", base, "ownership verified; environment classification supplied by you", "v1", "accepted",
            "user_owner", base, "https-file", "https-file.v1", "exact-origin.v1", 1, base, base, base + 3600,
            ids["verification_record_digest"],
        ),
    )
    conn.execute(
        "INSERT INTO canary_runners VALUES(?,?,?,?,?)",
        (ids["runner_id"], ids["workspace_id"], "Runner", "active", base),
    )
    conn.execute(
        "INSERT INTO canary_runner_keys VALUES(?,?,?,?,?,?,NULL)",
        (signer.key_id, ids["workspace_id"], ids["runner_id"], signer.canonical_public_key, "active", base),
    )
    identity = {
        "schema_version": "heel.runner-identity.v1", "runner_id": ids["runner_id"],
        "workspace_id": ids["workspace_id"],
        "public_key": {"algorithm": "Ed25519", "key_id": signer.key_id, "public_key_b64": signer.canonical_public_key},
        "fingerprint": __import__("hashlib").sha256(signer.public_key_bytes).hexdigest(),
        "runner_version": "1.0.0", "adapter_versions": ["1.0.0"],
        "capabilities": ["runner_claim", "runner_heartbeat", "runner_progress", "runner_result"],
        "pairing": {"paired_by": "user_owner", "paired_at_ms": base_ms, "fingerprint_confirmation": "confirmed",
                    "phrase_confirmation": "confirmed"},
        "last_heartbeat_at_ms": base_ms, "state": "active",
        "rotation": {"previous_key_ids": [], "rotated_at_ms": None, "verification_overlap_ends_at_ms": None},
        "revocation": {"revoked_at_ms": None, "revoked_by": None, "reason_code": None},
    }
    identity["identity_digest"] = canonical_digest(identity)
    conn.execute(
        "INSERT INTO canary_runner_identity_records VALUES(?,?,?,?,?)",
        (ids["workspace_id"], ids["runner_id"], canonical_bytes(identity).decode(), identity["identity_digest"], base),
    )
    conn.commit()
    return signer


class Authority:
    """One workspace's authoritative run graph in a real SQLite file."""

    def __init__(self, path: str, signing: SigningAuthority, index: int, base: float):
        self.path, self.signing, self.index, self.base = path, signing, index, base
        self.base_ms = int(base * 1000)
        self.ids = _ids(index)
        self.clock = SecondsClock(base)

    def runs(self, conn: sqlite3.Connection) -> CanaryRunService:
        auth = RunnerAuthStore(conn, pepper=RUNNER_PEPPER, now=self.clock)
        return CanaryRunService(conn, signing=self.signing, clock=self.clock, runner_auth=auth)

    def request(self, *, generation_id: str | None = None, sequence: int = 1, monotonic_ms: int = 1000,
                host_boot_epoch: str = "boot-0001", slot_id: str = "slot-a", **overrides) -> dict:
        request = {
            "schema_version": REQUEST_SCHEMA, "host_boot_epoch": host_boot_epoch, "slot_id": slot_id,
            "request_nonce": secrets.token_hex(16), "generation_id": generation_id or secrets.token_hex(16),
            "workspace_id": self.ids["workspace_id"], "project_id": self.ids["project_id"],
            "environment_id": self.ids["environment_id"],
            "verification_record_digest": self.ids["verification_record_digest"],
            "runner_id": self.ids["runner_id"], "runner_key_id": self.runner.key_id,
            "binding_id": getattr(self, "binding_id", "rcb_" + "0" * 32),
            "binding_digest": getattr(self, "binding_digest", "0" * 64),
            "run_id": self.run_id, "grant_id": getattr(self, "grant_id", "cgr_none"),
            "grant_digest": getattr(self, "grant_digest", "0" * 64),
            "sequence": sequence, "monotonic_ms": monotonic_ms, "kill_switch_generation": 0,
        }
        request.update(overrides)
        return request


def build_authority(path: str, *, signing: SigningAuthority | None = None, index: int = 0, base: float = NOW,
                    claim: bool = True, link: bool = True) -> Authority:
    """Migrate (first workspace only) and reach the claimed state through the product's own paths."""
    authority = Authority(path, signing or SigningAuthority.generate(), index, base)
    conn = open_db(path)
    try:
        if index == 0:
            Migrator(conn, CONTROL_PLANE_MIGRATIONS).apply_all()
            initialize_runner_auth_schema(conn)
            conn.commit()
        ids = authority.ids
        authority.runner = _seed_workspace(conn, ids, base)
        projection = approval_projection(
            authority.runner, workspace_id=ids["workspace_id"], project_ref=ids["project_id"],
            environment_id=ids["environment_id"], runner_id=ids["runner_id"],
            verification_digest=ids["verification_record_digest"],
        )
        projection = _resign(
            projection, authority.runner, compiled_at_ms=authority.base_ms, projection_id=f"ap_snapshot{index}",
        )
        runs = authority.runs(conn)
        if link:
            contexts = RunnerContextBindingService(conn, signing=authority.signing, clock=authority.clock)
            contexts.create(
                ids["workspace_id"], ids["project_id"],
                {"schema_version": "heel.runner-context-binding-create.v1", "environment_id": ids["environment_id"],
                 "verification_record_digest": ids["verification_record_digest"], "runner_id": ids["runner_id"],
                 "runner_key_id": authority.runner.key_id},
                actor="user_owner", role="owner",
            )
            binding = conn.execute(
                "SELECT * FROM canary_runner_context_bindings WHERE workspace_id=?", (ids["workspace_id"],),
            ).fetchone()
            authority.binding_id, authority.binding_digest = binding["rcb_id"], binding["binding_digest"]
            conn.execute("BEGIN IMMEDIATE")
            submitted = runs.submit_projection_from_runner_in_transaction(
                projection, binding, uploaded_by_runner_id=ids["runner_id"],
            )
            conn.commit()
        else:
            # The browser-submitted (legacy human) path: no runner context link row is written.
            submitted = runs.submit_projection(projection, uploaded_by="user_owner")
        authority.run_id = submitted["run_id"]
        approved = runs.approve(
            ids["workspace_id"], ids["project_id"], submitted["run_id"],
            projection_digest=projection["projection_digest"], actor="user_owner", role="owner",
            reason="Run the bounded canary rehearsal", exact_hostname="canary.acme.dev",
            recent_auth_at_ms=authority.base_ms, idempotency_key="ca1-" + "abcdef0123456789"[index] * 64,
            expected_kill_switch_generation=0,
        )
        authority.grant = approved["grant"]
        authority.grant_id, authority.grant_digest = approved["grant_id"], approved["grant"]["grant_digest"]
        if claim:
            assert runs.claim(ids["workspace_id"], ids["runner_id"], authority.runner.key_id) is not None
        conn.commit()
    finally:
        conn.close()
    return authority


@pytest.fixture
def short_tmp():
    """A short private directory (AF_UNIX paths are limited to ~104 bytes on macOS)."""
    path = tempfile.mkdtemp(prefix="hs")
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def authority(short_tmp) -> Authority:
    return build_authority(os.path.join(short_tmp, "cp.db"))


def default_clock(authority: Authority) -> Clock:
    # 5 s after the claim plus a sub-millisecond part, so ceil and floor differ.
    return Clock(authority.base_ms * 1_000_000 + 5_000_000_000 + 123_456)


def make_decider(authority: Authority, clock: Clock | None = None, **seams) -> HostSnapshotDecider:
    return HostSnapshotDecider(
        authority.path, signing=authority.signing, draining=lambda: False,
        _time_ns_for_tests=clock or default_clock(authority), **seams,
    )


def ledger(path: str) -> list[dict]:
    """Durable read on a fresh connection, after the decider returned."""
    conn = open_db(path)
    try:
        return [dict(row) for row in conn.execute(
            "SELECT * FROM host_authority_generations ORDER BY enrolled_cp_ms, generation_id",
        )]
    finally:
        conn.close()


def ledger_row(path: str, generation_id: str) -> dict | None:
    return next((row for row in ledger(path) if row["generation_id"] == generation_id), None)


def run_row(path: str, run_id: str) -> dict:
    conn = open_db(path)
    try:
        return dict(conn.execute("SELECT * FROM canary_runs WHERE run_id=?", (run_id,)).fetchone())
    finally:
        conn.close()


def inject(path: str, *statements: tuple[str, tuple]) -> None:
    """STATE-INJECTION: hand-altered rows for states the product does not produce."""
    conn = open_db(path)
    try:
        conn.execute("PRAGMA ignore_check_constraints=ON")
        for sql, params in statements:
            conn.execute(sql, params)
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------------------------
# S-1 .. S-8: selection, issued tuple, live state.

def test_snapshot_active_from_authoritative_state_real_sqlite(authority):
    clock = default_clock(authority)
    request = authority.request()
    reply = make_decider(authority, clock)(dict(request))

    assert reply["decision"] == "active" and reply["reason"] == "none"
    assert reply["sequence"] == 1
    assert reply["request_digest"] == host_snapshot.request_digest(request)
    assert reply["server_time_ms"] == math.ceil(clock.ns / 1_000_000) == clock.ns // 1_000_000 + 1
    conn = open_db(authority.path)
    try:
        env = conn.execute("SELECT proof_expires_at FROM canary_environments").fetchone()
        grant = conn.execute("SELECT expires_at FROM canary_execution_grants").fetchone()
        binding = conn.execute(
            "SELECT expires_at_ms,public_key_digest FROM canary_runner_context_bindings",
        ).fetchone()
    finally:
        conn.close()
    assert reply["proof_expires_at_ms"] == math.floor(env["proof_expires_at"] * 1000) - 1
    assert reply["grant_expires_at_ms"] == grant["expires_at"] == authority.grant["expires_at_ms"]
    assert reply["binding_expires_at_ms"] == binding["expires_at_ms"]
    assert reply["public_key_digest"] == binding["public_key_digest"]
    for field in ("workspace_id", "project_id", "environment_id", "runner_id", "runner_key_id", "run_id",
                  "binding_id", "binding_digest", "grant_id", "grant_digest", "verification_record_digest"):
        assert reply[field] == request[field], field
    assert (reply["run_status"], reply["stop_reason"], reply["egress_hostname"], reply["egress_port"]) == (
        "claimed", "none", "canary.acme.dev", 443)
    row = ledger_row(authority.path, request["generation_id"])
    assert (row["state"], row["last_sequence"], row["requests"], row["enrolled_cp_ms"]) == (
        "open", 1, 1, reply["server_time_ms"])


SUBSTITUTES = {
    "project_id": "prj_" + "f" * 32, "environment_id": "env_" + "f" * 32, "runner_id": "runr_other",
    "runner_key_id": "k_other", "run_id": "crun_" + "f" * 32, "binding_id": "rcb_" + "f" * 32,
    "binding_digest": "f" * 64, "grant_id": "cgr_other", "grant_digest": "f" * 64,
    "verification_record_digest": "f" * 64,
}


def test_issued_tuple_substitution_is_tuple_mismatch_for_every_field(authority):
    clock = default_clock(authority)
    decider = make_decider(authority, clock)
    generation = secrets.token_hex(16)
    assert decider(authority.request(generation_id=generation))["reason"] == "none"
    before = run_row(authority.path, authority.run_id)
    assert set(SUBSTITUTES) == set(host_snapshot._ISSUED_FIELDS)
    for offset, (field, value) in enumerate(SUBSTITUTES.items(), start=2):
        clock.advance_ms(1000)
        reply = decider(authority.request(
            generation_id=generation, sequence=offset, monotonic_ms=1000 * offset, **{field: value},
        ))
        assert (reply["decision"], reply["reason"]) == ("inactive", "tuple_mismatch"), field
        assert ledger_row(authority.path, generation)["last_sequence"] == offset  # the ledger advanced
    assert run_row(authority.path, authority.run_id) == before  # _gate never reached: run untouched


def test_cross_tenant_values_are_tuple_mismatch_and_touch_nothing(short_tmp):
    path = os.path.join(short_tmp, "cp.db")
    signing = SigningAuthority.generate()
    first = build_authority(path, signing=signing, index=0)
    second = build_authority(path, signing=signing, index=1)
    decider = make_decider(first)
    before = (run_row(path, first.run_id), run_row(path, second.run_id))
    foreign = second.request()
    for field in SUBSTITUTES:
        mixed = first.request(**{field: foreign[field]})
        assert decider(mixed)["reason"] == "tuple_mismatch", field
    # Every field of the other tenant at once under this workspace id, and the reverse.
    whole = dict(foreign, workspace_id=first.ids["workspace_id"], generation_id=secrets.token_hex(16))
    assert decider(whole)["reason"] == "tuple_mismatch"
    reverse = dict(first.request(), workspace_id=second.ids["workspace_id"])
    assert decider(reverse)["reason"] == "tuple_mismatch"
    assert (run_row(path, first.run_id), run_row(path, second.run_id)) == before


def _transition(authority: Authority, name: str) -> None:
    from heel.saas.ops import OpsStore
    from heel.saas.verification import VerifiedEnvironmentService

    ids = authority.ids
    conn = open_db(authority.path)
    try:
        if name == "environment_revoke":
            VerifiedEnvironmentService(conn).revoke(
                ids["workspace_id"], ids["project_id"], ids["environment_id"], actor="user_owner", reason="test",
            )
        elif name == "binding_revoke":
            RunnerContextBindingService(conn, signing=authority.signing, clock=authority.clock).revoke(
                ids["workspace_id"], ids["project_id"], authority.binding_id, actor="user_owner", role="owner",
            )
        elif name in {"kill_switch_trip", "kill_switch_trip_clear"}:
            ops = OpsStore(conn)
            ops.trip(ids["workspace_id"], actor="ops", reason="incident")
            if name == "kill_switch_trip_clear":
                ops.clear(ids["workspace_id"], actor="ops", reason="resolved")
        elif name == "runner_revoke":
            RunnerAuthStore(conn, pepper=RUNNER_PEPPER, now=authority.clock).revoke(
                ids["workspace_id"], ids["runner_id"], actor="user_owner",
            )
        else:
            raise AssertionError(name)
        conn.commit()
    finally:
        conn.close()


@pytest.mark.parametrize(("transition", "reason"), [
    ("environment_revoke", "proof_revoked"),
    ("binding_revoke", "binding_inactive"),
    ("kill_switch_trip", "kill_switch_active"),
    ("kill_switch_trip_clear", "kill_switch_generation_changed"),
    ("runner_revoke", "no_active_run"),  # the product stops the run first
])
def test_live_state_reasons_follow_the_products_own_transitions(short_tmp, transition, reason):
    authority = build_authority(os.path.join(short_tmp, "cp.db"))
    decider = make_decider(authority)
    assert decider(authority.request())["reason"] == "none"
    _transition(authority, transition)
    reply = decider(authority.request())
    assert (reply["decision"], reply["reason"]) == ("inactive", reason)
    if transition == "kill_switch_trip_clear":
        assert reply["kill_switch_generation"] == 2


@pytest.mark.parametrize(("reason", "statement"), [
    ("runner_revoked", ("UPDATE canary_runners SET status='revoked'", ())),
    ("key_revoked", ("UPDATE canary_runner_keys SET status='revoked',revoked_at=1", ())),
    ("grant_not_claimed", ("UPDATE canary_execution_grants SET status='revoked'", ())),
])
def test_live_state_reasons_by_state_injection(short_tmp, reason, statement):
    """STATE-INJECTION: the run stays claimed while one authority row changes underneath it."""
    authority = build_authority(os.path.join(short_tmp, "cp.db"))
    inject(authority.path, statement)
    assert make_decider(authority)(authority.request())["reason"] == reason


def test_digest_replacement_persists_stop_in_the_same_transaction(authority):
    """STATE-INJECTION of the environment re-verification outcome (the live digest replaced, as
    ``verification.py`` re-proof writes it; the network proof itself is not exercised here, the
    same technique as ``test_environment_reproof_digest_replacement_permanently_closes_gate``)."""
    clock = default_clock(authority)
    decider = make_decider(authority, clock)
    conn = open_db(authority.path)
    try:
        events = conn.execute("SELECT COUNT(*) FROM canary_run_events").fetchone()[0]
        audits = conn.execute("SELECT COUNT(*) FROM canary_audit_records").fetchone()[0]
    finally:
        conn.close()
    inject(authority.path, ("UPDATE canary_environments SET verification_record_digest=?", ("b" * 64,)))
    reply = decider(authority.request())  # the issued tuple still matches the signed records
    assert reply["reason"] == "verification_digest_replaced"
    run = run_row(authority.path, authority.run_id)
    assert (run["status"], run["stop_reason"]) == ("stop_requested", "target_revoked")
    assert run["stop_requested_at_ms"] >= clock.ns // 1_000_000
    conn = open_db(authority.path)
    try:
        assert conn.execute("SELECT COUNT(*) FROM canary_run_events").fetchone()[0] == events + 1
        assert conn.execute("SELECT COUNT(*) FROM canary_audit_records").fetchone()[0] == audits + 1
        assert conn.execute(
            "SELECT event_type FROM canary_run_events ORDER BY rowid DESC LIMIT 1",
        ).fetchone()[0] == "stop_requested"
    finally:
        conn.close()
    assert decider(authority.request())["reason"] == "no_active_run"


def test_zero_active_runs_is_no_active_run_and_two_is_multiple_active_runs(short_tmp):
    unclaimed = build_authority(os.path.join(short_tmp, "cp.db"), claim=False)
    with mock.patch.object(HostSnapshotDecider, "_issued_tuple_matches", wraps=HostSnapshotDecider._issued_tuple_matches) as compared:
        decider = make_decider(unclaimed)
        assert decider(unclaimed.request())["reason"] == "no_active_run"
        conn = open_db(unclaimed.path)
        try:
            runs = unclaimed.runs(conn)
            assert runs.claim(unclaimed.ids["workspace_id"], unclaimed.ids["runner_id"], unclaimed.runner.key_id)
            conn.commit()
        finally:
            conn.close()
        assert decider(unclaimed.request())["reason"] == "none"
        compared.reset_mock()
        # STATE-INJECTION: a second claimed run in the same workspace (the product never claims two).
        conn = open_db(unclaimed.path)
        try:
            row = dict(conn.execute("SELECT * FROM canary_runs").fetchone())
        finally:
            conn.close()
        row["run_id"], row["approval_id"] = "crun_" + "0" * 32, "ap_injected"
        columns = ",".join(row)
        inject(unclaimed.path, ("PRAGMA foreign_keys=OFF", ()),
               (f"INSERT INTO canary_runs({columns}) VALUES({','.join('?' for _ in row)})", tuple(row.values())))
        assert decider(unclaimed.request())["reason"] == "multiple_active_runs"
        assert compared.call_count == 0  # no tuple comparison was performed


def test_stop_requested_and_finalizing_runs_are_no_active_run(authority):
    decider = make_decider(authority)
    seen = [decider(authority.request())["reason"]]
    grant = authority.grant
    conn = open_db(authority.path)
    try:
        runs = authority.runs(conn)
        ids = authority.ids
        runs.progress(ids["workspace_id"], ids["project_id"], authority.run_id, ids["runner_id"], operational_projection(
            authority.runner, grant, sequence=0, phase="running", requests_started=1,
            updated_at_ms=authority.base_ms + 200,
        ))
        runs.request_stop(ids["workspace_id"], ids["project_id"], authority.run_id, actor="user_owner",
                          reason="cloud_stop", expected_kill_switch_generation=0)
    finally:
        conn.close()
    seen.append(decider(authority.request())["reason"])
    conn = open_db(authority.path)
    try:
        ack = authority.runs(conn).ack_stop(
            authority.ids["workspace_id"], authority.ids["project_id"], authority.run_id, authority.ids["runner_id"],
            operational_projection(
                authority.runner, grant, sequence=1, phase="stop_requested", requests_started=1,
                stop_reason="cloud_stop", stop_requested_at_ms=authority.base_ms,
                stop_acknowledged_at_ms=authority.base_ms + 4999, updated_at_ms=authority.base_ms + 4999,
            ),
        )
        assert ack["accepted"] is True
    finally:
        conn.close()
    seen.append(decider(authority.request())["reason"])
    assert seen == ["none", "no_active_run", "no_active_run"]
    assert "stop_requested" not in seen and "run_not_active" not in seen
    assert decider.counters["reason"].get("stop_requested") is None
    assert decider.counters["reason"].get("run_not_active") is None


def test_missing_binding_link_is_tuple_mismatch(short_tmp):
    """The browser-submitted path writes no runner context link; the run is claimed by the
    product's own claim. A request asserting any binding is a tuple mismatch, never
    ``binding_inactive``."""
    authority = build_authority(os.path.join(short_tmp, "cp.db"), link=False)
    conn = open_db(authority.path)
    try:
        assert conn.execute("SELECT COUNT(*) FROM canary_runner_context_projection_links").fetchone()[0] == 0
        assert conn.execute("SELECT status FROM canary_runs").fetchone()[0] == "claimed"
    finally:
        conn.close()
    reply = make_decider(authority)(authority.request())
    assert reply["reason"] == "tuple_mismatch"


# ---------------------------------------------------------------------------------------------
# S-9 .. S-13, S-25: the durable anti-replay and elapsed ledger (migration 31).

def test_sequence_enrolment_replay_and_concurrent_duplicate(authority):
    clock = default_clock(authority)
    decider = make_decider(authority, clock)
    g = secrets.token_hex(16)
    assert decider(authority.request(generation_id=g, sequence=1))["reason"] == "none"
    clock.advance_ms(1000)
    assert decider(authority.request(generation_id=g, sequence=1, monotonic_ms=2000))["reason"] == "replayed_sequence"
    row = ledger_row(authority.path, g)
    assert (row["state"], row["close_reason"]) == ("closed", "replayed_sequence")  # committed with the reply
    clock.advance_ms(1000)
    assert decider(authority.request(generation_id=g, sequence=3, monotonic_ms=3000))["reason"] == "replayed_sequence"
    assert ledger_row(authority.path, g) == row  # closed never changes again

    # Two deciders on one file, two threads, the same q=2: exactly one advances.
    g2 = secrets.token_hex(16)
    clock.advance_ms(1000)
    assert decider(authority.request(generation_id=g2, sequence=1, monotonic_ms=10_000))["reason"] == "none"
    clocks = [Clock(clock.ns + 1_000_000_000), Clock(clock.ns + 1_000_000_000)]
    deciders = [make_decider(authority, item) for item in clocks]
    barrier = threading.Barrier(2)
    outcomes: list[str] = []

    def race(index: int) -> None:
        barrier.wait(5)
        try:
            outcomes.append(deciders[index](authority.request(generation_id=g2, sequence=2, monotonic_ms=11_000))["reason"])
        except HostSnapshotError as error:
            outcomes.append(error.code)

    threads = [threading.Thread(target=race, args=(index,)) for index in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
    assert outcomes.count("none") == 1, outcomes
    assert set(outcomes) - {"none"} <= {"replayed_sequence", "db_busy"}, outcomes
    assert ledger_row(authority.path, g2)["last_sequence"] == 2


def test_unknown_generation_not_at_sequence_one_is_closed_forever(authority):
    clock = default_clock(authority)
    decider = make_decider(authority, clock)
    g = secrets.token_hex(16)
    assert decider(authority.request(generation_id=g, sequence=5, monotonic_ms=5000))["reason"] == "replayed_sequence"
    row = ledger_row(authority.path, g)
    assert (row["state"], row["close_reason"], row["last_sequence"]) == ("closed", "unenrolled", 5)
    assert row["enrolled_cp_ms"] == row["last_cp_ms"] == row["closed_cp_ms"]
    for sequence in (6, 1):
        clock.advance_ms(1000)
        assert decider(authority.request(generation_id=g, sequence=sequence, monotonic_ms=9000))["reason"] == (
            "replayed_sequence")
    assert ledger_row(authority.path, g) == row


def test_supersession_identity_mismatch_and_closed_never_reopens(authority):
    clock = default_clock(authority)
    decider = make_decider(authority, clock)
    g, g2 = secrets.token_hex(16), secrets.token_hex(16)
    assert decider(authority.request(generation_id=g, sequence=1))["reason"] == "none"
    clock.advance_ms(1000)
    assert decider(authority.request(generation_id=g2, sequence=1, monotonic_ms=2000))["reason"] == "none"
    assert (ledger_row(authority.path, g)["state"], ledger_row(authority.path, g)["close_reason"]) == (
        "closed", "superseded")
    clock.advance_ms(1000)
    assert decider(authority.request(generation_id=g, sequence=2, monotonic_ms=3000))["reason"] == "replayed_sequence"
    clock.advance_ms(1000)
    reply = decider(authority.request(generation_id=g2, sequence=2, monotonic_ms=3000,
                                      host_boot_epoch="boot-other", slot_id="slot-z"))
    assert reply["reason"] == "replayed_sequence"
    row = ledger_row(authority.path, g2)  # fresh connection: the closure committed with the reply
    assert (row["state"], row["close_reason"], row["host_boot_epoch"], row["slot_id"]) == (
        "closed", "identity_mismatch", "boot-0001", "slot-a")
    clock.advance_ms(1000)
    assert decider(authority.request(generation_id=g2, sequence=1, monotonic_ms=4000))["reason"] == "replayed_sequence"
    assert ledger_row(authority.path, g2) == row


def test_backward_and_forward_clock_gaps_close_the_generation_durably(authority):
    clock = default_clock(authority)
    decider = make_decider(authority, clock)

    def enrol(slot: str) -> str:
        g = secrets.token_hex(16)
        assert decider(authority.request(generation_id=g, slot_id=slot, sequence=1, monotonic_ms=1000))["reason"] == (
            "none")
        return g

    # Monotonic decreasing: impossible on one kernel.
    g = enrol("slot-mono")
    clock.advance_ms(1000)
    assert decider(authority.request(generation_id=g, slot_id="slot-mono", sequence=2, monotonic_ms=500))[
        "reason"] == "clock_gap"
    assert ledger_row(authority.path, g)["close_reason"] == "clock_gap"

    # CP time backward: closes with closed_cp_ms == last_cp_ms (the CHECK holds).
    g = enrol("slot-back")
    last_cp = ledger_row(authority.path, g)["last_cp_ms"]
    clock.advance_ms(-2000)
    assert decider(authority.request(generation_id=g, slot_id="slot-back", sequence=2, monotonic_ms=2000))[
        "reason"] == "clock_gap"
    row = ledger_row(authority.path, g)
    assert (row["state"], row["close_reason"], row["closed_cp_ms"], row["last_cp_ms"]) == (
        "closed", "clock_gap", last_cp, last_cp)
    clock.advance_ms(2000)

    # CP forward 10 s while the host's monotonic advanced 1 s (frozen guest clock).
    g = enrol("slot-fwd")
    clock.advance_ms(10_000)
    assert decider(authority.request(generation_id=g, slot_id="slot-fwd", sequence=2, monotonic_ms=2000))[
        "reason"] == "clock_gap"
    assert ledger_row(authority.path, g)["close_reason"] == "clock_gap"

    # Both directions within 500 ms stay active.
    g = enrol("slot-ok")
    clock.advance_ms(1000)
    assert decider(authority.request(generation_id=g, slot_id="slot-ok", sequence=2, monotonic_ms=2400))[
        "reason"] == "none"
    clock.advance_ms(1000)
    assert decider(authority.request(generation_id=g, slot_id="slot-ok", sequence=3, monotonic_ms=3000))[
        "reason"] == "none"
    row = ledger_row(authority.path, g)
    assert (row["state"], row["last_sequence"], row["requests"]) == ("open", 3, 3)


def test_restart_of_the_control_plane_keeps_the_ledger(authority):
    clock = default_clock(authority)
    g = secrets.token_hex(16)
    first = make_decider(authority, clock)
    assert first(authority.request(generation_id=g, sequence=1))["reason"] == "none"
    clock.advance_ms(1000)
    assert first(authority.request(generation_id=g, sequence=2, monotonic_ms=2000))["reason"] == "none"
    restarted = make_decider(authority, clock)  # a new process would construct a new decider on the file
    clock.advance_ms(1000)
    assert restarted(authority.request(generation_id=g, sequence=3, monotonic_ms=3000))["reason"] == "none"
    clock.advance_ms(1000)
    assert restarted(authority.request(generation_id=g, sequence=3, monotonic_ms=4000))["reason"] == "replayed_sequence"
    again = make_decider(authority, clock)
    clock.advance_ms(1000)
    assert again(authority.request(generation_id=g, sequence=4, monotonic_ms=5000))["reason"] == "replayed_sequence"
    assert ledger_row(authority.path, g)["close_reason"] == "replayed_sequence"


def test_generation_capacity_is_fail_closed_and_rows_are_never_deleted(authority):
    clock = default_clock(authority)
    capped = make_decider(authority, clock, _max_generation_rows_for_tests=3)  # SEAM-CAPACITY snapshot tests only
    generations = [secrets.token_hex(16) for _ in range(3)]
    for index, g in enumerate(generations):
        assert capped(authority.request(generation_id=g, slot_id=f"slot-{index}"))["reason"] == "none"
    before = ledger(authority.path)
    for attempt in (
        authority.request(slot_id="slot-new"),                   # new generation at q=1
        authority.request(slot_id="slot-new", sequence=7),       # unenrolled attempt
        authority.request(slot_id="slot-0"),                     # would supersede slot-0
    ):
        with pytest.raises(HostSnapshotError) as raised:
            capped(attempt)
        assert raised.value.code == "generation_capacity_exhausted"
        assert ledger(authority.path) == before  # nothing written, slot-0 not closed (rolled back)
    assert capped.counters["code"]["generation_capacity_exhausted"] == 3
    clock.advance_ms(1000)
    assert capped(authority.request(generation_id=generations[0], slot_id="slot-0", sequence=2,
                                    monotonic_ms=2000))["reason"] == "none"  # an UPDATE, not an INSERT

    # A reviewed release raising the bound admits a new generation with every old row present.
    raised_bound = make_decider(authority, clock, _max_generation_rows_for_tests=4)
    fresh = secrets.token_hex(16)
    assert raised_bound(authority.request(generation_id=fresh, slot_id="slot-new"))["reason"] == "none"
    after = {row["generation_id"]: row for row in ledger(authority.path)}
    assert set(generations) | {fresh} == set(after)

    # 1000 requests with 50 closures: the row count never decreases.
    bulk = make_decider(authority, clock)
    unknown = {"workspace_id": "ws_" + "0" * 16}  # the ledger runs before selection; keeps this fast
    counts = [len(ledger(authority.path))]
    closures = 0
    for round_ in range(50):
        g = secrets.token_hex(16)
        for sequence in range(1, 20):
            clock.advance_ms(100)
            assert bulk(authority.request(generation_id=g, slot_id=f"bulk-{round_}", sequence=sequence,
                                          monotonic_ms=100 * sequence, **unknown))["reason"] == "workspace_unknown"
        clock.advance_ms(100)
        assert bulk(authority.request(generation_id=g, slot_id=f"bulk-{round_}", sequence=19,
                                      monotonic_ms=2000, **unknown))["reason"] == "replayed_sequence"
        closures += 1
        counts.append(len(ledger(authority.path)))
    assert closures == 50 and counts == sorted(counts) and counts[-1] == counts[0] + 50
    assert sum(1 for row in ledger(authority.path) if row["close_reason"] == "replayed_sequence") == 50
    assert host_snapshot.MAX_GENERATION_ROWS == 65_536


# ---------------------------------------------------------------------------------------------
# S-14: expiry edges, per-member upper bounds, hostile futures.

def _fresh_on(authority: Authority, ns: int) -> dict:
    return make_decider(authority, Clock(ns))(authority.request())


def test_expiry_edges_and_hostile_futures(short_tmp):
    authority = build_authority(os.path.join(short_tmp, "cp.db"))
    expiry = authority.grant["expires_at_ms"]
    # Grant expiring exactly at now_floor: rem = E - ceil(now) = -1 -> expired.
    assert _fresh_on(authority, expiry * 1_000_000 + 500_000)["reason"] == "grant_expired"
    assert _fresh_on(authority, expiry * 1_000_000)["reason"] == "grant_expired"  # rem 0
    # One millisecond of remaining life is still active, with the integer reply exact.
    ns = (expiry - 1) * 1_000_000
    assert int(ns / 1e9 * 1000) <= expiry - 1  # the service's float clock agrees at this sample
    reply = _fresh_on(authority, ns)
    assert reply["reason"] == "none" and reply["grant_expires_at_ms"] - reply["server_time_ms"] == 1

    clock_ns = default_clock(authority).ns
    floor_ms = clock_ns // 1_000_000
    # STATE-INJECTION: a proof REAL expiring half a millisecond after the sample is expired.
    inject(authority.path, ("UPDATE canary_environments SET proof_expires_at=?", ((floor_ms + 0.5) / 1000,)))
    assert _fresh_on(authority, clock_ns)["reason"] == "proof_expired"
    for hostile in (1e300, float("nan"), -1.0):
        inject(authority.path, ("UPDATE canary_environments SET proof_expires_at=?", (hostile,)))
        with pytest.raises(HostSnapshotError) as raised:
            _fresh_on(authority, clock_ns)
        assert raised.value.code == "malformed_state", hostile
    inject(authority.path, ("UPDATE canary_environments SET proof_expires_at=?", (authority.base + 3600,)))
    assert _fresh_on(authority, clock_ns)["reason"] == "none"

    # STATE-INJECTION: a stored binding expiry two days out fails closed before any arithmetic.
    inject(authority.path, ("UPDATE canary_runner_context_bindings SET expires_at_ms=?",
                            (floor_ms + 2 * 86_400_000,)))
    with pytest.raises(HostSnapshotError) as raised:
        _fresh_on(authority, clock_ns)
    assert raised.value.code == "malformed_state"
    inject(authority.path, ("UPDATE canary_runner_context_bindings SET expires_at_ms=?",
                            (authority.base_ms + 3_600_000,)))
    # STATE-INJECTION: a grant expiry beyond ten minutes cannot be signed (validate_execution_grant),
    # so the stored column disagrees with the signed record and the decision is invalid_grant,
    # before the per-member bound is ever reached; never active.
    inject(authority.path, ("UPDATE canary_execution_grants SET expires_at=?", (floor_ms + 20 * 60_000,)))
    assert _fresh_on(authority, clock_ns)["reason"] == "invalid_grant"

    # The per-member upper bounds themselves (the third layer behind CHECKs and signatures).
    bounded, proof = HostSnapshotDecider._bounded, HostSnapshotDecider._proof_ms
    now = floor_ms
    assert bounded(now + 600_000, now, host_snapshot.MAX_GRANT_REMAINING_MS) == now + 600_000
    assert bounded(now + 86_400_000, now, host_snapshot.MAX_BINDING_REMAINING_MS) == now + 86_400_000
    for value, maximum in ((now + 600_001, host_snapshot.MAX_GRANT_REMAINING_MS),
                           (now + 86_400_001, host_snapshot.MAX_BINDING_REMAINING_MS),
                           (True, host_snapshot.MAX_GRANT_REMAINING_MS), (-1, host_snapshot.MAX_GRANT_REMAINING_MS),
                           (2 ** 53 + 1, 2 ** 60), (float(now), host_snapshot.MAX_GRANT_REMAINING_MS)):
        with pytest.raises(HostSnapshotError):
            bounded(value, now, maximum)
    assert proof((now + 2_592_000_000 + 1) / 1000, now) <= now + 2_592_000_000
    for value in ((now + 2_592_000_000 + 2) / 1000, math.inf, -0.5, None, "1"):
        with pytest.raises(HostSnapshotError):
            proof(value, now)
    assert proof(1800000000.0005, 1_799_999_000_000) == 1799999999999  # floor, then one millisecond


# ---------------------------------------------------------------------------------------------
# S-15, S-16: faults answer 500 with no body; malformed requests never reach the decider.

def _raw(request: dict) -> bytes:
    body = canonical(request)
    return (b"POST /host/v1/authority-snapshot HTTP/1.1\r\nContent-Type: application/json\r\n"
            b"Content-Length: %d\r\n\r\n" % len(body)) + body


def _exchange(listener, raw: bytes) -> bytes:
    # The socketpair pattern of tests/test_host_authority.py: the real frozen request path.
    server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.sendall(raw)
        listener._serve_request(server)
        server.close()
        data = b""
        with contextlib.suppress(ConnectionResetError):
            while chunk := client.recv(65536):
                data += chunk
        return data
    finally:
        client.close()


def _offline_listener(decide) -> HostAuthorityListener:
    return HostAuthorityListener(HostAuthorityConfig("/nonexistent/h.sock", os.geteuid(), PeerProfile.SHARED_PIDNS),
                                 decide)


def test_db_lock_and_db_error_answer_500_with_no_body_and_no_leak(authority, caplog):
    decider = make_decider(authority)
    holder = sqlite3.connect(authority.path)
    try:
        holder.execute("BEGIN IMMEDIATE")
        request = authority.request()
        started = time.monotonic()
        with pytest.raises(HostSnapshotError) as raised:
            decider(dict(request))
        assert raised.value.code == "db_busy" and time.monotonic() - started < 2.0
        assert str(raised.value) == "db_busy" and raised.value.__cause__ is None
        with caplog.at_level(logging.ERROR, logger="heel.saas.control_plane"):
            response = _exchange(_offline_listener(decider), _raw(authority.request()))
        assert response.startswith(b"HTTP/1.1 500 Internal Server Error\r\n")
        assert b"Content-Length: 0\r\n" in response and response.endswith(b"\r\n\r\n")
    finally:
        holder.rollback()
        holder.close()
    assert ledger_row(authority.path, request["generation_id"]) is None  # rolled back, not advanced
    assert all(authority.path not in record.getMessage() for record in caplog.records)
    assert any('"code":"db_busy"' in record.getMessage() for record in caplog.records)
    # STATE-INJECTION: a corrupted signed grant is a decision, not a fault. A tampered grant whose
    # signed digest still matches the issued tuple fails signature verification (invalid_grant); a
    # grant JSON without the signed digest is already an issued-tuple inequality (step 6 precedes 7a).
    conn = open_db(authority.path)
    try:
        grant = json.loads(conn.execute("SELECT grant_json FROM canary_execution_grants").fetchone()[0])
    finally:
        conn.close()
    grant["approval_reason"] = "tampered"
    inject(authority.path, ("UPDATE canary_execution_grants SET grant_json=?", (json.dumps(grant),)))
    assert decider(authority.request())["reason"] == "invalid_grant"
    inject(authority.path, ("UPDATE canary_execution_grants SET grant_json=?", ("{}",)))
    assert decider(authority.request())["reason"] == "tuple_mismatch"


def test_malformed_request_never_reaches_the_decider(authority):
    decider = make_decider(authority)
    calls = []

    def counted(request):
        calls.append(request)
        return decider(request)

    listener = _offline_listener(counted)
    good = _raw(authority.request())
    for raw in (b"GET / HTTP/1.1\r\n\r\n", good.replace(b"Content-Length", b"Content-Lengthx"),
                good[:-1] + b" ", good.replace(b'"sequence":1', b'"sequence":0')):
        response = _exchange(listener, raw)
        assert re.match(rb"HTTP/1\.1 (400|404) ", response), response[:40]
        assert b'"reason":"malformed_request"' in response
    assert calls == [] and ledger(authority.path) == []
    assert _exchange(listener, good).startswith(b"HTTP/1.1 200 OK")  # the same listener does decide
    assert len(calls) == 1


# ---------------------------------------------------------------------------------------------
# S-24, S-31: one transaction, one sample, and the connection discipline on every failure point.

class RecordingConnection(sqlite3.Connection):
    """SEAM-RECORDING-CONNECTION snapshot tests only. Records statement order and may raise at a
    planned point or stall inside COMMIT on a labelled barrier."""

    log: list
    plan: dict

    def _maybe_raise(self, kind: str, text: str = "") -> None:
        rule = self.plan.get(kind)
        if rule is None:
            return
        match, error = rule if isinstance(rule, tuple) else (None, rule)
        if match is None or match in text:
            self.plan.pop(kind)
            self.log.append(("raised", kind, text))
            raise error

    def execute(self, sql, *args):
        text = " ".join(str(sql).split())
        self.log.append(("execute", text))
        self._maybe_raise("execute", text)
        return super().execute(sql, *args)

    def commit(self):
        self.log.append(("commit",))
        barrier = self.plan.get("commit_barrier")
        if barrier is not None:
            entered, release = barrier
            entered.set()
            assert release.wait(30), "commit barrier never released"
        self._maybe_raise("commit")
        return super().commit()

    def rollback(self):
        self.log.append(("rollback",))
        self._maybe_raise("rollback")
        return super().rollback()

    def close(self):
        self.log.append(("close",))
        try:
            self._maybe_raise("close")
        finally:
            super().close()


def recording(**plan):
    cls = type("Recording", (RecordingConnection,), {"log": [], "plan": dict(plan)})
    connect_error = cls.plan.pop("connect", None)

    def connect(path: str):
        if connect_error is not None:
            cls.log.append(("raised", "connect", ""))
            raise connect_error
        return sqlite3.connect(path, factory=cls)

    return cls, connect


def test_decider_performs_exactly_one_begin_immediate_and_one_time_sample(authority):
    for label, overrides, expect in (
        ("active", {}, "none"),
        ("inactive", {"grant_digest": "f" * 64}, "tuple_mismatch"),
        ("fault", {}, "malformed_state"),
    ):
        cls, connect = recording()
        clock = default_clock(authority)
        decider = make_decider(authority, clock, _connect_for_tests=connect)
        if label == "fault":
            inject(authority.path, ("UPDATE canary_environments SET proof_expires_at=?", (1e300,)))
            with pytest.raises(HostSnapshotError) as raised:
                decider(authority.request(**overrides))
            assert raised.value.code == expect
        else:
            assert decider(authority.request(**overrides))["reason"] == expect, label
        statements = [entry[1] for entry in cls.log if entry[0] == "execute"]
        assert sum(1 for sql in statements if sql.upper().startswith("BEGIN")) == 1, label
        assert sum(1 for sql in statements if sql == "BEGIN IMMEDIATE") == 1, label
        assert not any(sql.upper().startswith(("COMMIT", "ROLLBACK", "SAVEPOINT", "END")) for sql in statements)
        ends = [entry[0] for entry in cls.log if entry[0] in {"commit", "rollback"}]
        assert ends == (["rollback"] if label == "fault" else ["commit"]), label
        assert [entry[0] for entry in cls.log].count("close") == 1 and cls.log[-1] == ("close",)
        assert clock.calls == 1, label


FAILURE_POINTS = {
    "connect": ({"connect": sqlite3.OperationalError("unable to open")}, "db_error", 0),
    "pragma": ({"execute": ("PRAGMA foreign_keys", sqlite3.DatabaseError("file is not a database"))}, "db_error", 1),
    "service": ({}, "malformed_state", 1),
    "clock": ({}, "malformed_state", 1),
    "mid_decision": ({"execute": ("FROM workspaces", sqlite3.OperationalError("disk I/O error"))}, "db_error", 1),
    "commit": ({"commit": sqlite3.OperationalError("disk I/O error")}, "db_error", 1),
    "rollback_after_commit": ({"commit": sqlite3.OperationalError("disk I/O error"),
                               "rollback": sqlite3.OperationalError("disk I/O error")}, "db_error", 1),
}


@pytest.mark.parametrize("point", sorted(FAILURE_POINTS))
def test_connection_closed_on_every_failure_point(authority, point):
    plan, code, closes = FAILURE_POINTS[point]
    cls, connect = recording(**plan)
    clock = default_clock(authority)
    if point == "clock":
        def clock_fails():
            clock.calls += 1
            raise RuntimeError("clock unavailable")
        sample = clock_fails
    else:
        sample = clock
    decider = HostSnapshotDecider(authority.path, signing=authority.signing, draining=lambda: False,
                                  _time_ns_for_tests=sample, _connect_for_tests=connect)
    request = authority.request()
    patch = (mock.patch.object(host_snapshot, "CanaryRunService", side_effect=TypeError("construction"))
             if point == "service" else contextlib.nullcontext())
    with patch, pytest.raises(HostSnapshotError) as raised:
        decider(request)
    assert raised.value.code == code and raised.value.__cause__ is None
    kinds = [entry[0] for entry in cls.log]
    assert kinds.count("close") == closes
    if "raised" in kinds:
        after = cls.log[kinds.index("raised") + 1:]
        assert {entry[0] for entry in after} <= {"rollback", "close", "raised"}, after  # cleanup only
    assert "commit" not in kinds or point.startswith(("commit", "rollback"))
    if point == "rollback_after_commit":
        assert decider.counters["cleanup_failed"] == {"rollback": 1}
    assert ledger_row(authority.path, request["generation_id"]) is None  # nothing persisted


def test_interrupt_mid_decision_is_reraised_rolled_back_and_closed(authority):
    cls, connect = recording(execute=("FROM workspaces", KeyboardInterrupt()))
    decider = make_decider(authority, _connect_for_tests=connect)
    request = authority.request()
    with pytest.raises(KeyboardInterrupt):
        decider(request)
    kinds = [entry[0] for entry in cls.log]
    assert kinds[-2:] == ["rollback", "close"] and kinds.count("close") == 1
    assert ledger_row(authority.path, request["generation_id"]) is None


def test_close_failure_after_commit_is_counted_and_never_claimed(authority):
    cls, connect = recording(close=sqlite3.OperationalError("close failed"))
    decider = make_decider(authority, _connect_for_tests=connect)
    request = authority.request()
    assert decider(request)["reason"] == "none"  # COMMIT returned: the reply stands
    assert decider.counters["cleanup_failed"] == {"close": 1}
    assert ledger_row(authority.path, request["generation_id"])["state"] == "open"


# ---------------------------------------------------------------------------------------------
# S-23: migration 31 and direct-construction parity.

def test_migration_31_and_direct_construction_parity(short_tmp):
    from heel.saas.canary_store import CanaryStore

    full = sqlite3.connect(os.path.join(short_tmp, "full.db"))
    try:
        assert Migrator(full, CONTROL_PLANE_MIGRATIONS).apply_all() == list(range(1, 33))
        assert (CONTROL_PLANE_MIGRATIONS[-2].version, CONTROL_PLANE_MIGRATIONS[-2].name) == (31, "host_authority_generations")
        assert (CONTROL_PLANE_MIGRATIONS[-1].version, CONTROL_PLANE_MIGRATIONS[-1].name) == (32, "stop_ack_signed_witness")
    finally:
        full.close()
    conn = sqlite3.connect(os.path.join(short_tmp, "older.db"))
    try:
        conn.execute("PRAGMA foreign_keys=ON")
        assert Migrator(conn, CONTROL_PLANE_MIGRATIONS[:30]).apply_all() == list(range(1, 31))
        CanaryStore(conn)  # direct construction creates the ledger (IF NOT EXISTS)
        conn.commit()
        assert Migrator(conn, CONTROL_PLANE_MIGRATIONS).apply_all() == [31, 32]
        assert Migrator(conn, CONTROL_PLANE_MIGRATIONS).current_version() == 32
        assert {
            "stop_ack_source_event_sequence", "stop_ack_projection_digest", "stop_ack_runner_local_at_ms",
        } <= {row[1] for row in conn.execute("PRAGMA table_info(canary_runs)")}
        objects = conn.execute(
            "SELECT type,name FROM sqlite_master WHERE tbl_name='host_authority_generations' ORDER BY type,name",
        ).fetchall()
        assert ("table", "host_authority_generations") in objects
        assert ("index", "idx_host_authority_generation_one_open") in objects
        assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
    finally:
        conn.close()


# ---------------------------------------------------------------------------------------------
# Static guarantees: no new authority surface, labelled seams, production defaults.

SEAM_PARAMETERS = (
    "_time_ns_for_tests", "_connect_for_tests", "_max_generation_rows_for_tests", "_listener_for_tests",
    "_serve_for_tests", "_thread_start_for_tests", "_stop_result_for_tests",
)
SEAM_LABELS = ("SEAM-CLOCK", "SEAM-RECORDING-CONNECTION", "SEAM-CAPACITY", "SEAM-LISTENER", "SEAM-SERVE-FAILURE",
               "SEAM-THREAD-START", "SEAM-STOP-HANG")


def test_seams_are_labelled_and_unused_by_production_modules():
    source = " ".join(Path(host_snapshot.__file__).read_text(encoding="utf-8").split())
    for label in SEAM_LABELS:
        assert f"{label} snapshot tests only" in source, label
    for path in sorted((REPO_ROOT / "heel").rglob("*.py")):
        if path.name == "host_snapshot.py":
            continue
        text = path.read_text(encoding="utf-8")
        for name in SEAM_PARAMETERS + SEAM_LABELS:
            assert name not in text, (path, name)


def test_module_text_has_no_header_route_or_deletion_surface():
    source = Path(host_snapshot.__file__).read_text(encoding="utf-8")
    for forbidden in ("authorization", "cookie", "x-heel-edge-auth"):
        assert forbidden not in source.lower(), forbidden
    assert "http_api" not in source and "DELETE" not in source
    # _gate(advance=False)'s server_time_ms is never read; the reply time is ceil(now).
    assert not re.search(r"""\[\s*["']server_time_ms["']\s*\]""", source)
    assert "_gate(context, advance=False)" in source and "advance=True" not in source
    server = (REPO_ROOT / "heel" / "saas" / "server.py").read_text(encoding="utf-8")
    assert not re.search(r"DELETE\s+FROM\s+host_authority", server)
    assert "socket_path" not in server.split("def _host_authority_from_environment")[0]


def test_production_bounds_and_defaults_are_unchanged():
    assert (host_snapshot.STARTUP_TIMEOUT_SECONDS, host_snapshot.STOP_TIMEOUT_SECONDS,
            host_snapshot.QUARANTINE_TIMEOUT_SECONDS) == (5.0, 6.0, 3.0)
    assert (host_snapshot.MAX_GRANT_REMAINING_MS, host_snapshot.MAX_BINDING_REMAINING_MS,
            host_snapshot.MAX_PROOF_REMAINING_MS, host_snapshot.CP_GAP_TOLERANCE_MS,
            host_snapshot.SNAPSHOT_BUSY_TIMEOUT_MS) == (600_000, 86_400_000, 2_592_000_000, 500, 250)
    for code in ("db_busy", "db_error", "malformed_state", "generation_capacity_exhausted", "service_stopped"):
        assert HostSnapshotError(code).code == code
    for code in ("thread_start_failed", "startup_timeout", "startup_failed", "listener_exited", "stop_timeout",
                 "restart_refused"):
        assert HostAuthorityServiceError(code).code == code
    with pytest.raises(ValueError):
        HostSnapshotError("tuple_mismatch")
    with pytest.raises(ValueError):
        HostAuthorityServiceError("anything")
    assert not hasattr(HostAuthorityService, "close")  # stop() reports; nothing hides its result


# ---------------------------------------------------------------------------------------------
# S-17: configuration, default off, managed host fails before any lock or bind.

def _pepper(byte: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(byte * 32).decode("ascii").rstrip("=")


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def valid_environment(root: str, signing: SigningAuthority | None = None) -> dict[str, str]:
    signing = signing or SigningAuthority.generate()
    return {
        "HEEL_DATABASE_PATH": os.path.join(root, "cp.db"), "HEEL_PUBLIC_ORIGIN": "https://heel.example",
        "HEEL_DEVICE_TOKEN_PEPPER_B64": _pepper(b"d"), "HEEL_RUNNER_AUTH_PEPPER_B64": _pepper(b"r"),
        "HEEL_API_KEY_PEPPER": _pepper(b"a"), "HEEL_EDGE_AUTH_SECRET_B64": _pepper(b"e"),
        "HEEL_CONTROL_PLANE_HOST": "127.0.0.1", "HEEL_CONTROL_PLANE_PORT": str(free_port()),
        "HEEL_BILLING_MODE": "free_launch",
        "HEEL_GRANT_SIGNING_PRIVATE_KEY_B64": signing.canonical_private_key,
        "HEEL_GRANT_SIGNING_KEY_ID": signing.key_id,
        "HEEL_GRANT_TRUSTED_PUBLIC_KEYS": json.dumps({signing.key_id: signing.canonical_public_key}),
    }


def test_build_server_default_off_and_managed_host_fails_before_any_bind(short_tmp):
    from heel.saas.server import ProductionConfiguration, ProductionConfigurationError, build_server

    env = valid_environment(short_tmp)
    config = ProductionConfiguration.from_environment(env)
    assert (config.host_authority, config.managed_host) == (None, False)
    server = build_server(config)
    try:
        assert server.host_authority is None and server.host_authority_ready is False
        assert server.host_authority_failure is None
        assert not any(thread.name == HOST_THREAD for thread in threading.enumerate())
    finally:
        server.server_close()
    os.unlink(env["HEEL_DATABASE_PATH"] + ".lock")

    socket_path = os.path.join(short_tmp, "h.sock")
    cases = {
        "HEEL_HOST_AUTHORITY_SOCKET": {"HEEL_MANAGED_HOST": "1"},
        "HEEL_HOST_AUTHORITY_PEER_PROFILE": {
            "HEEL_MANAGED_HOST": "1", "HEEL_HOST_AUTHORITY_SOCKET": socket_path,
            "HEEL_HOST_AUTHORITY_PEER_UID": "0", "HEEL_HOST_AUTHORITY_PEER_PROFILE": "shared-pidns"},
        "HEEL_HOST_AUTHORITY_PEER_UID=0": {
            "HEEL_MANAGED_HOST": "1", "HEEL_HOST_AUTHORITY_SOCKET": socket_path,
            "HEEL_HOST_AUTHORITY_PEER_UID": "1000", "HEEL_HOST_AUTHORITY_PEER_PROFILE": "external-pidns"},
        "HEEL_MANAGED_HOST": {"HEEL_MANAGED_HOST": "yes"},
        "below the database volume": {
            "HEEL_HOST_AUTHORITY_SOCKET": "/tmp/elsewhere/h.sock", "HEEL_HOST_AUTHORITY_PEER_UID": "0",
            "HEEL_HOST_AUTHORITY_PEER_PROFILE": "external-pidns"},
        "must be an integer uid": {
            "HEEL_HOST_AUTHORITY_SOCKET": socket_path, "HEEL_HOST_AUTHORITY_PEER_UID": "-1",
            "HEEL_HOST_AUTHORITY_PEER_PROFILE": "external-pidns"},
        "external-pidns or shared-pidns": {
            "HEEL_HOST_AUTHORITY_SOCKET": socket_path, "HEEL_HOST_AUTHORITY_PEER_UID": "0",
            "HEEL_HOST_AUTHORITY_PEER_PROFILE": "host"},
        "HEEL_HOST_AUTHORITY_SOCKET is required": {"HEEL_HOST_AUTHORITY_PEER_UID": "0"},
    }
    for expected, extra in cases.items():
        with pytest.raises(ProductionConfigurationError, match=re.escape(expected)):
            ProductionConfiguration.from_environment({**env, **extra})
        assert not os.path.exists(env["HEEL_DATABASE_PATH"] + ".lock"), expected  # no lock, no bind
        assert not os.path.exists(socket_path)
    managed = ProductionConfiguration.from_environment({
        **env, "HEEL_MANAGED_HOST": "1", "HEEL_HOST_AUTHORITY_SOCKET": socket_path,
        "HEEL_HOST_AUTHORITY_PEER_UID": "0", "HEEL_HOST_AUTHORITY_PEER_PROFILE": "external-pidns"})
    assert managed.managed_host is True
    assert managed.host_authority == HostAuthorityConfig(socket_path, 0, PeerProfile.EXTERNAL_PIDNS)


# ---------------------------------------------------------------------------------------------
# Service lifecycle through real AF_UNIX clients (SEAM-LISTENER on every OS).

class SeamListener(HostAuthorityListener):
    """SEAM-LISTENER snapshot tests only: ``start()`` publishes without ``check_startup`` and
    ``_handle`` skips the peer rule (both refuse on macOS); ``serve_forever``, ``_serve_request``,
    ``_answer`` and ``close`` are the frozen code. ``on_accept`` is a readiness barrier."""

    on_accept = None

    def start(self) -> None:
        self._publish()

    def _handle(self, connection: socket.socket) -> None:
        if self.on_accept is not None:
            self.on_accept()
        self._serve_request(connection)


def seam_listener(on_accept=None):
    def factory(config, decide):
        listener = SeamListener(config, decide)
        listener.on_accept = on_accept
        return listener
    return factory


@pytest.fixture
def fast_bounds():
    """Bounded test timing for the module's own constants; production defaults are pinned by
    ``test_production_bounds_and_defaults_are_unchanged``. The listener's 5 s recv timeout is not
    changed: trickles below send one byte every 0.25 s."""
    with mock.patch.object(host_snapshot, "STARTUP_TIMEOUT_SECONDS", 1.0), \
            mock.patch.object(host_snapshot, "STOP_TIMEOUT_SECONDS", 1.0), \
            mock.patch.object(host_snapshot, "QUARANTINE_TIMEOUT_SECONDS", 0.5):
        yield


@pytest.fixture
def no_host_thread_left():
    yield
    deadline = time.monotonic() + 10
    while any(thread.name == HOST_THREAD for thread in threading.enumerate()) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not any(thread.name == HOST_THREAD for thread in threading.enumerate())


@pytest.fixture
def live_authority(short_tmp) -> Authority:
    # Real wall-clock base: the service's decider samples time.time_ns() itself.
    return build_authority(os.path.join(short_tmp, "cp.db"), base=math.floor(time.time()) - 60)


def live_request(authority: Authority, **kwargs) -> dict:
    return authority.request(monotonic_ms=kwargs.pop("monotonic_ms", int(time.monotonic() * 1000)), **kwargs)


def make_service(path: str, sock_dir: str, signing, *, on_death=None, draining=lambda: False, **seams):
    seams.setdefault("_listener_for_tests", seam_listener())
    return HostAuthorityService(
        HostAuthorityConfig(os.path.join(sock_dir, "h.sock"), os.geteuid(), PeerProfile.SHARED_PIDNS), path,
        signing=signing, draining=draining, on_unexpected_death=on_death, **seams,
    )


def post(socket_path: str, request: dict, timeout: float = 15.0) -> tuple[int, bytes]:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(timeout)
    try:
        client.connect(socket_path)
        client.sendall(_raw(request))
        data = b""
        while chunk := client.recv(65536):
            data += chunk
    finally:
        client.close()
    head, _sep, body = data.partition(b"\r\n\r\n")
    return int(head.split(b" ")[1]), body


class Trickle:
    """A real peer that keeps one request in flight: one byte every 0.25 s (below the listener's
    5 s per-recv timeout), never completing the head, until ``close()`` in the test's finally."""

    def __init__(self, socket_path: str, *, max_bytes: int = 2000):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(socket_path)
        self.sock.sendall(b"POST /host/v1/authority-snapshot HTTP/1.1\r\nX-Pad: ")
        self.sent = threading.Event()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, args=(max_bytes,), name="test-trickle", daemon=True)
        self._thread.start()

    def _run(self, max_bytes: int) -> None:
        for _ in range(max_bytes):
            try:
                self.sock.sendall(b"a")
            except OSError:
                return
            self.sent.set()
            if self._stop.wait(0.25):
                return

    def close(self) -> None:
        self._stop.set()
        self._thread.join(5)
        with contextlib.suppress(OSError):
            self.sock.close()


def test_end_to_end_over_af_unix_through_seam_listener(live_authority, short_tmp, no_host_thread_left):
    """Real AF_UNIX client, real frozen request path and real decision on every OS; the peer
    rule and check_startup are replaced (SEAM-LISTENER) and are proven by S-20 on Linux only."""
    service = make_service(live_authority.path, short_tmp, live_authority.signing)
    service.start()
    try:
        assert service.phase == "serving" and service.alive
        socket_path = service.config.socket_path
        assert os.path.exists(socket_path)
        g = secrets.token_hex(16)
        status, body = post(socket_path, live_request(live_authority, generation_id=g, sequence=1))
        assert status == 200 and json.loads(body)["reason"] == "none"
        status, body = post(socket_path, live_request(live_authority, generation_id=g, sequence=2))
        assert status == 200 and json.loads(body)["decision"] == "active"
        status, body = post(socket_path, live_request(live_authority, generation_id=g, sequence=2))
        assert status == 200 and json.loads(body)["reason"] == "replayed_sequence"
    finally:
        assert service.stop() == StopResult(True, True)
    assert not os.path.exists(socket_path)
    assert service.phase == "stopped"


def test_stop_declares_draining_before_cleanup(live_authority, short_tmp, no_host_thread_left):
    service = make_service(live_authority.path, short_tmp, live_authority.signing)
    cls, connect = recording()
    service.decider._connect = connect  # SEAM-RECORDING-CONNECTION snapshot tests only (attribute)
    service.start()
    window = []
    listener = service.listener
    frozen_close = listener.close

    def close_after_window():
        # A request arriving after stop() step 1 and before the listener closes.
        window.append(service.decider(live_request(live_authority)))
        frozen_close()

    listener.close = close_after_window
    assert service.stop() == StopResult(True, True)
    assert [reply["reason"] for reply in window] == ["cp_draining"]
    assert cls.log == []  # no connection was opened
    # Precedence after stop: the stopping flag answers before the gate, without the database.
    assert service.decider(live_request(live_authority))["reason"] == "cp_draining"
    assert cls.log == [] and ledger(live_authority.path) == []
    # service_stopped is the quarantine reached without a prior stop flag (500 at the listener).
    other_cls, other_connect = recording()
    other = HostSnapshotDecider(live_authority.path, signing=live_authority.signing, draining=lambda: False,
                                _connect_for_tests=other_connect)
    assert other.quarantine(1.0) is True and other.quarantined
    with pytest.raises(HostSnapshotError) as raised:
        other(live_request(live_authority))
    assert raised.value.code == "service_stopped" and other_cls.log == []
    response = _exchange(_offline_listener(other), _raw(live_request(live_authority)))
    assert response.startswith(b"HTTP/1.1 500 ") and b"Content-Length: 0\r\n" in response


def test_quarantine_unproven_when_transaction_stalls(live_authority, short_tmp, fast_bounds, no_host_thread_left):
    """A labelled transaction barrier holds the request inside COMMIT until after the bounded stop
    returned; then it is released and the cleanup is verified."""
    entered, release = threading.Event(), threading.Event()
    service = make_service(live_authority.path, short_tmp, live_authority.signing)
    cls, connect = recording(commit_barrier=(entered, release))
    service.decider._connect = connect  # SEAM-RECORDING-CONNECTION snapshot tests only (attribute)
    service.start()
    replies = []
    request = live_request(live_authority)
    client = threading.Thread(target=lambda: replies.append(post(service.config.socket_path, request)), daemon=True)
    try:
        client.start()
        assert entered.wait(10), "the request never reached COMMIT"
        started = time.monotonic()
        result = service.stop()
        elapsed = time.monotonic() - started
        assert result == StopResult(False, False)
        assert elapsed < 1.0 + 0.5 + 1.0  # stop bound + quarantine bound (+ scheduling margin)
        assert service.phase == "lingering" and not service.quarantined
        assert isinstance(service.failure, HostAuthorityServiceError) and service.failure.code == "stop_timeout"
        assert service.thread.is_alive()
    finally:
        release.set()
        client.join(15)
    assert replies and replies[0][0] == 200 and json.loads(replies[0][1])["reason"] == "none"
    service.thread.join(10)
    assert not service.thread.is_alive()
    assert service.stop() == StopResult(True, True) and service.phase == "stopped" and service.quarantined
    kinds = [entry[0] for entry in cls.log]
    assert kinds.count("commit") == 1 and kinds.count("close") == 1 and "rollback" not in kinds
    assert ledger_row(live_authority.path, request["generation_id"])["state"] == "open"  # committed once


def test_restart_refused_and_stop_idempotent(live_authority, short_tmp, fast_bounds, no_host_thread_left):
    service = make_service(live_authority.path, short_tmp, live_authority.signing)
    service.start()
    first = service.stop()
    assert first == StopResult(True, True) and service.stop() == first
    with pytest.raises(HostAuthorityServiceError) as raised:
        service.start()
    assert raised.value.code == "restart_refused"
    assert sum(1 for thread in threading.enumerate() if thread.name == HOST_THREAD) == 0

    accepted = threading.Event()
    lingering = make_service(live_authority.path, short_tmp, live_authority.signing,
                             _listener_for_tests=seam_listener(accepted.set))
    lingering.start()
    trickle = Trickle(lingering.config.socket_path)
    try:
        assert accepted.wait(5) and trickle.sent.wait(5)
        assert lingering.stop() == StopResult(False, True)
        assert lingering.stop() == StopResult(False, True)  # repeatable while the peer holds it
        assert lingering.phase == "lingering"
        with pytest.raises(HostAuthorityServiceError) as raised:
            lingering.start()
        assert raised.value.code == "restart_refused"
        assert sum(1 for thread in threading.enumerate() if thread.name == HOST_THREAD) == 1
    finally:
        trickle.close()
    lingering.thread.join(10)
    assert lingering.stop() == StopResult(True, True) and lingering.phase == "stopped"


class RecordingLock:
    """Records, per acquisition, which recorded locks the acquiring thread already held."""

    held = threading.local()
    records: list

    def __init__(self, name: str, records: list):
        self.name, self._lock, self.records = name, threading.Lock(), records

    def _stack(self) -> list:
        if not hasattr(self.held, "stack"):
            self.held.stack = []
        return self.held.stack

    def acquire(self, blocking: bool = True, timeout: float = -1) -> bool:
        acquired = self._lock.acquire(blocking, timeout)
        if acquired:
            self.records.append((self.name, tuple(self._stack())))
            self._stack().append(self.name)
        return acquired

    def release(self) -> None:
        self._stack().remove(self.name)
        self._lock.release()

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *_exc):
        self.release()


def test_no_deadlock_between_death_callback_and_stop(live_authority, short_tmp, no_host_thread_left):
    records: list = []
    ready_lock = RecordingLock("ready_lock", records)
    die, in_callback, stop_started = threading.Event(), threading.Event(), threading.Event()
    deaths = []

    def serve(listener, mark_serving):  # SEAM-SERVE-FAILURE snapshot tests only
        mark_serving()
        die.wait(10)
        raise RuntimeError("listener died")

    def on_death(error):
        with ready_lock:
            deaths.append(error)
            in_callback.set()
            stop_started.wait(5)
            time.sleep(0.1)

    service = make_service(live_authority.path, short_tmp, live_authority.signing, on_death=on_death,
                           _serve_for_tests=serve)
    service._state_lock = RecordingLock("_state_lock", records)  # recording wrapper (test attribute)
    service.start()
    die.set()
    assert in_callback.wait(5)
    results = []
    stopper = threading.Thread(target=lambda: results.append(service.stop()))
    started = time.monotonic()
    stopper.start()
    stop_started.set()
    stopper.join(2.0)
    assert not stopper.is_alive() and time.monotonic() - started < 2.0
    service.thread.join(2.0)
    assert not service.thread.is_alive()
    assert results == [StopResult(True, True)] and len(deaths) == 1
    assert not os.path.exists(service.config.socket_path)
    # Lock order: ready_lock -> _state_lock only; never ready_lock while holding _state_lock.
    assert all(not (name == "ready_lock" and "_state_lock" in held) for name, held in records)
    assert ("ready_lock", ()) in records


# ---------------------------------------------------------------------------------------------
# build_server wiring: S-18', S-19, S-20, S-21', S-22. HostAuthorityService is patched in the
# test only, to pass labelled seams; build_server itself never passes one.

def host_environment(root: str, signing: SigningAuthority | None = None, *, socket_dir: str | None = None) -> dict:
    return {
        **valid_environment(root, signing),
        "HEEL_HOST_AUTHORITY_SOCKET": os.path.join(socket_dir or root, "h.sock"),
        "HEEL_HOST_AUTHORITY_PEER_UID": str(os.geteuid()), "HEEL_HOST_AUTHORITY_PEER_PROFILE": "shared-pidns",
    }


def seamed_service(**seams):
    seams.setdefault("_listener_for_tests", seam_listener())

    def factory(*args, **kwargs):
        return HostAuthorityService(*args, **kwargs, **seams)
    return factory


def lock_is_free(database_path: str) -> bool:
    from heel.saas.server import ProductionConfigurationError, _SingleProcessDatabaseLock
    try:
        _SingleProcessDatabaseLock.acquire(database_path).close()
    except ProductionConfigurationError as error:
        assert "already has a live process owner" in str(error)
        return False
    return True


def reaper_threads() -> int:
    return sum(1 for thread in threading.enumerate() if thread.name == "heel-canary-reaper" and thread.is_alive())


def release_retained_for_test(expected: int = 1) -> None:
    """Test cleanup only: the production process never releases a retained owner in-process; a
    pytest process must, after the worker ended, to free descriptors for later tests."""
    from socketserver import TCPServer

    from heel.saas import server as server_module
    with server_module._RETAINED_OWNERSHIP_LOCK:
        records = list(server_module._RETAINED_OWNERSHIP)
        server_module._RETAINED_OWNERSHIP.clear()
    assert len(records) == expected
    for record in records:
        if record.host_authority is not None:
            assert record.host_authority.thread is None or not record.host_authority.thread.is_alive()
        assert record.reaper.stop()
        TCPServer.server_close(record.server)
        record.control_plane.close()
        record.database_lock.close()


def _assert_torn_down(config, socket_path: str) -> None:
    import dataclasses

    from heel.saas import server as server_module
    assert not os.path.exists(socket_path)
    assert not any(thread.name == HOST_THREAD for thread in threading.enumerate())
    assert reaper_threads() == 0
    assert server_module._RETAINED_OWNERSHIP == []
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", config.port), timeout=1).close()
    assert lock_is_free(config.database_path)
    retry = server_module.build_server(dataclasses.replace(config, host_authority=None))
    retry.server_close()


def _delayed_serve(listener, _mark_serving):
    # SEAM-SERVE-FAILURE snapshot tests only: never reaches serving; ends when stop closes it.
    deadline = time.monotonic() + 20
    while not listener._stop.is_set() and time.monotonic() < deadline:
        time.sleep(0.02)


def _thread_start_fails(_thread):  # SEAM-THREAD-START snapshot tests only
    raise RuntimeError("can't start new thread")


def _dies_immediately(_listener, _mark_serving):  # SEAM-SERVE-FAILURE snapshot tests only
    raise RuntimeError("listener died before serving")


def _returns_immediately(_listener, _mark_serving):  # SEAM-SERVE-FAILURE snapshot tests only
    return None


@pytest.mark.parametrize("case", ["check_startup", "thread_start", "immediate_death", "listener_exited",
                                  "delayed_startup"])
def test_build_server_listener_failure_points_tear_down(short_tmp, fast_bounds, no_host_thread_left, case):
    from heel.saas.server import ProductionConfiguration, ProductionConfigurationError, build_server

    socket_dir = os.path.join(short_tmp, "sock")
    os.mkdir(socket_dir, 0o700)
    if case == "check_startup":
        os.chmod(socket_dir, 0o755)  # refused on Linux by the directory rule; on macOS uid_map comes first
    config = ProductionConfiguration.from_environment(host_environment(short_tmp, socket_dir=socket_dir))
    factory = {
        "check_startup": HostAuthorityService,  # the real listener and the real check_startup refusal
        "thread_start": seamed_service(_thread_start_for_tests=_thread_start_fails),
        "immediate_death": seamed_service(_serve_for_tests=_dies_immediately),
        "listener_exited": seamed_service(_serve_for_tests=_returns_immediately),
        "delayed_startup": seamed_service(_serve_for_tests=_delayed_serve),
    }[case]
    started = time.monotonic()
    with mock.patch("heel.saas.server.HostAuthorityService", factory), \
            pytest.raises(ProductionConfigurationError, match="host authority listener failed to start") as raised:
        build_server(config)
    cause = raised.value.__cause__
    expected = {"thread_start": "thread_start_failed", "immediate_death": "startup_failed",
                "listener_exited": "startup_failed", "delayed_startup": "startup_timeout"}
    if case == "check_startup":
        from heel.saas.host_authority import HostAuthorityConfigurationError
        assert isinstance(cause, HostAuthorityConfigurationError)
        assert cause.code == ("socket_directory_profile" if sys.platform == "linux" else "uid_map_unreadable")
    else:
        assert isinstance(cause, HostAuthorityServiceError) and cause.code == expected[case]
    if case in {"immediate_death", "listener_exited"}:
        assert time.monotonic() - started < 1.0 + 3.0  # woken by the death, not the startup bound
    if case == "delayed_startup":
        assert cause.stop_result == StopResult(True, True)  # the thread was joined on stop
    _assert_torn_down(config, config.host_authority.socket_path)


def _build_in_background(config, factory):
    from heel.saas.server import build_server

    outcome: dict = {}

    def run():
        with mock.patch("heel.saas.server.HostAuthorityService", factory):
            try:
                outcome["server"] = build_server(config)
            except BaseException as error:  # noqa: BLE001 - recorded for the assertions
                outcome["error"] = error

    thread = threading.Thread(target=run, name="test-build-server")
    thread.start()
    return thread, outcome


def _accept_one_then_handle(listener, _mark_serving):
    """SEAM-SERVE-FAILURE snapshot tests only: serves one accepted connection through the frozen
    per-connection path before ever reaching serving (start-time in-flight peer)."""
    sock = listener._sock
    sock.settimeout(0.05)
    deadline = time.monotonic() + 20
    while not listener._stop.is_set() and time.monotonic() < deadline:
        try:
            connection, _address = sock.accept()
        except TimeoutError:
            continue
        except OSError:
            return
        with connection:
            listener._handle(connection)
        return


def test_start_time_trickle_retains_ownership_until_process_exit(short_tmp, fast_bounds, no_host_thread_left,
                                                                  owned_workers, caplog):
    from heel.saas import server as server_module
    from heel.saas.server import ProductionConfiguration, build_server

    config = ProductionConfiguration.from_environment(host_environment(short_tmp))
    socket_path = config.host_authority.socket_path
    accepted = threading.Event()
    factory = seamed_service(_listener_for_tests=seam_listener(accepted.set), _serve_for_tests=_accept_one_then_handle)
    trickle = None
    caplog.set_level(logging.ERROR, logger="heel.saas.control_plane")
    builder, outcome = _build_in_background(config, factory)
    try:
        deadline = time.monotonic() + 10
        while not os.path.exists(socket_path) and builder.is_alive() and time.monotonic() < deadline:
            time.sleep(0.01)
        trickle = Trickle(socket_path)
        assert accepted.wait(5) and trickle.sent.wait(5)  # accepted and in flight before the bound
        builder.join(15)
        assert not builder.is_alive()
        error = outcome["error"]
        assert isinstance(error, HostAuthorityServiceError) and error.code == "stop_timeout"
        assert error.stop_result == StopResult(False, True)
        assert any('"event":"control_plane_ownership_retained","reason":"stop_timeout"' in record.getMessage()
                   for record in caplog.records)
        record = server_module._RETAINED_OWNERSHIP[-1]
        assert record.reason == "stop_timeout" and record.host_authority.quarantined
        assert record.host_authority.phase == "lingering"
        assert not lock_is_free(config.database_path)
        from heel.saas.server import ProductionConfigurationError
        with pytest.raises(ProductionConfigurationError, match="already has a live process owner"):
            build_server(config)
        assert record.control_plane.store.conn.execute("SELECT 1").fetchone()[0] == 1  # CP still open
        assert not os.path.exists(socket_path)  # unpublished
        assert reaper_threads() == 0  # joined on the start path; joining releases nothing
    finally:
        if trickle is not None:
            trickle.close()
        builder.join(15)
    record.host_authority.thread.join(10)
    assert not record.host_authority.thread.is_alive()
    # The worker ended, but a retained owner is never released or replaced in-process.
    assert not lock_is_free(config.database_path)
    release_retained_for_test()
    assert lock_is_free(config.database_path)
    # The retained record describes the quarantine truthfully, never a healthy node.
    assert (record.control_plane.draining, record.server.reaper_ready, record.server.host_authority_ready) == (
        True, False, False)


def test_reaper_stop_failure_on_the_start_path_retains_ownership(short_tmp, fast_bounds, no_host_thread_left,
                                                                 owned_workers):
    from heel.saas import server as server_module
    from heel.saas.canary_reaper import CanaryReaper, CanaryReaperError
    from heel.saas.server import ProductionConfiguration, build_server

    config = ProductionConfiguration.from_environment(host_environment(short_tmp))
    real_stop = CanaryReaper.stop

    def stop_hangs(self, *args, **kwargs):  # SEAM-STOP-HANG snapshot tests only (on the reaper)
        assert real_stop(self, *args, **kwargs)
        return False

    with mock.patch("heel.saas.server.HostAuthorityService",
                    seamed_service(_thread_start_for_tests=_thread_start_fails)), \
            mock.patch.object(CanaryReaper, "stop", stop_hangs), pytest.raises(CanaryReaperError):
        build_server(config)
    assert not lock_is_free(config.database_path)
    record = server_module._RETAINED_OWNERSHIP[-1]
    release_retained_for_test()
    assert lock_is_free(config.database_path)
    assert record.reason == "reaper_stop_timeout"
    assert (record.control_plane.draining, record.server.reaper_ready, record.server.host_authority_ready) == (
        True, False, False)


def _record_close_order(server, order: list):
    from socketserver import TCPServer

    original_tcp = TCPServer.server_close
    host_stop, reaper_stop, cp_close = server.host_authority.stop, server.canary_reaper.stop, server.control_plane.close

    def tcp(bound):
        order.append("tcp")
        return original_tcp(bound)

    def host(*args, **kwargs):
        order.append("host-authority")
        return host_stop(*args, **kwargs)

    def reaper(*args, **kwargs):
        order.append("reaper")
        return reaper_stop(*args, **kwargs)

    def control_plane():
        order.append("control-plane")
        return cp_close()

    server.host_authority.stop, server.canary_reaper.stop, server.control_plane.close = host, reaper, control_plane
    return mock.patch.object(TCPServer, "server_close", tcp)


def test_server_close_order_retry_and_trickle_retention(short_tmp, fast_bounds, no_host_thread_left, owned_workers):
    from heel.saas import server as server_module
    from heel.saas.server import ProductionConfiguration, build_server

    # Ordinary close: TCP -> host authority -> reaper -> control plane, path gone, thread joined.
    first_root = os.path.join(short_tmp, "a")
    os.mkdir(first_root, 0o700)
    config = ProductionConfiguration.from_environment(host_environment(first_root))
    with mock.patch("heel.saas.server.HostAuthorityService", seamed_service()):
        server = build_server(config)
    assert server.host_authority_ready is True and server.host_authority.alive
    order: list = []
    with _record_close_order(server, order):
        server.server_close()
    assert order == ["tcp", "host-authority", "reaper", "control-plane"]
    assert not os.path.exists(config.host_authority.socket_path) and server.host_authority.phase == "stopped"
    assert lock_is_free(config.database_path)

    # A real peer mid-request: close raises before any release; a repeated close is the retry.
    second_root = os.path.join(short_tmp, "b")
    os.mkdir(second_root, 0o700)
    config = ProductionConfiguration.from_environment(host_environment(second_root))
    accepted = threading.Event()
    with mock.patch("heel.saas.server.HostAuthorityService", seamed_service(_listener_for_tests=seam_listener(accepted.set))):
        server = build_server(config)
    trickle = Trickle(config.host_authority.socket_path)
    order = []
    try:
        assert accepted.wait(5) and trickle.sent.wait(5)
        with _record_close_order(server, order):
            started = time.monotonic()
            with pytest.raises(HostAuthorityServiceError) as raised:
                server.server_close()
            assert time.monotonic() - started < 1.0 + 0.5 + 2.0  # no TCP request was active to drain
            assert raised.value.code == "stop_timeout" and raised.value.stop_result == StopResult(False, True)
            assert order == ["tcp", "host-authority"]
            assert not lock_is_free(config.database_path)
            assert reaper_threads() == 1  # never stopped before the host authority stopped
            assert server.control_plane.store.conn.execute("SELECT 1").fetchone()[0] == 1
            assert (server.host_authority_ready, server.reaper_ready) == (False, False)
            assert server_module._RETAINED_OWNERSHIP[-1].reason == "stop_timeout"
            trickle.close()
            server.host_authority.thread.join(10)
            server.server_close()  # the retry completes once the worker is joined
        assert order == ["tcp", "host-authority", "tcp", "host-authority", "reaper", "control-plane"]
    finally:
        trickle.close()
    assert lock_is_free(config.database_path) and server_module._RETAINED_OWNERSHIP == []
    with pytest.raises(sqlite3.ProgrammingError):
        server.control_plane.store.conn.execute("SELECT 1")
    # After stop, the decider answers draining without the database; the ledger is untouched.
    decider = server.host_authority.decider
    assert decider.quarantined
    assert decider(_any_request())["reason"] == "cp_draining"
    assert ledger(config.database_path) == []


def _any_request() -> dict:
    return {
        "schema_version": REQUEST_SCHEMA, "host_boot_epoch": "boot-0001", "slot_id": "slot-a",
        "request_nonce": "1" * 32, "generation_id": "2" * 32, "workspace_id": "ws_" + "3" * 16,
        "project_id": "prj_" + "4" * 32, "environment_id": "env_" + "5" * 32, "verification_record_digest": "6" * 64,
        "runner_id": "runr", "runner_key_id": "key", "binding_id": "rcb_" + "7" * 32, "binding_digest": "8" * 64,
        "run_id": "crun_" + "9" * 32, "grant_id": "cgr", "grant_digest": "a" * 64, "sequence": 1,
        "monotonic_ms": 0, "kill_switch_generation": 0,
    }


def test_stop_hang_seam_raises_before_release(short_tmp, fast_bounds, no_host_thread_left, owned_workers):
    from heel.saas.server import ProductionConfiguration, build_server

    config = ProductionConfiguration.from_environment(host_environment(short_tmp))
    with mock.patch("heel.saas.server.HostAuthorityService",
                    seamed_service(_stop_result_for_tests=lambda: False)):  # SEAM-STOP-HANG snapshot tests only
        server = build_server(config)
    with pytest.raises(HostAuthorityServiceError, match="stop_timeout"):
        server.server_close()
    assert not lock_is_free(config.database_path)
    assert server.control_plane.store.conn.execute("SELECT 1").fetchone()[0] == 1
    release_retained_for_test()


def test_unexpected_listener_death_drains_unlinks_and_cannot_be_marked_ready(short_tmp, no_host_thread_left):
    from heel.saas.server import ProductionConfiguration, ProductionConfigurationError, build_server

    die = threading.Event()

    def dies_after_readiness(listener, mark_serving):  # SEAM-SERVE-FAILURE snapshot tests only
        mark_serving()
        die.wait(20)
        raise RuntimeError("listener died")

    config = ProductionConfiguration.from_environment(host_environment(short_tmp))
    with mock.patch("heel.saas.server.HostAuthorityService", seamed_service(_serve_for_tests=dies_after_readiness)):
        server = build_server(config)
    assert server.host_authority_ready is True
    die.set()
    server.host_authority.thread.join(10)
    assert (server.host_authority_ready, server.reaper_ready, server.control_plane.draining) == (False, False, True)
    assert isinstance(server.host_authority_failure, RuntimeError)
    assert not os.path.exists(config.host_authority.socket_path)
    assert not server.host_authority.alive
    server.server_close()
    assert lock_is_free(config.database_path)

    # A death racing the ready assignment never leaves host_authority_ready True.
    def races(listener, mark_serving):  # SEAM-SERVE-FAILURE snapshot tests only
        mark_serving()
        raise RuntimeError("listener died while readiness was assigned")

    outcomes = []
    for attempt in range(8):
        root = os.path.join(short_tmp, f"r{attempt}")
        os.mkdir(root, 0o700)
        config = ProductionConfiguration.from_environment(host_environment(root))
        with mock.patch("heel.saas.server.HostAuthorityService", seamed_service(_serve_for_tests=races)):
            try:
                server = build_server(config)
            except ProductionConfigurationError:
                outcomes.append("refused")
                assert lock_is_free(config.database_path)
                continue
        server.host_authority.thread.join(10)
        assert server.host_authority_ready is False and server.control_plane.draining is True
        outcomes.append("drained")
        server.server_close()
        assert lock_is_free(config.database_path)
    assert len(outcomes) == 8


def test_public_tcp_route_and_headers_are_not_an_authority_path(short_tmp):
    import http.client

    from heel.saas.server import ProductionConfiguration, build_server

    config = ProductionConfiguration.from_environment(valid_environment(short_tmp))
    server = build_server(config)
    serving = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    serving.start()
    try:
        body = canonical(_any_request())
        for headers, status in (
            ({}, 401),
            ({"Authorization": "Bearer x", "Cookie": "s=1", "X-Heel-Edge-Auth": "e"}, 401),
            # With the valid edge header the request reaches routing: no such route exists.
            ({"Authorization": "Bearer x", "Cookie": "s=1", "X-Heel-Edge-Auth": config.edge_auth_secret}, 404),
        ):
            connection = http.client.HTTPConnection("127.0.0.1", config.port, timeout=5)
            try:
                connection.request("POST", "/host/v1/authority-snapshot", body=body,
                                   headers={"Content-Type": "application/json", **headers})
                response = connection.getresponse()
                payload = response.read()
            finally:
                connection.close()
            assert response.status == status, headers
            assert b"heel.host-authority-snapshot" not in payload
    finally:
        server.shutdown()
        server.server_close()
        serving.join(5)


@pytest.mark.skipif(sys.platform != "linux", reason="real AF_UNIX peer credentials and check_startup need Linux")
def test_end_to_end_over_real_af_unix_with_peer_credentials(short_tmp, no_host_thread_left, capsys):
    """The real path: check_startup, publication, SO_PEERCRED peer rule, frozen codec, real
    decision, then the real reaper's expiry of the unheartbeated claim. The refusal half stays
    with the accepted T1-T3 proof."""
    from heel.saas.canary_reaper import HEARTBEAT_STALE_MS
    from heel.saas.server import ProductionConfiguration, build_server

    env = host_environment(short_tmp)
    config = ProductionConfiguration.from_environment(env)
    # A fresh claim: the reaper's startup cycle (proven before readiness) must not find it stale.
    authority = build_authority(config.database_path, signing=config.grant_authority, base=math.floor(time.time()))
    server = build_server(config)
    try:
        assert server.host_authority_ready is True
        socket_path = config.host_authority.socket_path
        g = secrets.token_hex(16)
        age_ms = time.time_ns() // 1_000_000 - authority.base_ms
        if age_ms >= HEARTBEAT_STALE_MS:
            pytest.fail(f"harness too slow: claim age {age_ms} ms at the first decision")
        status, body = post(socket_path, live_request(authority, generation_id=g, sequence=1))
        assert status == 200 and json.loads(body)["reason"] == "none", f"claim age {age_ms} ms"
        status, body = post(socket_path, live_request(authority, generation_id=g, sequence=2))
        assert status == 200 and json.loads(body)["decision"] == "active"
        status, body = post(socket_path, live_request(authority, generation_id=g, sequence=2))
        assert status == 200 and json.loads(body)["reason"] == "replayed_sequence"
        # Negative control: no heartbeat ever arrives, so the real reaper stops the run as disconnected.
        deadline = time.monotonic() + 15
        row = run_row(config.database_path, authority.run_id)
        while row["stop_reason"] == "none" and time.monotonic() < deadline:
            time.sleep(0.1)
            row = run_row(config.database_path, authority.run_id)
        assert (row["status"], row["stop_reason"], row["error_category"]) == (
            "stop_requested", "cloud_stop", "cloud_disconnected")
        # The duplicate closed generation g; it stays closed. A fresh generation sees no active run.
        status, body = post(socket_path, live_request(authority, generation_id=g, sequence=3))
        assert status == 200 and json.loads(body)["reason"] == "replayed_sequence"
        status, body = post(socket_path, live_request(authority, generation_id=secrets.token_hex(16), sequence=1))
        expired = json.loads(body)
        assert status == 200 and (expired["decision"], expired["reason"]) == ("inactive", "no_active_run")
    finally:
        server.server_close()
    with capsys.disabled():
        print(f"\nH1A2LR1-E2E S20 PASS first_age_ms={age_ms} positive=active replay=replayed_sequence"
              " expiry=cloud_stop/cloud_disconnected expiry_decision=no_active_run")


# ---------------------------------------------------------------------------------------------
# H1A2R1: every failure after a reaper thread may run (reaper start, service construction, host
# start, close-wrapper installation; ``BaseException`` included) goes through one unwind: unhealthy
# flags first, every stop outcome recorded, release only after proven joins, otherwise retained.
# Faults are injected in the test (labelled); the workers, flock and SQLite files are real.

class _Owned:
    def __init__(self):
        self.reapers: list = []
        self.services: list = []
        self.locks: list = []

    def service_factory(self, factory):
        def make(*args, **kwargs):
            service = factory(*args, **kwargs)
            self.services.append(service)
            return service
        return make


@pytest.fixture
def owned_workers():
    """Captures every reaper, host-authority service (built through ``service_factory``) and process
    lock that ``build_server`` creates, so a test observing the product leaving a worker alive still
    stops it and frees the descriptor. Teardown: services joined, reapers joined, retained records
    released (their workers ended), then any lock still open (only reached when the product leaked it)."""
    from socketserver import TCPServer

    from heel.saas import server as server_module
    from heel.saas.canary_reaper import CanaryReaper

    owned = _Owned()
    real_acquire = server_module._SingleProcessDatabaseLock.acquire

    def reaper_factory(*args, **kwargs):
        reaper = CanaryReaper(*args, **kwargs)
        owned.reapers.append(reaper)
        return reaper

    def acquire(database_path):
        lock = real_acquire(database_path)
        owned.locks.append(lock)
        return lock

    try:
        with mock.patch.object(server_module, "CanaryReaper", reaper_factory), \
                mock.patch.object(server_module._SingleProcessDatabaseLock, "acquire", acquire):
            yield owned
    finally:
        for service in owned.services:
            service.stop()
            if service.thread is not None:
                service.thread.join(10)
        for reaper in owned.reapers:
            assert reaper.stop(timeout=10)
        with server_module._RETAINED_OWNERSHIP_LOCK:
            records = list(server_module._RETAINED_OWNERSHIP)
            server_module._RETAINED_OWNERSHIP.clear()
        for record in records:
            with contextlib.suppress(Exception):
                TCPServer.server_close(record.server)
            with contextlib.suppress(Exception):
                record.control_plane.close()
        for lock in owned.locks:
            lock.close()


@contextlib.contextmanager
def observe_release(observed: list):
    """Records, at the moment the process lock is released, how many owned workers still run."""
    from heel.saas.server import _SingleProcessDatabaseLock
    real_close = _SingleProcessDatabaseLock.close

    def close(lock):
        observed.append({
            "reaper_threads": reaper_threads(),
            "host_threads": sum(1 for thread in threading.enumerate() if thread.name == HOST_THREAD),
        })
        return real_close(lock)

    with mock.patch.object(_SingleProcessDatabaseLock, "close", close):
        yield


def _assert_retained_unhealthy(config, reason: str):
    from heel.saas import server as server_module
    from heel.saas.server import ProductionConfigurationError, build_server

    assert len(server_module._RETAINED_OWNERSHIP) == 1
    record = server_module._RETAINED_OWNERSHIP[-1]
    assert record.reason == reason
    assert (record.control_plane.draining, record.server.reaper_ready, record.server.host_authority_ready) == (
        True, False, False)
    assert record.control_plane.store.conn.execute("SELECT 1").fetchone()[0] == 1  # CP still open
    assert not lock_is_free(config.database_path)
    with pytest.raises(ProductionConfigurationError, match="already has a live process owner"):
        build_server(config)
    return record


def _constructor_fails(*_args, **_kwargs):  # injected fault: raises after the real reaper started
    assert reaper_threads() == 1
    raise ValueError("injected constructor failure")


def test_constructor_failure_after_reaper_start_releases_only_after_the_join(short_tmp, owned_workers):
    from heel.saas import server as server_module
    from heel.saas.server import ProductionConfiguration, build_server

    config = ProductionConfiguration.from_environment(host_environment(short_tmp))
    released: list = []
    with mock.patch("heel.saas.server.HostAuthorityService", _constructor_fails), observe_release(released), \
            pytest.raises(ValueError, match="injected constructor failure"):
        build_server(config)
    assert released == [{"reaper_threads": 0, "host_threads": 0}]
    (reaper,) = owned_workers.reapers
    assert not reaper.thread.is_alive()
    assert server_module._RETAINED_OWNERSHIP == []
    assert lock_is_free(config.database_path)


@pytest.mark.parametrize("stop_fault", ["returns_false", "raises"])
def test_constructor_failure_with_unproven_reaper_stop_retains_ownership(short_tmp, owned_workers, stop_fault):
    from heel.saas.canary_reaper import CanaryReaper, CanaryReaperError
    from heel.saas.server import ProductionConfiguration, build_server

    config = ProductionConfiguration.from_environment(host_environment(short_tmp))
    real_stop = CanaryReaper.stop

    def unproven(self, *args, **kwargs):  # SEAM-STOP-HANG snapshot tests only (on the reaper; injected)
        assert real_stop(self, *args, **kwargs)
        if stop_fault == "raises":
            raise RuntimeError("injected reaper stop failure")
        return False

    released: list = []
    expected = CanaryReaperError if stop_fault == "returns_false" else RuntimeError
    with mock.patch("heel.saas.server.HostAuthorityService", _constructor_fails), \
            mock.patch.object(CanaryReaper, "stop", unproven), observe_release(released), \
            pytest.raises(expected) as raised:
        build_server(config)
    assert released == []
    assert isinstance(raised.value.__cause__ or raised.value.__context__, ValueError)
    record = _assert_retained_unhealthy(
        config, {"returns_false": "reaper_stop_timeout", "raises": "reaper_stop_failed"}[stop_fault])
    assert record.reaper is owned_workers.reapers[0] and record.host_authority is None
    release_retained_for_test()
    assert lock_is_free(config.database_path)


def _install_fails(server, reaper, database_lock, host_authority=None):  # injected fault
    assert reaper_threads() == 1 and host_authority.alive and server.host_authority_ready is True
    raise RuntimeError("injected close-wrapper installation failure")


@pytest.mark.parametrize("host_stop", ["joined", "unproven"])
def test_close_wrapper_installation_failure_unwinds_both_workers(short_tmp, fast_bounds, no_host_thread_left,
                                                                 owned_workers, host_stop):
    from heel.saas.server import ProductionConfiguration, build_server

    config = ProductionConfiguration.from_environment(host_environment(short_tmp))
    seams = {} if host_stop == "joined" else {
        "_stop_result_for_tests": lambda: False}  # SEAM-STOP-HANG snapshot tests only
    released: list = []
    expected = RuntimeError if host_stop == "joined" else HostAuthorityServiceError
    with mock.patch("heel.saas.server.HostAuthorityService", owned_workers.service_factory(seamed_service(**seams))), \
            mock.patch("heel.saas.server._install_production_close", _install_fails), observe_release(released), \
            pytest.raises(expected) as raised:
        build_server(config)
    (service,) = owned_workers.services
    assert not os.path.exists(config.host_authority.socket_path)
    assert reaper_threads() == 0  # joined on the start path even when the host stop is unproven
    if host_stop == "joined":
        assert "injected close-wrapper installation failure" in str(raised.value)
        assert released == [{"reaper_threads": 0, "host_threads": 0}]
        assert service.phase == "stopped" and service.decider.quarantined
        assert lock_is_free(config.database_path)
        return
    assert raised.value.code == "stop_timeout" and raised.value.stop_result == StopResult(False, True)
    assert isinstance(raised.value.__cause__, RuntimeError)
    assert released == []
    record = _assert_retained_unhealthy(config, "stop_timeout")
    assert record.host_authority is service and service.phase == "lingering"
    release_retained_for_test()
    assert lock_is_free(config.database_path)


@pytest.mark.parametrize("window", ["host_start_failure", "close_wrapper"])
def test_host_stop_raising_during_start_unwind_retains_ownership(short_tmp, fast_bounds, no_host_thread_left,
                                                                 owned_workers, window):
    """Injected fault: ``stop()`` raises without stopping. A host thread that may still run keeps
    every owned resource; the reaper is still joined and its outcome recorded."""
    from heel.saas.server import ProductionConfiguration, build_server

    config = ProductionConfiguration.from_environment(host_environment(short_tmp))
    seams = {"_thread_start_for_tests": _thread_start_fails} if window == "host_start_failure" else {}
    calls: list = []

    def stop_raises(self, *args, **kwargs):  # injected fault
        calls.append(self)
        raise RuntimeError("injected host stop failure")

    released: list = []
    factory = owned_workers.service_factory(seamed_service(**seams))
    patches = [mock.patch("heel.saas.server.HostAuthorityService", factory),
               mock.patch.object(HostAuthorityService, "stop", stop_raises)]
    if window == "close_wrapper":
        patches.append(mock.patch("heel.saas.server._install_production_close", _install_fails))
    with contextlib.ExitStack() as stack:
        for patch in patches:
            stack.enter_context(patch)
        stack.enter_context(observe_release(released))
        with pytest.raises(RuntimeError, match="injected host stop failure") as raised:
            build_server(config)
    (service,) = owned_workers.services
    assert calls == [service] and released == []
    assert raised.value.__context__ is not None
    assert reaper_threads() == 0
    if window == "close_wrapper":
        assert service.thread.is_alive()  # the stop never ran: the worker really may still run
    record = _assert_retained_unhealthy(config, "host_authority_stop_failed")
    assert record.host_authority is service
    service.stop()  # test cleanup: the real stop, after the observation
    if service.thread is not None:
        service.thread.join(10)
    release_retained_for_test()
    assert lock_is_free(config.database_path)


@pytest.mark.parametrize("interrupt", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("reaper_stop", ["joined", "unproven"])
def test_interrupt_after_reaper_start_is_reraised_and_never_releases_a_live_worker(
        short_tmp, owned_workers, interrupt, reaper_stop):
    from heel.saas import server as server_module
    from heel.saas.canary_reaper import CanaryReaper
    from heel.saas.server import ProductionConfiguration, build_server

    config = ProductionConfiguration.from_environment(host_environment(short_tmp))
    real_stop = CanaryReaper.stop

    def constructor_interrupted(*_args, **_kwargs):  # injected cancellation after the reaper started
        assert reaper_threads() == 1
        raise interrupt()

    def unproven(self, *args, **kwargs):  # SEAM-STOP-HANG snapshot tests only (on the reaper; injected)
        assert real_stop(self, *args, **kwargs)
        return False

    released: list = []
    with contextlib.ExitStack() as stack:
        stack.enter_context(mock.patch("heel.saas.server.HostAuthorityService", constructor_interrupted))
        if reaper_stop == "unproven":
            stack.enter_context(mock.patch.object(CanaryReaper, "stop", unproven))
        stack.enter_context(observe_release(released))
        with pytest.raises(interrupt) as raised:
            build_server(config)
    assert type(raised.value) is interrupt  # the original cancellation, never converted
    assert reaper_threads() == 0
    if reaper_stop == "joined":
        assert released == [{"reaper_threads": 0, "host_threads": 0}]
        assert server_module._RETAINED_OWNERSHIP == [] and lock_is_free(config.database_path)
        return
    assert released == []
    _assert_retained_unhealthy(config, "reaper_stop_timeout")
    release_retained_for_test()
    assert lock_is_free(config.database_path)


def test_interrupt_inside_host_start_unpublishes_joins_and_reraises(short_tmp, fast_bounds, no_host_thread_left,
                                                                   owned_workers):
    from heel.saas import server as server_module
    from heel.saas.server import ProductionConfiguration, build_server

    def interrupted(_thread):  # SEAM-THREAD-START snapshot tests only (injected cancellation)
        assert os.path.exists(config.host_authority.socket_path)  # published, not yet serving
        raise KeyboardInterrupt

    config = ProductionConfiguration.from_environment(host_environment(short_tmp))
    released: list = []
    factory = owned_workers.service_factory(seamed_service(_thread_start_for_tests=interrupted))
    with mock.patch("heel.saas.server.HostAuthorityService", factory), observe_release(released), \
            pytest.raises(KeyboardInterrupt):
        build_server(config)
    (service,) = owned_workers.services
    assert released == [{"reaper_threads": 0, "host_threads": 0}]
    assert service.phase == "stopped" and service.decider.quarantined
    assert not os.path.exists(config.host_authority.socket_path)
    assert server_module._RETAINED_OWNERSHIP == [] and lock_is_free(config.database_path)


@pytest.mark.parametrize("failure", ["startup_timeout", "interrupt"])
@pytest.mark.parametrize("reaper_stop", ["joined", "returns_false", "raises"])
def test_reaper_start_failure_with_a_live_thread_releases_only_after_a_proven_join(
        short_tmp, owned_workers, failure, reaper_stop):
    """Default off. The real reaper thread is held inside its first cycle by a bounded barrier
    (test-only timing wrapper) while ``start()`` times out or is interrupted; CanaryReaper.start's
    own bounded join proves nothing, so only ``stop()`` returning True may release."""
    from heel.saas import canary_reaper
    from heel.saas import server as server_module
    from heel.saas.canary_reaper import CanaryReaper, CanaryReaperError
    from heel.saas.server import ProductionConfiguration, ProductionConfigurationError, build_server

    config = ProductionConfiguration.from_environment(valid_environment(short_tmp))
    barrier, in_cycle = threading.Event(), threading.Event()
    real_cycle, real_start, real_stop = CanaryReaper._cycle, CanaryReaper.start, CanaryReaper.stop

    def blocked_cycle(self, *args, **kwargs):  # test-only barrier, bounded
        in_cycle.set()
        assert barrier.wait(20), "reaper barrier never released"
        return real_cycle(self, *args, **kwargs)

    class InterruptingStartup(threading.Event):
        def wait(self, timeout=None):  # injected cancellation of start()'s startup wait
            assert in_cycle.wait(5)
            raise KeyboardInterrupt

    def bounded_start(self, **_kwargs):  # test-only timing wrapper (production bound is 5 s)
        if failure == "interrupt":
            self._startup = InterruptingStartup()
        real_start(self, timeout=0.3)

    def stop(self, *args, **kwargs):
        assert self.thread.is_alive()  # still inside the blocked cycle
        if reaper_stop == "joined":
            barrier.set()
            return real_stop(self, timeout=10)
        if reaper_stop == "returns_false":
            return real_stop(self, timeout=0.2)  # the real bounded join, refused by the barrier
        raise RuntimeError("injected reaper stop failure")  # injected fault

    released: list = []
    expected = {"joined": ProductionConfigurationError, "returns_false": CanaryReaperError,
                "raises": RuntimeError}[reaper_stop]
    if failure == "interrupt":
        expected = KeyboardInterrupt
    try:
        with mock.patch.object(CanaryReaper, "_cycle", blocked_cycle), \
                mock.patch.object(CanaryReaper, "start", bounded_start), \
                mock.patch.object(CanaryReaper, "stop", stop), \
                mock.patch.object(canary_reaper, "STOP_TIMEOUT_SECONDS", 0.2), observe_release(released), \
                pytest.raises(expected) as raised:
            build_server(config)
        (reaper,) = owned_workers.reapers
        if failure == "startup_timeout" and reaper_stop == "joined":
            assert "canary lifecycle coordinator failed to start" in str(raised.value)
            assert "startup timed out" in str(raised.value.__cause__)
        if reaper_stop == "joined":
            assert released == [{"reaper_threads": 0, "host_threads": 0}]
            assert not reaper.thread.is_alive()
            assert server_module._RETAINED_OWNERSHIP == [] and lock_is_free(config.database_path)
            return
        assert released == [] and reaper.thread.is_alive()
        _assert_retained_unhealthy(
            config, {"returns_false": "reaper_stop_timeout", "raises": "reaper_stop_failed"}[reaper_stop])
    finally:
        barrier.set()
    reaper.thread.join(10)
    release_retained_for_test()
    assert lock_is_free(config.database_path)


def test_build_server_refuses_programmatic_managed_config_before_lock_or_bind(short_tmp, owned_workers):
    """The managed rules hold at the build_server boundary for a configuration that did not come
    from ``from_environment``; non-managed and default-off configurations stay supported."""
    import dataclasses

    from heel.saas.server import ProductionConfiguration, ProductionConfigurationError, build_server

    config = ProductionConfiguration.from_environment(valid_environment(short_tmp))
    socket_path = os.path.join(short_tmp, "h.sock")
    cases = [
        ("HEEL_MANAGED_HOST=1 requires HEEL_HOST_AUTHORITY_SOCKET", None),
        ("HEEL_MANAGED_HOST=1 requires HEEL_HOST_AUTHORITY_PEER_UID=0",
         HostAuthorityConfig(socket_path, 1000, PeerProfile.EXTERNAL_PIDNS)),
        ("HEEL_MANAGED_HOST=1 requires HEEL_HOST_AUTHORITY_PEER_UID=0",
         HostAuthorityConfig(socket_path, False, PeerProfile.EXTERNAL_PIDNS)),
        ("HEEL_MANAGED_HOST=1 requires HEEL_HOST_AUTHORITY_PEER_PROFILE=external-pidns",
         HostAuthorityConfig(socket_path, 0, PeerProfile.SHARED_PIDNS)),
        ("HEEL_MANAGED_HOST=1 requires HEEL_HOST_AUTHORITY_PEER_PROFILE=external-pidns",
         HostAuthorityConfig(socket_path, 0, "external-pidns")),
    ]
    for expected, authority in cases:
        with pytest.raises(ProductionConfigurationError, match=re.escape(expected)):
            build_server(dataclasses.replace(config, managed_host=True, host_authority=authority))
        assert owned_workers.locks == [] and not os.path.exists(config.database_path + ".lock")
        assert not os.path.exists(config.database_path) and not os.path.exists(socket_path)
        assert reaper_threads() == 0
        with pytest.raises(OSError):
            socket.create_connection(("127.0.0.1", config.port), timeout=1).close()
    server = build_server(config)  # default off, not managed
    try:
        assert server.host_authority is None and server.reaper_ready is True
    finally:
        server.server_close()


def test_small_monotonic_regression_with_flat_cp_time_closes_the_generation(authority):
    """A host monotonic regression inside the 500 ms skew tolerance, with the control plane's clock
    flat, is still a clock gap: the skew clause alone would admit it."""
    clock = default_clock(authority)
    decider = make_decider(authority, clock)
    for slot, back_ms in (("slot-1ms", 1), ("slot-500ms", 500)):
        g = secrets.token_hex(16)
        assert decider(authority.request(generation_id=g, slot_id=slot, sequence=1, monotonic_ms=1000))[
            "reason"] == "none"
        reply = decider(authority.request(generation_id=g, slot_id=slot, sequence=2, monotonic_ms=1000 - back_ms))
        assert (reply["decision"], reply["reason"]) == ("inactive", "clock_gap")
        row = ledger_row(authority.path, g)
        assert (row["state"], row["close_reason"], row["last_sequence"], row["last_monotonic_ms"]) == (
            "closed", "clock_gap", 1, 1000)


class StopDeclaringLock(RecordingLock):
    """The recording wrapper with an acquisition hook: runs ``before_acquire`` after the caller's
    pre-gate checks and before the lock is taken (test attribute only)."""

    def __init__(self, name: str, records: list, before_acquire):
        super().__init__(name, records)
        self.before_acquire = before_acquire

    def acquire(self, blocking: bool = True, timeout: float = -1) -> bool:
        self.before_acquire()
        return super().acquire(blocking, timeout)


def test_stop_declared_between_the_pre_check_and_the_gate_never_reaches_the_database(authority):
    cls, connect = recording()
    decider = make_decider(authority, _connect_for_tests=connect)  # SEAM-RECORDING-CONNECTION snapshot tests only
    records: list = []
    # Declares stop exactly as stop() step 1 does, after the pre-check passed (recording wrapper, test attribute).
    decider._db_gate = StopDeclaringLock("_db_gate", records, decider._stopping.set)
    reply = decider(authority.request())
    assert (reply["decision"], reply["reason"]) == ("inactive", "cp_draining")
    assert records == [("_db_gate", ())]  # the gate was entered: the race window was taken
    assert cls.log == [] and ledger(authority.path) == []
    assert not decider.quarantined


def test_ordinary_joined_stop_establishes_the_quarantine(live_authority, short_tmp, no_host_thread_left):
    service = make_service(live_authority.path, short_tmp, live_authority.signing)
    service.start()
    assert not service.decider.quarantined and not service.quarantined
    assert service.stop() == StopResult(True, True)
    assert service.phase == "stopped" and service.quarantined
    assert service.decider.quarantined  # the gate is closed, not merely reported closed
    assert service.decider._db_gate.acquire(timeout=1)  # and free: no decision holds it
    service.decider._db_gate.release()


# ---------------------------------------------------------------------------------------------
# S-30: a true process keeps the flock while a worker lingers, and releases it on exit.

CHILD = r'''
import json, os, sys
sys.path.insert(0, sys.argv[1])
from heel.crypto import SigningAuthority
from heel.saas import host_snapshot
from heel.saas.host_authority import HostAuthorityConfig, HostAuthorityListener, PeerProfile
from heel.saas.server import _SingleProcessDatabaseLock

root = sys.argv[2]
database = os.path.join(root, "cp.db")
lock = _SingleProcessDatabaseLock.acquire(database)


class SeamListener(HostAuthorityListener):
    """SEAM-LISTENER snapshot tests only (publish without check_startup, no peer rule)."""

    def start(self):
        self._publish()

    def _handle(self, connection):
        print("accepted", flush=True)
        self._serve_request(connection)


host_snapshot.STOP_TIMEOUT_SECONDS = 1.0  # bounded test timing in the child only
host_snapshot.QUARANTINE_TIMEOUT_SECONDS = 0.5
service = host_snapshot.HostAuthorityService(
    HostAuthorityConfig(os.path.join(root, "h.sock"), os.geteuid(), PeerProfile.SHARED_PIDNS), database,
    signing=SigningAuthority.generate(), draining=lambda: False, on_unexpected_death=None,
    _listener_for_tests=lambda config, decide: SeamListener(config, decide),
)
service.start()
print("ready", flush=True)
assert sys.stdin.readline().strip() == "go"
result = service.stop()
print(json.dumps({"stopped": result.stopped, "quarantined": result.quarantined}, sort_keys=True), flush=True)
raise RuntimeError("stop_timeout: ownership retained until the worker ends")
'''


def test_true_process_shutdown_keeps_flock_until_exit(short_tmp):
    import queue

    child_tmp = tempfile.mkdtemp(prefix="hc", dir=os.environ.get("TMPDIR"))
    proc = subprocess.Popen(
        [sys.executable, "-I", "-c", CHILD, str(REPO_ROOT), short_tmp],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        env={**os.environ, "TMPDIR": child_tmp},
    )
    lines: queue.Queue = queue.Queue()
    reader = threading.Thread(target=lambda: [lines.put(line.strip()) for line in proc.stdout], daemon=True)
    reader.start()
    trickle = None
    lock_path = os.path.join(short_tmp, "cp.db.lock")
    try:
        assert lines.get(timeout=20) == "ready"
        trickle = Trickle(os.path.join(short_tmp, "h.sock"))
        assert lines.get(timeout=10) == "accepted" and trickle.sent.wait(5)
        proc.stdin.write("go\n")
        proc.stdin.flush()
        assert json.loads(lines.get(timeout=10)) == {"quarantined": True, "stopped": False}
        with pytest.raises(subprocess.TimeoutExpired):
            proc.wait(timeout=2.0)  # main raised, yet the process lives while the worker lingers
        descriptor = os.open(lock_path, os.O_RDWR)
        try:
            with pytest.raises(OSError) as refused:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            assert refused.value.errno in {errno.EAGAIN, errno.EACCES}
        finally:
            os.close(descriptor)
        trickle.close()
        assert proc.wait(timeout=10) != 0
        assert "RuntimeError" in proc.stderr.read()
        descriptor = os.open(lock_path, os.O_RDWR)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)  # released by the kernel at exit
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)
    finally:
        if trickle is not None:
            trickle.close()
        if proc.poll() is None:
            proc.kill()
            proc.wait(10)
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            with contextlib.suppress(Exception):
                stream.close()
        shutil.rmtree(child_tmp, ignore_errors=True)
