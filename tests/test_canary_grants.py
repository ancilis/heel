from __future__ import annotations

import base64
import copy
import hashlib
import json

import pytest

from heel.canary_contracts import canonical_bytes, canonical_digest, validate_execution_grant
from heel.crypto import verify_envelope
from heel.saas.catalog import Meter
from heel.saas.ledger import QuotaExceeded

from canary_test_support import (
    Clock,
    NOW,
    NOW_MS,
    PROJECT,
    RUNNER,
    VERIFICATION_DIGEST,
    WORKSPACE,
    approval_projection,
    connect,
    seed_authority,
    service,
    submit_and_approve,
)


def test_context_migrations_preserve_binding_reaper_affinity_and_protocol_schema():
    from heel.saas.migrate import CONTROL_PLANE_MIGRATIONS

    assert [(migration.version, migration.name) for migration in CONTROL_PLANE_MIGRATIONS[-14:]] == [
        (16, "runner_context_bindings"),
        (17, "runner_context_one_active_per_runner"),
        (18, "runner_context_reaper_indexes"),
        (19, "runner_context_affinities"),
        (20, "runner_context_bounded_purge"),
        (21, "runner_context_affinity_guards"),
        (22, "pending_approval_live_seek"),
        (23, "runner_context_purge_readiness"),
        (24, "runner_pairing_control_protocol_v3"),
        (25, "runner_request_receipt_retention"),
        (26, "runner_activation_abort_receipts"),
        (27, "runner_single_open_rotation"),
        (28, "runner_key_history_expiry"),
        (29, "runner_auth_bounded_retention"),
    ]
    conn = connect()
    assert "verification_record_digest" in {
        row[1] for row in conn.execute("PRAGMA table_info(canary_environments)")
    }
    for table in (
        "canary_approval_projections", "canary_execution_grants", "canary_runs",
        "canary_run_events", "canary_operational_receipts", "canary_audit_records",
        "canary_disclosure_requests", "canary_disclosure_permits",
        "canary_findings_projections", "canary_reaper_state", "canary_control_generation",
    ):
        assert conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,),
        ).fetchone(), table
    assert conn.execute(
        "SELECT generation FROM canary_control_generation WHERE singleton=1"
    ).fetchone()[0] == 0
    conn.execute("INSERT INTO kill_switches VALUES('global','pause','admin',1)")
    assert conn.execute(
        "SELECT generation FROM canary_control_generation WHERE singleton=1"
    ).fetchone()[0] == 1
    permit_columns = {
        row[1] for row in conn.execute("PRAGMA table_info(canary_disclosure_permits)")
    }
    assert {
        "projection_schema_version", "scenario_count", "finding_count",
    } <= permit_columns
    findings_columns = {
        row[1] for row in conn.execute("PRAGMA table_info(canary_findings_projections)")
    }
    assert {
        "runner_id", "runner_key_id", "receipt_id", "receipt_json", "accepted_at",
    } <= findings_columns
    permit_sql = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='canary_disclosure_permits'"
    ).fetchone()[0]
    assert "'permitted','consumed','expired','revoked'" in "".join(permit_sql.split())


@pytest.mark.parametrize(
    ("statement", "label"),
    [
        (
            "CREATE TRIGGER canary_runner_receipt_destroy AFTER INSERT "
            "ON canary_runner_request_ledger BEGIN "
            "DELETE FROM canary_runner_request_ledger WHERE rowid=NEW.rowid; END",
            "trigger",
        ),
        (
            "CREATE VIEW canary_runner_receipt_view AS "
            "SELECT request_digest FROM canary_runner_request_ledger",
            "view",
        ),
    ],
)
def test_runner_auth_schema_rejects_extra_owned_trigger_or_view(statement, label):
    from heel.saas.runner_auth import validate_runner_auth_schema

    conn = connect()
    conn.execute(statement)
    with pytest.raises(RuntimeError, match="runner authentication schema is not current"):
        validate_runner_auth_schema(conn)
    assert conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type=?", (label,),
    ).fetchone() is not None


def test_submit_verifies_current_runner_signature_exact_proof_and_adapters():
    conn = connect()
    runner = seed_authority(conn)
    coordinator = service(conn, Clock())
    projection = approval_projection(runner)
    result = coordinator.submit_projection(projection, uploaded_by="user_owner")
    assert result["status"] == "awaiting_execution_approval"
    stored = conn.execute(
        "SELECT run_id,runner_key_id,manifest_digest,status FROM canary_approval_projections"
    ).fetchone()
    assert tuple(stored) == (
        result["run_id"], runner.key_id, projection["manifest_digest"],
        "awaiting_execution_approval",
    )
    assert [row["event_type"] for row in conn.execute(
        "SELECT event_type FROM canary_run_events ORDER BY sequence"
    )] == ["prepared", "awaiting_execution_approval"]
    assert sorted(row["action"] for row in conn.execute(
        "SELECT action FROM canary_audit_records"
    )) == ["awaiting_execution_approval", "prepared"]

    for mutation in ("signature", "proof", "adapter"):
        bad = copy.deepcopy(projection)
        if mutation == "signature":
            bad["signature_b64"] = "A" * 88
        elif mutation == "proof":
            bad["environment"]["verification_record_digest"] = "c" * 64
        else:
            bad["runner"]["adapter_versions"] = ["2.0.0"]
        if mutation != "signature":
            unsigned = {
                key: value for key, value in bad.items()
                if key not in {"projection_digest", "signing_key_id", "signature_b64"}
            }
            from heel.canary_contracts import canonical_digest
            bad["projection_digest"] = canonical_digest(unsigned)
            bad.update(runner.sign(canonical_bytes(unsigned)))
        with pytest.raises(ValueError):
            coordinator.submit_projection(bad, uploaded_by="user_owner")


def test_service_errors_expose_only_the_frozen_public_code_vocabulary():
    from heel.saas.canary_runs import CanaryRunError

    assert CanaryRunError("invalid_projection_signature").code == "invalid_canary_projection"
    assert CanaryRunError("proof_not_executable").code == "environment_not_executable"
    assert CanaryRunError("source_sequence_gap").code == "event_sequence_conflict"
    assert CanaryRunError("stop_conflict").code == "canary_state_conflict"
    assert CanaryRunError("invalid_canary_approval").code == "invalid_canary_approval"


def test_approval_reserves_and_issues_exact_signed_grant_in_one_transaction():
    conn = connect()
    runner = seed_authority(conn)
    coordinator = service(conn, Clock())
    projection = approval_projection(runner)
    submitted = coordinator.submit_projection(
        projection, uploaded_by="user_owner",
    )
    result = coordinator.approve(
        WORKSPACE, PROJECT, submitted["run_id"],
        projection_digest=projection["projection_digest"], actor="user_owner", role="owner",
        reason="Approve the exact bounded rehearsal", exact_hostname="canary.acme.dev",
        recent_auth_at_ms=NOW_MS, idempotency_key="ca1-" + "d" * 64,
        expected_kill_switch_generation=0,
    )
    grant = validate_execution_grant(result["grant"])
    unsigned = {
        key: value for key, value in grant.items()
        if key not in {"grant_digest", "signing_key_id", "signature_b64"}
    }
    verify_envelope(
        {coordinator.signing.key_id: coordinator.signing.public_key},
        {"signing_key_id": grant["signing_key_id"], "signature_b64": grant["signature_b64"]},
        canonical_bytes(unsigned),
    )
    assert grant["environment"]["verification_record_digest"] == VERIFICATION_DIGEST
    assert grant["runner_binding"]["runner_key_id"] == runner.key_id
    row = conn.execute(
        "SELECT status,reservation_id,idempotency_key FROM canary_execution_grants"
    ).fetchone()
    assert tuple(row) == ("issued", result["reservation_id"], "ca1-" + "d" * 64)
    assert conn.execute(
        "SELECT COUNT(*) FROM usage_ledger WHERE meter=? AND kind='reserve'",
        (Meter.CANARY_RUNS.value,),
    ).fetchone()[0] == 1
    assert conn.execute("SELECT COUNT(*) FROM canary_audit_records").fetchone()[0] >= 3


def test_approval_rechecks_ceremony_kill_runner_and_rolls_back_quota_failure():
    conn = connect()
    runner = seed_authority(conn)
    coordinator = service(conn, Clock())
    projection = approval_projection(runner)
    submitted = coordinator.submit_projection(
        projection, uploaded_by="user_owner",
    )
    base = dict(
        projection_digest=projection["projection_digest"], actor="user_owner", role="owner",
        reason="Approve bounded rehearsal",
        exact_hostname="canary.acme.dev", recent_auth_at_ms=NOW_MS,
        idempotency_key="ca1-" + "e" * 64, expected_kill_switch_generation=0,
    )
    for change in (
        {"role": "member"}, {"reason": ""}, {"reason": " padded"},
        {"reason": "Cafe\u0301"}, {"reason": "bad\nreason"},
        {"projection_digest": "c" * 64},
        {"exact_hostname": "other.acme.dev"}, {"exact_hostname": "CANARY.ACME.DEV"},
        {"recent_auth_at_ms": NOW_MS - 15 * 60 * 1000 - 1},
        {"idempotency_key": "not-closed"},
    ):
        with pytest.raises(ValueError):
            coordinator.approve(WORKSPACE, PROJECT, submitted["run_id"], **(base | change))

    class FailingLedger:
        def reserve_in_transaction(self, *_args, **_kwargs):
            raise QuotaExceeded(Meter.CANARY_RUNS, 1, 10, 10)

    coordinator.ledger = FailingLedger()
    before = conn.total_changes
    with pytest.raises(QuotaExceeded):
        coordinator.approve(WORKSPACE, PROJECT, submitted["run_id"], **base)
    assert conn.total_changes == before
    assert conn.execute("SELECT COUNT(*) FROM canary_execution_grants").fetchone()[0] == 0


def test_approval_rechecks_persisted_membership_inside_its_write_transaction():
    conn = connect()
    runner = seed_authority(conn)
    coordinator = service(conn, Clock())
    projection = approval_projection(runner)
    run_id = coordinator.submit_projection(projection, uploaded_by="user_owner")["run_id"]
    conn.execute(
        "UPDATE memberships SET role='member' WHERE workspace_id=? AND user_id=?",
        (WORKSPACE, "user_owner"),
    )
    conn.commit()
    with pytest.raises(ValueError):
        coordinator.approve(
            WORKSPACE, PROJECT, run_id, projection_digest=projection["projection_digest"],
            actor="user_owner", role="owner",
            reason="Approve bounded rehearsal", exact_hostname="canary.acme.dev",
            recent_auth_at_ms=NOW_MS, idempotency_key="ca1-" + "9" * 64,
            expected_kill_switch_generation=0,
        )
    assert conn.execute("SELECT COUNT(*) FROM canary_execution_grants").fetchone()[0] == 0
    assert conn.execute(
        "SELECT status FROM canary_runs WHERE run_id=?", (run_id,),
    ).fetchone()[0] == "awaiting_execution_approval"


def test_approval_is_exactly_idempotent_and_cross_run_key_reuse_conflicts():
    conn = connect()
    runner = seed_authority(conn)
    coordinator = service(conn, Clock())
    first_projection = approval_projection(runner)
    first_run = coordinator.submit_projection(
        first_projection, uploaded_by="user_owner",
    )["run_id"]
    args = dict(
        projection_digest=first_projection["projection_digest"], actor="user_owner",
        role="owner", reason="Approve bounded rehearsal",
        exact_hostname="canary.acme.dev", recent_auth_at_ms=NOW_MS,
        idempotency_key="ca1-" + "f" * 64, expected_kill_switch_generation=0,
    )
    first = coordinator.approve(WORKSPACE, PROJECT, first_run, **args)
    assert coordinator.approve(WORKSPACE, PROJECT, first_run, **args) == first
    with pytest.raises(ValueError):
        coordinator.approve(
            WORKSPACE, PROJECT, first_run,
            **(args | {"exact_hostname": "other.acme.dev"}),
        )
    projection = approval_projection(runner)
    projection["projection_id"] = "ap_second"
    unsigned = {
        key: value for key, value in projection.items()
        if key not in {"projection_digest", "signing_key_id", "signature_b64"}
    }
    from heel.canary_contracts import canonical_digest
    projection["projection_digest"] = canonical_digest(unsigned)
    projection.update(runner.sign(canonical_bytes(unsigned)))
    second_run = coordinator.submit_projection(projection, uploaded_by="user_owner")["run_id"]
    with pytest.raises(ValueError):
        coordinator.approve(WORKSPACE, PROJECT, second_run, **args)
    assert conn.execute("SELECT COUNT(*) FROM canary_execution_grants").fetchone()[0] == 1


def test_claim_consumes_oldest_exact_nonce_and_provisions_four_chains_atomically():
    from heel.saas.runner_auth import RunnerAuthStore, initialize_runner_auth_schema

    conn = connect()
    runner = seed_authority(conn)
    initialize_runner_auth_schema(conn)
    runner_auth = RunnerAuthStore(conn, pepper=b"r" * 32, now=Clock())
    coordinator = service(conn, Clock(), runner_auth=runner_auth)
    projection = approval_projection(runner)
    submitted = coordinator.submit_projection(projection, uploaded_by="user_owner")
    approved = coordinator.approve(
        WORKSPACE, PROJECT, submitted["run_id"],
        projection_digest=projection["projection_digest"], actor="user_owner", role="owner",
        reason="Approve bounded rehearsal", exact_hostname="canary.acme.dev",
        recent_auth_at_ms=NOW_MS, idempotency_key="ca1-" + "1" * 64,
        expected_kill_switch_generation=0,
    )
    claimed = coordinator.claim(WORKSPACE, RUNNER, runner.key_id)
    assert claimed["run_id"] == approved["run_id"]
    assert claimed["grant"] == approved["grant"]
    assert claimed["approval_projection"]["projection_id"] == "ap_canary"
    assert set(claimed["chain_states"]) == {"heartbeat", "progress", "result", "stop-ack"}
    assert claimed["gate"]["active"] is True
    assert conn.execute("SELECT status FROM canary_execution_grants").fetchone()[0] == "claimed"
    assert conn.execute("SELECT kind FROM canary_consumed_nonces").fetchone()[0] == "execution_grant"
    assert coordinator.claim(WORKSPACE, RUNNER, runner.key_id) is None

    stored = json.loads(conn.execute("SELECT grant_json FROM canary_execution_grants").fetchone()[0])
    stored["runner_binding"]["runner_key_id"] = "k_wrong"
    conn.execute(
        "UPDATE canary_execution_grants SET status='issued',claimed_at=NULL,grant_json=?",
        (json.dumps(stored),),
    )
    conn.execute("UPDATE canary_runs SET status='approved',claimed_at_ms=NULL")
    conn.commit()
    with pytest.raises(ValueError):
        coordinator.claim(WORKSPACE, RUNNER, runner.key_id)


def test_claim_rolls_back_nonce_chains_and_grant_if_run_is_no_longer_approved():
    from heel.saas.runner_auth import RunnerAuthStore, initialize_runner_auth_schema

    conn = connect()
    runner = seed_authority(conn)
    initialize_runner_auth_schema(conn)
    clock = Clock()
    auth = RunnerAuthStore(conn, pepper=b"r" * 32, now=clock)
    coordinator, _, approved = submit_and_approve(
        conn, clock, runner, runner_auth=auth, idem_char="4",
    )
    conn.execute(
        "UPDATE canary_runs SET status='cancelled' WHERE run_id=?", (approved["run_id"],),
    )
    conn.commit()
    with pytest.raises(ValueError):
        coordinator.claim(WORKSPACE, RUNNER, runner.key_id)
    assert conn.execute(
        "SELECT status FROM canary_execution_grants WHERE grant_id=?",
        (approved["grant_id"],),
    ).fetchone()[0] == "issued"
    assert conn.execute("SELECT COUNT(*) FROM canary_consumed_nonces").fetchone()[0] == 0
    assert conn.execute(
        "SELECT COUNT(*) FROM canary_runner_nonce_chains WHERE chain_name LIKE ?",
        ("%:" + approved["run_id"],),
    ).fetchone()[0] == 0


def test_claim_uses_signed_expiry_not_a_later_mutated_database_expiry():
    from heel.saas.runner_auth import RunnerAuthStore, initialize_runner_auth_schema

    conn = connect()
    runner = seed_authority(conn, proof_expires_at=NOW + 60)
    initialize_runner_auth_schema(conn)
    clock = Clock()
    auth = RunnerAuthStore(conn, pepper=b"r" * 32, now=clock)
    coordinator, _, approved = submit_and_approve(
        conn, clock, runner, runner_auth=auth, idem_char="5",
    )
    conn.execute(
        "UPDATE canary_environments SET proof_expires_at=? WHERE environment_id=?",
        (NOW + 3600, approved["grant"]["environment"]["environment_id"]),
    )
    conn.execute(
        "UPDATE canary_execution_grants SET expires_at=? WHERE grant_id=?",
        (NOW_MS + 120_000, approved["grant_id"]),
    )
    conn.commit()
    clock.value += 61
    with pytest.raises(ValueError):
        coordinator.claim(WORKSPACE, RUNNER, runner.key_id)
    assert conn.execute(
        "SELECT status FROM canary_execution_grants WHERE grant_id=?",
        (approved["grant_id"],),
    ).fetchone()[0] == "issued"
    assert conn.execute("SELECT COUNT(*) FROM canary_consumed_nonces").fetchone()[0] == 0


def test_claim_skips_expired_oldest_grant_for_a_newer_unexpired_grant():
    from heel.saas.runner_auth import RunnerAuthStore, initialize_runner_auth_schema

    conn = connect()
    runner = seed_authority(conn, proof_expires_at=NOW + 60)
    initialize_runner_auth_schema(conn)
    clock = Clock()
    auth = RunnerAuthStore(conn, pepper=b"r" * 32, now=clock)
    coordinator, _, first = submit_and_approve(
        conn, clock, runner, runner_auth=auth, idem_char="6",
    )
    conn.execute(
        "UPDATE canary_environments SET proof_expires_at=? WHERE environment_id=?",
        (NOW + 3600, first["grant"]["environment"]["environment_id"]),
    )
    conn.commit()
    second_projection = approval_projection(runner)
    second_projection["projection_id"] = "ap_canary_second"
    unsigned = {
        key: value for key, value in second_projection.items()
        if key not in {"projection_digest", "signing_key_id", "signature_b64"}
    }
    second_projection["projection_digest"] = canonical_digest(unsigned)
    second_projection.update(runner.sign(canonical_bytes(unsigned)))
    second_run = coordinator.submit_projection(
        second_projection, uploaded_by="user_owner",
    )["run_id"]
    coordinator.approve(
        WORKSPACE, PROJECT, second_run,
        projection_digest=second_projection["projection_digest"],
        actor="user_owner", role="owner", reason="Approve the newer bounded rehearsal",
        exact_hostname="canary.acme.dev", recent_auth_at_ms=NOW_MS,
        idempotency_key="ca1-" + "7" * 64, expected_kill_switch_generation=0,
    )
    clock.value += 61
    claimed = coordinator.claim(WORKSPACE, RUNNER, runner.key_id)
    assert claimed is not None and claimed["run_id"] == second_run
    assert conn.execute(
        "SELECT status FROM canary_execution_grants WHERE grant_id=?", (first["grant_id"],),
    ).fetchone()[0] == "issued"


def test_rotation_is_blocked_while_a_claimed_run_is_active():
    from heel.crypto import SigningAuthority
    from heel.runner.identity import runner_phrase_words
    from heel.saas.runner_auth import RunnerAuthError, RunnerAuthStore

    conn = connect()
    runner = seed_authority(conn)
    runner_auth = RunnerAuthStore(conn, pepper=b"r" * 32, now=Clock())
    coordinator = service(conn, Clock(), runner_auth=runner_auth)
    projection = approval_projection(runner)
    submitted = coordinator.submit_projection(
        projection, uploaded_by="user_owner",
    )
    coordinator.approve(
        WORKSPACE, PROJECT, submitted["run_id"],
        projection_digest=projection["projection_digest"], actor="user_owner", role="owner",
        reason="Approve bounded rehearsal", exact_hostname="canary.acme.dev",
        recent_auth_at_ms=NOW_MS, idempotency_key="ca1-" + "2" * 64,
        expected_kill_switch_generation=0,
    )
    coordinator.claim(WORKSPACE, RUNNER, runner.key_id)

    replacement = SigningAuthority.generate()
    with pytest.raises(RunnerAuthError, match="active canary run"):
        runner_auth.start_rotation(
            WORKSPACE, RUNNER,
            previous_fingerprint=hashlib.sha256(runner.public_key_bytes).hexdigest(),
            public_key_b64=replacement.canonical_public_key,
            phrase=" ".join(runner_phrase_words()[:6]),
            runner_version="2.0.0", adapters={"http": "1.0.0"},
        )


def test_rotation_start_has_one_immutable_old_key_bound_ceremony():
    from heel.crypto import SigningAuthority
    from heel.runner.identity import runner_phrase_words
    from heel.saas.runner_auth import RunnerAuthStore, RunnerRotationInProgress

    conn = connect()
    runner = seed_authority(conn)
    runner_auth = RunnerAuthStore(conn, pepper=b"r" * 32, now=Clock())
    first = SigningAuthority.generate()
    second = SigningAuthority.generate()
    phrase = " ".join(runner_phrase_words()[:6])
    rotation = runner_auth.start_rotation(
        WORKSPACE, RUNNER,
        previous_fingerprint=hashlib.sha256(runner.public_key_bytes).hexdigest(),
        public_key_b64=first.canonical_public_key, phrase=phrase,
        runner_version="2.0.0", adapters={"http": "1.0.0"},
    )

    row = conn.execute(
        "SELECT old_key_id,old_fingerprint,status FROM canary_runner_rotations WHERE pairing_id=?",
        (rotation.pairing_id,),
    ).fetchone()
    assert tuple(row) == (
        runner.key_id, hashlib.sha256(runner.public_key_bytes).hexdigest(), "rotation_pending",
    )
    with pytest.raises(RunnerRotationInProgress, match="rotation in progress"):
        runner_auth.start_rotation(
            WORKSPACE, RUNNER,
            previous_fingerprint=hashlib.sha256(runner.public_key_bytes).hexdigest(),
            public_key_b64=second.canonical_public_key,
            phrase=phrase, runner_version="2.0.0", adapters={"http": "1.0.0"},
        )
    assert conn.execute(
        "SELECT COUNT(*) FROM canary_runner_rotations WHERE workspace_id=? AND runner_id=? "
        "AND status IN ('rotation_pending','rotation_approved')",
        (WORKSPACE, RUNNER),
    ).fetchone()[0] == 1


def test_rotation_revokes_and_refunds_unused_old_key_grants_atomically():
    from heel.crypto import SigningAuthority
    from heel.runner.identity import runner_phrase_words
    from heel.saas.runner_auth import RunnerAuthStore

    conn = connect()
    runner = seed_authority(conn)
    coordinator, _, approved = submit_and_approve(conn, Clock(), runner, idem_char="3")
    runner_auth = RunnerAuthStore(conn, pepper=b"r" * 32, now=Clock())
    conn.execute(
        "INSERT INTO canary_runner_chain_cursors VALUES(?,?,?,?,?,?)",
        (WORKSPACE, RUNNER, "claim", 1, 0, NOW),
    )
    conn.commit()
    replacement = SigningAuthority.generate()
    phrase = " ".join(runner_phrase_words()[:6])
    rotation = runner_auth.start_rotation(
        WORKSPACE, RUNNER,
        previous_fingerprint=hashlib.sha256(runner.public_key_bytes).hexdigest(),
        public_key_b64=replacement.canonical_public_key,
        phrase=phrase, runner_version="2.0.0", adapters={"http": "1.0.0"},
    )
    runner_auth.approve_rotation(
        WORKSPACE, rotation.pairing_id, phrase=phrase,
        fingerprint=rotation.fingerprint, actor="user_owner",
    )
    challenge = runner_auth.rotation_activation_challenge(rotation.pairing_id)
    proof = b"heel.runner-rotation-activate.v2\0" + canonical_bytes({
        "pairing_id": rotation.pairing_id, "challenge": challenge,
    })
    signature = base64.b64encode(replacement.private_key.sign(proof)).decode()
    runner_auth.activate_rotation(rotation.pairing_id, signature)

    assert conn.execute(
        "SELECT status FROM canary_execution_grants WHERE grant_id=?",
        (approved["grant"]["grant_id"],),
    ).fetchone()[0] == "revoked"
    assert tuple(conn.execute(
        "SELECT status,quota_state FROM canary_runs WHERE run_id=?",
        (approved["run_id"],),
    ).fetchone()) == ("cancelled", "refunded")
    assert conn.execute(
        "SELECT COUNT(*) FROM usage_ledger WHERE reservation_id=? AND kind='refund'",
        (approved["reservation_id"],),
    ).fetchone()[0] == 1
    assert coordinator.claim(WORKSPACE, RUNNER, replacement.key_id) is None


def test_rotation_activation_rechecks_for_a_run_claimed_during_the_ceremony():
    from heel.crypto import SigningAuthority
    from heel.runner.identity import runner_phrase_words
    from heel.saas.runner_auth import RunnerAuthError, RunnerAuthStore

    conn = connect()
    runner = seed_authority(conn)
    coordinator, _, _approved = submit_and_approve(conn, Clock(), runner, idem_char="4")
    runner_auth = RunnerAuthStore(conn, pepper=b"r" * 32, now=Clock())
    conn.execute(
        "INSERT INTO canary_runner_chain_cursors VALUES(?,?,?,?,?,?)",
        (WORKSPACE, RUNNER, "claim", 1, 0, NOW),
    )
    conn.commit()
    replacement = SigningAuthority.generate()
    phrase = " ".join(runner_phrase_words()[:6])
    rotation = runner_auth.start_rotation(
        WORKSPACE, RUNNER,
        previous_fingerprint=hashlib.sha256(runner.public_key_bytes).hexdigest(),
        public_key_b64=replacement.canonical_public_key,
        phrase=phrase, runner_version="2.0.0", adapters={"http": "1.0.0"},
    )
    runner_auth.approve_rotation(
        WORKSPACE, rotation.pairing_id, phrase=phrase,
        fingerprint=rotation.fingerprint, actor="user_owner",
    )
    challenge = runner_auth.rotation_activation_challenge(rotation.pairing_id)
    proof = b"heel.runner-rotation-activate.v2\0" + canonical_bytes({
        "pairing_id": rotation.pairing_id, "challenge": challenge,
    })
    signature = base64.b64encode(replacement.private_key.sign(proof)).decode()

    # Simulate the competing old-key claim transaction committing after the
    # rotation start check and before activation acquires its own writer lock.
    conn.execute(
        "UPDATE canary_execution_grants SET status='claimed',claimed_at=? WHERE run_id=?",
        (NOW, _approved["run_id"]),
    )
    conn.execute(
        "UPDATE canary_runs SET status='claimed',claimed_at_ms=?,quota_state='consumed' WHERE run_id=?",
        (NOW_MS, _approved["run_id"]),
    )
    conn.commit()
    prior_keys = tuple(conn.execute(
        "SELECT key_id,status FROM canary_runner_keys WHERE workspace_id=? AND runner_id=? ORDER BY key_id",
        (WORKSPACE, RUNNER),
    ))
    prior_cursor = tuple(conn.execute(
        "SELECT next_sequence,generation FROM canary_runner_chain_cursors "
        "WHERE workspace_id=? AND runner_id=? AND chain_name='claim'",
        (WORKSPACE, RUNNER),
    ).fetchone())

    with pytest.raises(RunnerAuthError, match="runner rotation busy"):
        runner_auth.activate_rotation(rotation.pairing_id, signature)

    assert tuple(conn.execute(
        "SELECT key_id,status FROM canary_runner_keys WHERE workspace_id=? AND runner_id=? ORDER BY key_id",
        (WORKSPACE, RUNNER),
    )) == prior_keys
    assert tuple(conn.execute(
        "SELECT next_sequence,generation FROM canary_runner_chain_cursors "
        "WHERE workspace_id=? AND runner_id=? AND chain_name='claim'",
        (WORKSPACE, RUNNER),
    ).fetchone()) == prior_cursor
    assert conn.execute(
        "SELECT status FROM canary_runner_rotations WHERE pairing_id=?", (rotation.pairing_id,),
    ).fetchone()[0] == "rotation_approved"
