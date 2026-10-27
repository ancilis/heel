"""Read-only local run-reservation probe (C recovery, runtime phase R1).

``RunnerStore.probe_run_reservation`` answers whether a local reservation can exist for one run
without rolling any run-authority journal forward and without creating ``runs/``.  Only
``ABSENT`` may satisfy recovery eligibility L3; every error or malformed state must surface as a
non-``ABSENT`` value (CONTRACT-CLARIFICATION §2).
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil

import pytest

from heel.canary_contracts import canonical_bytes
from heel.crypto import SigningAuthority
import heel.runner.store as store_module
from heel.runner.store import RunnerStore, RunnerStoreError
from tests.test_runner_stop import (
    ExecutionBundle, LocalCanaryExecutor, RunnerRuntimeState, ScriptedTransport, StaticVault,
    _install_runtime_active_claim, active_gate, compiled_pair, signed_grant,
)


_OTHER_RUN_ID = "crun_" + "f" * 32


def _context_path(store: RunnerStore):
    return store.root / "runner" / "contexts" / store.namespace


def _tree(path):
    """(relative path, size, sha256) of every file, excluding the permitted lock bookkeeping file.

    File modes are deliberately not compared (``_read_json``/``_secure_directory`` re-assert 0600/0700),
    and neither are mtime or ctime.
    """
    if not path.exists():
        return None
    return sorted(
        (str(item.relative_to(path)), item.stat().st_size, hashlib.sha256(item.read_bytes()).hexdigest())
        for item in path.rglob("*")
        if item.is_file() and item.name != ".metadata.lock"
    )


def _probe(store, run_id):
    return store.probe_run_reservation(run_id)


def _crash_reserve_after_journal(store, grant, monkeypatch):
    def interrupted(*_args, **_kwargs):
        raise OSError("interrupted")

    with monkeypatch.context() as fault:
        fault.setattr(store, "_ensure_json_exact", interrupted)
        with pytest.raises(OSError, match="interrupted"):
            store.reserve_run(grant, retention_expires_at_ms=86_400_000)
    runs = _context_path(store) / "runs"
    assert (runs / store_module._RUN_AUTHORITY_JOURNAL_FILENAME).is_file()
    return runs


def _signed_reserve_journal_tampered(runs):
    journal_path = runs / store_module._RUN_AUTHORITY_JOURNAL_FILENAME
    journal = json.loads(journal_path.read_text())
    signature = journal["signature_b64"]
    journal["signature_b64"] = ("A" if signature[0] != "A" else "B") + signature[1:]
    journal_path.write_bytes(canonical_bytes(journal))


def test_probe_enum_is_closed_and_only_absent_equals_the_runtime_literal():
    probe = store_module.RunReservationProbe
    assert [member.name for member in probe] == ["ABSENT", "RESERVED", "JOURNAL_PENDING", "UNRESOLVED"]
    assert all(isinstance(member, str) for member in probe)
    assert [member for member in probe if member == "absent"] == [probe.ABSENT]


def test_probe_requires_runtime_authority_and_a_valid_run_id_without_touching_state(tmp_path):
    store, _identity, _signer, _manifest, _projection = compiled_pair(tmp_path)
    before = _tree(_context_path(store))

    with pytest.raises(RunnerStoreError, match="authenticated runner store is required"):
        RunnerStore(store.root).probe_run_reservation("crun_" + "a" * 32)
    # An invalid argument raises (the store's shared ``_id`` input check); it is never a probe value.
    with pytest.raises(ValueError, match="invalid run ID"):
        store.probe_run_reservation("not a run id")

    assert _tree(_context_path(store)) == before


def test_probe_is_absent_before_and_reserved_after_reserve_run_for_only_that_run(tmp_path):
    store, identity, _signer, manifest, projection = compiled_pair(tmp_path)
    grant = signed_grant(manifest, projection, identity, SigningAuthority.generate())
    probe = store_module.RunReservationProbe

    before = _tree(_context_path(store))
    assert _probe(store, grant["run_id"]) is probe.ABSENT
    assert _tree(_context_path(store)) == before

    store.reserve_run(grant, retention_expires_at_ms=86_400_000)
    reserved = _tree(_context_path(store))
    assert _probe(store, grant["run_id"]) is probe.RESERVED
    assert _probe(store, _OTHER_RUN_ID) is probe.ABSENT
    assert _tree(_context_path(store)) == reserved


def test_probe_is_absent_without_creating_a_missing_runs_directory(tmp_path):
    store, _identity, _signer, _manifest, _projection = compiled_pair(tmp_path)
    runs = _context_path(store) / "runs"
    shutil.rmtree(runs)
    before = _tree(_context_path(store))

    assert _probe(store, _OTHER_RUN_ID) is store_module.RunReservationProbe.ABSENT

    assert not runs.exists()
    assert _tree(_context_path(store)) == before


def test_probe_run_reservation_is_read_only_with_a_crashed_reserve_journal(tmp_path, monkeypatch):
    store, identity, _signer, manifest, projection = compiled_pair(tmp_path)
    grant = signed_grant(manifest, projection, identity, SigningAuthority.generate())
    runs = _crash_reserve_after_journal(store, grant, monkeypatch)
    run_hash = store._run_hash(grant["run_id"])
    reservation = runs / store._run_authority_record_filename("reserve", run_hash)
    journal_bytes = (runs / store_module._RUN_AUTHORITY_JOURNAL_FILENAME).read_bytes()
    assert not reservation.exists()
    before = _tree(_context_path(store))

    # Any pending journal blocks absence, for this run and for every other run: it is never
    # rolled forward by the probe and the reservation it would create does not appear.
    assert _probe(store, grant["run_id"]) is store_module.RunReservationProbe.JOURNAL_PENDING
    assert _probe(store, _OTHER_RUN_ID) is store_module.RunReservationProbe.JOURNAL_PENDING

    assert _tree(_context_path(store)) == before
    assert (runs / store_module._RUN_AUTHORITY_JOURNAL_FILENAME).read_bytes() == journal_bytes
    assert not reservation.exists()

    # The existing writer path still owns roll-forward; afterwards the run is reserved.
    store.recover_run_reservation(grant["run_id"])
    assert not (runs / store_module._RUN_AUTHORITY_JOURNAL_FILENAME).exists()
    assert _probe(store, grant["run_id"]) is store_module.RunReservationProbe.RESERVED


def test_probe_reports_a_valid_compaction_journal_as_pending_without_completing_it(tmp_path, monkeypatch):
    store, identity, signer, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)
    LocalCanaryExecutor(
        store=store, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 2_000,
        monotonic=lambda: 1.0,
    ).execute(
        ExecutionBundle(manifest, projection, grant),
        transport=ScriptedTransport([401, 200, 200, 403]), gate_source=active_gate,
    )
    runtime = RunnerRuntimeState(tmp_path / "runtime.sqlite3", identity, signer)
    _install_runtime_active_claim(runtime, identity, signer, projection, grant)
    local = runtime.register_local_terminal(**store._runtime_terminal_anchor(grant["run_id"]))
    store.detach_terminal(
        grant["run_id"], runtime=runtime,
        expected_local_state_digest=local.state_digest, now_ms=2_000,
    )
    pending = runtime.claim_due_prune(
        now_ms=store.load_run(grant["run_id"])["retention_expires_at_ms"],
    )[0]
    runs = store.run_path(grant["run_id"]).parent
    compaction = runs / store_module._RUN_AUTHORITY_COMPACTION_JOURNAL_FILENAME
    real_write_json = store_module._write_json

    def fail_after_prepare_journal(directory_fd, filename, value):
        if filename == store_module._RUN_AUTHORITY_CHECKPOINT_FILENAME and compaction.exists():
            raise OSError("compaction checkpoint publish interrupted")
        return real_write_json(directory_fd, filename, value)

    with monkeypatch.context() as fault:
        fault.setattr(store_module, "_write_json", fail_after_prepare_journal)
        with pytest.raises(OSError, match="compaction checkpoint publish interrupted"):
            store.prune_runtime_terminal(
                grant["run_id"], runtime=runtime,
                expected_runtime_state_digest=pending.state_digest,
                now_ms=pending.retention_expires_at_ms,
            )
    assert compaction.is_file()
    compaction_bytes = compaction.read_bytes()
    before = _tree(_context_path(store))

    assert _probe(store, grant["run_id"]) is store_module.RunReservationProbe.JOURNAL_PENDING
    assert _probe(store, _OTHER_RUN_ID) is store_module.RunReservationProbe.JOURNAL_PENDING

    assert _tree(_context_path(store)) == before
    assert compaction.read_bytes() == compaction_bytes


@pytest.mark.parametrize("damage", (
    "tampered-reserve-journal", "invalid-compaction-journal", "missing-index", "tampered-index",
    "symlinked-reservation", "malformed-reservation", "context-rollover-journal",
))
def test_probe_reports_unresolved_for_malformed_state_and_changes_nothing(tmp_path, monkeypatch, damage):
    store, identity, signer, manifest, projection = compiled_pair(tmp_path)
    grant = signed_grant(manifest, projection, identity, SigningAuthority.generate())
    runs = _context_path(store) / "runs"
    run_hash = store._run_hash(grant["run_id"])
    reservation = runs / store._run_authority_record_filename("reserve", run_hash)
    index = runs / store_module._RUN_AUTHORITY_INDEX_FILENAME
    if damage == "tampered-reserve-journal":
        _crash_reserve_after_journal(store, grant, monkeypatch)
        _signed_reserve_journal_tampered(runs)
    elif damage == "invalid-compaction-journal":
        (runs / store_module._RUN_AUTHORITY_COMPACTION_JOURNAL_FILENAME).write_bytes(
            canonical_bytes(store._signed_run_authority_value(
                {"schema_version": store_module._RUN_AUTHORITY_COMPACTION_JOURNAL_SCHEMA},
                signer=signer, record_digest=False,
            ))
        )
    elif damage == "missing-index":
        index.unlink()
    elif damage == "tampered-index":
        value = json.loads(index.read_text())
        value["generation"] += 1
        index.write_bytes(canonical_bytes(value))
    elif damage == "symlinked-reservation":
        target = tmp_path / "elsewhere.json"
        target.write_text("{}")
        os.symlink(target, reservation)
    elif damage == "malformed-reservation":
        reservation.write_bytes(b"{not json")
    else:
        (_context_path(store) / "context-rollover.json").write_bytes(b"{}")
    before = _tree(_context_path(store))
    before_link = os.readlink(reservation) if reservation.is_symlink() else None

    observed = _probe(store, grant["run_id"])

    assert observed is store_module.RunReservationProbe.UNRESOLVED
    assert observed != "absent"
    assert _tree(_context_path(store)) == before
    assert (os.readlink(reservation) if reservation.is_symlink() else None) == before_link


def _runtime_run_rows(runtime, run_hash):
    import sqlite3
    from contextlib import closing

    with closing(sqlite3.connect(runtime.path)) as conn:
        return {
            table: conn.execute(f"SELECT COUNT(*) FROM {table} WHERE run_hash=?", (run_hash,)).fetchone()[0]
            for table in ("active_runs", "control_chains", "pending_calls", "terminal_disclosures")
        }


def test_probe_reaches_absent_on_the_real_prune_path_only_after_the_runtime_dropped_the_active_group(
    tmp_path,
):
    """Real execute → terminal → detach → due-prune → Store prune → finish → compaction path.

    Pruning plus compaction deletes the reservation root, so the probe then reports ABSENT for a run
    that was reserved.  On this local path that is only reachable after the runtime removed the run's
    active group and chains in the same transaction that made the terminal ``prune_pending``
    (``_claim_due_prune``), and the Store refuses to prune before that state.  While a
    ``prune_pending``/``available`` terminal row survives, recovery eligibility L4 fails anyway.  A
    cloud claim response naming an already pruned run is outside this local proof.
    """
    store, identity, signer, manifest, projection = compiled_pair(tmp_path)
    authority = SigningAuthority.generate()
    grant = signed_grant(manifest, projection, identity, authority)
    run_id = grant["run_id"]
    run_hash = store._run_hash(run_id)
    probe = store_module.RunReservationProbe
    LocalCanaryExecutor(
        store=store, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id: authority.public_key},
        vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: 2_000,
        monotonic=lambda: 1.0,
    ).execute(
        ExecutionBundle(manifest, projection, grant),
        transport=ScriptedTransport([401, 200, 200, 403]), gate_source=active_gate,
    )
    runtime = RunnerRuntimeState(tmp_path / "runtime.sqlite3", identity, signer)
    _install_runtime_active_claim(runtime, identity, signer, projection, grant)
    group = {"active_runs": 1, "control_chains": 4, "pending_calls": 0}

    def observed():
        rows = _runtime_run_rows(runtime, run_hash)
        return _probe(store, run_id), {key: rows[key] for key in group}, rows["terminal_disclosures"]

    assert observed() == (probe.RESERVED, group, 0)
    local = runtime.register_local_terminal(**store._runtime_terminal_anchor(run_id))
    store.detach_terminal(
        run_id, runtime=runtime, expected_local_state_digest=local.state_digest, now_ms=2_000,
    )
    assert observed() == (probe.RESERVED, group, 1)

    # The Store cannot prune (and so cannot delete the reservation root) while the runtime still
    # holds the local terminal beside the live group.
    before = _tree(_context_path(store))
    with pytest.raises(RunnerStoreError, match="local terminal prune authority is unavailable"):
        store.prune_runtime_terminal(
            run_id, runtime=runtime, expected_runtime_state_digest=local.state_digest,
            now_ms=local.retention_expires_at_ms,
        )
    assert _tree(_context_path(store)) == before
    assert observed() == (probe.RESERVED, group, 1)

    pending = runtime.claim_due_prune(now_ms=store.load_run(run_id)["retention_expires_at_ms"])[0]
    assert pending.state == "prune_pending"
    no_group = {"active_runs": 0, "control_chains": 0, "pending_calls": 0}
    assert observed() == (probe.RESERVED, no_group, 1)
    assert runtime.load_active_run_controls() == ()

    receipt = store.prune_runtime_terminal(
        run_id, runtime=runtime, expected_runtime_state_digest=pending.state_digest,
        now_ms=pending.retention_expires_at_ms,
    )
    # First ABSENT: the root is gone, the runtime holds only the prune_pending terminal (L4 fails).
    assert observed() == (probe.ABSENT, no_group, 1)
    assert runtime.load_terminal_state(run_id).state == "prune_pending"

    completion = runtime.finish_prune(
        receipt=receipt, expected_prune_pending_state_digest=pending.state_digest,
    )
    store.finish_pruned_compaction(completion, runtime=runtime)
    assert observed() == (probe.ABSENT, no_group, 0)
    assert sorted(path.name for path in (_context_path(store) / "runs").iterdir()) == [
        "run-authority-checkpoint.json", "run-authority-index.json",
    ]
    # The signed compaction time floor still refuses to re-reserve the pruned grant.
    with pytest.raises(RunnerStoreError, match="execution grant has expired"):
        store.reserve_run(grant, retention_expires_at_ms=pending.retention_expires_at_ms + 1)
    assert observed() == (probe.ABSENT, no_group, 0)


def test_prune_refuses_a_run_whose_grant_outlives_its_retention_and_keeps_the_roots(tmp_path):
    """Pins the compaction ordering invariant ``grant_expires <= retention <= pruned_at``.

    TAMPERED, NON-COMPILER pair (labelled): the compiler always writes 86 400 s retention; here the
    manifest's retention is 60 s and the approval projection is re-signed with the runner's own signer
    and saved outside ``CanaryCompiler``.  The grant lives 600 s (the contract maximum).  The real
    execute → terminal → detach → due-prune → Store prune path then refuses compaction.  The run
    directory is already gone, but every authority root stays, so the probe stays RESERVED and neither
    a reservation nor an execution of that grant is possible again.
    """
    import copy
    import base64

    from heel.canary_contracts import canonical_digest, validate_approval_projection, validate_test_manifest

    store, identity, signer, compiled_manifest, compiled_projection = compiled_pair(tmp_path)
    tampered = copy.deepcopy(compiled_manifest)
    tampered.pop("manifest_digest")
    tampered["local_evidence_policy"]["retention_seconds"] = 60
    tampered["manifest_digest"] = canonical_digest(tampered)
    manifest = validate_test_manifest(tampered)
    unsigned = {
        key: copy.deepcopy(value) for key, value in compiled_projection.items()
        if key not in {"projection_digest", "signing_key_id", "signature_b64"}
    }
    unsigned["manifest_digest"] = manifest["manifest_digest"]
    unsigned["projection_id"] = f"projection_{manifest['manifest_digest'][:24]}"
    projection = validate_approval_projection({
        **unsigned, "projection_digest": canonical_digest(unsigned), "signing_key_id": identity.key_id,
        "signature_b64": base64.b64encode(signer.sign(canonical_bytes(unsigned))).decode("ascii"),
    })
    store.save_approved_pair(manifest, projection)
    authority = SigningAuthority.generate()
    trusted = {authority.key_id: authority.public_key}
    grant = signed_grant(manifest, projection, identity, authority, expires=601_000)
    run_id = grant["run_id"]
    run_hash = store._run_hash(run_id)
    runs = store.run_path(run_id).parent

    def executor(clock):
        return LocalCanaryExecutor(
            store=store, identity=identity, signer=signer, trusted_grant_keys=trusted,
            vaults={"ephemeral_env": StaticVault()}, clock_ms=lambda: clock, monotonic=lambda: 1.0,
        )

    first = ScriptedTransport([401, 200, 200, 403])
    executor(2_000).execute(ExecutionBundle(manifest, projection, grant), transport=first, gate_source=active_gate)
    assert len(first.calls) == 4
    runtime = RunnerRuntimeState(tmp_path / "runtime.sqlite3", identity, signer)
    _install_runtime_active_claim(runtime, identity, signer, projection, grant)
    local = runtime.register_local_terminal(**store._runtime_terminal_anchor(run_id))
    store.detach_terminal(run_id, runtime=runtime, expected_local_state_digest=local.state_digest, now_ms=2_000)
    retention = store.load_run(run_id)["retention_expires_at_ms"]
    assert grant["expires_at_ms"] > retention
    pending = runtime.claim_due_prune(now_ms=retention)[0]
    roots = {
        f"grant-{grant['grant_digest']}.json",
        store._run_authority_record_filename("reserve", run_hash),
        store._run_authority_record_filename("terminal", run_hash),
        store._run_authority_record_filename("detach_terminal", run_hash),
        "run-authority-checkpoint.json", "run-authority-index.json",
    }
    before = {path.name for path in runs.iterdir()}
    assert before == roots | {run_hash}

    with pytest.raises(RunnerStoreError, match="local run authority compaction entry is invalid"):
        store.prune_runtime_terminal(
            run_id, runtime=runtime, expected_runtime_state_digest=pending.state_digest, now_ms=retention,
        )

    after = {path.name for path in runs.iterdir()}
    # The run directory itself was removed before the refusal; every authority root was kept.
    assert run_hash not in after
    assert roots <= after
    assert after - roots == {store._run_authority_record_filename("prune", run_hash)}
    assert _probe(store, run_id) is store_module.RunReservationProbe.RESERVED
    with pytest.raises(ValueError, match="execution grant was already consumed"):
        store.reserve_run(grant, retention_expires_at_ms=retention + 60_000)
    again = ScriptedTransport([401, 200, 200, 403])
    with pytest.raises(ValueError, match="execution grant was already consumed"):
        executor(retention + 1_000).execute(
            ExecutionBundle(manifest, projection, grant), transport=again, gate_source=active_gate,
        )
    assert again.calls == []
    assert runtime.load_active_run_controls() == ()
    assert runtime.load_terminal_state(run_id).state == "prune_pending"
    assert {path.name for path in runs.iterdir()} == after
