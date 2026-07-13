"""
Arceo hosted — job plane: budgeted, leased, ledger-settled runs (COMMERCIAL layer).

SPDX-License-Identifier: LicenseRef-Arceo-Commercial

Lifecycle: enqueue (quota reserved atomically) → claim (worker lease) → complete/fail
(reservations consumed on completion, refunded on failure/expiry). Every job carries an immutable
RunBudget; workers enforce it and the reaper refunds jobs whose lease died. Verified-target jobs
additionally require, at enqueue time: a currently verified target, and a scope token minted by
the engine's human-only signed-scope path — this module never mints or bypasses scopes, it only
requires their presence via an injected validator.
"""
from __future__ import annotations

import json
import secrets
import sqlite3
import time
from dataclasses import asdict, dataclass
from typing import Callable

from .egress import EgressPolicy

DEFAULT_LEASE = 120           # seconds a worker holds a claim before the reaper may reclaim

_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs(
  job_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, kind TEXT NOT NULL,
  state TEXT NOT NULL, target TEXT, scope_ref TEXT, budget TEXT NOT NULL,
  reservations TEXT NOT NULL, created_at REAL, claimed_at REAL, lease_until REAL,
  worker_id TEXT, finished_at REAL, outcome TEXT);
CREATE INDEX IF NOT EXISTS idx_jobs_ws ON jobs(workspace_id);
CREATE INDEX IF NOT EXISTS idx_jobs_state ON jobs(state);
"""

STATES = ("queued", "running", "succeeded", "failed", "expired")


def _now() -> float:
    return time.time()


@dataclass(frozen=True)
class RunBudget:
    """Immutable per-run ceilings; the free-tier liability bound from PRODUCT.md #cost-model."""
    wall_clock_s: int = 60
    token_budget: int = 20_000
    egress_hosts: tuple = ()      # empty = no network at all (synthetic runs)

    def egress_policy(self) -> EgressPolicy:
        return EgressPolicy(self.egress_hosts)


@dataclass
class Job:
    job_id: str
    workspace_id: str
    kind: str          # 'synthetic' | 'verified'
    state: str
    target: str | None
    budget: RunBudget


class JobPlane:
    def __init__(self, conn: sqlite3.Connection, *,
                 scope_validator: Callable[[str, str, str], bool] | None = None):
        """scope_validator(workspace_id, scope_ref, target) -> bool. Injected from the engine's
        signed scope verifier by the deployment; absent means verified jobs cannot be enqueued at
        all (fail closed). The target is part of the check so a scope minted for one target can
        never authorize a different target, verified or not."""
        self.conn = conn
        self.conn.executescript(_SCHEMA)
        self.scope_validator = scope_validator

    # --- enqueue ---
    def enqueue(self, workspace_id: str, *, kind: str, reservation_ids: list,
                target: str | None = None, target_is_verified: bool = False,
                scope_ref: str | None = None, budget: RunBudget | None = None) -> Job:
        """Quota must already be reserved by the caller (EntitlementService.reserve_run) — the
        reservation ids are recorded so settlement is exact. Verified jobs fail closed unless the
        target is verified AND a valid human-minted scope reference is presented."""
        if kind not in ("synthetic", "verified"):
            raise ValueError("kind must be synthetic or verified")
        if not reservation_ids:
            raise ValueError("enqueue requires the ledger reservation ids")
        if kind == "synthetic":
            budget = budget or RunBudget()
            if budget.egress_hosts:
                raise PermissionError("synthetic runs get no network egress")
            target = None
        else:
            if not target or not target_is_verified:
                raise PermissionError("verified run requires a currently verified target")
            if self.scope_validator is None:
                raise PermissionError("no scope validator configured; verified runs disabled")
            if not scope_ref or not self.scope_validator(workspace_id, scope_ref, target):
                raise PermissionError(
                    "verified run requires a valid human-authorized scope for this exact target")
            budget = budget or RunBudget(egress_hosts=(target,))
            extra = set(budget.egress_hosts) - {target}
            if extra:
                raise PermissionError(f"egress beyond the verified target refused: {sorted(extra)}")
        jid = f"job_{secrets.token_hex(8)}"
        self.conn.execute(
            "INSERT INTO jobs(job_id,workspace_id,kind,state,target,scope_ref,budget,"
            "reservations,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (jid, workspace_id, kind, "queued", target, scope_ref,
             json.dumps(asdict(budget)), json.dumps(list(reservation_ids)), _now()))
        self.conn.commit()
        return Job(jid, workspace_id, kind, "queued", target, budget)

    # --- worker side ---
    def claim(self, worker_id: str, *, workspace_id: str | None = None,
              lease_s: int = DEFAULT_LEASE) -> Job | None:
        """Atomically claim the oldest queued job. Workers pinned to a tenant pass their
        workspace_id and can only ever claim that tenant's jobs; a None filter is for
        shared-pool deployments where isolation is per-run (sandbox + egress), not per-worker."""
        now = _now()
        where = "state='queued'"
        args: list = [worker_id, now, now + lease_s]
        if workspace_id is not None:
            where += " AND workspace_id=?"
            args.append(workspace_id)
        cur = self.conn.execute(
            "UPDATE jobs SET state='running', worker_id=?, claimed_at=?, lease_until=? "
            f"WHERE job_id=(SELECT job_id FROM jobs WHERE {where} "
            "ORDER BY created_at LIMIT 1) RETURNING *",
            args)
        row = cur.fetchone()
        self.conn.commit()
        return self._to_job(row) if row else None

    def heartbeat(self, job_id: str, worker_id: str, *, lease_s: int = DEFAULT_LEASE) -> bool:
        cur = self.conn.execute(
            "UPDATE jobs SET lease_until=? WHERE job_id=? AND worker_id=? AND state='running'",
            (_now() + lease_s, job_id, worker_id))
        self.conn.commit()
        return cur.rowcount == 1

    def _settle(self, job_id: str, worker_id: str | None, state: str, outcome: str,
                settle: Callable[[str], bool]) -> bool:
        q = "UPDATE jobs SET state=?, finished_at=?, outcome=? WHERE job_id=? AND state='running'"
        args = [state, _now(), outcome, job_id]
        if worker_id is not None:
            q += " AND worker_id=?"
            args.append(worker_id)
        cur = self.conn.execute(q, args)
        self.conn.commit()
        if cur.rowcount != 1:
            return False
        row = self.conn.execute("SELECT reservations FROM jobs WHERE job_id=?",
                                (job_id,)).fetchone()
        for rid in json.loads(row["reservations"] if isinstance(row, sqlite3.Row) else row[0]):
            settle(rid)
        return True

    def complete(self, job_id: str, worker_id: str, ledger, *, outcome: str = "ok") -> bool:
        """Consume the quota reservations — the run happened."""
        return self._settle(job_id, worker_id, "succeeded", outcome, ledger.consume)

    def fail(self, job_id: str, worker_id: str, ledger, *, outcome: str = "error") -> bool:
        """Refund — the customer does not pay quota for our failure."""
        return self._settle(job_id, worker_id, "failed", outcome, ledger.refund)

    # --- reaper ---
    def reap_expired(self, ledger) -> int:
        """Expire running jobs whose lease lapsed; refund their reservations."""
        rows = self.conn.execute(
            "SELECT job_id FROM jobs WHERE state='running' AND lease_until < ?",
            (_now(),)).fetchall()
        n = 0
        for r in rows:
            if self._settle(r["job_id"] if isinstance(r, sqlite3.Row) else r[0], None,
                            "expired", "lease_expired", ledger.refund):
                n += 1
        return n

    # --- queries ---
    def get(self, workspace_id: str, job_id: str) -> Job | None:
        row = self.conn.execute(
            "SELECT * FROM jobs WHERE job_id=? AND workspace_id=?",
            (job_id, workspace_id)).fetchone()
        return self._to_job(row) if row else None

    def _to_job(self, row) -> Job:
        b = json.loads(row["budget"])
        b["egress_hosts"] = tuple(b.get("egress_hosts") or ())
        return Job(row["job_id"], row["workspace_id"], row["kind"], row["state"],
                   row["target"], RunBudget(**b))
