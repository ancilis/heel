"""
HEEL — immutable containment log (spec §6, §10.2.8). Self-audit.

Every action HEEL takes against any target — and every REJECTED escalation attempt from a
caller — is recorded immutably with a per-entry HASH CHAIN (entry_hash = sha256(prev_hash +
canonical(entry))), so any tampering with the audit trail is detectable. Append-only.
"""
from __future__ import annotations

import json
import time

from . import scope as scopemod
from .contracts import ContainmentEntry

GENESIS = "0" * 64


def _entry_canonical(seq, ts, run_id, caller, action, detail, prev):
    return json.dumps({"seq": seq, "ts": round(ts, 6), "run_id": run_id, "caller": caller,
                       "action": action, "detail": detail, "prev": prev}, sort_keys=True, default=str)


class ContainmentLog:
    def __init__(self, store, run_id: str, caller: str):
        self.store = store
        self.run_id = run_id
        self.caller = caller
        last = store.last_containment()
        self.seq = (last["seq"] + 1) if last else 0
        self.prev_hash = last["entry_hash"] if last else GENESIS

    def append(self, action: str, detail: dict) -> ContainmentEntry:
        ts = time.time()
        e = ContainmentEntry(seq=self.seq, ts=ts, run_id=self.run_id, caller_identity=self.caller,
                             action=action, detail=detail, prev_hash=self.prev_hash)
        canonical = _entry_canonical(e.seq, ts, e.run_id, e.caller_identity, e.action, e.detail, e.prev_hash)
        # HMAC (not bare sha256): an attacker WITHOUT the key cannot rewrite + re-chain the log
        e.entry_hash = scopemod.hmac_sign(self.prev_hash + canonical)
        self.store.add_containment(e)
        self.seq += 1
        self.prev_hash = e.entry_hash
        return e

    def logger(self):
        """Returns a `log(action, detail)` callable for agents."""
        return lambda action, detail: self.append(action, detail)


def verify_chain(store, run_id: str | None = None) -> tuple[bool, str]:
    """Verifies linkage, HMAC authenticity (re-chaining needs the key), AND completeness:
    seq is contiguous over the GLOBAL log, defeating tail-truncation/whole-run deletion."""
    rows = store.containment_log()              # always verify the full log for completeness
    prev = None
    for i, r in enumerate(rows):
        if r["seq"] != i:
            return False, f"seq gap/truncation at index {i} (seq={r['seq']})"
        canonical = _entry_canonical(r["seq"], r["ts"], r["run_id"], r["caller"], r["action"],
                                     json.loads(r["detail"]), r["prev_hash"])
        if scopemod.hmac_sign(r["prev_hash"] + canonical) != r["entry_hash"]:
            return False, f"HMAC mismatch at seq {r['seq']} (tampered or re-chained without key)"
        if prev is not None and r["prev_hash"] != prev:
            return False, f"chain break at seq {r['seq']}"
        prev = r["entry_hash"]
    return True, f"{len(rows)} entries verified (linkage + HMAC + contiguity)"


def run_is_logged(store, run_id: str) -> bool:
    """A completed run MUST have a run_start and run_complete entry — a 'complete' run with no
    log entries is treated as unverified (defeats run-deletion to avoid attribution)."""
    actions = {r["action"] for r in store.containment_log(run_id)}
    return "run_start" in actions
