"""
HEEL — immutable containment log (spec §6, §10.2.8). Self-audit.

Every action HEEL takes against any target — and every REJECTED escalation attempt from a
caller — is recorded immutably with a per-entry HASH CHAIN (entry_hash = sha256(prev_hash +
canonical(entry))), so any tampering with the audit trail is detectable. Append-only.
"""
from __future__ import annotations

import hashlib
import json
import time

from .contracts import ContainmentEntry

GENESIS = "0" * 64


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
        canonical = json.dumps({"seq": e.seq, "ts": round(ts, 6), "run_id": e.run_id,
                                "caller": e.caller_identity, "action": e.action,
                                "detail": e.detail, "prev": e.prev_hash}, sort_keys=True, default=str)
        e.entry_hash = hashlib.sha256((self.prev_hash + canonical).encode()).hexdigest()
        self.store.add_containment(e)
        self.seq += 1
        self.prev_hash = e.entry_hash
        return e

    def logger(self):
        """Returns a `log(action, detail)` callable for agents."""
        return lambda action, detail: self.append(action, detail)


def verify_chain(store, run_id: str | None = None) -> tuple[bool, str]:
    rows = store.containment_log(run_id)
    prev = None
    for r in rows:
        canonical = json.dumps({"seq": r["seq"], "ts": round(r["ts"], 6), "run_id": r["run_id"],
                                "caller": r["caller"], "action": r["action"],
                                "detail": json.loads(r["detail"]), "prev": r["prev_hash"]},
                               sort_keys=True, default=str)
        expected = hashlib.sha256((r["prev_hash"] + canonical).encode()).hexdigest()
        if expected != r["entry_hash"]:
            return False, f"hash mismatch at seq {r['seq']}"
        if prev is not None and r["prev_hash"] != prev:
            return False, f"chain break at seq {r['seq']}"
        prev = r["entry_hash"]
    return True, f"{len(rows)} entries verified"
