"""
Heel hosted — billing state machine + webhook safety + Stripe/Stub adapters (COMMERCIAL layer).

SPDX-License-Identifier: LicenseRef-Heel-Commercial

The subscription STATE lives in our store, driven by verified webhook events. Entitlements read that
state (never raw Stripe metadata or client claims). Webhooks are safe against duplicate, delayed,
missing, replayed, and out-of-order delivery via an event-dedupe table + monotonic version guard.

No production Product/Price IDs or secrets are in this file. The live Stripe adapter reads them from
env per environment; `StubBilling` drives the full lifecycle offline for tests/CI.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import time
from dataclasses import dataclass

from .catalog import CATALOG_VERSION, Plan, get_plan


_SCHEMA = """
CREATE TABLE IF NOT EXISTS subscriptions(
  workspace_id TEXT PRIMARY KEY,
  provider_customer_id TEXT, provider_subscription_id TEXT,
  plan_id TEXT NOT NULL, state TEXT NOT NULL, catalog_version TEXT NOT NULL,
  interval TEXT, version INTEGER NOT NULL DEFAULT 0,
  current_period_end REAL, cancel_at_period_end INTEGER DEFAULT 0, updated_at REAL);
CREATE TABLE IF NOT EXISTS billing_events(
  event_id TEXT PRIMARY KEY, type TEXT, received_at REAL, applied INTEGER DEFAULT 0);
"""

# Legal state transitions. Guards against nonsense jumps from replayed/out-of-order events.
_ALLOWED = {
    "incomplete": {"trialing", "active", "canceled", "unpaid"},
    "trialing":   {"active", "past_due", "canceled", "unpaid"},
    "active":     {"active", "past_due", "canceled", "unpaid"},
    "past_due":   {"active", "canceled", "unpaid"},
    "unpaid":     {"active", "canceled"},
    "canceled":   {"active"},  # resubscribe
}


def _now() -> float:
    return time.time()


class WebhookVerificationError(Exception):
    pass


def verify_webhook_signature(payload: bytes, header: str, secret: str, *, tolerance: int = 300,
                             now: float | None = None) -> None:
    """Stripe-style HMAC signature check: header 't=<ts>,v1=<sig>'. Constant-time compare + replay
    window. Raises WebhookVerificationError on any mismatch."""
    if not secret:
        raise WebhookVerificationError("no webhook secret configured")
    parts = dict(p.split("=", 1) for p in header.split(",") if "=" in p)
    ts, sig = parts.get("t"), parts.get("v1")
    if not ts or not sig:
        raise WebhookVerificationError("malformed signature header")
    signed = f"{ts}.".encode() + payload
    expected = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        raise WebhookVerificationError("signature mismatch")
    cur = now if now is not None else _now()
    if abs(cur - int(ts)) > tolerance:
        raise WebhookVerificationError("timestamp outside tolerance (replay)")


@dataclass
class SubState:
    workspace_id: str
    plan_id: str
    state: str
    catalog_version: str
    version: int
    cancel_at_period_end: bool = False


class BillingStore:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.conn.executescript(_SCHEMA)

    @classmethod
    def in_memory(cls) -> "BillingStore":
        c = sqlite3.connect(":memory:", check_same_thread=False)
        c.row_factory = sqlite3.Row
        return cls(c)

    def get(self, workspace_id: str) -> SubState | None:
        r = self.conn.execute("SELECT * FROM subscriptions WHERE workspace_id=?",
                              (workspace_id,)).fetchone()
        if not r:
            return None
        return SubState(r["workspace_id"], r["plan_id"], r["state"], r["catalog_version"],
                        r["version"], bool(r["cancel_at_period_end"]))

    def upsert(self, s: SubState, *, interval: str | None = None,
               current_period_end: float | None = None,
               provider_customer_id: str | None = None,
               provider_subscription_id: str | None = None) -> None:
        self.conn.execute(
            """INSERT INTO subscriptions
               (workspace_id, provider_customer_id, provider_subscription_id, plan_id, state,
                catalog_version, interval, version, current_period_end, cancel_at_period_end, updated_at)
               VALUES(?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(workspace_id) DO UPDATE SET
                 provider_customer_id=COALESCE(excluded.provider_customer_id, provider_customer_id),
                 provider_subscription_id=COALESCE(excluded.provider_subscription_id, provider_subscription_id),
                 plan_id=excluded.plan_id, state=excluded.state, catalog_version=excluded.catalog_version,
                 interval=COALESCE(excluded.interval, interval),
                 version=excluded.version,
                 current_period_end=COALESCE(excluded.current_period_end, current_period_end),
                 cancel_at_period_end=excluded.cancel_at_period_end, updated_at=excluded.updated_at""",
            (s.workspace_id, provider_customer_id, provider_subscription_id, s.plan_id, s.state,
             s.catalog_version, interval, s.version, current_period_end,
             int(s.cancel_at_period_end), _now()))
        self.conn.commit()

    def seen_event(self, event_id: str) -> bool:
        return self.conn.execute("SELECT 1 FROM billing_events WHERE event_id=?",
                                (event_id,)).fetchone() is not None

    def record_event(self, event_id: str, type_: str, applied: bool) -> None:
        self.conn.execute("INSERT OR IGNORE INTO billing_events VALUES(?,?,?,?)",
                          (event_id, type_, _now(), int(applied)))
        self.conn.commit()


class SubscriptionManager:
    """Applies verified billing events to subscription state with idempotency + ordering guards."""

    def __init__(self, store: BillingStore):
        self.store = store

    def apply_event(self, event: dict) -> str:
        """event = {id, type, workspace_id, state, plan_id, version, ...}. Returns disposition:
        'applied' | 'duplicate' | 'stale' | 'illegal'. Duplicate/stale/illegal are safe no-ops."""
        eid = event["id"]
        if self.store.seen_event(eid):
            return "duplicate"
        wid = event["workspace_id"]
        new_state = event["state"]
        new_plan = event.get("plan_id")
        new_version = int(event.get("version", 0))
        cur = self.store.get(wid)

        if cur is not None:
            if new_version <= cur.version:
                self.store.record_event(eid, event["type"], applied=False)
                return "stale"  # out-of-order / replayed older event
            if new_state != cur.state and new_state not in _ALLOWED.get(cur.state, set()):
                self.store.record_event(eid, event["type"], applied=False)
                return "illegal"

        plan_id = new_plan or (cur.plan_id if cur else "free")
        get_plan(plan_id)  # validate the plan id exists
        catalog_version = (event.get("catalog_version")
                           or (cur.catalog_version if cur else CATALOG_VERSION))
        s = SubState(wid, plan_id, new_state, catalog_version, new_version,
                     bool(event.get("cancel_at_period_end", cur.cancel_at_period_end if cur else False)))
        self.store.upsert(s, interval=event.get("interval"),
                          current_period_end=event.get("current_period_end"),
                          provider_customer_id=event.get("provider_customer_id"),
                          provider_subscription_id=event.get("provider_subscription_id"))
        self.store.record_event(eid, event["type"], applied=True)
        return "applied"


# --------------------------------------------------------------------------- #
# Provider adapters
# --------------------------------------------------------------------------- #
class Billing:
    """Interface. Live Stripe impl reads keys/price-ids from env; StubBilling runs offline."""
    def price_id(self, plan: Plan, interval: str) -> str:
        raise NotImplementedError

    def create_checkout(self, workspace_id: str, plan: Plan, interval: str) -> dict:
        raise NotImplementedError


class BillingUnavailable(RuntimeError):
    """Paid checkout is deliberately unavailable in this deployment."""


class DisabledBilling(Billing):
    """Fail-closed production adapter for a free-launch deployment.

    This is intentionally distinct from ``StubBilling``: a production process must never hand a
    customer a synthetic checkout URL or imply that payment was accepted.
    """

    def price_id(self, plan: Plan, interval: str) -> str:
        raise BillingUnavailable("paid checkout is not configured")

    def create_checkout(self, workspace_id: str, plan: Plan, interval: str) -> dict:
        raise BillingUnavailable("paid checkout is not configured")


class StubBilling(Billing):
    """Deterministic offline billing for local/CI. Emits the same event shape a real provider would,
    so the full lifecycle (checkout→active→past_due→canceled, upgrade/downgrade) is testable."""

    def __init__(self):
        self._version = {}

    def price_id(self, plan: Plan, interval: str) -> str:
        # Never a production id — a synthetic, clearly-fake local id.
        return f"price_stub_{plan.id}_{interval}"

    def create_checkout(self, workspace_id: str, plan: Plan, interval: str) -> dict:
        return {"url": f"https://stub.local/checkout/{workspace_id}/{plan.id}/{interval}",
                "price_id": self.price_id(plan, interval)}

    def next_version(self, workspace_id: str) -> int:
        v = self._version.get(workspace_id, 0) + 1
        self._version[workspace_id] = v
        return v

    def event(self, workspace_id: str, type_: str, state: str, plan_id: str, **extra) -> dict:
        return {"id": f"evt_stub_{workspace_id}_{self.next_version(workspace_id)}",
                "type": type_, "workspace_id": workspace_id, "state": state,
                "plan_id": plan_id, "version": self._version[workspace_id], **extra}


def live_price_id(plan: Plan, interval: str) -> str:
    """Read the Stripe Price ID for a plan/interval from env. Raises if unset — we never guess or
    hard-code a production id."""
    key = f"{plan.price_env_var}_{interval.upper()}"
    val = os.environ.get(key)
    if not val:
        raise KeyError(f"missing Stripe price id env {key} (owner action; see OWNER_ACTIONS.md)")
    return val
