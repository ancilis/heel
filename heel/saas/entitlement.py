"""
Heel hosted — the single server-side entitlement authority (COMMERCIAL layer).

SPDX-License-Identifier: LicenseRef-Heel-Commercial

Every surface (UI, API, MCP, workers, billing) asks THIS service what a workspace may do. Answers are
computed from: the pinned catalog version + live subscription state + deployment configuration + the
usage ledger. Client claims and raw Stripe metadata are never authorization.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from .catalog import (
    CONFIG_GATED_FEATURES, CUSTOM, Feature, Meter, Plan, get_plan,
)
from .ledger import GlobalCapExceeded, QuotaExceeded, Reservation, UsageLedger


# Subscription states in which entitlements are ACTIVE (paid features usable).
# past_due keeps access during dunning grace; canceled/unpaid drop to free.
ACTIVE_STATES = {"trialing", "active", "past_due"}


@dataclass
class Subscription:
    workspace_id: str
    plan_id: str
    state: str            # trialing|active|past_due|canceled|unpaid|incomplete
    catalog_version: str


# Platform-wide per-period ceilings — the automatic circuit breaker bounding AGGREGATE
# liability (many small workspaces are still finite). Deployment-tunable via env.
GLOBAL_RUNS_CAP = 100_000
GLOBAL_VERIFIED_RUNS_CAP = 10_000


class EntitlementService:
    def __init__(self, ledger: UsageLedger, *, config_features: frozenset | None = None,
                 global_runs_cap: int | None = None,
                 global_verified_runs_cap: int | None = None):
        self.ledger = ledger
        # Which config-gated (enterprise) features this deployment has actually configured.
        # Anything not here is DISABLED even if the plan lists it (no dead checkboxes).
        self.config_features = config_features if config_features is not None else _config_from_env()
        env = os.environ
        self.global_runs_cap = (global_runs_cap if global_runs_cap is not None
                                else int(env.get("HEEL_GLOBAL_RUNS_CAP", GLOBAL_RUNS_CAP)))
        self.global_verified_runs_cap = (
            global_verified_runs_cap if global_verified_runs_cap is not None
            else int(env.get("HEEL_GLOBAL_VERIFIED_RUNS_CAP", GLOBAL_VERIFIED_RUNS_CAP)))

    def effective_plan(self, sub: Subscription) -> Plan:
        """The plan whose entitlements currently apply, resolved from the catalog version the
        subscription pinned at creation — a later catalog edit never silently changes a
        grandfathered subscription. Non-active subscriptions fall back to that version's free plan."""
        version = sub.catalog_version or None
        if sub.state in ACTIVE_STATES:
            return get_plan(sub.plan_id, version)
        return get_plan("free", version)

    def has_feature(self, sub: Subscription, feature: Feature) -> bool:
        plan = self.effective_plan(sub)
        if not plan.has(feature):
            return False
        if feature in CONFIG_GATED_FEATURES and feature not in self.config_features:
            return False  # listed on the plan but not configured in this deployment
        return True

    def feature_status(self, sub: Subscription, feature: Feature) -> str:
        """'enabled' | 'contact_sales' | 'unavailable' — drives honest UI, never a dead checkbox."""
        plan = self.effective_plan(sub)
        if self.has_feature(sub, feature):
            return "enabled"
        if feature in CONFIG_GATED_FEATURES:
            return "contact_sales"
        return "unavailable"

    def quota(self, sub: Subscription, meter: Meter) -> int:
        return self.effective_plan(sub).quota(meter)

    def remaining(self, sub: Subscription, meter: Meter, period: str) -> int | None:
        return self.ledger.remaining(self.effective_plan(sub), sub.workspace_id, meter, period)

    # --- the enqueue/execute quota choke points ---
    def reserve(self, sub: Subscription, meter: Meter, amount: int, period: str,
                *, idempotency_key: str | None = None, ref: str | None = None) -> Reservation:
        """Reserve metered value at ENQUEUE. Raises QuotaExceeded with an upgrade hint attached."""
        return self.ledger.reserve(self.effective_plan(sub), sub.workspace_id, meter, amount, period,
                                   idempotency_key=idempotency_key, ref=ref)

    def reserve_run(self, sub: Subscription, period: str, *, verified: bool,
                    idempotency_key: str | None = None, ref: str | None = None) -> list[Reservation]:
        """Reserve one rehearsal run. A verified-target run also draws down the VERIFIED_RUNS ceiling
        (the costly subset that bounds free-tier liability). Both reservations succeed or neither does:
        if the verified ceiling is exhausted, the RUNS reservation is refunded before raising."""
        runs_resv = self.ledger.reserve(self.effective_plan(sub), sub.workspace_id, Meter.RUNS,
                                        1, period, idempotency_key=idempotency_key, ref=ref,
                                        global_cap=self.global_runs_cap)
        if not verified:
            return [runs_resv]
        vk = f"{idempotency_key}:verified" if idempotency_key else None
        try:
            vr = self.ledger.reserve(self.effective_plan(sub), sub.workspace_id,
                                     Meter.VERIFIED_RUNS, 1, period, idempotency_key=vk,
                                     ref=ref, global_cap=self.global_verified_runs_cap)
        except (QuotaExceeded, GlobalCapExceeded):
            self.ledger.refund(runs_resv.reservation_id)
            raise
        return [runs_resv, vr]

    def can_run(self, sub: Subscription, period: str, amount: int = 1) -> bool:
        rem = self.remaining(sub, Meter.RUNS, period)
        return rem is None or rem >= amount

    def upgrade_target(self, sub: Subscription) -> str | None:
        """Next plan up to suggest when a limit is hit."""
        order = ["free", "pro", "team", "enterprise"]
        try:
            i = order.index(self.effective_plan(sub).id)
        except ValueError:
            return None
        return order[i + 1] if i + 1 < len(order) else None


def _config_from_env() -> frozenset:
    """Enterprise features are enabled only when the deployment sets HEEL_FEATURE_<NAME>=1."""
    enabled = set()
    for f in CONFIG_GATED_FEATURES:
        if os.environ.get(f"HEEL_FEATURE_{f.value.upper()}") == "1":
            enabled.add(f)
    return frozenset(enabled)
