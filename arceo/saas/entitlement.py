"""
Arceo hosted — the single server-side entitlement authority (COMMERCIAL layer).

SPDX-License-Identifier: LicenseRef-Arceo-Commercial

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
from .ledger import QuotaExceeded, Reservation, UsageLedger


# Subscription states in which entitlements are ACTIVE (paid features usable).
# past_due keeps access during dunning grace; canceled/unpaid drop to free.
ACTIVE_STATES = {"trialing", "active", "past_due"}


@dataclass
class Subscription:
    workspace_id: str
    plan_id: str
    state: str            # trialing|active|past_due|canceled|unpaid|incomplete
    catalog_version: str


class EntitlementService:
    def __init__(self, ledger: UsageLedger, *, config_features: frozenset | None = None):
        self.ledger = ledger
        # Which config-gated (enterprise) features this deployment has actually configured.
        # Anything not here is DISABLED even if the plan lists it (no dead checkboxes).
        self.config_features = config_features if config_features is not None else _config_from_env()

    def effective_plan(self, sub: Subscription) -> Plan:
        """The plan whose entitlements currently apply. Non-active subscriptions fall back to free."""
        if sub.state in ACTIVE_STATES:
            return get_plan(sub.plan_id)
        return get_plan("free")

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
    """Enterprise features are enabled only when the deployment sets ARCEO_FEATURE_<NAME>=1."""
    enabled = set()
    for f in CONFIG_GATED_FEATURES:
        if os.environ.get(f"ARCEO_FEATURE_{f.value.upper()}") == "1":
            enabled.add(f)
    return frozenset(enabled)
