"""
Heel hosted — typed, versioned product catalog (COMMERCIAL layer).

SPDX-License-Identifier: LicenseRef-Heel-Commercial

THE source of truth for plans, prices, quotas, and entitlements. No production Stripe Product/Price
IDs live here — those are injected per-environment (see `price_env_var`). The entitlement service
(`entitlement.py`) computes what a workspace may do purely from a pinned catalog version + live
subscription state; client claims and raw billing metadata are never authorization.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Mapping


CATALOG_VERSION = "2026-08-04"
LEGACY_CATALOG_VERSION = "2026-07-13"


class Meter(str, Enum):
    """The costly, durable units we meter. NOT UI decoration."""
    RUNS = "runs"                       # total rehearsal run credits / month (synthetic + verified)
    VERIFIED_RUNS = "verified_runs"     # subset ceiling: costly runs against a verified real target
    VERIFIED_TARGETS = "verified_targets"
    CONCURRENCY = "concurrency"         # parallel workers
    RETENTION_DAYS = "retention_days"
    SEATS = "seats"
    INTEGRATIONS = "integrations"       # CI/API/MCP connectors
    SYNCED_REVIEWS = "synced_reviews"   # new substantive findings projections / month


class Feature(str, Enum):
    """Boolean capabilities. Enterprise ones default OFF and are surfaced via contact-sales."""
    API = "api"
    MCP = "mcp"
    EXPORTS = "exports"
    SCHEDULED_REGRESSIONS = "scheduled_regressions"
    RBAC = "rbac"
    AUDIT_EXPORT = "audit_export"
    SSO = "sso"
    SCIM = "scim"
    DATA_REGION = "data_region"
    PRIVATE_RUNNERS = "private_runners"


# A sentinel meaning "no fixed ceiling in the catalog" (custom/enterprise-negotiated).
CUSTOM = -1


@dataclass(frozen=True)
class Plan:
    id: str
    name: str
    price_month_cents: int          # 0 = free; CUSTOM = contact-sales
    price_year_cents: int
    quotas: Mapping[Meter, int]     # per-month / point-in-time ceilings
    features: frozenset             # enabled Feature set
    no_card: bool = False
    contact_sales: bool = False
    support: str = "community"

    def quota(self, meter: Meter) -> int:
        return self.quotas.get(meter, 0)

    def has(self, feature: Feature) -> bool:
        return feature in self.features

    @property
    def price_env_var(self) -> str:
        """Env var name that must carry the Stripe Price ID for this plan in a given environment.
        Kept OUT of code so no production price/ID is ever hard-coded."""
        return f"HEEL_STRIPE_PRICE_{self.id.upper()}"


def _q(**kw) -> dict:
    return {Meter[k.upper()]: v for k, v in kw.items()}


# --------------------------------------------------------------------------- #
# The catalog. Editing quotas/prices here is the ONLY place they change.
# --------------------------------------------------------------------------- #
_PLANS = {
    "free": Plan(
        id="free", name="Free", price_month_cents=0, price_year_cents=0, no_card=True,
        support="community",
        quotas=_q(runs=25, verified_runs=5, verified_targets=1, concurrency=1,
                  retention_days=7, seats=1, integrations=0, synced_reviews=3),
        # 25 total run credits; at most 5 of them may be verified-target runs (the VERIFIED_RUNS
        # subset ceiling, enforced in reserve_run). Synthetic runs may consume all 25.
        features=frozenset(),
    ),
    "pro": Plan(
        id="pro", name="Pro", price_month_cents=4900, price_year_cents=49000, support="email",
        quotas=_q(runs=300, verified_runs=100, verified_targets=5, concurrency=3,
                  retention_days=30, seats=3, integrations=3, synced_reviews=25),
        features=frozenset({Feature.API, Feature.MCP, Feature.EXPORTS, Feature.SCHEDULED_REGRESSIONS}),
    ),
    "team": Plan(
        id="team", name="Team", price_month_cents=19900, price_year_cents=199000, support="priority",
        quotas=_q(runs=1500, verified_runs=500, verified_targets=25, concurrency=8,
                  retention_days=90, seats=10, integrations=10, synced_reviews=100),
        features=frozenset({
            Feature.API, Feature.MCP, Feature.EXPORTS, Feature.SCHEDULED_REGRESSIONS,
            Feature.RBAC, Feature.AUDIT_EXPORT,
        }),
    ),
    "enterprise": Plan(
        id="enterprise", name="Enterprise", price_month_cents=CUSTOM, price_year_cents=CUSTOM,
        contact_sales=True, support="sla",
        quotas=_q(runs=CUSTOM, verified_runs=CUSTOM, verified_targets=CUSTOM,
                  concurrency=CUSTOM, retention_days=CUSTOM, seats=CUSTOM,
                  integrations=CUSTOM, synced_reviews=CUSTOM),
        # Enterprise-only features default present in the plan but are gated ON only when the
        # deployment actually configures them (entitlement.py checks configuration, not the flag).
        features=frozenset({
            Feature.API, Feature.MCP, Feature.EXPORTS, Feature.SCHEDULED_REGRESSIONS,
            Feature.RBAC, Feature.AUDIT_EXPORT, Feature.SSO, Feature.SCIM,
            Feature.DATA_REGION, Feature.PRIVATE_RUNNERS,
        }),
    ),
}

# Free-tier verified ceiling (the costly, liability-bearing run kind). The total pool is
# Meter.RUNS on the free plan; synthetic runs (~$0 marginal) may consume all of it.
FREE_VERIFIED_RUNS = 5

# Enterprise capabilities that require deployment configuration before they do anything.
# Until configured they are DISABLED and surfaced through contact-sales (no dead checkboxes).
CONFIG_GATED_FEATURES = frozenset({Feature.SSO, Feature.SCIM, Feature.DATA_REGION, Feature.PRIVATE_RUNNERS})


# Versioned catalog history. The prior catalog predates hosted findings continuity, so its plans
# deliberately resolve the new meter to Plan.quota's zero default. A subscription pins the version
# it was created on; current quota changes never silently alter that grandfathered subscription.
_LEGACY_PLANS = {
    plan_id: replace(
        plan,
        quotas={
            meter: quota
            for meter, quota in plan.quotas.items()
            if meter is not Meter.SYNCED_REVIEWS
        },
    )
    for plan_id, plan in _PLANS.items()
}
_CATALOGS: dict[str, dict] = {
    LEGACY_CATALOG_VERSION: _LEGACY_PLANS,
    CATALOG_VERSION: _PLANS,
}


def get_plan(plan_id: str, catalog_version: str | None = None) -> Plan:
    plans = _PLANS if catalog_version is None else _catalog(catalog_version)
    try:
        return plans[plan_id]
    except KeyError:
        raise KeyError(f"unknown plan {plan_id!r}; known: {sorted(plans)}")


def _catalog(version: str) -> dict:
    try:
        return _CATALOGS[version]
    except KeyError:
        raise KeyError(f"unknown catalog version {version!r}; known: {sorted(_CATALOGS)}")


def all_plans() -> list[Plan]:
    return [_PLANS[k] for k in ("free", "pro", "team", "enterprise")]


def self_serve_plans() -> list[Plan]:
    return [p for p in all_plans() if not p.contact_sales]
