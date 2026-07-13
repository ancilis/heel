"""
Arceo hosted — typed, versioned product catalog (COMMERCIAL layer).

SPDX-License-Identifier: LicenseRef-Arceo-Commercial

THE source of truth for plans, prices, quotas, and entitlements. No production Stripe Product/Price
IDs live here — those are injected per-environment (see `price_env_var`). The entitlement service
(`entitlement.py`) computes what a workspace may do purely from a pinned catalog version + live
subscription state; client claims and raw billing metadata are never authorization.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Mapping


CATALOG_VERSION = "2026-07-13"


class Meter(str, Enum):
    """The costly, durable units we meter. NOT UI decoration."""
    RUNS = "runs"                       # rehearsal run credits / month
    VERIFIED_TARGETS = "verified_targets"
    CONCURRENCY = "concurrency"         # parallel workers
    RETENTION_DAYS = "retention_days"
    SEATS = "seats"
    INTEGRATIONS = "integrations"       # CI/API/MCP connectors


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
        return f"ARCEO_STRIPE_PRICE_{self.id.upper()}"


def _q(**kw) -> dict:
    return {Meter[k.upper()]: v for k, v in kw.items()}


# --------------------------------------------------------------------------- #
# The catalog. Editing quotas/prices here is the ONLY place they change.
# --------------------------------------------------------------------------- #
_PLANS = {
    "free": Plan(
        id="free", name="Free", price_month_cents=0, price_year_cents=0, no_card=True,
        support="community",
        quotas=_q(runs=25, verified_targets=1, concurrency=1, retention_days=7, seats=1, integrations=0),
        # 25 = 20 synthetic + 5 verified (enforced separately by run kind; see PRICING doc).
        features=frozenset(),
    ),
    "pro": Plan(
        id="pro", name="Pro", price_month_cents=4900, price_year_cents=49000, support="email",
        quotas=_q(runs=300, verified_targets=5, concurrency=3, retention_days=30, seats=3, integrations=3),
        features=frozenset({Feature.API, Feature.MCP, Feature.EXPORTS, Feature.SCHEDULED_REGRESSIONS}),
    ),
    "team": Plan(
        id="team", name="Team", price_month_cents=19900, price_year_cents=199000, support="priority",
        quotas=_q(runs=1500, verified_targets=25, concurrency=8, retention_days=90, seats=10, integrations=10),
        features=frozenset({
            Feature.API, Feature.MCP, Feature.EXPORTS, Feature.SCHEDULED_REGRESSIONS,
            Feature.RBAC, Feature.AUDIT_EXPORT,
        }),
    ),
    "enterprise": Plan(
        id="enterprise", name="Enterprise", price_month_cents=CUSTOM, price_year_cents=CUSTOM,
        contact_sales=True, support="sla",
        quotas=_q(runs=CUSTOM, verified_targets=CUSTOM, concurrency=CUSTOM, retention_days=CUSTOM,
                  seats=CUSTOM, integrations=CUSTOM),
        # Enterprise-only features default present in the plan but are gated ON only when the
        # deployment actually configures them (entitlement.py checks configuration, not the flag).
        features=frozenset({
            Feature.API, Feature.MCP, Feature.EXPORTS, Feature.SCHEDULED_REGRESSIONS,
            Feature.RBAC, Feature.AUDIT_EXPORT, Feature.SSO, Feature.SCIM,
            Feature.DATA_REGION, Feature.PRIVATE_RUNNERS,
        }),
    ),
}

# Free-tier split: synthetic vs verified-target runs (verified runs are the costly ones).
FREE_SYNTHETIC_RUNS = 20
FREE_VERIFIED_RUNS = 5

# Enterprise capabilities that require deployment configuration before they do anything.
# Until configured they are DISABLED and surfaced through contact-sales (no dead checkboxes).
CONFIG_GATED_FEATURES = frozenset({Feature.SSO, Feature.SCIM, Feature.DATA_REGION, Feature.PRIVATE_RUNNERS})


def get_plan(plan_id: str) -> Plan:
    try:
        return _PLANS[plan_id]
    except KeyError:
        raise KeyError(f"unknown plan {plan_id!r}; known: {sorted(_PLANS)}")


def all_plans() -> list[Plan]:
    return [_PLANS[k] for k in ("free", "pro", "team", "enterprise")]


def self_serve_plans() -> list[Plan]:
    return [p for p in all_plans() if not p.contact_sales]
