"""First-class Arceo operating modes and their safety constraints."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ArceoMode:
    id: str
    requires_scope: bool
    allows_live_probe: bool
    requires_canary_accounts: bool
    default_rate_limits: dict[str, Any]
    allowed_target_sources: list[str]
    output_emphasis: str
    allows_scope_mutation: bool = False
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "requires_scope": self.requires_scope,
            "allows_live_probe": self.allows_live_probe,
            "requires_canary_accounts": self.requires_canary_accounts,
            "default_rate_limits": dict(self.default_rate_limits),
            "allowed_target_sources": list(self.allowed_target_sources),
            "output_emphasis": self.output_emphasis,
            "allows_scope_mutation": self.allows_scope_mutation,
            "description": self.description,
        }


MODES: dict[str, ArceoMode] = {
    "synthetic": ArceoMode(
        id="synthetic",
        requires_scope=True,
        allows_live_probe=False,
        requires_canary_accounts=False,
        default_rate_limits={"max_requests": 200, "max_concurrency": 8, "backoff": True},
        allowed_target_sources=["built-in synthetic target"],
        output_emphasis="synthetic self-consistency backtest; no external product data",
        description="Current built-in synthetic targets with no external product data.",
    ),
    "launch-review": ArceoMode(
        id="launch-review",
        requires_scope=False,
        allows_live_probe=False,
        requires_canary_accounts=False,
        default_rate_limits={"max_requests": 0, "max_concurrency": 0, "backoff": True},
        allowed_target_sources=["before/after ProductModels"],
        output_emphasis="static ProductModel diff; no live probing by default",
        description="Compare before/after ProductModels before launch.",
    ),
    "staging": ArceoMode(
        id="staging",
        requires_scope=True,
        allows_live_probe=False,
        requires_canary_accounts=True,
        default_rate_limits={"max_requests": 20, "max_concurrency": 2, "backoff": True},
        allowed_target_sources=["staging ProductModel", "canary staging target"],
        output_emphasis="canary-only staging rehearsal with stricter signed-scope limits",
        description="Scoped, canary-only staging rehearsal with tighter resource limits.",
    ),
    "existing-imported": ArceoMode(
        id="existing-imported",
        requires_scope=True,
        allows_live_probe=False,
        requires_canary_accounts=False,
        default_rate_limits={"max_requests": 80, "max_concurrency": 4, "backoff": True},
        allowed_target_sources=["ProductModel", "EntitlementGraph"],
        output_emphasis="mature products via imported ProductModel/EntitlementGraph; no live probing",
        description="Model-only rehearsal for existing mature products.",
    ),
    "incident-regression": ArceoMode(
        id="incident-regression",
        requires_scope=True,
        allows_live_probe=False,
        requires_canary_accounts=True,
        default_rate_limits={"max_requests": 50, "max_concurrency": 3, "backoff": True},
        allowed_target_sources=["stored abuse regressions", "sanitized incidents", "stored findings"],
        output_emphasis="canary-only rerun of stored incident/finding regressions",
        description="Run stored regressions created from sanitized incidents or findings.",
    ),
}


def get_mode(mode_id: str | None) -> ArceoMode:
    key = mode_id or "synthetic"
    try:
        return MODES[key]
    except KeyError as exc:
        allowed = ", ".join(sorted(MODES))
        raise ValueError(f"unknown mode '{key}'; allowed modes: {allowed}") from exc


def describe_mode(mode_id: str | None) -> dict[str, Any]:
    return get_mode(mode_id).to_dict()


def scope_limit_errors(mode: ArceoMode, limits: dict[str, Any] | None) -> list[str]:
    """Return signed-scope limit violations for modes with stricter defaults."""
    limits = limits or {}
    errors: list[str] = []
    for key in ("max_requests", "max_concurrency"):
        expected = mode.default_rate_limits.get(key)
        actual = limits.get(key)
        if isinstance(expected, int):
            if not isinstance(actual, int) or actual > expected:
                errors.append(f"{key}<={expected}")
    if mode.default_rate_limits.get("backoff") is True and limits.get("backoff") is not True:
        errors.append("backoff=true")
    return errors
