"""
HEEL — Frozen data contracts (spec §6).

These are the versioned interfaces every squad integrates against. Changing a field
after Phase 1 requires an explicit migration + version bump. All modules import their
shapes from HERE.

Design notes
------------
* Pure stdlib dataclasses (DECISIONS D-001: single-language pure-stdlib core for
  zero-install one-command bring-up + end-to-end testability).
* The safety-critical contract is `AuthorizationScope`: it is created OUT-OF-BAND by a
  human only, is signed, and is immutable from the MCP/agent side. The MCP tool schema
  (`mcp_server.TOOL_SCHEMAS`) contains NO scope-mutation tool by construction (spec §10.1).
* Every `AbuseVector` is reachability/plausibility-scored and severity is honest
  (likelihood × impact with uncertainty). Degenerate findings are flagged, never ranked.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

CONTRACTS_VERSION = "1.0.0"


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #
class Category(str, Enum):
    """The §4 taxonomy. 1–9 are the universal core (any SaaS); 10 is conditional."""
    LICENSE_ENTITLEMENT = "license_entitlement"        # 4.1
    DATA_HARVESTING = "data_harvesting"                # 4.2
    UNINTENDED_ENDPOINTS = "unintended_endpoints"      # 4.3
    FUNCTION_ABUSE = "function_abuse"                  # 4.4
    CONTENT_POLICY = "content_policy"                  # 4.5
    IDENTITY_ACCOUNT = "identity_account"              # 4.6
    TRUST_ECONOMY = "trust_economy"                    # 4.7
    INTEGRATION_EXTENSIBILITY = "integration_extensibility"  # 4.8
    COMPLIANCE_BOUNDARY = "compliance_boundary"        # 4.9
    AGENT_MCP_SURFACE = "agent_mcp_surface"            # 4.10 (conditional)


CORE_CATEGORIES = {c for c in Category if c != Category.AGENT_MCP_SURFACE}


class AppliesWhen(str, Enum):
    ALWAYS = "always"
    HAS_AGENT_SURFACE = "has_agent_surface"


class ScenarioSource(str, Enum):
    SEED = "seed"
    DISCOVERED = "discovered"


class VerificationStatus(str, Enum):
    PREDICTED = "predicted"     # reachability proven by contained PoC, not yet observed in prod
    OBSERVED = "observed"       # later corroborated by real post-launch telemetry (stretch hook)


class DataHandlingMode(str, Enum):
    SYNTHETIC_ONLY = "synthetic_only"   # canary records only — the default & safe mode
    MINIMIZE = "minimize"               # real target: minimize, never persist contents


# --------------------------------------------------------------------------- #
# Scenario library (declarative; addable without code)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class AbuseScenario:
    id: str
    category: Category
    objective: str
    target_affordance_pattern: dict        # what surface elements this probes (declarative match)
    probe_strategy: str                    # named strategy the agent executes (no weaponization)
    success_criterion: dict                # declarative condition that constitutes the abuse
    severity_model: dict                   # {likelihood, impact} priors in [0,1]
    classification_impact: Optional[str] = None    # optional data-class annotation hint
    containment_limits: dict = field(default_factory=dict)  # per-scenario back-off / sample caps
    applies_when: AppliesWhen = AppliesWhen.ALWAYS
    source: ScenarioSource = ScenarioSource.SEED
    # declarative outputs (so scenarios are addable WITHOUT code, incl. from JSON):
    recommended_control: str = ""
    exploitability_reduction: float = 0.6
    handoff: str = ""                      # "" | "appsec" | "model_redteam"


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #
@dataclass
class Severity:
    likelihood: float          # [0,1]
    impact: float              # [0,1]
    uncertainty: float = 0.2   # explicit uncertainty band (no inflation, spec §10.2.7)

    @property
    def score(self) -> float:
        return round(self.likelihood * self.impact, 3)

    @property
    def label(self) -> str:
        s = self.score
        return "critical" if s >= 0.6 else "high" if s >= 0.4 else "medium" if s >= 0.2 else "low"


@dataclass
class AbuseVector:
    id: str
    scenario_id: str
    category: Category
    reproduction: dict                 # CONTAINED PoC: steps + bounded canary result. No real exfil.
    severity: Severity
    reachability_score: float          # [0,1] — traffic/affordance plausibility
    plausible: bool                    # reachability above the plausibility floor
    recommended_control: str
    classification_impact: Optional[dict] = None     # optional annotation (off by default)
    obligation_impact: Optional[dict] = None
    estimated_exploitability_reduction: Optional[float] = None
    verification_status: VerificationStatus = VerificationStatus.PREDICTED
    handoff_to_appsec: bool = False    # true security vuln (memory/crypto/novel) — not HEEL's lane
    handoff_to_model_redteam: bool = False  # pure jailbreak technique — not HEEL's lane
    target_id: str = ""
    affordance_id: str = ""
    notes: str = ""


# --------------------------------------------------------------------------- #
# Opportunistic-human class (defined now; used in Phase 3)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class MotivationProfile:
    id: str
    cost_sensitivity: float    # [0,1]
    risk_tolerance: float
    sophistication: float
    tos_willingness: float     # willingness to violate ToS [0,1]


# --------------------------------------------------------------------------- #
# Authorization — created OUT-OF-BAND by a human only; immutable from caller side
# --------------------------------------------------------------------------- #
@dataclass
class AuthorizationScope:
    scope_id: str
    target_allowlist: list[str]            # only these targets may be run
    operator_confirmation: str             # human approver identity (bind)
    signature: str                         # HMAC over canonical scope content (tamper-evident)
    rate_and_resource_limits: dict         # enforced server-side regardless of caller request
    data_handling_mode: DataHandlingMode
    expiry: float                          # epoch seconds; expired scope cannot run
    created_ts: float = 0.0

    def public_view(self) -> dict:
        """What `heel_list_scopes` returns — NEVER secrets (signature redacted)."""
        return {
            "scope_id": self.scope_id,
            "target_allowlist": list(self.target_allowlist),
            "operator_confirmation": self.operator_confirmation,
            "rate_and_resource_limits": dict(self.rate_and_resource_limits),
            "data_handling_mode": self.data_handling_mode.value,
            "expiry": self.expiry,
            "signature": "<redacted>",
        }


@dataclass
class CallerContext:
    caller_identity: str       # the invoking agent/tool identity (MCP clientInfo or CLI user)
    scope_id: str
    ts: float


# --------------------------------------------------------------------------- #
# Synthetic targets + planted ground truth (used ONLY by the backtest)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Affordance:
    """A probe-able element of a synthetic product's capability surface."""
    id: str
    kind: str                  # endpoint | flag | meter | trial | export | record | referral |
                               # admin_action | agent_tool | mcp_connector | content_guardrail
    category: Category
    properties: dict
    guard_present: bool        # is the control that SHOULD gate this present?
    reachability: float        # [0,1] how reachable the (mis)behavior is
    planted_weakness: Optional[str] = None   # None = hardened; else the planted abuse type
    true_severity: Optional[Severity] = None # ground-truth severity (planted only)
    decoy: bool = False        # looks abusable but is hardened (FP bait)


@dataclass
class PlantedVector:
    """Ground-truth abuse vector planted in a synthetic target (backtest only)."""
    id: str
    target_id: str
    category: Category
    affordance_id: str
    weakness: str
    true_severity: Severity
    reachable: bool = True


@dataclass
class SyntheticTarget:
    id: str
    kind: str                  # "saas" | "ai_agent"
    has_agent_surface: bool
    affordances: list[Affordance]
    planted_vectors: list[PlantedVector]
    description: str = ""


# --------------------------------------------------------------------------- #
# Immutable audit trail
# --------------------------------------------------------------------------- #
@dataclass
class ContainmentEntry:
    seq: int
    ts: float
    run_id: str
    caller_identity: str
    action: str                # what HEEL did (probe, reject, finding, backoff, ...)
    detail: dict
    prev_hash: str             # hash chain → tamper-evident
    entry_hash: str = ""


# --------------------------------------------------------------------------- #
# Run lifecycle
# --------------------------------------------------------------------------- #
@dataclass
class RunSpec:
    scope_id: str
    target: str
    scenario_ids: Optional[list[str]] = None
    agent_classes: Optional[list[str]] = None       # ["adversarial"] for v1 slice
    budget: dict = field(default_factory=dict)


@dataclass
class RunResult:
    run_id: str
    status: str                # queued | running | complete | rejected
    caller: CallerContext
    findings: list[AbuseVector] = field(default_factory=list)
    coverage: Optional[dict] = None
    error: Optional[str] = None
