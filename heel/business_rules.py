"""Product intent and evidence semantics; declarations never certify behavior."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

EVIDENCE_STATES = frozenset({'unknown', 'customer_declared', 'inferred', 'observed', 'verified'})


@dataclass(frozen=True)
class ProductRule:
    id: str
    statement: str
    source: str
    evidence_state: str = 'customer_declared'

    def __post_init__(self):
        if not all(type(v) is str and v.strip() for v in (self.id, self.statement, self.source)):
            raise ValueError('product rule requires an identifier, statement and source')
        if self.evidence_state not in EVIDENCE_STATES:
            raise ValueError('invalid evidence state')


@dataclass(frozen=True)
class LifecycleAction:
    actor: str
    action: str
    preconditions: tuple[str, ...] = ()
    state_changes: tuple[str, ...] = ()


@dataclass(frozen=True)
class LifecycleSequence:
    id: str
    actions: tuple[LifecycleAction, ...]
    invariant: str
    execution_support: str = 'future'

    def to_dict(self) -> dict[str, Any]:
        return {'id': self.id, 'actions': [
            {'ordinal': index, 'actor': item.actor, 'action': item.action,
             'preconditions': list(item.preconditions), 'state_changes': list(item.state_changes)}
            for index, item in enumerate(self.actions)
        ], 'invariant': self.invariant, 'execution_support': self.execution_support,
            'executed': False, 'evidence_state': 'unknown'}


LIFECYCLES = (
    LifecycleSequence('trial-lifecycle', (
        LifecycleAction('customer', 'claim trial', ('eligible subject',), ('trial consumed',)),
        LifecycleAction('customer', 'change account identity', ('trial consumed',), ('login identifier changed',)),
        LifecycleAction('customer', 'request another trial', ('same eligibility subject',)),
    ), 'A subject receives only the trial value permitted by the declared eligibility policy'),
    LifecycleSequence('cumulative-consumption', (
        LifecycleAction('integration', 'consume expensive feature', ('quota available',), ('usage increases',)),
        LifecycleAction('integration', 'consume through alternate operation', ('same accounting subject',), ('usage increases',)),
    ), 'All chargeable operations contribute to the declared aggregate meter'),
    LifecycleSequence('export-entitlement-transition', (
        LifecycleAction('tenant administrator', 'downgrade plan', ('paid export access',), ('export entitlement removed',)),
        LifecycleAction('integration', 'read through UI and API paths', ('entitlement removed',)),
    ), 'All paths honor current entitlement; a read pair alone does not execute this lifecycle'),
)


def exposure(rule: ProductRule) -> dict[str, Any]:
    return {
        'mechanism_id': 'export-read-entitlement',
        'motivation': 'Obtain paid export value using a lower-priced account',
        'actor': 'lower-plan customer or integration', 'capability': 'read a synthetic export',
        'rule': {'id': rule.id, 'statement': rule.statement, 'source': rule.source,
                 'evidence_state': rule.evidence_state},
        'preconditions': ['two isolated synthetic accounts with known plans', 'one shared synthetic export fixture'],
        'suspected_violation': 'lower-plan account receives protected export content',
        'invariant': 'protected marker is available to the entitled account and absent from the lower-plan response',
        'required_observations': ['positive entitled read', 'lower-plan read', 'exact protected marker comparison'],
        'safe_boundary': 'two sequential read-only requests; one synthetic row; no network destination',
        'recommended_control': 'Check current server-side export entitlement before serializing protected fields on every access path',
        'regression': 'Repeat the same fixture and isolated-account read pair after the server-side entitlement fix',
        'economic_impact': {'evidence_state': 'inferred', 'assumption': 'unpriced paid-feature value; no monetary amount measured'},
        'coverage_gaps': ['trial/promotion eligibility', 'usage accounting', 'cumulative scraping limits',
                          'unpriced automation at scale', 'plan-change lifecycle', 'unexercised access paths'],
    }


def mechanism_for(identifier: str) -> str:
    """Alternate encodings share a mechanism; this is not an execution count."""
    families = (
        ('trial-eligibility', ('trial',)),
        ('promotion-eligibility', ('coupon', 'promo')),
        ('seat-entitlement', ('seat', 'concurr')),
        ('usage-accounting', ('meter',)),
        ('export-read-entitlement', ('export.entitlement', 'export.overbroad', 'bulk_export', 'ungated_bulk_export')),
        ('automation-entitlement', ('shadow_api',)),
        ('object-access', ('enumeration', 'seq_id')),
        ('route-access', ('endpoint.hidden', 'forced_browsing', 'zombie_api', 'debug_endpoint', 'introspection')),
    )
    for mechanism, encodings in families:
        if any(encoding in identifier for encoding in encodings):
            return mechanism
    return identifier
