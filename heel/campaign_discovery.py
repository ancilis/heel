"""Use an API inventory to suggest explicit, still-unexecuted business-rule campaigns."""
from .campaign_contract import FAMILIES
from .campaign_templates import RULES
from .openapi_model import product_model_from_openapi

_HINTS = {
    'trial_eligibility': ('trial', 'signup', 'eligibility'),
    'promotion_limits': ('coupon', 'promotion', 'promo', 'referral'),
    'usage_accounting': ('usage', 'meter', 'consume', 'generate', 'inference'),
    'quota': ('quota', 'limit', 'consume', 'export', 'generate'),
    'lifecycle': ('subscription', 'plan', 'downgrade', 'cancel', 'revoke'),
    'entitlement': ('export', 'download', 'premium', 'paid'),
    'role_boundary': ('admin', 'support', 'role', 'permission'),
    'tenant_isolation': ('tenant', 'workspace', 'org', 'record', 'document'),
    'idempotency': ('grant', 'credit', 'claim', 'redeem', 'refund', 'reward'),
    'workflow_order': ('approve', 'fulfill', 'publish', 'release', 'submit'),
    'integration_scope': ('oauth', 'integration', 'webhook', 'connector'),
    'agent_actions': ('agent', 'tool', 'mcp', 'assistant'),
}


def discover_campaigns(spec):
    model = product_model_from_openapi(spec)
    operations, suggested = [], set()
    for operation in model['endpoints_routes']:
        description = ' '.join(str(operation.get(key, '')) for key in ('route', 'operation_id', 'tags', 'required_plan')).lower()
        families = sorted(family for family, words in _HINTS.items() if any(word in description for word in words))
        suggested.update(families)
        operations.append({'operation_id': operation['operation_id'], 'method': operation['method'], 'path': operation['route'],
            'suggested_families': families, 'candidate_rules': [RULES[family] for family in families],
            'required_bindings': ['intended product rule', 'isolated canary actors', 'synthetic fixture identifiers',
                                  'positive control', 'response fields and expected business outcome', 'cleanup for mutations'],
            'evidence_state': 'inferred'})
    return {'schema_version': 'heel.campaign.discovery.v1', 'product_id': model['product_id'], 'executed': False,
            'operations': operations, 'suggested_families': sorted(suggested), 'unmapped_families': sorted(set(FAMILIES)-suggested),
            'note': 'Suggestions are based on declared API vocabulary. Unmapped families may still apply. Define rules and bind fixtures before authorization.'}
