"""Editable, executable business-rule examples, with explicit fixtures and cleanup."""
from .campaign_contract import FAMILIES, validate_campaign

RULES = {
    'tenant_isolation': 'A customer cannot read a canary object owned by another tenant.',
    'role_boundary': 'A lower-privilege actor cannot read administrator-only data.',
    'entitlement': 'An account without the paid export entitlement cannot obtain protected export content.',
    'trial_eligibility': 'Changing login identity does not give the same eligibility subject a second trial.',
    'promotion_limits': 'Only one promotional benefit may be granted per eligibility subject.',
    'usage_accounting': 'Both UI and API consumption contribute to the same authoritative usage meter.',
    'quota': 'Two bounded consumption attempts cannot exceed the one-unit fixture quota.',
    'lifecycle': 'Downgrading a plan removes export entitlement on subsequent reads.',
    'idempotency': 'Repeating the same benefit request with the same idempotency key grants value once.',
    'workflow_order': 'An unapproved request cannot reach fulfilled state.',
    'integration_scope': 'An integration credential cannot access data outside its granted scope.',
    'agent_actions': 'A delegated agent credential cannot access owner-only product capabilities.',
}
READ_FAMILIES = {'tenant_isolation', 'role_boundary', 'entitlement', 'integration_scope', 'agent_actions'}


def template_campaign(origin='http://127.0.0.1:8765', *, family=None, environment='loopback'):
    selected = list(FAMILIES) if family is None else [family]
    if any(item not in FAMILIES for item in selected):
        raise ValueError('unknown campaign family')
    scenarios = []
    for name in selected:
        base = '/heel-canary-{run}/' + name
        def step(identifier, operation, *, actor='owner', method='GET', body=None, key=None):
            result = {'id': identifier, 'actor': actor, 'method': method, 'path': base + '/' + operation,
                      'expected_status': [200] if method == 'GET' else [200, 403, 409]}
            if body is not None:
                result['json'] = body
            if key is not None:
                result['idempotency_key'] = key
            return result
        def ref(identifier, pointer):
            return {'step': identifier, 'pointer': pointer}
        reset = step('setup', 'reset', method='POST', body={'subject': 'heel-canary-{run}'})
        reset['expected_status'] = [200]
        cleanup = step('cleanup', 'reset', method='DELETE')
        cleanup['expected_status'] = [200]
        positive = step('before', 'export' if name in READ_FAMILIES or name == 'lifecycle' else 'state')
        precondition = {'id': 'known_fixture', 'left': ref('before', '/protected_canary' if name in READ_FAMILIES or name == 'lifecycle' else '/fixture'),
                        'op': 'eq', 'right': 'heel-canary-{run}'}
        steps = [reset, positive]
        if name in READ_FAMILIES:
            steps.append(step('after', 'export', actor='outsider'))
            checks = [{'id': 'boundary', 'left': ref('after', '/protected_canary'), 'op': 'absent'}]
        elif name == 'lifecycle':
            steps += [step('downgrade', 'downgrade', method='POST', body={'subject': 'heel-canary-{run}'}), step('after', 'export')]
            checks = [{'id': 'current_entitlement', 'left': ref('after', '/protected_canary'), 'op': 'absent'}]
        else:
            operations = {
                'trial_eligibility': ['claim-trial', 'change-identity', 'claim-trial'],
                'promotion_limits': ['promotion-a', 'promotion-b'],
                'usage_accounting': ['consume-ui', 'consume-api'],
                'quota': ['consume-ui', 'consume-api'],
                'idempotency': ['grant-benefit', 'grant-benefit'],
                'workflow_order': ['fulfill'],
            }[name]
            for index, operation in enumerate(operations):
                steps.append(step('action_' + str(index), operation, method='POST', body={'subject': 'heel-canary-{run}'},
                                  key='heel-canary-{run}' if name == 'idempotency' else None))
            steps.append(step('after', 'state'))
            field = '/usage' if name in {'usage_accounting', 'quota'} else '/fulfilled' if name == 'workflow_order' else '/benefits'
            checks = [{'id': 'business_value', 'left': ref('after', field), 'baseline': ref('before', field),
                       'op': 'delta_gte' if name == 'usage_accounting' else 'delta_lte',
                       'right': 2 if name == 'usage_accounting' else 0 if name == 'workflow_order' else 1}]
        scenarios.append({'id': name, 'family': name, 'rule': RULES[name], 'steps': steps,
                          'preconditions': [precondition], 'assertions': checks, 'cleanup': [cleanup]})
    return validate_campaign({'schema_version': 'heel.campaign.v1', 'name': 'Business-abuse campaign',
        'origin': origin, 'environment': environment, 'allow_mutations': True,
        'actors': [{'id': 'owner', 'auth': 'bearer', 'credential_env': 'HEEL_CANARY_OWNER'},
                   {'id': 'outsider', 'auth': 'bearer', 'credential_env': 'HEEL_CANARY_OUTSIDER'}],
        'limits': {'max_requests': sum(len(s['steps'])+len(s['cleanup']) for s in scenarios),
                   'timeout_seconds': 5, 'max_duration_seconds': 120, 'min_interval_ms': 100},
        'scenarios': scenarios})
