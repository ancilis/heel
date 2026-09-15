"""Bounded declarative business rules; no expression evaluation or target I/O."""
from __future__ import annotations

import hashlib
import json
import math
import re
from urllib.parse import urlsplit

FAMILIES = ('tenant_isolation', 'role_boundary', 'entitlement', 'trial_eligibility',
            'promotion_limits', 'usage_accounting', 'quota', 'lifecycle',
            'idempotency', 'workflow_order', 'integration_scope', 'agent_actions')
OPS = {'eq', 'ne', 'lt', 'lte', 'gt', 'gte', 'contains', 'not_contains', 'exists', 'absent', 'delta_lte', 'delta_gte'}
MAX_BYTES = 256 * 1024
MAX_RESPONSE = 64 * 1024
_ID = re.compile(r'[a-z][a-z0-9_-]{0,63}\Z')
_MISSING = object()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True, allow_nan=False)


def strict_json(text):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('duplicate JSON key')
            result[key] = value
        return result
    def constant(_):
        raise ValueError('non-finite JSON value')
    if len(text.encode('utf-8') if isinstance(text, str) else text) > MAX_BYTES:
        raise ValueError('campaign JSON exceeds 256 KiB')
    return json.loads(text, object_pairs_hook=unique, parse_constant=constant)


def _fields(value, required, optional=()):
    if type(value) is not dict or not set(required) <= value.keys() or value.keys() - set(required) - set(optional):
        raise ValueError('unsupported or missing campaign fields')


def _text(value, maximum=400):
    if type(value) is not str or not value.strip() or len(value) > maximum or any(ord(c) < 32 for c in value):
        raise ValueError('invalid campaign text')


def _identifier(value):
    if type(value) is not str or not _ID.fullmatch(value):
        raise ValueError('invalid campaign identifier')


def _number(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError('campaign limit out of range')


def validate_origin(origin, environment):
    if environment == 'loopback':
        if type(origin) is not str or not re.fullmatch(r'http://127\.0\.0\.1:[0-9]{1,5}', origin):
            raise ValueError('loopback requires literal http://127.0.0.1:PORT')
        _number(urlsplit(origin).port, 1024, 65535)
    elif environment in {'sandbox', 'staging'}:
        from .runner.http_transport import normalize_target_origin
        try:
            if normalize_target_origin(origin) != origin:
                raise ValueError('origin must be canonical')
        except Exception:
            raise ValueError('sandbox/staging requires a canonical public HTTPS origin') from None
    else:
        raise ValueError('choose sandbox, staging or explicit loopback')


def _reference(value, steps):
    _fields(value, ('step', 'pointer'))
    if value['step'] not in steps or type(value['pointer']) is not str:
        raise ValueError('assertion references an unknown step')
    pointer = value['pointer']
    if len(pointer) > 256 or (pointer not in {'', '$status'} and not pointer.startswith('/')):
        raise ValueError('assertion requires a JSON pointer or $status')
    if re.search(r'~(?![01])', pointer):
        raise ValueError('invalid JSON pointer escape')


def _assertion(value, steps):
    _fields(value, ('id', 'left', 'op'), ('right', 'baseline'))
    _identifier(value['id'])
    _reference(value['left'], steps)
    if type(value['op']) is not str or value['op'] not in OPS:
        raise ValueError('unsupported comparison')
    if value['op'] not in {'exists', 'absent'}:
        if 'right' not in value:
            raise ValueError('comparison requires right operand')
        if type(value['right']) is dict:
            _reference(value['right'], steps)
        elif type(value['right']) not in {str, int, float, bool, type(None)}:
            raise ValueError('comparison requires a scalar or observation')
    elif 'right' in value:
        raise ValueError('presence comparisons have no right operand')
    if value['op'].startswith('delta_'):
        _reference(value.get('baseline'), steps)
    elif 'baseline' in value:
        raise ValueError('only delta comparisons accept baseline')


def _step(step, actors, mutations):
    _fields(step, ('id', 'actor', 'method', 'path', 'expected_status'), ('json', 'idempotency_key'))
    _identifier(step['id'])
    if step['actor'] not in actors or step['method'] not in {'GET', 'POST', 'PUT', 'PATCH', 'DELETE'}:
        raise ValueError('unsupported actor or method')
    path = step['path']
    if type(path) is not str or not re.fullmatch(r'/[A-Za-z0-9_./{}:-]*', path) or path.startswith('//'):
        raise ValueError('only exact relative paths are supported; no query, encoding or alternate origin')
    if any(part in {'.', '..'} for part in path.split('/')) or len(path.replace('{run}', '0' * 32)) > 1024:
        raise ValueError('invalid campaign path')
    if '{' in path.replace('{run}', '') or '}' in path.replace('{run}', ''):
        raise ValueError('only the {run} fixture placeholder is allowed')
    statuses = step['expected_status']
    if type(statuses) is not list or not 1 <= len(statuses) <= 12 or any(type(s) is not int or not 200 <= s <= 499 or 300 <= s < 400 or s == 429 for s in statuses):
        raise ValueError('invalid expected status codes')
    if step['method'] == 'GET' and 'json' in step:
        raise ValueError('GET cannot carry a body')
    if 'json' in step and (type(step['json']) is not dict or len(canonical(step['json']).replace('{run}', '0' * 32)) > 8192):
        raise ValueError('request JSON must be an object at most 8 KiB')
    from .openapi_model import _reject_secret_examples
    _reject_secret_examples(step)
    pending = [step.get('json', {})]
    while pending:
        item = pending.pop()
        if type(item) is dict:
            if any(key.lower().replace('-', '_') in {'password', 'secret', 'api_key', 'access_token', 'refresh_token', 'authorization', 'cookie'} for key in item):
                raise ValueError('request credentials must be local actor environment references')
            pending.extend(item.values())
        elif type(item) is list:
            pending.extend(item)
    if step['method'] != 'GET':
        if not mutations or 'heel-canary-' not in path + canonical(step.get('json', {})):
            raise ValueError('mutations require explicit consent and a heel-canary- fixture')
    if 'idempotency_key' in step:
        if type(step['idempotency_key']) is not str or not re.fullmatch(r'heel-canary-[A-Za-z0-9_{}-]{1,100}', step['idempotency_key']):
            raise ValueError('invalid canary idempotency key')


def validate_campaign(value):
    try:
        return _validate_campaign(value)
    except (TypeError, KeyError, OverflowError, RecursionError):
        raise ValueError('invalid campaign structure') from None


def _validate_campaign(value):
    # JSON round trip both detaches inputs and rejects executable Python objects.
    raw = canonical(value)
    if len(raw) > MAX_BYTES:
        raise ValueError('campaign exceeds 256 KiB')
    value = strict_json(raw)
    from .openapi_model import _reject_secret_examples
    _reject_secret_examples(value)
    _fields(value, ('schema_version', 'name', 'origin', 'environment', 'allow_mutations', 'actors', 'limits', 'scenarios'))
    if value['schema_version'] != 'heel.campaign.v1' or type(value['allow_mutations']) is not bool:
        raise ValueError('unsupported campaign schema')
    _text(value['name'], 120)
    validate_origin(value['origin'], value['environment'])
    actors = value['actors']
    if type(actors) is not list or not 1 <= len(actors) <= 16:
        raise ValueError('campaign requires 1–16 isolated actors')
    actor_ids = set()
    for actor in actors:
        _fields(actor, ('id', 'auth'), ('credential_env',))
        _identifier(actor['id'])
        if actor['id'] in actor_ids or actor['auth'] not in {'anonymous', 'bearer', 'x_api_key'}:
            raise ValueError('duplicate actor or unsupported authentication')
        actor_ids.add(actor['id'])
        if actor['auth'] == 'anonymous':
            if 'credential_env' in actor:
                raise ValueError('anonymous actor cannot carry credentials')
        elif type(actor.get('credential_env')) is not str or not re.fullmatch(r'HEEL_CANARY_[A-Z0-9_]{1,80}', actor['credential_env']):
            raise ValueError('use a HEEL_CANARY_ credential environment reference')
    limits = value['limits']
    _fields(limits, ('max_requests', 'timeout_seconds', 'max_duration_seconds', 'min_interval_ms'))
    for key, low, high in [('max_requests', 1, 200), ('timeout_seconds', 1, 15), ('max_duration_seconds', 1, 300), ('min_interval_ms', 0, 5000)]:
        _number(limits[key], low, high)
    if value['environment'] != 'loopback' and limits['min_interval_ms'] < 100:
        raise ValueError('remote campaigns require at least 100ms between requests')
    scenarios = value['scenarios']
    if type(scenarios) is not list or not 1 <= len(scenarios) <= 40:
        raise ValueError('campaign requires 1–40 scenarios')
    ids, total = set(), 0
    for scenario in scenarios:
        _fields(scenario, ('id', 'family', 'rule', 'steps', 'preconditions', 'assertions', 'cleanup'), ('not_applicable_reason',))
        _identifier(scenario['id'])
        if scenario['id'] in ids or scenario['family'] not in FAMILIES:
            raise ValueError('duplicate scenario or unknown rule family')
        ids.add(scenario['id']); _text(scenario['rule'])
        if 'not_applicable_reason' in scenario:
            _text(scenario['not_applicable_reason'])
        if type(scenario['steps']) is not list or not 1 <= len(scenario['steps']) <= 20 or type(scenario['cleanup']) is not list or len(scenario['cleanup']) > 5:
            raise ValueError('invalid scenario steps')
        step_ids = set()
        for step in scenario['steps'] + scenario['cleanup']:
            _step(step, actor_ids, value['allow_mutations'])
            if step['id'] in step_ids:
                raise ValueError('duplicate step identifier')
            step_ids.add(step['id'])
        step_ids = {step['id'] for step in scenario['steps']}
        for key in ('preconditions', 'assertions'):
            if type(scenario[key]) is not list or not 1 <= len(scenario[key]) <= 20:
                raise ValueError('each scenario needs positive prerequisites and assertions')
            assertion_ids = set()
            for assertion in scenario[key]:
                _assertion(assertion, step_ids)
                if assertion['id'] in assertion_ids:
                    raise ValueError('duplicate assertion identifier')
                assertion_ids.add(assertion['id'])
        total += len(scenario['steps']) + len(scenario['cleanup'])
    if total > limits['max_requests']:
        raise ValueError('steps and cleanup exceed approved request budget')
    return value


def campaign_target(plan):
    return 'campaign:' + hashlib.sha256(canonical(validate_campaign(plan)).encode()).hexdigest()


def _operand(value, observations):
    if type(value) is not dict:
        return value
    record = observations.get(value['step'])
    if record is None:
        return _MISSING
    if value['pointer'] == '$status':
        return record['status']
    node = record.get('body', _MISSING)
    if node is _MISSING:
        return node
    for token in value['pointer'].split('/')[1:]:
        token = token.replace('~1', '/').replace('~0', '~')
        if type(node) is dict:
            node = node.get(token, _MISSING)
        elif type(node) is list and token.isdigit() and int(token) < len(node):
            node = node[int(token)]
        else:
            return _MISSING
    return node


def evaluate_assertion(check, observations):
    left = _operand(check['left'], observations)
    op = check['op']
    # An absent field only counts when a complete JSON observation exists.
    if check['left']['step'] not in observations or 'body' not in observations[check['left']['step']]:
        return None
    if op in {'exists', 'absent'}:
        return (left is not _MISSING) if op == 'exists' else (left is _MISSING)
    right = _operand(check['right'], observations)
    if left is _MISSING or right is _MISSING:
        return None
    if op in {'eq', 'ne'}:
        equal = type(left) is type(right) and left == right
        return equal if op == 'eq' else not equal
    if op in {'contains', 'not_contains'}:
        if type(left) not in {str, list} or (type(left) is str and type(right) is not str):
            return None
        contained = right in left
        return contained if op == 'contains' else not contained
    if op.startswith('delta_'):
        baseline = _operand(check['baseline'], observations)
        if type(baseline) not in {int, float} or type(left) not in {int, float}:
            return None
        left -= baseline
        op = op[6:]
    if type(left) not in {int, float} or type(right) not in {int, float}:
        return None
    if abs(left) > 2**53 - 1 or abs(right) > 2**53 - 1 or not math.isfinite(left) or not math.isfinite(right):
        return None
    return {'lt': left < right, 'lte': left <= right, 'gt': left > right, 'gte': left >= right}[op]
