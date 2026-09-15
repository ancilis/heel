"""Execute declared business invariants under an exact human-signed campaign scope."""
from __future__ import annotations

from collections import Counter
import hmac
import os
import threading
import time

from . import scope as scopes
from .campaign_contract import FAMILIES, canonical, campaign_target, evaluate_assertion, strict_json, validate_campaign
from .campaign_store import campaign_store
from .campaign_transport import CampaignFailure, CampaignTransport
from .contracts import DataHandlingMode


def authorize_campaign(plan, operator, *, runs=1, ttl_seconds=3600):
    """Human CLI only. The target digest binds origin, credentials' names, operations and limits."""
    plan = validate_campaign(plan)
    if type(runs) is not int or not 1 <= runs <= 50 or type(ttl_seconds) is not int or not 60 <= ttl_seconds <= 86400:
        raise ValueError('authorize 1–50 runs for 60–86400 seconds')
    if type(operator) is not str or not operator.strip():
        raise ValueError('operator name required')
    return scopes.create_scope([campaign_target(plan)], operator,
        limits={'max_requests': plan['limits']['max_requests'] * runs, 'max_concurrency': 1, 'backoff': True},
        data_mode=DataHandlingMode.SYNTHETIC_ONLY, ttl_seconds=ttl_seconds)


def _scope(scope_id, target):
    scope = scopes.get_scope(scope_id)
    if scope is None or not scopes.verify(scope)[0] or not scopes.target_in_scope(scope, target):
        raise ValueError('valid human-created scope for this exact campaign required')
    if scope.data_handling_mode != DataHandlingMode.SYNTHETIC_ONLY or scope.rate_and_resource_limits.get('max_concurrency') != 1:
        raise ValueError('campaign scope must be sequential and canary-only')
    return scope


def _dependencies(check):
    return {value['step'] for value in (check.get('left'), check.get('right'), check.get('baseline')) if type(value) is dict}


def _scenario(plan, scenario, transport, credentials, attempt, scope_id, target, deadline, cancellation, budget):
    result = {'scenario_id': scenario['id'], 'family': scenario['family'], 'rule': scenario['rule'],
              'outcome': 'inconclusive', 'reason': 'not_started', 'checks': [], 'evidence': [], 'cleanup': 'not_needed'}
    if scenario.get('not_applicable_reason'):
        return {**result, 'outcome': 'not_applicable', 'reason': scenario['not_applicable_reason']}
    # Only a fixed identifier placeholder may vary across runs; its value is not a URL or expression.
    scenario = strict_json(canonical(scenario).replace('{run}', attempt))
    actors = {a['id']: a for a in plan['actors']}
    observations, validated = {}, set()

    def perform(step):
        _scope(scope_id, target)
        if cancellation.is_set() or time.monotonic() >= deadline:
            raise CampaignFailure('cancelled_or_duration_exhausted')
        if budget[0] <= 0:
            raise CampaignFailure('request_budget_exhausted')
        delay = plan['limits']['min_interval_ms'] / 1000 - (time.monotonic() - transport.last_request)
        if delay > 0 and cancellation.wait(delay):
            raise CampaignFailure('cancelled')
        current_scope = _scope(scope_id, target)
        request_deadline = min(deadline, time.monotonic() + current_scope.expiry - time.time())
        budget[0] -= 1
        transport.last_request = time.monotonic()
        row = transport.request(step, actors[step['actor']], credentials, request_deadline)
        result['evidence'].append({'step_id': step['id'], **{k: v for k, v in row.items() if k != 'body'}})
        if row['status'] not in step['expected_status']:
            raise CampaignFailure('unexpected_status')
        observations[step['id']] = row

    started = False
    try:
        for step in scenario['steps']:
            started = True
            perform(step)
            for check in scenario['preconditions']:
                if check['id'] not in validated and _dependencies(check) <= observations.keys():
                    if evaluate_assertion(check, observations) is not True:
                        raise CampaignFailure('prerequisite_not_established')
                    validated.add(check['id'])
        if len(validated) != len(scenario['preconditions']):
            raise CampaignFailure('prerequisite_not_established')
        values = []
        for check in scenario['assertions']:
            value = evaluate_assertion(check, observations)
            values.append(value)
            result['checks'].append({'id': check['id'], 'outcome': 'inconclusive' if value is None else 'held' if value else 'violation'})
        result['outcome'] = 'violation' if False in values else 'inconclusive' if None in values else 'held'
        result['reason'] = 'assertions_evaluated'
    except (CampaignFailure, ValueError):
        # Keep transport errors non-reflective: target content and credentials never enter reports.
        import sys
        error = sys.exception()
        result['reason'] = str(error) if isinstance(error, CampaignFailure) else 'scope_rejected'
        if result['reason'] in {'throttled', 'dns_changed', 'unsafe_or_unavailable_dns', 'scope_rejected'}:
            cancellation.set()
    finally:
        if started and scenario['cleanup']:
            result['cleanup'] = 'complete'
            for step in scenario['cleanup']:
                try:
                    perform(step)
                except (CampaignFailure, ValueError):
                    result['cleanup'] = 'failed'
            if result['cleanup'] == 'failed' and result['outcome'] == 'held':
                result['outcome'] = 'inconclusive'
                result['reason'] = 'cleanup_failed'
    return result


def run_campaign(plan, scope_id, attempt, *, cancellation=None):
    plan = validate_campaign(plan)
    target = campaign_target(plan)
    scope = _scope(scope_id, target)
    cancellation = cancellation if cancellation is not None else threading.Event()
    credentials = {a['credential_env']: os.environ.get(a['credential_env']) for a in plan['actors'] if a['auth'] != 'anonymous'}
    actor_credentials = [credentials[a['credential_env']] for a in plan['actors'] if a['auth'] != 'anonymous' and credentials[a['credential_env']]]
    if len(actor_credentials) != len(set(actor_credentials)):
        raise ValueError('distinct campaign actors must use distinct credentials')
    with campaign_store() as store:
        store.reserve(attempt, scope_id, plan['limits']['max_requests'], scope.rate_and_resource_limits.get('max_requests', 0))
        transport = CampaignTransport(plan, cancellation)
        deadline = time.monotonic() + plan['limits']['max_duration_seconds']
        budget = [plan['limits']['max_requests']]
        results = [_scenario(plan, scenario, transport, credentials, attempt, scope_id, target, deadline, cancellation, budget) for scenario in plan['scenarios']]
        counts = Counter(row['outcome'] for row in results)
        report = {'schema_version': 'heel.campaign.report.v1', 'run_id': attempt, 'scope_id': scope_id,
                  'campaign_digest': target.split(':')[1], 'name': plan['name'], 'origin': plan['origin'],
                  'created_at': int(time.time()), 'results': results, 'uploaded': False,
                  'requests_attempted': plan['limits']['max_requests'] - budget[0],
                  'coverage': {'total': len(results), **{key: counts[key] for key in ('held', 'violation', 'inconclusive', 'not_applicable')},
                    'families': {family: {'configured': sum(row['family'] == family for row in results),
                                'held': sum(row['family'] == family and row['outcome'] == 'held' for row in results),
                                'violation': sum(row['family'] == family and row['outcome'] == 'violation' for row in results)} for family in FAMILIES}}}
        report['signature'] = scopes.hmac_sign(canonical(report))
        store.write(attempt + '.json', report)
        return report


def verify_report(report):
    if type(report) is not dict or report.get('schema_version') != 'heel.campaign.report.v1' or type(report.get('signature')) is not str:
        return False
    return hmac.compare_digest(report['signature'], scopes.hmac_sign(canonical({k: v for k, v in report.items() if k != 'signature'})))


def compare_reports(before, after):
    if not verify_report(before) or not verify_report(after) or before['campaign_digest'] != after['campaign_digest']:
        raise ValueError('comparison requires authentic reports for the same campaign')
    previous = {row['scenario_id']: row['outcome'] for row in before['results']}
    fixed, regressed, unresolved = [], [], []
    for row in after['results']:
        old = previous.get(row['scenario_id'])
        if old == 'violation' and row['outcome'] == 'held':
            fixed.append(row['scenario_id'])
        elif old == 'held' and row['outcome'] == 'violation':
            regressed.append(row['scenario_id'])
        elif row['outcome'] == 'inconclusive':
            unresolved.append(row['scenario_id'])
    return {'fixed': fixed, 'regressed': regressed, 'inconclusive': unresolved, 'campaign_digest': after['campaign_digest']}
