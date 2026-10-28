"""Closed reference-product journey through the signed local canary executor.

Never accepts a URL, transport, credentials, authority keys, or product implementation
from callers. Reference signing authority is ephemeral and trusted only in this run.
It is not a replacement for cloud target verification or production grants.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import time

from .business_rules import ProductRule, exposure, LIFECYCLES
from .canary_contracts import EXECUTION_GRANT_SCHEMA, OPERATIONAL_RUN_SCHEMA, canonical_bytes, canonical_digest
from .crypto import SigningAuthority, ed25519_key_id
from .reference_product import CASES, ExportProduct, MARKER, ROUTE
from .scope import get_scope, verify, target_in_scope, heel_home
from .runner.content_assertion import protected_content
from .runner.catalog import CATALOG_IDS
from .runner.compiler import CanaryCompiler
from .runner.execution import ExecutionBundle, ExecutionGate, LocalCanaryExecutor
from .runner.http_transport import BoundedResponseEvidence, TargetResponse, CancellationToken
from .runner.identity import RunnerIdentity, SecureSigner, runner_phrase_words
from .runner.openapi_routes import RouteInventory
from .runner.store import RunnerContext, RunnerStore

TARGET = 'reference:export'
RULE = ProductRule('paid-export', 'Only export-licensed accounts may receive protected export content',
                   'reference-product commercial policy v1')


def prepare_reference() -> dict:
    return {**exposure(RULE), 'target': TARGET, 'cases': list(CASES),
            'evidence_state': 'inferred', 'result': 'hypothesis', 'execution_disposition': 'not_started',
            'authorization': 'Human-created signed scope for reference:export; unique 32-hex attempt ID',
            'execution_support': 'reference_only', 'lifecycle_sequences': [s.to_dict() for s in LIFECYCLES]}


class _ReferenceSigner(SecureSigner):
    def __init__(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        self._private = Ed25519PrivateKey.generate()
        self.public_key = self._private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.key_id = ed25519_key_id(self.public_key)

    def sign(self, payload):
        return self._private.sign(payload)


class _ReferenceVault:
    supported = True
    backend_id = 'ephemeral_env'

    def __init__(self):
        self.values = {}

    def load(self, handle):
        return self.values[handle]


class _ReferenceTransport:
    def __init__(self, product):
        self.product = product

    def request(self, action, *, credential, cancellation, retry_policy, remaining_requests,
                before_attempt, evidence_context, evidence_sink, redactor):
        cancellation.raise_if_cancelled()
        if action.method != 'GET' or action.route != ROUTE or remaining_requests < 1:
            raise ValueError('reference transport rejects any other action')
        before_attempt(1, None)
        status, body = self.product.get(action.route, credential)
        ref = evidence_sink(BoundedResponseEvidence(
            evidence_context.action_ordinal, action.scenario_id, action.semantic_auth_role,
            'GET', evidence_context.route_template, 1, status,
            b'Content-Type: application/json', body,
        ))
        return TargetResponse(status, 'json_object', len(body), 1, ref, 0)


def _grant(manifest, projection, identity, authority, attempt, now):
    unsigned = {
        'schema_version': EXECUTION_GRANT_SCHEMA, 'grant_id': 'grant_' + attempt,
        'run_id': 'crun_' + attempt, 'workspace_id': manifest['workspace_id'],
        'project_id': manifest['project_id'],
        'approval': {'projection_id': projection['projection_id'],
                     'projection_digest': projection['projection_digest'], 'manifest_digest': manifest['manifest_digest']},
        'environment': manifest['environment'],
        'runner_binding': {'runner_id': identity.runner_id, 'runner_key_id': identity.key_id, 'public_key_digest': identity.fingerprint},
        'approval_actor': {'user_id': 'reference_owner', 'role': 'owner'},
        'approval_reason': 'Human-authorized synthetic export reference only', 'consented_at_ms': now,
        'budgets': manifest['budgets'], 'egress': manifest['egress'], 'retry_policy': manifest['retry_policy'],
        'grant_nonce': 'nonce_' + attempt, 'kill_switch_generation': 0,
        'operational_receipt_policy': {'schema_version': OPERATIONAL_RUN_SCHEMA, 'maximum_bytes': 32768,
            'allowed_error_categories': sorted(['none','platform_fault','runner_fault','target_unavailable','proof_expired','dns_changed','credential_unavailable','version_mismatch','budget_exhausted','containment_rejected','cloud_disconnected']),
            'allowed_stop_reasons': sorted(['none','local_emergency_stop','cloud_stop','runner_revoked','target_revoked','kill_switch']),
            'allowed_containment_codes': sorted(['admitted','action_started','action_completed','action_rejected','budget_exhausted','dns_changed','stop_observed','response_truncated','redacted'])},
        'issued_at_ms': now, 'expires_at_ms': now + 30_000,
    }
    return {**unsigned, 'grant_digest': canonical_digest(unsigned), **authority.sign(canonical_bytes(unsigned))}


def run_reference(scope_id: str, variant: str, attempt: str, *, stop: bool = False) -> dict:
    if variant not in CASES or type(attempt) is not str or re.fullmatch('[0-9a-f]{32}', attempt) is None:
        raise ValueError('invalid reference case or attempt')
    scope = get_scope(scope_id)
    if scope is None or not verify(scope)[0] or not target_in_scope(scope, TARGET):
        raise ValueError('valid human-created reference scope required')
    if scope.data_handling_mode.value != 'synthetic_only' or scope.rate_and_resource_limits.get('max_requests', 0) < 2:
        raise ValueError('scope must permit two synthetic reads')
    # RunnerStore opens and verifies every path component without following symlinks.
    RunnerStore(Path(heel_home()) / 'reference')
    root = Path(heel_home()) / 'reference' / attempt
    os.mkdir(root, 0o700)  # exclusive, durable one-shot attempt barrier (also after crashes)
    signer = _ReferenceSigner()
    identity = RunnerIdentity('runner_reference', 'workspace_reference', '1',
        {key: '1' for key in CATALOG_IDS}, base64.b64encode(signer.public_key).decode(),
        hashlib.sha256(signer.public_key).hexdigest(), signer.key_id, runner_phrase_words()[:6])
    store = RunnerStore(root)
    # This is a sandbox context label; the closed transport never resolves it.
    context = RunnerContext('workspace_reference', 'project_reference', 'environment_reference',
                            'https://reference.heel.dev', '0' * 64, 'sandbox')
    store.bind_context(context, identity=identity, signer=signer, signer_label='reference-ephemeral')
    spec = {'openapi':'3.1.0', 'info':{'title':'Reference Export','version':'1'},
            'paths':{'/exports/{fixture}':{'get':{'operationId':'export', 'x-heel-plan':'licensed'}}}}
    inventory = RouteInventory(spec)
    store.replace_routes(inventory.read_routes(), source_digest=inventory.source_digest)
    store.save_mapping('plan_entitlement_read', method='GET', route_template='/exports/{fixture}',
                       fixture_bindings={'fixture': MARKER})
    vault = _ReferenceVault()
    for role, session in [('lower_plan','synthetic-basic-session'), ('higher_plan','synthetic-paid-session')]:
        record = store.register_ephemeral_credential(semantic_role=role, auth_profile='bearer',
                                                     source_kind='environment', label=role.replace('_',' '))
        vault.values[record['credential_handle_id']] = session.encode()
    now = int(time.time() * 1000)
    compiled = CanaryCompiler(store=store, identity=identity, signer=signer, now_ms=now).compile(['plan_entitlement_read'])
    authority = SigningAuthority.generate()
    grant = _grant(compiled.manifest, compiled.projection, identity, authority, attempt, now)
    cancellation = CancellationToken()
    if stop:
        cancellation.cancel()
    def gate():
        valid = verify(scope)[0]
        return ExecutionGate(valid, 'active', 'valid', min(int(scope.expiry*1000), now+30_000), 0,
                             'none', int(time.time()*1000))
    result = LocalCanaryExecutor(store=store, identity=identity, signer=signer,
        trusted_grant_keys={authority.key_id:authority.public_key}, vaults={'ephemeral_env':vault}).execute(
            ExecutionBundle(compiled.manifest, compiled.projection, grant),
            transport=_ReferenceTransport(ExportProduct(variant)), gate_source=gate, cancellation=cancellation)
    status = {'observed':'verified_violation', 'blocked':'invariant_held', 'inconclusive':'inconclusive'}[result.assessment_outcome]
    content_observations = []
    # Read the same private, integrity-checked evidence; export only predicate results.
    for scenario in result.findings_projection['scenario_results']:
        for observation in scenario['observations']:
            ordinal = 0 if observation['semantic_role'] == 'lower_plan' else 1
            for ref in scenario['local_evidence_refs']:
                # References are unordered in projections. Match via bounded evidence metadata
                # using the action ordinal written by the executor, never by body vocabulary.
                metadata_path = store.run_path(grant['run_id']) / 'evidence' / (ref + '.meta')
                metadata = json.loads(metadata_path.read_text())
                if metadata.get('action_ordinal') != ordinal:
                    continue
                _, body = store.load_response_evidence(grant['run_id'], ref, now_ms=int(time.time()*1000))
                content_observations.append({'actor': observation['semantic_role'],
                    'evidence_state': 'observed', 'protected_content': protected_content(body, marker=MARKER,
                    status=observation['status_code']), 'local_evidence_ref': ref})
    report = {**prepare_reference(), 'case':variant, 'attempt':attempt, 'result':status,
              'evidence_state':'verified' if status != 'inconclusive' else 'unknown',
              'execution_disposition':result.execution_disposition,
              'tested':f'{len(content_observations)} completed GET observations of one synthetic export using independently configured lower and higher plan accounts',
              'provenance':{'kind':'reference_product_execution', 'network_calls':False,
                            'manifest_digest':compiled.manifest['manifest_digest'], 'run_id':grant['run_id']},
              'observations':result.findings_projection['scenario_results'],
              'invariant_observations':content_observations,
              'regression_passed':status == 'invariant_held', 'uploaded':False}
    # Report has only synthetic summaries. Raw evidence remains in the private runner store.
    descriptor = os.open(root / 'report.json', os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, 'w') as output:
        json.dump(report, output, indent=2)
    return report
