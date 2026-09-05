"""A tiny reference SaaS product with actual server-side account/entitlement behavior.

This application has no socket, external target, billing provider, or customer data.
Its account table is independent of Heel's scenario metadata and semantic role names.
"""
from __future__ import annotations

import json

CASES = ('vulnerable', 'hardened', 'error_envelope', 'redacted', 'public', 'inconclusive')
MARKER = 'heel-canary-export-row'
ROUTE = '/exports/' + MARKER


class ExportProduct:
    def __init__(self, variant: str):
        if variant not in CASES:
            raise ValueError('unknown reference variant')
        self.variant = variant
        self.accounts = {
            'synthetic-basic-session': {'plan': 'community', 'export_license': False},
            'synthetic-paid-session': {'plan': 'researcher', 'export_license': True},
        }
        self.records = {'protected_canary': MARKER, 'records': [{'name': 'Synthetic row'}]}
        self.reads = 0

    def get(self, route: str, session: str) -> tuple[int, bytes]:
        self.reads += 1
        if self.reads > 2:
            raise ValueError('reference read budget exhausted')
        if route != ROUTE:
            return 404, b'{"error":"not found"}'
        account = self.accounts.get(session)
        if account is None:
            return 401, b'{"error":"sign in"}'
        # Different vocabulary is deliberate; Heel observes serialized content.
        if self.variant == 'inconclusive':
            return 200, b'{"message":"export pending"}'
        if not account['export_license'] and self.variant != 'vulnerable':
            if self.variant == 'error_envelope':
                return 200, b'{"error":"license required"}'
            if self.variant in {'public', 'redacted'}:
                return 200, json.dumps({'visibility': self.variant, 'id': MARKER}).encode()
            return 403, b'{"error":"license required"}'
        return 200, json.dumps(self.records).encode()
