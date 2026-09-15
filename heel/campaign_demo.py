"""Independent local HTTP SaaS fixture: account state, entitlement and commercial ledgers.

Deliberately vulnerable by default. It binds only 127.0.0.1 and stores synthetic data
in memory. It is a fixture application, not a production service or target adapter.
"""
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading


class DemoProduct:
    def __init__(self, hardened=False):
        self.hardened = hardened
        self.accounts = {}
        self.lock = threading.Lock()

    def handle(self, method, path, actor, key):
        pieces = path.strip('/').split('/')
        if len(pieces) != 3 or not pieces[0].startswith('heel-canary-'):
            return 404, {'error': 'fixture missing'}
        subject, feature, operation = pieces
        namespace = (subject, feature)
        if actor not in {'heel-canary-owner', 'heel-canary-outsider'}:
            return 401, {'error': 'canary credential required'}
        with self.lock:
            if operation == 'reset' and actor == 'heel-canary-owner':
                if method == 'DELETE':
                    self.accounts.pop(namespace, None)
                    return 200, {'removed': True}
                if method == 'POST':
                    if len(self.accounts) >= 200:
                        return 429, {'error': 'fixture capacity'}
                    self.accounts[namespace] = {'subject': subject, 'identity': subject, 'benefits': 0,
                        'usage': 0, 'fulfilled': 0, 'paid': True, 'trial_claimed': False,
                        'promotion_claimed': False, 'idempotency': set(), 'approved': False}
                    return 200, {'created': True}
            account = self.accounts.get(namespace)
            if account is None:
                return 404, {'error': 'fixture missing'}
            if method == 'GET' and operation == 'export':
                allowed = actor == 'heel-canary-owner' and account['paid']
                if self.hardened and not allowed:
                    return 200, {'denied': True}
                return 200, {'protected_canary': subject, 'records': [{'synthetic': True}]}
            if actor != 'heel-canary-owner':
                return 403, {'error': 'owner required'}
            if method == 'GET' and operation == 'state':
                return 200, {'fixture': subject, **{field: account[field] for field in ('benefits', 'usage', 'fulfilled')}}
            if method != 'POST':
                return 405, {'error': 'method'}
            if operation == 'claim-trial':
                if self.hardened and account['trial_claimed']:
                    return 409, {'error': 'subject already eligible once'}
                account['trial_claimed'] = True
                account['benefits'] += 1
            elif operation == 'change-identity':
                account['identity'] += '-changed'
            elif operation.startswith('promotion-'):
                if self.hardened and account['promotion_claimed']:
                    return 409, {'error': 'promotion allowance consumed'}
                account['promotion_claimed'] = True
                account['benefits'] += 1
            elif operation in {'consume-ui', 'consume-api'}:
                if feature == 'quota' and self.hardened and account['usage'] >= 1:
                    return 403, {'error': 'quota reached'}
                if not (feature == 'usage_accounting' and operation == 'consume-api' and not self.hardened):
                    account['usage'] += 1
            elif operation == 'downgrade':
                account['paid'] = False
            elif operation == 'grant-benefit':
                if self.hardened and key in account['idempotency']:
                    return 200, {'replayed': True}
                account['idempotency'].add(key)
                account['benefits'] += 1
            elif operation == 'fulfill':
                if self.hardened and not account['approved']:
                    return 409, {'error': 'approval required'}
                account['fulfilled'] += 1
            else:
                return 404, {'error': 'operation'}
            return 200, {'accepted': True}


def make_demo_server(port=8765, *, hardened=False):
    product = DemoProduct(hardened)

    class Handler(BaseHTTPRequestHandler):
        def handle_request(self):
            try:
                size = int(self.headers.get('Content-Length', '0'))
                if not 0 <= size <= 8192:
                    self.send_error(413); return
                self.rfile.read(size)
                actor = self.headers.get('Authorization', '').removeprefix('Bearer ')
                status, body = product.handle(self.command, self.path, actor, self.headers.get('Idempotency-Key', ''))
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers(); self.wfile.write(data)
            except (ValueError, OSError):
                self.close_connection = True
        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = handle_request
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(('127.0.0.1', port), Handler)
    server.product = product
    return server
