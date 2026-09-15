"""Single-origin, bounded HTTP for explicitly approved sandbox campaigns."""
from __future__ import annotations

import hashlib
import http.client
import socket
import ssl
import threading
import time
from urllib.parse import urlsplit

from .campaign_contract import MAX_RESPONSE, canonical, strict_json, validate_origin
from .runner.http_transport import BoundedResolver, select_public_addresses


class CampaignFailure(ValueError):
    """Only fixed public reason codes leave the transport."""


class CampaignTransport:
    def __init__(self, plan, cancellation):
        validate_origin(plan['origin'], plan['environment'])
        self.plan = plan
        self.cancellation = cancellation
        self.pinned = None
        self.last_request = 0.0

    def request(self, step, actor, credentials, deadline):
        if self.cancellation.is_set():
            raise CampaignFailure('cancelled')
        origin = urlsplit(self.plan['origin'])
        host = origin.hostname
        timeout = min(self.plan['limits']['timeout_seconds'], deadline - time.monotonic())
        if timeout <= 0:
            raise CampaignFailure('duration_exhausted')
        started = time.monotonic()
        if self.plan['environment'] == 'loopback':
            address, port = '127.0.0.1', origin.port
        else:
            try:
                addresses = tuple(str(ip) for ip in select_public_addresses(BoundedResolver()(host, deadline=started + timeout)))
            except Exception:
                raise CampaignFailure('unsafe_or_unavailable_dns') from None
            if self.pinned is not None and addresses != self.pinned:
                raise CampaignFailure('dns_changed')
            self.pinned = addresses
            address, port = addresses[0], 443
        timeout -= time.monotonic() - started
        if timeout <= 0:
            raise CampaignFailure('timeout')
        headers = {'Accept': 'application/json', 'Accept-Encoding': 'identity', 'Connection': 'close', 'User-Agent': 'Heel-Canary-Campaign/1'}
        if actor['auth'] != 'anonymous':
            secret = credentials.get(actor['credential_env'])
            if type(secret) is not str or not 1 <= len(secret) <= 4096 or any(ord(c) < 33 or ord(c) > 126 for c in secret):
                raise CampaignFailure('credential_unavailable')
            headers['Authorization' if actor['auth'] == 'bearer' else 'X-API-Key'] = ('Bearer ' if actor['auth'] == 'bearer' else '') + secret
        if 'idempotency_key' in step:
            headers['Idempotency-Key'] = step['idempotency_key']
        body = canonical(step['json']).encode() if 'json' in step else None
        if body is not None:
            headers['Content-Type'] = 'application/json'

        sockets = []
        cancellation = self.cancellation
        class PinnedConnection(http.client.HTTPConnection):
            def connect(connection):
                connection.sock = socket.create_connection((address, port), timeout=timeout)
                sockets.append(connection.sock)
                if connection.sock.getpeername()[0] != address:
                    connection.close()
                    raise CampaignFailure('peer_mismatch')
                if origin.scheme == 'https':
                    connection.sock = ssl.create_default_context().wrap_socket(connection.sock, server_hostname=host)
                    sockets.append(connection.sock)
                if cancellation.is_set() or time.monotonic() >= deadline:
                    connection.close()
                    raise CampaignFailure('cancelled_or_duration_exhausted')

        connection = PinnedConnection(host, port=port, timeout=timeout)
        finished = threading.Event()
        timed_out = threading.Event()

        def watchdog():
            while not finished.wait(0.02):
                if self.cancellation.is_set() or time.monotonic() >= started + self.plan['limits']['timeout_seconds'] or time.monotonic() >= deadline:
                    timed_out.set()
                    for sock in sockets:
                        try:
                            sock.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass
                    connection.close()
                    return

        worker = threading.Thread(target=watchdog, daemon=True)
        worker.start()
        try:
            if self.cancellation.is_set() or time.monotonic() >= deadline:
                raise CampaignFailure('cancelled')
            connection.request(step['method'], step['path'], body=body, headers=headers)
            response = connection.getresponse()
            if 300 <= response.status < 400:
                raise CampaignFailure('redirect_rejected')
            if response.status == 429:
                raise CampaignFailure('throttled')
            if response.getheader('Content-Encoding', 'identity') != 'identity':
                raise CampaignFailure('encoded_response_rejected')
            data = response.read(MAX_RESPONSE + 1)
            if len(data) > MAX_RESPONSE:
                raise CampaignFailure('response_too_large')
            if timed_out.is_set() or self.cancellation.is_set():
                raise CampaignFailure('cancelled_or_timeout')
            result = {'status': response.status, 'sha256': hashlib.sha256(data).hexdigest(),
                      'bytes': len(data), 'duration_ms': round((time.monotonic()-started)*1000)}
            try:
                decoded = strict_json(data)
                if type(decoded) in {dict, list}:
                    result['body'] = decoded
            except (ValueError, UnicodeError, RecursionError):
                pass
            return result
        except CampaignFailure:
            raise
        except (OSError, http.client.HTTPException, ValueError):
            raise CampaignFailure('transport_unavailable') from None
        finally:
            finished.set()
            connection.close()
            for sock in sockets:
                sock.close()
            worker.join(timeout=0.1)
