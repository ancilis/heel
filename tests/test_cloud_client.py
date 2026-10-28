"""Strict machine client for Heel's closed cloud control-plane surface."""
from __future__ import annotations

import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import threading
import unittest
from contextlib import contextmanager
from unittest.mock import patch

from heel.cloud_auth import DeviceCredentials, StoredDeviceCredentials
from heel.cloud_client import CloudClient, CloudClientError, HttpResponse
from heel.sync_queue import (
    RetryState,
    StoredHumanApproval,
    StoredTransmission,
    StoredTransportApproval,
    SyncRecord,
    SyncTransmissionPermit,
)


ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = "ws_0123456789abcdef"
PROJECT = "prj_0123456789abcdef0123456789abcdef"
NAMESPACE_KEY = bytes(range(32))


class FakeCredentialStore:
    def __init__(self, credentials=None, *, cloud_base_url="https://heel.example", fail_save=False):
        self.cloud_base_url = cloud_base_url
        self.credentials = credentials
        self.saved = []
        self.deleted = False
        self.fail_save = fail_save

    def load(self):
        return self.credentials

    def save(self, credentials):
        if self.fail_save:
            raise OSError("synthetic storage failure")
        self.credentials = StoredDeviceCredentials(
            schema_version="heel.stored-device-credentials.v1",
            cloud_base_url=credentials.cloud_base_url,
            device_id=credentials.device_id,
            refresh_token=credentials.refresh_token,
            refresh_expires_at=credentials.refresh_expires_at,
        )
        self.saved.append(credentials)

    def delete(self):
        self.deleted = True
        self.credentials = None

    @contextmanager
    def refresh_lock(self):
        yield


class FakeTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url, dict(headers), body))
        if not self.responses:
            raise AssertionError("unexpected transport call")
        result = self.responses.pop(0)
        if isinstance(result, BaseException):
            raise result
        return result


def response(status, value):
    return HttpResponse(
        status=status,
        headers={"content-type": "application/json"},
        body=json.dumps(value, separators=(",", ":")).encode(),
    )


def credentials(*, access_expires_at=2_000, cloud_base_url="https://heel.example"):
    return DeviceCredentials(
        schema_version="heel.device-credentials.v1",
        cloud_base_url=cloud_base_url,
        device_id="dev_" + "a" * 32,
        access_token="heel_at_" + "A" * 43,
        access_expires_at=access_expires_at,
        refresh_token="heel_rt_" + "B" * 64,
        refresh_expires_at=3_000,
    )


def stored_credentials(*, cloud_base_url="https://heel.example"):
    value = credentials(cloud_base_url=cloud_base_url)
    return StoredDeviceCredentials(
        schema_version="heel.stored-device-credentials.v1",
        cloud_base_url=value.cloud_base_url,
        device_id=value.device_id,
        refresh_token=value.refresh_token,
        refresh_expires_at=value.refresh_expires_at,
    )


def token_response(access="C", refresh="D"):
    return {
        "schema_version": "heel.device-token-response.v1",
        "token_type": "Bearer",
        "access_token": "heel_at_" + access * 43,
        "expires_in": 900,
        "refresh_token": "heel_rt_" + refresh * 64,
        "refresh_expires_in": 2_592_000,
        "device_id": "dev_" + "a" * 32,
        "workspace_id": WORKSPACE,
        "capabilities": ["sync_findings", "view_synced_reviews"],
    }


def transmission_permit(request_json: str, digest: str, *, expires_at: float = 1_600.0):
    lease_token = "fsl_" + "2" * 32
    permit_token = "fst_" + "3" * 32
    record = SyncRecord(
        "heel.sync-queue-record.v1",
        WORKSPACE,
        PROJECT,
        digest,
        request_json,
        StoredHumanApproval(999.0, expires_at),
        StoredTransportApproval("fsauth_" + "1" * 32, digest, 999.0, expires_at),
        StoredTransmission(permit_token, lease_token, digest, 1_000.0, expires_at),
        RetryState(1, 1_000.0, None, lease_token, expires_at),
        None,
    )
    return SyncTransmissionPermit(permit_token, 1_000.0, expires_at, record)


class CloudClientTests(unittest.TestCase):
    def test_device_start_poll_and_exchange_are_exact_and_store_validated_tokens(self):
        transport = FakeTransport([
            response(201, {
                "schema_version": "heel.device-start-response.v1",
                "device_code": "heel_dev_" + "a" * 43,
                "user_code": "ABCD-EFGH",
                "verification_uri": "https://heel.example/device",
                "expires_in": 600,
                "interval": 5,
            }),
            response(200, {
                "schema_version": "heel.device-poll-response.v1",
                "status": "approved",
            }),
            response(200, token_response()),
        ])
        store = FakeCredentialStore()
        client = CloudClient("https://heel.example", store, transport=transport, now=lambda: 1_000)

        login = client.start_device_login("Alice's MacBook")
        self.assertEqual((login.user_code, login.verification_uri),
                         ("ABCD-EFGH", "https://heel.example/device"))
        start_body = json.loads(transport.calls[0][3])
        self.assertEqual(set(start_body), {
            "schema_version", "client_id", "device_name", "device_challenge",
        })
        self.assertRegex(login.device_verifier, r"heel_dv_[A-Za-z0-9_-]{43}\Z")
        expected = base64.urlsafe_b64encode(
            hashlib.sha256(login.device_verifier.encode()).digest()
        ).decode().rstrip("=")
        self.assertEqual(start_body["device_challenge"], expected)
        self.assertEqual(client.poll_device_login(login).status, "approved")
        issued = client.exchange_device_login(login)
        self.assertEqual(issued.workspace_id, WORKSPACE)
        self.assertFalse(hasattr(store.credentials, "access_token"))
        self.assertEqual(issued.credentials.access_token, "heel_at_" + "C" * 43)
        self.assertEqual([call[1] for call in transport.calls], [
            "https://heel.example/api/control-plane/v1/device/start",
            "https://heel.example/api/control-plane/v1/device/poll",
            "https://heel.example/api/control-plane/v1/device/token",
        ])

    def test_expired_access_refreshes_once_before_authenticated_request(self):
        transport = FakeTransport([
            response(200, token_response("E", "F")),
            response(200, {"projects": [{
                "workspace_id": WORKSPACE,
                "project_ref": PROJECT,
                "name": "Production API",
                "created_by": "usr_0123456789abcdef",
                "created_at": 1_000,
            }]}),
        ])
        store = FakeCredentialStore(stored_credentials())
        client = CloudClient("https://heel.example", store, transport=transport, now=lambda: 1_000)

        projects = client.list_projects(WORKSPACE)
        self.assertEqual(projects[0].project_ref, PROJECT)
        refresh_body = json.loads(transport.calls[0][3])
        self.assertEqual(refresh_body, {
            "schema_version": "heel.device-refresh.v1",
            "grant_type": "refresh_token",
            "refresh_token": "heel_rt_" + "B" * 64,
        })
        self.assertEqual(
            transport.calls[1][2]["Authorization"], "Bearer " + "heel_at_" + "E" * 43,
        )
        self.assertEqual(len(store.saved), 1)

    def test_account_status_is_exact_and_workspace_bound(self):
        transport = FakeTransport([response(200, {
            "principal": "device_session",
            "device_id": "dev_" + "a" * 32,
            "workspace_id": WORKSPACE,
            "role": "member",
            "capabilities": ["sync_findings", "view_synced_reviews"],
        })])
        client = CloudClient(
            "https://heel.example", FakeCredentialStore(stored_credentials()),
            transport=transport, now=lambda: 1_000,
        )
        client._access = credentials()

        status = client.account_status()

        self.assertEqual(status.workspace_ref, WORKSPACE)
        self.assertEqual(status.role, "member")
        self.assertEqual(transport.calls[0][1], "https://heel.example/api/control-plane/v1/me")

    def test_one_401_refresh_retry_is_bounded(self):
        transport = FakeTransport([
            response(401, {"error": "invalid device token", "code": "invalid_grant"}),
            response(200, token_response("E", "F")),
            response(401, {"error": "invalid device token", "code": "invalid_grant"}),
        ])
        store = FakeCredentialStore(stored_credentials())
        client = CloudClient("https://heel.example", store, transport=transport, now=lambda: 1_000)
        client._access = credentials()
        with self.assertRaises(CloudClientError) as caught:
            client.list_projects(WORKSPACE)
        self.assertEqual(caught.exception.code, "auth_required")
        self.assertEqual(len(transport.calls), 3)

    def test_approval_sync_and_history_use_only_fixed_paths_and_exact_bytes(self):
        request_json = (ROOT / "tests/fixtures/findings_sync/request-one-finding.json").read_text().strip()
        digest = hashlib.sha256(request_json.encode()).hexdigest()
        receipt = json.loads(
            (ROOT / "tests/fixtures/findings_sync/receipt-created.json").read_text()
        )
        transport = FakeTransport([
            response(201, {
                "workspace_id": WORKSPACE,
                "project_ref": PROJECT,
                "approval_id": "fsauth_" + "1" * 32,
                "request_digest": digest,
                "approved_by": "dev_" + "a" * 32,
                "approved_at": 1_000.0,
                "expires_at": 1_600.0,
            }),
            response(201, receipt),
            response(200, {"reviews": []}),
        ])
        store = FakeCredentialStore(stored_credentials())
        client = CloudClient("https://heel.example", store, transport=transport, now=lambda: 1_000)
        client._access = credentials()

        approval = client.approve_findings(WORKSPACE, PROJECT, digest)
        self.assertEqual(approval.request_digest, digest)
        permit = transmission_permit(request_json, digest)
        accepted = client.sync_findings(permit, NAMESPACE_KEY)
        self.assertEqual(accepted["request_digest"], digest)
        self.assertEqual(client.list_history(WORKSPACE, PROJECT), ())
        self.assertEqual(json.loads(transport.calls[0][3]), {"request_digest": digest})
        self.assertEqual(transport.calls[1][3].decode(), request_json)
        self.assertEqual(transport.calls[1][2]["Idempotency-Key"], f"fs1-{digest}")
        for _, url, _, body in transport.calls:
            self.assertNotIn("raw_review", url)
            self.assertNotIn("openapi", url.lower())
            self.assertNotIn("raw_review", body.decode() if body else "")

    def test_logout_revokes_then_deletes_and_unknown_response_data_never_echoes(self):
        secret = "private-control-plane-detail"
        transport = FakeTransport([
            response(200, {"schema_version": "heel.device-revoke-response.v1", "ok": True}),
            response(200, {"projects": [], "raw_review": secret}),
        ])
        store = FakeCredentialStore(stored_credentials())
        client = CloudClient("https://heel.example", store, transport=transport, now=lambda: 1_000)
        client.logout()
        self.assertTrue(store.deleted)
        self.assertNotIn("Authorization", transport.calls[0][2])

        store.credentials = stored_credentials()
        client._access = credentials()
        with self.assertRaises(CloudClientError) as caught:
            client.list_projects(WORKSPACE)
        self.assertEqual(caught.exception.code, "invalid_response")
        self.assertNotIn(secret, str(caught.exception))

    def test_non_https_origin_redirect_and_oversized_or_duplicate_json_fail_closed(self):
        with self.assertRaises(ValueError):
            CloudClient("http://heel.example", FakeCredentialStore(), transport=FakeTransport([]))
        for result in (
            HttpResponse(302, {"location": "https://attacker.invalid"}, b""),
            HttpResponse(200, {"content-type": "application/json"}, b"{" + b"x" * (256 * 1024)),
            HttpResponse(200, {"content-type": "application/json"}, b'{"projects":[],"projects":[]}'),
        ):
            client = CloudClient(
                "https://heel.example", FakeCredentialStore(stored_credentials()),
                transport=FakeTransport([result]), now=lambda: 1_000,
            )
            client._access = credentials()
            with self.assertRaises(CloudClientError):
                client.list_projects(WORKSPACE)

    def test_private_or_noncanonical_request_is_rejected_before_transport(self):
        request = json.loads(
            (ROOT / "tests/fixtures/findings_sync/request-one-finding.json").read_text()
        )
        request["raw_review"] = {"openapi": "private"}
        request_json = json.dumps(request, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(request_json.encode()).hexdigest()
        transport = FakeTransport([])
        client = CloudClient(
            "https://heel.example", FakeCredentialStore(stored_credentials()),
            transport=transport, now=lambda: 1_000,
        )
        client._access = credentials()

        with self.assertRaises(CloudClientError) as caught:
            client.sync_findings(transmission_permit(request_json, digest), NAMESPACE_KEY)

        self.assertEqual(caught.exception.code, "invalid_request")
        self.assertEqual(transport.calls, [])

    def test_refresh_uncertainty_and_save_failure_delete_durable_grant(self):
        for responses, fail_save, expected in (
            ([CloudClientError("unavailable")], False, "unavailable"),
            ([response(200, token_response("E", "F"))], True, "unavailable"),
            ([response(401, {
                "schema_version": "heel.device-error.v1",
                "code": "refresh_reuse_detected",
            })], False, "refresh_reuse_detected"),
        ):
            with self.subTest(fail_save=fail_save, expected=expected):
                store = FakeCredentialStore(stored_credentials(), fail_save=fail_save)
                client = CloudClient(
                    "https://heel.example", store,
                    transport=FakeTransport(responses), now=lambda: 1_000,
                )
                with self.assertRaises(CloudClientError) as caught:
                    client.refresh()
                self.assertEqual(caught.exception.code, expected)
                self.assertTrue(store.deleted)
                self.assertIsNone(store.credentials)

    def test_credential_store_origin_mismatch_fails_before_network(self):
        transport = FakeTransport([])
        with self.assertRaises(ValueError):
            CloudClient(
                "https://heel.example",
                FakeCredentialStore(cloud_base_url="https://other.example"),
                transport=transport,
            )
        self.assertEqual(transport.calls, [])

    def test_exact_status_receipt_media_type_and_route_table_fail_closed(self):
        request_json = (
            ROOT / "tests/fixtures/findings_sync/request-one-finding.json"
        ).read_text().strip()
        digest = hashlib.sha256(request_json.encode()).hexdigest()
        receipt = (
            ROOT / "tests/fixtures/findings_sync/receipt-created.json"
        ).read_bytes()
        for result, operation in (
            (response(201, {"projects": []}), "projects"),
            (HttpResponse(201, {"content-type": "text/plain"}, receipt), "sync"),
        ):
            with self.subTest(operation=operation):
                transport = FakeTransport([result])
                client = CloudClient(
                    "https://heel.example", FakeCredentialStore(stored_credentials()),
                    transport=transport, now=lambda: 1_000,
                )
                client._access = credentials()
                with self.assertRaises(CloudClientError) as caught:
                    if operation == "projects":
                        client.list_projects(WORKSPACE)
                    else:
                        client.sync_findings(
                            transmission_permit(request_json, digest), NAMESPACE_KEY
                        )
                self.assertEqual(caught.exception.code, "invalid_response")

    def test_sync_requires_a_live_transmission_permit_before_opening_transport(self):
        request_json = (
            ROOT / "tests/fixtures/findings_sync/request-one-finding.json"
        ).read_text().strip()
        digest = hashlib.sha256(request_json.encode()).hexdigest()
        transport = FakeTransport([])
        client = CloudClient(
            "https://heel.example", FakeCredentialStore(stored_credentials()),
            transport=transport, now=lambda: 1_601,
        )
        client._access = credentials()

        with self.assertRaises(TypeError):
            client.sync_findings(WORKSPACE, PROJECT, request_json, digest, NAMESPACE_KEY)
        with self.assertRaises(CloudClientError) as caught:
            client.sync_findings(
                transmission_permit(request_json, digest, expires_at=1_600),
                NAMESPACE_KEY,
            )

        self.assertEqual(caught.exception.code, "approval_expired")
        self.assertEqual(transport.calls, [])

    def test_sync_rechecks_permit_after_credential_refresh_before_sending(self):
        request_json = (
            ROOT / "tests/fixtures/findings_sync/request-one-finding.json"
        ).read_text().strip()
        digest = hashlib.sha256(request_json.encode()).hexdigest()
        clock = iter((1_000, 1_000, 1_000, 1_601))
        transport = FakeTransport([response(200, token_response())])
        store = FakeCredentialStore(stored_credentials())
        client = CloudClient(
            "https://heel.example", store, transport=transport, now=lambda: next(clock),
        )
        client._access = credentials(access_expires_at=999)

        with self.assertRaises(CloudClientError) as caught:
            client.sync_findings(
                transmission_permit(request_json, digest, expires_at=1_600),
                NAMESPACE_KEY,
            )

        self.assertEqual(caught.exception.code, "approval_expired")
        self.assertEqual(len(transport.calls), 1)
        self.assertTrue(transport.calls[0][1].endswith("/v1/device/refresh"))

        transport = FakeTransport([])
        client = CloudClient(
            "https://heel.example", FakeCredentialStore(stored_credentials()),
            transport=transport,
        )
        for method, path in (
            ("GET", "/v1/workspaces/../projects"),
            ("POST", "/v1/device/%72efresh"),
            ("DELETE", "/v1/device/revoke"),
        ):
            with self.assertRaises(CloudClientError):
                client._request(method, path)
        self.assertEqual(transport.calls, [])

    def test_real_transport_ignores_proxy_environment_and_refuses_redirect(self):
        class RecordingHandler(BaseHTTPRequestHandler):
            hits = 0
            status = 200
            location = None

            def do_GET(self):
                type(self).hits += 1
                self.send_response(type(self).status)
                if type(self).location is not None:
                    self.send_header("Location", type(self).location)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"projects":[]}')

            def log_message(self, _format, *_args):
                return

        class TargetHandler(RecordingHandler):
            hits = 0

        class ProxyHandler(RecordingHandler):
            hits = 0

        target = ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)
        proxy = ThreadingHTTPServer(("127.0.0.1", 0), ProxyHandler)
        target_url = f"http://127.0.0.1:{target.server_port}/captured"

        class SourceHandler(RecordingHandler):
            hits = 0
            status = 302
            location = target_url

        source = ThreadingHTTPServer(("127.0.0.1", 0), SourceHandler)
        threads = [threading.Thread(target=server.serve_forever) for server in (target, proxy, source)]
        for thread in threads:
            thread.start()
        origin = f"http://127.0.0.1:{source.server_port}"
        try:
            store = FakeCredentialStore(
                stored_credentials(cloud_base_url=origin), cloud_base_url=origin
            )
            client = CloudClient(origin, store, now=lambda: 1_000)
            client._access = credentials(cloud_base_url=origin)
            proxy_url = f"http://127.0.0.1:{proxy.server_port}"
            with patch.dict(os.environ, {
                "HTTP_PROXY": proxy_url,
                "HTTPS_PROXY": proxy_url,
                "ALL_PROXY": proxy_url,
                "NO_PROXY": "",
            }, clear=False):
                with self.assertRaises(CloudClientError) as caught:
                    client.list_projects(WORKSPACE)
            self.assertEqual(caught.exception.code, "invalid_response")
            self.assertEqual(SourceHandler.hits, 1)
            self.assertEqual(TargetHandler.hits, 0)
            self.assertEqual(ProxyHandler.hits, 0)
        finally:
            for server in (source, proxy, target):
                server.shutdown()
                server.server_close()
            for thread in threads:
                thread.join(2)


if __name__ == "__main__":
    unittest.main()
