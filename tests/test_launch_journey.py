"""End-to-end free-launch journey across browser session, device auth, queue, and cloud API."""
from __future__ import annotations

from contextlib import contextmanager
import http.client
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from urllib.parse import urlsplit

from heel.cloud_auth import DeviceCredentials, StoredDeviceCredentials
from heel.cloud_client import CloudClient, HttpResponse
from heel.findings_sync import project_findings_sync
from heel.review_service import review_openapi
from heel.saas.http_api import ControlPlane, serve
from heel.sync_queue import HumanSyncApproval, SyncQueue


ROOT = Path(__file__).resolve().parents[1]
EDGE_SECRET = "E" * 43


class MemoryCredentialStore:
    cloud_base_url = "https://heel.example"

    def __init__(self):
        self.credentials = None

    def load(self):
        return self.credentials

    def save(self, credentials: DeviceCredentials):
        self.credentials = StoredDeviceCredentials(
            schema_version="heel.stored-device-credentials.v1",
            cloud_base_url=credentials.cloud_base_url,
            device_id=credentials.device_id,
            refresh_token=credentials.refresh_token,
            refresh_expires_at=credentials.refresh_expires_at,
        )

    def delete(self):
        self.credentials = None

    @contextmanager
    def refresh_lock(self):
        yield


class PrivateEdgeTransport:
    def __init__(self, port: int):
        self.port = port

    def __call__(self, method, url, headers, body):
        parsed = urlsplit(url)
        prefix = "/api/control-plane"
        if parsed.scheme != "https" or parsed.netloc != "heel.example" or not parsed.path.startswith(prefix):
            raise AssertionError("cloud client escaped the fixed public origin")
        path = parsed.path[len(prefix):]
        forwarded = dict(headers)
        forwarded["X-Heel-Edge-Auth"] = EDGE_SECRET
        if path == "/v1/device/start":
            forwarded["X-Heel-Client-Key"] = "a" * 64
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        connection.request(method, path, body, forwarded)
        response = connection.getresponse()
        result = HttpResponse(response.status, dict(response.getheaders()), response.read())
        connection.close()
        return result


class FreeLaunchJourneyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cp = ControlPlane(
            device_token_pepper=b"d" * 32,
            enable_device_auth=True,
            public_origin="https://heel.example",
            edge_auth_secret=EDGE_SECRET,
            trust_edge_client_key=True,
        )
        cls.server = serve(cls.cp)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def browser_request(self, method, path, value, headers=None):
        payload = json.dumps(value, separators=(",", ":")).encode()
        request_headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(payload)),
            "X-Heel-Edge-Auth": EDGE_SECRET,
            **(headers or {}),
        }
        if path == "/v1/signup":
            request_headers["X-Heel-Client-Key"] = "b" * 64
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        connection.request(method, path, payload, request_headers)
        response = connection.getresponse()
        body = json.loads(response.read())
        cookie = response.getheader("Set-Cookie")
        status = response.status
        connection.close()
        return status, body, cookie

    def test_customer_gets_local_value_then_explicitly_keeps_only_minimized_findings(self):
        status, account, cookie = self.browser_request("POST", "/v1/signup", {
            "email": "launch@example.com",
            "password": "correct-horse-staple-42",
        })
        self.assertEqual(status, 201)
        workspace = account["workspace_id"]
        session_cookie = cookie.split(";", 1)[0]
        status, project, _ = self.browser_request(
            "POST",
            f"/v1/workspaces/{workspace}/projects",
            {"name": "Launch API"},
            {"Cookie": session_cookie},
        )
        self.assertEqual(status, 201)
        project_ref = project["project_ref"]

        client = CloudClient(
            "https://heel.example",
            MemoryCredentialStore(),
            transport=PrivateEdgeTransport(self.port),
        )
        login = client.start_device_login("Launch laptop")
        status, claim, _ = self.browser_request(
            "POST", "/v1/device/verify",
            {
                "schema_version": "heel.device-verify.v1",
                "user_code": login.user_code,
                "action": "inspect",
            },
            {
                "Cookie": session_cookie,
                "Origin": "https://heel.example",
                "X-Heel-Internal-Origin": "same-origin",
            },
        )
        self.assertEqual(status, 200)
        status, decision, _ = self.browser_request(
            "POST", "/v1/device/verify",
            {
                "schema_version": "heel.device-verify.v1",
                "user_code": login.user_code,
                "action": "approve",
                "workspace_id": workspace,
                "confirmation_nonce": claim["confirmation_nonce"],
            },
            {
                "Cookie": session_cookie,
                "Origin": "https://heel.example",
                "X-Heel-Internal-Origin": "same-origin",
            },
        )
        self.assertEqual((status, decision["status"]), (200, "approved"))
        self.assertEqual(client.poll_device_login(login).status, "approved")
        client.exchange_device_login(login)
        self.assertEqual(client.account_status().workspace_ref, workspace)

        spec = json.loads(
            (ROOT / "tests/fixtures/openapi/saas_api.json").read_text(encoding="utf-8")
        )
        review = review_openapi(spec, execution_mode="machine_local")
        namespace_key = client.namespace_key(workspace, project_ref)
        request = project_findings_sync(review, project_ref, namespace_key)
        with tempfile.TemporaryDirectory() as tmp:
            queue = SyncQueue(root=Path(tmp).resolve(strict=True) / "heel-home")
            prepared = queue.prepare(request, namespace_key, workspace)
            approved_at = time.time()
            queue.record_human_approval(HumanSyncApproval(
                workspace,
                project_ref,
                prepared.request_digest,
                approved_at,
                approved_at + 300,
            ))
            lease = queue.claim(workspace, project_ref, prepared.request_digest)
            self.assertIsNotNone(lease)
            transport_approval = client.approve_findings(
                workspace, project_ref, prepared.request_digest,
            )
            bound = queue.bind_transport_approval(lease, transport_approval)
            self.assertIsNotNone(bound)
            renewed = queue.renew(bound)
            self.assertIsNotNone(renewed)
            permit = queue.begin_transmission(renewed)
            self.assertIsNotNone(permit)
            receipt = client.sync_findings(permit, namespace_key)
            self.assertTrue(queue.complete(permit, receipt))

        history = client.list_history(workspace, project_ref)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["projection_hash"], request["projection_hash"])
        serialized = json.dumps(request, sort_keys=True)
        self.assertNotIn("openapi", serialized.lower())
        self.assertNotIn("raw_review", serialized)
        self.assertNotIn("questions", serialized)


if __name__ == "__main__":
    unittest.main()
