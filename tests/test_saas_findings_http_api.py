"""HTTP contract tests for hosted projects and findings-only continuity."""
from __future__ import annotations

import copy
import concurrent.futures
import http.client
import json
from pathlib import Path
import re
import socket
import threading
import time
import unittest

import heel.saas.http_api as http_api_module
from heel.findings_sync import (
    FINDINGS_SYNC_RECEIPT_SCHEMA_VERSION,
    MAX_FINDINGS_SYNC_BYTES,
    findings_sync_request_digest,
    project_findings_sync,
    stable_json,
)
from heel.review_service import review_openapi
from heel.saas.catalog import CATALOG_VERSION, Meter
from heel.saas.http_api import ControlPlane, current_period, serve
from heel.saas.projects import ProjectStore
from heel.saas.tenancy import Role


ROOT = Path(__file__).resolve().parents[1]
SPEC = json.loads((ROOT / "tests/fixtures/openapi/saas_api.json").read_text())
HEX_KEY = re.compile(r"[0-9a-f]{64}\Z")


def _sync_request(project_ref: str, namespace_key: bytes, *, title: str):
    spec = copy.deepcopy(SPEC)
    spec["info"]["title"] = title
    review = review_openapi(spec, execution_mode="machine_local")
    return project_findings_sync(review, project_ref, namespace_key)


class FindingsHttpApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cp = ControlPlane()
        cls.projects = ProjectStore(cls.cp.store.conn)
        cls.org = cls.cp.store.create_org("Acme")
        cls.workspace = cls.cp.store.create_workspace(
            cls.org, "Acme", "pro", CATALOG_VERSION,
        )
        cls.other_workspace = cls.cp.store.create_workspace(
            cls.org, "Other", "pro", CATALOG_VERSION,
        )

        cls.headers = {}
        for role in (Role.OWNER, Role.ADMIN, Role.MEMBER, Role.VIEWER, Role.BILLING):
            user_id = cls.cp.store.create_user(f"findings-{role.value}@example.test")
            cls.cp.store.add_member(cls.workspace, user_id, role)
            session = cls.cp.auth.create_session(user_id)
            cls.headers[role] = {
                "Cookie": f"heel_session={session.token}",
            }
            if role is Role.OWNER:
                cls.owner_id = user_id

        other_owner = cls.cp.store.create_user("findings-other@example.test")
        cls.cp.store.add_member(cls.other_workspace, other_owner, Role.OWNER)
        other_session = cls.cp.auth.create_session(other_owner)
        cls.other_headers = {"Cookie": f"heel_session={other_session.token}"}

        member_key = cls.cp.store.issue_api_key(
            cls.workspace, Role.MEMBER, "findings test client",
        )
        cls.api_key_id = member_key.key_id
        cls.api_key_headers = {
            "Authorization": f"Bearer {member_key.secret}",
        }

        cls.server = serve(cls.cp)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=10)

    def _raw_request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, bytes]:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        raw = response.read()
        status = response.status
        conn.close()
        return status, raw

    def _request(
        self,
        method: str,
        path: str,
        body=None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict]:
        request_headers = dict(headers or {})
        data = None
        if body is not None:
            data = json.dumps(body, separators=(",", ":")).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")
        status, raw = self._raw_request(method, path, data, request_headers)
        return status, json.loads(raw) if raw else {}

    def _raw_http(self, request: bytes) -> tuple[int, bytes]:
        connection = socket.create_connection(("127.0.0.1", self.port), timeout=2)
        self.addCleanup(connection.close)
        connection.sendall(request)
        response = http.client.HTTPResponse(connection)
        response.begin()
        return response.status, response.read()

    def _seed_project(self, name: str):
        project = self.projects.create(
            self.workspace, name, created_by=self.owner_id,
        )
        key = self.projects.namespace_key(self.workspace, project.project_ref)
        return project, key

    def _approve(self, project_ref: str, digest: str, *, headers=None):
        return self._request(
            "POST",
            f"/v1/workspaces/{self.workspace}/projects/{project_ref}"
            "/findings-sync/approve",
            {"request_digest": digest},
            headers or self.headers[Role.OWNER],
        )

    def _accept_raw(self, project_ref: str, request: dict, digest: str, *, headers=None):
        request_headers = {
            "Content-Type": "application/json",
            "Content-Encoding": "identity",
            "Idempotency-Key": f"fs1-{digest}",
            **(headers or self.headers[Role.MEMBER]),
        }
        return self._raw_request(
            "POST",
            f"/v1/workspaces/{self.workspace}/projects/{project_ref}/findings-sync",
            stable_json(request).encode("utf-8"),
            request_headers,
        )

    def _assert_error(
        self,
        status: int,
        raw: bytes,
        expected_status: int,
        expected_code: str,
        *forbidden: str,
    ) -> dict:
        self.assertEqual(status, expected_status, raw)
        payload = json.loads(raw)
        self.assertEqual(payload.get("code"), expected_code, payload)
        rendered = raw.decode("utf-8", "replace")
        for secret in forbidden:
            self.assertNotIn(secret, rendered)
        return payload

    def test_project_create_list_and_key_retrieval_are_authorized_and_secret_safe(self):
        projects_path = f"/v1/workspaces/{self.workspace}/projects"
        status, created = self._request(
            "POST", projects_path, {"name": "Production API"},
            self.headers[Role.MEMBER],
        )
        self.assertEqual(status, 201, created)
        self.assertRegex(created["project_ref"], r"prj_[0-9a-f]{32}\Z")
        self.assertEqual(created["name"], "Production API")
        self.assertEqual(created["workspace_id"], self.workspace)
        self.assertNotIn("namespace_key_hex", created)

        status, listed = self._request(
            "GET", projects_path, headers=self.headers[Role.VIEWER],
        )
        self.assertEqual(status, 200, listed)
        matching = [
            project for project in listed["projects"]
            if project["project_ref"] == created["project_ref"]
        ]
        self.assertEqual(len(matching), 1)
        self.assertNotIn("namespace_key_hex", matching[0])

        key_path = f"{projects_path}/{created['project_ref']}/namespace-key"
        status, key_payload = self._request(
            "GET", key_path, headers=self.headers[Role.OWNER],
        )
        self.assertEqual(status, 200, key_payload)
        self.assertEqual(key_payload["project_ref"], created["project_ref"])
        self.assertRegex(key_payload["namespace_key_hex"], HEX_KEY)
        namespace_key_hex = key_payload["namespace_key_hex"]
        self.assertNotIn(namespace_key_hex, json.dumps(created))
        self.assertNotIn(namespace_key_hex, json.dumps(listed))

        status, machine_key = self._request(
            "GET", key_path, headers=self.api_key_headers,
        )
        self.assertEqual(status, 200, machine_key)
        self.assertEqual(machine_key["namespace_key_hex"], namespace_key_hex)

        status, ambiguous = self._request(
            "GET",
            key_path,
            headers={**self.api_key_headers, **self.headers[Role.OWNER]},
        )
        self.assertEqual(status, 400, ambiguous)
        self.assertEqual(ambiguous.get("code"), "ambiguous_request_headers")

        for headers in (self.headers[Role.VIEWER], self.headers[Role.BILLING]):
            status, denied = self._request("GET", key_path, headers=headers)
            self.assertEqual(status, 403, denied)
            self.assertNotIn(namespace_key_hex, json.dumps(denied))

        status, denied = self._request(
            "GET", key_path, headers=self.other_headers,
        )
        self.assertEqual(status, 403, denied)
        self.assertNotIn(namespace_key_hex, json.dumps(denied))
        self.assertEqual(self._request("GET", key_path)[0], 401)

    def test_project_role_and_cross_tenant_boundaries_use_findings_capabilities(self):
        path = f"/v1/workspaces/{self.workspace}/projects"
        self.assertEqual(
            self._request(
                "POST", path, {"name": "Admin project"},
                self.headers[Role.ADMIN],
            )[0],
            201,
        )
        for role in (Role.VIEWER, Role.BILLING):
            self.assertEqual(
                self._request(
                    "POST", path, {"name": f"Denied {role.value}"},
                    self.headers[role],
                )[0],
                403,
            )

        self.assertEqual(
            self._request("GET", path, headers=self.headers[Role.VIEWER])[0],
            200,
        )
        self.assertEqual(
            self._request("GET", path, headers=self.headers[Role.BILLING])[0],
            403,
        )
        self.assertEqual(
            self._request("GET", path, headers=self.other_headers)[0],
            403,
        )

    def test_human_approval_allows_api_key_accept_and_viewer_history(self):
        project, namespace_key = self._seed_project("Approval API")
        request = _sync_request(project.project_ref, namespace_key, title="Approval API")
        digest = findings_sync_request_digest(request, namespace_key)
        key_hex = namespace_key.hex()

        status, raw = self._accept_raw(project.project_ref, request, digest)
        self._assert_error(status, raw, 403, "approval_required", key_hex)

        status, rejected = self._request(
            "POST",
            f"/v1/workspaces/{self.workspace}/projects/{project.project_ref}"
            "/findings-sync/approve",
            {"request_digest": digest, "project_ref": project.project_ref},
            self.headers[Role.OWNER],
        )
        self.assertEqual(status, 400, rejected)
        self.assertEqual(rejected.get("code"), "invalid_approval_request")

        status, approval = self._approve(project.project_ref, digest)
        self.assertEqual(status, 201, approval)
        self.assertEqual(approval["project_ref"], project.project_ref)
        self.assertEqual(approval["request_digest"], digest)
        self.assertRegex(approval["approval_id"], r"fsauth_[0-9a-f]{32}\Z")
        self.assertNotIn(key_hex, json.dumps(approval))

        status, raw = self._accept_raw(
            project.project_ref, request, digest, headers=self.api_key_headers,
        )
        self.assertEqual(status, 201, raw)
        receipt = json.loads(raw)
        self.assertEqual(receipt["schema_version"], FINDINGS_SYNC_RECEIPT_SCHEMA_VERSION)
        self.assertEqual(receipt["request_digest"], digest)
        self.assertEqual(receipt["project_ref"], project.project_ref)
        self.assertNotIn(key_hex, raw.decode())
        actors = {
            row["action"]: row["actor_ref"]
            for row in self.cp.store.conn.execute(
                "SELECT action, actor_ref FROM findings_sync_audit "
                "WHERE workspace_id=? AND project_ref=?",
                (self.workspace, project.project_ref),
            )
        }
        self.assertEqual(actors["approval_created"], self.owner_id)
        self.assertEqual(actors["sync_created"], self.api_key_id)

        reviews_path = (
            f"/v1/workspaces/{self.workspace}/projects/{project.project_ref}/reviews"
        )
        status, history = self._request(
            "GET", reviews_path, headers=self.headers[Role.VIEWER],
        )
        self.assertEqual(status, 200, history)
        self.assertEqual(
            [item["synced_review_id"] for item in history["reviews"]],
            [receipt["synced_review_id"]],
        )
        self.assertNotIn(key_hex, json.dumps(history))

        status, detail = self._request(
            "GET", f"{reviews_path}/{receipt['synced_review_id']}",
            headers=self.headers[Role.VIEWER],
        )
        self.assertEqual(status, 200, detail)
        self.assertEqual(detail["projection_hash"], request["projection_hash"])
        self.assertEqual(detail["findings"], request["findings"])
        self.assertNotIn(key_hex, json.dumps(detail))

    def test_approval_and_history_reject_machine_roles_and_cross_tenant_access(self):
        project, namespace_key = self._seed_project("Authorization API")
        request = _sync_request(project.project_ref, namespace_key, title="Authorization API")
        digest = findings_sync_request_digest(request, namespace_key)
        key_hex = namespace_key.hex()

        status, denied = self._approve(
            project.project_ref, digest, headers=self.api_key_headers,
        )
        self.assertEqual(status, 403, denied)
        self.assertEqual(denied.get("code"), "human_session_required")
        self.assertNotIn(key_hex, json.dumps(denied))

        duplicate = (
            '{"request_digest":"' + ("0" * 64) + '","request_digest":"'
            + digest + '"}'
        ).encode("utf-8")
        cookie = self.headers[Role.OWNER]["Cookie"]
        status, raw = self._raw_http(
            (
                f"POST /v1/workspaces/{self.workspace}/projects/{project.project_ref}/"
                "findings-sync/approve HTTP/1.1\r\n"
                "Host: 127.0.0.1\r\n"
                f"Cookie: {cookie}\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {len(duplicate)}\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii") + duplicate
        )
        self._assert_error(
            status, raw, 400, "invalid_approval_request", digest, "0" * 64,
        )
        self.assertEqual(
            self._approve(
                project.project_ref, digest, headers=self.headers[Role.VIEWER],
            )[0],
            403,
        )

        status, raw = self._accept_raw(
            project.project_ref, request, digest, headers=self.headers[Role.VIEWER],
        )
        self.assertEqual(status, 403, raw)
        self.assertNotIn(key_hex, raw.decode("utf-8", "replace"))

        reviews_path = (
            f"/v1/workspaces/{self.workspace}/projects/{project.project_ref}/reviews"
        )
        self.assertEqual(
            self._request("GET", reviews_path, headers=self.headers[Role.BILLING])[0],
            403,
        )
        status, denied = self._request(
            "GET", reviews_path, headers=self.other_headers,
        )
        self.assertEqual(status, 403, denied)
        self.assertNotIn(key_hex, json.dumps(denied))

        wrong_tenant_path = (
            f"/v1/workspaces/{self.other_workspace}/projects/"
            f"{project.project_ref}/reviews"
        )
        status, denied = self._request(
            "GET", wrong_tenant_path, headers=self.other_headers,
        )
        self.assertEqual(status, 404, denied)
        self.assertNotIn(key_hex, json.dumps(denied))

    def test_sync_reader_is_duplicate_free_identity_only_bounded_and_non_echoing(self):
        project, namespace_key = self._seed_project("Strict API")
        request = _sync_request(project.project_ref, namespace_key, title="Strict API")
        digest = findings_sync_request_digest(request, namespace_key)
        path = (
            f"/v1/workspaces/{self.workspace}/projects/{project.project_ref}/findings-sync"
        )
        base_headers = {
            "Content-Type": "application/json",
            "Idempotency-Key": f"fs1-{digest}",
            **self.headers[Role.MEMBER],
        }
        key_hex = namespace_key.hex()

        canonical = stable_json(request)
        project_field = f'"project_ref":"{project.project_ref}"'
        duplicate = canonical.replace(
            project_field, f"{project_field},{project_field}", 1,
        ).encode("utf-8")
        status, raw = self._raw_request(
            "POST", path, duplicate,
            {"Content-Encoding": "identity", **base_headers},
        )
        self._assert_error(status, raw, 400, "duplicate_json_key", key_hex)

        status, raw = self._raw_request(
            "POST", path, canonical.encode("utf-8"),
            {"Content-Encoding": "gzip", **base_headers},
        )
        self._assert_error(status, raw, 415, "unsupported_content_encoding", key_hex)

        status, raw = self._raw_request(
            "POST", path, canonical.encode("utf-8"),
            {"Transfer-Encoding": "chunked", **base_headers},
        )
        self._assert_error(status, raw, 415, "unsupported_transfer_encoding", key_hex)

        padding_envelope = len(b'{"padding":""}')
        at_limit = (
            b'{"padding":"'
            + (b"x" * (MAX_FINDINGS_SYNC_BYTES - padding_envelope))
            + b'"}'
        )
        self.assertEqual(len(at_limit), MAX_FINDINGS_SYNC_BYTES)
        status, raw = self._raw_request(
            "POST", path, at_limit,
            {"Content-Encoding": "identity", **base_headers},
        )
        self._assert_error(
            status, raw, 400, "invalid_findings_sync_request", key_hex,
        )

        too_large = at_limit + b" "
        status, raw = self._raw_request(
            "POST", path, too_large,
            {"Content-Encoding": "identity", **base_headers},
        )
        self._assert_error(
            status, raw, 413, "findings_sync_request_too_large", key_hex,
        )

        marker = "customer-private-value-DO-NOT-ECHO"
        invalid = dict(request)
        invalid["private_payload"] = marker
        status, raw = self._raw_request(
            "POST", path, stable_json(invalid).encode("utf-8"),
            {"Content-Encoding": "identity", **base_headers},
        )
        payload = self._assert_error(
            status, raw, 400, "invalid_findings_sync_request", marker, key_hex,
        )
        self.assertNotIn("private_payload", json.dumps(payload))

    def test_request_framing_and_paths_are_canonical_without_global_slow_body_lock(self):
        cookie = self.headers[Role.MEMBER]["Cookie"]
        body = b'{"name":"Ambiguous"}'
        status, raw = self._raw_http(
            (
                f"POST /v1//workspaces/{self.workspace}//projects/ HTTP/1.1\r\n"
                "Host: 127.0.0.1\r\n"
                f"Cookie: {cookie}\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii") + body
        )
        self._assert_error(status, raw, 400, "noncanonical_path")

        status, raw = self._raw_http(
            (
                f"POST /v1/workspaces/{self.workspace}/projects HTTP/1.1\r\n"
                "Host: 127.0.0.1\r\n"
                f"Cookie: {cookie}\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii") + body
        )
        self._assert_error(status, raw, 400, "ambiguous_request_framing")

        for invalid_length in ("+2", "0_2"):
            status, raw = self._raw_http(
                (
                    "POST /v1/signup HTTP/1.1\r\n"
                    "Host: 127.0.0.1\r\n"
                    f"Content-Length: {invalid_length}\r\n"
                    "Connection: close\r\n\r\n{}"
                ).encode("ascii")
            )
            self._assert_error(status, raw, 400, "ambiguous_request_framing")

        partial = socket.create_connection(("127.0.0.1", self.port), timeout=2)
        partial.sendall(
            b"POST /v1/signup HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: 100\r\n\r\n{"
        )
        time.sleep(0.05)
        try:
            self.assertEqual(self._request("GET", "/v1/health")[0], 200)
        finally:
            partial.close()

        status, raw = self._raw_http(
            b"POST /v1/signup HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Length: -1\r\n"
            b"Connection: close\r\n\r\n"
        )
        self._assert_error(status, raw, 400, "ambiguous_request_framing")

        original_deadline = http_api_module.REQUEST_BODY_TOTAL_DEADLINE_SECONDS
        http_api_module.REQUEST_BODY_TOTAL_DEADLINE_SECONDS = 0.1
        self.addCleanup(
            setattr,
            http_api_module,
            "REQUEST_BODY_TOTAL_DEADLINE_SECONDS",
            original_deadline,
        )
        trickle = socket.create_connection(("127.0.0.1", self.port), timeout=2)
        self.addCleanup(trickle.close)
        trickle.sendall(
            b"POST /v1/signup HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Length: 2\r\n"
            b"Connection: close\r\n\r\n{"
        )
        response = http.client.HTTPResponse(trickle)
        response.begin()
        self.assertEqual(response.status, 408)
        self.assertEqual(json.loads(response.read()).get("code"), "request_timeout")
        http_api_module.REQUEST_BODY_TOTAL_DEADLINE_SECONDS = original_deadline

    def test_exact_idempotency_route_binding_and_replay_are_enforced(self):
        project, namespace_key = self._seed_project("Replay API")
        request = _sync_request(project.project_ref, namespace_key, title="Replay API")
        digest = findings_sync_request_digest(request, namespace_key)
        key_hex = namespace_key.hex()
        path = (
            f"/v1/workspaces/{self.workspace}/projects/{project.project_ref}/findings-sync"
        )
        encoded = stable_json(request).encode("utf-8")
        usage_before = self.cp.ledger.usage(
            self.workspace, Meter.SYNCED_REVIEWS, current_period(),
        )
        headers = {
            "Content-Type": "application/json",
            "Content-Encoding": "identity",
            **self.headers[Role.MEMBER],
        }

        status, raw = self._raw_request("POST", path, encoded, headers)
        self._assert_error(status, raw, 400, "idempotency_key_required", key_hex)

        status, raw = self._raw_request(
            "POST", path, encoded,
            {"Idempotency-Key": f"fs1-{'0' * 64}", **headers},
        )
        self._assert_error(status, raw, 409, "idempotency_key_mismatch", key_hex)

        other_project, other_key = self._seed_project("Route binding API")
        route_mismatched = _sync_request(
            project.project_ref, other_key, title="Route binding API",
        )
        mismatch_digest = findings_sync_request_digest(route_mismatched, other_key)
        self.assertEqual(self._approve(other_project.project_ref, mismatch_digest)[0], 201)
        mismatch_path = (
            f"/v1/workspaces/{self.workspace}/projects/"
            f"{other_project.project_ref}/findings-sync"
        )
        status, raw = self._raw_request(
            "POST", mismatch_path, stable_json(route_mismatched).encode("utf-8"),
            {
                "Idempotency-Key": f"fs1-{mismatch_digest}",
                "Content-Type": "application/json",
                "Content-Encoding": "identity",
                **self.headers[Role.MEMBER],
            },
        )
        self._assert_error(
            status, raw, 409, "project_ref_mismatch",
            namespace_key.hex(), other_key.hex(),
        )

        self.assertEqual(self._approve(project.project_ref, digest)[0], 201)
        first_status, first_raw = self._accept_raw(project.project_ref, request, digest)
        second_status, second_raw = self._accept_raw(project.project_ref, request, digest)
        self.assertEqual(first_status, 201, first_raw)
        self.assertEqual(second_status, first_status, second_raw)
        self.assertEqual(second_raw, first_raw)
        self.assertNotIn(key_hex, first_raw.decode())
        self.assertEqual(
            self.cp.ledger.usage(
                self.workspace, Meter.SYNCED_REVIEWS, current_period(),
            ),
            usage_before + 1,
        )
        receipt = json.loads(first_raw)
        self.assertEqual(receipt["disposition"], "created")
        self.assertTrue(receipt["metered"])
        self.assertEqual(
            self.cp.store.conn.execute(
                "SELECT COUNT(*) FROM findings_sync_receipts "
                "WHERE workspace_id=? AND project_ref=? AND request_digest=?",
                (self.workspace, project.project_ref, digest),
            ).fetchone()[0],
            1,
        )

    def test_concurrent_exact_replays_share_one_receipt_and_one_charge(self):
        project, namespace_key = self._seed_project("Concurrent replay API")
        request = _sync_request(
            project.project_ref, namespace_key, title="Concurrent replay API",
        )
        digest = findings_sync_request_digest(request, namespace_key)
        self.assertEqual(self._approve(project.project_ref, digest)[0], 201)
        usage_before = self.cp.ledger.usage(
            self.workspace, Meter.SYNCED_REVIEWS, current_period(),
        )

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            responses = list(executor.map(
                lambda _index: self._accept_raw(project.project_ref, request, digest),
                range(8),
            ))

        self.assertEqual({status for status, _raw in responses}, {201}, responses)
        self.assertEqual(len({raw for _status, raw in responses}), 1, responses)
        self.assertEqual(
            self.cp.ledger.usage(
                self.workspace, Meter.SYNCED_REVIEWS, current_period(),
            ),
            usage_before + 1,
        )


if __name__ == "__main__":
    unittest.main()
