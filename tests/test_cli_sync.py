"""Interactive CLI is the only machine-side human authority for findings sync."""
from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import time
import unittest
from unittest import mock

from heel import cli
from heel.cloud_client import TransportApproval
from heel.findings_sync import project_findings_sync
from heel.review_service import review_openapi
from heel.sync_queue import HumanSyncApproval


ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = "ws_0123456789abcdef"
PROJECT = "prj_0123456789abcdef0123456789abcdef"
NAMESPACE_KEY = bytes(range(32))


class TtyInput(io.StringIO):
    def isatty(self):
        return True


class TtyOutput(io.StringIO):
    def isatty(self):
        return True


class NonTtyInput(io.StringIO):
    def isatty(self):
        return False


class FakeProjects:
    def __init__(self, review):
        self.review = review

    def get_review(self, review_id):
        return self.review if review_id == self.review["review_id"] else None


class FakeQueue:
    def __init__(self, record=None, events=None):
        self.record = record
        self.events = events if events is not None else []

    def prepare(self, request, namespace_key, workspace_ref):
        self.events.append("prepare")
        self.record = type("Record", (), {
            "workspace_ref": workspace_ref,
            "project_ref": request["project_ref"],
            "request_digest": __import__("hashlib").sha256(
                json.dumps(request, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest(),
            "request_json": json.dumps(request, sort_keys=True, separators=(",", ":")),
            "human_approval": None,
            "transport_approval": None,
            "retry": type("Retry", (), {
                "attempts": 0, "next_attempt_at": None, "last_error_code": None,
            })(),
            "receipt": None,
        })()
        return self.record

    def get(self, workspace_ref, project_ref, digest):
        if self.record and (
            workspace_ref, project_ref, digest
        ) == (
            self.record.workspace_ref, self.record.project_ref, self.record.request_digest
        ):
            return self.record
        return None

    def record_human_approval(self, approval):
        self.events.append("local_approval")
        assert isinstance(approval, HumanSyncApproval)
        self.record.human_approval = type("Human", (), {
            "approved_at": approval.approved_at,
            "expires_at": approval.expires_at,
        })()
        return self.record

    def claim(self, workspace_ref, project_ref, digest):
        self.events.append("claim")
        return type("Lease", (), {"record": self.record})()

    def bind_transport_approval(self, lease, approval):
        self.events.append("transport_approval")
        lease.record.transport_approval = approval
        return lease

    def renew(self, lease):
        self.events.append("renew")
        return lease

    def begin_transmission(self, lease):
        self.events.append("begin_transmission")
        return type("Permit", (), {"record": lease.record})()

    def complete(self, permit, receipt):
        self.events.append("complete")
        permit.record.receipt = receipt
        return True

    def schedule_retry(self, lease, due, code):
        self.events.append(("retry", code))
        return True

    def list(self, workspace_ref):
        return [self.record] if self.record and self.record.workspace_ref == workspace_ref else []


class FakeClient:
    cloud_base_url = "https://heel.example"

    def __init__(self, events=None):
        self.events = events if events is not None else []

    def namespace_key(self, workspace_ref, project_ref):
        self.events.append("namespace")
        return NAMESPACE_KEY

    def approve_findings(self, workspace_ref, project_ref, digest):
        self.events.append("server_approval")
        now = time.time()
        return TransportApproval(
            workspace_ref, project_ref, "fsauth_" + "1" * 32, digest,
            "dev_" + "a" * 32, now - 1, now + 300,
        )

    def sync_findings(self, permit, namespace_key):
        self.events.append("sync")
        workspace_ref = permit.record.workspace_ref
        project_ref = permit.record.project_ref
        request_json = permit.record.request_json
        digest = permit.record.request_digest
        request = json.loads(request_json)
        return {
            "schema_version": "heel.findings-sync-receipt.v1",
            "receipt_id": "fsr_" + "1" * 32,
            "project_ref": project_ref,
            "request_digest": digest,
            "projection_hash": request["projection_hash"],
            "synced_review_id": "synrev_" + "1" * 32,
            "disposition": "created",
            "metered": True,
            "accepted_at": "2026-08-04T12:00:00.000Z",
        }


class CliSyncTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = json.loads(
            (ROOT / "tests/fixtures/openapi/saas_api.json").read_text(encoding="utf-8")
        )
        cls.review = review_openapi(spec, execution_mode="machine_local")

    def test_prepare_projects_only_closed_findings_and_records_no_authority(self):
        events = []
        client = FakeClient(events)
        queue = FakeQueue(events=events)
        stdout = io.StringIO()

        with contextlib.redirect_stdout(stdout):
            code = cli._cloud_sync_prepare(
                client, queue, FakeProjects(self.review),
                self.review["review_id"], WORKSPACE, PROJECT,
            )

        self.assertEqual(code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["state"], "prepared")
        self.assertEqual(payload["request"]["project_ref"], PROJECT)
        self.assertIsNone(queue.record.human_approval)
        self.assertEqual(events, ["namespace", "prepare"])
        rendered = stdout.getvalue()
        for forbidden in ("raw_review", "paths", "questions", "answers", "reason"):
            self.assertNotIn(forbidden, rendered)

    def test_approve_requires_tty_exact_phrase_and_persists_before_network(self):
        events = []
        request = project_findings_sync(self.review, PROJECT, NAMESPACE_KEY)
        queue = FakeQueue(events=events)
        record = queue.prepare(request, NAMESPACE_KEY, WORKSPACE)
        events.clear()
        client = FakeClient(events)
        stdout = TtyOutput()
        typed = f"SYNC {record.request_digest[:12]}\n"

        with (
            mock.patch.object(cli.sys, "stdin", TtyInput(typed)),
            mock.patch.object(cli.sys, "stdout", stdout),
        ):
            code = cli._cloud_sync_approve(
                client, queue, WORKSPACE, PROJECT, record.request_digest
            )

        self.assertEqual(code, 0)
        self.assertLess(events.index("local_approval"), events.index("server_approval"))
        self.assertLess(events.index("transport_approval"), events.index("sync"))
        self.assertLess(events.index("begin_transmission"), events.index("sync"))
        self.assertEqual(events[-1], "complete")
        self.assertIn(record.request_json, stdout.getvalue())
        self.assertIn("never includes raw OpenAPI", stdout.getvalue())

    def test_approve_from_non_tty_or_wrong_phrase_has_zero_network_authority(self):
        request = project_findings_sync(self.review, PROJECT, NAMESPACE_KEY)
        for stdin, tty_stdout in (
            (NonTtyInput("SYNC anything\n"), TtyOutput()),
            (TtyInput("yes\n"), TtyOutput()),
        ):
            with self.subTest(stdin=type(stdin).__name__):
                events = []
                queue = FakeQueue(events=events)
                record = queue.prepare(request, NAMESPACE_KEY, WORKSPACE)
                events.clear()
                stderr = io.StringIO()
                with (
                    mock.patch.object(cli.sys, "stdin", stdin),
                    mock.patch.object(cli.sys, "stdout", tty_stdout),
                    contextlib.redirect_stderr(stderr),
                ):
                    code = cli._cloud_sync_approve(
                        FakeClient(events), queue, WORKSPACE, PROJECT,
                        record.request_digest,
                    )
                self.assertEqual(code, 2)
                self.assertNotIn("local_approval", events)
                self.assertNotIn("server_approval", events)
                self.assertNotIn("sync", events)


if __name__ == "__main__":
    unittest.main()
