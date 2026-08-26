"""Immutable local findings-sync queue security contract."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor
import unittest
from unittest import mock

from heel.review_contract import stable_json


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/findings_sync"
WORKSPACE = "ws_0123456789abcdef"
OTHER_WORKSPACE = "ws_0000000000000000"
NAMESPACE_KEY = bytes(range(32))
NOW = 1_786_000_000.0


def _physical_temp(path: str) -> Path:
    return Path(path).resolve(strict=True)


def _request(name: str = "request-one-finding.json") -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _digest(request: dict) -> str:
    return hashlib.sha256(stable_json(request).encode("utf-8")).hexdigest()


def _approval(request: dict | None = None, **overrides):
    from heel.sync_queue import HumanSyncApproval

    item = _request() if request is None else request
    values = {
        "workspace_ref": WORKSPACE,
        "project_ref": item["project_ref"],
        "request_digest": _digest(item),
        "approved_at": NOW - 1,
        "expires_at": NOW + 60,
    }
    values.update(overrides)
    return HumanSyncApproval(**values)


class SyncQueueTests(unittest.TestCase):
    def _queue(self, root: Path, **kwargs):
        from heel.sync_queue import SyncQueue

        clock = kwargs.pop("now", lambda: NOW)
        return SyncQueue(root=root, now=clock, **kwargs)

    @unittest.skipUnless(os.name == "posix", "POSIX descriptor operations required")
    def test_enqueue_persists_only_exact_canonical_approved_projection(self):
        from heel.sync_queue import SyncRecord

        with tempfile.TemporaryDirectory() as tmp:
            root = _physical_temp(tmp) / "heel-home"
            queue = self._queue(root)
            request = _request()

            record = queue.enqueue_approved(request, NAMESPACE_KEY, _approval(request))

            self.assertIsInstance(record, SyncRecord)
            self.assertEqual(record.workspace_ref, WORKSPACE)
            self.assertEqual(record.project_ref, request["project_ref"])
            self.assertEqual(record.request_digest, _digest(request))
            self.assertEqual(record.request_json, stable_json(request))
            self.assertEqual(record.retry.attempts, 0)
            self.assertEqual(record.retry.next_attempt_at, NOW)
            self.assertIsNone(record.transport_approval)
            self.assertIsNone(record.receipt)

            records = list((root / "sync-queue" / WORKSPACE).glob("*.json"))
            self.assertEqual(len(records), 1)
            raw = json.loads(records[0].read_text(encoding="utf-8"))
            self.assertEqual(
                set(raw),
                {
                    "schema_version",
                    "workspace_ref",
                    "project_ref",
                    "request_digest",
                    "request_json",
                    "human_approval",
                    "transport_approval",
                    "transmission",
                    "retry",
                    "receipt",
                },
            )
            self.assertIsNone(raw["transmission"])
            self.assertEqual(set(raw["human_approval"]), {"approved_at", "expires_at"})
            self.assertEqual(
                set(raw["retry"]),
                {
                    "attempts",
                    "next_attempt_at",
                    "last_error_code",
                    "lease_token",
                    "lease_expires_at",
                },
            )
            rendered = stable_json(raw)
            for forbidden in (
                "raw_review",
                "raw-customer-openapi",
                "questions",
                "answers",
                "reason",
                "arbitrary_metadata",
            ):
                self.assertNotIn(forbidden, rendered)
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((root / "sync-queue").stat().st_mode), 0o700)
            self.assertEqual(
                stat.S_IMODE((root / "sync-queue" / WORKSPACE).stat().st_mode),
                0o700,
            )
            self.assertEqual(stat.S_IMODE(records[0].stat().st_mode), 0o600)

    def test_prepare_is_authority_free_and_later_process_records_exact_human_approval(
        self,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            root = _physical_temp(tmp) / "heel-home"
            request = _request()
            mcp_queue = self._queue(root)

            prepared = mcp_queue.prepare(request, NAMESPACE_KEY, WORKSPACE)

            self.assertIsNone(prepared.human_approval)
            self.assertIsNone(prepared.transport_approval)
            self.assertIsNone(prepared.retry.next_attempt_at)
            self.assertEqual(prepared.request_json, stable_json(request))
            self.assertEqual(
                mcp_queue.prepare(request, NAMESPACE_KEY, WORKSPACE), prepared
            )

            cli_queue = self._queue(root)
            approved = cli_queue.record_human_approval(_approval(request))

            self.assertEqual(approved.request_json, prepared.request_json)
            self.assertEqual(approved.request_digest, prepared.request_digest)
            self.assertEqual(approved.human_approval.approved_at, NOW - 1)
            self.assertEqual(approved.retry.next_attempt_at, NOW)

    def test_get_list_and_explicit_delete_are_workspace_scoped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _physical_temp(tmp) / "heel-home"
            queue = self._queue(root)
            first = _request()
            second = _request("request-pass.json")
            first_record = queue.enqueue_approved(
                first, NAMESPACE_KEY, _approval(first)
            )
            second_record = queue.enqueue_approved(
                second, NAMESPACE_KEY, _approval(second)
            )
            credential = root / "cloud" / "credentials-unrelated.json"
            credential.parent.mkdir(mode=0o700)
            credential.write_text("keep", encoding="utf-8")

            self.assertEqual(
                queue.get(
                    WORKSPACE, first_record.project_ref, first_record.request_digest
                ),
                first_record,
            )
            self.assertEqual(
                queue.list(WORKSPACE),
                sorted(
                    [first_record, second_record],
                    key=lambda item: (item.project_ref, item.request_digest),
                ),
            )
            self.assertEqual(queue.list(OTHER_WORKSPACE), [])
            self.assertFalse(hasattr(queue, "clear"))

            self.assertTrue(
                queue.delete(
                    WORKSPACE, first_record.project_ref, first_record.request_digest
                )
            )
            self.assertFalse(
                queue.delete(
                    WORKSPACE, first_record.project_ref, first_record.request_digest
                )
            )
            self.assertEqual(queue.list(WORKSPACE), [second_record])
            self.assertEqual(credential.read_text(encoding="utf-8"), "keep")

    def test_claim_is_transactional_fenced_and_reclaims_only_after_expiry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _physical_temp(tmp) / "heel-home"
            current = [NOW]
            request = _request()
            first = self._queue(
                root,
                now=lambda: current[0],
                lease_seconds=100,
                token=lambda: "fsl_" + "1" * 32,
            )
            second = self._queue(
                root,
                now=lambda: current[0],
                lease_seconds=100,
                token=lambda: "fsl_" + "2" * 32,
            )
            prepared = first.prepare(request, NAMESPACE_KEY, WORKSPACE)
            self.assertIsNone(
                first.claim(WORKSPACE, prepared.project_ref, prepared.request_digest)
            )
            first.record_human_approval(
                _approval(request, approved_at=NOW, expires_at=NOW + 600)
            )

            with ThreadPoolExecutor(max_workers=2) as pool:
                claims = list(
                    pool.map(
                        lambda queue: queue.claim(
                            WORKSPACE, prepared.project_ref, prepared.request_digest
                        ),
                        (first, second),
                    )
                )

            active = [claim for claim in claims if claim is not None]
            self.assertEqual(len(active), 1)
            lease = active[0]
            self.assertEqual(lease.record.retry.attempts, 1)
            self.assertEqual(lease.record.retry.lease_token, lease.lease_token)
            self.assertIsNone(
                first.claim(WORKSPACE, prepared.project_ref, prepared.request_digest)
            )

            current[0] += 101
            reclaimed = second.claim(
                WORKSPACE, prepared.project_ref, prepared.request_digest
            )
            self.assertIsNotNone(reclaimed)
            self.assertNotEqual(reclaimed.lease_token, lease.lease_token)
            self.assertEqual(reclaimed.record.retry.attempts, 2)

    def test_claim_next_has_no_scan_cap_and_same_workspace_poison_cannot_starve(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _physical_temp(tmp) / "heel-home"
            queue = self._queue(
                root,
                token=lambda: "fsl_" + "9" * 32,
            )
            request = _request()
            target = queue.enqueue_approved(request, NAMESPACE_KEY, _approval(request))
            workspace = root / "sync-queue" / WORKSPACE
            for index in range(1_025):
                project = f"prj_{index:032x}"
                digest = f"{index:064x}"
                (workspace / f"{project}.{digest}.json").write_text(
                    '{"raw_review":"must-never-surface"}', encoding="utf-8"
                )

            self.assertEqual(queue.list(WORKSPACE), [target])
            claimed = queue.claim_next(WORKSPACE)

            self.assertIsNotNone(claimed)
            self.assertEqual(claimed.record.request_digest, target.request_digest)
            self.assertEqual(claimed.record.request_json, target.request_json)

    def test_renewal_rotates_fence_and_only_live_owner_can_schedule_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _physical_temp(tmp) / "heel-home"
            current = [NOW]
            tokens = iter(("fsl_" + "1" * 32, "fsl_" + "2" * 32))
            first = self._queue(
                root,
                now=lambda: current[0],
                lease_seconds=100,
                token=lambda: next(tokens),
            )
            second = self._queue(
                root,
                now=lambda: current[0],
                lease_seconds=100,
                token=lambda: "fsl_" + "3" * 32,
            )
            request = _request()
            record = first.enqueue_approved(
                request,
                NAMESPACE_KEY,
                _approval(request, approved_at=NOW, expires_at=NOW + 600),
            )
            original = first.claim(WORKSPACE, record.project_ref, record.request_digest)
            self.assertIsNotNone(original)

            current[0] += 80
            renewed = first.renew(original)
            self.assertIsNotNone(renewed)
            self.assertEqual(renewed.lease_token, "fsl_" + "2" * 32)
            self.assertEqual(renewed.lease_expires_at, NOW + 180)
            current[0] += 21
            self.assertIsNone(
                second.claim(WORKSPACE, record.project_ref, record.request_digest)
            )
            self.assertFalse(
                first.schedule_retry(original, current[0] + 500, "transport_error")
            )
            self.assertTrue(
                first.schedule_retry(renewed, current[0] + 400, "transport_error")
            )
            self.assertIsNone(first.claim_next(WORKSPACE))

            current[0] += 400
            retry = second.claim_next(WORKSPACE)
            self.assertIsNotNone(retry)
            self.assertEqual(retry.record.retry.attempts, 2)
            self.assertEqual(retry.record.retry.last_error_code, "transport_error")

    def test_expired_human_approval_cannot_claim_bind_renew_or_complete(self):
        from heel.cloud_client import TransportApproval

        with tempfile.TemporaryDirectory() as tmp:
            root = _physical_temp(tmp) / "heel-home"
            current = [NOW]
            queue = self._queue(
                root,
                now=lambda: current[0],
                token=lambda: "fsl_" + "7" * 32,
            )
            request = _request()
            record = queue.enqueue_approved(request, NAMESPACE_KEY, _approval(request))
            current[0] = NOW + 60
            self.assertIsNone(
                queue.claim(WORKSPACE, record.project_ref, record.request_digest)
            )
            self.assertIsNone(queue.claim_next(WORKSPACE))

            refreshed = queue.record_human_approval(
                _approval(
                    request,
                    approved_at=current[0],
                    expires_at=current[0] + 10,
                )
            )
            lease = queue.claim(
                WORKSPACE, refreshed.project_ref, refreshed.request_digest
            )
            approval = TransportApproval(
                WORKSPACE,
                refreshed.project_ref,
                "fsauth_" + "7" * 32,
                refreshed.request_digest,
                "dev_" + "a" * 32,
                current[0],
                current[0] + 60,
            )
            bound = queue.bind_transport_approval(lease, approval)
            current[0] += 11

            self.assertIsNone(queue.renew(bound))
            with self.assertRaises(ValueError):
                queue.bind_transport_approval(bound, approval)
            receipt = json.loads(
                (FIXTURES / "receipt-created.json").read_text(encoding="utf-8")
            )
            with self.assertRaises(ValueError):
                queue.complete(bound, receipt)

    def test_transport_approval_binds_only_to_live_lease_and_same_exact_digest(self):
        from heel.cloud_client import TransportApproval

        with tempfile.TemporaryDirectory() as tmp:
            root = _physical_temp(tmp) / "heel-home"
            request = _request()
            queue = self._queue(root, token=lambda: "fsl_" + "4" * 32)
            record = queue.enqueue_approved(request, NAMESPACE_KEY, _approval(request))
            lease = queue.claim(WORKSPACE, record.project_ref, record.request_digest)
            self.assertIsNotNone(lease)
            approval = TransportApproval(
                WORKSPACE,
                record.project_ref,
                "fsauth_" + "1" * 32,
                record.request_digest,
                "dev_" + "a" * 32,
                NOW - 1,
                NOW + 60,
            )

            bound = queue.bind_transport_approval(lease, approval)

            self.assertIsNotNone(bound)
            self.assertEqual(
                bound.record.transport_approval.request_digest,
                record.request_digest,
            )
            self.assertEqual(
                bound.record.transport_approval.approval_id,
                "fsauth_" + "1" * 32,
            )
            self.assertIsNone(queue.bind_transport_approval(lease, approval))

            mismatched = TransportApproval(
                WORKSPACE,
                record.project_ref,
                "fsauth_" + "2" * 32,
                "0" * 64,
                "dev_" + "a" * 32,
                NOW - 1,
                NOW + 60,
            )
            with self.assertRaises(ValueError):
                queue.bind_transport_approval(bound, mismatched)

            raw = json.loads(
                next((root / "sync-queue" / WORKSPACE).glob("*.json")).read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                set(raw["transport_approval"]),
                {"approval_id", "request_digest", "approved_at", "expires_at"},
            )
            self.assertNotIn("approved_by", stable_json(raw))

    def test_begin_transmission_is_only_send_authority_and_completion_uses_live_start(
        self,
    ):
        from heel.cloud_client import TransportApproval
        from heel.sync_queue import SyncTransmissionPermit

        with tempfile.TemporaryDirectory() as tmp:
            root = _physical_temp(tmp) / "heel-home"
            current = [NOW]
            queue = self._queue(
                root,
                now=lambda: current[0],
                token=lambda: "fsl_" + "5" * 32,
            )
            request = _request()
            record = queue.enqueue_approved(
                request,
                NAMESPACE_KEY,
                _approval(request, approved_at=NOW, expires_at=NOW + 10),
            )
            lease = queue.claim(WORKSPACE, record.project_ref, record.request_digest)
            receipt = json.loads(
                (FIXTURES / "receipt-created.json").read_text(encoding="utf-8")
            )
            with self.assertRaises(ValueError):
                queue.complete(lease, receipt)

            approval = TransportApproval(
                WORKSPACE,
                record.project_ref,
                "fsauth_" + "3" * 32,
                record.request_digest,
                "dev_" + "a" * 32,
                NOW,
                NOW + 60,
            )
            bound = queue.bind_transport_approval(lease, approval)
            with self.assertRaises(ValueError):
                queue.complete(bound, receipt)

            permit = queue.begin_transmission(bound)

            self.assertIsInstance(permit, SyncTransmissionPermit)
            self.assertEqual(permit.record.request_json, stable_json(request))
            self.assertEqual(permit.record.request_digest, record.request_digest)
            self.assertEqual(permit.begun_at, NOW)
            self.assertEqual(permit.effective_expires_at, NOW + 10)
            self.assertEqual(
                permit.record.transmission.permit_token,
                permit.permit_token,
            )
            raw = json.loads(
                next((root / "sync-queue" / WORKSPACE).glob("*.json")).read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(
                set(raw["transmission"]),
                {
                    "permit_token",
                    "lease_token",
                    "request_digest",
                    "begun_at",
                    "effective_expires_at",
                },
            )
            self.assertNotIn("raw_review", stable_json(raw))

            mismatched = {**receipt, "projection_hash": "0" * 64}
            with self.assertRaises(ValueError):
                queue.complete(permit, mismatched)

            current[0] += 11
            self.assertTrue(queue.complete(permit, receipt))
            receipt["receipt_id"] = "fsr_" + "9" * 32
            completed = queue.get(WORKSPACE, record.project_ref, record.request_digest)
            self.assertIsNotNone(completed.receipt)
            self.assertEqual(
                completed.receipt["receipt_id"],
                "fsr_" + "1" * 32,
            )
            self.assertIsNone(completed.retry.next_attempt_at)
            self.assertIsNone(completed.retry.lease_token)
            self.assertIsNone(completed.transmission)
            self.assertFalse(
                queue.complete(
                    permit,
                    json.loads(
                        (FIXTURES / "receipt-created.json").read_text(encoding="utf-8")
                    ),
                )
            )

    def test_reclaim_retry_and_stale_transmission_require_fresh_transport_approval(
        self,
    ):
        from heel.cloud_client import TransportApproval

        with tempfile.TemporaryDirectory() as tmp:
            root = _physical_temp(tmp) / "heel-home"
            current = [NOW]
            tokens = iter(f"fsl_{index:032x}" for index in range(1, 6))
            queue = self._queue(
                root,
                now=lambda: current[0],
                lease_seconds=5,
                token=lambda: next(tokens),
            )
            request = _request()
            record = queue.enqueue_approved(
                request,
                NAMESPACE_KEY,
                _approval(request, approved_at=NOW, expires_at=NOW + 600),
            )
            first = queue.claim(WORKSPACE, record.project_ref, record.request_digest)
            first_approval = TransportApproval(
                WORKSPACE,
                record.project_ref,
                "fsauth_" + "1" * 32,
                record.request_digest,
                "dev_" + "a" * 32,
                current[0],
                current[0] + 60,
            )
            first_bound = queue.bind_transport_approval(first, first_approval)

            current[0] += 6
            reclaimed = queue.claim(
                WORKSPACE, record.project_ref, record.request_digest
            )
            self.assertIsNotNone(reclaimed)
            self.assertIsNone(reclaimed.record.transport_approval)
            self.assertIsNone(queue.begin_transmission(first_bound))
            with self.assertRaises(ValueError):
                queue.begin_transmission(reclaimed)

            second_approval = TransportApproval(
                WORKSPACE,
                record.project_ref,
                "fsauth_" + "2" * 32,
                record.request_digest,
                "dev_" + "a" * 32,
                current[0],
                current[0] + 60,
            )
            second_bound = queue.bind_transport_approval(reclaimed, second_approval)
            stale_permit = queue.begin_transmission(second_bound)
            current[0] += 6
            after_stale_transmission = queue.claim(
                WORKSPACE, record.project_ref, record.request_digest
            )
            self.assertIsNotNone(after_stale_transmission)
            self.assertIsNone(after_stale_transmission.record.transport_approval)
            self.assertIsNone(after_stale_transmission.record.transmission)
            receipt = json.loads(
                (FIXTURES / "receipt-created.json").read_text(encoding="utf-8")
            )
            self.assertFalse(queue.complete(stale_permit, receipt))

            third_approval = TransportApproval(
                WORKSPACE,
                record.project_ref,
                "fsauth_" + "3" * 32,
                record.request_digest,
                "dev_" + "a" * 32,
                current[0],
                current[0] + 60,
            )
            third_bound = queue.bind_transport_approval(
                after_stale_transmission, third_approval
            )
            current_permit = queue.begin_transmission(third_bound)
            self.assertTrue(
                queue.schedule_retry(current_permit, current[0] + 1, "transport_error")
            )
            scheduled = queue.get(WORKSPACE, record.project_ref, record.request_digest)
            self.assertIsNone(scheduled.transport_approval)
            self.assertIsNone(scheduled.transmission)
            current[0] += 1
            retry = queue.claim(WORKSPACE, record.project_ref, record.request_digest)
            self.assertIsNotNone(retry)
            self.assertIsNone(retry.record.transport_approval)
            with self.assertRaises(ValueError):
                queue.begin_transmission(retry)

    def test_begin_transmission_rejects_clock_rollback_before_approval_times(self):
        from heel.cloud_client import TransportApproval

        with tempfile.TemporaryDirectory() as tmp:
            root = _physical_temp(tmp) / "heel-home"
            current = [NOW]
            queue = self._queue(root, now=lambda: current[0])
            request = _request()
            record = queue.enqueue_approved(
                request,
                NAMESPACE_KEY,
                _approval(request, approved_at=NOW, expires_at=NOW + 60),
            )
            lease = queue.claim(WORKSPACE, record.project_ref, record.request_digest)
            approval = TransportApproval(
                WORKSPACE,
                record.project_ref,
                "fsauth_" + "9" * 32,
                record.request_digest,
                "dev_" + "a" * 32,
                NOW,
                NOW + 60,
            )
            bound = queue.bind_transport_approval(lease, approval)

            current[0] -= 1

            with self.assertRaises(ValueError):
                queue.begin_transmission(bound)

    @unittest.skipUnless(os.name == "posix", "POSIX flock required")
    def test_claim_samples_time_after_waiting_for_global_flock(self):
        import fcntl as real_fcntl

        with tempfile.TemporaryDirectory() as tmp:
            root = _physical_temp(tmp) / "heel-home"
            current = [NOW]
            queue = self._queue(root, now=lambda: current[0])
            request = _request()
            record = queue.enqueue_approved(
                request,
                NAMESPACE_KEY,
                _approval(request, approved_at=NOW, expires_at=NOW + 10),
            )
            lock_fd = os.open(root / "sync-queue" / ".queue.lock", os.O_RDWR)
            real_fcntl.flock(lock_fd, real_fcntl.LOCK_EX)
            attempted = threading.Event()

            class SignalingFcntl:
                LOCK_EX = real_fcntl.LOCK_EX
                LOCK_UN = real_fcntl.LOCK_UN

                @staticmethod
                def flock(descriptor, operation):
                    if operation == real_fcntl.LOCK_EX:
                        attempted.set()
                    return real_fcntl.flock(descriptor, operation)

            try:
                with mock.patch("heel.sync_queue.fcntl", SignalingFcntl):
                    with ThreadPoolExecutor(max_workers=1) as pool:
                        future = pool.submit(
                            queue.claim,
                            WORKSPACE,
                            record.project_ref,
                            record.request_digest,
                        )
                        self.assertTrue(attempted.wait(timeout=2))
                        current[0] += 11
                        real_fcntl.flock(lock_fd, real_fcntl.LOCK_UN)
                        self.assertIsNone(future.result(timeout=2))
            finally:
                real_fcntl.flock(lock_fd, real_fcntl.LOCK_UN)
                os.close(lock_fd)

    @unittest.skipUnless(os.name == "posix", "POSIX flock required")
    def test_bind_samples_time_after_waiting_for_global_flock(self):
        import fcntl as real_fcntl

        from heel.cloud_client import TransportApproval

        with tempfile.TemporaryDirectory() as tmp:
            root = _physical_temp(tmp) / "heel-home"
            current = [NOW]
            queue = self._queue(root, now=lambda: current[0])
            request = _request()
            record = queue.enqueue_approved(
                request,
                NAMESPACE_KEY,
                _approval(request, approved_at=NOW, expires_at=NOW + 10),
            )
            lease = queue.claim(WORKSPACE, record.project_ref, record.request_digest)
            approval = TransportApproval(
                WORKSPACE,
                record.project_ref,
                "fsauth_" + "8" * 32,
                record.request_digest,
                "dev_" + "a" * 32,
                NOW,
                NOW + 60,
            )
            lock_fd = os.open(root / "sync-queue" / ".queue.lock", os.O_RDWR)
            real_fcntl.flock(lock_fd, real_fcntl.LOCK_EX)
            attempted = threading.Event()

            class SignalingFcntl:
                LOCK_EX = real_fcntl.LOCK_EX
                LOCK_UN = real_fcntl.LOCK_UN

                @staticmethod
                def flock(descriptor, operation):
                    if operation == real_fcntl.LOCK_EX:
                        attempted.set()
                    return real_fcntl.flock(descriptor, operation)

            try:
                with mock.patch("heel.sync_queue.fcntl", SignalingFcntl):
                    with ThreadPoolExecutor(max_workers=1) as pool:
                        future = pool.submit(
                            queue.bind_transport_approval, lease, approval
                        )
                        self.assertTrue(attempted.wait(timeout=2))
                        current[0] += 11
                        real_fcntl.flock(lock_fd, real_fcntl.LOCK_UN)
                        with self.assertRaises(ValueError):
                            future.result(timeout=2)
            finally:
                real_fcntl.flock(lock_fd, real_fcntl.LOCK_UN)
                os.close(lock_fd)

    def test_human_approval_is_exact_live_at_most_ten_minutes_and_refreshable(self):
        from heel.sync_queue import ImmutableQueueConflict

        with tempfile.TemporaryDirectory() as tmp:
            root = _physical_temp(tmp) / "heel-home"
            current = [NOW]
            queue = self._queue(root, now=lambda: current[0])
            request = _request()
            prepared = queue.prepare(request, NAMESPACE_KEY, WORKSPACE)

            invalid = (
                _approval(request, workspace_ref=OTHER_WORKSPACE),
                _approval(request, project_ref="prj_" + "0" * 32),
                _approval(request, request_digest="0" * 64),
                _approval(request, approved_at=NOW + 1),
                _approval(request, expires_at=NOW - 2),
                _approval(request, approved_at=NOW - 1, expires_at=NOW + 600),
                _approval(request, approved_at=True),
            )
            for approval in invalid:
                with self.subTest(approval=approval):
                    with self.assertRaises((ValueError, KeyError)):
                        queue.record_human_approval(approval)
            self.assertIsNone(
                queue.get(
                    WORKSPACE, prepared.project_ref, prepared.request_digest
                ).human_approval
            )

            first = queue.record_human_approval(_approval(request))
            self.assertEqual(queue.record_human_approval(_approval(request)), first)
            with self.assertRaises(ImmutableQueueConflict):
                queue.record_human_approval(
                    _approval(request, approved_at=NOW, expires_at=NOW + 120)
                )

            current[0] = NOW + 61
            refreshed_approval = _approval(
                request,
                approved_at=current[0],
                expires_at=current[0] + 60,
            )
            refreshed = queue.record_human_approval(refreshed_approval)
            self.assertEqual(refreshed.request_json, first.request_json)
            self.assertEqual(refreshed.request_digest, first.request_digest)
            self.assertEqual(refreshed.human_approval.approved_at, current[0])
            self.assertEqual(refreshed.retry.attempts, 0)

            second = _request("request-pass.json")
            distinct = queue.prepare(second, NAMESPACE_KEY, WORKSPACE)
            self.assertNotEqual(distinct.request_digest, refreshed.request_digest)
            with self.assertRaises(ValueError):
                queue.prepare(
                    {**request, "raw_review": "never"}, NAMESPACE_KEY, WORKSPACE
                )

    def test_corrupt_exact_record_is_hidden_and_never_overwritten(self):
        from heel.sync_queue import StoredSyncQueueError

        with tempfile.TemporaryDirectory() as tmp:
            root = _physical_temp(tmp) / "heel-home"
            queue = self._queue(root)
            request = _request()
            prepared = queue.prepare(request, NAMESPACE_KEY, WORKSPACE)
            path = next((root / "sync-queue" / WORKSPACE).glob("*.json"))
            poison = '{"raw_review":"must-not-overwrite"}'
            path.write_text(poison, encoding="utf-8")

            self.assertIsNone(
                queue.get(WORKSPACE, prepared.project_ref, prepared.request_digest)
            )
            self.assertEqual(queue.list(WORKSPACE), [])
            with self.assertRaises(StoredSyncQueueError):
                queue.prepare(request, NAMESPACE_KEY, WORKSPACE)
            self.assertEqual(path.read_text(encoding="utf-8"), poison)

    @unittest.skipUnless(os.name == "posix", "POSIX descriptor operations required")
    def test_symlinked_storage_components_and_targets_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = _physical_temp(tmp)
            request = _request()

            real_root = base / "real-root"
            real_root.mkdir(mode=0o700)
            linked_root = base / "linked-root"
            linked_root.symlink_to(real_root, target_is_directory=True)
            with self.assertRaises(ValueError):
                self._queue(linked_root).prepare(request, NAMESPACE_KEY, WORKSPACE)

            root = base / "heel-home"
            root.mkdir(mode=0o700)
            foreign_queue = base / "foreign-queue"
            foreign_queue.mkdir(mode=0o700)
            (root / "sync-queue").symlink_to(foreign_queue, target_is_directory=True)
            with self.assertRaises(ValueError):
                self._queue(root).prepare(request, NAMESPACE_KEY, WORKSPACE)

            (root / "sync-queue").unlink()
            queue_dir = root / "sync-queue"
            queue_dir.mkdir(mode=0o700)
            foreign_workspace = base / "foreign-workspace"
            foreign_workspace.mkdir(mode=0o700)
            (queue_dir / WORKSPACE).symlink_to(
                foreign_workspace, target_is_directory=True
            )
            with self.assertRaises(ValueError):
                self._queue(root).prepare(request, NAMESPACE_KEY, WORKSPACE)

            (queue_dir / WORKSPACE).unlink()
            queue = self._queue(root)
            record = queue.prepare(request, NAMESPACE_KEY, WORKSPACE)
            victim = base / "victim"
            victim.write_text("keep", encoding="utf-8")
            lock = queue_dir / ".queue.lock"
            lock.unlink()
            lock.symlink_to(victim)
            with self.assertRaises(ValueError):
                queue.get(WORKSPACE, record.project_ref, record.request_digest)
            self.assertEqual(victim.read_text(encoding="utf-8"), "keep")

            lock.unlink()
            lock.write_text("", encoding="utf-8")
            path = next((queue_dir / WORKSPACE).glob("*.json"))
            path.unlink()
            path.symlink_to(victim)
            self.assertIsNone(
                queue.get(WORKSPACE, record.project_ref, record.request_digest)
            )
            self.assertEqual(victim.read_text(encoding="utf-8"), "keep")

    @unittest.skipUnless(os.name == "posix", "POSIX descriptor operations required")
    def test_hardlinked_lock_and_record_are_rejected_without_chmod_side_effects(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = _physical_temp(tmp)
            root = base / "heel-home"
            request = _request()
            queue = self._queue(root)
            record = queue.prepare(request, NAMESPACE_KEY, WORKSPACE)
            queue_dir = root / "sync-queue"
            workspace_dir = queue_dir / WORKSPACE
            victim = base / "victim.json"
            victim.write_text('{"keep":true}', encoding="utf-8")
            victim.chmod(0o644)

            lock = queue_dir / ".queue.lock"
            lock.unlink()
            os.link(victim, lock)
            with self.assertRaises(ValueError):
                queue.get(WORKSPACE, record.project_ref, record.request_digest)
            self.assertEqual(stat.S_IMODE(victim.stat().st_mode), 0o644)

            lock.unlink()
            lock.write_text("", encoding="utf-8")
            lock.chmod(0o600)
            path = next(workspace_dir.glob("*.json"))
            path.unlink()
            os.link(victim, path)
            self.assertIsNone(
                queue.get(WORKSPACE, record.project_ref, record.request_digest)
            )
            self.assertEqual(stat.S_IMODE(victim.stat().st_mode), 0o644)

    @unittest.skipUnless(os.name == "posix", "POSIX descriptor operations required")
    def test_atomic_replace_failure_cleans_exclusive_temp_and_preserves_absence(self):
        from heel.sync_queue import SecureQueueStorageUnavailable

        with tempfile.TemporaryDirectory() as tmp:
            root = _physical_temp(tmp) / "heel-home"
            queue = self._queue(root)
            request = _request()
            workspace_dir = root / "sync-queue" / WORKSPACE

            with mock.patch(
                "heel.sync_queue.os.replace",
                side_effect=TypeError("dir_fd unavailable"),
            ):
                with self.assertRaises(SecureQueueStorageUnavailable):
                    queue.prepare(request, NAMESPACE_KEY, WORKSPACE)

            self.assertEqual(list(workspace_dir.glob("*.json")), [])
            self.assertEqual(list(workspace_dir.glob(".*.tmp")), [])

    def test_constructor_rejects_hosts_without_secure_descriptor_capabilities(self):
        from heel.sync_queue import SecureQueueStorageUnavailable

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "heel-home"
            with mock.patch("heel.sync_queue.os.name", "nt"):
                with self.assertRaises(SecureQueueStorageUnavailable):
                    self._queue(root)
            with mock.patch("heel.sync_queue.fcntl", None):
                with self.assertRaises(SecureQueueStorageUnavailable):
                    self._queue(root)


if __name__ == "__main__":
    unittest.main()
