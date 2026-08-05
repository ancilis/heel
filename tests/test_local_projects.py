import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from collections.abc import Mapping
from unittest import mock

from heel.review_contract import stable_json
from heel.review_service import review_openapi


ROOT = Path(__file__).resolve().parents[1]
OPENAPI_FIXTURE = ROOT / "tests/fixtures/openapi/saas_api.json"
GOLDEN_FIXTURE = ROOT / "tests/fixtures/reviews/sample_review_v1.json"


def _golden_envelope():
    return json.loads(GOLDEN_FIXTURE.read_text(encoding="utf-8"))


def _sample_spec():
    return json.loads(OPENAPI_FIXTURE.read_text(encoding="utf-8"))


def _review_for(product_id):
    return review_openapi({
        "openapi": "3.1.0",
        "info": {"title": product_id, "version": "1"},
        "paths": {},
    })


def _physical_temp(path):
    """Avoid macOS's /var -> /private/var alias in ordinary-path test cases."""
    return Path(path).resolve(strict=True)


def _review_files(root):
    reviews = root / "reviews"
    return [] if not reviews.exists() else sorted(path.name for path in reviews.iterdir())


class LocalProjectStoreTests(unittest.TestCase):
    def test_unsupported_secure_storage_capabilities_fail_closed(self):
        from heel.local_projects import LocalProjectStore, SecureStorageUnavailable

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(os, "supports_dir_fd", frozenset()):
                with self.assertRaisesRegex(
                    SecureStorageUnavailable, "secure local review storage"
                ):
                    LocalProjectStore(_physical_temp(tmp))

    def test_review_round_trip_uses_canonical_heel_home_and_sorted_json(self):
        from heel.local_projects import LocalProjectStore

        with tempfile.TemporaryDirectory() as tmp:
            root = _physical_temp(tmp)
            with mock.patch.dict(os.environ, {"HEEL_HOME": str(root)}):
                store = LocalProjectStore()
                envelope = _golden_envelope()
                saved = store.save_review(envelope)

                expected = root / "reviews" / f"{envelope['review_id']}.json"
                self.assertEqual(saved, expected)
                self.assertEqual(store.get_review(envelope["review_id"]), envelope)
                self.assertEqual(
                    store.list_reviews(),
                    [{
                        "review_id": envelope["review_id"],
                        "product_id": envelope["product_id"],
                        "gate_status": envelope["gate_status"],
                    }],
                )
                self.assertEqual(list(root.rglob("*.json")), [expected])
                self.assertEqual(
                    expected.read_text(encoding="utf-8"),
                    stable_json(envelope) + "\n",
                )

    @unittest.skipUnless(os.name == "posix", "POSIX permission bits required")
    def test_store_locks_directories_and_review_files_to_owner(self):
        from heel.local_projects import LocalProjectStore

        with tempfile.TemporaryDirectory() as parent:
            root = _physical_temp(parent) / "heel-home"
            store = LocalProjectStore(root)
            path = store.save_review(_golden_envelope())

            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((root / "reviews").stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    @unittest.skipUnless(os.name == "posix", "POSIX descriptor operations required")
    def test_atomic_replace_is_anchored_and_temp_file_is_owner_only(self):
        from heel.local_projects import LocalProjectStore

        with tempfile.TemporaryDirectory() as tmp:
            root = _physical_temp(tmp) / "heel-home"
            store = LocalProjectStore(root)
            real_replace = os.replace
            calls = []

            def anchored_replace(source, destination, **kwargs):
                self.assertNotIn(os.sep, source)
                self.assertNotIn(os.sep, destination)
                self.assertEqual(kwargs["src_dir_fd"], kwargs["dst_dir_fd"])
                status = os.stat(
                    source, dir_fd=kwargs["src_dir_fd"], follow_symlinks=False
                )
                self.assertEqual(stat.S_IMODE(status.st_mode), 0o600)
                calls.append((source, destination))
                return real_replace(source, destination, **kwargs)

            with mock.patch(
                "heel.local_projects.os.replace", side_effect=anchored_replace
            ):
                path = store.save_review(_golden_envelope())
            self.assertEqual(len(calls), 1)
            self.assertEqual(path.name, _golden_envelope()["review_id"] + ".json")

    def test_fchmod_failure_and_wrong_directory_mode_fail_closed(self):
        from heel.local_projects import LocalProjectStore

        with tempfile.TemporaryDirectory() as tmp:
            root = _physical_temp(tmp) / "heel-home"
            root.mkdir(mode=0o755)
            store = LocalProjectStore(root)
            with mock.patch(
                "heel.local_projects.os.fchmod",
                side_effect=PermissionError("fchmod denied"),
            ):
                with self.assertRaisesRegex(PermissionError, "fchmod denied"):
                    store.save_review(_golden_envelope())
            self.assertEqual(_review_files(root), [])

            with mock.patch("heel.local_projects.os.fchmod", return_value=None):
                with self.assertRaisesRegex(PermissionError, r"mode 0o0?700"):
                    store.save_review(_golden_envelope())
            self.assertEqual(_review_files(root), [])

    def test_file_fsync_failure_propagates_and_cleans_temp(self):
        from heel.local_projects import LocalProjectStore

        with tempfile.TemporaryDirectory() as tmp:
            root = _physical_temp(tmp) / "heel-home"
            store = LocalProjectStore(root)
            with mock.patch(
                "heel.local_projects.os.fsync", side_effect=OSError("file fsync failed")
            ):
                with self.assertRaisesRegex(OSError, "file fsync failed"):
                    store.save_review(_golden_envelope())
            self.assertEqual(_review_files(root), [])

    def test_replace_failure_propagates_and_cleans_temp(self):
        from heel.local_projects import LocalProjectStore

        with tempfile.TemporaryDirectory() as tmp:
            root = _physical_temp(tmp) / "heel-home"
            store = LocalProjectStore(root)
            with mock.patch(
                "heel.local_projects.os.replace", side_effect=OSError("replace failed")
            ):
                with self.assertRaisesRegex(OSError, "replace failed"):
                    store.save_review(_golden_envelope())
            self.assertEqual(_review_files(root), [])

    def test_directory_fsync_failure_propagates_after_replace_without_temp(self):
        from heel.local_projects import LocalProjectStore

        with tempfile.TemporaryDirectory() as tmp:
            root = _physical_temp(tmp) / "heel-home"
            store = LocalProjectStore(root)
            calls = 0

            def fail_directory_fsync(descriptor):
                nonlocal calls
                calls += 1
                if calls == 2:
                    raise OSError("directory fsync failed")

            with mock.patch(
                "heel.local_projects.os.fsync", side_effect=fail_directory_fsync
            ):
                with self.assertRaisesRegex(OSError, "directory fsync failed"):
                    store.save_review(_golden_envelope())
            self.assertEqual(
                _review_files(root), [_golden_envelope()["review_id"] + ".json"]
            )

    def test_invalid_and_traversal_review_ids_are_rejected(self):
        from heel.local_projects import LocalProjectStore

        invalid_ids = (
            "review_abc",
            "review_" + "a" * 19,
            "review_" + "A" * 20,
            "review_" + "a" * 21,
            "../review_" + "a" * 20,
            "review_" + "a" * 20 + "/../../escape",
            "/tmp/review_" + "a" * 20,
            "review_" + "a" * 19 + "g",
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = _physical_temp(tmp)
            store = LocalProjectStore(root)
            for review_id in invalid_ids:
                with self.subTest(review_id=review_id):
                    envelope = _golden_envelope()
                    envelope["review_id"] = review_id
                    with self.assertRaisesRegex(ValueError, "review_id"):
                        store.save_review(envelope)
                    with self.assertRaisesRegex(ValueError, "review_id"):
                        store.get_review(review_id)
            self.assertFalse((root.parent / "escape.json").exists())

    def test_valid_shape_but_wrong_content_address_is_rejected(self):
        from heel.local_projects import LocalProjectStore

        with tempfile.TemporaryDirectory() as tmp:
            store = LocalProjectStore(_physical_temp(tmp))
            envelope = _golden_envelope()
            envelope["review_id"] = "review_" + "a" * 20
            with self.assertRaisesRegex(ValueError, "review_id"):
                store.save_review(envelope)

    def test_symlinked_review_target_is_rejected_for_save_read_and_list(self):
        from heel.local_projects import LocalProjectStore, StoredReviewError

        if not hasattr(os, "symlink"):
            self.skipTest("symbolic links unavailable")
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = _physical_temp(tmp)
            reviews = root / "reviews"
            reviews.mkdir()
            envelope = _golden_envelope()
            outside_path = _physical_temp(outside) / "review.json"
            outside_path.write_text(stable_json(envelope) + "\n", encoding="utf-8")
            target = reviews / f"{envelope['review_id']}.json"
            try:
                target.symlink_to(outside_path)
            except OSError as exc:
                self.skipTest(f"symbolic links unavailable: {exc}")

            store = LocalProjectStore(root)
            with self.assertRaises(StoredReviewError) as caught:
                store.get_review(envelope["review_id"])
            self.assertIn(target.name, str(caught.exception))
            self.assertIn("symbolic link", str(caught.exception.__cause__))
            with self.assertRaises(StoredReviewError) as caught:
                store.list_reviews()
            self.assertIn(target.name, str(caught.exception))
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                store.save_review(envelope)
            self.assertEqual(json.loads(outside_path.read_text(encoding="utf-8")), envelope)

    def test_symlinked_reviews_directory_is_rejected(self):
        from heel.local_projects import LocalProjectStore

        if not hasattr(os, "symlink"):
            self.skipTest("symbolic links unavailable")
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = _physical_temp(tmp)
            outside_root = _physical_temp(outside)
            reviews = root / "reviews"
            try:
                reviews.symlink_to(outside_root, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"symbolic links unavailable: {exc}")
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                LocalProjectStore(root)
            self.assertEqual(list(outside_root.iterdir()), [])

    def test_explicit_symlinked_root_is_rejected_without_writing_outside(self):
        from heel.local_projects import LocalProjectStore

        if not hasattr(os, "symlink"):
            self.skipTest("symbolic links unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            parent = _physical_temp(tmp)
            outside = parent / "outside"
            outside.mkdir()
            symlink_root = parent / "heel-home"
            symlink_root.symlink_to(outside, target_is_directory=True)

            with self.assertRaisesRegex(ValueError, "symbolic link"):
                LocalProjectStore(symlink_root)
            self.assertEqual(list(outside.iterdir()), [])

    def test_default_store_rejects_symlinked_heel_home_without_writing_outside(self):
        from heel.local_projects import LocalProjectStore

        if not hasattr(os, "symlink"):
            self.skipTest("symbolic links unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            parent = _physical_temp(tmp)
            outside = parent / "outside"
            outside.mkdir()
            symlink_root = parent / "heel-home"
            symlink_root.symlink_to(outside, target_is_directory=True)

            with mock.patch.dict(os.environ, {"HEEL_HOME": str(symlink_root)}):
                with self.assertRaisesRegex(ValueError, "symbolic link"):
                    LocalProjectStore()
            self.assertEqual(list(outside.iterdir()), [])

    def test_symlinked_intermediate_ancestor_is_rejected_without_writing_outside(self):
        from heel.local_projects import LocalProjectStore

        if not hasattr(os, "symlink"):
            self.skipTest("symbolic links unavailable")
        with tempfile.TemporaryDirectory() as tmp:
            parent = _physical_temp(tmp)
            outside = parent / "outside"
            outside.mkdir()
            intermediate = parent / "linked-parent"
            intermediate.symlink_to(outside, target_is_directory=True)
            root = intermediate / "heel-home"

            with self.assertRaisesRegex(ValueError, "symbolic link"):
                LocalProjectStore(root)
            self.assertFalse((outside / "heel-home").exists())

    def test_relative_real_root_remains_supported(self):
        from heel.local_projects import LocalProjectStore

        with tempfile.TemporaryDirectory() as tmp:
            parent = _physical_temp(tmp)
            with mock.patch.object(Path, "cwd", return_value=parent):
                store = LocalProjectStore(Path("relative-home"))
            path = store.save_review(_golden_envelope())
            self.assertEqual(path.parent, parent / "relative-home" / "reviews")

    def test_tampered_hash_is_rejected_on_save_read_and_list(self):
        from heel.local_projects import LocalProjectStore, StoredReviewError

        with tempfile.TemporaryDirectory() as tmp:
            store = LocalProjectStore(_physical_temp(tmp))
            envelope = _golden_envelope()
            tampered = json.loads(json.dumps(envelope))
            tampered["product_id"] = "tampered-product"
            with self.assertRaisesRegex(ValueError, "result_hash"):
                store.save_review(tampered)

            path = store.save_review(envelope)
            path.write_text(stable_json(tampered) + "\n", encoding="utf-8")
            with self.assertRaises(StoredReviewError) as caught:
                store.get_review(envelope["review_id"])
            self.assertIn(path.name, str(caught.exception))
            self.assertIn("result_hash", str(caught.exception.__cause__))
            with self.assertRaises(StoredReviewError) as caught:
                store.list_reviews()
            self.assertIn(path.name, str(caught.exception))

    def test_save_snapshots_changing_mapping_before_deriving_review_id(self):
        from heel.local_projects import LocalProjectStore

        envelope = _golden_envelope()
        forged_id = "review_" + "0" * 20

        class ChangingReview(Mapping):
            def __init__(self, values):
                self.values = values
                self.review_id_reads = 0

            def __getitem__(self, key):
                if key == "review_id":
                    self.review_id_reads += 1
                    return envelope["review_id"] if self.review_id_reads == 1 else forged_id
                return self.values[key]

            def __iter__(self):
                return iter(self.values)

            def __len__(self):
                return len(self.values)

        with tempfile.TemporaryDirectory() as tmp:
            root = _physical_temp(tmp)
            saved = LocalProjectStore(root).save_review(ChangingReview(envelope))
            self.assertEqual(saved.name, envelope["review_id"] + ".json")
            self.assertFalse((root / "reviews" / f"{forged_id}.json").exists())

    def test_corrupt_stored_json_fails_visibly(self):
        from heel.local_projects import LocalProjectStore, StoredReviewError

        with tempfile.TemporaryDirectory() as tmp:
            root = _physical_temp(tmp)
            store = LocalProjectStore(root)
            envelope = _golden_envelope()
            reviews = root / "reviews"
            reviews.mkdir()
            path = reviews / f"{envelope['review_id']}.json"
            path.write_text("{not valid JSON\n", encoding="utf-8")

            with self.assertRaises(StoredReviewError) as caught:
                store.get_review(envelope["review_id"])
            self.assertIn(path.name, str(caught.exception))
            self.assertIsInstance(caught.exception.__cause__, json.JSONDecodeError)
            with self.assertRaises(StoredReviewError) as caught:
                store.list_reviews()
            self.assertIn(path.name, str(caught.exception))

    def test_invalid_stored_review_filename_fails_with_filename_context(self):
        from heel.local_projects import LocalProjectStore, StoredReviewError

        with tempfile.TemporaryDirectory() as tmp:
            root = _physical_temp(tmp)
            store = LocalProjectStore(root)
            store.save_review(_golden_envelope())
            invalid = root / "reviews" / "review_invalid.json"
            invalid.write_text("{}\n", encoding="utf-8")

            with self.assertRaises(StoredReviewError) as caught:
                store.list_reviews()
            self.assertIn(invalid.name, str(caught.exception))
            self.assertIsInstance(caught.exception.__cause__, ValueError)

    def test_missing_review_returns_none_and_list_is_deterministic(self):
        from heel.local_projects import LocalProjectStore

        with tempfile.TemporaryDirectory() as tmp:
            store = LocalProjectStore(_physical_temp(tmp))
            self.assertIsNone(store.get_review("review_" + "0" * 20))
            self.assertEqual(store.list_reviews(), [])

            reviews = [_review_for("Zulu Product"), _review_for("Alpha Product")]
            for envelope in reversed(reviews):
                store.save_review(envelope)
            expected = sorted(({
                "review_id": envelope["review_id"],
                "product_id": envelope["product_id"],
                "gate_status": envelope["gate_status"],
            } for envelope in reviews), key=lambda item: item["review_id"])
            self.assertEqual(store.list_reviews(), expected)

    def test_saved_and_returned_reviews_are_detached_from_caller_mutation(self):
        from heel.local_projects import LocalProjectStore

        with tempfile.TemporaryDirectory() as tmp:
            store = LocalProjectStore(_physical_temp(tmp))
            envelope = _golden_envelope()
            expected = json.loads(json.dumps(envelope))
            store.save_review(envelope)

            envelope["product_id"] = "caller-mutated"
            envelope["findings"][0]["reason"] = "caller-mutated"
            loaded = store.get_review(expected["review_id"])
            self.assertEqual(loaded, expected)

            loaded["product_id"] = "return-mutated"
            loaded["findings"][0]["reason"] = "return-mutated"
            self.assertEqual(store.get_review(expected["review_id"]), expected)

    def test_sample_review_persists_only_envelope_not_raw_openapi_content(self):
        from heel.local_projects import LocalProjectStore

        marker = "INTERNAL ROUTE DESCRIPTION: customer source content"
        spec = _sample_spec()
        spec["paths"]["/api/export/bulk"]["get"]["description"] = marker
        envelope = review_openapi(spec)

        with tempfile.TemporaryDirectory() as tmp:
            store = LocalProjectStore(_physical_temp(tmp))
            path = store.save_review(envelope)
            persisted = path.read_text(encoding="utf-8")

            self.assertEqual(json.loads(persisted), envelope)
            self.assertNotIn(marker, persisted)
            self.assertNotIn("Broad access for tests", persisted)
            self.assertNotIn('"paths"', persisted)
            self.assertIn("downloadbulkexport", persisted)
            self.assertIn("/api/export/bulk", persisted)


class ReviewExportTests(unittest.TestCase):
    def test_markdown_is_deterministic_and_contains_required_review_details(self):
        from heel.review_export import review_to_markdown

        envelope = _golden_envelope()
        reordered = {key: value for key, value in reversed(envelope.items())}
        markdown = review_to_markdown(envelope)

        self.assertEqual(markdown, review_to_markdown(reordered))
        self.assertTrue(markdown.startswith(
            "# Heel launch review: acme\\-platform\\-api\n"
        ))
        self.assertIn(f"Gate: **{envelope['gate_status'].upper()}**", markdown)
        self.assertIn(f"Findings: {envelope['summary']['findings']}", markdown)
        self.assertIn(f"Blockers: {envelope['summary']['blockers']}", markdown)
        finding = envelope["findings"][0]
        self.assertIn(f"Severity: **{finding['severity'].upper()}**", markdown)
        self.assertIn("endpoints\\_routes / createoauthapp", markdown)
        self.assertIn(finding["reason"].replace("-", "\\-"), markdown)
        self.assertIn(f"Recommended control: {finding['control']}", markdown)
        self.assertIn("Envelope declares local analysis", markdown)
        self.assertIn("no upload", markdown)

    def test_cloud_markdown_does_not_claim_local_analysis_or_no_upload(self):
        from heel.review_export import review_to_markdown

        markdown = review_to_markdown(
            review_openapi(_sample_spec(), execution_mode="cloud_isolated")
        )
        self.assertIn("Envelope declares isolated cloud analysis", markdown)
        self.assertIn("sanitized-model upload", markdown)
        self.assertNotIn("analyzed locally", markdown)
        self.assertNotIn("was uploaded", markdown)

    def test_markdown_escapes_embedded_html(self):
        from heel.review_contract import build_review_envelope
        from heel.review_export import review_to_markdown

        review = {
            "product_id": "<script>alert(1)</script>",
            "launch_gate_status": "block",
            "new_abuse_affordances": [{
                "surface_type": "exports",
                "surface_id": "<img src=x onerror=alert(1)>",
                "risk": "missing_control",
                "severity": "block",
                "control": "<b>tenant gate</b>",
                "reason": "<svg onload=alert(1)>",
                "reachable": True,
            }],
            "recommended_controls": [],
            "suggested_regression_tests": [],
            "safety": {
                "mode": "static ProductModel diff",
                "live_probing": False,
                "network_calls": False,
                "requires_signed_scope_for_live_or_staging_runs": True,
                "canary_only": True,
            },
        }
        envelope = build_review_envelope(
            review,
            source_hash="a" * 64,
            model_hash="b" * 64,
            baseline_hash=None,
            execution_mode="machine_local",
            questions=[],
        )
        markdown = review_to_markdown(envelope)

        self.assertNotRegex(markdown, r"(?<!\\)<(?:script|img|b|svg)")
        self.assertIn("\\<script\\>", markdown)
        self.assertIn("\\<svg", markdown)

    def test_markdown_collapses_controls_and_escapes_commonmark_injections(self):
        from heel.review_contract import build_review_envelope
        from heel.review_export import review_to_markdown

        review = {
            "product_id": "Product\n# injected heading",
            "launch_gate_status": "block",
            "new_abuse_affordances": [{
                "surface_type": "exports\r\n- injected list",
                "surface_id": "![image](javascript:alert(1))",
                "risk": "risk",
                "severity": "block",
                "control": "`code` *bold* _italic_ \\ raw",
                "reason": "[link](javascript:alert(1))\x00 <script>alert(1)</script>",
                "reachable": True,
            }],
            "recommended_controls": [],
            "suggested_regression_tests": [],
            "safety": {
                "mode": "static ProductModel diff",
                "live_probing": False,
                "network_calls": False,
                "requires_signed_scope_for_live_or_staging_runs": True,
                "canary_only": True,
            },
        }
        envelope = build_review_envelope(
            review,
            source_hash="a" * 64,
            model_hash="b" * 64,
            baseline_hash=None,
            execution_mode="machine_local",
            questions=[],
        )
        markdown = review_to_markdown(envelope)

        for injection in (
            "\n# injected heading",
            "\n- injected list",
            "![image]",
            "[link](",
            "`code`",
            "<script>",
            "\x00",
        ):
            self.assertNotIn(injection, markdown)
        for escaped in (
            "Product \\# injected heading",
            "exports \\- injected list",
            "\\!\\[image\\]\\(javascript\\:alert\\(1\\)\\)",
            "\\[link\\]\\(javascript\\:alert\\(1\\)\\)",
            "\\`code\\` \\*bold\\* \\_italic\\_ \\\\ raw",
            "\\<script\\>alert\\(1\\)\\<\\/script\\>",
        ):
            self.assertIn(escaped, markdown)

    def test_json_export_is_valid_sorted_deterministic_and_integrity_checked(self):
        from heel.review_export import review_to_json, review_to_markdown

        envelope = _golden_envelope()
        reordered = {key: value for key, value in reversed(envelope.items())}
        exported = review_to_json(envelope)
        self.assertEqual(exported, review_to_json(reordered))
        self.assertEqual(exported, stable_json(envelope) + "\n")
        self.assertEqual(json.loads(exported), envelope)

        tampered = json.loads(json.dumps(envelope))
        tampered["gate_status"] = "pass"
        with self.assertRaises(ValueError):
            review_to_json(tampered)
        with self.assertRaises(ValueError):
            review_to_markdown(tampered)


if __name__ == "__main__":
    unittest.main()
