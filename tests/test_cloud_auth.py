"""Local device credential storage security contract."""
from __future__ import annotations

from dataclasses import FrozenInstanceError
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock


def _physical_temp(path: str) -> Path:
    """Avoid macOS's /var -> /private/var alias in ordinary path tests."""
    return Path(path).resolve(strict=True)


def _credentials(
    *,
    base_url: str = "https://cloud.heel.example",
    refresh_character: str = "B",
):
    from heel.cloud_auth import DeviceCredentials

    return DeviceCredentials(
        schema_version="heel.device-credentials.v1",
        cloud_base_url=base_url,
        device_id="dev_" + "a" * 32,
        access_token="heel_at_" + "A" * 43,
        access_expires_at=2_000,
        refresh_token="heel_rt_" + refresh_character * 64,
        refresh_expires_at=3_000,
    )


def _stored_credentials(
    *,
    base_url: str = "https://cloud.heel.example",
    refresh_character: str = "B",
):
    from heel.cloud_auth import StoredDeviceCredentials

    return StoredDeviceCredentials(
        schema_version="heel.stored-device-credentials.v1",
        cloud_base_url=base_url,
        device_id="dev_" + "a" * 32,
        refresh_token="heel_rt_" + refresh_character * 64,
        refresh_expires_at=3_000,
    )


class CredentialValueContractTests(unittest.TestCase):
    def test_credentials_are_exact_and_frozen_and_status_is_redacted(self):
        from heel.cloud_auth import (
            CredentialStatus,
            CredentialStore,
            DeviceCredentials,
            StoredDeviceCredentials,
        )

        credentials = DeviceCredentials(
            schema_version="heel.device-credentials.v1",
            cloud_base_url="https://cloud.heel.example",
            device_id="dev_" + "a" * 32,
            access_token="heel_at_" + "A" * 43,
            access_expires_at=2_000,
            refresh_token="heel_rt_" + "B" * 64,
            refresh_expires_at=3_000,
        )
        self.assertEqual(
            tuple(credentials.__dataclass_fields__),
            (
                "schema_version",
                "cloud_base_url",
                "device_id",
                "access_token",
                "access_expires_at",
                "refresh_token",
                "refresh_expires_at",
            ),
        )
        with self.assertRaises(FrozenInstanceError):
            credentials.access_token = "changed"  # type: ignore[misc]
        stored = _stored_credentials()
        self.assertIsInstance(stored, StoredDeviceCredentials)
        self.assertEqual(
            tuple(stored.__dataclass_fields__),
            (
                "schema_version",
                "cloud_base_url",
                "device_id",
                "refresh_token",
                "refresh_expires_at",
            ),
        )

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch(
                "heel.cloud_auth._macos_keychain_available", return_value=False
            ):
                store = CredentialStore(
                    "https://cloud.heel.example",
                    root=_physical_temp(tmp) / "heel-home",
                )
            self.assertEqual(
                store.status(),
                CredentialStatus(
                    authenticated=False,
                    backend="restricted_file",
                    cloud_base_url=None,
                    device_id=None,
                    refresh_expires_at=None,
                ),
            )

    def test_cloud_origin_is_canonical_and_transport_safe(self):
        from heel.cloud_auth import CredentialStore

        with tempfile.TemporaryDirectory() as tmp:
            root = _physical_temp(tmp) / "heel-home"
            with mock.patch(
                "heel.cloud_auth._macos_keychain_available", return_value=False
            ):
                store = CredentialStore("https://Cloud.Heel.Example:443/", root=root)
                self.assertEqual(store.cloud_base_url, "https://cloud.heel.example")
                CredentialStore("http://127.0.0.1:8080", root=root)
                for invalid in (
                    "http://cloud.heel.example",
                    "https://user@cloud.heel.example",
                    "https://cloud.heel.example/path",
                    "https://cloud.heel.example?token=secret",
                    "https://cloud.heel.example#fragment",
                    "https://cloud.\nheel.example",
                    "https://cloud.heel.example.",
                    "https://\N{SNOWMAN}.example",
                ):
                    with self.subTest(invalid=invalid):
                        with self.assertRaises(ValueError):
                            CredentialStore(invalid, root=root)


class RestrictedFileCredentialStoreTests(unittest.TestCase):
    def _store(self, root: Path):
        from heel.cloud_auth import CredentialStore

        patcher = mock.patch(
            "heel.cloud_auth._macos_keychain_available", return_value=False
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        return CredentialStore("https://cloud.heel.example", root=root)

    @unittest.skipUnless(os.name == "posix", "POSIX descriptor operations required")
    def test_round_trip_is_canonical_owner_only_and_status_never_contains_tokens(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _physical_temp(tmp) / "heel-home"
            store = self._store(root)

            path = store.save(_credentials())

            account = __import__("hashlib").sha256(
                b"https://cloud.heel.example"
            ).hexdigest()
            self.assertEqual(
                path, root / "cloud" / f"credentials-{account}.json"
            )
            self.assertEqual(store.load(), _stored_credentials())
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((root / "cloud").stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            expected = json.dumps(
                {
                    "cloud_base_url": "https://cloud.heel.example",
                    "device_id": "dev_" + "a" * 32,
                    "refresh_expires_at": 3_000,
                    "refresh_token": "heel_rt_" + "B" * 64,
                    "schema_version": "heel.stored-device-credentials.v1",
                },
                sort_keys=True,
                separators=(",", ":"),
            ) + "\n"
            self.assertEqual(path.read_text(encoding="utf-8"), expected)
            self.assertNotIn("heel_at_", path.read_text(encoding="utf-8"))
            status = store.status()
            self.assertTrue(status.authenticated)
            self.assertEqual(status.device_id, "dev_" + "a" * 32)
            rendered = repr(status)
            self.assertNotIn("heel_at_", rendered)
            self.assertNotIn("heel_rt_", rendered)

    def test_delete_removes_only_credentials_and_preserves_sync_queue(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _physical_temp(tmp) / "heel-home"
            store = self._store(root)
            store.save(_credentials())
            queue = root / "sync-queue" / "approved-request.json"
            queue.parent.mkdir(mode=0o700)
            queue.write_text("persist", encoding="utf-8")

            store.delete()
            store.delete()

            self.assertIsNone(store.load())
            self.assertEqual(queue.read_text(encoding="utf-8"), "persist")

    def test_save_accepts_only_the_frozen_closed_credential_type(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _physical_temp(tmp) / "heel-home"
            store = self._store(root)
            exact_mapping = {
                name: getattr(_credentials(), name)
                for name in _credentials().__dataclass_fields__
            }

            with self.assertRaisesRegex(ValueError, "DeviceCredentials"):
                store.save(exact_mapping)  # type: ignore[arg-type]
            self.assertFalse(store.credentials_path.exists())

    def test_fallback_credentials_are_isolated_by_cloud_origin(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _physical_temp(tmp) / "heel-home"
            first = self._store(root)
            from heel.cloud_auth import CredentialStore

            second = CredentialStore("https://other.heel.example", root=root)
            first_path = first.save(_credentials())
            second_path = second.save(
                _credentials(
                    base_url="https://other.heel.example", refresh_character="C"
                )
            )

            self.assertNotEqual(first_path, second_path)
            self.assertEqual(first.load(), _stored_credentials())
            self.assertEqual(
                second.load(),
                _stored_credentials(
                    base_url="https://other.heel.example", refresh_character="C"
                ),
            )
            first.delete()
            self.assertIsNone(first.load())
            self.assertIsNotNone(second.load())

    def test_refresh_lock_serializes_load_network_save_across_instances(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _physical_temp(tmp) / "heel-home"
            first = self._store(root)
            second = self._store(root)
            attempting = threading.Event()
            acquired = threading.Event()

            def contender():
                attempting.set()
                with second.refresh_lock():
                    acquired.set()

            with first.refresh_lock():
                thread = threading.Thread(target=contender, daemon=True)
                thread.start()
                self.assertTrue(attempting.wait(1))
                self.assertFalse(acquired.wait(0.1))

            self.assertTrue(acquired.wait(1))
            thread.join(1)
            self.assertFalse(thread.is_alive())

    def test_load_rejects_extra_duplicate_and_malformed_fields_without_echoing_secrets(self):
        from heel.cloud_auth import StoredCredentialError

        corrupt_documents = [
            json.dumps(
                {
                    **{
                        name: getattr(_stored_credentials(), name)
                        for name in _stored_credentials().__dataclass_fields__
                    },
                    "metadata": {"raw_review": "must-not-cross"},
                }
            ),
            '{"schema_version":"heel.stored-device-credentials.v1",'
            '"schema_version":"heel.stored-device-credentials.v1"}',
            json.dumps(
                {
                    **{
                        name: getattr(_stored_credentials(), name)
                        for name in _stored_credentials().__dataclass_fields__
                    },
                    "refresh_expires_at": True,
                }
            ),
            json.dumps(
                {
                    **{
                        name: getattr(_stored_credentials(), name)
                        for name in _stored_credentials().__dataclass_fields__
                    },
                    "refresh_token": "heel_rt_BAD_SECRET",
                }
            ),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            root = _physical_temp(tmp) / "heel-home"
            store = self._store(root)
            store.save(_credentials())
            for document in corrupt_documents:
                with self.subTest(document=document[:30]):
                    store.credentials_path.write_text(document, encoding="utf-8")
                    with self.assertRaises(StoredCredentialError) as caught:
                        store.load()
                    self.assertNotIn("must-not-cross", str(caught.exception))
                    self.assertNotIn("heel_rt_BAD_SECRET", str(caught.exception))

            store.credentials_path.write_bytes(b"{" + b"x" * (16 * 1024))
            with self.assertRaises(StoredCredentialError):
                store.load()

    @unittest.skipUnless(os.name == "posix", "POSIX descriptor operations required")
    def test_symlink_and_nonregular_targets_are_rejected(self):
        from heel.cloud_auth import StoredCredentialError

        with tempfile.TemporaryDirectory() as tmp:
            parent = _physical_temp(tmp)
            real_root = parent / "real"
            real_root.mkdir()
            linked_root = parent / "linked"
            linked_root.symlink_to(real_root, target_is_directory=True)
            linked_store = self._store(linked_root)
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                linked_store.save(_credentials())

        with tempfile.TemporaryDirectory() as tmp:
            root = _physical_temp(tmp) / "heel-home"
            store = self._store(root)
            cloud = root / "cloud"
            cloud.mkdir(parents=True)
            os.mkfifo(store.credentials_path, mode=0o600)
            with self.assertRaises(StoredCredentialError):
                store.load()
            with self.assertRaisesRegex(ValueError, "regular file"):
                store.save(_credentials())

    @unittest.skipUnless(os.name == "posix", "POSIX descriptor operations required")
    def test_failed_anchored_replace_keeps_prior_credentials_and_cleans_temp(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _physical_temp(tmp) / "heel-home"
            store = self._store(root)
            first = _credentials()
            store.save(first)
            replacement = _credentials(refresh_character="C")
            with mock.patch(
                "heel.cloud_auth.os.replace", side_effect=OSError("replace failed")
            ):
                with self.assertRaisesRegex(OSError, "replace failed"):
                    store.save(replacement)

            self.assertEqual(store.load(), _stored_credentials())
            self.assertEqual(
                sorted(path.name for path in (root / "cloud").iterdir()),
                [store.credentials_path.name],
            )

    def test_unsupported_secure_fallback_capabilities_fail_closed(self):
        from heel.cloud_auth import CredentialStore, SecureCredentialStorageUnavailable

        with tempfile.TemporaryDirectory() as tmp:
            root = _physical_temp(tmp) / "heel-home"
            with mock.patch(
                "heel.cloud_auth._macos_keychain_available", return_value=False
            ), mock.patch.object(os, "supports_dir_fd", frozenset()):
                with self.assertRaisesRegex(
                    SecureCredentialStorageUnavailable, "secure credential fallback"
                ):
                    CredentialStore("https://cloud.heel.example", root=root)


class MacOSKeychainCredentialStoreTests(unittest.TestCase):
    def _store(self, root: Path):
        from heel.cloud_auth import CredentialStore

        available = mock.patch(
            "heel.cloud_auth._macos_keychain_available", return_value=True
        )
        available.start()
        self.addCleanup(available.stop)
        return CredentialStore("https://cloud.heel.example", root=root)

    def test_security_process_capture_retains_at_most_the_document_limit(self):
        from heel.cloud_auth import _run_bounded_process

        result = _run_bounded_process(
            [
                sys.executable,
                "-c",
                "import sys; sys.stdout.buffer.write(b'x' * (32 * 1024))",
            ],
            payload=None,
        )

        self.assertEqual(result.returncode, 0)
        self.assertEqual(len(result.stdout), 16 * 1024 + 1)

    def test_keychain_round_trip_passes_secret_only_over_stdin(self):
        import hashlib

        with tempfile.TemporaryDirectory() as tmp:
            root = _physical_temp(tmp) / "heel-home"
            store = self._store(root)
            calls = []
            saved_payload = None

            def run(command, *, payload):
                nonlocal saved_payload
                calls.append((command, payload))
                if command[1] == "add-generic-password":
                    saved_payload = payload
                    return subprocess.CompletedProcess(command, 0, b"", b"")
                if command[1] == "find-generic-password":
                    return subprocess.CompletedProcess(command, 0, saved_payload, b"")
                raise AssertionError(command)

            with mock.patch("heel.cloud_auth._run_bounded_process", side_effect=run):
                self.assertIsNone(store.save(_credentials()))
                self.assertEqual(store.load(), _stored_credentials())

            account = hashlib.sha256(b"https://cloud.heel.example").hexdigest()
            self.assertEqual(
                calls[0][0],
                [
                    "/usr/bin/security",
                    "add-generic-password",
                    "-U",
                    "-a",
                    account,
                    "-s",
                    "io.ancilis.heel.cloud.v1",
                    "-w",
                ],
            )
            self.assertEqual(
                calls[1][0],
                [
                    "/usr/bin/security",
                    "find-generic-password",
                    "-a",
                    account,
                    "-s",
                    "io.ancilis.heel.cloud.v1",
                    "-w",
                ],
            )
            for command, payload in calls:
                rendered_command = " ".join(command)
                self.assertNotIn("heel_at_", rendered_command)
                self.assertNotIn("heel_rt_", rendered_command)
                self.assertNotIn(b"heel_at_", payload or b"")
            self.assertNotIn(b"heel_at_", calls[0][1])
            self.assertIn(b"heel_rt_", calls[0][1])
            self.assertIsNone(calls[1][1])
            self.assertFalse(root.exists())

    def test_missing_item_is_unauthenticated_but_denial_never_falls_back(self):
        from heel.cloud_auth import CredentialStoreError

        with tempfile.TemporaryDirectory() as tmp:
            root = _physical_temp(tmp) / "heel-home"
            store = self._store(root)
            missing = subprocess.CompletedProcess([], 44, b"", b"not found")
            denied = subprocess.CompletedProcess([], 51, b"", b"interaction denied")

            with mock.patch(
                "heel.cloud_auth._run_bounded_process", return_value=missing
            ):
                self.assertIsNone(store.load())
            with mock.patch(
                "heel.cloud_auth._run_bounded_process", return_value=denied
            ):
                with self.assertRaisesRegex(CredentialStoreError, "Keychain") as caught:
                    store.save(_credentials())
            self.assertNotIn("interaction denied", str(caught.exception))
            self.assertFalse(root.exists())

    def test_delete_is_keychain_only_and_missing_item_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = _physical_temp(tmp) / "heel-home"
            store = self._store(root)
            calls = []

            def run(command, *, payload):
                calls.append((command, payload))
                return subprocess.CompletedProcess(command, 44, b"", b"not found")

            with mock.patch("heel.cloud_auth._run_bounded_process", side_effect=run):
                store.delete()

            self.assertEqual(calls[0][0][1], "delete-generic-password")
            self.assertIsNone(calls[0][1])
            self.assertFalse(root.exists())


if __name__ == "__main__":
    unittest.main()
