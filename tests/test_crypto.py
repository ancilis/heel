import base64
import hashlib
import unittest

from heel.canary_contracts import canonical_bytes, canonical_digest, validate_execution_grant
from heel.crypto import (
    SigningAuthority,
    ed25519_key_id,
    load_public_key_base64,
    load_private_key_base64,
    load_public_key_set,
    sign_envelope,
    verify_envelope,
)


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


class CryptoTests(unittest.TestCase):
    def setUp(self):
        self.authority = SigningAuthority.generate()
        self.private = self.authority.private_key
        self.public_bytes = self.authority.public_key_bytes

    def test_raw_keys_use_canonical_standard_padded_base64(self):
        private_value = _b64(self.authority.seed)
        public_value = _b64(self.public_bytes)
        self.assertEqual(
            _b64(SigningAuthority.from_private_key(
                load_private_key_base64(private_value), self.authority.key_id,
            ).seed),
            private_value,
        )
        loaded_public = load_public_key_base64(public_value)
        self.assertEqual(loaded_public.public_bytes_raw(), self.public_bytes)
        self.assertIn("=", public_value)

    def test_key_id_is_stable_sha256_digest(self):
        self.assertEqual(
            ed25519_key_id(self.public_bytes),
            "k_" + hashlib.sha256(b"heel.ed25519.v1:" + self.public_bytes).hexdigest()[:16],
        )

    def test_trusted_mapping_is_bounded_and_canonical(self):
        value = '{"' + self.authority.key_id + '":"' + _b64(self.public_bytes) + '"}'
        keys = load_public_key_set(value, max_keys=2)
        self.assertEqual(keys, {self.authority.key_id: load_public_key_base64(_b64(self.public_bytes))})
        with self.assertRaises(ValueError):
            load_public_key_set(value, max_keys=0)
        with self.assertRaises(ValueError):
            load_public_key_set('{"a":"b"}')

    def test_envelope_signs_exact_payload_and_verifies(self):
        payload = b"\x00canonical bytes"
        signed = sign_envelope(self.private, self.authority.key_id, payload)
        self.assertEqual(set(signed), {"signing_key_id", "signature_b64"})
        self.assertEqual(signed["signing_key_id"], self.authority.key_id)
        self.assertEqual(len(base64.b64decode(signed["signature_b64"], validate=True)), 64)
        verify_envelope(
            {self.authority.key_id: self.authority.public_key}, signed, payload)

    def test_wrong_key_id_message_or_signature_fail_closed(self):
        payload = b"payload"
        signed = sign_envelope(self.private, self.authority.key_id, payload)
        other = SigningAuthority.generate()
        with self.assertRaises(ValueError):
            verify_envelope({"wrong": load_public_key_base64(_b64(self.public_bytes))}, signed, payload)
        tampered_key_id = {**signed, "signing_key_id": "wrong"}
        with self.assertRaises(ValueError):
            verify_envelope({"wrong": self.authority.public_key}, tampered_key_id, payload)
        with self.assertRaises(ValueError):
            verify_envelope({self.authority.key_id: other.public_key}, signed, payload)
        with self.assertRaises(ValueError):
            verify_envelope(
                {self.authority.key_id: load_public_key_base64(_b64(self.public_bytes))},
                signed,
                payload + b"x",
            )

    def test_execution_grant_uses_the_frozen_signature_envelope(self):
        from tests.test_canary_contracts import grant

        record = grant()
        payload = {key: value for key, value in record.items()
                   if key not in {"grant_digest", "signing_key_id", "signature_b64"}}
        record["grant_digest"] = canonical_digest(payload)
        record.update(self.authority.sign(canonical_bytes(payload)))
        validated = validate_execution_grant(record)
        verify_envelope(
            {self.authority.key_id: self.authority.public_key},
            {
                "signing_key_id": validated["signing_key_id"],
                "signature_b64": validated["signature_b64"],
            },
            canonical_bytes(payload),
        )

    def test_immutable_authority_signs_with_derived_identifier(self):
        self.assertEqual(self.authority.key_id, ed25519_key_id(self.public_bytes))
        with self.assertRaises(Exception):
            self.authority.key_id = "bad"

    def test_trusted_key_identifier_must_be_derived_from_its_public_key(self):
        value = '{"arbitrary":"' + _b64(self.public_bytes) + '"}'
        with self.assertRaises(ValueError):
            load_public_key_set(value)
