"""Lazy Ed25519 support for signed canary control envelopes."""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json

_RAW_KEY_BYTES = 32
_SIGNATURE_BYTES = 64
_KEY_ID_PREFIX = "k_"
_DOMAIN = b"heel.ed25519.v1:"
_MAX_KEY_ID_BYTES = 128
_DEFAULT_MAX_TRUSTED_KEYS = 64


def _canonical_base64(value: str, size: int) -> bytes:
    if not isinstance(value, str) or not value or len(value) % 4:
        raise ValueError("key must be standard padded base64")
    try:
        decoded = base64.b64decode(value, validate=True)
        canonical = base64.b64encode(decoded).decode("ascii")
    except (ValueError, TypeError):
        raise ValueError("key must be standard padded base64") from None
    if value.encode("ascii") != canonical.encode("ascii") or len(decoded) != size:
        raise ValueError("invalid encoded key")
    return decoded


def ed25519_key_id(public_key_bytes: bytes) -> str:
    if not isinstance(public_key_bytes, bytes) or len(public_key_bytes) != _RAW_KEY_BYTES:
        raise ValueError("Ed25519 public key must contain exactly 32 bytes")
    digest = hashlib.sha256(_DOMAIN + public_key_bytes).hexdigest()
    return _KEY_ID_PREFIX + digest[:16]


def load_private_key_base64(value: str):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return Ed25519PrivateKey.from_private_bytes(_canonical_base64(value, _RAW_KEY_BYTES))


def load_public_key_base64(value: str):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    return Ed25519PublicKey.from_public_bytes(_canonical_base64(value, _RAW_KEY_BYTES))


def load_public_key_set(
    value: str, *, max_keys: int = _DEFAULT_MAX_TRUSTED_KEYS,
) -> dict[str, object]:
    if not isinstance(max_keys, int) or not 1 <= max_keys <= 1024:
        raise ValueError("trusted-key limit must be between 1 and 1024")
    def no_duplicates(pairs):
        result = {}
        for key, entry in pairs:
            if key in result:
                raise ValueError("trusted keys contain a duplicate identifier")
            result[key] = entry
        return result

    try:
        decoded = json.loads(value, object_pairs_hook=no_duplicates)
    except (json.JSONDecodeError, TypeError):
        raise ValueError("trusted keys must be a JSON object") from None
    if not isinstance(decoded, dict) or not decoded or len(decoded) > max_keys:
        raise ValueError(f"trusted keys must contain 1 to {max_keys} entries")
    result: dict[str, object] = {}
    for key_id, encoded in decoded.items():
        if (
            not isinstance(key_id, str)
            or not key_id.strip()
            or len(key_id.encode("utf-8")) > _MAX_KEY_ID_BYTES
            or key_id != key_id.strip()
            or "\x00" in key_id
        ):
            raise ValueError("invalid trusted key identifier")
        public_key_bytes = _canonical_base64(encoded, _RAW_KEY_BYTES)
        if key_id != ed25519_key_id(public_key_bytes):
            raise ValueError("trusted key identifier does not match its public key")
        result[key_id] = load_public_key_base64(encoded)
    return result


def sign_envelope(private_key, key_id: str, payload: bytes) -> dict[str, str]:
    if not isinstance(key_id, str) or not key_id or "\x00" in key_id:
        raise ValueError("signing key ID is required")
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes")
    from cryptography.hazmat.primitives.serialization import Encoding
    from cryptography.hazmat.primitives.serialization import PublicFormat

    actual_id = ed25519_key_id(private_key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw,
    ))
    if key_id != actual_id:
        raise ValueError("signing key ID does not match the supplied private key")
    signature = private_key.sign(payload)
    return {
        "signing_key_id": key_id,
        "signature_b64": base64.b64encode(signature).decode("ascii"),
    }


def verify_envelope(keys: dict[str, object], signed: dict[str, str], payload: bytes) -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if not isinstance(keys, dict) or not isinstance(signed, dict) or not isinstance(payload, bytes):
        raise TypeError("keys, signed envelope, and bytes payload are required")
    if set(signed) != {"signing_key_id", "signature_b64"}:
        raise ValueError("signed envelope must contain exact fields")
    key_id = signed.get("signing_key_id")
    if not isinstance(key_id, str) or key_id not in keys:
        raise ValueError("signing key is not trusted")
    key = keys[key_id]
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("trusted signing key is not an Ed25519 public key")
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    if key_id != ed25519_key_id(key.public_bytes(Encoding.Raw, PublicFormat.Raw)):
        raise ValueError("trusted signing key identifier does not match its public key")
    signature_value = signed.get("signature_b64")
    if not isinstance(signature_value, str):
        raise ValueError("signature is required")
    try:
        signature = base64.b64decode(signature_value, validate=True)
    except (ValueError, TypeError):
        raise ValueError("signature must be standard padded base64") from None
    if len(signature) != _SIGNATURE_BYTES:
        raise ValueError("signature length is invalid")
    if base64.b64encode(signature).decode("ascii") != signature_value:
        raise ValueError("signature must be canonical standard padded base64")
    try:
        key.verify(signature, payload)
    except InvalidSignature:
        raise ValueError("signature verification failed") from None


@dataclass(frozen=True)
class SigningAuthority:
    """An immutable production signing identity with a derived public identifier."""

    private_key: object
    public_key: object
    public_key_bytes: bytes
    key_id: str

    @classmethod
    def generate(cls, key_id: str | None = None):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding
        from cryptography.hazmat.primitives.serialization import PublicFormat

        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        public_key_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        derived = ed25519_key_id(public_key_bytes)
        if key_id is not None and key_id != derived:
            raise ValueError("explicit signing key ID does not match the public key")
        return cls(private_key, public_key, public_key_bytes, derived)

    @classmethod
    def from_private_key(cls, private_key, key_id: str):
        """Build a production authority only when its configured ID is derived from its key."""
        from cryptography.hazmat.primitives.serialization import Encoding
        from cryptography.hazmat.primitives.serialization import PublicFormat

        public_key = private_key.public_key()
        public_key_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        derived = ed25519_key_id(public_key_bytes)
        if key_id != derived:
            raise ValueError("configured signing key ID does not match the private key")
        return cls(private_key, public_key, public_key_bytes, derived)

    @property
    def seed(self) -> bytes:
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PrivateFormat,
            NoEncryption,
        )

        return self.private_key.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption(),
        )

    @property
    def canonical_private_key(self) -> str:
        return base64.b64encode(self.seed).decode("ascii")

    @property
    def canonical_public_key(self) -> str:
        return base64.b64encode(self.public_key_bytes).decode("ascii")

    def sign(self, payload: bytes) -> dict[str, str]:
        return sign_envelope(self.private_key, self.key_id, payload)
