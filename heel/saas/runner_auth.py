"""Runner pairing and rotating proof-of-possession authentication.

This is intentionally separate from browser, API-key, and device authentication.
Runner requests prove control of an Ed25519 key for one fixed route and then consume
a one-time, domain-hashed nonce in the same small database transaction as the action.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import re
import secrets
import sqlite3
import time
import unicodedata
from dataclasses import dataclass
from typing import Callable, Literal, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from heel.canary_contracts import (
    canonical_bytes, canonical_digest, parse_json, validate_runner_identity,
)
from heel.crypto import ed25519_key_id, load_public_key_base64
from heel.runner.identity import runner_phrase_words, validate_pairing_phrase


PAIRING_TTL = 10 * 60
NONCE_TTL = 60
CLOCK_SKEW_MS = 30_000
MAX_RUNNER_BODY = 64 * 1024
MAX_RUNNER_UPLOAD_BODY = 272 * 1024
MAX_SEALED_RESPONSE_BODY = 512 * 1024
_SAFE_JSON_INT = (1 << 53) - 1
RUNNER_CAPABILITIES = ("runner_claim", "runner_heartbeat", "runner_progress", "runner_result")


def _normalize_sealed_response(value, depth: int = 0):
    """Normalize trusted action output without widening signed contract JSON."""
    if depth > 16:
        raise ValueError("runner response nesting is too deep")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if not -_SAFE_JSON_INT <= value <= _SAFE_JSON_INT:
            raise ValueError("runner response integer is outside the portable range")
        return value
    if isinstance(value, float):
        raise ValueError("runner response floats are forbidden")
    if isinstance(value, str):
        if (
            unicodedata.normalize("NFC", value) != value
            or len(value.encode("utf-8")) > 4096
            or any(
                unicodedata.category(character) == "Cc"
                or 0xD800 <= ord(character) <= 0xDFFF
                for character in value
            )
        ):
            raise ValueError("runner response text is invalid")
        return value
    if isinstance(value, list):
        return [_normalize_sealed_response(item, depth + 1) for item in value]
    if isinstance(value, dict):
        output = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("runner response keys must be strings")
            normalized_key = _normalize_sealed_response(key, depth + 1)
            if normalized_key in output:
                raise ValueError("runner response keys are ambiguous")
            output[normalized_key] = _normalize_sealed_response(item, depth + 1)
        return output
    raise ValueError("runner response value is unsupported")


def _sealed_response_json(value: dict) -> str:
    if not isinstance(value, dict):
        raise ValueError("runner action must return a response object")
    normalized = _normalize_sealed_response(value)
    encoded = json.dumps(
        normalized,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(encoded) > MAX_SEALED_RESPONSE_BODY:
        raise ValueError("runner response is too large")
    return encoded.decode("utf-8")


RUNNER_AUTH_SCHEMA = """
CREATE TABLE IF NOT EXISTS canary_runner_pairings(
  pairing_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL,
  invitation_hash TEXT NOT NULL UNIQUE, phrase TEXT, public_key TEXT, fingerprint TEXT,
  key_id TEXT, runner_version TEXT, adapters_json TEXT, activation_challenge TEXT,
  status TEXT NOT NULL, created_at REAL NOT NULL, expires_at REAL NOT NULL,
  approved_at REAL, activated_at REAL, approved_by TEXT,
  UNIQUE(workspace_id, runner_id));
CREATE TABLE IF NOT EXISTS canary_runner_nonce_chains(
  workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL, chain_name TEXT NOT NULL,
  nonce_hash TEXT NOT NULL, next_sequence INTEGER NOT NULL, expires_at REAL NOT NULL,
  PRIMARY KEY(workspace_id, runner_id, chain_name));
CREATE TABLE IF NOT EXISTS canary_runner_request_ledger(
  workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL, chain_name TEXT NOT NULL,
  sequence INTEGER NOT NULL, request_digest TEXT NOT NULL, response_json TEXT NOT NULL,
  next_nonce TEXT NOT NULL, created_at REAL NOT NULL,
  PRIMARY KEY(workspace_id, runner_id, chain_name, sequence));
CREATE INDEX IF NOT EXISTS idx_canary_runner_pairings_expiry
 ON canary_runner_pairings(expires_at);
CREATE INDEX IF NOT EXISTS idx_canary_runner_ledger_cleanup
 ON canary_runner_request_ledger(created_at);
CREATE TABLE IF NOT EXISTS canary_runner_rotations(
  pairing_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL,
  phrase TEXT NOT NULL, public_key TEXT NOT NULL, fingerprint TEXT NOT NULL, key_id TEXT NOT NULL,
  runner_version TEXT NOT NULL, adapters_json TEXT NOT NULL, activation_challenge TEXT,
  status TEXT NOT NULL, created_at REAL NOT NULL, expires_at REAL NOT NULL,
  approved_at REAL, activated_at REAL, approved_by TEXT);
"""

# Migration nine established the isolated tables.  Migration ten only appends columns: it
# never rewrites that applied schema, and makes a replay receipt attest the entire verified
# request rather than merely its body.
RUNNER_AUTH_HARDENING_MIGRATION = """
ALTER TABLE canary_runner_request_ledger ADD COLUMN nonce_hash TEXT;
ALTER TABLE canary_runner_request_ledger ADD COLUMN key_id TEXT;
ALTER TABLE canary_runner_request_ledger ADD COLUMN capability TEXT;
ALTER TABLE canary_runner_request_ledger ADD COLUMN method TEXT;
ALTER TABLE canary_runner_request_ledger ADD COLUMN path TEXT;
ALTER TABLE canary_runner_request_ledger ADD COLUMN timestamp_ms INTEGER;
ALTER TABLE canary_runner_request_ledger ADD COLUMN signed_request_digest TEXT;
ALTER TABLE canary_runner_request_ledger ADD COLUMN body_digest TEXT;
ALTER TABLE canary_runner_request_ledger ADD COLUMN response_ciphertext TEXT;
ALTER TABLE canary_runner_request_ledger ADD COLUMN next_nonce_ciphertext TEXT;
"""

# Migration eleven intentionally leaves migrations 9 and 10 byte-stable.  The runner tables
# below are rebuilt where SQLite permits it, adding tenant FKs and vocabulary checks; the
# identity/audit tables are new immutable lifecycle projections.
RUNNER_AUTH_LIFECYCLE_MIGRATION = """
ALTER TABLE canary_runner_pairings RENAME TO canary_runner_pairings_v10;
CREATE TABLE canary_runner_pairings(
  pairing_id TEXT PRIMARY KEY CHECK(length(pairing_id) BETWEEN 1 AND 128),
  workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL,
  invitation_hash TEXT NOT NULL UNIQUE CHECK(length(invitation_hash)=64 AND invitation_hash NOT GLOB '*[^0-9a-f]*'),
  phrase TEXT, public_key TEXT, fingerprint TEXT, key_id TEXT, runner_version TEXT,
  adapters_json TEXT, activation_challenge TEXT,
  status TEXT NOT NULL CHECK(status IN ('invited','pending','approved','activated','expired')),
  created_at REAL NOT NULL, expires_at REAL NOT NULL, approved_at REAL, activated_at REAL, approved_by TEXT,
  UNIQUE(workspace_id, runner_id), FOREIGN KEY(workspace_id) REFERENCES workspaces(workspace_id));
INSERT INTO canary_runner_pairings SELECT * FROM canary_runner_pairings_v10;
DROP TABLE canary_runner_pairings_v10;
ALTER TABLE canary_runner_nonce_chains RENAME TO canary_runner_nonce_chains_v10;
CREATE TABLE canary_runner_nonce_chains(
  workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL, chain_name TEXT NOT NULL,
  nonce_hash TEXT NOT NULL CHECK(length(nonce_hash)=64 AND nonce_hash NOT GLOB '*[^0-9a-f]*'),
  next_sequence INTEGER NOT NULL CHECK(next_sequence >= 1), expires_at REAL NOT NULL,
  PRIMARY KEY(workspace_id,runner_id,chain_name),
  FOREIGN KEY(workspace_id,runner_id) REFERENCES canary_runners(workspace_id,runner_id));
INSERT INTO canary_runner_nonce_chains SELECT * FROM canary_runner_nonce_chains_v10;
DROP TABLE canary_runner_nonce_chains_v10;
ALTER TABLE canary_runner_request_ledger RENAME TO canary_runner_request_ledger_v10;
CREATE TABLE canary_runner_request_ledger(
  workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL, chain_name TEXT NOT NULL,
  sequence INTEGER NOT NULL CHECK(sequence >= 1), request_digest TEXT NOT NULL,
  response_json TEXT NOT NULL, next_nonce TEXT NOT NULL, created_at REAL NOT NULL,
  nonce_hash TEXT, key_id TEXT, capability TEXT CHECK(capability IN ('runner_claim','runner_heartbeat','runner_progress','runner_result')),
  method TEXT CHECK(method='POST'), path TEXT, timestamp_ms INTEGER CHECK(timestamp_ms >= 0),
  signed_request_digest TEXT, body_digest TEXT, response_ciphertext TEXT, next_nonce_ciphertext TEXT,
  PRIMARY KEY(workspace_id,runner_id,chain_name,sequence),
  FOREIGN KEY(workspace_id,runner_id) REFERENCES canary_runners(workspace_id,runner_id));
INSERT INTO canary_runner_request_ledger SELECT * FROM canary_runner_request_ledger_v10;
DROP TABLE canary_runner_request_ledger_v10;
ALTER TABLE canary_runner_rotations RENAME TO canary_runner_rotations_v10;
CREATE TABLE canary_runner_rotations(
  pairing_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL,
  phrase TEXT NOT NULL, public_key TEXT NOT NULL, fingerprint TEXT NOT NULL CHECK(length(fingerprint)=64 AND fingerprint NOT GLOB '*[^0-9a-f]*'),
  key_id TEXT NOT NULL, runner_version TEXT NOT NULL, adapters_json TEXT NOT NULL, activation_challenge TEXT,
  status TEXT NOT NULL CHECK(status IN ('rotation_pending','rotation_approved','rotated','expired')),
  created_at REAL NOT NULL, expires_at REAL NOT NULL, approved_at REAL, activated_at REAL, approved_by TEXT,
  FOREIGN KEY(workspace_id,runner_id) REFERENCES canary_runners(workspace_id,runner_id));
INSERT INTO canary_runner_rotations SELECT * FROM canary_runner_rotations_v10;
DROP TABLE canary_runner_rotations_v10;
CREATE TABLE IF NOT EXISTS canary_runner_identity_records(
  workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL, identity_json TEXT NOT NULL,
  identity_digest TEXT NOT NULL CHECK(length(identity_digest)=64 AND identity_digest NOT GLOB '*[^0-9a-f]*'),
  updated_at REAL NOT NULL, PRIMARY KEY(workspace_id,runner_id), UNIQUE(identity_digest),
  FOREIGN KEY(workspace_id,runner_id) REFERENCES canary_runners(workspace_id,runner_id));
CREATE TABLE IF NOT EXISTS canary_runner_audit_records(
  audit_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL,
  action TEXT NOT NULL CHECK(action IN ('runner_revoked','runner_rotated','runner_activated')),
  actor TEXT NOT NULL, reason_code TEXT, created_at REAL NOT NULL,
  FOREIGN KEY(workspace_id,runner_id) REFERENCES canary_runners(workspace_id,runner_id));
UPDATE canary_runners SET status='disabled' WHERE status='active';
"""

RUNNER_AUTH_RESYNC_MIGRATION = """
ALTER TABLE canary_runner_pairings ADD COLUMN display_name TEXT;
UPDATE canary_runner_pairings SET status='expired' WHERE status IN ('invited','pending','approved');
CREATE TABLE IF NOT EXISTS canary_runner_chain_cursors(
 workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL, chain_name TEXT NOT NULL,
 next_sequence INTEGER NOT NULL CHECK(next_sequence>=1), generation INTEGER NOT NULL CHECK(generation>=0), updated_at REAL NOT NULL,
 PRIMARY KEY(workspace_id,runner_id,chain_name), FOREIGN KEY(workspace_id,runner_id) REFERENCES canary_runners(workspace_id,runner_id));
CREATE TABLE IF NOT EXISTS canary_runner_resync_challenges(
 challenge_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL, chain_name TEXT NOT NULL,
 client_nonce_hash TEXT NOT NULL, server_challenge_hash TEXT NOT NULL, signed_digest TEXT NOT NULL,
 client_nonce_ciphertext TEXT NOT NULL, server_challenge_ciphertext TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('pending','completed','invalidated')), created_at REAL NOT NULL, expires_at REAL NOT NULL,
 completed_response_ciphertext TEXT, complete_signed_digest TEXT, completed_at REAL,
 FOREIGN KEY(workspace_id,runner_id,chain_name) REFERENCES canary_runner_chain_cursors(workspace_id,runner_id,chain_name));
CREATE UNIQUE INDEX IF NOT EXISTS idx_runner_key_triple ON canary_runner_keys(workspace_id,runner_id,key_id);
CREATE INDEX IF NOT EXISTS idx_canary_runner_pairings_expiry ON canary_runner_pairings(expires_at);
CREATE INDEX IF NOT EXISTS idx_canary_runner_ledger_cleanup ON canary_runner_request_ledger(created_at);
CREATE INDEX IF NOT EXISTS idx_canary_runner_nonce_expiry ON canary_runner_nonce_chains(expires_at);
CREATE INDEX IF NOT EXISTS idx_canary_runner_resync_expiry ON canary_runner_resync_challenges(expires_at);
CREATE INDEX IF NOT EXISTS idx_canary_runner_resync_rate ON canary_runner_resync_challenges(workspace_id,runner_id,created_at);
"""

# Migration thirteen is the only compatibility bridge from the pre-operation chain namespace.
# It never guesses an ambiguous heartbeat ledger operation: the exact persisted route decides,
# and anything else becomes non-replayable evidence in the archive.
RUNNER_AUTH_GENERATION_MIGRATION = """
ALTER TABLE canary_runner_pairings RENAME TO canary_runner_pairings_v12;
CREATE TABLE canary_runner_pairings(
  pairing_id TEXT PRIMARY KEY CHECK(length(pairing_id) BETWEEN 1 AND 128),
  workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL,
  invitation_hash TEXT NOT NULL UNIQUE CHECK(length(invitation_hash)=64 AND invitation_hash NOT GLOB '*[^0-9a-f]*'),
  phrase TEXT, public_key TEXT, fingerprint TEXT, key_id TEXT, runner_version TEXT,
  adapters_json TEXT, activation_challenge TEXT,
  status TEXT NOT NULL CHECK(status IN ('invited','pending','approved','activated','expired')),
  created_at REAL NOT NULL, expires_at REAL NOT NULL, approved_at REAL, activated_at REAL, approved_by TEXT,
  display_name TEXT CHECK(display_name IS NULL OR (length(display_name) BETWEEN 1 AND 64 AND length(CAST(display_name AS BLOB))<=128 AND trim(display_name)=display_name)),
  UNIQUE(workspace_id, runner_id), FOREIGN KEY(workspace_id) REFERENCES workspaces(workspace_id));
INSERT INTO canary_runner_pairings SELECT * FROM canary_runner_pairings_v12;
DROP TABLE canary_runner_pairings_v12;

ALTER TABLE canary_runner_nonce_chains RENAME TO canary_runner_nonce_chains_v12;
CREATE TABLE canary_runner_nonce_chains(
  workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL, chain_name TEXT NOT NULL CHECK(chain_name='claim' OR chain_name GLOB 'heartbeat:?*' OR chain_name GLOB 'progress:?*' OR chain_name GLOB 'result:?*' OR chain_name GLOB 'stop-ack:?*'),
  nonce_hash TEXT NOT NULL CHECK(length(nonce_hash)=64 AND nonce_hash NOT GLOB '*[^0-9a-f]*'),
  next_sequence INTEGER NOT NULL CHECK(next_sequence>=1), expires_at REAL NOT NULL,
  PRIMARY KEY(workspace_id,runner_id,chain_name), FOREIGN KEY(workspace_id,runner_id) REFERENCES canary_runners(workspace_id,runner_id));
INSERT INTO canary_runner_nonce_chains
SELECT workspace_id,runner_id,
 CASE WHEN chain_name='claim' THEN 'claim'
      WHEN chain_name GLOB 'runner_progress:?*' THEN 'progress:'||substr(chain_name,17)
      WHEN chain_name GLOB 'runner_result:?*' THEN 'result:'||substr(chain_name,15)
      WHEN chain_name GLOB 'runner_heartbeat:?*' THEN 'heartbeat:'||substr(chain_name,18)
      ELSE chain_name END,
 nonce_hash,next_sequence,expires_at
FROM canary_runner_nonce_chains_v12
WHERE chain_name='claim' OR chain_name GLOB 'runner_progress:?*' OR chain_name GLOB 'runner_result:?*' OR chain_name GLOB 'runner_heartbeat:?*'
   OR chain_name GLOB 'heartbeat:?*' OR chain_name GLOB 'progress:?*' OR chain_name GLOB 'result:?*' OR chain_name GLOB 'stop-ack:?*';

ALTER TABLE canary_runner_chain_cursors RENAME TO canary_runner_chain_cursors_v12;
ALTER TABLE canary_runner_request_ledger RENAME TO canary_runner_request_ledger_v12;
CREATE TABLE canary_runner_request_ledger_archive(
  workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL, legacy_chain_name TEXT NOT NULL,
  sequence INTEGER NOT NULL, request_digest TEXT, response_json TEXT, next_nonce TEXT, created_at REAL NOT NULL,
  nonce_hash TEXT, key_id TEXT, capability TEXT, method TEXT, path TEXT, timestamp_ms INTEGER,
  signed_request_digest TEXT, body_digest TEXT, response_ciphertext TEXT, next_nonce_ciphertext TEXT,
  archive_reason TEXT NOT NULL CHECK(archive_reason IN ('unclassifiable_operation','path_chain_mismatch')),
  PRIMARY KEY(workspace_id,runner_id,legacy_chain_name,sequence),
  FOREIGN KEY(workspace_id,runner_id) REFERENCES canary_runners(workspace_id,runner_id));
INSERT INTO canary_runner_request_ledger_archive
SELECT *, CASE WHEN path IS NULL THEN 'unclassifiable_operation' ELSE 'path_chain_mismatch' END
FROM canary_runner_request_ledger_v12
WHERE NOT (
 chain_name='claim' AND capability='runner_claim' AND path LIKE '%/claim' OR
 chain_name GLOB 'runner_progress:?*' AND capability='runner_progress' AND path LIKE '%/progress' OR
 chain_name GLOB 'runner_result:?*' AND capability='runner_result' AND path LIKE '%/result' OR
 chain_name GLOB 'runner_heartbeat:?*' AND capability='runner_heartbeat' AND (path LIKE '%/heartbeat' OR path LIKE '%/stop-ack') OR
 chain_name GLOB 'progress:?*' AND capability='runner_progress' AND path LIKE '%/progress' OR
 chain_name GLOB 'result:?*' AND capability='runner_result' AND path LIKE '%/result' OR
 chain_name GLOB 'heartbeat:?*' AND capability='runner_heartbeat' AND path LIKE '%/heartbeat' OR
 chain_name GLOB 'stop-ack:?*' AND capability='runner_heartbeat' AND path LIKE '%/stop-ack');

CREATE TABLE canary_runner_chain_cursors(
 workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL,
 chain_name TEXT NOT NULL CHECK(chain_name='claim' OR chain_name GLOB 'heartbeat:?*' OR chain_name GLOB 'progress:?*' OR chain_name GLOB 'result:?*' OR chain_name GLOB 'stop-ack:?*'),
 next_sequence INTEGER NOT NULL CHECK(next_sequence>=1), generation INTEGER NOT NULL CHECK(generation>=0), updated_at REAL NOT NULL,
 PRIMARY KEY(workspace_id,runner_id,chain_name), FOREIGN KEY(workspace_id,runner_id) REFERENCES canary_runners(workspace_id,runner_id));
INSERT INTO canary_runner_chain_cursors
WITH candidates(workspace_id,runner_id,chain_name,next_sequence,generation,updated_at) AS (
 SELECT workspace_id,runner_id,
  CASE WHEN chain_name='claim' THEN 'claim' WHEN chain_name GLOB 'runner_progress:?*' THEN 'progress:'||substr(chain_name,17) WHEN chain_name GLOB 'runner_result:?*' THEN 'result:'||substr(chain_name,15) WHEN chain_name GLOB 'runner_heartbeat:?*' THEN 'heartbeat:'||substr(chain_name,18) ELSE chain_name END,
  next_sequence,generation,updated_at FROM canary_runner_chain_cursors_v12
 UNION ALL SELECT workspace_id,runner_id,chain_name,next_sequence,0,0 FROM canary_runner_nonce_chains
 UNION ALL SELECT workspace_id,runner_id,
  CASE WHEN chain_name='claim' THEN 'claim' WHEN path LIKE '%/progress' THEN 'progress:'||substr(chain_name,instr(chain_name,':')+1) WHEN path LIKE '%/result' THEN 'result:'||substr(chain_name,instr(chain_name,':')+1) WHEN path LIKE '%/heartbeat' THEN 'heartbeat:'||substr(chain_name,instr(chain_name,':')+1) WHEN path LIKE '%/stop-ack' THEN 'stop-ack:'||substr(chain_name,instr(chain_name,':')+1) END,
  sequence+1,0,created_at FROM canary_runner_request_ledger_v12
 WHERE chain_name='claim' AND capability='runner_claim' AND path LIKE '%/claim' OR capability='runner_progress' AND path LIKE '%/progress' OR capability='runner_result' AND path LIKE '%/result' OR capability='runner_heartbeat' AND (path LIKE '%/heartbeat' OR path LIKE '%/stop-ack')
)
SELECT workspace_id,runner_id,chain_name,max(next_sequence),max(generation),max(updated_at)
FROM candidates WHERE chain_name IS NOT NULL GROUP BY workspace_id,runner_id,chain_name;
DELETE FROM canary_runner_nonce_chains
WHERE next_sequence != (SELECT next_sequence FROM canary_runner_chain_cursors c
 WHERE c.workspace_id=canary_runner_nonce_chains.workspace_id AND c.runner_id=canary_runner_nonce_chains.runner_id AND c.chain_name=canary_runner_nonce_chains.chain_name);

CREATE TABLE canary_runner_request_ledger(
  workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL,
  chain_name TEXT NOT NULL CHECK(chain_name='claim' OR chain_name GLOB 'heartbeat:?*' OR chain_name GLOB 'progress:?*' OR chain_name GLOB 'result:?*' OR chain_name GLOB 'stop-ack:?*'),
  sequence INTEGER NOT NULL CHECK(sequence>=1), generation INTEGER NOT NULL CHECK(generation>=0),
  request_digest TEXT NOT NULL CHECK(length(request_digest)=64 AND request_digest NOT GLOB '*[^0-9a-f]*'),
  response_json TEXT NOT NULL, next_nonce TEXT NOT NULL, created_at REAL NOT NULL,
  nonce_hash TEXT NOT NULL CHECK(length(nonce_hash)=64 AND nonce_hash NOT GLOB '*[^0-9a-f]*'), key_id TEXT NOT NULL,
  capability TEXT NOT NULL CHECK(capability IN ('runner_claim','runner_heartbeat','runner_progress','runner_result')),
  method TEXT NOT NULL CHECK(method='POST'), path TEXT NOT NULL, timestamp_ms INTEGER NOT NULL CHECK(timestamp_ms>=0),
  signed_request_digest TEXT NOT NULL CHECK(length(signed_request_digest)=64 AND signed_request_digest NOT GLOB '*[^0-9a-f]*'),
  body_digest TEXT NOT NULL CHECK(length(body_digest)=64 AND body_digest NOT GLOB '*[^0-9a-f]*'),
  response_ciphertext TEXT NOT NULL, next_nonce_ciphertext TEXT NOT NULL,
  PRIMARY KEY(workspace_id,runner_id,chain_name,sequence,generation),
  FOREIGN KEY(workspace_id,runner_id,chain_name) REFERENCES canary_runner_chain_cursors(workspace_id,runner_id,chain_name));
INSERT INTO canary_runner_request_ledger
SELECT l.workspace_id,l.runner_id,
 CASE WHEN l.chain_name='claim' THEN 'claim' WHEN l.path LIKE '%/progress' THEN 'progress:'||substr(l.chain_name,instr(l.chain_name,':')+1) WHEN l.path LIKE '%/result' THEN 'result:'||substr(l.chain_name,instr(l.chain_name,':')+1) WHEN l.path LIKE '%/heartbeat' THEN 'heartbeat:'||substr(l.chain_name,instr(l.chain_name,':')+1) WHEN l.path LIKE '%/stop-ack' THEN 'stop-ack:'||substr(l.chain_name,instr(l.chain_name,':')+1) END,
 l.sequence,c.generation,l.request_digest,l.response_json,l.next_nonce,l.created_at,l.nonce_hash,l.key_id,l.capability,l.method,l.path,l.timestamp_ms,l.signed_request_digest,l.body_digest,l.response_ciphertext,l.next_nonce_ciphertext
FROM canary_runner_request_ledger_v12 l JOIN canary_runner_chain_cursors c ON c.workspace_id=l.workspace_id AND c.runner_id=l.runner_id AND c.chain_name=(CASE WHEN l.chain_name='claim' THEN 'claim' WHEN l.path LIKE '%/progress' THEN 'progress:'||substr(l.chain_name,instr(l.chain_name,':')+1) WHEN l.path LIKE '%/result' THEN 'result:'||substr(l.chain_name,instr(l.chain_name,':')+1) WHEN l.path LIKE '%/heartbeat' THEN 'heartbeat:'||substr(l.chain_name,instr(l.chain_name,':')+1) WHEN l.path LIKE '%/stop-ack' THEN 'stop-ack:'||substr(l.chain_name,instr(l.chain_name,':')+1) END)
WHERE l.chain_name='claim' AND l.capability='runner_claim' AND l.path LIKE '%/claim' OR l.capability='runner_progress' AND l.path LIKE '%/progress' OR l.capability='runner_result' AND l.path LIKE '%/result' OR l.capability='runner_heartbeat' AND (l.path LIKE '%/heartbeat' OR l.path LIKE '%/stop-ack');

ALTER TABLE canary_runner_resync_challenges RENAME TO canary_runner_resync_challenges_v12;
CREATE TABLE canary_runner_resync_challenges(
 challenge_id TEXT PRIMARY KEY CHECK(length(challenge_id)=36 AND substr(challenge_id,1,4)='rrs_' AND substr(challenge_id,5) NOT GLOB '*[^0-9a-f]*'), workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL, chain_name TEXT NOT NULL,
 client_nonce_hash TEXT NOT NULL CHECK(length(client_nonce_hash)=64 AND client_nonce_hash NOT GLOB '*[^0-9a-f]*'), server_challenge_hash TEXT NOT NULL CHECK(length(server_challenge_hash)=64 AND server_challenge_hash NOT GLOB '*[^0-9a-f]*'), signed_digest TEXT NOT NULL CHECK(length(signed_digest)=64 AND signed_digest NOT GLOB '*[^0-9a-f]*'),
 client_nonce_ciphertext TEXT NOT NULL, server_challenge_ciphertext TEXT NOT NULL,
 challenge_generation INTEGER NOT NULL CHECK(challenge_generation>=0), result_generation INTEGER CHECK(result_generation>=1),
 status TEXT NOT NULL CHECK(status IN ('pending','completed','invalidated')), created_at REAL NOT NULL, expires_at REAL NOT NULL CHECK(expires_at>created_at),
 completed_response_ciphertext TEXT, complete_signed_digest TEXT CHECK(complete_signed_digest IS NULL OR (length(complete_signed_digest)=64 AND complete_signed_digest NOT GLOB '*[^0-9a-f]*')), completed_at REAL,
 CHECK((status='pending' AND result_generation IS NULL AND completed_response_ciphertext IS NULL AND complete_signed_digest IS NULL AND completed_at IS NULL) OR (status='completed' AND result_generation=challenge_generation+1 AND completed_response_ciphertext IS NOT NULL AND complete_signed_digest IS NOT NULL AND completed_at IS NOT NULL) OR status='invalidated'),
 FOREIGN KEY(workspace_id,runner_id,chain_name) REFERENCES canary_runner_chain_cursors(workspace_id,runner_id,chain_name));
INSERT INTO canary_runner_resync_challenges
SELECT r.challenge_id,r.workspace_id,r.runner_id,r.chain_name,r.client_nonce_hash,r.server_challenge_hash,r.signed_digest,r.client_nonce_ciphertext,r.server_challenge_ciphertext,c.generation,NULL,'invalidated',r.created_at,CASE WHEN r.expires_at>r.created_at THEN r.expires_at ELSE r.created_at+1 END,NULL,NULL,NULL
FROM canary_runner_resync_challenges_v12 r JOIN canary_runner_chain_cursors c ON c.workspace_id=r.workspace_id AND c.runner_id=r.runner_id AND c.chain_name=r.chain_name;

DROP TABLE canary_runner_nonce_chains_v12;
DROP TABLE canary_runner_resync_challenges_v12;
DROP TABLE canary_runner_chain_cursors_v12;
DROP TABLE canary_runner_request_ledger_v12;
DROP INDEX IF EXISTS idx_canary_runner_resync_expiry;
DROP INDEX IF EXISTS idx_canary_runner_resync_rate;
CREATE UNIQUE INDEX IF NOT EXISTS idx_runner_key_triple ON canary_runner_keys(workspace_id,runner_id,key_id);
CREATE INDEX idx_canary_runner_pairings_expiry ON canary_runner_pairings(expires_at);
CREATE INDEX idx_canary_runner_ledger_cleanup ON canary_runner_request_ledger(created_at);
CREATE INDEX idx_canary_runner_nonce_expiry ON canary_runner_nonce_chains(expires_at);
CREATE INDEX idx_canary_runner_resync_status_expiry ON canary_runner_resync_challenges(status,expires_at);
CREATE INDEX idx_canary_runner_resync_rate ON canary_runner_resync_challenges(workspace_id,runner_id,created_at);
CREATE UNIQUE INDEX idx_canary_runner_resync_pending ON canary_runner_resync_challenges(workspace_id,runner_id,chain_name) WHERE status='pending';
"""

# Migration fourteen removes the narrow class of v13 rows whose legacy evidence was both
# archived and accidentally promoted, then rebuilds the externally writable state tables with
# their final closed shapes.  Quarantine tables exist only inside the migration transaction.
RUNNER_AUTH_FINALIZATION_MIGRATION = """
CREATE TABLE canary_runner_quarantine_rows_v14(
 workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL, chain_name TEXT NOT NULL,
 sequence INTEGER NOT NULL, generation INTEGER NOT NULL, created_at REAL NOT NULL,
 PRIMARY KEY(workspace_id,runner_id,chain_name,sequence,generation));
INSERT INTO canary_runner_quarantine_rows_v14
SELECT l.workspace_id,l.runner_id,l.chain_name,l.sequence,l.generation,l.created_at
FROM canary_runner_request_ledger l
WHERE NOT (
 l.chain_name='claim' AND l.capability='runner_claim'
  AND l.path='/v1/workspaces/'||l.workspace_id||'/runners/'||l.runner_id||'/claim'
 OR substr(l.chain_name,1,10)='heartbeat:' AND l.capability='runner_heartbeat'
  AND l.path='/v1/workspaces/'||l.workspace_id||'/runners/'||l.runner_id||'/runs/'||substr(l.chain_name,11)||'/heartbeat'
 OR substr(l.chain_name,1,9)='progress:' AND l.capability='runner_progress'
  AND l.path='/v1/workspaces/'||l.workspace_id||'/runners/'||l.runner_id||'/runs/'||substr(l.chain_name,10)||'/progress'
 OR substr(l.chain_name,1,7)='result:' AND l.capability='runner_result'
  AND l.path='/v1/workspaces/'||l.workspace_id||'/runners/'||l.runner_id||'/runs/'||substr(l.chain_name,8)||'/result'
 OR substr(l.chain_name,1,9)='stop-ack:' AND l.capability='runner_heartbeat'
  AND l.path='/v1/workspaces/'||l.workspace_id||'/runners/'||l.runner_id||'/runs/'||substr(l.chain_name,10)||'/stop-ack'
)
OR EXISTS (
 SELECT 1 FROM canary_runner_request_ledger_archive a
 WHERE a.workspace_id=l.workspace_id AND a.runner_id=l.runner_id
  AND a.sequence=l.sequence AND a.path=l.path AND a.capability=l.capability
  AND (
   substr(l.chain_name,1,10)='heartbeat:' AND substr(a.legacy_chain_name,instr(a.legacy_chain_name,':')+1)=substr(l.chain_name,11)
    AND a.legacy_chain_name NOT IN ('heartbeat:'||substr(l.chain_name,11),'runner_heartbeat:'||substr(l.chain_name,11))
   OR substr(l.chain_name,1,9)='progress:' AND substr(a.legacy_chain_name,instr(a.legacy_chain_name,':')+1)=substr(l.chain_name,10)
    AND a.legacy_chain_name NOT IN ('progress:'||substr(l.chain_name,10),'runner_progress:'||substr(l.chain_name,10))
   OR substr(l.chain_name,1,7)='result:' AND substr(a.legacy_chain_name,instr(a.legacy_chain_name,':')+1)=substr(l.chain_name,8)
    AND a.legacy_chain_name NOT IN ('result:'||substr(l.chain_name,8),'runner_result:'||substr(l.chain_name,8))
   OR substr(l.chain_name,1,9)='stop-ack:' AND substr(a.legacy_chain_name,instr(a.legacy_chain_name,':')+1)=substr(l.chain_name,10)
    AND a.legacy_chain_name NOT IN ('stop-ack:'||substr(l.chain_name,10),'runner_heartbeat:'||substr(l.chain_name,10))
  )
);
INSERT INTO canary_runner_request_ledger_archive(
 workspace_id,runner_id,legacy_chain_name,sequence,request_digest,response_json,next_nonce,created_at,
 nonce_hash,key_id,capability,method,path,timestamp_ms,signed_request_digest,body_digest,
 response_ciphertext,next_nonce_ciphertext,archive_reason)
SELECT l.workspace_id,l.runner_id,l.chain_name,l.sequence,l.request_digest,l.response_json,l.next_nonce,l.created_at,
 l.nonce_hash,l.key_id,l.capability,l.method,l.path,l.timestamp_ms,l.signed_request_digest,l.body_digest,
 l.response_ciphertext,l.next_nonce_ciphertext,'path_chain_mismatch'
FROM canary_runner_request_ledger l
JOIN canary_runner_quarantine_rows_v14 q
 ON q.workspace_id=l.workspace_id AND q.runner_id=l.runner_id AND q.chain_name=l.chain_name
 AND q.sequence=l.sequence AND q.generation=l.generation
WHERE NOT (
 l.chain_name='claim' AND l.capability='runner_claim'
  AND l.path='/v1/workspaces/'||l.workspace_id||'/runners/'||l.runner_id||'/claim'
 OR substr(l.chain_name,1,10)='heartbeat:' AND l.capability='runner_heartbeat'
  AND l.path='/v1/workspaces/'||l.workspace_id||'/runners/'||l.runner_id||'/runs/'||substr(l.chain_name,11)||'/heartbeat'
 OR substr(l.chain_name,1,9)='progress:' AND l.capability='runner_progress'
  AND l.path='/v1/workspaces/'||l.workspace_id||'/runners/'||l.runner_id||'/runs/'||substr(l.chain_name,10)||'/progress'
 OR substr(l.chain_name,1,7)='result:' AND l.capability='runner_result'
  AND l.path='/v1/workspaces/'||l.workspace_id||'/runners/'||l.runner_id||'/runs/'||substr(l.chain_name,8)||'/result'
 OR substr(l.chain_name,1,9)='stop-ack:' AND l.capability='runner_heartbeat'
  AND l.path='/v1/workspaces/'||l.workspace_id||'/runners/'||l.runner_id||'/runs/'||substr(l.chain_name,10)||'/stop-ack'
);
DELETE FROM canary_runner_request_ledger
WHERE EXISTS (
 SELECT 1 FROM canary_runner_quarantine_rows_v14 q
 WHERE q.workspace_id=canary_runner_request_ledger.workspace_id
  AND q.runner_id=canary_runner_request_ledger.runner_id
  AND q.chain_name=canary_runner_request_ledger.chain_name
  AND q.sequence=canary_runner_request_ledger.sequence
  AND q.generation=canary_runner_request_ledger.generation);

ALTER TABLE canary_runner_pairings RENAME TO canary_runner_pairings_v13;
CREATE TABLE canary_runner_pairings(
  pairing_id TEXT PRIMARY KEY CHECK(length(pairing_id) BETWEEN 1 AND 128),
  workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL,
  invitation_hash TEXT NOT NULL UNIQUE CHECK(length(invitation_hash)=64 AND invitation_hash NOT GLOB '*[^0-9a-f]*'),
  phrase TEXT, public_key TEXT, fingerprint TEXT, key_id TEXT, runner_version TEXT,
  adapters_json TEXT, activation_challenge TEXT,
  status TEXT NOT NULL CHECK(status IN ('invited','pending','approved','activated','expired')),
  created_at REAL NOT NULL, expires_at REAL NOT NULL, approved_at REAL, activated_at REAL, approved_by TEXT,
  display_name TEXT CHECK(
   display_name IS NULL AND status='expired' OR
   display_name IS NOT NULL AND length(display_name) BETWEEN 1 AND 64
    AND length(CAST(display_name AS BLOB))<=128 AND instr(display_name,char(0))=0
    AND unicode(substr(display_name,1,1)) NOT IN (9,10,11,12,13,32)
    AND unicode(substr(display_name,length(display_name),1)) NOT IN (9,10,11,12,13,32)),
  UNIQUE(workspace_id, runner_id), FOREIGN KEY(workspace_id) REFERENCES workspaces(workspace_id));
INSERT INTO canary_runner_pairings
SELECT pairing_id,workspace_id,runner_id,invitation_hash,phrase,public_key,fingerprint,key_id,
 runner_version,adapters_json,activation_challenge,status,created_at,expires_at,approved_at,
 activated_at,approved_by,CASE WHEN display_name IS NULL AND status!='expired' THEN 'Pending runner' ELSE display_name END
FROM canary_runner_pairings_v13;
DROP TABLE canary_runner_pairings_v13;

ALTER TABLE canary_runner_resync_challenges RENAME TO canary_runner_resync_challenges_v13;
ALTER TABLE canary_runner_request_ledger RENAME TO canary_runner_request_ledger_v13;
ALTER TABLE canary_runner_chain_cursors RENAME TO canary_runner_chain_cursors_v13;
CREATE TABLE canary_runner_chain_cursors(
 workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL,
 chain_name TEXT NOT NULL CHECK(
  chain_name='claim' OR (
   substr(chain_name,1,instr(chain_name,':')) IN ('heartbeat:','progress:','result:','stop-ack:')
   AND length(CAST(substr(chain_name,instr(chain_name,':')+1) AS BLOB)) BETWEEN 1 AND 128
   AND substr(chain_name,instr(chain_name,':')+1) NOT GLOB '*[^A-Za-z0-9_-]*')),
 next_sequence INTEGER NOT NULL CHECK(next_sequence>=1),
 generation INTEGER NOT NULL CHECK(generation>=0), updated_at REAL NOT NULL,
 PRIMARY KEY(workspace_id,runner_id,chain_name),
 FOREIGN KEY(workspace_id,runner_id) REFERENCES canary_runners(workspace_id,runner_id));
INSERT INTO canary_runner_chain_cursors
SELECT c.* FROM canary_runner_chain_cursors_v13 c
WHERE NOT (
 EXISTS (SELECT 1 FROM canary_runner_quarantine_rows_v14 q
  WHERE q.workspace_id=c.workspace_id AND q.runner_id=c.runner_id AND q.chain_name=c.chain_name)
 AND NOT EXISTS (SELECT 1 FROM canary_runner_request_ledger_v13 l
  WHERE l.workspace_id=c.workspace_id AND l.runner_id=c.runner_id AND l.chain_name=c.chain_name)
 AND NOT EXISTS (SELECT 1 FROM canary_runner_nonce_chains n
  WHERE n.workspace_id=c.workspace_id AND n.runner_id=c.runner_id AND n.chain_name=c.chain_name)
 AND NOT EXISTS (SELECT 1 FROM canary_runner_resync_challenges_v13 r
  WHERE r.workspace_id=c.workspace_id AND r.runner_id=c.runner_id AND r.chain_name=c.chain_name
   AND r.status IN ('pending','completed'))
 AND c.next_sequence=(SELECT max(q.sequence)+1 FROM canary_runner_quarantine_rows_v14 q
  WHERE q.workspace_id=c.workspace_id AND q.runner_id=c.runner_id AND q.chain_name=c.chain_name)
 AND c.updated_at=(SELECT max(q.created_at) FROM canary_runner_quarantine_rows_v14 q
  WHERE q.workspace_id=c.workspace_id AND q.runner_id=c.runner_id AND q.chain_name=c.chain_name)
);

CREATE TABLE canary_runner_request_ledger(
  workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL,
  chain_name TEXT NOT NULL CHECK(
   chain_name='claim' OR (
    substr(chain_name,1,instr(chain_name,':')) IN ('heartbeat:','progress:','result:','stop-ack:')
    AND length(CAST(substr(chain_name,instr(chain_name,':')+1) AS BLOB)) BETWEEN 1 AND 128
    AND substr(chain_name,instr(chain_name,':')+1) NOT GLOB '*[^A-Za-z0-9_-]*')),
  sequence INTEGER NOT NULL CHECK(sequence>=1), generation INTEGER NOT NULL CHECK(generation>=0),
  request_digest TEXT NOT NULL CHECK(length(request_digest)=64 AND request_digest NOT GLOB '*[^0-9a-f]*'),
  response_json TEXT NOT NULL, next_nonce TEXT NOT NULL, created_at REAL NOT NULL,
  nonce_hash TEXT NOT NULL CHECK(length(nonce_hash)=64 AND nonce_hash NOT GLOB '*[^0-9a-f]*'), key_id TEXT NOT NULL,
  capability TEXT NOT NULL CHECK(capability IN ('runner_claim','runner_heartbeat','runner_progress','runner_result')),
  method TEXT NOT NULL CHECK(method='POST'), path TEXT NOT NULL, timestamp_ms INTEGER NOT NULL CHECK(timestamp_ms>=0),
  signed_request_digest TEXT NOT NULL CHECK(length(signed_request_digest)=64 AND signed_request_digest NOT GLOB '*[^0-9a-f]*'),
  body_digest TEXT NOT NULL CHECK(length(body_digest)=64 AND body_digest NOT GLOB '*[^0-9a-f]*'),
  response_ciphertext TEXT NOT NULL, next_nonce_ciphertext TEXT NOT NULL,
  PRIMARY KEY(workspace_id,runner_id,chain_name,sequence,generation),
  FOREIGN KEY(workspace_id,runner_id,chain_name)
   REFERENCES canary_runner_chain_cursors(workspace_id,runner_id,chain_name));
INSERT INTO canary_runner_request_ledger
SELECT l.* FROM canary_runner_request_ledger_v13 l
JOIN canary_runner_chain_cursors c
 ON c.workspace_id=l.workspace_id AND c.runner_id=l.runner_id AND c.chain_name=l.chain_name;

CREATE TABLE canary_runner_resync_challenges(
 challenge_id TEXT PRIMARY KEY CHECK(
  length(challenge_id)=36 AND substr(challenge_id,1,4)='rrs_'
  AND substr(challenge_id,5) NOT GLOB '*[^0-9a-f]*'),
 workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL,
 chain_name TEXT NOT NULL CHECK(
  chain_name='claim' OR (
   substr(chain_name,1,instr(chain_name,':')) IN ('heartbeat:','progress:','result:','stop-ack:')
   AND length(CAST(substr(chain_name,instr(chain_name,':')+1) AS BLOB)) BETWEEN 1 AND 128
   AND substr(chain_name,instr(chain_name,':')+1) NOT GLOB '*[^A-Za-z0-9_-]*')),
 client_nonce_hash TEXT NOT NULL CHECK(length(client_nonce_hash)=64 AND client_nonce_hash NOT GLOB '*[^0-9a-f]*'),
 server_challenge_hash TEXT NOT NULL CHECK(length(server_challenge_hash)=64 AND server_challenge_hash NOT GLOB '*[^0-9a-f]*'),
 signed_digest TEXT NOT NULL CHECK(length(signed_digest)=64 AND signed_digest NOT GLOB '*[^0-9a-f]*'),
 client_nonce_ciphertext TEXT NOT NULL CHECK(length(CAST(client_nonce_ciphertext AS BLOB)) BETWEEN 1 AND 4096),
 server_challenge_ciphertext TEXT NOT NULL CHECK(length(CAST(server_challenge_ciphertext AS BLOB)) BETWEEN 1 AND 4096),
 challenge_generation INTEGER NOT NULL CHECK(challenge_generation>=0),
 result_generation INTEGER CHECK(result_generation>=1),
 status TEXT NOT NULL CHECK(status IN ('pending','completed','invalidated')),
 created_at REAL NOT NULL,
 expires_at REAL NOT NULL CHECK(created_at<expires_at AND expires_at<=created_at+60),
 completed_response_ciphertext TEXT CHECK(
  completed_response_ciphertext IS NULL OR length(CAST(completed_response_ciphertext AS BLOB)) BETWEEN 1 AND 4096),
 complete_signed_digest TEXT CHECK(
  complete_signed_digest IS NULL OR (
   length(complete_signed_digest)=64 AND complete_signed_digest NOT GLOB '*[^0-9a-f]*')),
 completed_at REAL,
 CHECK(
  status IN ('pending','invalidated') AND result_generation IS NULL
   AND completed_response_ciphertext IS NULL AND complete_signed_digest IS NULL AND completed_at IS NULL
  OR status='completed' AND result_generation=challenge_generation+1
   AND completed_response_ciphertext IS NOT NULL AND complete_signed_digest IS NOT NULL AND completed_at IS NOT NULL),
 FOREIGN KEY(workspace_id,runner_id,chain_name)
  REFERENCES canary_runner_chain_cursors(workspace_id,runner_id,chain_name));
INSERT INTO canary_runner_resync_challenges
SELECT r.challenge_id,r.workspace_id,r.runner_id,r.chain_name,r.client_nonce_hash,
 r.server_challenge_hash,r.signed_digest,r.client_nonce_ciphertext,r.server_challenge_ciphertext,
 r.challenge_generation,CASE WHEN r.status='completed' THEN r.result_generation END,r.status,
 r.created_at,CASE WHEN r.expires_at<=r.created_at THEN r.created_at+1
  WHEN r.expires_at>r.created_at+60 THEN r.created_at+60 ELSE r.expires_at END,
 CASE WHEN r.status='completed' THEN r.completed_response_ciphertext END,
 CASE WHEN r.status='completed' THEN r.complete_signed_digest END,
 CASE WHEN r.status='completed' THEN r.completed_at END
FROM canary_runner_resync_challenges_v13 r
JOIN canary_runner_chain_cursors c
 ON c.workspace_id=r.workspace_id AND c.runner_id=r.runner_id AND c.chain_name=r.chain_name;

DROP TABLE canary_runner_resync_challenges_v13;
DROP TABLE canary_runner_request_ledger_v13;
DROP TABLE canary_runner_chain_cursors_v13;
DROP TABLE canary_runner_quarantine_rows_v14;
CREATE UNIQUE INDEX IF NOT EXISTS idx_runner_key_triple
 ON canary_runner_keys(workspace_id,runner_id,key_id);
CREATE INDEX idx_canary_runner_pairings_expiry ON canary_runner_pairings(expires_at);
CREATE INDEX idx_canary_runner_ledger_cleanup ON canary_runner_request_ledger(created_at);
CREATE INDEX idx_canary_runner_resync_status_expiry ON canary_runner_resync_challenges(status,expires_at);
CREATE INDEX idx_canary_runner_resync_rate ON canary_runner_resync_challenges(workspace_id,runner_id,created_at);
CREATE UNIQUE INDEX idx_canary_runner_resync_pending
 ON canary_runner_resync_challenges(workspace_id,runner_id,chain_name) WHERE status='pending';
"""

# A new in-process ControlPlane has no runner-auth rows to preserve.  Build its tables directly
# at the v11 shape instead of creating v9 then replaying a destructive rename/copy migration.
# Existing durable databases are upgraded exclusively by the append-only migration list above.
RUNNER_AUTH_RUNTIME_SCHEMA = """
CREATE TABLE IF NOT EXISTS canary_runner_pairings(
  pairing_id TEXT PRIMARY KEY CHECK(length(pairing_id) BETWEEN 1 AND 128),
  workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL,
  invitation_hash TEXT NOT NULL UNIQUE CHECK(length(invitation_hash)=64 AND invitation_hash NOT GLOB '*[^0-9a-f]*'),
  phrase TEXT, public_key TEXT, fingerprint TEXT, key_id TEXT, runner_version TEXT,
  adapters_json TEXT, activation_challenge TEXT,
  status TEXT NOT NULL CHECK(status IN ('invited','pending','approved','activated','expired')),
  created_at REAL NOT NULL, expires_at REAL NOT NULL, approved_at REAL, activated_at REAL, approved_by TEXT, display_name TEXT,
  UNIQUE(workspace_id, runner_id), FOREIGN KEY(workspace_id) REFERENCES workspaces(workspace_id));
CREATE TABLE IF NOT EXISTS canary_runner_nonce_chains(
  workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL, chain_name TEXT NOT NULL,
  nonce_hash TEXT NOT NULL CHECK(length(nonce_hash)=64 AND nonce_hash NOT GLOB '*[^0-9a-f]*'),
  next_sequence INTEGER NOT NULL CHECK(next_sequence >= 1), expires_at REAL NOT NULL,
  PRIMARY KEY(workspace_id,runner_id,chain_name),
  FOREIGN KEY(workspace_id,runner_id) REFERENCES canary_runners(workspace_id,runner_id));
CREATE TABLE IF NOT EXISTS canary_runner_request_ledger(
  workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL, chain_name TEXT NOT NULL,
  sequence INTEGER NOT NULL CHECK(sequence >= 1), request_digest TEXT NOT NULL,
  response_json TEXT NOT NULL, next_nonce TEXT NOT NULL, created_at REAL NOT NULL,
  nonce_hash TEXT, key_id TEXT, capability TEXT CHECK(capability IN ('runner_claim','runner_heartbeat','runner_progress','runner_result')),
  method TEXT CHECK(method='POST'), path TEXT, timestamp_ms INTEGER CHECK(timestamp_ms >= 0),
  signed_request_digest TEXT, body_digest TEXT, response_ciphertext TEXT, next_nonce_ciphertext TEXT,
  PRIMARY KEY(workspace_id,runner_id,chain_name,sequence),
  FOREIGN KEY(workspace_id,runner_id) REFERENCES canary_runners(workspace_id,runner_id));
CREATE TABLE IF NOT EXISTS canary_runner_rotations(
  pairing_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL,
  phrase TEXT NOT NULL, public_key TEXT NOT NULL, fingerprint TEXT NOT NULL CHECK(length(fingerprint)=64 AND fingerprint NOT GLOB '*[^0-9a-f]*'),
  key_id TEXT NOT NULL, runner_version TEXT NOT NULL, adapters_json TEXT NOT NULL, activation_challenge TEXT,
  status TEXT NOT NULL CHECK(status IN ('rotation_pending','rotation_approved','rotated','expired')),
  created_at REAL NOT NULL, expires_at REAL NOT NULL, approved_at REAL, activated_at REAL, approved_by TEXT,
  FOREIGN KEY(workspace_id,runner_id) REFERENCES canary_runners(workspace_id,runner_id));
CREATE TABLE IF NOT EXISTS canary_runner_identity_records(
  workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL, identity_json TEXT NOT NULL,
  identity_digest TEXT NOT NULL CHECK(length(identity_digest)=64 AND identity_digest NOT GLOB '*[^0-9a-f]*'),
  updated_at REAL NOT NULL, PRIMARY KEY(workspace_id,runner_id), UNIQUE(identity_digest),
  FOREIGN KEY(workspace_id,runner_id) REFERENCES canary_runners(workspace_id,runner_id));
CREATE TABLE IF NOT EXISTS canary_runner_audit_records(
  audit_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL,
  action TEXT NOT NULL CHECK(action IN ('runner_revoked','runner_rotated','runner_activated')),
  actor TEXT NOT NULL, reason_code TEXT, created_at REAL NOT NULL,
  FOREIGN KEY(workspace_id,runner_id) REFERENCES canary_runners(workspace_id,runner_id));
CREATE TABLE IF NOT EXISTS canary_runner_chain_cursors(
 workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL, chain_name TEXT NOT NULL,
 next_sequence INTEGER NOT NULL CHECK(next_sequence>=1), generation INTEGER NOT NULL CHECK(generation>=0), updated_at REAL NOT NULL,
 PRIMARY KEY(workspace_id,runner_id,chain_name), FOREIGN KEY(workspace_id,runner_id) REFERENCES canary_runners(workspace_id,runner_id));
CREATE TABLE IF NOT EXISTS canary_runner_resync_challenges(
 challenge_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL, chain_name TEXT NOT NULL,
 client_nonce_hash TEXT NOT NULL, server_challenge_hash TEXT NOT NULL, signed_digest TEXT NOT NULL,
 client_nonce_ciphertext TEXT NOT NULL, server_challenge_ciphertext TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('pending','completed','invalidated')), created_at REAL NOT NULL, expires_at REAL NOT NULL,
 completed_response_ciphertext TEXT, complete_signed_digest TEXT, completed_at REAL,
 FOREIGN KEY(workspace_id,runner_id,chain_name) REFERENCES canary_runner_chain_cursors(workspace_id,runner_id,chain_name));
CREATE UNIQUE INDEX IF NOT EXISTS idx_runner_key_triple ON canary_runner_keys(workspace_id,runner_id,key_id);
CREATE INDEX IF NOT EXISTS idx_canary_runner_pairings_expiry ON canary_runner_pairings(expires_at);
CREATE INDEX IF NOT EXISTS idx_canary_runner_ledger_cleanup ON canary_runner_request_ledger(created_at);
CREATE INDEX IF NOT EXISTS idx_canary_runner_nonce_expiry ON canary_runner_nonce_chains(expires_at);
CREATE INDEX IF NOT EXISTS idx_canary_runner_resync_expiry ON canary_runner_resync_challenges(expires_at);
CREATE INDEX IF NOT EXISTS idx_canary_runner_resync_rate ON canary_runner_resync_challenges(workspace_id,runner_id,created_at);
"""


# Fresh local control planes replay the same final rebuild used by durable databases.  This keeps
# runtime table SQL, foreign keys, and index metadata byte-for-byte aligned with migrations.
RUNNER_AUTH_RUNTIME_SCHEMA += RUNNER_AUTH_GENERATION_MIGRATION
RUNNER_AUTH_RUNTIME_SCHEMA += RUNNER_AUTH_FINALIZATION_MIGRATION

# Pairing v3 is the executable control protocol.  The three protocol rows bind the
# activation exchange to the control cursor; sealed receipts make an accepted activation
# replayable without allocating a second nonce or runner identity.
RUNNER_AUTH_PROTOCOL_V3_MIGRATION = """
CREATE TABLE canary_runner_pairing_protocols(
 pairing_id TEXT PRIMARY KEY,
 protocol_version INTEGER NOT NULL CHECK(protocol_version=3),
 control_protocol TEXT NOT NULL CHECK(control_protocol='heel.runner-control.v2'),
 exchange_digest TEXT NOT NULL CHECK(length(exchange_digest)=64 AND exchange_digest NOT GLOB '*[^0-9a-f]*'),
 created_at REAL NOT NULL,
 FOREIGN KEY(pairing_id) REFERENCES canary_runner_pairings(pairing_id) ON DELETE CASCADE);
CREATE TABLE canary_runner_execution_protocols(
 workspace_id TEXT NOT NULL,
 runner_id TEXT NOT NULL,
 protocol_version INTEGER NOT NULL CHECK(protocol_version=3),
 control_protocol TEXT NOT NULL CHECK(control_protocol='heel.runner-control.v2'),
 exchange_digest TEXT NOT NULL CHECK(length(exchange_digest)=64 AND exchange_digest NOT GLOB '*[^0-9a-f]*'),
 activated_at REAL NOT NULL,
 PRIMARY KEY(workspace_id,runner_id),
 FOREIGN KEY(workspace_id,runner_id) REFERENCES canary_runners(workspace_id,runner_id));
CREATE TABLE canary_runner_pairing_activation_receipts(
 pairing_id TEXT PRIMARY KEY,
 request_digest TEXT NOT NULL CHECK(length(request_digest)=64 AND request_digest NOT GLOB '*[^0-9a-f]*'),
 response_ciphertext TEXT NOT NULL,
 created_at REAL NOT NULL,
 expires_at REAL NOT NULL,
 FOREIGN KEY(pairing_id) REFERENCES canary_runner_pairings(pairing_id) ON DELETE CASCADE);
CREATE TABLE canary_runner_rotation_activation_receipts(
 pairing_id TEXT PRIMARY KEY,
 request_digest TEXT NOT NULL CHECK(length(request_digest)=64 AND request_digest NOT GLOB '*[^0-9a-f]*'),
 response_ciphertext TEXT NOT NULL,
 created_at REAL NOT NULL,
 expires_at REAL NOT NULL,
 FOREIGN KEY(pairing_id) REFERENCES canary_runner_rotations(pairing_id) ON DELETE CASCADE);
"""
RUNNER_AUTH_RUNTIME_SCHEMA += RUNNER_AUTH_PROTOCOL_V3_MIGRATION


# Migration twenty-five upgrades the one-row-per-chain replay ledger from a short-lived
# implementation detail to the durable, exact HTTP receipt required for loss recovery.
RUNNER_AUTH_RECEIPT_RETENTION_MIGRATION = """
DROP INDEX IF EXISTS idx_canary_runner_ledger_cleanup;
ALTER TABLE canary_runner_request_ledger RENAME TO canary_runner_request_ledger_v24;
CREATE TABLE canary_runner_request_ledger(
 workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL,
 chain_name TEXT NOT NULL CHECK(
  chain_name='claim' OR (
   substr(chain_name,1,instr(chain_name,':')) IN ('heartbeat:','progress:','result:','stop-ack:')
   AND length(CAST(substr(chain_name,instr(chain_name,':')+1) AS BLOB)) BETWEEN 1 AND 128
   AND substr(chain_name,instr(chain_name,':')+1) NOT GLOB '*[^A-Za-z0-9_-]*')),
 sequence INTEGER NOT NULL CHECK(sequence>=1),
 generation INTEGER NOT NULL CHECK(generation>=0),
 request_digest TEXT NOT NULL CHECK(length(request_digest)=64 AND request_digest NOT GLOB '*[^0-9a-f]*'),
 response_json TEXT NOT NULL, next_nonce TEXT NOT NULL, created_at REAL NOT NULL,
 nonce_hash TEXT NOT NULL CHECK(length(nonce_hash)=64 AND nonce_hash NOT GLOB '*[^0-9a-f]*'),
 key_id TEXT NOT NULL,
 capability TEXT NOT NULL CHECK(capability IN ('runner_claim','runner_heartbeat','runner_progress','runner_result')),
 method TEXT NOT NULL CHECK(method='POST'), path TEXT NOT NULL,
 timestamp_ms INTEGER NOT NULL CHECK(timestamp_ms>=0),
 signed_request_digest TEXT NOT NULL CHECK(length(signed_request_digest)=64 AND signed_request_digest NOT GLOB '*[^0-9a-f]*'),
 body_digest TEXT NOT NULL CHECK(length(body_digest)=64 AND body_digest NOT GLOB '*[^0-9a-f]*'),
 response_ciphertext TEXT NOT NULL, next_nonce_ciphertext TEXT NOT NULL,
 response_status INTEGER NOT NULL CHECK(response_status IN (0,200,201,204)),
 response_body_digest TEXT CHECK(response_body_digest IS NULL OR (length(response_body_digest)=64 AND response_body_digest NOT GLOB '*[^0-9a-f]*')),
 retention_expires_at REAL NOT NULL CHECK(retention_expires_at>=created_at AND retention_expires_at<=created_at+2592000.0),
 PRIMARY KEY(workspace_id,runner_id,chain_name,sequence,generation),
 UNIQUE(workspace_id,runner_id,chain_name),
 CHECK(response_status=0 AND response_body_digest IS NULL OR response_status IN (200,201,204) AND response_body_digest IS NOT NULL),
 FOREIGN KEY(workspace_id,runner_id,chain_name)
  REFERENCES canary_runner_chain_cursors(workspace_id,runner_id,chain_name));
INSERT INTO canary_runner_request_ledger(
 workspace_id,runner_id,chain_name,sequence,generation,request_digest,response_json,next_nonce,created_at,
 nonce_hash,key_id,capability,method,path,timestamp_ms,signed_request_digest,body_digest,
 response_ciphertext,next_nonce_ciphertext,response_status,response_body_digest,retention_expires_at)
SELECT l.workspace_id,l.runner_id,l.chain_name,l.sequence,l.generation,l.request_digest,l.response_json,l.next_nonce,l.created_at,
 l.nonce_hash,l.key_id,l.capability,l.method,l.path,l.timestamp_ms,l.signed_request_digest,l.body_digest,
 l.response_ciphertext,l.next_nonce_ciphertext,0,NULL,l.created_at+3600.0
FROM canary_runner_request_ledger_v24 l
WHERE NOT EXISTS (
 SELECT 1 FROM canary_runner_request_ledger_v24 n
 WHERE n.workspace_id=l.workspace_id AND n.runner_id=l.runner_id AND n.chain_name=l.chain_name
  AND (n.generation>l.generation OR n.generation=l.generation AND n.sequence>l.sequence));
DROP TABLE canary_runner_request_ledger_v24;
CREATE INDEX idx_canary_runner_ledger_retention
 ON canary_runner_request_ledger(retention_expires_at,workspace_id,runner_id,chain_name,sequence,generation);

UPDATE canary_runner_pairings
 SET expires_at=activated_at+2592000.0
 WHERE status='activated' AND activated_at IS NOT NULL AND expires_at<activated_at+2592000.0;
UPDATE canary_runner_pairing_activation_receipts
 SET expires_at=(SELECT p.expires_at FROM canary_runner_pairings p
                 WHERE p.pairing_id=canary_runner_pairing_activation_receipts.pairing_id)
 WHERE EXISTS (SELECT 1 FROM canary_runner_pairings p
               WHERE p.pairing_id=canary_runner_pairing_activation_receipts.pairing_id
                AND p.status='activated' AND p.activated_at IS NOT NULL);
UPDATE canary_runner_rotations
 SET expires_at=activated_at+2592000.0
 WHERE status='rotated' AND activated_at IS NOT NULL AND expires_at<activated_at+2592000.0;
UPDATE canary_runner_rotation_activation_receipts
 SET expires_at=(SELECT r.expires_at FROM canary_runner_rotations r
                 WHERE r.pairing_id=canary_runner_rotation_activation_receipts.pairing_id)
 WHERE EXISTS (SELECT 1 FROM canary_runner_rotations r
               WHERE r.pairing_id=canary_runner_rotation_activation_receipts.pairing_id
                AND r.status='rotated' AND r.activated_at IS NOT NULL);
CREATE INDEX idx_canary_runner_pairing_status_expiry
 ON canary_runner_pairings(workspace_id,status,expires_at,pairing_id);
CREATE INDEX idx_canary_runner_rotation_status_expiry
 ON canary_runner_rotations(workspace_id,status,expires_at,pairing_id);
CREATE INDEX idx_canary_runner_pairing_receipt_expiry
 ON canary_runner_pairing_activation_receipts(expires_at,pairing_id);
CREATE INDEX idx_canary_runner_rotation_receipt_expiry
 ON canary_runner_rotation_activation_receipts(expires_at,pairing_id);
"""
RUNNER_AUTH_RUNTIME_SCHEMA += RUNNER_AUTH_RECEIPT_RETENTION_MIGRATION


RUNNER_AUTH_ACTIVATION_ABORT_MIGRATION = """
CREATE TABLE canary_runner_pairing_activation_abort_receipts(
 pairing_id TEXT PRIMARY KEY,
 request_digest TEXT NOT NULL CHECK(length(request_digest)=64 AND request_digest NOT GLOB '*[^0-9a-f]*'),
 response_digest TEXT NOT NULL CHECK(length(response_digest)=64 AND response_digest NOT GLOB '*[^0-9a-f]*'),
 response_ciphertext TEXT NOT NULL,
 created_at REAL NOT NULL,
 expires_at REAL NOT NULL CHECK(expires_at>created_at AND expires_at<=created_at+2592000.0),
 FOREIGN KEY(pairing_id) REFERENCES canary_runner_pairings(pairing_id) ON DELETE CASCADE);
CREATE TABLE canary_runner_rotation_activation_abort_receipts(
 pairing_id TEXT PRIMARY KEY,
 request_digest TEXT NOT NULL CHECK(length(request_digest)=64 AND request_digest NOT GLOB '*[^0-9a-f]*'),
 response_digest TEXT NOT NULL CHECK(length(response_digest)=64 AND response_digest NOT GLOB '*[^0-9a-f]*'),
 response_ciphertext TEXT NOT NULL,
 created_at REAL NOT NULL,
 expires_at REAL NOT NULL CHECK(expires_at>created_at AND expires_at<=created_at+2592000.0),
 FOREIGN KEY(pairing_id) REFERENCES canary_runner_rotations(pairing_id) ON DELETE CASCADE);
CREATE INDEX idx_canary_runner_pairing_abort_receipt_expiry
 ON canary_runner_pairing_activation_abort_receipts(expires_at,pairing_id);
CREATE INDEX idx_canary_runner_rotation_abort_receipt_expiry
 ON canary_runner_rotation_activation_abort_receipts(expires_at,pairing_id);
"""
RUNNER_AUTH_RUNTIME_SCHEMA += RUNNER_AUTH_ACTIVATION_ABORT_MIGRATION


# Migration twenty-seven makes the old runner authority an immutable property
# of a rotation ceremony.  A local journal is bound to that exact old key, so
# an existing overlapping ceremony must make the migration fail rather than
# being silently selected or expired.
RUNNER_AUTH_SINGLE_OPEN_ROTATION_MIGRATION = """
ALTER TABLE canary_runner_rotations ADD COLUMN old_key_id TEXT;
ALTER TABLE canary_runner_rotations ADD COLUMN old_fingerprint TEXT;

UPDATE canary_runner_rotations
SET old_key_id=(
      SELECT json_extract(i.identity_json,'$.public_key.key_id')
      FROM canary_runner_identity_records i
      WHERE i.workspace_id=canary_runner_rotations.workspace_id
        AND i.runner_id=canary_runner_rotations.runner_id),
    old_fingerprint=(
      SELECT json_extract(i.identity_json,'$.fingerprint')
      FROM canary_runner_identity_records i
      WHERE i.workspace_id=canary_runner_rotations.workspace_id
        AND i.runner_id=canary_runner_rotations.runner_id)
WHERE status IN ('rotation_pending','rotation_approved');

CREATE TABLE canary_runner_rotation_m27_guard(
 invalid INTEGER NOT NULL CHECK(invalid=0)
);
INSERT INTO canary_runner_rotation_m27_guard(invalid)
SELECT 1
WHERE EXISTS(
 SELECT 1
 FROM canary_runner_rotations r
 WHERE r.status IN ('rotation_pending','rotation_approved')
   AND (
    r.old_key_id IS NULL
    OR length(CAST(r.old_key_id AS BLOB)) NOT BETWEEN 1 AND 128
    OR trim(r.old_key_id)<>r.old_key_id
    OR r.old_fingerprint IS NULL
    OR length(r.old_fingerprint)<>64
    OR r.old_fingerprint GLOB '*[^0-9a-f]*'
    OR NOT EXISTS(
      SELECT 1 FROM canary_runner_keys k
      WHERE k.workspace_id=r.workspace_id AND k.runner_id=r.runner_id
        AND k.key_id=r.old_key_id AND k.status='active' AND k.revoked_at IS NULL)
   )
 )
 OR EXISTS(
  SELECT 1 FROM canary_runner_rotations r
  WHERE r.status IN ('rotation_pending','rotation_approved')
  GROUP BY r.workspace_id,r.runner_id HAVING count(*)<>1
 );
DROP TABLE canary_runner_rotation_m27_guard;

CREATE UNIQUE INDEX idx_canary_runner_one_open_rotation
 ON canary_runner_rotations(workspace_id,runner_id)
 WHERE status IN ('rotation_pending','rotation_approved');
CREATE INDEX idx_canary_runner_rotation_old_key_history
 ON canary_runner_rotations(workspace_id,runner_id,old_key_id,status,created_at,pairing_id);
CREATE INDEX idx_canary_runner_old_key_overlap_expiry
 ON canary_runner_keys(revoked_at,workspace_id,runner_id,key_id)
 WHERE status='verification_only' AND revoked_at IS NOT NULL;

CREATE TRIGGER trg_canary_runner_rotation_old_key_insert_guard
BEFORE INSERT ON canary_runner_rotations
WHEN NEW.status IN ('rotation_pending','rotation_approved') AND (
 NEW.old_key_id IS NULL
 OR length(CAST(NEW.old_key_id AS BLOB)) NOT BETWEEN 1 AND 128
 OR trim(NEW.old_key_id)<>NEW.old_key_id
 OR NEW.old_fingerprint IS NULL
 OR length(NEW.old_fingerprint)<>64
 OR NEW.old_fingerprint GLOB '*[^0-9a-f]*')
BEGIN
 SELECT RAISE(ABORT,'invalid runner rotation old key');
END;

CREATE TRIGGER trg_canary_runner_rotation_old_key_update_guard
BEFORE UPDATE OF status,workspace_id,runner_id,old_key_id,old_fingerprint
ON canary_runner_rotations
WHEN NEW.status IN ('rotation_pending','rotation_approved') AND (
 NEW.old_key_id IS NULL
 OR length(CAST(NEW.old_key_id AS BLOB)) NOT BETWEEN 1 AND 128
 OR trim(NEW.old_key_id)<>NEW.old_key_id
 OR NEW.old_fingerprint IS NULL
 OR length(NEW.old_fingerprint)<>64
 OR NEW.old_fingerprint GLOB '*[^0-9a-f]*')
BEGIN
 SELECT RAISE(ABORT,'invalid runner rotation old key');
END;
"""
RUNNER_AUTH_RUNTIME_SCHEMA += RUNNER_AUTH_SINGLE_OPEN_ROTATION_MIGRATION


# Keep the schema-28 old-key retire lane separate from the immutable m27
# literal: the reaper is never permitted to fall back to an unindexed scan.
RUNNER_AUTH_KEY_HISTORY_EXPIRY_MIGRATION = """
CREATE INDEX idx_canary_runner_key_history_expiry
 ON canary_runner_keys(revoked_at,workspace_id,runner_id,key_id)
 WHERE status='verification_only' AND revoked_at IS NOT NULL;
"""
RUNNER_AUTH_RUNTIME_SCHEMA += RUNNER_AUTH_KEY_HISTORY_EXPIRY_MIGRATION


class RunnerAuthError(PermissionError):
    """Uniform external runner-auth failure."""


class RunnerAuthRateLimited(RunnerAuthError):
    """A verified runner exhausted its small recovery-start budget."""


class RunnerProtocolUpgradeRequired(RunnerAuthError):
    """A legacy inventory pairing cannot consume executable runner authority."""


class RunnerActivationAbortConflict(RunnerAuthError):
    """A verified abort request reached a closed, non-mutating state."""

    def __init__(self, code: str, *, retry_after_ms: int | None = None):
        super().__init__(code)
        self.code = code
        self.retry_after_ms = retry_after_ms


class RunnerActivationAbortDeferred(RunnerAuthError):
    """A v2 abort proved possession but the Cloud challenge is still live."""

    def __init__(self, response: Mapping[str, object]):
        super().__init__("runner_activation_challenge_live")
        self.response = dict(response)


class RunnerActivationReceiptExpired(RunnerAuthError):
    """An otherwise authentic activation/abort receipt outlived replay authority."""


class RunnerRotationBusy(RunnerAuthError):
    """Activation observed live old-key authority after rotation approval."""


class RunnerRotationInProgress(RunnerAuthError):
    """A runner already has one immutable open rotation ceremony."""


@dataclass(frozen=True)
class RunnerHttpAction:
    """The one closed HTTP result a verified runner action may persist."""

    status: Literal[200, 201, 204]
    body: dict | None


@dataclass(frozen=True)
class RunnerAuthReapResult:
    """Exact bounded work completed by one auth-retention transaction."""

    request_receipts: int
    pairing_receipts: int
    rotation_receipts: int
    abort_receipts: int
    pairing_parents: int
    rotation_parents: int
    old_keys: int
    has_more: bool


@dataclass(frozen=True)
class PairingInvitation:
    token: str
    expires_at: float


@dataclass(frozen=True)
class PairingView:
    pairing_id: str
    runner_id: str
    phrase: str
    fingerprint: str
    status: str
    expires_at: float
    activation_challenge: str | None = None
    control_protocol: str | None = None
    pairing_exchange_digest: str | None = None


def _now() -> float:
    return time.time()


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _token() -> str:
    return _b64(secrets.token_bytes(32))


def _lower_hex_digest(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and value == value.lower()
        and all(character in "0123456789abcdef" for character in value)
    )


WORDS = runner_phrase_words()


def _valid_persisted_display_name(value: object) -> bool:
    return bool(
        type(value) is str
        and value
        and value == unicodedata.normalize("NFC", value)
        and value == value.strip()
        and len(value) <= 64
        and len(value.encode("utf-8")) <= 128
        and not any(unicodedata.category(char).startswith("C") for char in value)
    )


def _ensure_hardened_ledger_schema(conn: sqlite3.Connection) -> None:
    present = {row[1] for row in conn.execute("PRAGMA table_info(canary_runner_request_ledger)")}
    for statement in RUNNER_AUTH_HARDENING_MIGRATION.strip().split(";"):
        statement = statement.strip()
        if not statement:
            continue
        column = statement.split()[5]
        if column not in present:
            conn.execute(statement)
            present.add(column)


def _ensure_lifecycle_tables(conn: sqlite3.Connection) -> None:
    """Install v11's additive identity/audit tables for direct runtime construction.

    The migration owns the constrained table rebuild; direct in-memory ControlPlane instances
    start from an empty v9 schema and require the same observable table/column shape without
    replaying a destructive migration.
    """
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS canary_runner_identity_records(
      workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL, identity_json TEXT NOT NULL,
      identity_digest TEXT NOT NULL CHECK(length(identity_digest)=64 AND identity_digest NOT GLOB '*[^0-9a-f]*'),
      updated_at REAL NOT NULL, PRIMARY KEY(workspace_id,runner_id), UNIQUE(identity_digest));
    CREATE TABLE IF NOT EXISTS canary_runner_audit_records(
      audit_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, runner_id TEXT NOT NULL,
      action TEXT NOT NULL CHECK(action IN ('runner_revoked','runner_rotated','runner_activated')),
      actor TEXT NOT NULL, reason_code TEXT, created_at REAL NOT NULL);
    """)


_RUNNER_AUTH_TABLES = ("canary_runner_pairings", "canary_runner_nonce_chains", "canary_runner_request_ledger", "canary_runner_request_ledger_archive", "canary_runner_rotations", "canary_runner_identity_records", "canary_runner_audit_records", "canary_runner_chain_cursors", "canary_runner_resync_challenges", "canary_runner_pairing_protocols", "canary_runner_execution_protocols", "canary_runner_pairing_activation_receipts", "canary_runner_rotation_activation_receipts", "canary_runner_pairing_activation_abort_receipts", "canary_runner_rotation_activation_abort_receipts")


def validate_runner_auth_schema(conn: sqlite3.Connection) -> None:
    """Read-only exact final schema/data validation; startup must migrate rather than repair."""
    if not isinstance(conn, sqlite3.Connection):
        raise TypeError("runner authentication requires a SQLite connection")
    expected = sqlite3.connect(":memory:")
    try:
        expected.executescript(
            "CREATE TABLE workspaces(workspace_id TEXT PRIMARY KEY);"
            "CREATE TABLE canary_runners(workspace_id TEXT,runner_id TEXT,UNIQUE(workspace_id,runner_id));"
            "CREATE TABLE canary_runner_keys("
            "key_id TEXT PRIMARY KEY,workspace_id TEXT,runner_id TEXT,public_key TEXT,"
            "status TEXT,created_at REAL,revoked_at REAL);"
        )
        expected.executescript(RUNNER_AUTH_RUNTIME_SCHEMA)
        for table in _RUNNER_AUTH_TABLES:
            actual = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
            wanted = expected.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
            if actual is None or wanted is None or "".join(actual[0].split()) != "".join(wanted[0].split()):
                raise RuntimeError("runner authentication schema is not current")
            for pragma in ("foreign_key_list", "index_list"):
                if [tuple(row) for row in conn.execute(f"PRAGMA {pragma}({table})")] != [tuple(row) for row in expected.execute(f"PRAGMA {pragma}({table})")]:
                    raise RuntimeError("runner authentication schema is not current")
            if [tuple(row) for row in conn.execute(f"PRAGMA table_info({table})")] != [tuple(row) for row in expected.execute(f"PRAGMA table_info({table})")]:
                raise RuntimeError("runner authentication schema is not current")

        # Schema 28 owns exactly one key-history access path.  The runner key
        # table itself belongs to the canary store, so compare only this frozen
        # object instead of admitting a wider auth-schema ownership claim.
        def index_shape(database: sqlite3.Connection, name: str) -> tuple[str, list[tuple[object, ...]]]:
            row = database.execute(
                "SELECT sql FROM sqlite_master WHERE type='index' AND name=?", (name,),
            ).fetchone()
            if row is None or type(row[0]) is not str:
                raise RuntimeError("runner authentication schema is not current")
            return "".join(row[0].split()), [
                tuple(value) for value in database.execute(f"PRAGMA index_xinfo({name})")
            ]

        if index_shape(conn, "idx_canary_runner_key_history_expiry") != index_shape(
            expected, "idx_canary_runner_key_history_expiry",
        ):
            raise RuntimeError("runner authentication schema is not current")
        owned = set(_RUNNER_AUTH_TABLES)

        def normalized(value: object) -> str:
            if type(value) is not str:
                raise RuntimeError("runner authentication schema is not current")
            return "".join(value.split())

        def attached_triggers(database: sqlite3.Connection) -> list[tuple[str, str, str]]:
            return sorted(
                (str(row[0]), str(row[1]), normalized(row[2]))
                for row in database.execute(
                    "SELECT name,tbl_name,sql FROM sqlite_master "
                    "WHERE type='trigger' ORDER BY name",
                )
                if row[1] in owned
            )

        # PRAGMA index_list above rejects extra indexes.  Triggers do not
        # appear there, so compare their exact owned-schema set separately.
        # This is intentionally dynamic from the literal schema: later owned
        # migrations can add a frozen trigger without opening a permissive
        # side-channel for unlisted triggers.
        if attached_triggers(conn) != attached_triggers(expected):
            raise RuntimeError("runner authentication schema is not current")

        table_pattern = re.compile(
            r"(?<![A-Za-z0-9_])(?:" + "|".join(
                re.escape(table) for table in sorted(owned, key=len, reverse=True)
            ) + r")(?![A-Za-z0-9_])",
        )
        actual_views = sorted(
            (str(row[0]), normalized(row[1]))
            for row in conn.execute("SELECT name,sql FROM sqlite_master WHERE type='view' ORDER BY name")
            if type(row[1]) is str and table_pattern.search(row[1]) is not None
        )
        expected_views = sorted(
            (str(row[0]), normalized(row[1]))
            for row in expected.execute("SELECT name,sql FROM sqlite_master WHERE type='view' ORDER BY name")
            if type(row[1]) is str and table_pattern.search(row[1]) is not None
        )
        if actual_views != expected_views:
            raise RuntimeError("runner authentication schema is not current")
        if conn.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise RuntimeError("runner authentication schema has foreign-key violations")
        for display_name, status in conn.execute("SELECT display_name,status FROM canary_runner_pairings"):
            if display_name is None:
                if status != "expired":
                    raise RuntimeError("runner pairing has an invalid persisted display name")
            elif not _valid_persisted_display_name(display_name):
                raise RuntimeError("runner pairing has an invalid persisted display name")
    finally:
        expected.close()


def initialize_runner_auth_schema(conn: sqlite3.Connection) -> None:
    """Startup-only creation for a fresh local ControlPlane; never repairs old databases."""
    if not isinstance(conn, sqlite3.Connection):
        raise TypeError("runner authentication requires a SQLite connection")
    if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='canary_runner_pairings'").fetchone() is None:
        conn.executescript(RUNNER_AUTH_RUNTIME_SCHEMA)
    validate_runner_auth_schema(conn)


class RunnerAuthStore:
    def __init__(self, conn: sqlite3.Connection, *, pepper: bytes, now: Callable[[], float] = _now):
        if not isinstance(pepper, bytes) or not 32 <= len(pepper) <= 64:
            raise ValueError("runner authentication pepper must be 32 to 64 bytes")
        self.conn, self._pepper, self._now = conn, pepper, now
        self.conn.row_factory = sqlite3.Row

    def _ensure_hardened_ledger(self) -> None:
        _ensure_hardened_ledger_schema(self.conn)

    def _ensure_lifecycle_schema(self) -> None:
        """Runtime parity for new databases; migrated production gets these through v11."""
        _ensure_lifecycle_tables(self.conn)

    def _seal(self, value: str, *, aad: bytes) -> str:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        key = hashlib.sha256(b"heel.runner-ledger-aead.v1\0" + self._pepper).digest()
        nonce = secrets.token_bytes(12)
        return _b64(nonce + ChaCha20Poly1305(key).encrypt(nonce, value.encode("utf-8"), aad))

    def _open(self, value: str, *, aad: bytes) -> str:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        raw = base64.b64decode(value, validate=True)
        if len(raw) < 29:
            raise ValueError
        key = hashlib.sha256(b"heel.runner-ledger-aead.v1\0" + self._pepper).digest()
        return ChaCha20Poly1305(key).decrypt(raw[:12], raw[12:], aad).decode("utf-8")

    def _hash(self, domain: str, value: str) -> str:
        return hmac.new(self._pepper, domain.encode("ascii") + b"\0" + value.encode("utf-8"), hashlib.sha256).hexdigest()

    @staticmethod
    def _milliseconds(instant: float) -> int:
        return max(0, int(instant * 1000))

    def _identity_record(self, *, workspace_id: str, runner_id: str, public_key: str,
                         fingerprint: str, key_id: str, runner_version: str,
                         adapters_json: str, paired_by: str, paired_at: float,
                         heartbeat_at: float, state: str = "active",
                         previous_key_ids: list[str] | None = None,
                         rotated_at: float | None = None,
                         overlap_ends_at: float | None = None,
                         revoked_at: float | None = None, revoked_by: str | None = None,
                         reason_code: str | None = None) -> dict:
        try:
            adapters = json.loads(adapters_json or "{}")
            versions = sorted(set(adapters.values()))
        except (TypeError, ValueError):
            raise RunnerAuthError("invalid runner identity") from None
        base = {
            "schema_version": "heel.runner-identity.v1", "runner_id": runner_id,
            "workspace_id": workspace_id,
            "public_key": {"algorithm": "Ed25519", "key_id": key_id,
                           "public_key_b64": public_key},
            "fingerprint": fingerprint, "runner_version": runner_version,
            "adapter_versions": versions,
            "capabilities": list(RUNNER_CAPABILITIES),
            "pairing": {"paired_by": paired_by, "paired_at_ms": self._milliseconds(paired_at),
                        "fingerprint_confirmation": "confirmed", "phrase_confirmation": "confirmed"},
            "last_heartbeat_at_ms": self._milliseconds(heartbeat_at), "state": state,
            "rotation": {"previous_key_ids": sorted(previous_key_ids or []),
                         "rotated_at_ms": None if rotated_at is None else self._milliseconds(rotated_at),
                         "verification_overlap_ends_at_ms": None if overlap_ends_at is None else self._milliseconds(overlap_ends_at)},
            "revocation": {"revoked_at_ms": None if revoked_at is None else self._milliseconds(revoked_at),
                           "revoked_by": revoked_by, "reason_code": reason_code},
        }
        base["identity_digest"] = canonical_digest(base)
        return validate_runner_identity(base)

    def _save_identity(self, record: dict, *, instant: float) -> dict:
        validated = validate_runner_identity(record)
        self.conn.execute(
            "INSERT OR REPLACE INTO canary_runner_identity_records(workspace_id,runner_id,identity_json,identity_digest,updated_at) VALUES(?,?,?,?,?)",
            (validated["workspace_id"], validated["runner_id"], canonical_bytes(validated).decode("utf-8"),
             validated["identity_digest"], instant),
        )
        return validated

    def _load_identity(self, workspace_id: str, runner_id: str) -> dict:
        row = self.conn.execute("SELECT identity_json FROM canary_runner_identity_records WHERE workspace_id=? AND runner_id=?", (workspace_id, runner_id)).fetchone()
        if row is None:
            raise RunnerAuthError("invalid runner identity")
        try:
            return validate_runner_identity(json.loads(row["identity_json"]))
        except (TypeError, ValueError):
            raise RunnerAuthError("invalid runner identity") from None

    def _require_executable_protocol_in_transaction(self, workspace_id: str, runner_id: str) -> None:
        """Gate every PoP/control cursor before it can consume a nonce or resync it."""
        row = self.conn.execute(
            "SELECT protocol_version,control_protocol FROM canary_runner_execution_protocols "
            "WHERE workspace_id=? AND runner_id=?",
            (workspace_id, runner_id),
        ).fetchone()
        if row is None or tuple(row) != (3, "heel.runner-control.v2"):
            raise RunnerProtocolUpgradeRequired("runner protocol upgrade required")

    def _save_changed_identity(self, identity: dict, *, instant: float) -> dict:
        identity["identity_digest"] = canonical_digest({key: value for key, value in identity.items() if key != "identity_digest"})
        return self._save_identity(identity, instant=instant)

    def _single_active_key_locked(self, workspace_id: str, runner_id: str) -> sqlite3.Row:
        """Return the one currently active old key or fail closed.

        The row-bound rotation protocol intentionally never chooses an
        arbitrary active key.  This helper is called only while the caller
        owns its short SQLite transaction.
        """
        rows = self.conn.execute(
            "SELECT key_id,public_key FROM canary_runner_keys WHERE workspace_id=? AND runner_id=? "
            "AND status='active' AND revoked_at IS NULL ORDER BY key_id ASC",
            (workspace_id, runner_id),
        ).fetchall()
        if len(rows) != 1:
            raise RunnerAuthError("invalid rotation")
        return rows[0]

    def _bound_rotation_old_key_locked(self, row: sqlite3.Row) -> sqlite3.Row:
        """Prove an open ceremony still names the live identity authority."""
        old = self._single_active_key_locked(row["workspace_id"], row["runner_id"])
        try:
            raw = load_public_key_base64(old["public_key"]).public_bytes(Encoding.Raw, PublicFormat.Raw)
        except ValueError:
            raise RunnerAuthError("invalid rotation") from None
        fingerprint = hashlib.sha256(raw).hexdigest()
        if (
            row["old_key_id"] != old["key_id"]
            or row["old_fingerprint"] != fingerprint
        ):
            raise RunnerAuthError("invalid rotation")
        identity = self._load_identity(row["workspace_id"], row["runner_id"])
        public = identity.get("public_key")
        if (
            not isinstance(public, dict)
            or public.get("key_id") != old["key_id"]
            or public.get("public_key_b64") != old["public_key"]
            or identity.get("fingerprint") != fingerprint
        ):
            raise RunnerAuthError("invalid rotation")
        return old

    def identity(self, workspace_id: str, runner_id: str) -> dict:
        """Return a detached validated cloud identity projection, never local key material."""
        return self._load_identity(workspace_id, runner_id)

    @staticmethod
    def _identifier(value: object, field: str) -> str:
        if type(value) is not str or not value or len(value.encode("utf-8")) > 128 or value.strip() != value:
            raise ValueError(f"invalid {field}")
        return value

    @staticmethod
    def _phrase(value: object) -> str:
        return validate_pairing_phrase(value)

    def invite(self, workspace_id: str) -> PairingInvitation:
        self._identifier(workspace_id, "workspace")
        token, instant = _token(), self._now()
        # Invitation is intentionally a pairing row only after runner exchange, so it is
        # returned exactly once and the raw value never reaches persistent storage.
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            # Activation receipts are authority-recovery evidence for thirty days.  An
            # invitation in another tenant must never sweep an activated pairing (and
            # cascade-delete its receipt) merely because its original ten-minute
            # challenge deadline passed.
            self.conn.execute(
                "DELETE FROM canary_runner_pairings WHERE workspace_id=? "
                "AND status IN ('invited','pending','approved','expired') AND expires_at<?",
                (workspace_id, instant),
            )
            self.conn.execute(
                "INSERT INTO canary_runner_pairings(pairing_id,workspace_id,runner_id,invitation_hash,status,created_at,expires_at,display_name) VALUES(?,?,?,?,?,?,?,?)",
                ("pending_" + secrets.token_hex(16), workspace_id, "", self._hash("invitation", token), "invited", instant, instant + PAIRING_TTL, "Pending runner"),
            )
            self.conn.commit()
        except Exception:
            self.conn.rollback(); raise
        return PairingInvitation(token, instant + PAIRING_TTL)

    def exchange(self, invitation: str, public_key_b64: str, phrase: str, *, display_name: str,
                 runner_version: str, adapters: Mapping[str, str],
                 control_protocol: str | None = None, exchange_digest: str | None = None) -> PairingView:
        if type(display_name) is not str:
            raise ValueError("invalid runner display name")
        display_name = unicodedata.normalize("NFC", display_name)
        if (not display_name or display_name != display_name.strip() or len(display_name.encode()) > 128
                or len(display_name) > 64 or any(unicodedata.category(char).startswith("C") for char in display_name)):
            raise ValueError("invalid runner display name")
        self._identifier(runner_version, "runner version")
        phrase = self._phrase(phrase)
        if not isinstance(adapters, Mapping) or not all(type(k) is str and type(v) is str for k, v in adapters.items()):
            raise ValueError("invalid runner adapters")
        if (control_protocol is None) != (exchange_digest is None):
            raise ValueError("invalid runner protocol exchange")
        if control_protocol is not None:
            if control_protocol != "heel.runner-control.v2" or not _lower_hex_digest(exchange_digest):
                raise ValueError("invalid runner protocol exchange")
        try:
            key = load_public_key_base64(public_key_b64)
        except ValueError as error:
            raise ValueError("invalid runner public key") from error
        raw_key = key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        key_id, fingerprint, instant = ed25519_key_id(raw_key), hashlib.sha256(raw_key).hexdigest(), self._now()
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            row = self.conn.execute("SELECT * FROM canary_runner_pairings WHERE invitation_hash=?", (self._hash("invitation", invitation),)).fetchone()
            if row is None or row["status"] != "invited" or row["expires_at"] <= instant:
                raise RunnerAuthError("invalid pairing")
            runner_id = None
            for _ in range(8):
                candidate = "runr_" + secrets.token_hex(16)
                if self.conn.execute("SELECT 1 FROM canary_runners WHERE runner_id=? UNION SELECT 1 FROM canary_runner_pairings WHERE runner_id=?", (candidate, candidate)).fetchone() is None:
                    runner_id = candidate; break
            if runner_id is None: raise RunnerAuthError("runner ID unavailable")
            challenge = _token()
            self.conn.execute("UPDATE canary_runner_pairings SET runner_id=?, invitation_hash=?, phrase=?, public_key=?, fingerprint=?, key_id=?, runner_version=?, adapters_json=?, activation_challenge=?, status='pending', display_name=? WHERE pairing_id=?",
                              (runner_id, self._hash("consumed-invitation", row["pairing_id"]), phrase, public_key_b64, fingerprint, key_id, runner_version, canonical_bytes(dict(adapters)).decode(), challenge, display_name, row["pairing_id"]))
            if control_protocol is not None:
                self.conn.execute(
                    "INSERT INTO canary_runner_pairing_protocols(pairing_id,protocol_version,control_protocol,exchange_digest,created_at) VALUES(?,?,?,?,?)",
                    (row["pairing_id"], 3, control_protocol, exchange_digest, instant),
                )
            self.conn.commit()
        except Exception:
            self.conn.rollback(); raise
        return PairingView(
            row["pairing_id"], runner_id, phrase, fingerprint, "pending", row["expires_at"],
            challenge, control_protocol, exchange_digest,
        )

    def inspect(self, workspace_id: str, pairing_id: str) -> PairingView:
        row = self.conn.execute("SELECT * FROM canary_runner_pairings WHERE workspace_id=? AND pairing_id=?", (workspace_id, pairing_id)).fetchone()
        if row is None or row["status"] not in {"pending", "approved"} or not row["phrase"] or not row["fingerprint"]:
            raise RunnerAuthError("invalid pairing")
        return PairingView(row["pairing_id"], row["runner_id"], row["phrase"], row["fingerprint"], row["status"], row["expires_at"])

    def approve(self, workspace_id: str, pairing_id: str, *, phrase: str, fingerprint: str, actor: str) -> None:
        phrase = self._phrase(phrase)
        if type(fingerprint) is not str or len(fingerprint) != 64 or fingerprint != fingerprint.lower():
            raise ValueError("invalid runner fingerprint")
        instant = self._now()
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            row = self.conn.execute("SELECT * FROM canary_runner_pairings WHERE workspace_id=? AND pairing_id=?", (workspace_id, pairing_id)).fetchone()
            if row is None or row["status"] != "pending" or row["expires_at"] <= instant or not hmac.compare_digest(row["phrase"], phrase) or not hmac.compare_digest(row["fingerprint"], fingerprint):
                raise RunnerAuthError("invalid pairing")
            self.conn.execute("UPDATE canary_runner_pairings SET status='approved', approved_at=?, approved_by=? WHERE pairing_id=?", (instant, actor, pairing_id))
            self.conn.commit()
        except Exception:
            self.conn.rollback(); raise

    def activate(self, pairing_id: str, signature_b64: str, *, max_active: int | None = None) -> tuple[str, str, str]:
        instant = self._now()
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            row = self.conn.execute("SELECT * FROM canary_runner_pairings WHERE pairing_id=?", (pairing_id,)).fetchone()
            if row is None or row["status"] != "approved" or row["expires_at"] <= instant:
                raise RunnerAuthError("invalid pairing")
            try:
                signature = base64.b64decode(signature_b64, validate=True)
                if len(signature) != 64 or _b64(signature) != signature_b64:
                    raise ValueError
                key = load_public_key_base64(row["public_key"])
                proof = b"heel.runner-pairing-activate.v1\0" + canonical_bytes({"pairing_id": pairing_id, "challenge": row["activation_challenge"]})
                key.verify(signature, proof)
            except (ValueError, InvalidSignature):
                raise RunnerAuthError("invalid pairing") from None
            current = self.conn.execute("SELECT COUNT(*) FROM canary_runners WHERE workspace_id=? AND status='active'", (row["workspace_id"],)).fetchone()[0]
            if max_active is not None and current >= max_active:
                raise RunnerAuthError("runner quota exceeded")
            self.conn.execute("INSERT INTO canary_runners(runner_id,workspace_id,display_name,status,created_at) VALUES(?,?,?,?,?)", (row["runner_id"], row["workspace_id"], row["display_name"] or row["runner_id"], "active", instant))
            self.conn.execute("INSERT INTO canary_runner_keys(key_id,workspace_id,runner_id,public_key,status,created_at,revoked_at) VALUES(?,?,?,?,?,?,NULL)", (row["key_id"], row["workspace_id"], row["runner_id"], row["public_key"], "active", instant))
            nonce = _token()
            self.conn.execute("INSERT INTO canary_runner_nonce_chains VALUES(?,?,?,?,?,?)", (row["workspace_id"], row["runner_id"], "claim", self._hash("nonce", nonce), 1, instant + NONCE_TTL))
            self.conn.execute("INSERT INTO canary_runner_chain_cursors VALUES(?,?,?,?,?,?)", (row["workspace_id"], row["runner_id"], "claim", 1, 0, instant))
            self._save_identity(self._identity_record(
                workspace_id=row["workspace_id"], runner_id=row["runner_id"], public_key=row["public_key"],
                fingerprint=row["fingerprint"], key_id=row["key_id"], runner_version=row["runner_version"],
                adapters_json=row["adapters_json"], paired_by=row["approved_by"],
                paired_at=row["approved_at"], heartbeat_at=instant), instant=instant)
            self.conn.execute("INSERT INTO canary_runner_audit_records(audit_id,workspace_id,runner_id,action,actor,reason_code,created_at) VALUES(?,?,?,?,?,?,?)", ("runner_audit_" + secrets.token_hex(16), row["workspace_id"], row["runner_id"], "runner_activated", row["approved_by"], None, instant))
            self.conn.execute("UPDATE canary_runner_pairings SET status='activated', phrase=NULL, activation_challenge=NULL, activated_at=? WHERE pairing_id=?", (instant, pairing_id))
            self.conn.commit()
        except Exception:
            self.conn.rollback(); raise
        return row["workspace_id"], row["runner_id"], nonce

    @staticmethod
    def _activation_request_digest(pairing_id: str, request: Mapping[str, object]) -> str:
        if type(pairing_id) is not str or not pairing_id:
            raise ValueError("invalid pairing")
        path = f"/v1/runner-pairings/{pairing_id}/activate".encode("utf-8")
        return hashlib.sha256(b"POST\0" + path + b"\0" + canonical_bytes(dict(request))).hexdigest()

    @staticmethod
    def _activation_nonce(value: object) -> str:
        if type(value) is not str:
            raise ValueError("invalid pairing")
        try:
            raw = base64.b64decode(value, validate=True)
        except (ValueError, TypeError):
            raise ValueError("invalid pairing") from None
        if len(raw) != 32 or _b64(raw) != value:
            raise ValueError("invalid pairing")
        return value

    def _validated_v3_activation_response(self, value: object, row: sqlite3.Row,
                                          protocol: sqlite3.Row) -> dict:
        if not isinstance(value, dict) or set(value) != {
            "schema_version", "workspace_id", "runner_id", "runner_key_id",
            "pairing_exchange_digest", "initial_claim_nonce", "initial_claim_sequence",
            "initial_claim_generation", "capabilities", "control_protocol", "activated_at_ms",
        }:
            raise RunnerAuthError("invalid pairing")
        if (
            value["schema_version"] != "heel.runner-pairing-activated.v3"
            or value["workspace_id"] != row["workspace_id"]
            or value["runner_id"] != row["runner_id"]
            or value["runner_key_id"] != row["key_id"]
            or value["pairing_exchange_digest"] != protocol["exchange_digest"]
            or value["control_protocol"] != "heel.runner-control.v2"
            or value["capabilities"] != sorted(RUNNER_CAPABILITIES)
            or value["initial_claim_sequence"] != 1
            or value["initial_claim_generation"] != 0
            or type(value["activated_at_ms"]) is not int
            or not 0 <= value["activated_at_ms"] <= _SAFE_JSON_INT
        ):
            raise RunnerAuthError("invalid pairing")
        self._activation_nonce(value["initial_claim_nonce"])
        return value

    def activate_executable(self, pairing_id: str, request: Mapping[str, object], *,
                            max_active: int | None = None) -> dict:
        """Activate one v3 pairing and persist the exact response before answering it."""
        if not isinstance(request, Mapping) or set(request) != {
            "schema_version", "client_activation_nonce_b64", "signature_b64",
        } or request.get("schema_version") != "heel.runner-pairing-activate.v3":
            raise ValueError("invalid pairing")
        client_nonce = self._activation_nonce(request["client_activation_nonce_b64"])
        if type(request["signature_b64"]) is not str:
            raise ValueError("invalid pairing")
        request_digest = self._activation_request_digest(pairing_id, request)
        instant = self._now()
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            row = self.conn.execute("SELECT * FROM canary_runner_pairings WHERE pairing_id=?", (pairing_id,)).fetchone()
            protocol = self.conn.execute(
                "SELECT * FROM canary_runner_pairing_protocols WHERE pairing_id=?", (pairing_id,),
            ).fetchone()
            if row is None or protocol is None or protocol["protocol_version"] != 3 or protocol["control_protocol"] != "heel.runner-control.v2":
                raise RunnerAuthError("invalid pairing")
            if row["status"] == "activated":
                receipt = self.conn.execute(
                    "SELECT request_digest,response_ciphertext,expires_at FROM canary_runner_pairing_activation_receipts WHERE pairing_id=?",
                    (pairing_id,),
                ).fetchone()
                if receipt is None or not hmac.compare_digest(receipt["request_digest"], request_digest):
                    raise RunnerAuthError("invalid pairing")
                if receipt["expires_at"] <= instant:
                    raise RunnerActivationReceiptExpired("runner activation receipt expired")
                try:
                    response = json_load(self._open(
                        receipt["response_ciphertext"], aad=f"pairing-v3-activation\0{pairing_id}".encode(),
                    ))
                except (TypeError, ValueError, RunnerAuthError):
                    raise RunnerAuthError("invalid pairing") from None
                response = self._validated_v3_activation_response(response, row, protocol)
                self.conn.commit()
                return response
            if row["status"] != "approved" or row["expires_at"] <= instant:
                raise RunnerAuthError("invalid pairing")
            try:
                signature = base64.b64decode(request["signature_b64"], validate=True)
                if len(signature) != 64 or _b64(signature) != request["signature_b64"]:
                    raise ValueError
                key = load_public_key_base64(row["public_key"])
                proof = {
                    "pairing_id": pairing_id, "activation_challenge": row["activation_challenge"],
                    "pairing_exchange_digest": protocol["exchange_digest"],
                    "client_activation_nonce_b64": client_nonce,
                    "control_protocol": "heel.runner-control.v2",
                }
                key.verify(signature, b"heel.runner-pairing-activate.v3\0" + canonical_bytes(proof))
            except (ValueError, InvalidSignature):
                raise RunnerAuthError("invalid pairing") from None
            current = self.conn.execute(
                "SELECT COUNT(*) FROM canary_runners WHERE workspace_id=? AND status='active'",
                (row["workspace_id"],),
            ).fetchone()[0]
            if max_active is not None and current >= max_active:
                raise RunnerAuthError("runner quota exceeded")
            self.conn.execute(
                "INSERT INTO canary_runners(runner_id,workspace_id,display_name,status,created_at) VALUES(?,?,?,?,?)",
                (row["runner_id"], row["workspace_id"], row["display_name"] or row["runner_id"], "active", instant),
            )
            self.conn.execute(
                "INSERT INTO canary_runner_keys(key_id,workspace_id,runner_id,public_key,status,created_at,revoked_at) VALUES(?,?,?,?,?,?,NULL)",
                (row["key_id"], row["workspace_id"], row["runner_id"], row["public_key"], "active", instant),
            )
            nonce = _token()
            self.conn.execute(
                "INSERT INTO canary_runner_nonce_chains VALUES(?,?,?,?,?,?)",
                (row["workspace_id"], row["runner_id"], "claim", self._hash("nonce", nonce), 1, instant + NONCE_TTL),
            )
            self.conn.execute(
                "INSERT INTO canary_runner_chain_cursors VALUES(?,?,?,?,?,?)",
                (row["workspace_id"], row["runner_id"], "claim", 1, 0, instant),
            )
            self._save_identity(self._identity_record(
                workspace_id=row["workspace_id"], runner_id=row["runner_id"], public_key=row["public_key"],
                fingerprint=row["fingerprint"], key_id=row["key_id"], runner_version=row["runner_version"],
                adapters_json=row["adapters_json"], paired_by=row["approved_by"], paired_at=row["approved_at"],
                heartbeat_at=instant,
            ), instant=instant)
            self.conn.execute(
                "INSERT INTO canary_runner_execution_protocols(workspace_id,runner_id,protocol_version,control_protocol,exchange_digest,activated_at) VALUES(?,?,?,?,?,?)",
                (row["workspace_id"], row["runner_id"], 3, "heel.runner-control.v2", protocol["exchange_digest"], instant),
            )
            self.conn.execute(
                "INSERT INTO canary_runner_audit_records(audit_id,workspace_id,runner_id,action,actor,reason_code,created_at) VALUES(?,?,?,?,?,?,?)",
                ("runner_audit_" + secrets.token_hex(16), row["workspace_id"], row["runner_id"], "runner_activated", row["approved_by"], None, instant),
            )
            response = {
                "schema_version": "heel.runner-pairing-activated.v3", "workspace_id": row["workspace_id"],
                "runner_id": row["runner_id"], "runner_key_id": row["key_id"],
                "pairing_exchange_digest": protocol["exchange_digest"], "initial_claim_nonce": nonce,
                "initial_claim_sequence": 1, "initial_claim_generation": 0,
                "capabilities": sorted(RUNNER_CAPABILITIES), "control_protocol": "heel.runner-control.v2",
                "activated_at_ms": self._milliseconds(instant),
            }
            self._validated_v3_activation_response(response, row, protocol)
            receipt_expiry = instant + 2_592_000.0
            self.conn.execute(
                "INSERT INTO canary_runner_pairing_activation_receipts(pairing_id,request_digest,response_ciphertext,created_at,expires_at) VALUES(?,?,?,?,?)",
                (pairing_id, request_digest, self._seal(canonical_bytes(response).decode(), aad=f"pairing-v3-activation\0{pairing_id}".encode()), instant, receipt_expiry),
            )
            self.conn.execute(
                "UPDATE canary_runner_pairings SET status='activated', phrase=NULL, activation_challenge=NULL, activated_at=?,expires_at=? WHERE pairing_id=?",
                (instant, receipt_expiry, pairing_id),
            )
            self.conn.commit()
            return response
        except Exception:
            if self.conn.in_transaction:
                self.conn.rollback()
            raise

    def abort_executable_pairing_activation(
        self, pairing_id: str, request: Mapping[str, object],
    ) -> dict[str, object]:
        """Atomically abandon an expired v3 activation, preserving a replay receipt."""
        v1_fields = {
            "schema_version", "pairing_id", "runner_id", "pairing_exchange_digest",
            "activation_request_digest", "challenge_expires_at_ms", "reason_code",
            "signature_b64",
        }
        v2_fields = {
            "schema_version", "pairing_id", "runner_id", "pairing_exchange_digest",
            "activation_request_digest", "activation_challenge_digest", "reason_code",
            "signature_b64",
        }
        is_v1 = isinstance(request, Mapping) and set(request) == v1_fields and (
            request.get("schema_version") == "heel.runner-pairing-activation-abort.v1"
        )
        is_v2 = isinstance(request, Mapping) and set(request) == v2_fields and (
            request.get("schema_version") == "heel.runner-pairing-activation-abort.v2"
        )
        if (
            not (is_v1 or is_v2)
            or request.get("pairing_id") != pairing_id
            or request.get("reason_code") != "activation_challenge_expired"
            or not _lower_hex_digest(request.get("pairing_exchange_digest"))
            or not _lower_hex_digest(request.get("activation_request_digest"))
            or type(request.get("signature_b64")) is not str
            or (is_v1 and (
                isinstance(request.get("challenge_expires_at_ms"), bool)
                or not isinstance(request.get("challenge_expires_at_ms"), int)
                or not 0 <= request["challenge_expires_at_ms"] <= _SAFE_JSON_INT
            ))
            or (is_v2 and not _lower_hex_digest(request.get("activation_challenge_digest")))
        ):
            raise ValueError("invalid pairing activation abort")
        self._identifier(pairing_id, "pairing")
        self._identifier(request["runner_id"], "runner")
        digest = hashlib.sha256(canonical_bytes(dict(request))).hexdigest()
        fields = v1_fields if is_v1 else v2_fields
        unsigned = {key: request[key] for key in fields - {"signature_b64"}}
        try:
            signature = base64.b64decode(request["signature_b64"], validate=True)
            if len(signature) != 64 or _b64(signature) != request["signature_b64"]:
                raise ValueError
        except (TypeError, ValueError):
            raise ValueError("invalid pairing activation abort") from None
        instant = self._now()
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            row = self.conn.execute(
                "SELECT * FROM canary_runner_pairings WHERE pairing_id=?", (pairing_id,),
            ).fetchone()
            protocol = self.conn.execute(
                "SELECT * FROM canary_runner_pairing_protocols WHERE pairing_id=?", (pairing_id,),
            ).fetchone()
            if (
                row is None or protocol is None or row["runner_id"] != request["runner_id"]
                or protocol["protocol_version"] != 3
                or protocol["control_protocol"] != "heel.runner-control.v2"
                or not hmac.compare_digest(protocol["exchange_digest"], request["pairing_exchange_digest"])
            ):
                raise RunnerAuthError("invalid pairing")
            try:
                load_public_key_base64(row["public_key"]).verify(
                    signature,
                    (
                        b"heel.runner-pairing-activation-abort.v1\0"
                        if is_v1 else b"heel.runner-pairing-activation-abort.v2\0"
                    ) + canonical_bytes(unsigned),
                )
            except (ValueError, InvalidSignature):
                raise RunnerAuthError("invalid pairing") from None
            existing = self.conn.execute(
                "SELECT request_digest,response_digest,response_ciphertext,expires_at FROM "
                "canary_runner_pairing_activation_abort_receipts WHERE pairing_id=?",
                (pairing_id,),
            ).fetchone()
            if existing is not None:
                if not hmac.compare_digest(existing["request_digest"], digest):
                    raise RunnerAuthError("invalid pairing")
                if existing["expires_at"] <= instant:
                    raise RunnerActivationReceiptExpired("runner activation receipt expired")
                response = json_load(self._open(
                    existing["response_ciphertext"],
                    aad=f"pairing-v3-activation-abort\0{pairing_id}".encode(),
                ))
                if hashlib.sha256(canonical_bytes(response)).hexdigest() != existing["response_digest"]:
                    raise RunnerAuthError("invalid pairing")
                self.conn.commit()
                return response
            activation = self.conn.execute(
                "SELECT 1 FROM canary_runner_pairing_activation_receipts WHERE pairing_id=?",
                (pairing_id,),
            ).fetchone()
            if row["status"] == "activated" and activation is not None:
                raise RunnerActivationAbortConflict("runner_activation_already_accepted")
            expiry_ms = int(row["expires_at"] * 1000)
            if is_v1 and expiry_ms != request["challenge_expires_at_ms"]:
                raise RunnerAuthError("invalid pairing")
            if is_v2:
                try:
                    challenge = self._activation_nonce(row["activation_challenge"])
                    challenge_digest = hashlib.sha256(
                        base64.b64decode(challenge, validate=True),
                    ).hexdigest()
                except (TypeError, ValueError):
                    raise RunnerAuthError("invalid pairing") from None
                if not hmac.compare_digest(challenge_digest, request["activation_challenge_digest"]):
                    raise RunnerAuthError("invalid pairing")
            if instant < row["expires_at"]:
                if is_v2:
                    response = {
                        "schema_version": "heel.runner-pairing-activation-abort-deferred.v1",
                        "code": "runner_activation_challenge_live", "pairing_id": pairing_id,
                        "runner_id": row["runner_id"],
                        "pairing_exchange_digest": protocol["exchange_digest"],
                        "activation_challenge_digest": request["activation_challenge_digest"],
                        "challenge_expires_at_ms": expiry_ms,
                        "server_time_ms": self._milliseconds(instant),
                        "retry_after_ms": max(1, expiry_ms - self._milliseconds(instant)),
                    }
                    self.conn.commit()
                    raise RunnerActivationAbortDeferred(response)
                retry = min(600_000, max(0, int((row["expires_at"] - instant) * 1000)))
                raise RunnerActivationAbortConflict("runner_activation_not_expired", retry_after_ms=retry)
            if row["status"] != "approved" or activation is not None:
                raise RunnerAuthError("invalid pairing")
            if is_v1:
                response = {
                    "schema_version": "heel.runner-pairing-activation-aborted.v1",
                    "workspace_id": row["workspace_id"], "runner_id": row["runner_id"],
                    "pairing_id": pairing_id,
                    "activation_request_digest": request["activation_request_digest"],
                    "status": "expired", "aborted_at_ms": self._milliseconds(instant),
                }
            else:
                response = {
                    "schema_version": "heel.runner-pairing-activation-aborted.v2",
                    "workspace_id": row["workspace_id"], "runner_id": row["runner_id"],
                    "pairing_id": pairing_id,
                    "activation_request_digest": request["activation_request_digest"],
                    "activation_challenge_digest": request["activation_challenge_digest"],
                    "challenge_expires_at_ms": expiry_ms,
                    "status": "expired", "aborted_at_ms": self._milliseconds(instant),
                }
            response_digest = hashlib.sha256(canonical_bytes(response)).hexdigest()
            expiry = instant + 2_592_000.0
            self.conn.execute(
                "INSERT INTO canary_runner_pairing_activation_abort_receipts("
                "pairing_id,request_digest,response_digest,response_ciphertext,created_at,expires_at) "
                "VALUES(?,?,?,?,?,?)",
                (
                    pairing_id, digest, response_digest,
                    self._seal(canonical_bytes(response).decode(), aad=f"pairing-v3-activation-abort\0{pairing_id}".encode()),
                    instant, expiry,
                ),
            )
            changed = self.conn.execute(
                "UPDATE canary_runner_pairings SET status='expired',phrase=NULL,activation_challenge=NULL,expires_at=? "
                "WHERE pairing_id=? AND status='approved'",
                (expiry, pairing_id),
            )
            if changed.rowcount != 1:
                raise RunnerAuthError("invalid pairing")
            self.conn.commit()
            return response
        except Exception:
            if self.conn.in_transaction:
                self.conn.rollback()
            raise

    def abort_rotation_activation(
        self, pairing_id: str, request: Mapping[str, object],
    ) -> dict[str, object]:
        """Atomically restore the old Cloud identity after an expired rotation challenge."""
        fields = {
            "schema_version", "workspace_id", "runner_id", "pairing_id",
            "old_runner_key_id", "new_runner_key_id", "activation_request_digest",
            "activation_challenge_digest", "challenge_expires_at_ms", "reason_code",
            "old_signature_b64", "new_signature_b64",
        }
        if (
            not isinstance(request, Mapping) or set(request) != fields
            or request.get("schema_version") != "heel.runner-rotation-activation-abort.v1"
            or request.get("pairing_id") != pairing_id
            or request.get("reason_code") != "activation_challenge_expired"
            or any(not _lower_hex_digest(request.get(key)) for key in (
                "activation_request_digest", "activation_challenge_digest",
            ))
            or isinstance(request.get("challenge_expires_at_ms"), bool)
            or not isinstance(request.get("challenge_expires_at_ms"), int)
            or not 0 <= request["challenge_expires_at_ms"] <= _SAFE_JSON_INT
            or type(request.get("old_signature_b64")) is not str
            or type(request.get("new_signature_b64")) is not str
        ):
            raise ValueError("invalid rotation activation abort")
        for field in ("workspace_id", "runner_id", "old_runner_key_id", "new_runner_key_id"):
            self._identifier(request[field], field)
        self._identifier(pairing_id, "pairing")
        core = {key: request[key] for key in fields - {"old_signature_b64", "new_signature_b64"}}
        digest = hashlib.sha256(canonical_bytes(dict(request))).hexdigest()
        try:
            old_signature = base64.b64decode(request["old_signature_b64"], validate=True)
            new_signature = base64.b64decode(request["new_signature_b64"], validate=True)
            if (
                len(old_signature) != 64 or _b64(old_signature) != request["old_signature_b64"]
                or len(new_signature) != 64 or _b64(new_signature) != request["new_signature_b64"]
            ):
                raise ValueError
        except (TypeError, ValueError):
            raise ValueError("invalid rotation activation abort") from None
        instant = self._now()
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            row = self.conn.execute(
                "SELECT * FROM canary_runner_rotations WHERE pairing_id=?", (pairing_id,),
            ).fetchone()
            if (
                row is None or row["workspace_id"] != request["workspace_id"]
                or row["runner_id"] != request["runner_id"]
                or row["key_id"] != request["new_runner_key_id"]
                or row["old_key_id"] != request["old_runner_key_id"]
            ):
                raise RunnerAuthError("invalid rotation")
            old = self._bound_rotation_old_key_locked(row)
            try:
                load_public_key_base64(old["public_key"]).verify(
                    old_signature,
                    b"heel.runner-rotation-activation-abort.v1.old\0" + canonical_bytes(core),
                )
                load_public_key_base64(row["public_key"]).verify(
                    new_signature,
                    b"heel.runner-rotation-activation-abort.v1.new\0" + canonical_bytes(core),
                )
            except (ValueError, InvalidSignature):
                raise RunnerAuthError("invalid rotation") from None
            existing = self.conn.execute(
                "SELECT request_digest,response_digest,response_ciphertext,expires_at FROM "
                "canary_runner_rotation_activation_abort_receipts WHERE pairing_id=?",
                (pairing_id,),
            ).fetchone()
            if existing is not None:
                if not hmac.compare_digest(existing["request_digest"], digest):
                    raise RunnerAuthError("invalid rotation")
                if existing["expires_at"] <= instant:
                    raise RunnerActivationReceiptExpired("runner activation receipt expired")
                response = json_load(self._open(
                    existing["response_ciphertext"],
                    aad=f"rotation-v2-activation-abort\0{pairing_id}".encode(),
                ))
                if hashlib.sha256(canonical_bytes(response)).hexdigest() != existing["response_digest"]:
                    raise RunnerAuthError("invalid rotation")
                self.conn.commit()
                return response
            accepted = self.conn.execute(
                "SELECT 1 FROM canary_runner_rotation_activation_receipts WHERE pairing_id=?",
                (pairing_id,),
            ).fetchone()
            if row["status"] == "rotated" and accepted is not None:
                raise RunnerActivationAbortConflict("runner_activation_already_accepted")
            try:
                if hashlib.sha256(base64.b64decode(row["activation_challenge"], validate=True)).hexdigest() != request["activation_challenge_digest"]:
                    raise ValueError
            except (TypeError, ValueError):
                raise RunnerAuthError("invalid rotation") from None
            if int(row["expires_at"] * 1000) != request["challenge_expires_at_ms"]:
                raise RunnerAuthError("invalid rotation")
            if instant < row["expires_at"]:
                retry = min(600_000, max(0, int((row["expires_at"] - instant) * 1000)))
                raise RunnerActivationAbortConflict("runner_activation_not_expired", retry_after_ms=retry)
            if row["status"] != "rotation_approved" or accepted is not None:
                raise RunnerAuthError("invalid rotation")
            response = {
                "schema_version": "heel.runner-rotation-activation-aborted.v1",
                "workspace_id": row["workspace_id"], "runner_id": row["runner_id"],
                "pairing_id": pairing_id, "old_runner_key_id": request["old_runner_key_id"],
                "new_runner_key_id": request["new_runner_key_id"],
                "activation_request_digest": request["activation_request_digest"],
                "status": "expired", "aborted_at_ms": self._milliseconds(instant),
            }
            response_digest = hashlib.sha256(canonical_bytes(response)).hexdigest()
            expiry = instant + 2_592_000.0
            self.conn.execute(
                "INSERT INTO canary_runner_rotation_activation_abort_receipts("
                "pairing_id,request_digest,response_digest,response_ciphertext,created_at,expires_at) "
                "VALUES(?,?,?,?,?,?)",
                (
                    pairing_id, digest, response_digest,
                    self._seal(canonical_bytes(response).decode(), aad=f"rotation-v2-activation-abort\0{pairing_id}".encode()),
                    instant, expiry,
                ),
            )
            identity = self._load_identity(row["workspace_id"], row["runner_id"])
            if identity.get("state") != "rotating":
                raise RunnerAuthError("invalid rotation")
            identity["state"] = "active"
            self._save_changed_identity(identity, instant=instant)
            changed = self.conn.execute(
                "UPDATE canary_runner_rotations SET status='expired',phrase=NULL,activation_challenge=NULL,expires_at=? "
                "WHERE pairing_id=? AND status='rotation_approved'",
                (expiry, pairing_id),
            )
            if changed.rowcount != 1:
                raise RunnerAuthError("invalid rotation")
            self.conn.commit()
            return response
        except Exception:
            if self.conn.in_transaction:
                self.conn.rollback()
            raise

    def provision_run_chains(self, workspace_id: str, runner_id: str, run_id: str) -> dict[str, dict[str, object]]:
        """Atomically issue independent nonce state for every named run operation."""
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            issued = self.provision_run_chains_in_transaction(workspace_id, runner_id, run_id)
            self.conn.commit()
        except Exception:
            self.conn.rollback(); raise
        return issued

    def provision_run_chains_in_transaction(
        self, workspace_id: str, runner_id: str, run_id: str,
    ) -> dict[str, dict[str, object]]:
        """Issue run chains inside the caller's claim transaction, without nesting BEGIN."""
        if not self.conn.in_transaction:
            raise RuntimeError("run-chain provisioning requires an active transaction")
        self._identifier(run_id, "run")
        instant = self._now()
        row = self.conn.execute(
            "SELECT 1 FROM canary_runners WHERE workspace_id=? AND runner_id=? AND status='active'",
            (workspace_id, runner_id),
        ).fetchone()
        if row is None:
            raise RunnerAuthError("invalid runner")
        issued: dict[str, dict[str, object]] = {}
        for operation in ("heartbeat", "progress", "result", "stop-ack"):
            nonce, chain = _token(), f"{operation}:{run_id}"
            self.conn.execute(
                "INSERT INTO canary_runner_nonce_chains VALUES(?,?,?,?,?,?)",
                (workspace_id, runner_id, chain, self._hash("nonce", nonce), 1,
                 instant + NONCE_TTL),
            )
            self.conn.execute(
                "INSERT INTO canary_runner_chain_cursors VALUES(?,?,?,?,?,?)",
                (workspace_id, runner_id, chain, 1, 0, instant),
            )
            issued[operation] = {
                "next_nonce_b64": nonce, "next_sequence": 1, "generation": 0,
            }
        return issued

    def _revoke_unused_canary_grants_in_transaction(
        self,
        workspace_id: str,
        runner_id: str,
        *,
        runner_key_id: str | None,
        actor: str,
        reason_code: str,
        instant: float,
        ledger: object,
    ) -> None:
        """Cancel and refund unclaimed grants bound to authority that is going away."""
        if not self.conn.in_transaction:
            raise RuntimeError("grant revocation requires an active transaction")
        columns = {
            row[1] for row in self.conn.execute("PRAGMA table_info(canary_execution_grants)")
        }
        if "runner_key_id" not in columns:
            self.conn.execute(
                "UPDATE canary_execution_grants SET status='revoked' "
                "WHERE workspace_id=? AND runner_id=? "
                "AND status IN ('prepared','approved','issued')",
                (workspace_id, runner_id),
            )
            return

        parameters: list[object] = [workspace_id, runner_id]
        key_clause = ""
        if runner_key_id is not None:
            key_clause = " AND g.runner_key_id=?"
            parameters.append(runner_key_id)
        grants = self.conn.execute(
            "SELECT g.grant_id,g.run_id,g.reservation_id,g.project_ref,r.quota_state,"
            "r.cloud_event_sequence,r.purge_at "
            "FROM canary_execution_grants g JOIN canary_runs r "
            "ON r.workspace_id=g.workspace_id AND r.project_ref=g.project_ref "
            "AND r.run_id=g.run_id AND r.grant_id=g.grant_id "
            "WHERE g.workspace_id=? AND g.runner_id=? "
            "AND g.status IN ('prepared','approved','issued')" + key_clause,
            tuple(parameters),
        ).fetchall()
        now_ms = self._milliseconds(instant)
        for grant in grants:
            quota_refunded = False
            if grant["quota_state"] == "reserved":
                quota_refunded = ledger._settle_in_transaction(
                    grant["reservation_id"], "refund",
                )
            self.conn.execute(
                "UPDATE canary_execution_grants SET status='revoked' WHERE grant_id=?",
                (grant["grant_id"],),
            )
            self.conn.execute(
                "UPDATE canary_runs SET status='cancelled',quota_state=?,updated_at=? "
                "WHERE workspace_id=? AND project_ref=? AND run_id=?",
                (
                    "refunded" if quota_refunded or grant["quota_state"] == "refunded"
                    else grant["quota_state"],
                    now_ms, workspace_id, grant["project_ref"], grant["run_id"],
                ),
            )
            event_types = ["grant_revoked"]
            if quota_refunded:
                event_types.append("quota_refunded")
            event_types.append("cancelled")
            sequence = int(grant["cloud_event_sequence"])
            for event_type in event_types:
                status = "cancelled" if event_type == "cancelled" else "approved"
                payload = {
                    "schema_version": "heel.canary-run-event.v1",
                    "event_type": event_type,
                    "status": status,
                    "reason_code": reason_code,
                }
                self.conn.execute(
                    "INSERT INTO canary_run_events("
                    "event_id,workspace_id,project_ref,run_id,sequence,event_type,event_json,"
                    "payload_digest,source_event_sequence,actor_class,actor_id,reason_code,created_at) "
                    "VALUES(?,?,?,?,?,?,?,?,NULL,?,?,?,?)",
                    (
                        "cre_" + secrets.token_hex(16), workspace_id, grant["project_ref"],
                        grant["run_id"], sequence, event_type, canonical_bytes(payload).decode(),
                        canonical_digest(payload), "human", actor, reason_code, now_ms,
                    ),
                )
                action = event_type if event_type in {"cancelled", "quota_refunded"} else None
                if action is not None:
                    self.conn.execute(
                        "INSERT INTO canary_audit_records("
                        "audit_id,workspace_id,project_ref,run_id,subject_ref,action,actor_class,"
                        "actor_id,reason_code,payload_digest,created_at,purge_at) "
                        "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            "cra_" + secrets.token_hex(16), workspace_id, grant["project_ref"],
                            grant["run_id"], grant["grant_id"], action, "human", actor,
                            reason_code, canonical_digest(payload), now_ms, grant["purge_at"],
                        ),
                    )
                sequence += 1
            self.conn.execute(
                "UPDATE canary_runs SET cloud_event_sequence=? WHERE workspace_id=? "
                "AND project_ref=? AND run_id=?",
                (sequence, workspace_id, grant["project_ref"], grant["run_id"]),
            )

    def _stop_inflight_canary_runs_in_transaction(
        self, workspace_id: str, runner_id: str, *, actor: str, instant: float,
    ) -> None:
        columns = {row[1] for row in self.conn.execute("PRAGMA table_info(canary_runs)")}
        if "stop_deadline_ms" not in columns:
            return
        generation_row = self.conn.execute(
            "SELECT generation FROM canary_control_generation WHERE singleton=1"
        ).fetchone()
        generation = int(generation_row[0]) if generation_row is not None else 0
        now_ms = self._milliseconds(instant)
        runs = self.conn.execute(
            "SELECT * FROM canary_runs WHERE workspace_id=? AND runner_id=? "
            "AND status IN ('claimed','running','finalizing') AND stop_reason='none'",
            (workspace_id, runner_id),
        ).fetchall()
        for run in runs:
            next_status = "finalizing" if run["status"] == "finalizing" else "stop_requested"
            self.conn.execute(
                "UPDATE canary_runs SET status=?,stop_reason='runner_revoked',stop_generation=?,"
                "stop_requested_at_ms=?,stop_deadline_ms=?,updated_at=? "
                "WHERE workspace_id=? AND project_ref=? AND run_id=?",
                (
                    next_status, generation, now_ms, now_ms + 5000, now_ms,
                    workspace_id, run["project_ref"], run["run_id"],
                ),
            )
            payload = {
                "schema_version": "heel.canary-run-event.v1",
                "event_type": "stop_requested", "status": next_status,
                "reason_code": "runner_revoked",
            }
            self.conn.execute(
                "INSERT INTO canary_run_events("
                "event_id,workspace_id,project_ref,run_id,sequence,event_type,event_json,"
                "payload_digest,source_event_sequence,actor_class,actor_id,reason_code,created_at) "
                "VALUES(?,?,?,?,?,'stop_requested',?,?,NULL,'human',?,'runner_revoked',?)",
                (
                    "cre_" + secrets.token_hex(16), workspace_id, run["project_ref"],
                    run["run_id"], run["cloud_event_sequence"], canonical_bytes(payload).decode(),
                    canonical_digest(payload), actor, now_ms,
                ),
            )
            self.conn.execute(
                "UPDATE canary_runs SET cloud_event_sequence=cloud_event_sequence+1 "
                "WHERE workspace_id=? AND project_ref=? AND run_id=?",
                (workspace_id, run["project_ref"], run["run_id"]),
            )
            self.conn.execute(
                "INSERT INTO canary_audit_records("
                "audit_id,workspace_id,project_ref,run_id,subject_ref,action,actor_class,actor_id,"
                "reason_code,payload_digest,created_at,purge_at) VALUES(?,?,?,?,?,'stop_requested',"
                "'human',?,'runner_revoked',?,?,?)",
                (
                    "cra_" + secrets.token_hex(16), workspace_id, run["project_ref"],
                    run["run_id"], run["run_id"], actor, canonical_digest(payload), now_ms,
                    run["purge_at"],
                ),
            )

    def revoke(self, workspace_id: str, runner_id: str, *, actor: str, reason_code: str = "human_revocation") -> bool:
        """Human-authorized revocation preserves historical runs but ends every control chain."""
        self._identifier(actor, "actor")
        instant = self._now()
        from .ledger import UsageLedger
        ledger = UsageLedger(self.conn)
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            row = self.conn.execute("SELECT 1 FROM canary_runners WHERE workspace_id=? AND runner_id=? AND status='active'", (workspace_id, runner_id)).fetchone()
            if row is None:
                self.conn.rollback(); return False
            self._identifier(reason_code, "revocation reason")
            self._revoke_unused_canary_grants_in_transaction(
                workspace_id, runner_id, runner_key_id=None, actor=actor,
                reason_code=reason_code, instant=instant, ledger=ledger,
            )
            self._stop_inflight_canary_runs_in_transaction(
                workspace_id, runner_id, actor=actor, instant=instant,
            )
            self.conn.execute("UPDATE canary_runners SET status='revoked' WHERE workspace_id=? AND runner_id=?", (workspace_id, runner_id))
            self.conn.execute("UPDATE canary_runner_keys SET status='revoked', revoked_at=? WHERE workspace_id=? AND runner_id=? AND revoked_at IS NULL", (instant, workspace_id, runner_id))
            self.conn.execute("DELETE FROM canary_runner_nonce_chains WHERE workspace_id=? AND runner_id=?", (workspace_id, runner_id))
            self.conn.execute("UPDATE canary_runner_chain_cursors SET generation=generation+1,updated_at=? WHERE workspace_id=? AND runner_id=?", (instant, workspace_id, runner_id))
            self.conn.execute("UPDATE canary_runner_resync_challenges SET status='invalidated' WHERE workspace_id=? AND runner_id=? AND status='pending'", (workspace_id, runner_id))
            # A runner loss invalidates only work which has not been claimed; historical and
            # in-flight records remain evidence and are settled by Task 7's lifecycle service.
            identity = self._load_identity(workspace_id, runner_id)
            identity["state"] = "revoked"
            identity["revocation"] = {"revoked_at_ms": self._milliseconds(instant), "revoked_by": actor, "reason_code": reason_code}
            self._save_changed_identity(identity, instant=instant)
            self.conn.execute("INSERT INTO canary_runner_audit_records(audit_id,workspace_id,runner_id,action,actor,reason_code,created_at) VALUES(?,?,?,?,?,?,?)", ("runner_audit_" + secrets.token_hex(16), workspace_id, runner_id, "runner_revoked", actor, reason_code, instant))
            self.conn.commit()
        except Exception:
            if self.conn.in_transaction: self.conn.rollback()
            raise
        return True

    def start_rotation(self, workspace_id: str, runner_id: str, *, previous_fingerprint: str,
                       public_key_b64: str, phrase: str, runner_version: str, adapters: Mapping[str, str]) -> PairingView:
        """Begin a fresh visible-key rotation; old control remains active until new-key PoP."""
        phrase = self._phrase(phrase)
        self._identifier(runner_version, "runner version")
        if not isinstance(adapters, Mapping) or not all(type(k) is str and type(v) is str for k, v in adapters.items()):
            raise ValueError("invalid runner adapters")
        try:
            key = load_public_key_base64(public_key_b64)
        except ValueError as error:
            raise ValueError("invalid runner public key") from error
        raw = key.public_bytes(Encoding.Raw, PublicFormat.Raw)
        key_id, fingerprint, instant = ed25519_key_id(raw), hashlib.sha256(raw).hexdigest(), self._now()
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            # The partial unique index is the race authority; this fast
            # exact lookup preserves the closed 409 surface after a prior
            # starter has already moved the signed identity to rotating.
            if self.conn.execute(
                "SELECT 1 FROM canary_runner_rotations INDEXED BY idx_canary_runner_one_open_rotation "
                "WHERE workspace_id=? AND runner_id=? "
                "AND status IN ('rotation_pending','rotation_approved') LIMIT 1",
                (workspace_id, runner_id),
            ).fetchone() is not None:
                raise RunnerRotationInProgress("runner rotation in progress")
            old = self._single_active_key_locked(workspace_id, runner_id)
            old_raw = load_public_key_base64(old["public_key"]).public_bytes(Encoding.Raw, PublicFormat.Raw)
            old_fingerprint = hashlib.sha256(old_raw).hexdigest()
            identity = self._load_identity(workspace_id, runner_id)
            if (
                not _lower_hex_digest(previous_fingerprint)
                or not hmac.compare_digest(old_fingerprint, previous_fingerprint)
                or identity.get("state") != "active"
                or identity.get("fingerprint") != old_fingerprint
                or not isinstance(identity.get("public_key"), dict)
                or identity["public_key"].get("key_id") != old["key_id"]
                or identity["public_key"].get("public_key_b64") != old["public_key"]
            ):
                raise RunnerAuthError("invalid rotation")
            if self.conn.execute(
                "SELECT 1 FROM canary_runner_keys WHERE workspace_id=? AND runner_id=? "
                "AND (key_id=? OR public_key=?) LIMIT 1",
                (workspace_id, runner_id, key_id, public_key_b64),
            ).fetchone() is not None:
                raise RunnerAuthError("invalid rotation")
            active = self.conn.execute(
                "SELECT 1 FROM canary_runs WHERE workspace_id=? AND runner_id=? "
                "AND status IN ('claimed','running','stop_requested','finalizing') LIMIT 1",
                (workspace_id, runner_id),
            ).fetchone()
            if active is not None:
                raise RunnerAuthError("active canary run blocks rotation")
            pairing_id, challenge = "rotation_" + secrets.token_hex(16), _token()
            try:
                self.conn.execute(
                    "INSERT INTO canary_runner_rotations("
                    "pairing_id,workspace_id,runner_id,phrase,public_key,fingerprint,key_id,runner_version,"
                    "adapters_json,activation_challenge,status,created_at,expires_at,old_key_id,old_fingerprint"
                    ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        pairing_id, workspace_id, runner_id, phrase, public_key_b64, fingerprint,
                        key_id, runner_version, canonical_bytes(dict(adapters)).decode(), challenge,
                        "rotation_pending", instant, instant + PAIRING_TTL, old["key_id"], old_fingerprint,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise RunnerRotationInProgress("runner rotation in progress") from error
            identity["state"] = "rotating"
            self._save_changed_identity(identity, instant=instant)
            self.conn.commit()
        except Exception:
            self.conn.rollback(); raise
        return PairingView(pairing_id, runner_id, phrase, fingerprint, "rotation_pending", instant + PAIRING_TTL)

    def approve_rotation(self, workspace_id: str, pairing_id: str, *, phrase: str, fingerprint: str, actor: str) -> None:
        phrase, instant = self._phrase(phrase), self._now()
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            row = self.conn.execute("SELECT * FROM canary_runner_rotations WHERE workspace_id=? AND pairing_id=?", (workspace_id, pairing_id)).fetchone()
            if row is None or row["status"] != "rotation_pending" or row["expires_at"] <= instant or not hmac.compare_digest(row["phrase"], phrase) or not hmac.compare_digest(row["fingerprint"], fingerprint):
                raise RunnerAuthError("invalid rotation")
            self._bound_rotation_old_key_locked(row)
            self.conn.execute("UPDATE canary_runner_rotations SET status='rotation_approved',approved_at=?,approved_by=? WHERE pairing_id=?", (instant, actor, pairing_id))
            self.conn.commit()
        except Exception:
            self.conn.rollback(); raise

    def rotation_activation_challenge(self, pairing_id: str) -> str:
        self.conn.execute("BEGIN")
        try:
            row = self.conn.execute("SELECT * FROM canary_runner_rotations WHERE pairing_id=?", (pairing_id,)).fetchone()
            if row is None or row["status"] != "rotation_approved" or row["expires_at"] <= self._now() or not row["activation_challenge"]:
                raise RunnerAuthError("invalid rotation")
            self._bound_rotation_old_key_locked(row)
            self.conn.commit()
            return row["activation_challenge"]
        except Exception:
            if self.conn.in_transaction:
                self.conn.rollback()
            raise

    @staticmethod
    def _rotation_activation_request_digest(pairing_id: str, signature_b64: str) -> str:
        if type(pairing_id) is not str or not pairing_id or type(signature_b64) is not str:
            raise ValueError("invalid rotation")
        request = {
            "schema_version": "heel.runner-rotation-activate.v2",
            "signature_b64": signature_b64,
        }
        path = f"/v1/runner-rotations/{pairing_id}/activate".encode("utf-8")
        return hashlib.sha256(b"POST\0" + path + b"\0" + canonical_bytes(request)).hexdigest()

    @staticmethod
    def _validated_rotation_activation_response(value: object, row: sqlite3.Row) -> dict:
        fields = {
            "schema_version", "workspace_id", "runner_id", "initial_claim_nonce",
            "initial_claim_sequence", "initial_claim_generation",
        }
        if not isinstance(value, dict) or set(value) != fields:
            raise RunnerAuthError("invalid rotation")
        if (
            value["schema_version"] != "heel.runner-rotation-activated.v2"
            or value["workspace_id"] != row["workspace_id"]
            or value["runner_id"] != row["runner_id"]
            or type(value["initial_claim_sequence"]) is not int
            or value["initial_claim_sequence"] < 1
            or type(value["initial_claim_generation"]) is not int
            or not 0 <= value["initial_claim_generation"] <= _SAFE_JSON_INT
        ):
            raise RunnerAuthError("invalid rotation")
        RunnerAuthStore._activation_nonce(value["initial_claim_nonce"])
        return value

    def _rotation_activation_busy_locked(self, *, workspace_id: str, runner_id: str, old_key_id: str) -> bool:
        """Reject activation when the old key acquired executable authority mid-ceremony."""
        tables = {
            item[0] for item in self.conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name IN "
                "('canary_runs','canary_execution_grants','canary_approval_projections',"
                "'canary_runner_context_bindings')",
            ).fetchall()
        }
        if "canary_runs" in tables and self.conn.execute(
            "SELECT 1 FROM canary_runs WHERE workspace_id=? AND runner_id=? "
            "AND status IN ('claimed','running','stop_requested','finalizing') LIMIT 1",
            (workspace_id, runner_id),
        ).fetchone() is not None:
            return True
        if "canary_execution_grants" in tables and self.conn.execute(
            "SELECT 1 FROM canary_execution_grants WHERE workspace_id=? AND runner_id=? "
            "AND runner_key_id=? AND status='claimed' LIMIT 1",
            (workspace_id, runner_id, old_key_id),
        ).fetchone() is not None:
            return True
        if "canary_approval_projections" in tables and self.conn.execute(
            "SELECT 1 FROM canary_approval_projections WHERE workspace_id=? AND runner_id=? "
            "AND runner_key_id=? AND status='awaiting_execution_approval' LIMIT 1",
            (workspace_id, runner_id, old_key_id),
        ).fetchone() is not None:
            return True
        if "canary_runner_context_bindings" in tables and self.conn.execute(
            "SELECT 1 FROM canary_runner_context_bindings WHERE workspace_id=? AND runner_id=? "
            "AND runner_key_id=? AND status='active' LIMIT 1",
            (workspace_id, runner_id, old_key_id),
        ).fetchone() is not None:
            return True
        return False

    def activate_rotation(self, pairing_id: str, signature_b64: str, *, overlap_seconds: int = 300) -> tuple[str, str, str, int, int]:
        if not isinstance(overlap_seconds, int) or not 1 <= overlap_seconds <= 3600:
            raise ValueError("invalid key overlap")
        request_digest = self._rotation_activation_request_digest(pairing_id, signature_b64)
        instant = self._now()
        from .ledger import UsageLedger
        ledger = UsageLedger(self.conn)
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            row = self.conn.execute("SELECT * FROM canary_runner_rotations WHERE pairing_id=?", (pairing_id,)).fetchone()
            if row is None:
                raise RunnerAuthError("invalid rotation")
            if row["status"] == "rotated":
                receipt = self.conn.execute(
                    "SELECT request_digest,response_ciphertext,expires_at FROM canary_runner_rotation_activation_receipts "
                    "WHERE pairing_id=?",
                    (pairing_id,),
                ).fetchone()
                if receipt is None or not hmac.compare_digest(receipt["request_digest"], request_digest):
                    raise RunnerAuthError("invalid rotation")
                if receipt["expires_at"] <= instant:
                    raise RunnerActivationReceiptExpired("runner activation receipt expired")
                try:
                    response = self._validated_rotation_activation_response(
                        json_load(self._open(
                            receipt["response_ciphertext"],
                            aad=f"rotation-v2-activation\0{pairing_id}".encode(),
                        )),
                        row,
                    )
                except (TypeError, ValueError, RunnerAuthError):
                    raise RunnerAuthError("invalid rotation") from None
                self.conn.commit()
                return (
                    response["workspace_id"], response["runner_id"], response["initial_claim_nonce"],
                    response["initial_claim_sequence"], response["initial_claim_generation"],
                )
            if row["status"] != "rotation_approved" or row["expires_at"] <= instant:
                raise RunnerAuthError("invalid rotation")
            try:
                signature = base64.b64decode(signature_b64, validate=True)
                if len(signature) != 64 or _b64(signature) != signature_b64: raise ValueError
                load_public_key_base64(row["public_key"]).verify(signature, b"heel.runner-rotation-activate.v2\0" + canonical_bytes({"pairing_id": pairing_id, "challenge": row["activation_challenge"]}))
            except (ValueError, InvalidSignature):
                raise RunnerAuthError("invalid rotation") from None
            old_key = self._bound_rotation_old_key_locked(row)
            if self._rotation_activation_busy_locked(
                workspace_id=row["workspace_id"], runner_id=row["runner_id"],
                old_key_id=old_key["key_id"],
            ):
                raise RunnerRotationBusy("runner rotation busy")
            self._revoke_unused_canary_grants_in_transaction(
                row["workspace_id"], row["runner_id"], runner_key_id=old_key["key_id"],
                actor=row["approved_by"], reason_code="runner_key_rotated", instant=instant,
                ledger=ledger,
            )
            changed = self.conn.execute(
                "UPDATE canary_runner_keys SET status='verification_only',revoked_at=? "
                "WHERE workspace_id=? AND runner_id=? AND key_id=? AND status='active' AND revoked_at IS NULL",
                (instant + overlap_seconds, row["workspace_id"], row["runner_id"], old_key["key_id"]),
            )
            if changed.rowcount != 1:
                raise RunnerAuthError("invalid rotation")
            self.conn.execute("INSERT INTO canary_runner_keys(key_id,workspace_id,runner_id,public_key,status,created_at,revoked_at) VALUES(?,?,?,?,?,?,NULL)", (row["key_id"], row["workspace_id"], row["runner_id"], row["public_key"], "active", instant))
            self.conn.execute("DELETE FROM canary_runner_nonce_chains WHERE workspace_id=? AND runner_id=?", (row["workspace_id"], row["runner_id"]))
            self.conn.execute("UPDATE canary_runner_chain_cursors SET generation=generation+1,updated_at=? WHERE workspace_id=? AND runner_id=?", (instant, row["workspace_id"], row["runner_id"]))
            self.conn.execute("UPDATE canary_runner_resync_challenges SET status='invalidated' WHERE workspace_id=? AND runner_id=? AND status='pending'", (row["workspace_id"], row["runner_id"]))
            nonce = _token()
            claim_cursor = self.conn.execute("SELECT next_sequence,generation FROM canary_runner_chain_cursors WHERE workspace_id=? AND runner_id=? AND chain_name='claim'", (row["workspace_id"], row["runner_id"])).fetchone()
            if claim_cursor is None:
                raise RunnerAuthError("invalid rotation")
            self.conn.execute("INSERT INTO canary_runner_nonce_chains VALUES(?,?,?,?,?,?)", (row["workspace_id"], row["runner_id"], "claim", self._hash("nonce", nonce), claim_cursor["next_sequence"], instant + NONCE_TTL))
            identity = self._load_identity(row["workspace_id"], row["runner_id"])
            # The identity is a signed current summary, not the complete key
            # archive.  Select the durable history after promoting the new
            # key, retain the 20 newest IDs, then lexically sort the summary
            # required by the public identity contract.
            previous_rows = self.conn.execute(
                "SELECT key_id FROM canary_runner_keys WHERE workspace_id=? AND runner_id=? "
                "AND key_id<>? ORDER BY created_at DESC,key_id ASC LIMIT 21",
                (row["workspace_id"], row["runner_id"], row["key_id"]),
            ).fetchall()
            previous = sorted(item["key_id"] for item in previous_rows[:20])
            history_advanced = len(previous_rows) > 20
            identity["public_key"] = {"algorithm": "Ed25519", "key_id": row["key_id"], "public_key_b64": row["public_key"]}
            identity["fingerprint"] = row["fingerprint"]
            identity["runner_version"] = row["runner_version"]
            identity["adapter_versions"] = sorted(set(json.loads(row["adapters_json"]).values()))
            identity["state"] = "active"
            identity["rotation"] = {"previous_key_ids": previous, "rotated_at_ms": self._milliseconds(instant), "verification_overlap_ends_at_ms": self._milliseconds(instant + overlap_seconds)}
            self._save_changed_identity(identity, instant=instant)
            self.conn.execute("INSERT INTO canary_runner_audit_records(audit_id,workspace_id,runner_id,action,actor,reason_code,created_at) VALUES(?,?,?,?,?,?,?)", ("runner_audit_" + secrets.token_hex(16), row["workspace_id"], row["runner_id"], "runner_rotated", row["approved_by"], "previous_key_history_window_advanced" if history_advanced else None, instant))
            response = {
                "schema_version": "heel.runner-rotation-activated.v2",
                "workspace_id": row["workspace_id"], "runner_id": row["runner_id"],
                "initial_claim_nonce": nonce, "initial_claim_sequence": claim_cursor["next_sequence"],
                "initial_claim_generation": claim_cursor["generation"],
            }
            self._validated_rotation_activation_response(response, row)
            receipt_expiry = instant + 2_592_000.0
            self.conn.execute(
                "INSERT INTO canary_runner_rotation_activation_receipts(pairing_id,request_digest,response_ciphertext,created_at,expires_at) VALUES(?,?,?,?,?)",
                (
                    pairing_id, request_digest,
                    self._seal(canonical_bytes(response).decode(), aad=f"rotation-v2-activation\0{pairing_id}".encode()),
                    instant, receipt_expiry,
                ),
            )
            self.conn.execute(
                "UPDATE canary_runner_rotations SET status='rotated',activation_challenge=NULL,activated_at=?,expires_at=? WHERE pairing_id=?",
                (instant, receipt_expiry, pairing_id),
            )
            self.conn.commit()
        except Exception:
            self.conn.rollback(); raise
        return row["workspace_id"], row["runner_id"], nonce, claim_cursor["next_sequence"], claim_cursor["generation"]

    @staticmethod
    def _resync_chain(value: object) -> tuple[str, str | None, str]:
        if not isinstance(value, dict) or set(value) != {"operation", "run_id"}:
            raise RunnerAuthError("invalid runner authentication")
        operation, run_id = value.get("operation"), value.get("run_id")
        if operation == "claim" and run_id is None:
            return operation, run_id, "claim"
        if operation in {"heartbeat", "progress", "result", "stop-ack"} and type(run_id) is str and run_id:
            return operation, run_id, f"{operation}:{run_id}"
        raise RunnerAuthError("invalid runner authentication")

    @staticmethod
    def _b64_32(value: object) -> str:
        if type(value) is not str:
            raise RunnerAuthError("invalid runner authentication")
        try:
            decoded = base64.b64decode(value, validate=True)
        except (ValueError, TypeError):
            raise RunnerAuthError("invalid runner authentication") from None
        if len(decoded) != 32 or _b64(decoded) != value:
            raise RunnerAuthError("invalid runner authentication")
        return value

    def _resync_proof(self, *, workspace_id: str, runner_id: str, path: str, raw_body: bytes,
                      headers: Mapping[str, list[str]], proof_schema: str, domain: bytes,
                      allow_stale: bool = False) -> tuple[sqlite3.Row, str, int]:
        required = ("X-Heel-Runner-Id", "X-Heel-Runner-Key-Id", "X-Heel-Runner-Timestamp-Ms", "X-Heel-Runner-Signature")
        if any(len(headers.get(name, ())) != 1 for name in required):
            raise RunnerAuthError("invalid runner authentication")
        if headers.get("Authorization") or headers.get("Cookie") or headers.get("X-Heel-Runner-Nonce") or headers.get("X-Heel-Runner-Sequence"):
            raise RunnerAuthError("invalid runner authentication")
        values = {name: headers[name][0] for name in required}
        if values["X-Heel-Runner-Id"] != runner_id:
            raise RunnerAuthError("invalid runner authentication")
        timestamp = values["X-Heel-Runner-Timestamp-Ms"]
        if not timestamp.isascii() or not timestamp.isdecimal() or (len(timestamp) > 1 and timestamp.startswith("0")):
            raise RunnerAuthError("invalid runner authentication")
        timestamp_ms = int(timestamp)
        row = self.conn.execute("SELECT * FROM canary_runner_keys WHERE workspace_id=? AND runner_id=? AND key_id=? AND status='active' AND revoked_at IS NULL", (workspace_id, runner_id, values["X-Heel-Runner-Key-Id"])).fetchone()
        if row is None:
            raise RunnerAuthError("invalid runner authentication")
        proof = {"schema_version": proof_schema, "workspace_id": workspace_id, "runner_id": runner_id,
                 "key_id": values["X-Heel-Runner-Key-Id"], "method": "POST", "path": path,
                 "body_sha256": hashlib.sha256(raw_body).hexdigest(), "timestamp_ms": timestamp_ms}
        proof_bytes = domain + canonical_bytes(proof)
        try:
            signature = base64.b64decode(values["X-Heel-Runner-Signature"], validate=True)
            if len(signature) != 64 or _b64(signature) != values["X-Heel-Runner-Signature"]:
                raise ValueError
            load_public_key_base64(row["public_key"]).verify(signature, proof_bytes)
        except (ValueError, InvalidSignature):
            raise RunnerAuthError("invalid runner authentication") from None
        if not allow_stale and abs(self._milliseconds(self._now()) - timestamp_ms) > CLOCK_SKEW_MS:
            raise RunnerAuthError("invalid runner authentication")
        return row, hashlib.sha256(proof_bytes + signature).hexdigest(), timestamp_ms

    def start_resync(self, *, workspace_id: str, runner_id: str, path: str, raw_body: bytes,
                     headers: Mapping[str, list[str]]) -> dict:
        try:
            body = parse_json(raw_body, max_bytes=2048)
            if canonical_bytes(body) != raw_body or set(body) != {"schema_version", "chain", "client_nonce_b64"} or body["schema_version"] != "heel.runner-resync-start.v2":
                raise RunnerAuthError("invalid runner authentication")
            operation, run_id, chain = self._resync_chain(body["chain"])
            client_nonce = self._b64_32(body["client_nonce_b64"])
            self.conn.execute("BEGIN IMMEDIATE")
            self._require_executable_protocol_in_transaction(workspace_id, runner_id)
            _, signed_digest, timestamp_ms = self._resync_proof(workspace_id=workspace_id, runner_id=runner_id, path=path, raw_body=raw_body, headers=headers, proof_schema="heel.runner-resync-start-proof.v2", domain=b"heel.runner-resync-start-pop.v2\0", allow_stale=True)
            instant = self._now()
            cursor = self.conn.execute("SELECT * FROM canary_runner_chain_cursors WHERE workspace_id=? AND runner_id=? AND chain_name=?", (workspace_id, runner_id, chain)).fetchone()
            if cursor is None:
                raise RunnerAuthError("invalid runner authentication")
            nonce_hash = self._hash("resync-client", client_nonce)
            existing = self.conn.execute("SELECT * FROM canary_runner_resync_challenges WHERE workspace_id=? AND runner_id=? AND chain_name=? AND status='pending' ORDER BY created_at DESC LIMIT 1", (workspace_id, runner_id, chain)).fetchone()
            if existing is not None:
                if existing["expires_at"] > instant and existing["challenge_generation"] == cursor["generation"] and (hmac.compare_digest(existing["client_nonce_hash"], nonce_hash) and hmac.compare_digest(existing["signed_digest"], signed_digest)):
                    aad = f"resync\0{existing['challenge_id']}".encode()
                    server = self._open(existing["server_challenge_ciphertext"], aad=aad)
                    self.conn.commit()
                    return {"schema_version": "heel.runner-resync-challenge.v2", "challenge_id": existing["challenge_id"], "chain": {"operation": operation, "run_id": run_id}, "server_challenge_b64": server, "next_sequence": cursor["next_sequence"], "expires_at_ms": self._milliseconds(existing["expires_at"]), "generation": cursor["generation"]}
                if existing["status"] == "pending" and existing["expires_at"] > instant:
                    raise RunnerAuthError("invalid runner authentication")
                self.conn.execute("UPDATE canary_runner_resync_challenges SET status='invalidated' WHERE challenge_id=?", (existing["challenge_id"],))
            if abs(self._milliseconds(instant) - timestamp_ms) > CLOCK_SKEW_MS:
                raise RunnerAuthError("invalid runner authentication")
            attempts = self.conn.execute("SELECT COUNT(*) FROM canary_runner_resync_challenges WHERE workspace_id=? AND runner_id=? AND created_at>=?", (workspace_id, runner_id, instant - 60)).fetchone()[0]
            if attempts >= 3:
                raise RunnerAuthRateLimited("runner recovery rate limited")
            challenge_id, server = "rrs_" + secrets.token_hex(16), _token()
            aad = f"resync\0{challenge_id}".encode()
            expires = instant + 60
            self.conn.execute("INSERT INTO canary_runner_resync_challenges(challenge_id,workspace_id,runner_id,chain_name,client_nonce_hash,server_challenge_hash,signed_digest,client_nonce_ciphertext,server_challenge_ciphertext,challenge_generation,result_generation,status,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (challenge_id, workspace_id, runner_id, chain, nonce_hash, self._hash("resync-server", server), signed_digest, self._seal(client_nonce, aad=aad), self._seal(server, aad=aad), cursor["generation"], None, "pending", instant, expires))
            self.conn.commit()
            return {"schema_version": "heel.runner-resync-challenge.v2", "challenge_id": challenge_id, "chain": {"operation": operation, "run_id": run_id}, "server_challenge_b64": server, "next_sequence": cursor["next_sequence"], "expires_at_ms": self._milliseconds(expires), "generation": cursor["generation"]}
        except Exception:
            if self.conn.in_transaction:
                self.conn.rollback()
            raise

    def complete_resync(self, *, workspace_id: str, runner_id: str, path: str, raw_body: bytes,
                        headers: Mapping[str, list[str]]) -> dict:
        try:
            body = parse_json(raw_body, max_bytes=2048)
            if canonical_bytes(body) != raw_body or set(body) != {"schema_version", "challenge_id", "chain", "client_nonce_b64", "server_challenge_b64", "generation"} or body["schema_version"] != "heel.runner-resync-complete.v2" or type(body["generation"]) is not int or body["generation"] < 0:
                raise RunnerAuthError("invalid runner authentication")
            challenge_id = body["challenge_id"]
            if type(challenge_id) is not str or len(challenge_id) != 36 or not challenge_id.startswith("rrs_") or any(c not in "0123456789abcdef" for c in challenge_id[4:]):
                raise RunnerAuthError("invalid runner authentication")
            operation, run_id, chain = self._resync_chain(body["chain"])
            client_nonce, server_challenge = self._b64_32(body["client_nonce_b64"]), self._b64_32(body["server_challenge_b64"])
            self.conn.execute("BEGIN IMMEDIATE")
            self._require_executable_protocol_in_transaction(workspace_id, runner_id)
            challenge = self.conn.execute("SELECT * FROM canary_runner_resync_challenges WHERE challenge_id=? AND workspace_id=? AND runner_id=?", (challenge_id, workspace_id, runner_id)).fetchone()
            if challenge is None or challenge["chain_name"] != chain or challenge["challenge_generation"] != body["generation"] or not hmac.compare_digest(challenge["client_nonce_hash"], self._hash("resync-client", client_nonce)) or not hmac.compare_digest(challenge["server_challenge_hash"], self._hash("resync-server", server_challenge)):
                raise RunnerAuthError("invalid runner authentication")
            _, signed_digest, _ = self._resync_proof(workspace_id=workspace_id, runner_id=runner_id, path=path, raw_body=raw_body, headers=headers, proof_schema="heel.runner-resync-complete-proof.v2", domain=b"heel.runner-resync-complete-pop.v2\0", allow_stale=challenge["status"] == "completed")
            instant = self._now()
            cursor = self.conn.execute("SELECT * FROM canary_runner_chain_cursors WHERE workspace_id=? AND runner_id=? AND chain_name=?", (workspace_id, runner_id, chain)).fetchone()
            if challenge["status"] == "completed":
                if not hmac.compare_digest(challenge["complete_signed_digest"] or "", signed_digest):
                    raise RunnerAuthError("invalid runner authentication")
                if challenge["completed_at"] is None or challenge["completed_at"] + 600 <= instant or cursor is None or cursor["generation"] != challenge["result_generation"]:
                    raise RunnerAuthError("invalid runner authentication")
                aad = f"resync-completed\0{challenge_id}".encode()
                response = json_load(self._open(challenge["completed_response_ciphertext"], aad=aad))
                self.conn.commit()
                return response
            if challenge["status"] != "pending" or challenge["expires_at"] <= instant:
                raise RunnerAuthError("invalid runner authentication")
            if cursor is None or cursor["generation"] != challenge["challenge_generation"]:
                raise RunnerAuthError("invalid runner authentication")
            next_nonce, expires = _token(), instant + NONCE_TTL
            self.conn.execute("INSERT OR REPLACE INTO canary_runner_nonce_chains VALUES(?,?,?,?,?,?)", (workspace_id, runner_id, chain, self._hash("nonce", next_nonce), cursor["next_sequence"], expires))
            changed = self.conn.execute("UPDATE canary_runner_chain_cursors SET generation=generation+1,updated_at=? WHERE workspace_id=? AND runner_id=? AND chain_name=? AND generation=?", (instant, workspace_id, runner_id, chain, cursor["generation"]))
            if changed.rowcount != 1:
                raise RunnerAuthError("invalid runner authentication")
            result_generation = cursor["generation"] + 1
            response = {"schema_version": "heel.runner-resync-completed.v2", "chain": {"operation": operation, "run_id": run_id}, "next_sequence": cursor["next_sequence"], "next_nonce_b64": next_nonce, "expires_at_ms": self._milliseconds(expires), "generation": result_generation}
            aad = f"resync-completed\0{challenge_id}".encode()
            completed = self.conn.execute("UPDATE canary_runner_resync_challenges SET status='completed',result_generation=?,completed_at=?,completed_response_ciphertext=?,complete_signed_digest=? WHERE challenge_id=? AND status='pending' AND challenge_generation=?", (result_generation, instant, self._seal(canonical_bytes(response).decode(), aad=aad), signed_digest, challenge_id, cursor["generation"]))
            if completed.rowcount != 1:
                raise RunnerAuthError("invalid runner authentication")
            self.conn.commit()
            return response
        except Exception:
            if self.conn.in_transaction:
                self.conn.rollback()
            raise

    @staticmethod
    def _receipt_aad(
        workspace_id: str, runner_id: str, chain: str, sequence: int, generation: int,
    ) -> bytes:
        return (
            b"heel.runner-http-receipt.v1\0" + workspace_id.encode("utf-8") + b"\0"
            + runner_id.encode("utf-8") + b"\0" + chain.encode("utf-8") + b"\0"
            + str(sequence).encode("ascii") + b"\0" + str(generation).encode("ascii")
        )

    def _open_exact_receipt(
        self, row: sqlite3.Row, *, workspace_id: str, runner_id: str, chain: str,
        sequence: int, generation: int,
    ) -> tuple[int, dict | None, str]:
        try:
            status = int(row["response_status"])
            if status == 0:
                # Migration-25's only legacy form retains the previous encryption and derives
                # its closed status from the frozen old routes without rewriting the row.
                legacy_aad = f"{workspace_id}\0{runner_id}\0{chain}\0{sequence}".encode()
                body = json_load(self._open(row["response_ciphertext"], aad=legacy_aad))
                status = 204 if body.get("schema_version") == "heel.runner-claim-idle.internal.v1" else (
                    201 if row["path"].endswith("/approval-projections") else 200
                )
                if status == 204:
                    body = None
                nonce = self._open(row["next_nonce_ciphertext"], aad=legacy_aad)
                return status, body, nonce
            if status not in {200, 201, 204}:
                raise ValueError
            aad = self._receipt_aad(workspace_id, runner_id, chain, sequence, generation)
            envelope = json_load(self._open(row["response_ciphertext"], aad=aad))
            if set(envelope) != {"schema_version", "status", "body"} or (
                envelope["schema_version"] != "heel.runner-http-receipt.v1"
                or envelope["status"] != status
                or (status == 204) != (envelope["body"] is None)
                or (status != 204 and not isinstance(envelope["body"], dict))
            ):
                raise ValueError
            wire = b"" if status == 204 else self.response_wire_body(envelope["body"])
            if row["response_body_digest"] != hashlib.sha256(wire).hexdigest():
                raise ValueError
            nonce = self._open(row["next_nonce_ciphertext"], aad=aad)
            if not isinstance(nonce, str) or not nonce:
                raise ValueError
            return status, envelope["body"], nonce
        except (KeyError, TypeError, ValueError, RunnerAuthError):
            raise RunnerAuthError("invalid runner authentication") from None

    @staticmethod
    def response_wire_body(body: dict) -> bytes:
        """Return the sole JSON serialization permitted for a runner receipt body.

        Receipt replay is required to preserve the original HTTP bytes.  The normal
        handler therefore writes this same compact, validated representation rather
        than passing the mapping through its generic JSON response helper.
        """
        return _sealed_response_json(body).encode("utf-8")

    def authenticate_and_consume(self, *, workspace_id: str, runner_id: str, capability: str, path: str,
                                 raw_body: bytes, headers: Mapping[str, list[str]],
                                 action: Callable[[], RunnerHttpAction], chain_name: str | None = None,
                                 max_body_bytes: int = MAX_RUNNER_BODY) -> tuple[int, dict | None, str]:
        """Verify a fixed request then atomically record its exact HTTP receipt."""
        if (
            isinstance(max_body_bytes, bool)
            or not isinstance(max_body_bytes, int)
            or not 1 <= max_body_bytes <= MAX_RUNNER_UPLOAD_BODY
        ):
            raise ValueError("invalid runner request body limit")
        required = ("X-Heel-Runner-Id", "X-Heel-Runner-Key-Id", "X-Heel-Runner-Timestamp-Ms", "X-Heel-Runner-Nonce", "X-Heel-Runner-Sequence", "X-Heel-Runner-Signature")
        try:
            if capability not in RUNNER_CAPABILITIES or any(len(headers.get(name, ())) != 1 for name in required):
                raise RunnerAuthError("invalid runner authentication")
            if headers.get("Authorization") or headers.get("Cookie"):
                raise RunnerAuthError("invalid runner authentication")
            values = {name: headers[name][0] for name in required}
            if values["X-Heel-Runner-Id"] != runner_id or not values["X-Heel-Runner-Nonce"] or not values["X-Heel-Runner-Key-Id"]:
                raise RunnerAuthError("invalid runner authentication")
            timestamp, sequence = values["X-Heel-Runner-Timestamp-Ms"], values["X-Heel-Runner-Sequence"]
            if not timestamp.isascii() or not sequence.isascii() or not timestamp.isdecimal() or not sequence.isdecimal() or (len(timestamp) > 1 and timestamp.startswith("0")) or (len(sequence) > 1 and sequence.startswith("0")):
                raise RunnerAuthError("invalid runner authentication")
            timestamp, sequence = int(timestamp), int(sequence)
            if sequence < 1:
                raise RunnerAuthError("invalid runner authentication")
            parsed = parse_json(raw_body, max_bytes=max_body_bytes)
            if canonical_bytes(parsed) != raw_body:
                raise RunnerAuthError("invalid runner authentication")
            body_digest = hashlib.sha256(raw_body).hexdigest()
            self.conn.execute("BEGIN IMMEDIATE")
            self._require_executable_protocol_in_transaction(workspace_id, runner_id)
            row = self.conn.execute("SELECT * FROM canary_runner_keys WHERE workspace_id=? AND runner_id=? AND key_id=? AND status='active' AND revoked_at IS NULL", (workspace_id, runner_id, values["X-Heel-Runner-Key-Id"])).fetchone()
            if row is None:
                raise RunnerAuthError("invalid runner authentication")
            chain = chain_name or ("claim" if capability == "runner_claim" else f"{capability.removeprefix('runner_')}:{parsed.get('run_id', '')}")
            proof = {"schema_version":"heel.runner-request-proof.v1", "workspace_id":workspace_id, "runner_id":runner_id, "key_id":values["X-Heel-Runner-Key-Id"], "capability":capability, "method":"POST", "path":path, "body_sha256":body_digest, "timestamp_ms":timestamp, "server_nonce":values["X-Heel-Runner-Nonce"], "sequence":sequence}
            proof_bytes = b"heel.runner-pop.v1\0" + canonical_bytes(proof)
            try:
                signature = base64.b64decode(values["X-Heel-Runner-Signature"], validate=True)
                if len(signature) != 64 or _b64(signature) != values["X-Heel-Runner-Signature"]:
                    raise ValueError
                load_public_key_base64(row["public_key"]).verify(signature, proof_bytes)
            except (ValueError, InvalidSignature):
                raise RunnerAuthError("invalid runner authentication") from None
            signed_digest = hashlib.sha256(proof_bytes + signature).hexdigest()
            nonce_hash = self._hash("nonce", values["X-Heel-Runner-Nonce"])
            cursor = self.conn.execute("SELECT * FROM canary_runner_chain_cursors WHERE workspace_id=? AND runner_id=? AND chain_name=?", (workspace_id, runner_id, chain)).fetchone()
            if cursor is None:
                raise RunnerAuthError("invalid runner authentication")
            generation = cursor["generation"]
            # Exact receipt lookup intentionally precedes timestamp freshness and cursor state:
            # a restart must replay its original signed bytes after ordinary clock skew expires.
            prior = self.conn.execute(
                "SELECT * FROM canary_runner_request_ledger WHERE workspace_id=? AND runner_id=? "
                "AND chain_name=? AND sequence=? AND generation=?",
                (workspace_id, runner_id, chain, sequence, generation),
            ).fetchone()
            if prior is not None:
                if not all((
                    hmac.compare_digest(prior["signed_request_digest"] or "", signed_digest),
                    hmac.compare_digest(prior["nonce_hash"] or "", nonce_hash),
                    hmac.compare_digest(prior["key_id"] or "", values["X-Heel-Runner-Key-Id"]),
                    hmac.compare_digest(prior["capability"] or "", capability),
                    prior["method"] == "POST", prior["path"] == path,
                    prior["timestamp_ms"] == timestamp,
                    hmac.compare_digest(prior["body_digest"] or "", body_digest),
                )):
                    raise RunnerAuthError("invalid runner authentication")
                # The exact sealed receipt is replay authority only through
                # its retained horizon.  Physical reclamation belongs to the
                # bounded reaper; request handling never deletes it.
                if prior["retention_expires_at"] <= self._now():
                    raise RunnerAuthError("runner replay receipt expired")
                result = self._open_exact_receipt(
                    prior, workspace_id=workspace_id, runner_id=runner_id, chain=chain,
                    sequence=sequence, generation=generation,
                )
                self.conn.rollback()
                return result
            if abs(int(self._now() * 1000) - timestamp) > CLOCK_SKEW_MS:
                raise RunnerAuthError("invalid runner authentication")
            state = self.conn.execute("SELECT * FROM canary_runner_nonce_chains WHERE workspace_id=? AND runner_id=? AND chain_name=?", (workspace_id, runner_id, chain)).fetchone()
            if state is None or state["expires_at"] <= self._now() or sequence != state["next_sequence"] or sequence != cursor["next_sequence"] or not hmac.compare_digest(state["nonce_hash"], nonce_hash):
                raise RunnerAuthError("invalid runner authentication")
            outcome = action()
            if not isinstance(outcome, RunnerHttpAction) or outcome.status not in {200, 201, 204} or (
                outcome.status == 204 and outcome.body is not None
            ) or (outcome.status != 204 and not isinstance(outcome.body, dict)):
                raise ValueError("runner action must return a closed HTTP response")
            if capability == "runner_heartbeat":
                identity = self._load_identity(workspace_id, runner_id)
                identity["last_heartbeat_at_ms"] = self._milliseconds(self._now())
                self._save_changed_identity(identity, instant=self._now())
            nonce = _token()
            aad = self._receipt_aad(workspace_id, runner_id, chain, sequence, generation)
            wire_body = b"" if outcome.status == 204 else self.response_wire_body(outcome.body)
            envelope = {
                "schema_version": "heel.runner-http-receipt.v1",
                "status": outcome.status, "body": outcome.body,
            }
            response_ciphertext = self._seal(_sealed_response_json(envelope), aad=aad)
            nonce_ciphertext = self._seal(nonce, aad=aad)
            self.conn.execute("UPDATE canary_runner_nonce_chains SET nonce_hash=?,next_sequence=?,expires_at=? WHERE workspace_id=? AND runner_id=? AND chain_name=?", (self._hash("nonce", nonce), sequence + 1, self._now() + NONCE_TTL, workspace_id, runner_id, chain))
            changed = self.conn.execute("UPDATE canary_runner_chain_cursors SET next_sequence=?,updated_at=? WHERE workspace_id=? AND runner_id=? AND chain_name=? AND generation=?", (sequence + 1, self._now(), workspace_id, runner_id, chain, generation))
            if changed.rowcount != 1:
                raise RunnerAuthError("invalid runner authentication")
            created_at = self._now()
            self.conn.execute(
                "DELETE FROM canary_runner_request_ledger WHERE workspace_id=? AND runner_id=? AND chain_name=?",
                (workspace_id, runner_id, chain),
            )
            self.conn.execute("INSERT INTO canary_runner_request_ledger(workspace_id,runner_id,chain_name,sequence,generation,request_digest,response_json,next_nonce,created_at,nonce_hash,key_id,capability,method,path,timestamp_ms,signed_request_digest,body_digest,response_ciphertext,next_nonce_ciphertext,response_status,response_body_digest,retention_expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", (workspace_id, runner_id, chain, sequence, generation, signed_digest, "sealed-v2", self._hash("next-nonce", nonce), created_at, nonce_hash, values["X-Heel-Runner-Key-Id"], capability, "POST", path, timestamp, signed_digest, body_digest, response_ciphertext, nonce_ciphertext, outcome.status, hashlib.sha256(wire_body).hexdigest(), created_at + 2_592_000.0))
            self.conn.commit()
            return outcome.status, outcome.body, nonce
        except Exception:
            if self.conn.in_transaction:
                self.conn.rollback()
            raise

    def purge_runner_request_receipts(self, now: float, limit: int = 128) -> tuple[int, bool]:
        """Bound the thirty-day replay ledger without doing work on a request path."""
        if isinstance(now, bool) or not isinstance(now, (int, float)) or not 1 <= limit <= 128:
            raise ValueError("invalid runner receipt purge request")
        instant = float(now)
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            rows = self.conn.execute(
                "SELECT workspace_id,runner_id,chain_name,sequence,generation "
                "FROM canary_runner_request_ledger INDEXED BY idx_canary_runner_ledger_retention "
                "WHERE retention_expires_at<=? "
                "ORDER BY retention_expires_at,workspace_id,runner_id,chain_name,sequence,generation LIMIT ?",
                (instant, limit + 1),
            ).fetchall()
            for row in rows[:limit]:
                deleted = self.conn.execute(
                    "DELETE FROM canary_runner_request_ledger WHERE workspace_id=? AND runner_id=? "
                    "AND chain_name=? AND sequence=? AND generation=?",
                    tuple(row),
                )
                if deleted.rowcount != 1:
                    raise RunnerAuthError("invalid runner authentication")
            self.conn.commit()
            return min(len(rows), limit), len(rows) > limit
        except Exception:
            if self.conn.in_transaction:
                self.conn.rollback()
            raise

    def reap_expired_auth(self, *, now: float, limit: int = 128) -> RunnerAuthReapResult:
        """Delete only receipt-retention work in one globally bounded transaction.

        Runner request paths deliberately do no cleanup.  Each phase uses its
        purpose-built expiry index and consumes from the same mutation budget,
        so a large tenant cannot turn a reaper tick into an unbounded write.
        Old-key retirement is intentionally deferred until the frozen indexed
        migration exists; this method never falls back to a table scan.
        """
        if (
            isinstance(now, bool) or not isinstance(now, (int, float))
            or not math.isfinite(float(now)) or isinstance(limit, bool)
            or not isinstance(limit, int) or not 1 <= limit <= 128
        ):
            raise ValueError("invalid runner auth reap request")
        # The old-key phase is legal only once the append-only schema-28
        # index exists.  Check before BEGIN: a legacy database cannot turn a
        # retention tick into an accidental full scan or partial mutation.
        expected_key_history_index = "".join(
            RUNNER_AUTH_KEY_HISTORY_EXPIRY_MIGRATION.strip().rstrip(";").split()
        )
        key_history_index = self.conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='index' "
            "AND name='idx_canary_runner_key_history_expiry'",
        ).fetchone()
        if (
            key_history_index is None or type(key_history_index[0]) is not str
            or "".join(key_history_index[0].split()) != expected_key_history_index
        ):
            raise RunnerAuthError("runner authentication schema upgrade required")
        instant = float(now)
        counts = {
            "request_receipts": 0, "pairing_receipts": 0,
            "rotation_receipts": 0, "abort_receipts": 0,
            "pairing_parents": 0, "rotation_parents": 0, "old_keys": 0,
        }
        remaining = limit
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            def consume_phase(
                query: str, parameters: tuple[object, ...], delete: str, field: str,
            ) -> bool:
                nonlocal remaining
                if remaining == 0:
                    return bool(self.conn.execute(query, (*parameters, 1)).fetchone())
                capacity = remaining
                rows = self.conn.execute(query, (*parameters, capacity + 1)).fetchall()
                take = min(len(rows), capacity)
                for row in rows[:take]:
                    changed = self.conn.execute(delete, tuple(row))
                    if changed.rowcount != 1:
                        raise RunnerAuthError("runner auth retention state is invalid")
                    counts[field] += 1
                remaining -= take
                return len(rows) > take

            phases = (
                (
                    "SELECT workspace_id,runner_id,chain_name,sequence,generation "
                    "FROM canary_runner_request_ledger INDEXED BY idx_canary_runner_ledger_retention "
                    "WHERE retention_expires_at<=? "
                    "ORDER BY retention_expires_at,workspace_id,runner_id,chain_name,sequence,generation LIMIT ?",
                    (instant,),
                    "DELETE FROM canary_runner_request_ledger WHERE workspace_id=? AND runner_id=? "
                    "AND chain_name=? AND sequence=? AND generation=?",
                    "request_receipts",
                ),
                (
                    "SELECT pairing_id FROM canary_runner_pairing_activation_receipts "
                    "INDEXED BY idx_canary_runner_pairing_receipt_expiry WHERE expires_at<=? "
                    "ORDER BY expires_at,pairing_id LIMIT ?",
                    (instant,), "DELETE FROM canary_runner_pairing_activation_receipts WHERE pairing_id=?",
                    "pairing_receipts",
                ),
                (
                    "SELECT pairing_id FROM canary_runner_rotation_activation_receipts "
                    "INDEXED BY idx_canary_runner_rotation_receipt_expiry WHERE expires_at<=? "
                    "ORDER BY expires_at,pairing_id LIMIT ?",
                    (instant,), "DELETE FROM canary_runner_rotation_activation_receipts WHERE pairing_id=?",
                    "rotation_receipts",
                ),
                (
                    "SELECT pairing_id FROM canary_runner_pairing_activation_abort_receipts "
                    "INDEXED BY idx_canary_runner_pairing_abort_receipt_expiry WHERE expires_at<=? "
                    "ORDER BY expires_at,pairing_id LIMIT ?",
                    (instant,), "DELETE FROM canary_runner_pairing_activation_abort_receipts WHERE pairing_id=?",
                    "abort_receipts",
                ),
                (
                    "SELECT pairing_id FROM canary_runner_rotation_activation_abort_receipts "
                    "INDEXED BY idx_canary_runner_rotation_abort_receipt_expiry WHERE expires_at<=? "
                    "ORDER BY expires_at,pairing_id LIMIT ?",
                    (instant,), "DELETE FROM canary_runner_rotation_activation_abort_receipts WHERE pairing_id=?",
                    "abort_receipts",
                ),
                (
                    "SELECT pairing_id FROM canary_runner_pairings "
                    "INDEXED BY idx_canary_runner_pairing_status_expiry "
                    "WHERE expires_at<=? AND ("
                    "(status='activated' AND EXISTS(SELECT 1 FROM canary_runner_execution_protocols ep "
                    " WHERE ep.workspace_id=canary_runner_pairings.workspace_id "
                    " AND ep.runner_id=canary_runner_pairings.runner_id) "
                    " AND NOT EXISTS(SELECT 1 FROM canary_runner_pairing_activation_receipts ar "
                    " WHERE ar.pairing_id=canary_runner_pairings.pairing_id)) "
                    "OR (status='expired' AND NOT EXISTS(SELECT 1 FROM canary_runner_pairing_activation_receipts ar "
                    " WHERE ar.pairing_id=canary_runner_pairings.pairing_id) "
                    " AND NOT EXISTS(SELECT 1 FROM canary_runner_pairing_activation_abort_receipts ab "
                    " WHERE ab.pairing_id=canary_runner_pairings.pairing_id))) "
                    "ORDER BY workspace_id,status,expires_at,pairing_id LIMIT ?",
                    (instant,), "DELETE FROM canary_runner_pairings WHERE pairing_id=?",
                    "pairing_parents",
                ),
                (
                    "SELECT pairing_id FROM canary_runner_rotations "
                    "INDEXED BY idx_canary_runner_rotation_status_expiry "
                    "WHERE expires_at<=? AND status IN ('rotated','expired') "
                    "AND NOT EXISTS(SELECT 1 FROM canary_runner_rotation_activation_receipts ar "
                    " WHERE ar.pairing_id=canary_runner_rotations.pairing_id) "
                    "AND NOT EXISTS(SELECT 1 FROM canary_runner_rotation_activation_abort_receipts ab "
                    " WHERE ab.pairing_id=canary_runner_rotations.pairing_id) "
                    "ORDER BY workspace_id,status,expires_at,pairing_id LIMIT ?",
                    (instant,), "DELETE FROM canary_runner_rotations WHERE pairing_id=?",
                    "rotation_parents",
                ),
            )
            has_more = False
            for query, parameters, delete, field in phases:
                if consume_phase(query, parameters, delete, field):
                    has_more = True
                    break
            if not has_more:
                old_key_cutoff = instant - 2_592_000.0
                query = (
                    "SELECT revoked_at,workspace_id,runner_id,key_id "
                    "FROM canary_runner_keys INDEXED BY idx_canary_runner_key_history_expiry "
                    "WHERE status='verification_only' "
                    "AND revoked_at IS NOT NULL "
                    "AND revoked_at<=? "
                    "ORDER BY revoked_at,workspace_id,runner_id,key_id "
                    "LIMIT ?"
                )
                if remaining == 0:
                    has_more = bool(self.conn.execute(query, (old_key_cutoff, 1)).fetchone())
                else:
                    candidate_budget = remaining
                    candidates = self.conn.execute(
                        query, (old_key_cutoff, candidate_budget + 1),
                    ).fetchall()
                    # Every negative reference check is an exact point lookup
                    # rooted by this candidate; it never broadens the index
                    # range into a tenant-wide history scan.
                    for candidate in candidates[:candidate_budget]:
                        revoked_at, workspace_id, runner_id, key_id = tuple(candidate)
                        referenced = self.conn.execute(
                            "SELECT 1 WHERE "
                            "EXISTS(SELECT 1 FROM canary_runner_identity_records i "
                            " WHERE i.workspace_id=? AND i.runner_id=? "
                            " AND json_extract(i.identity_json,'$.public_key.key_id')=?) "
                            "OR EXISTS(SELECT 1 FROM canary_runner_request_ledger l "
                            " WHERE l.workspace_id=? AND l.runner_id=? AND l.key_id=?) "
                            "OR EXISTS(SELECT 1 FROM canary_runner_context_bindings b "
                            " WHERE b.workspace_id=? AND b.runner_id=? AND b.runner_key_id=?) "
                            "OR EXISTS(SELECT 1 FROM canary_runner_context_projection_links l "
                            " WHERE l.workspace_id=? AND l.runner_id=? AND l.runner_key_id=?) "
                            "OR EXISTS(SELECT 1 FROM canary_runner_context_events e "
                            " WHERE e.workspace_id=? AND e.runner_id=? AND e.runner_key_id=?) "
                            "OR EXISTS(SELECT 1 FROM canary_runner_context_affinities a "
                            " WHERE a.workspace_id=? AND a.runner_id=? AND a.runner_key_id=?) "
                            "OR EXISTS(SELECT 1 FROM canary_execution_grants g "
                            " WHERE g.workspace_id=? AND g.runner_id=? AND g.runner_key_id=?) "
                            "OR EXISTS(SELECT 1 FROM canary_approval_projections p "
                            " WHERE p.workspace_id=? AND p.runner_id=? AND p.runner_key_id=?) "
                            "OR EXISTS(SELECT 1 FROM canary_runner_pairings p "
                            " WHERE p.workspace_id=? AND p.runner_id=? AND p.key_id=?) "
                            "OR EXISTS(SELECT 1 FROM canary_runner_rotations r "
                            " WHERE r.workspace_id=? AND r.runner_id=? "
                            " AND (r.key_id=? OR r.old_key_id=?))",
                            (
                                workspace_id, runner_id, key_id,
                                workspace_id, runner_id, key_id,
                                workspace_id, runner_id, key_id,
                                workspace_id, runner_id, key_id,
                                workspace_id, runner_id, key_id,
                                workspace_id, runner_id, key_id,
                                workspace_id, runner_id, key_id,
                                workspace_id, runner_id, key_id,
                                workspace_id, runner_id, key_id,
                                workspace_id, runner_id, key_id, key_id,
                            ),
                        ).fetchone()
                        if referenced is not None:
                            continue
                        deleted = self.conn.execute(
                            "DELETE FROM canary_runner_keys WHERE revoked_at=? AND workspace_id=? "
                            "AND runner_id=? AND key_id=? AND status='verification_only' "
                            "AND revoked_at<=?",
                            (revoked_at, workspace_id, runner_id, key_id, old_key_cutoff),
                        )
                        if deleted.rowcount != 1:
                            raise RunnerAuthError("runner auth retention state is invalid")
                        counts["old_keys"] += 1
                        remaining -= 1
                        if remaining == 0:
                            break
                    has_more = len(candidates) > candidate_budget
            self.conn.commit()
            return RunnerAuthReapResult(**counts, has_more=has_more)
        except Exception:
            if self.conn.in_transaction:
                self.conn.rollback()
            raise


def json_load(value: str) -> dict:
    if not isinstance(value, str):
        raise RunnerAuthError("invalid runner authentication")

    def pairs(items):
        result = {}
        for key, item in items:
            if key in result:
                raise ValueError("duplicate runner response key")
            result[key] = item
        return result

    try:
        decoded = json.loads(
            value,
            object_pairs_hook=pairs,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("constant")),
        )
        if _sealed_response_json(decoded) != value:
            raise ValueError("noncanonical runner response")
    except (TypeError, ValueError, json.JSONDecodeError):
        raise RunnerAuthError("invalid runner authentication")
    return decoded
