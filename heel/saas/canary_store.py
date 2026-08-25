"""Tenant-bound persistence primitives for verified canary control data.

This module deliberately owns the SQL used by migration 6 and by an in-memory ``ControlPlane``.
Keeping one schema literal prevents an un-migrated unit instance from drifting from production.
"""
from __future__ import annotations

import sqlite3
import re


CANARY_STORE_SCHEMA = """
CREATE TABLE IF NOT EXISTS canary_environments(
  environment_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  project_ref TEXT NOT NULL,
  origin TEXT NOT NULL,
  environment_class TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at REAL NOT NULL,
  UNIQUE(workspace_id, project_ref, environment_id),
  FOREIGN KEY(workspace_id, project_ref)
    REFERENCES projects(workspace_id, project_ref));
CREATE TABLE IF NOT EXISTS canary_runners(
  runner_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  display_name TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at REAL NOT NULL,
  UNIQUE(workspace_id, runner_id),
  FOREIGN KEY(workspace_id) REFERENCES workspaces(workspace_id));
CREATE TABLE IF NOT EXISTS canary_runner_keys(
  key_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  runner_id TEXT NOT NULL,
  public_key TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at REAL NOT NULL,
  revoked_at REAL,
  UNIQUE(workspace_id, key_id),
  UNIQUE(public_key),
  FOREIGN KEY(workspace_id, runner_id)
    REFERENCES canary_runners(workspace_id, runner_id));
CREATE TABLE IF NOT EXISTS canary_consumed_nonces(
  nonce_hash TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  runner_id TEXT NOT NULL,
  consumed_at REAL NOT NULL,
  expires_at REAL NOT NULL,
  UNIQUE(workspace_id, runner_id, nonce_hash),
  FOREIGN KEY(workspace_id, runner_id)
    REFERENCES canary_runners(workspace_id, runner_id));
CREATE TABLE IF NOT EXISTS canary_approval_projections(
  approval_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  project_ref TEXT NOT NULL,
  environment_id TEXT NOT NULL,
  runner_id TEXT NOT NULL,
  projection_digest TEXT NOT NULL,
  projection_json TEXT NOT NULL,
  created_at REAL NOT NULL,
  expires_at REAL NOT NULL,
  UNIQUE(workspace_id, project_ref, projection_digest),
  UNIQUE(workspace_id, project_ref, approval_id),
  UNIQUE(workspace_id, project_ref, approval_id, environment_id, runner_id),
  FOREIGN KEY(workspace_id, project_ref, environment_id)
    REFERENCES canary_environments(workspace_id, project_ref, environment_id),
  FOREIGN KEY(workspace_id, runner_id)
    REFERENCES canary_runners(workspace_id, runner_id));
CREATE TABLE IF NOT EXISTS canary_execution_grants(
  grant_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  project_ref TEXT NOT NULL,
  approval_id TEXT NOT NULL,
  environment_id TEXT NOT NULL,
  runner_id TEXT NOT NULL,
  nonce_hash TEXT NOT NULL,
  grant_digest TEXT NOT NULL,
  status TEXT NOT NULL,
  expires_at REAL NOT NULL,
  created_at REAL NOT NULL,
  UNIQUE(nonce_hash),
  UNIQUE(workspace_id, project_ref, grant_id),
  UNIQUE(workspace_id, project_ref, grant_id, environment_id, runner_id),
  FOREIGN KEY(workspace_id, project_ref, approval_id)
    REFERENCES canary_approval_projections(workspace_id, project_ref, approval_id),
  FOREIGN KEY(workspace_id, project_ref, environment_id)
    REFERENCES canary_environments(workspace_id, project_ref, environment_id),
  FOREIGN KEY(workspace_id, runner_id)
    REFERENCES canary_runners(workspace_id, runner_id),
  FOREIGN KEY(workspace_id, project_ref, approval_id, environment_id, runner_id)
    REFERENCES canary_approval_projections(
      workspace_id, project_ref, approval_id, environment_id, runner_id));
CREATE TABLE IF NOT EXISTS canary_runs(
  run_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  project_ref TEXT NOT NULL,
  grant_id TEXT NOT NULL,
  environment_id TEXT NOT NULL,
  runner_id TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL,
  UNIQUE(workspace_id, project_ref, run_id),
  FOREIGN KEY(workspace_id, project_ref, grant_id)
    REFERENCES canary_execution_grants(workspace_id, project_ref, grant_id),
  FOREIGN KEY(workspace_id, project_ref, environment_id)
    REFERENCES canary_environments(workspace_id, project_ref, environment_id),
  FOREIGN KEY(workspace_id, runner_id)
    REFERENCES canary_runners(workspace_id, runner_id),
  FOREIGN KEY(workspace_id, project_ref, grant_id, environment_id, runner_id)
    REFERENCES canary_execution_grants(
      workspace_id, project_ref, grant_id, environment_id, runner_id));
CREATE TABLE IF NOT EXISTS canary_run_events(
  event_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  project_ref TEXT NOT NULL,
  run_id TEXT NOT NULL,
  sequence INTEGER NOT NULL CHECK(sequence >= 0),
  event_type TEXT NOT NULL,
  payload_digest TEXT NOT NULL,
  created_at REAL NOT NULL,
  UNIQUE(run_id, sequence),
  FOREIGN KEY(workspace_id, project_ref, run_id)
    REFERENCES canary_runs(workspace_id, project_ref, run_id));
CREATE TABLE IF NOT EXISTS canary_operational_receipts(
  run_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  project_ref TEXT NOT NULL,
  receipt_digest TEXT NOT NULL,
  receipt_json TEXT NOT NULL,
  created_at REAL NOT NULL,
  updated_at REAL NOT NULL,
  UNIQUE(workspace_id, project_ref, run_id),
  FOREIGN KEY(workspace_id, project_ref, run_id)
    REFERENCES canary_runs(workspace_id, project_ref, run_id));
CREATE TABLE IF NOT EXISTS canary_disclosure_permits(
  permit_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  project_ref TEXT NOT NULL,
  run_id TEXT NOT NULL,
  projection_digest TEXT NOT NULL,
  status TEXT NOT NULL,
  expires_at REAL NOT NULL,
  created_at REAL NOT NULL,
  UNIQUE(workspace_id, project_ref, permit_id),
  FOREIGN KEY(workspace_id, project_ref, run_id)
    REFERENCES canary_runs(workspace_id, project_ref, run_id));
CREATE TABLE IF NOT EXISTS canary_findings_projections(
  finding_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  project_ref TEXT NOT NULL,
  run_id TEXT NOT NULL,
  projection_digest TEXT NOT NULL UNIQUE,
  projection_json TEXT NOT NULL,
  created_at REAL NOT NULL,
  UNIQUE(workspace_id, project_ref, finding_id),
  FOREIGN KEY(workspace_id, project_ref, run_id)
    REFERENCES canary_runs(workspace_id, project_ref, run_id));
CREATE TABLE IF NOT EXISTS canary_audit_records(
  audit_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  project_ref TEXT NOT NULL,
  run_id TEXT NOT NULL,
  subject_ref TEXT NOT NULL,
  action TEXT NOT NULL,
  actor TEXT NOT NULL,
  payload_digest TEXT NOT NULL,
  created_at REAL NOT NULL,
  UNIQUE(workspace_id, project_ref, audit_id),
  FOREIGN KEY(workspace_id, project_ref, run_id)
    REFERENCES canary_runs(workspace_id, project_ref, run_id));
"""

# Migration 7 deliberately extends the original Task-2 identity table rather than introducing a
# second environment identity.  Keep ``CANARY_STORE_SCHEMA`` above byte-stable: it is migration 6.
CANARY_ENVIRONMENT_VERIFICATION_MIGRATION = """
ALTER TABLE canary_environments ADD COLUMN attestation_text TEXT;
ALTER TABLE canary_environments ADD COLUMN attestation_version TEXT;
ALTER TABLE canary_environments ADD COLUMN attested_by TEXT;
ALTER TABLE canary_environments ADD COLUMN attested_at REAL;
ALTER TABLE canary_environments ADD COLUMN proof_method TEXT;
ALTER TABLE canary_environments ADD COLUMN proof_version TEXT;
ALTER TABLE canary_environments ADD COLUMN normalization_version TEXT;
ALTER TABLE canary_environments ADD COLUMN challenge_generation INTEGER NOT NULL DEFAULT 0;
ALTER TABLE canary_environments ADD COLUMN challenge_digest TEXT;
ALTER TABLE canary_environments ADD COLUMN challenge_token TEXT;
ALTER TABLE canary_environments ADD COLUMN challenge_created_at REAL;
ALTER TABLE canary_environments ADD COLUMN challenge_expires_at REAL;
ALTER TABLE canary_environments ADD COLUMN last_check_at REAL;
ALTER TABLE canary_environments ADD COLUMN last_failure_code TEXT;
ALTER TABLE canary_environments ADD COLUMN verified_at REAL;
ALTER TABLE canary_environments ADD COLUMN proof_expires_at REAL;
ALTER TABLE canary_environments ADD COLUMN revoked_at REAL;
ALTER TABLE canary_environments ADD COLUMN revoked_by TEXT;
ALTER TABLE canary_environments ADD COLUMN revoked_reason TEXT;
CREATE INDEX IF NOT EXISTS idx_canary_environment_project
  ON canary_environments(workspace_id, project_ref, origin);
"""

CANARY_ENVIRONMENT_ATTESTATION_ACK_MIGRATION = """
ALTER TABLE canary_environments ADD COLUMN attestation_acknowledgement TEXT;
"""


# Migration 15 is the first executable Cloud coordination schema.  The earlier Task-2 tables
# intentionally proved tenant-bound storage shape only; they never represented authority.  The
# rebuild below therefore does not promote their rows into executable approvals or grants.  In
# particular, all environment rows that predate v15 retain a NULL verification-record digest and
# must be re-proven before a projection can be submitted.
CANARY_COORDINATION_MIGRATION = r"""
ALTER TABLE canary_environments ADD COLUMN verification_record_digest TEXT
 CHECK(verification_record_digest IS NULL OR (
  length(verification_record_digest)=64
  AND verification_record_digest NOT GLOB '*[^0-9a-f]*'));
CREATE UNIQUE INDEX IF NOT EXISTS idx_runner_key_triple
 ON canary_runner_keys(workspace_id,runner_id,key_id);

ALTER TABLE canary_findings_projections RENAME TO canary_findings_projections_v14;
ALTER TABLE canary_disclosure_permits RENAME TO canary_disclosure_permits_v14;
ALTER TABLE canary_operational_receipts RENAME TO canary_operational_receipts_v14;
ALTER TABLE canary_audit_records RENAME TO canary_audit_records_v14;
ALTER TABLE canary_run_events RENAME TO canary_run_events_v14;
ALTER TABLE canary_runs RENAME TO canary_runs_v14;
ALTER TABLE canary_execution_grants RENAME TO canary_execution_grants_v14;
ALTER TABLE canary_approval_projections RENAME TO canary_approval_projections_v14;
ALTER TABLE canary_consumed_nonces RENAME TO canary_consumed_nonces_v14;

CREATE TABLE canary_approval_projections(
 approval_id TEXT PRIMARY KEY CHECK(length(CAST(approval_id AS BLOB)) BETWEEN 1 AND 128),
 workspace_id TEXT NOT NULL, project_ref TEXT NOT NULL,
 run_id TEXT NOT NULL CHECK(length(CAST(run_id AS BLOB)) BETWEEN 1 AND 128),
 environment_id TEXT NOT NULL, runner_id TEXT NOT NULL, runner_key_id TEXT NOT NULL,
 manifest_digest TEXT NOT NULL CHECK(length(manifest_digest)=64 AND manifest_digest NOT GLOB '*[^0-9a-f]*'),
 projection_digest TEXT NOT NULL CHECK(length(projection_digest)=64 AND projection_digest NOT GLOB '*[^0-9a-f]*'),
 signing_key_id TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('awaiting_execution_approval','approved','cancelled','expired')),
 projection_json TEXT CHECK(projection_json IS NULL OR length(CAST(projection_json AS BLOB)) BETWEEN 2 AND 65536),
 scenario_ids_json TEXT NOT NULL CHECK(length(CAST(scenario_ids_json AS BLOB)) BETWEEN 2 AND 4096),
 budgets_json TEXT NOT NULL CHECK(length(CAST(budgets_json AS BLOB)) BETWEEN 2 AND 4096),
 uploaded_by TEXT NOT NULL CHECK(length(CAST(uploaded_by AS BLOB)) BETWEEN 1 AND 128),
 approved_by TEXT, reason TEXT CHECK(reason IS NULL OR length(CAST(reason AS BLOB)) BETWEEN 1 AND 500),
 created_at INTEGER NOT NULL CHECK(created_at>=0), expires_at INTEGER NOT NULL CHECK(expires_at>created_at),
 approved_at INTEGER, purge_at INTEGER NOT NULL CHECK(purge_at>created_at),
 CHECK((status='approved' AND approved_by IS NOT NULL AND reason IS NOT NULL AND approved_at IS NOT NULL)
    OR (status!='approved' AND approved_by IS NULL AND reason IS NULL AND approved_at IS NULL)),
 UNIQUE(workspace_id,project_ref,approval_id),
 UNIQUE(workspace_id,project_ref,run_id),
 UNIQUE(workspace_id,project_ref,projection_digest),
 UNIQUE(workspace_id,project_ref,approval_id,environment_id,runner_id,runner_key_id),
 UNIQUE(workspace_id,project_ref,approval_id,run_id,environment_id,runner_id,runner_key_id),
 FOREIGN KEY(workspace_id,project_ref) REFERENCES projects(workspace_id,project_ref),
 FOREIGN KEY(workspace_id,project_ref,environment_id)
  REFERENCES canary_environments(workspace_id,project_ref,environment_id),
 FOREIGN KEY(workspace_id,runner_id,runner_key_id)
  REFERENCES canary_runner_keys(workspace_id,runner_id,key_id));

CREATE TABLE canary_execution_grants(
 grant_id TEXT PRIMARY KEY CHECK(length(CAST(grant_id AS BLOB)) BETWEEN 1 AND 128),
 workspace_id TEXT NOT NULL, project_ref TEXT NOT NULL, approval_id TEXT NOT NULL,
 run_id TEXT NOT NULL, environment_id TEXT NOT NULL, runner_id TEXT NOT NULL,
 runner_key_id TEXT NOT NULL,
 nonce_hash TEXT NOT NULL UNIQUE CHECK(length(nonce_hash)=64 AND nonce_hash NOT GLOB '*[^0-9a-f]*'),
 grant_digest TEXT NOT NULL UNIQUE CHECK(length(grant_digest)=64 AND grant_digest NOT GLOB '*[^0-9a-f]*'),
 grant_json TEXT CHECK(grant_json IS NULL OR length(CAST(grant_json AS BLOB)) BETWEEN 2 AND 32768),
 status TEXT NOT NULL CHECK(status IN ('prepared','approved','issued','claimed','expired','revoked','terminal')),
 reservation_id TEXT NOT NULL UNIQUE,
 meter TEXT NOT NULL CHECK(meter='canary_runs'),
 period TEXT NOT NULL CHECK(length(period)=7 AND substr(period,5,1)='-'),
 idempotency_key TEXT NOT NULL CHECK(
  length(idempotency_key)=68 AND substr(idempotency_key,1,4)='ca1-'
  AND substr(idempotency_key,5) NOT GLOB '*[^0-9a-f]*'),
 issued_at INTEGER NOT NULL CHECK(issued_at>=0),
 expires_at INTEGER NOT NULL CHECK(issued_at<expires_at AND expires_at<=issued_at+600000),
 claimed_at INTEGER, purge_at INTEGER NOT NULL CHECK(purge_at>issued_at),
 UNIQUE(workspace_id,project_ref,grant_id),
 UNIQUE(workspace_id,project_ref,run_id),
 UNIQUE(workspace_id,meter,idempotency_key),
 UNIQUE(workspace_id,project_ref,grant_id,environment_id,runner_id,runner_key_id),
 UNIQUE(workspace_id,project_ref,grant_id,approval_id,run_id,environment_id,runner_id,runner_key_id),
 FOREIGN KEY(workspace_id,project_ref,approval_id,run_id,environment_id,runner_id,runner_key_id)
  REFERENCES canary_approval_projections(
   workspace_id,project_ref,approval_id,run_id,environment_id,runner_id,runner_key_id),
 FOREIGN KEY(workspace_id,project_ref,approval_id)
  REFERENCES canary_approval_projections(workspace_id,project_ref,approval_id),
 FOREIGN KEY(workspace_id,project_ref,environment_id)
  REFERENCES canary_environments(workspace_id,project_ref,environment_id),
 FOREIGN KEY(workspace_id,runner_id,runner_key_id)
  REFERENCES canary_runner_keys(workspace_id,runner_id,key_id));

CREATE TABLE canary_runs(
 run_id TEXT PRIMARY KEY CHECK(length(CAST(run_id AS BLOB)) BETWEEN 1 AND 128),
 workspace_id TEXT NOT NULL, project_ref TEXT NOT NULL, approval_id TEXT NOT NULL,
 grant_id TEXT, environment_id TEXT NOT NULL, runner_id TEXT NOT NULL, runner_key_id TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN (
  'prepared','awaiting_execution_approval','approved','claimed','running','stop_requested',
  'finalizing','terminal','cancelled','expired')),
 execution_disposition TEXT CHECK(execution_disposition IS NULL OR execution_disposition IN (
  'completed','incomplete','failed','stopped')),
 error_category TEXT NOT NULL CHECK(error_category IN (
  'none','platform_fault','runner_fault','target_unavailable','proof_expired','dns_changed',
  'credential_unavailable','version_mismatch','budget_exhausted','containment_rejected','cloud_disconnected')),
 stop_reason TEXT NOT NULL CHECK(stop_reason IN (
  'none','local_emergency_stop','cloud_stop','runner_revoked','target_revoked','kill_switch')),
 source_event_sequence INTEGER NOT NULL CHECK(source_event_sequence>=-1),
 source_projection_digest TEXT CHECK(source_projection_digest IS NULL OR (
  length(source_projection_digest)=64 AND source_projection_digest NOT GLOB '*[^0-9a-f]*')),
 cloud_event_sequence INTEGER NOT NULL CHECK(cloud_event_sequence>=0),
 last_heartbeat_at_ms INTEGER, last_gate_at_ms INTEGER,
 claimed_at_ms INTEGER, started_at_ms INTEGER, stop_requested_at_ms INTEGER,
 stop_acknowledged_at_ms INTEGER, terminal_at_ms INTEGER,
 stop_generation INTEGER NOT NULL CHECK(stop_generation>=0), stop_deadline_ms INTEGER,
 stop_ack_late INTEGER NOT NULL CHECK(stop_ack_late IN (0,1)),
 reservation_id TEXT,
 quota_state TEXT NOT NULL CHECK(quota_state IN ('unreserved','reserved','consumed','refunded','compensated')),
 kill_switch_generation INTEGER NOT NULL CHECK(kill_switch_generation>=0),
 created_at INTEGER NOT NULL CHECK(created_at>=0), updated_at INTEGER NOT NULL CHECK(updated_at>=created_at),
 purge_at INTEGER NOT NULL CHECK(purge_at>created_at),
 CHECK((grant_id IS NULL AND status IN ('prepared','awaiting_execution_approval','cancelled','expired'))
    OR grant_id IS NOT NULL),
 CHECK((status='terminal')=(execution_disposition IS NOT NULL)),
 UNIQUE(workspace_id,project_ref,run_id),
 UNIQUE(workspace_id,project_ref,run_id,grant_id),
 UNIQUE(workspace_id,project_ref,approval_id),
 UNIQUE(workspace_id,project_ref,run_id,grant_id,environment_id,runner_id,runner_key_id),
 FOREIGN KEY(workspace_id,project_ref,approval_id,run_id,environment_id,runner_id,runner_key_id)
  REFERENCES canary_approval_projections(
   workspace_id,project_ref,approval_id,run_id,environment_id,runner_id,runner_key_id),
 FOREIGN KEY(workspace_id,project_ref,grant_id,approval_id,run_id,environment_id,runner_id,runner_key_id)
  REFERENCES canary_execution_grants(
   workspace_id,project_ref,grant_id,approval_id,run_id,environment_id,runner_id,runner_key_id));

CREATE TABLE canary_consumed_nonces(
 nonce_hash TEXT PRIMARY KEY CHECK(length(nonce_hash)=64 AND nonce_hash NOT GLOB '*[^0-9a-f]*'),
 workspace_id TEXT NOT NULL, project_ref TEXT NOT NULL, runner_id TEXT NOT NULL,
 run_id TEXT NOT NULL, grant_id TEXT NOT NULL,
 kind TEXT NOT NULL CHECK(kind='execution_grant'),
 consumed_at INTEGER NOT NULL CHECK(consumed_at>=0), expires_at INTEGER NOT NULL CHECK(expires_at>consumed_at),
 UNIQUE(workspace_id,project_ref,run_id,grant_id,kind),
 FOREIGN KEY(workspace_id,project_ref,run_id,grant_id)
  REFERENCES canary_runs(workspace_id,project_ref,run_id,grant_id),
 FOREIGN KEY(workspace_id,project_ref,grant_id)
  REFERENCES canary_execution_grants(workspace_id,project_ref,grant_id),
 FOREIGN KEY(workspace_id,runner_id) REFERENCES canary_runners(workspace_id,runner_id));

CREATE TABLE canary_run_events(
 event_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, project_ref TEXT NOT NULL,
 run_id TEXT NOT NULL, sequence INTEGER NOT NULL CHECK(sequence>=0),
 event_type TEXT NOT NULL CHECK(event_type IN (
  'prepared','awaiting_execution_approval','projection_submitted','approval_granted',
  'grant_issued','grant_claimed','run_started',
  'heartbeat_accepted','progress_accepted','stop_requested','stop_acknowledged',
  'finalizing','terminal','cancelled','expired','quota_reserved','quota_consumed',
  'quota_refunded','quota_compensated','grant_revoked')),
 event_json TEXT NOT NULL CHECK(length(CAST(event_json AS BLOB)) BETWEEN 2 AND 32768),
 payload_digest TEXT NOT NULL CHECK(length(payload_digest)=64 AND payload_digest NOT GLOB '*[^0-9a-f]*'),
 source_event_sequence INTEGER, actor_class TEXT NOT NULL CHECK(actor_class IN ('human','runner','system')),
 actor_id TEXT NOT NULL, reason_code TEXT, created_at INTEGER NOT NULL CHECK(created_at>=0),
 UNIQUE(workspace_id,project_ref,run_id,sequence),
 FOREIGN KEY(workspace_id,project_ref,run_id)
  REFERENCES canary_runs(workspace_id,project_ref,run_id));

CREATE TABLE canary_operational_receipts(
 run_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, project_ref TEXT NOT NULL,
 grant_id TEXT NOT NULL, runner_id TEXT NOT NULL, runner_key_id TEXT NOT NULL,
 source_event_sequence INTEGER NOT NULL CHECK(source_event_sequence>=0),
 lifecycle_phase TEXT NOT NULL CHECK(lifecycle_phase IN (
  'claimed','running','stop_requested','finalizing','terminal')),
 execution_disposition TEXT CHECK(execution_disposition IS NULL OR execution_disposition IN (
  'completed','incomplete','failed','stopped')),
 error_category TEXT NOT NULL, stop_reason TEXT NOT NULL,
 receipt_digest TEXT NOT NULL CHECK(length(receipt_digest)=64 AND receipt_digest NOT GLOB '*[^0-9a-f]*'),
 receipt_json TEXT CHECK(receipt_json IS NULL OR length(CAST(receipt_json AS BLOB)) BETWEEN 2 AND 32768),
 created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, purge_at INTEGER NOT NULL,
 UNIQUE(workspace_id,project_ref,run_id),
 FOREIGN KEY(workspace_id,project_ref,run_id,grant_id)
  REFERENCES canary_runs(workspace_id,project_ref,run_id,grant_id),
 FOREIGN KEY(workspace_id,runner_id,runner_key_id)
  REFERENCES canary_runner_keys(workspace_id,runner_id,key_id));

CREATE TABLE canary_audit_records(
 audit_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, project_ref TEXT NOT NULL,
 run_id TEXT NOT NULL, subject_ref TEXT NOT NULL,
 action TEXT NOT NULL CHECK(action IN (
  'prepared','awaiting_execution_approval','approved','cancelled','expired','claimed',
  'running','target_attempted','contained','stop_requested','stop_acknowledged',
  'stop_ack_late','finalized','local_result_ready','disclosure_permitted','local_only',
  'synchronized','quota_reserved','quota_consumed','quota_refunded','quota_compensated')),
 actor_class TEXT NOT NULL CHECK(actor_class IN ('human','runner','system')),
 actor_id TEXT NOT NULL, reason_code TEXT,
 payload_digest TEXT NOT NULL CHECK(length(payload_digest)=64 AND payload_digest NOT GLOB '*[^0-9a-f]*'),
 created_at INTEGER NOT NULL CHECK(created_at>=0), purge_at INTEGER NOT NULL CHECK(purge_at>created_at),
 UNIQUE(workspace_id,project_ref,audit_id),
 FOREIGN KEY(workspace_id,project_ref,run_id)
  REFERENCES canary_runs(workspace_id,project_ref,run_id));

CREATE TABLE canary_disclosure_requests(
 request_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, project_ref TEXT NOT NULL,
 run_id TEXT NOT NULL, grant_id TEXT NOT NULL, runner_id TEXT NOT NULL, runner_key_id TEXT NOT NULL,
 schema_version TEXT NOT NULL CHECK(schema_version='heel.canary-findings-projection.v1'),
 projection_digest TEXT NOT NULL CHECK(length(projection_digest)=64 AND projection_digest NOT GLOB '*[^0-9a-f]*'),
 maximum_bytes INTEGER NOT NULL CHECK(maximum_bytes BETWEEN 1 AND 262144),
 scenario_count INTEGER NOT NULL CHECK(scenario_count BETWEEN 0 AND 4),
 finding_count INTEGER NOT NULL CHECK(finding_count BETWEEN 0 AND 4),
 status TEXT NOT NULL CHECK(status IN (
  'local_result_ready','awaiting_disclosure_approval','permitted','synchronized','local_only','expired')),
 created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, updated_at INTEGER NOT NULL,
 UNIQUE(workspace_id,project_ref,run_id), UNIQUE(workspace_id,project_ref,projection_digest),
 UNIQUE(workspace_id,project_ref,request_id,run_id,grant_id,runner_id,runner_key_id),
 FOREIGN KEY(workspace_id,project_ref,run_id,grant_id)
  REFERENCES canary_runs(workspace_id,project_ref,run_id,grant_id),
 FOREIGN KEY(workspace_id,runner_id,runner_key_id)
  REFERENCES canary_runner_keys(workspace_id,runner_id,key_id));

CREATE TABLE canary_disclosure_permits(
 permit_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, project_ref TEXT NOT NULL,
 request_id TEXT NOT NULL, run_id TEXT NOT NULL, grant_id TEXT NOT NULL,
 runner_id TEXT NOT NULL, runner_key_id TEXT NOT NULL,
 schema_version TEXT NOT NULL CHECK(schema_version='heel.disclosure-permit.v1'),
 projection_schema_version TEXT NOT NULL
  CHECK(projection_schema_version='heel.canary-findings-projection.v1'),
 projection_digest TEXT NOT NULL CHECK(
  length(projection_digest)=64 AND projection_digest NOT GLOB '*[^0-9a-f]*'),
 permit_digest TEXT NOT NULL UNIQUE CHECK(
  length(permit_digest)=64 AND permit_digest NOT GLOB '*[^0-9a-f]*'),
 permit_json TEXT NOT NULL CHECK(length(CAST(permit_json AS BLOB)) BETWEEN 2 AND 16384),
 nonce_hash TEXT NOT NULL UNIQUE CHECK(length(nonce_hash)=64 AND nonce_hash NOT GLOB '*[^0-9a-f]*'),
 maximum_bytes INTEGER NOT NULL CHECK(maximum_bytes BETWEEN 1 AND 262144),
 scenario_count INTEGER NOT NULL CHECK(scenario_count BETWEEN 0 AND 4),
 finding_count INTEGER NOT NULL CHECK(finding_count BETWEEN 0 AND 4),
 status TEXT NOT NULL CHECK(status IN ('permitted','consumed','expired','revoked')),
 approved_by TEXT NOT NULL, approved_at INTEGER NOT NULL, issued_at INTEGER NOT NULL,
 expires_at INTEGER NOT NULL CHECK(issued_at<expires_at AND expires_at<=issued_at+600000),
 consumed_at INTEGER, purge_at INTEGER NOT NULL,
 UNIQUE(workspace_id,project_ref,permit_id),
 UNIQUE(workspace_id,project_ref,permit_id,run_id,grant_id,runner_id,runner_key_id),
 FOREIGN KEY(workspace_id,project_ref,request_id,run_id,grant_id,runner_id,runner_key_id)
  REFERENCES canary_disclosure_requests(
   workspace_id,project_ref,request_id,run_id,grant_id,runner_id,runner_key_id),
 FOREIGN KEY(workspace_id,project_ref,run_id,grant_id)
  REFERENCES canary_runs(workspace_id,project_ref,run_id,grant_id),
 FOREIGN KEY(workspace_id,runner_id,runner_key_id)
  REFERENCES canary_runner_keys(workspace_id,runner_id,key_id));

CREATE TABLE canary_findings_projections(
 finding_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, project_ref TEXT NOT NULL,
 run_id TEXT NOT NULL, grant_id TEXT NOT NULL, permit_id TEXT NOT NULL,
 runner_id TEXT NOT NULL, runner_key_id TEXT NOT NULL,
 schema_version TEXT NOT NULL CHECK(schema_version='heel.canary-findings-projection.v1'),
 projection_digest TEXT NOT NULL UNIQUE CHECK(
  length(projection_digest)=64 AND projection_digest NOT GLOB '*[^0-9a-f]*'),
 projection_json TEXT CHECK(
  projection_json IS NULL OR length(CAST(projection_json AS BLOB)) BETWEEN 2 AND 262144),
 byte_count INTEGER NOT NULL CHECK(byte_count BETWEEN 1 AND 262144),
 scenario_count INTEGER NOT NULL CHECK(scenario_count BETWEEN 0 AND 4),
 finding_count INTEGER NOT NULL CHECK(finding_count BETWEEN 0 AND 4),
 receipt_id TEXT NOT NULL UNIQUE CHECK(length(CAST(receipt_id AS BLOB)) BETWEEN 1 AND 128),
 receipt_digest TEXT NOT NULL CHECK(
  length(receipt_digest)=64 AND receipt_digest NOT GLOB '*[^0-9a-f]*'),
 receipt_json TEXT NOT NULL CHECK(length(CAST(receipt_json AS BLOB)) BETWEEN 2 AND 16384),
 status TEXT NOT NULL CHECK(status='synchronized'),
 accepted_at INTEGER NOT NULL, purge_at INTEGER NOT NULL,
 UNIQUE(workspace_id,project_ref,finding_id), UNIQUE(workspace_id,project_ref,run_id),
 FOREIGN KEY(workspace_id,project_ref,run_id,grant_id)
  REFERENCES canary_runs(workspace_id,project_ref,run_id,grant_id),
 FOREIGN KEY(workspace_id,project_ref,permit_id,run_id,grant_id,runner_id,runner_key_id)
  REFERENCES canary_disclosure_permits(
   workspace_id,project_ref,permit_id,run_id,grant_id,runner_id,runner_key_id),
 FOREIGN KEY(workspace_id,runner_id,runner_key_id)
  REFERENCES canary_runner_keys(workspace_id,runner_id,key_id));

CREATE TABLE canary_reaper_state(
 singleton INTEGER PRIMARY KEY CHECK(singleton=1), lease_owner TEXT,
 lease_expires_at INTEGER, last_run_at INTEGER,
 CHECK((lease_owner IS NULL)=(lease_expires_at IS NULL)));
INSERT INTO canary_reaper_state(singleton) VALUES(1);

CREATE TABLE canary_control_generation(
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 generation INTEGER NOT NULL CHECK(generation>=0), updated_at REAL NOT NULL);
INSERT INTO canary_control_generation VALUES(1,0,0);
CREATE TRIGGER canary_control_generation_insert AFTER INSERT ON kill_switches BEGIN
 UPDATE canary_control_generation SET generation=generation+1,
  updated_at=CAST(strftime('%s','now') AS REAL) WHERE singleton=1;
END;
CREATE TRIGGER canary_control_generation_update AFTER UPDATE ON kill_switches BEGIN
 UPDATE canary_control_generation SET generation=generation+1,
  updated_at=CAST(strftime('%s','now') AS REAL) WHERE singleton=1;
END;
CREATE TRIGGER canary_control_generation_delete AFTER DELETE ON kill_switches BEGIN
 UPDATE canary_control_generation SET generation=generation+1,
  updated_at=CAST(strftime('%s','now') AS REAL) WHERE singleton=1;
END;

CREATE INDEX idx_canary_approvals_status_expiry
 ON canary_approval_projections(status,expires_at);
CREATE INDEX idx_canary_grants_runner_status
 ON canary_execution_grants(workspace_id,runner_id,runner_key_id,status,issued_at);
CREATE INDEX idx_canary_grants_expiry ON canary_execution_grants(status,expires_at);
CREATE INDEX idx_canary_runs_status_heartbeat ON canary_runs(status,last_heartbeat_at_ms);
CREATE INDEX idx_canary_events_run_sequence
 ON canary_run_events(workspace_id,project_ref,run_id,sequence);
CREATE INDEX idx_canary_receipts_purge ON canary_operational_receipts(purge_at);
CREATE INDEX idx_canary_audit_purge ON canary_audit_records(purge_at);
CREATE INDEX idx_canary_disclosure_expiry ON canary_disclosure_permits(status,expires_at);
CREATE INDEX idx_canary_findings_purge ON canary_findings_projections(purge_at);

DROP TABLE canary_findings_projections_v14;
DROP TABLE canary_disclosure_permits_v14;
DROP TABLE canary_operational_receipts_v14;
DROP TABLE canary_audit_records_v14;
DROP TABLE canary_run_events_v14;
DROP TABLE canary_runs_v14;
DROP TABLE canary_execution_grants_v14;
DROP TABLE canary_approval_projections_v14;
DROP TABLE canary_consumed_nonces_v14;
"""

# Migration 16: a browser-authorized context permits a paired runner to submit an
# approval projection only.  It deliberately has no grant, reservation, or execution
# authority.  Keep this literal shared by Migrator and direct ControlPlane startup.
RUNNER_CONTEXT_BINDINGS_MIGRATION = r"""
CREATE TABLE canary_runner_context_bindings(
 rcb_id TEXT PRIMARY KEY CHECK(length(rcb_id)=36 AND substr(rcb_id,1,4)='rcb_' AND substr(rcb_id,5) NOT GLOB '*[^0-9a-f]*'),
 workspace_id TEXT NOT NULL, project_ref TEXT NOT NULL, environment_id TEXT NOT NULL,
 runner_id TEXT NOT NULL, runner_key_id TEXT NOT NULL,
 environment_origin TEXT NOT NULL CHECK(length(CAST(environment_origin AS BLOB)) BETWEEN 1 AND 2048),
 environment_class TEXT NOT NULL CHECK(environment_class IN ('staging','sandbox')),
 binding_digest TEXT NOT NULL CHECK(length(binding_digest)=64 AND binding_digest NOT GLOB '*[^0-9a-f]*'),
 public_key_digest TEXT NOT NULL CHECK(length(public_key_digest)=64 AND public_key_digest NOT GLOB '*[^0-9a-f]*'),
 verification_record_digest TEXT NOT NULL CHECK(length(verification_record_digest)=64 AND verification_record_digest NOT GLOB '*[^0-9a-f]*'),
 binding_json TEXT NOT NULL CHECK(length(CAST(binding_json AS BLOB)) BETWEEN 2 AND 16384 AND json_valid(binding_json)),
 status TEXT NOT NULL CHECK(status IN ('active','revoked','expired')),
 created_by TEXT NOT NULL CHECK(length(CAST(created_by AS BLOB)) BETWEEN 1 AND 128),
 created_role TEXT NOT NULL CHECK(created_role IN ('owner','admin')),
 issued_at_ms INTEGER NOT NULL CHECK(issued_at_ms>=0),
 expires_at_ms INTEGER NOT NULL CHECK(expires_at_ms>issued_at_ms AND expires_at_ms<=issued_at_ms+86400000),
 first_claimed_at_ms INTEGER CHECK(first_claimed_at_ms IS NULL OR (first_claimed_at_ms>=issued_at_ms AND first_claimed_at_ms<expires_at_ms)),
 revoked_by TEXT CHECK(revoked_by IS NULL OR length(CAST(revoked_by AS BLOB)) BETWEEN 1 AND 128),
 revoked_at_ms INTEGER CHECK(revoked_at_ms IS NULL OR revoked_at_ms>=issued_at_ms),
 revoke_reason TEXT CHECK(revoke_reason IS NULL OR revoke_reason='operator_requested'),
 purge_at_ms INTEGER NOT NULL CHECK(purge_at_ms>issued_at_ms),
 CHECK((status='revoked' AND revoked_by IS NOT NULL AND revoked_at_ms IS NOT NULL AND revoke_reason='operator_requested')
    OR (status IN ('active','expired') AND revoked_by IS NULL AND revoked_at_ms IS NULL AND revoke_reason IS NULL)),
 UNIQUE(workspace_id,project_ref,environment_id,runner_id,runner_key_id,rcb_id,binding_digest),
 UNIQUE(workspace_id,project_ref,binding_digest),
 FOREIGN KEY(workspace_id,project_ref,environment_id)
  REFERENCES canary_environments(workspace_id,project_ref,environment_id),
 FOREIGN KEY(workspace_id,runner_id,runner_key_id)
  REFERENCES canary_runner_keys(workspace_id,runner_id,key_id));
CREATE UNIQUE INDEX idx_runner_context_one_active
 ON canary_runner_context_bindings(workspace_id,project_ref,environment_id,runner_id)
 WHERE status='active';
CREATE INDEX idx_runner_context_runner_status_expiry
 ON canary_runner_context_bindings(workspace_id,runner_id,runner_key_id,status,expires_at_ms);
CREATE INDEX idx_runner_context_purge ON canary_runner_context_bindings(purge_at_ms);
CREATE UNIQUE INDEX idx_canary_approval_projection_context_digest
 ON canary_approval_projections(workspace_id,project_ref,approval_id,run_id,environment_id,runner_id,runner_key_id,projection_digest);

CREATE TABLE canary_runner_context_projection_links(
 workspace_id TEXT NOT NULL, project_ref TEXT NOT NULL, approval_id TEXT NOT NULL,
 run_id TEXT NOT NULL, environment_id TEXT NOT NULL, runner_id TEXT NOT NULL,
 runner_key_id TEXT NOT NULL, rcb_id TEXT NOT NULL,
 binding_digest TEXT NOT NULL CHECK(length(binding_digest)=64 AND binding_digest NOT GLOB '*[^0-9a-f]*'),
 projection_digest TEXT NOT NULL CHECK(length(projection_digest)=64 AND projection_digest NOT GLOB '*[^0-9a-f]*'),
 created_at_ms INTEGER NOT NULL CHECK(created_at_ms>=0),
 PRIMARY KEY(workspace_id,project_ref,approval_id,run_id),
 FOREIGN KEY(workspace_id,project_ref,approval_id,run_id,environment_id,runner_id,runner_key_id,projection_digest)
  REFERENCES canary_approval_projections(workspace_id,project_ref,approval_id,run_id,environment_id,runner_id,runner_key_id,projection_digest),
 FOREIGN KEY(workspace_id,project_ref,environment_id,runner_id,runner_key_id,rcb_id,binding_digest)
  REFERENCES canary_runner_context_bindings(workspace_id,project_ref,environment_id,runner_id,runner_key_id,rcb_id,binding_digest));
CREATE INDEX idx_runner_context_links_binding
 ON canary_runner_context_projection_links(workspace_id,project_ref,rcb_id);

CREATE TABLE canary_runner_context_events(
 rce_id TEXT PRIMARY KEY CHECK(length(rce_id)=36 AND substr(rce_id,1,4)='rce_' AND substr(rce_id,5) NOT GLOB '*[^0-9a-f]*'),
 workspace_id TEXT NOT NULL, project_ref TEXT NOT NULL, environment_id TEXT NOT NULL,
 runner_id TEXT NOT NULL, runner_key_id TEXT NOT NULL, rcb_id TEXT NOT NULL,
 action TEXT NOT NULL CHECK(action IN ('created','claimed','revoked','expired','projection_submitted')),
 actor_class TEXT NOT NULL CHECK(actor_class IN ('human','runner','system')),
 actor_id TEXT NOT NULL CHECK(length(CAST(actor_id AS BLOB)) BETWEEN 1 AND 128),
 reason_code TEXT CHECK(reason_code IS NULL OR reason_code IN ('operator_requested','ttl_elapsed')),
 binding_digest TEXT NOT NULL CHECK(length(binding_digest)=64 AND binding_digest NOT GLOB '*[^0-9a-f]*'),
 created_at_ms INTEGER NOT NULL CHECK(created_at_ms>=0),
 purge_at_ms INTEGER NOT NULL CHECK(purge_at_ms>created_at_ms),
 CHECK((action='revoked' AND reason_code='operator_requested') OR (action='expired' AND reason_code='ttl_elapsed') OR (action NOT IN ('revoked','expired') AND reason_code IS NULL)),
 FOREIGN KEY(workspace_id,project_ref,environment_id,runner_id,runner_key_id,rcb_id,binding_digest)
  REFERENCES canary_runner_context_bindings(workspace_id,project_ref,environment_id,runner_id,runner_key_id,rcb_id,binding_digest));
CREATE INDEX idx_runner_context_events_purge ON canary_runner_context_events(purge_at_ms);
"""

# Migration 17 narrows the discoverable runner authority to one active binding across
# every project/environment.  Context selection is intentionally absent from the runner
# protocol, so permitting two live bindings would make acquisition permanently ambiguous.
RUNNER_CONTEXT_ONE_ACTIVE_PER_RUNNER_MIGRATION = r"""
CREATE UNIQUE INDEX idx_runner_context_one_active_per_runner
 ON canary_runner_context_bindings(workspace_id,runner_id)
 WHERE status='active';
"""

# Migration 18: bounded lifecycle reconciliation must seek exact terminal/active
# context rows under its short writer transaction, never scan or sort history.
RUNNER_CONTEXT_REAPER_INDEXES_MIGRATION = r"""
CREATE INDEX idx_runner_context_active_expiry_order ON canary_runner_context_bindings(expires_at_ms,rcb_id) WHERE status='active';
CREATE INDEX idx_runner_context_terminal_cancel_order ON canary_runner_context_bindings(expires_at_ms,rcb_id) WHERE status IN ('revoked','expired');
CREATE INDEX idx_runner_context_terminal_purge_order ON canary_runner_context_bindings(purge_at_ms,rcb_id) WHERE status IN ('revoked','expired');
CREATE INDEX idx_runner_context_links_binding_run ON canary_runner_context_projection_links(workspace_id,project_ref,rcb_id,binding_digest,run_id,approval_id);
CREATE INDEX idx_runner_context_events_binding_purge ON canary_runner_context_events(workspace_id,project_ref,rcb_id,binding_digest,purge_at_ms);
CREATE INDEX idx_canary_approval_context_awaiting ON canary_approval_projections(workspace_id,project_ref,approval_id,run_id) WHERE status='awaiting_execution_approval';
CREATE INDEX idx_canary_runs_context_pregrant ON canary_runs(workspace_id,project_ref,run_id) WHERE status IN ('prepared','awaiting_execution_approval');
CREATE INDEX idx_canary_approval_pending_discovery_order ON canary_approval_projections(workspace_id,project_ref,created_at DESC,run_id ASC,expires_at,approval_id) WHERE status='awaiting_execution_approval';
CREATE INDEX idx_canary_runs_pending_approval_discovery ON canary_runs(workspace_id,project_ref,run_id,approval_id) WHERE status='awaiting_execution_approval';
CREATE INDEX idx_runner_context_dashboard_history ON canary_runner_context_bindings(workspace_id,project_ref,(CASE status WHEN 'active' THEN 0 ELSE 1 END),issued_at_ms DESC,rcb_id DESC);
CREATE INDEX idx_canary_runners_dashboard_selector ON canary_runners(workspace_id,runner_id) WHERE status='active';
CREATE INDEX idx_canary_runner_keys_dashboard_selector ON canary_runner_keys(workspace_id,runner_id,key_id) WHERE status='active' AND revoked_at IS NULL;
CREATE UNIQUE INDEX idx_runner_context_binding_cancellation_ref
 ON canary_runner_context_bindings(workspace_id,project_ref,environment_id,runner_id,runner_key_id,rcb_id,binding_digest,expires_at_ms);
CREATE TABLE canary_runner_context_cancellation_queue(
 workspace_id TEXT NOT NULL CHECK(length(CAST(workspace_id AS BLOB)) BETWEEN 1 AND 128),
 project_ref TEXT NOT NULL CHECK(length(CAST(project_ref AS BLOB)) BETWEEN 1 AND 128),
 environment_id TEXT NOT NULL CHECK(length(CAST(environment_id AS BLOB)) BETWEEN 1 AND 128),
 runner_id TEXT NOT NULL CHECK(length(CAST(runner_id AS BLOB)) BETWEEN 1 AND 128),
 runner_key_id TEXT NOT NULL CHECK(length(CAST(runner_key_id AS BLOB)) BETWEEN 1 AND 128),
 rcb_id TEXT NOT NULL COLLATE BINARY CHECK(length(rcb_id)=36 AND substr(rcb_id,1,4)='rcb_' AND substr(rcb_id,5) NOT GLOB '*[^0-9a-f]*'),
 binding_digest TEXT NOT NULL CHECK(length(binding_digest)=64 AND binding_digest NOT GLOB '*[^0-9a-f]*'),
 binding_expires_at_ms INTEGER NOT NULL CHECK(binding_expires_at_ms>0),
 last_scanned_run_id TEXT COLLATE BINARY CHECK(last_scanned_run_id IS NULL OR (length(last_scanned_run_id)=37 AND substr(last_scanned_run_id,1,5)='crun_' AND substr(last_scanned_run_id,6) NOT GLOB '*[^0-9a-f]*')),
 PRIMARY KEY(workspace_id,project_ref,rcb_id,binding_digest),
 FOREIGN KEY(workspace_id,project_ref,environment_id,runner_id,runner_key_id,rcb_id,binding_digest,binding_expires_at_ms)
  REFERENCES canary_runner_context_bindings(workspace_id,project_ref,environment_id,runner_id,runner_key_id,rcb_id,binding_digest,expires_at_ms));
CREATE INDEX idx_runner_context_cancellation_queue_order
 ON canary_runner_context_cancellation_queue(binding_expires_at_ms,rcb_id);
CREATE TRIGGER trg_runner_context_cancellation_queue_insert_guard
BEFORE INSERT ON canary_runner_context_cancellation_queue
WHEN NEW.last_scanned_run_id IS NOT NULL OR NOT EXISTS(SELECT 1 FROM canary_runner_context_bindings b WHERE b.workspace_id=NEW.workspace_id AND b.project_ref=NEW.project_ref AND b.environment_id=NEW.environment_id AND b.runner_id=NEW.runner_id AND b.runner_key_id=NEW.runner_key_id AND b.rcb_id=NEW.rcb_id AND b.binding_digest=NEW.binding_digest AND b.expires_at_ms=NEW.binding_expires_at_ms AND b.status IN ('revoked','expired'))
BEGIN SELECT RAISE(ABORT,'invalid runner context cancellation queue insert'); END;
CREATE TRIGGER trg_runner_context_cancellation_queue_update_guard
BEFORE UPDATE ON canary_runner_context_cancellation_queue
WHEN NEW.workspace_id<>OLD.workspace_id OR NEW.project_ref<>OLD.project_ref OR NEW.environment_id<>OLD.environment_id OR NEW.runner_id<>OLD.runner_id OR NEW.runner_key_id<>OLD.runner_key_id OR NEW.rcb_id<>OLD.rcb_id OR NEW.binding_digest<>OLD.binding_digest OR NEW.binding_expires_at_ms<>OLD.binding_expires_at_ms OR NEW.last_scanned_run_id IS NULL OR (OLD.last_scanned_run_id IS NOT NULL AND NEW.last_scanned_run_id<=OLD.last_scanned_run_id) OR NOT EXISTS(SELECT 1 FROM canary_runner_context_bindings b WHERE b.workspace_id=NEW.workspace_id AND b.project_ref=NEW.project_ref AND b.environment_id=NEW.environment_id AND b.runner_id=NEW.runner_id AND b.runner_key_id=NEW.runner_key_id AND b.rcb_id=NEW.rcb_id AND b.binding_digest=NEW.binding_digest AND b.expires_at_ms=NEW.binding_expires_at_ms AND b.status IN ('revoked','expired')) OR NOT EXISTS(SELECT 1 FROM canary_runner_context_projection_links l WHERE l.workspace_id=NEW.workspace_id AND l.project_ref=NEW.project_ref AND l.environment_id=NEW.environment_id AND l.runner_id=NEW.runner_id AND l.runner_key_id=NEW.runner_key_id AND l.rcb_id=NEW.rcb_id AND l.binding_digest=NEW.binding_digest AND l.run_id=NEW.last_scanned_run_id)
BEGIN SELECT RAISE(ABORT,'invalid runner context cancellation queue update'); END;
INSERT INTO canary_runner_context_cancellation_queue(
 workspace_id,project_ref,environment_id,runner_id,runner_key_id,rcb_id,binding_digest,binding_expires_at_ms,last_scanned_run_id)
SELECT b.workspace_id,b.project_ref,b.environment_id,b.runner_id,b.runner_key_id,b.rcb_id,b.binding_digest,b.expires_at_ms,NULL
FROM canary_runner_context_bindings b
WHERE b.status IN ('revoked','expired') AND EXISTS(
 SELECT 1 FROM canary_runner_context_projection_links l INDEXED BY idx_runner_context_links_binding_run
 WHERE l.workspace_id=b.workspace_id AND l.project_ref=b.project_ref
  AND l.environment_id=b.environment_id AND l.runner_id=b.runner_id AND l.runner_key_id=b.runner_key_id
  AND l.rcb_id=b.rcb_id AND l.binding_digest=b.binding_digest LIMIT 1);
"""

# Migration 19: claiming a context fixes the runner to that environment
# coordinate.  The runner's first claim is the only durable establishment point;
# creating an unclaimed binding deliberately has no such effect.
RUNNER_CONTEXT_AFFINITIES_MIGRATION = r"""
CREATE TABLE canary_runner_context_affinities(
 workspace_id TEXT NOT NULL CHECK(length(CAST(workspace_id AS BLOB)) BETWEEN 1 AND 128),
 runner_id TEXT NOT NULL CHECK(length(CAST(runner_id AS BLOB)) BETWEEN 1 AND 128),
 runner_key_id TEXT NOT NULL CHECK(length(CAST(runner_key_id AS BLOB)) BETWEEN 1 AND 128),
 project_ref TEXT NOT NULL CHECK(length(CAST(project_ref AS BLOB)) BETWEEN 1 AND 128),
 environment_id TEXT NOT NULL CHECK(length(CAST(environment_id AS BLOB)) BETWEEN 1 AND 128),
 environment_origin TEXT NOT NULL CHECK(length(CAST(environment_origin AS BLOB)) BETWEEN 1 AND 2048),
 environment_class TEXT NOT NULL CHECK(environment_class IN ('staging','sandbox')),
 public_key_digest TEXT NOT NULL CHECK(length(public_key_digest)=64 AND public_key_digest NOT GLOB '*[^0-9a-f]*'),
 established_rcb_id TEXT NOT NULL CHECK(length(established_rcb_id)=36 AND substr(established_rcb_id,1,4)='rcb_' AND substr(established_rcb_id,5) NOT GLOB '*[^0-9a-f]*'),
 established_binding_digest TEXT NOT NULL CHECK(length(established_binding_digest)=64 AND established_binding_digest NOT GLOB '*[^0-9a-f]*'),
 established_at_ms INTEGER NOT NULL CHECK(established_at_ms>=0),
 PRIMARY KEY(workspace_id,runner_id),
 FOREIGN KEY(workspace_id,runner_id,runner_key_id)
  REFERENCES canary_runner_keys(workspace_id,runner_id,key_id));
CREATE INDEX idx_runner_context_affinities_project_runner
 ON canary_runner_context_affinities(workspace_id,project_ref,runner_id);
CREATE TABLE canary_runner_context_affinity_backfill_guard(ok INTEGER NOT NULL CHECK(ok=1));
INSERT INTO canary_runner_context_affinity_backfill_guard(ok)
SELECT CASE WHEN EXISTS(
 SELECT 1 FROM (
  SELECT workspace_id,runner_id
  FROM canary_runner_context_bindings
  WHERE first_claimed_at_ms IS NOT NULL
  GROUP BY workspace_id,runner_id
  HAVING MIN(project_ref)<>MAX(project_ref) OR MIN(environment_id)<>MAX(environment_id)
   OR MIN(environment_origin)<>MAX(environment_origin) OR MIN(environment_class)<>MAX(environment_class)
   OR MIN(runner_key_id)<>MAX(runner_key_id) OR MIN(public_key_digest)<>MAX(public_key_digest)
 )
) OR EXISTS(
 SELECT 1 FROM canary_runner_context_bindings active
 JOIN (
  SELECT workspace_id,runner_id,MIN(project_ref) AS project_ref,MIN(environment_id) AS environment_id,
   MIN(environment_origin) AS environment_origin,MIN(environment_class) AS environment_class,
   MIN(runner_key_id) AS runner_key_id,MIN(public_key_digest) AS public_key_digest
  FROM canary_runner_context_bindings
  WHERE first_claimed_at_ms IS NOT NULL
  GROUP BY workspace_id,runner_id
 ) claimed ON claimed.workspace_id=active.workspace_id AND claimed.runner_id=active.runner_id
 WHERE active.status='active' AND (active.project_ref<>claimed.project_ref OR active.environment_id<>claimed.environment_id
  OR active.environment_origin<>claimed.environment_origin OR active.environment_class<>claimed.environment_class
  OR active.runner_key_id<>claimed.runner_key_id OR active.public_key_digest<>claimed.public_key_digest)
) THEN 0 ELSE 1 END;
INSERT INTO canary_runner_context_affinities(
 workspace_id,runner_id,runner_key_id,project_ref,environment_id,environment_origin,environment_class,
 public_key_digest,established_rcb_id,established_binding_digest,established_at_ms)
SELECT b.workspace_id,b.runner_id,b.runner_key_id,b.project_ref,b.environment_id,b.environment_origin,b.environment_class,
 b.public_key_digest,b.rcb_id,b.binding_digest,b.first_claimed_at_ms
FROM canary_runner_context_bindings b
WHERE b.first_claimed_at_ms IS NOT NULL AND NOT EXISTS(
 SELECT 1 FROM canary_runner_context_bindings earlier
 WHERE earlier.workspace_id=b.workspace_id AND earlier.runner_id=b.runner_id AND earlier.first_claimed_at_ms IS NOT NULL
 AND (earlier.first_claimed_at_ms<b.first_claimed_at_ms OR (earlier.first_claimed_at_ms=b.first_claimed_at_ms AND earlier.rcb_id<b.rcb_id)));
DROP TABLE canary_runner_context_affinity_backfill_guard;
"""

_ENVIRONMENT_COLUMNS = (
    "attestation_text", "attestation_version", "attested_by", "attested_at", "proof_method",
    "proof_version", "normalization_version", "challenge_generation", "challenge_digest",
    "challenge_token", "challenge_created_at", "challenge_expires_at", "last_check_at",
    "last_failure_code", "verified_at", "proof_expires_at", "revoked_at", "revoked_by",
    "revoked_reason",
    "verification_record_digest",
)


def ensure_canary_environment_schema(conn: sqlite3.Connection) -> None:
    """Bring direct in-process construction to migration-7 schema parity.

    Migrated production databases take the same statements through ``Migrator``.  Unit/control
    plane construction intentionally owns a runtime schema too, so add only missing columns here.
    """
    present = {row[1] for row in conn.execute("PRAGMA table_info(canary_environments)")}
    for statement in CANARY_ENVIRONMENT_VERIFICATION_MIGRATION.strip().split(";"):
        statement = statement.strip()
        if not statement:
            continue
        if statement.startswith("ALTER TABLE"):
            column = statement.split()[5]
            if column in present:
                continue
            conn.execute(statement)
            present.add(column)
        else:
            conn.execute(statement)
    present = {row[1] for row in conn.execute("PRAGMA table_info(canary_environments)")}
    if "attestation_acknowledgement" not in present:
        conn.execute(CANARY_ENVIRONMENT_ATTESTATION_ACK_MIGRATION.strip())


def _sqlite_schema_statements(script: str) -> list[str]:
    """Split a frozen SQLite script without splitting trigger bodies."""
    statements: list[str] = []
    buffer = ""
    for line in script.splitlines(keepends=True):
        buffer += line
        if sqlite3.complete_statement(buffer):
            statements.append(buffer.strip())
            buffer = ""
    if buffer.strip():
        raise RuntimeError("runner context schema migration is incomplete")
    return statements


def _apply_runner_context_schema_script(conn: sqlite3.Connection, script: str, *, label: str) -> None:
    """Run direct-runtime DDL atomically; ``executescript`` would commit partial state."""
    savepoint = "runner_context_schema_apply"
    conn.execute(f"SAVEPOINT {savepoint}")
    try:
        for statement in _sqlite_schema_statements(script):
            if statement:
                conn.execute(statement)
    except Exception as error:
        conn.execute(f"ROLLBACK TO SAVEPOINT {savepoint}")
        conn.execute(f"RELEASE SAVEPOINT {savepoint}")
        raise RuntimeError(f"runner context {label} schema initialization failed") from error
    conn.execute(f"RELEASE SAVEPOINT {savepoint}")


def ensure_runner_context_schema(conn: sqlite3.Connection) -> None:
    """Apply the v16 tables atomically for direct ControlPlane construction.

    A partially provisioned context schema is unsafe: bindings could appear valid while
    their submission audit/link table is absent, so fail closed instead of repairing it.
    """
    tables = {
        "canary_runner_context_bindings",
        "canary_runner_context_projection_links",
        "canary_runner_context_events",
    }
    present = {row[0] for row in conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'"
    )}
    found = tables & present
    if found and found != tables:
        raise RuntimeError("runner context binding schema is partially initialized")
    if not found:
        conn.executescript(RUNNER_CONTEXT_BINDINGS_MIGRATION)
        conn.executescript(RUNNER_CONTEXT_ONE_ACTIVE_PER_RUNNER_MIGRATION)
    # A names-only or fragment check is unsafe: a hand-created table can omit the
    # composite FK/check that keeps pairing authorization from becoming broader
    # authority.  Compare the frozen v16 definitions, then independently inspect
    # columns and FK shapes so SQLite parser normalization cannot hide a substitution.
    def normalize(sql: object) -> str:
        return re.sub(r"\s+", "", str(sql).lower())

    tables = (
        "canary_runner_context_bindings",
        "canary_runner_context_projection_links",
        "canary_runner_context_events",
    )
    expected_columns = {
        "canary_runner_context_bindings": (
            "rcb_id", "workspace_id", "project_ref", "environment_id", "runner_id", "runner_key_id",
            "environment_origin", "environment_class", "binding_digest", "public_key_digest",
            "verification_record_digest", "binding_json", "status", "created_by", "created_role",
            "issued_at_ms", "expires_at_ms", "first_claimed_at_ms", "revoked_by", "revoked_at_ms",
            "revoke_reason", "purge_at_ms",
        ),
        "canary_runner_context_projection_links": (
            "workspace_id", "project_ref", "approval_id", "run_id", "environment_id", "runner_id",
            "runner_key_id", "rcb_id", "binding_digest", "projection_digest", "created_at_ms",
        ),
        "canary_runner_context_events": (
            "rce_id", "workspace_id", "project_ref", "environment_id", "runner_id", "runner_key_id",
            "rcb_id", "action", "actor_class", "actor_id", "reason_code", "binding_digest",
            "created_at_ms", "purge_at_ms",
        ),
    }
    expected_fks = {
        "canary_runner_context_bindings": {
            ("canary_environments", frozenset({
                ("workspace_id", "workspace_id"), ("project_ref", "project_ref"),
                ("environment_id", "environment_id"),
            })),
            ("canary_runner_keys", frozenset({
                ("workspace_id", "workspace_id"), ("runner_id", "runner_id"),
                ("runner_key_id", "key_id"),
            })),
        },
        "canary_runner_context_projection_links": {
            ("canary_approval_projections", frozenset({
                ("workspace_id", "workspace_id"), ("project_ref", "project_ref"),
                ("approval_id", "approval_id"), ("run_id", "run_id"),
                ("environment_id", "environment_id"), ("runner_id", "runner_id"),
                ("runner_key_id", "runner_key_id"), ("projection_digest", "projection_digest"),
            })),
            ("canary_runner_context_bindings", frozenset({
                ("workspace_id", "workspace_id"), ("project_ref", "project_ref"),
                ("environment_id", "environment_id"), ("runner_id", "runner_id"),
                ("runner_key_id", "runner_key_id"), ("rcb_id", "rcb_id"),
                ("binding_digest", "binding_digest"),
            })),
        },
        "canary_runner_context_events": {
            ("canary_runner_context_bindings", frozenset({
                ("workspace_id", "workspace_id"), ("project_ref", "project_ref"),
                ("environment_id", "environment_id"), ("runner_id", "runner_id"),
                ("runner_key_id", "runner_key_id"), ("rcb_id", "rcb_id"),
                ("binding_digest", "binding_digest"),
            })),
        },
    }
    for table in tables:
        match = re.search(
            rf"CREATE TABLE {re.escape(table)}\((.*?)\);", RUNNER_CONTEXT_BINDINGS_MIGRATION,
            flags=re.DOTALL,
        )
        row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)
        ).fetchone()
        if match is None or row is None or row[0] is None or normalize(row[0]) != normalize(
            f"CREATE TABLE {table}({match.group(1)})"
        ):
            raise RuntimeError("runner context binding schema does not match migration 16")
        columns = tuple(row[1] for row in conn.execute(f"PRAGMA table_info({table})"))
        if columns != expected_columns[table]:
            raise RuntimeError("runner context binding schema columns do not match migration 16")
        grouped: dict[int, list[sqlite3.Row | tuple]] = {}
        for foreign in conn.execute(f"PRAGMA foreign_key_list({table})"):
            grouped.setdefault(foreign[0], []).append(foreign)
        actual_fks = {
            (rows[0][2], frozenset((row[3], row[4]) for row in rows))
            for rows in grouped.values()
        }
        if actual_fks != expected_fks[table]:
            raise RuntimeError("runner context binding schema foreign keys do not match migration 16")

    expected_indexes = (
        "idx_runner_context_one_active", "idx_runner_context_runner_status_expiry",
        "idx_runner_context_purge", "idx_canary_approval_projection_context_digest",
        "idx_runner_context_links_binding", "idx_runner_context_events_purge",
    )
    for index in expected_indexes:
        match = re.search(
            rf"(CREATE (?:UNIQUE )?INDEX {re.escape(index)}\s+ON .*?);",
            RUNNER_CONTEXT_BINDINGS_MIGRATION, flags=re.DOTALL,
        )
        row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='index' AND name=?", (index,)
        ).fetchone()
        if match is None or row is None or row[0] is None or normalize(row[0]) != normalize(match.group(1)):
            raise RuntimeError("runner context binding schema indexes are incomplete")
    row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='index' AND name='idx_runner_context_one_active_per_runner'"
    ).fetchone()
    expected = re.search(
        r"(CREATE UNIQUE INDEX idx_runner_context_one_active_per_runner\s+ON .*?);",
        RUNNER_CONTEXT_ONE_ACTIVE_PER_RUNNER_MIGRATION, flags=re.DOTALL,
    )
    if expected is None or row is None or row[0] is None or normalize(row[0]) != normalize(expected.group(1)):
        raise RuntimeError("runner context binding schema indexes are incomplete")
    reaper_indexes = (
        "idx_runner_context_active_expiry_order", "idx_runner_context_terminal_cancel_order",
        "idx_runner_context_terminal_purge_order", "idx_runner_context_links_binding_run",
        "idx_runner_context_events_binding_purge", "idx_canary_approval_context_awaiting",
        "idx_canary_runs_context_pregrant", "idx_canary_approval_pending_discovery_order",
        "idx_canary_runs_pending_approval_discovery", "idx_runner_context_dashboard_history",
        "idx_canary_runners_dashboard_selector", "idx_canary_runner_keys_dashboard_selector",
        "idx_runner_context_binding_cancellation_ref", "idx_runner_context_cancellation_queue_order",
    )
    found_reaper = {
        row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name IN (%s)"
            % ",".join("?" for _ in reaper_indexes), reaper_indexes,
        )
    }
    reaper_aux = {
        "canary_runner_context_cancellation_queue",
        "trg_runner_context_cancellation_queue_insert_guard",
        "trg_runner_context_cancellation_queue_update_guard",
    }
    found_reaper_aux = {
        row[0] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE name IN (%s)"
            % ",".join("?" for _ in reaper_aux), tuple(reaper_aux),
        )
    }
    if not found_reaper:
        if found_reaper_aux:
            raise RuntimeError("runner context reaper index schema is partially initialized")
        _apply_runner_context_schema_script(conn, RUNNER_CONTEXT_REAPER_INDEXES_MIGRATION, label="reaper")
    elif found_reaper != set(reaper_indexes):
        raise RuntimeError("runner context reaper index schema is partially initialized")
    for index in reaper_indexes:
        match = re.search(
            rf"(CREATE (?:UNIQUE )?INDEX {re.escape(index)}\s+ON .*?);",
            RUNNER_CONTEXT_REAPER_INDEXES_MIGRATION, flags=re.DOTALL,
        )
        row = conn.execute("SELECT sql FROM sqlite_master WHERE type='index' AND name=?", (index,)).fetchone()
        if match is None or row is None or row[0] is None or normalize(row[0]) != normalize(match.group(1)):
            raise RuntimeError("runner context reaper index schema does not match migration 18")
    queue_table = "canary_runner_context_cancellation_queue"
    queue_row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (queue_table,)
    ).fetchone()
    queue_expected = re.search(
        rf"CREATE TABLE {queue_table}\((.*?)\);", RUNNER_CONTEXT_REAPER_INDEXES_MIGRATION,
        flags=re.DOTALL,
    )
    if (
        queue_expected is None or queue_row is None or queue_row[0] is None
        or normalize(queue_row[0]) != normalize(f"CREATE TABLE {queue_table}({queue_expected.group(1)})")
    ):
        raise RuntimeError("runner context cancellation queue schema does not match migration 18")
    queue_columns = tuple(row[1] for row in conn.execute(f"PRAGMA table_info({queue_table})"))
    if queue_columns != (
        "workspace_id", "project_ref", "environment_id", "runner_id", "runner_key_id",
        "rcb_id", "binding_digest", "binding_expires_at_ms", "last_scanned_run_id",
    ):
        raise RuntimeError("runner context cancellation queue columns do not match migration 18")
    queue_fks: dict[int, list[sqlite3.Row | tuple]] = {}
    for foreign in conn.execute(f"PRAGMA foreign_key_list({queue_table})"):
        queue_fks.setdefault(foreign[0], []).append(foreign)
    if {
        (rows[0][2], frozenset((item[3], item[4]) for item in rows))
        for rows in queue_fks.values()
    } != {
        ("canary_runner_context_bindings", frozenset({
            ("workspace_id", "workspace_id"), ("project_ref", "project_ref"),
            ("environment_id", "environment_id"), ("runner_id", "runner_id"),
            ("runner_key_id", "runner_key_id"), ("rcb_id", "rcb_id"),
            ("binding_digest", "binding_digest"), ("binding_expires_at_ms", "expires_at_ms"),
        })),
    }:
        raise RuntimeError("runner context cancellation queue foreign keys do not match migration 18")
    for trigger in (
        "trg_runner_context_cancellation_queue_insert_guard",
        "trg_runner_context_cancellation_queue_update_guard",
    ):
        trigger_row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (trigger,)
        ).fetchone()
        trigger_expected = re.search(
            rf"(CREATE TRIGGER {re.escape(trigger)}\b.*?END;)",
            RUNNER_CONTEXT_REAPER_INDEXES_MIGRATION, flags=re.DOTALL,
        )
        if (
            trigger_expected is None or trigger_row is None or trigger_row[0] is None
            # SQLite stores trigger text without the script terminator.  The body,
            # predicate and trigger identity remain part of the closed comparison.
            or normalize(trigger_row[0]).rstrip(";")
            != normalize(trigger_expected.group(1)).rstrip(";")
        ):
            raise RuntimeError("runner context cancellation queue triggers do not match migration 18")
    affinity_table = "canary_runner_context_affinities"
    affinity_index = "idx_runner_context_affinities_project_runner"
    affinity_guard = "canary_runner_context_affinity_backfill_guard"
    affinity_table_row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (affinity_table,)
    ).fetchone()
    affinity_index_row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='index' AND name=?", (affinity_index,)
    ).fetchone()
    affinity_guard_row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (affinity_guard,)
    ).fetchone()
    if affinity_table_row is None and affinity_index_row is None and affinity_guard_row is None:
        _apply_runner_context_schema_script(conn, RUNNER_CONTEXT_AFFINITIES_MIGRATION, label="affinity")
        affinity_table_row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (affinity_table,)
        ).fetchone()
        affinity_index_row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='index' AND name=?", (affinity_index,)
        ).fetchone()
    elif affinity_table_row is None or affinity_index_row is None or affinity_guard_row is not None:
        raise RuntimeError("runner context affinity schema is partially initialized")
    affinity_table_expected = re.search(
        rf"CREATE TABLE {affinity_table}\((.*?)\);", RUNNER_CONTEXT_AFFINITIES_MIGRATION, flags=re.DOTALL,
    )
    affinity_index_expected = re.search(
        rf"(CREATE INDEX {affinity_index}\s+ON .*?);", RUNNER_CONTEXT_AFFINITIES_MIGRATION, flags=re.DOTALL,
    )
    if (
        affinity_table_expected is None or affinity_index_expected is None
        or affinity_table_row is None or affinity_table_row[0] is None
        or affinity_index_row is None or affinity_index_row[0] is None
        or normalize(affinity_table_row[0]) != normalize(
            f"CREATE TABLE {affinity_table}({affinity_table_expected.group(1)})"
        )
        or normalize(affinity_index_row[0]) != normalize(affinity_index_expected.group(1))
    ):
        raise RuntimeError("runner context affinity schema does not match migration 19")
    affinity_columns = tuple(row[1] for row in conn.execute(f"PRAGMA table_info({affinity_table})"))
    if affinity_columns != (
        "workspace_id", "runner_id", "runner_key_id", "project_ref", "environment_id",
        "environment_origin", "environment_class", "public_key_digest", "established_rcb_id",
        "established_binding_digest", "established_at_ms",
    ):
        raise RuntimeError("runner context affinity schema columns do not match migration 19")
    affinity_foreign = {
        (foreign[2], frozenset((row[3], row[4]) for row in rows))
        for foreign_id, rows in {
            foreign_id: [row for row in conn.execute(f"PRAGMA foreign_key_list({affinity_table})") if row[0] == foreign_id]
            for foreign_id in {row[0] for row in conn.execute(f"PRAGMA foreign_key_list({affinity_table})")}
        }.items()
        for foreign in [rows[0]]
    }
    if affinity_foreign != {
        ("canary_runner_keys", frozenset({
            ("workspace_id", "workspace_id"), ("runner_id", "runner_id"), ("runner_key_id", "key_id"),
        })),
    }:
        raise RuntimeError("runner context affinity schema foreign keys do not match migration 19")
    if conn.execute(
        "SELECT 1 FROM canary_runner_context_bindings b "
        "LEFT JOIN canary_runner_context_affinities a "
        "ON a.workspace_id=b.workspace_id AND a.runner_id=b.runner_id "
        "WHERE b.first_claimed_at_ms IS NOT NULL AND (a.workspace_id IS NULL "
        "OR a.runner_key_id<>b.runner_key_id OR a.project_ref<>b.project_ref "
        "OR a.environment_id<>b.environment_id OR a.environment_origin<>b.environment_origin "
        "OR a.environment_class<>b.environment_class OR a.public_key_digest<>b.public_key_digest) LIMIT 1"
    ).fetchone() is not None:
        raise RuntimeError("runner context affinity history does not match migration 19")
    if conn.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise RuntimeError("runner context binding schema foreign keys are invalid")


class CanaryStore:
    """Typed schema owner. Higher canary services are added in later packets."""

    def __init__(self, conn: sqlite3.Connection):
        if not isinstance(conn, sqlite3.Connection):
            raise TypeError("CanaryStore requires the ControlPlane SQLite connection")
        self.conn = conn
        self.conn.executescript(CANARY_STORE_SCHEMA)
        ensure_canary_environment_schema(conn)
        environment_columns = {
            row[1] for row in self.conn.execute("PRAGMA table_info(canary_environments)")
        }
        approval_columns = {
            row[1] for row in self.conn.execute("PRAGMA table_info(canary_approval_projections)")
        }
        has_control = self.conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='canary_control_generation'"
        ).fetchone() is not None
        has_environment_digest = "verification_record_digest" in environment_columns
        has_coordination_approval = "runner_key_id" in approval_columns
        if not has_environment_digest and not has_coordination_approval:
            # Standalone verifier/store tests do not construct the wider v5 runtime first.
            # This dependency is byte-compatible with v5 and remains owned there in migrations.
            self.conn.execute(
                "CREATE TABLE IF NOT EXISTS kill_switches("
                "scope TEXT PRIMARY KEY,reason TEXT NOT NULL,actor TEXT NOT NULL,tripped_at REAL NOT NULL)"
            )
            # Tolerate a pre-v15 Ops bootstrap, but never use its singleton as proof that the
            # complete coordination schema exists.
            if has_control:
                self.conn.executescript(
                    "DROP TRIGGER IF EXISTS canary_control_generation_insert;"
                    "DROP TRIGGER IF EXISTS canary_control_generation_update;"
                    "DROP TRIGGER IF EXISTS canary_control_generation_delete;"
                    "DROP TABLE canary_control_generation;"
                )
            self.conn.executescript(CANARY_COORDINATION_MIGRATION)
        elif not (has_environment_digest and has_coordination_approval and has_control):
            raise RuntimeError("canary coordination schema is partially initialized")
        ensure_runner_context_schema(self.conn)
