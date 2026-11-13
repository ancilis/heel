// SPDX-License-Identifier: LicenseRef-Heel-Commercial

/** Closed same-origin browser client for verified canary activation and history. */

const CONTROL_PLANE_PREFIX = "/api/control-plane";
const MAX_REQUEST_BYTES = 272 * 1024;
const MAX_RESPONSE_BYTES = 272 * 1024;
const DEFAULT_TIMEOUT_MS = 15_000;
const WORKSPACE_REF = /^ws_[0-9a-f]{16}$/;
const PROJECT_REF = /^prj_[0-9a-f]{32}$/;
const RUN_REF = /^crun_[0-9a-f]{32}$/;
const ENVIRONMENT_REF = /^env_[0-9a-f]{32}$/;
const PAIRING_REF = /^pending_[0-9a-f]{32}$/;
// The control plane mints 32 random bytes as padded standard base64; the runner CLI accepts exactly
// this grammar (heel/runner/daemon.py `_INVITATION`), so the browser renders nothing else.
const INVITATION_TOKEN = /^[A-Za-z0-9+/]{43}=$/;
// The Worker's runner-route segment grammar; a runner id outside it is never sent.
const RUNNER_REF = /^[A-Za-z0-9_-]{1,128}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const ID = /^[A-Za-z0-9._:-]{1,256}$/;
const BASE64_SIGNATURE = /^(?:[A-Za-z0-9+/]{4}){21}[A-Za-z0-9+/]{2}==$/;

export type CanaryTransport = (path: string, init: RequestInit) => Promise<Response>;
type JsonRecord = Record<string, unknown>;

export interface CanaryApiOptions {
  transport?: CanaryTransport;
  timeoutMs?: number;
}

export interface CanaryRunStatus {
  runId: string;
  approvalId: string;
  grantId: string | null;
  status: string;
  executionDisposition: string | null;
  errorCategory: string;
  stopReason: string;
  sourceEventSequence: number;
  quotaState: string;
  killSwitchGeneration: number;
  stopGeneration: number;
  stopDeadlineMs: number | null;
  stopAcknowledgedAtMs: number | null;
  stopAckLate: boolean;
}

export interface CanaryRunProgress {
  available: boolean;
  currentScenarioId: string | null;
  scenariosCompleted: number | null;
  scenariosTotal: number | null;
  requestsStarted: number | null;
  requestsCompleted: number | null;
  remainingRequests: number | null;
  remainingWallMs: number | null;
  retriesUsed: number | null;
  redactionCount: number | null;
  localResultReady: boolean;
}

export interface CanaryRunDashboard {
  approvalControlGeneration: number;
  run: CanaryRunStatus;
  progress: CanaryRunProgress;
}

export interface CanaryDisclosureMetadata {
  projectionDigest: string;
  projectionBytes: number;
  scenarioCount: number;
  findingCount: number;
}

/** Every status a disclosure request row can hold (`canary_store.py` CHECK); nothing else is accepted. */
export type CanaryDisclosureStatus =
  | "local_result_ready" | "awaiting_disclosure_approval" | "permitted" | "synchronized" | "local_only" | "expired";

/** The human `view` read of a run's disclosure: the runner-registered metadata and its status, never findings bytes. */
export interface CanaryDisclosureState {
  requestId: string;
  runId: string;
  status: CanaryDisclosureStatus;
  projection: CanaryDisclosureMetadata;
}

export type CanaryAssessmentOutcome = "blocked" | "observed" | "inconclusive";

export interface CanaryFindingObservation {
  semantic_role: string;
  status_code: number;
  body_shape: string;
  truncation_state: "complete" | "truncated";
}

export interface CanaryFinding {
  title: string;
  reachability_rationale: string;
  confidence: "low" | "medium" | "high";
  recommended_control: string;
  regression_suggestion: string;
}

export interface CanaryScenarioResult {
  ordinal: number;
  scenario_id: string;
  adapter_version: string;
  assessment_outcome: CanaryAssessmentOutcome;
  route: { method: "GET" | "HEAD"; route_template: string };
  observations: readonly CanaryFindingObservation[];
  finding: CanaryFinding | null;
  containment_codes: readonly string[];
  redaction_count: number;
  local_evidence_refs: readonly string[];
}

/** The synchronized, runner-signed redacted projection exactly as `GET …/findings` returns it (validated below). */
export interface CanaryFindingsProjection {
  schema_version: "heel.canary-findings-projection.v1";
  projection_id: string;
  run_id: string;
  grant_id: string;
  workspace_id: string;
  project_id: string;
  environment_id: string;
  manifest_digest: string;
  approval_projection_digest: string;
  grant_digest: string;
  engine_version: string;
  adapter_versions: readonly string[];
  started_at_ms: number;
  finished_at_ms: number;
  assessment_outcome: CanaryAssessmentOutcome;
  scenario_results: readonly CanaryScenarioResult[];
  containment_codes: readonly string[];
  redaction_count: number;
  projection_digest: string;
  signing_key_id: string;
  signature_b64: string;
}

export interface CanaryApprovalSummary {
  approvalId: string;
  runId: string;
  projectionDigest: string;
  origin: string;
  hostname: string;
  routes: readonly string[];
  scenarios: readonly string[];
  requestBudget: number;
  durationSeconds: number;
  egress: string;
}

export type ScenarioExecutionSupport = "static_only" | "runner_supported";
export type ScenarioBindableCatalogId = "anonymous_authenticated_read" | "plan_entitlement_read";

/** One effective library or current private custom scenario exactly as the workspace listing returns it. */
export interface ScenarioLibraryEntry {
  id: string;
  source: "library" | "custom";
  revision: number | null;
  definitionDigest: string;
  /** The full evaluation definition (digest subject); browser-local assessment uses it unchanged. */
  definition: Readonly<Record<string, unknown>>;
  objective: string;
  category: string;
  kind: string;
  pack: string;
  recommendedControl: string;
  mechanismId: string;
  applicability: "unknown";
  applicabilityRule: string;
  evidenceState: "inferred" | "customer_declared";
  executionSupport: ScenarioExecutionSupport;
  catalogScenarioId: string | null;
  bindingVersion: 1 | null;
  coverageStatement: string | null;
  prerequisites: readonly string[];
}

export interface ScenarioLibrary {
  libraryDigest: string;
  engineVersion: string;
  bindingVersion: 1;
  customCoverageStatements: Readonly<Record<ScenarioBindableCatalogId, string>>;
  scenarios: readonly ScenarioLibraryEntry[];
}

export interface CustomScenarioInput {
  definition: Readonly<Record<string, unknown>>;
  supersedesRevision: number | null;
  executionBinding: null | { catalogScenarioId: ScenarioBindableCatalogId; coverageAck: string };
}

export interface ScenarioPlanAction {
  catalogScenarioId: string;
  method: "GET" | "HEAD";
  routeTemplate: string;
}

export interface ScenarioBindingItem extends ScenarioPlanAction {
  libraryScenarioId: string;
  source: "library" | "custom";
  definitionDigest: string;
}

/** A write-once association frozen before approval; its display snapshot never follows later edits. */
export interface FrozenScenarioBinding extends ScenarioBindingItem {
  revision: number | null;
  libraryDigest: string;
  bindingVersion: 1;
  approvalId: string;
  projectionDigest: string;
  manifestDigest: string;
  display: Readonly<{ objective: string; mechanismId: string; pack: string; coverageStatement: string }>;
  boundAtMs: number;
}

export interface RunScenarioBindingsView {
  runId: string;
  approvalId: string;
  projectionDigest: string;
  manifestDigest: string;
  acceptingBindings: boolean;
  actions: readonly ScenarioPlanAction[];
  bindings: readonly FrozenScenarioBinding[];
  libraryDigest: string;
}

export interface CanaryPendingApprovalRequest extends CanaryApprovalSummary {
  submittedAtMs: number;
  expiresAtMs: number;
}

export interface RunnerContextBindingRecord {
  bindingId: string; bindingDigest: string; environmentId: string; origin: string;
  environmentClass: "staging" | "sandbox"; verificationRecordDigest: string;
  runnerId: string; runnerKeyId: string; status: "active" | "revoked" | "expired";
  issuedAtMs: number; expiresAtMs: number; firstClaimedAtMs: number | null;
}
export interface RunnerContextRunner {
  runnerId: string; runnerKeyId: string; displayName: string; fingerprint: string;
  runnerVersion: string; adapterVersions: readonly string[]; status: "active";
}
/** A pending runner pairing as the control plane shows it to the approving owner or admin. */
export interface RunnerPairingView {
  pairingId: string; runnerId: string; pairingPhrase: string; fingerprint: string; status: "pending"; expiresAt: number;
}
export interface RunnerContextBindingDashboard {
  runners: readonly RunnerContextRunner[]; bindings: readonly RunnerContextBindingRecord[];
}

function parseRunnerContextBinding(value: unknown): RunnerContextBindingRecord {
  if (!exact(value, ["schema_version", "binding_id", "workspace_id", "project_id", "environment", "runner_binding", "authorization", "issued_at_ms", "expires_at_ms", "binding_digest", "signing_key_id", "signature_b64"])
    || value.schema_version !== "heel.runner-context-binding.v1" || !/^rcb_[0-9a-f]{32}$/.test(String(value.binding_id))
    || !identifier(value.workspace_id) || !identifier(value.project_id) || !digest(value.binding_digest)
    || !identifier(value.signing_key_id) || typeof value.signature_b64 !== "string" || !BASE64_SIGNATURE.test(value.signature_b64)
    || !integer(value.issued_at_ms) || !integer(value.expires_at_ms) || value.expires_at_ms <= value.issued_at_ms
    || !exact(value.environment, ["environment_id", "origin", "environment_class", "verification_record_digest"])
    || !ENVIRONMENT_REF.test(String(value.environment.environment_id)) || typeof value.environment.origin !== "string"
    || !["staging", "sandbox"].includes(String(value.environment.environment_class)) || !digest(value.environment.verification_record_digest)
    || !exact(value.runner_binding, ["runner_id", "runner_key_id", "public_key_digest"])
    || !identifier(value.runner_binding.runner_id) || !identifier(value.runner_binding.runner_key_id) || !digest(value.runner_binding.public_key_digest)
    || !exact(value.authorization, ["user_id", "role"]) || !identifier(value.authorization.user_id)
    || !["owner", "admin"].includes(String(value.authorization.role))) invalidResponse();
  return deepFreeze({ bindingId: value.binding_id as string, bindingDigest: value.binding_digest as string,
    environmentId: value.environment.environment_id as string, origin: value.environment.origin as string,
    environmentClass: value.environment.environment_class as "staging" | "sandbox",
    verificationRecordDigest: value.environment.verification_record_digest as string,
    runnerId: value.runner_binding.runner_id as string, runnerKeyId: value.runner_binding.runner_key_id as string,
    status: "active", issuedAtMs: value.issued_at_ms as number, expiresAtMs: value.expires_at_ms as number,
    firstClaimedAtMs: null });
}

export interface VerifiedEnvironmentRecord {
  schemaVersion: "VerifiedEnvironment.v1";
  environmentId: string;
  origin: string;
  environmentClass: "staging" | "sandbox" | "production";
  status: "pending" | "verified" | "revoked";
  proofMethod: "https-file" | "dns-txt";
  challengeGeneration: number;
  challengeExpiresAt: number | null;
  proofExpiresAt: number | null;
  lastFailureCode: string | null;
  verificationRecordDigest: string | null;
  isExecutable: boolean;
}

/** One pending record's current proof instruction; it lives only in the caller's memory, never in storage. */
export interface PendingEnvironmentProof {
  environmentId: string;
  origin: string;
  environmentClass: VerifiedEnvironmentRecord["environmentClass"];
  proofMethod: VerifiedEnvironmentRecord["proofMethod"];
  token: string;
  httpUrl: string;
  dnsRecord: string;
  challengeGeneration: number;
  expiresAt: number;
}

const PUBLIC_MESSAGES = Object.freeze({
  invalid_request: "Heel could not safely prepare that canary request.",
  invalid_response: "Heel Cloud returned an invalid canary response.",
  unavailable: "Heel Cloud is temporarily unavailable. Your local result is unchanged.",
  invalid_canary_projection: "The signed rehearsal plan is invalid or no longer matches this project.",
  invalid_canary_approval: "The rehearsal approval did not match the immutable plan.",
  hostname_confirmation_mismatch: "Retype the exact verified staging hostname.",
  environment_not_executable: "Verify a staging or sandbox environment before this rehearsal.",
  canary_quota_exceeded: "This workspace has reached its canary rehearsal allowance.",
  canary_state_conflict: "The rehearsal changed. Refresh its status before trying again.",
  event_sequence_conflict: "Runner progress could not be ordered safely.",
  disclosure_permit_required: "Review the separate summary disclosure before sharing it.",
  disclosure_permit_expired: "That one-use disclosure permit expired. Review it again.",
  permit_consumed: "That disclosure permit has already been used.",
  canary_run_not_found: "That rehearsal is unavailable in this project.",
  canary_authority_unavailable: "Canary signing authority is temporarily unavailable.",
  recent_auth_required: "Sign in again before this sensitive action.",
  same_origin_required: "Open this action from the signed-in Heel dashboard.",
  invalid_environment_request: "Heel could not safely prepare that environment proof.",
  invalid_environment_check: "That environment proof check is invalid.",
  environment_not_found: "That environment is unavailable in this project.",
  environment_check_cooldown: "Wait briefly before checking this proof again.",
  invalid_environment_challenge: "That pending proof request is invalid.",
  environment_challenge_expired: "This pending proof expired. Issue a replacement proof for the same target.",
  environment_challenge_missing: "This pending proof is no longer available. Issue a replacement proof for the same target.",
  environment_challenge_closed: "This target is no longer pending, so its proof cannot be reopened.",
  environment_challenge_live: "This pending proof is still current. Resume it instead of replacing it.",
  quota_exceeded: "This workspace has reached its current allowance.",
  invalid_runner_pairing: "That runner pairing request is invalid or expired.",
  runner_pairing_not_found: "That runner pairing request is no longer available.",
  invalid_runner_revocation: "That runner is already revoked or no longer available in this workspace.",
  not_found: "That workspace library is unavailable.",
  browser_session_required: "Open the scenario library from the signed-in Heel dashboard.",
  forbidden: "Your workspace role cannot change the scenario library.",
  invalid_custom_request: "Heel could not safely accept that custom scenario request.",
  invalid_scenario: "The custom scenario did not pass validation.",
  custom_definition_too_large: "The custom scenario definition is too large.",
  library_id_collision: "That identifier belongs to the shared library. Choose a workspace identifier.",
  revision_conflict: "This custom scenario changed. Reload it before saving a new revision.",
  binding_ack_required: "Confirm the exact executed-check statement to bind a runner check.",
  custom_scenario_limit: "This workspace has reached its custom scenario limit.",
  custom_revision_limit: "This custom scenario has reached its revision limit.",
  run_not_found: "That rehearsal is unavailable in this project.",
  run_bindings_frozen: "Library bindings are frozen once a rehearsal leaves approval.",
  run_bindings_exist: "Library bindings for this rehearsal are already frozen.",
  projection_mismatch: "The signed plan changed. Refresh it before freezing bindings.",
  projection_unavailable: "The signed plan for this rehearsal is unavailable.",
  invalid_binding_request: "Heel could not safely prepare those library bindings.",
  action_not_in_plan: "A selected check is not an action in the signed plan.",
  binding_not_allowed: "That scenario is not bound to the selected runner check.",
  stale_definition: "A selected scenario changed. Reload the library before freezing bindings.",
} as const);

type CanaryErrorCode = keyof typeof PUBLIC_MESSAGES;
const PUBLIC_ERROR_CODES = new Set(Object.keys(PUBLIC_MESSAGES));

export class CanaryApiError extends Error {
  readonly code: CanaryErrorCode;
  readonly status: number;
  /** Validator messages for an invalid custom scenario only; bounded and plain text. */
  readonly details: readonly string[];

  constructor(code: string, status: number, details: readonly string[] = []) {
    const safeCode = (PUBLIC_ERROR_CODES.has(code) ? code : "unavailable") as CanaryErrorCode;
    super(PUBLIC_MESSAGES[safeCode]);
    this.name = "CanaryApiError";
    this.code = safeCode;
    this.status = status;
    this.details = Object.freeze(safeCode === "invalid_scenario" ? [...details] : []);
  }
}

async function sameOriginCanaryFetch(path: string, init: RequestInit): Promise<Response> {
  return fetch(path, init);
}

function record(value: unknown): value is JsonRecord {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exact(value: unknown, fields: readonly string[]): value is JsonRecord {
  if (!record(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function integer(value: unknown, minimum = 0, maximum = Number.MAX_SAFE_INTEGER): value is number {
  return Number.isSafeInteger(value) && (value as number) >= minimum && (value as number) <= maximum;
}

function nullableInteger(value: unknown): value is number | null {
  return value === null || integer(value);
}

function nullableFiniteNonnegative(value: unknown): value is number | null {
  return value === null || (typeof value === "number" && Number.isFinite(value) && value >= 0);
}

function identifier(value: unknown): value is string {
  return typeof value === "string" && ID.test(value);
}

function digest(value: unknown): value is string {
  return typeof value === "string" && DIGEST.test(value);
}

function closedString(value: unknown, maximum = 512): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= maximum
    && !/[\u0000-\u001f\u007f]/.test(value);
}

function validApprovalRouteSummary(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const matched = /^(GET|HEAD) (\/[\s\S]*)$/u.exec(value);
  if (matched === null) return false;
  const route = matched[2];
  return route.normalize("NFC") === route
    && new TextEncoder().encode(route).byteLength <= 1024
    && !/[\p{Cc}\uD800-\uDFFF]/u.test(route)
    && !route.includes("?") && !route.includes("#") && !route.includes("//");
}

function deepFreeze<T>(value: T): T {
  if (value !== null && typeof value === "object") {
    for (const nested of Object.values(value as Record<string, unknown>)) deepFreeze(nested);
    Object.freeze(value);
  }
  return value;
}

const SCENARIO_ID = /^[a-z0-9][a-z0-9._-]{2,127}$/;
const BINDABLE_CATALOG_IDS: readonly ScenarioBindableCatalogId[] = ["anonymous_authenticated_read", "plan_entitlement_read"];
const ROUTE_TEMPLATE = /^\/[A-Za-z0-9._~!$&'()*+,;=:@/{}-]{0,511}$/;
const MAX_CUSTOM_DEFINITION_BYTES = 4096;
const MAX_SCENARIO_BINDING_ITEMS = 8;

function plainJson(value: unknown, depth = 0): boolean {
  if (depth > 16) return false;
  if (value === null || typeof value === "boolean" || typeof value === "string") return true;
  if (typeof value === "number") return Number.isFinite(value);
  if (Array.isArray(value)) return value.length <= 256 && value.every((item) => plainJson(item, depth + 1));
  return record(value) && Object.keys(value).length <= 64
    && Object.values(value).every((item) => plainJson(item, depth + 1));
}

function parseLibraryEntry(value: unknown): ScenarioLibraryEntry {
  if (!exact(value, ["id", "source", "revision", "definition_digest", "definition", "mechanism_id", "applicability", "applicability_rule", "evidence_state", "execution_support", "catalog_scenario_id", "binding_version", "coverage_statement", "prerequisites"])
    || typeof value.id !== "string" || !SCENARIO_ID.test(value.id) || !digest(value.definition_digest)
    || !record(value.definition) || !plainJson(value.definition) || value.definition.id !== value.id
    || !closedString(value.definition.objective, 2000) || !closedString(value.definition.category, 128)
    || !closedString(value.definition.kind, 128) || !closedString(value.definition.recommended_control, 2000)
    || !closedString(value.mechanism_id, 128) || value.applicability !== "unknown"
    || !closedString(value.applicability_rule, 64)
    || !["static_only", "runner_supported"].includes(String(value.execution_support))
    || !Array.isArray(value.prerequisites) || value.prerequisites.length > 16
    || !value.prerequisites.every((item) => closedString(item, 256))) invalidResponse();
  const bound = value.execution_support === "runner_supported";
  if (bound !== (value.catalog_scenario_id !== null) || bound !== (value.binding_version === 1)
    || bound !== (value.coverage_statement !== null) || bound !== (value.prerequisites.length > 0)
    || (bound && (!identifier(value.catalog_scenario_id) || !closedString(value.coverage_statement, 512)))
    || (!bound && value.binding_version !== null)) invalidResponse();
  if (value.source === "library") {
    if (value.revision !== null || value.evidence_state !== "inferred") invalidResponse();
  } else if (value.source === "custom") {
    if (!integer(value.revision, 1) || value.evidence_state !== "customer_declared") invalidResponse();
  } else invalidResponse();
  const pack = value.definition.pack;
  return {
    id: value.id, source: value.source as "library" | "custom", revision: value.revision as number | null,
    definitionDigest: value.definition_digest, definition: value.definition,
    objective: value.definition.objective as string, category: value.definition.category as string,
    kind: value.definition.kind as string, pack: typeof pack === "string" ? pack : "custom",
    recommendedControl: value.definition.recommended_control as string, mechanismId: value.mechanism_id as string,
    applicability: "unknown", applicabilityRule: value.applicability_rule as string,
    evidenceState: value.evidence_state as "inferred" | "customer_declared",
    executionSupport: value.execution_support as ScenarioExecutionSupport,
    catalogScenarioId: value.catalog_scenario_id as string | null, bindingVersion: bound ? 1 : null,
    coverageStatement: value.coverage_statement as string | null, prerequisites: value.prerequisites as string[],
  };
}

function parsePlanAction(value: unknown): ScenarioPlanAction {
  if (!exact(value, ["catalog_scenario_id", "method", "route_template"]) || !identifier(value.catalog_scenario_id)
    || (value.method !== "GET" && value.method !== "HEAD") || typeof value.route_template !== "string"
    || !ROUTE_TEMPLATE.test(value.route_template)) invalidResponse();
  return { catalogScenarioId: value.catalog_scenario_id, method: value.method, routeTemplate: value.route_template };
}

function parseFrozenBinding(value: unknown, view: JsonRecord): FrozenScenarioBinding {
  if (!exact(value, ["catalog_scenario_id", "method", "route_template", "library_scenario_id", "source", "revision", "definition_digest", "library_digest", "binding_version", "approval_id", "projection_digest", "manifest_digest", "display", "bound_at_ms"])
    || typeof value.library_scenario_id !== "string" || !SCENARIO_ID.test(value.library_scenario_id)
    || !digest(value.definition_digest) || !digest(value.library_digest) || value.binding_version !== 1
    || value.approval_id !== view.approval_id || value.projection_digest !== view.projection_digest
    || value.manifest_digest !== view.manifest_digest || !integer(value.bound_at_ms)
    || !exact(value.display, ["objective", "mechanism_id", "pack", "coverage_statement"])
    || !closedString(value.display.objective, 500) || !closedString(value.display.mechanism_id, 128)
    || !closedString(value.display.pack, 64) || !closedString(value.display.coverage_statement, 512)) invalidResponse();
  if (!(value.source === "library" && value.revision === null) && !(value.source === "custom" && integer(value.revision, 1))) invalidResponse();
  const action = parsePlanAction({ catalog_scenario_id: value.catalog_scenario_id, method: value.method, route_template: value.route_template });
  return {
    ...action, libraryScenarioId: value.library_scenario_id, source: value.source as "library" | "custom",
    definitionDigest: value.definition_digest, revision: value.revision as number | null,
    libraryDigest: value.library_digest, bindingVersion: 1, approvalId: value.approval_id as string,
    projectionDigest: value.projection_digest as string, manifestDigest: value.manifest_digest as string,
    display: { objective: value.display.objective, mechanismId: value.display.mechanism_id,
      pack: value.display.pack, coverageStatement: value.display.coverage_statement },
    boundAtMs: value.bound_at_ms,
  };
}

function parseBindingsView(value: unknown, runRef: string): RunScenarioBindingsView {
  if (!exact(value, ["schema_version", "run_id", "approval_id", "projection_digest", "manifest_digest", "accepting_bindings", "actions", "bindings", "library_digest"])
    || value.schema_version !== "heel.run-scenario-bindings-view.v1" || value.run_id !== runRef
    || !identifier(value.approval_id) || !digest(value.projection_digest) || !digest(value.manifest_digest)
    || typeof value.accepting_bindings !== "boolean" || !Array.isArray(value.actions) || value.actions.length > 20
    || !Array.isArray(value.bindings) || value.bindings.length > MAX_SCENARIO_BINDING_ITEMS
    || !digest(value.library_digest) || (!value.accepting_bindings && value.actions.length !== 0)) invalidResponse();
  return deepFreeze({
    runId: runRef, approvalId: value.approval_id, projectionDigest: value.projection_digest,
    manifestDigest: value.manifest_digest, acceptingBindings: value.accepting_bindings,
    actions: value.actions.map(parsePlanAction),
    bindings: value.bindings.map((item) => parseFrozenBinding(item, value)),
    libraryDigest: value.library_digest,
  });
}

/** A bounded JSON body serialized by its caller (custom scenario definitions only). */
class PreserializedJson {
  constructor(readonly text: string) {}
}

function invalidRequest(): never {
  throw new CanaryApiError("invalid_request", 0);
}

function invalidResponse(): never {
  throw new CanaryApiError("invalid_response", 502);
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    if (typeof value === "string" && value.normalize("NFC") !== value) invalidRequest();
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value) || value < 0) invalidRequest();
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (!record(value)) invalidRequest();
  const fields = Object.keys(value).sort();
  return `{${fields.map((field) => `${JSON.stringify(field)}:${canonicalJson(value[field])}`).join(",")}}`;
}

function workspacePath(workspaceRef: string, suffix: string): string {
  if (!WORKSPACE_REF.test(workspaceRef)) invalidRequest();
  return `${CONTROL_PLANE_PREFIX}/v1/workspaces/${workspaceRef}${suffix}`;
}

function projectPath(workspaceRef: string, projectRef: string, suffix: string): string {
  if (!WORKSPACE_REF.test(workspaceRef) || !PROJECT_REF.test(projectRef)) invalidRequest();
  return `${CONTROL_PLANE_PREFIX}/v1/workspaces/${workspaceRef}/projects/${projectRef}${suffix}`;
}

function runPath(workspaceRef: string, projectRef: string, runRef: string, suffix = ""): string {
  if (!RUN_REF.test(runRef)) invalidRequest();
  return projectPath(workspaceRef, projectRef, `/canary-runs/${runRef}${suffix}`);
}

function environmentPath(workspaceRef: string, projectRef: string, suffix = ""): string {
  return projectPath(workspaceRef, projectRef, `/environments${suffix}`);
}

function metadataBody(schema: string, value: CanaryDisclosureMetadata): JsonRecord {
  if (!digest(value.projectionDigest) || !integer(value.projectionBytes, 1, 256 * 1024)
    || !integer(value.scenarioCount, 0, 4) || !integer(value.findingCount, 0, value.scenarioCount)) {
    invalidRequest();
  }
  return {
    schema_version: schema,
    projection_digest: value.projectionDigest,
    projection_bytes: value.projectionBytes,
    scenario_count: value.scenarioCount,
    finding_count: value.findingCount,
  };
}

function parseRunStatus(value: unknown, expectedRun: string): CanaryRunStatus {
  if (!exact(value, [
    "schema_version", "run_id", "approval_id", "grant_id", "status", "execution_disposition",
    "error_category", "stop_reason", "source_event_sequence", "quota_state",
    "kill_switch_generation", "stop_generation", "stop_deadline_ms",
    "stop_acknowledged_at_ms", "stop_ack_late",
  ]) || value.schema_version !== "heel.canary-run-status.v1" || value.run_id !== expectedRun
    || !identifier(value.approval_id)
    || !(value.grant_id === null || identifier(value.grant_id))
    || !["prepared", "awaiting_execution_approval", "approved", "claimed", "running", "stop_requested", "finalizing", "terminal", "cancelled", "expired"].includes(String(value.status))
    || !(value.execution_disposition === null || ["completed", "incomplete", "failed", "stopped"].includes(String(value.execution_disposition)))
    || !["none", "platform_fault", "runner_fault", "target_unavailable", "proof_expired", "dns_changed", "credential_unavailable", "version_mismatch", "budget_exhausted", "containment_rejected", "cloud_disconnected"].includes(String(value.error_category))
    || !["none", "local_emergency_stop", "cloud_stop", "runner_revoked", "target_revoked", "kill_switch"].includes(String(value.stop_reason))
    || !integer(value.source_event_sequence, -1) || !["unreserved", "reserved", "consumed", "refunded", "compensated"].includes(String(value.quota_state))
    || !integer(value.kill_switch_generation) || !integer(value.stop_generation)
    || !nullableInteger(value.stop_deadline_ms) || !nullableInteger(value.stop_acknowledged_at_ms)
    || typeof value.stop_ack_late !== "boolean") invalidResponse();
  return deepFreeze({
    runId: value.run_id as string,
    approvalId: value.approval_id as string,
    grantId: value.grant_id as string | null,
    status: value.status as string,
    executionDisposition: value.execution_disposition as string | null,
    errorCategory: value.error_category as string,
    stopReason: value.stop_reason as string,
    sourceEventSequence: value.source_event_sequence as number,
    quotaState: value.quota_state as string,
    killSwitchGeneration: value.kill_switch_generation as number,
    stopGeneration: value.stop_generation as number,
    stopDeadlineMs: value.stop_deadline_ms as number | null,
    stopAcknowledgedAtMs: value.stop_acknowledged_at_ms as number | null,
    stopAckLate: value.stop_ack_late as boolean,
  });
}

function parseRunDashboard(value: unknown, expectedRun: string): CanaryRunDashboard {
  if (!exact(value, ["schema_version", "approval_control_generation", "run", "progress"])
    || value.schema_version !== "heel.canary-run-dashboard.v1"
    || !integer(value.approval_control_generation)
    || !exact(value.progress, [
      "schema_version", "available", "current_scenario_id", "scenarios_completed",
      "scenarios_total", "requests_started", "requests_completed", "remaining_requests",
      "remaining_wall_ms", "retries_used", "redaction_count", "local_result_ready",
    ]) || value.progress.schema_version !== "heel.canary-run-progress.v1"
    || typeof value.progress.available !== "boolean"
    || !(value.progress.current_scenario_id === null || identifier(value.progress.current_scenario_id))
    || !nullableInteger(value.progress.scenarios_completed)
    || !nullableInteger(value.progress.scenarios_total)
    || !nullableInteger(value.progress.requests_started)
    || !nullableInteger(value.progress.requests_completed)
    || !nullableInteger(value.progress.remaining_requests)
    || !nullableInteger(value.progress.remaining_wall_ms)
    || !nullableInteger(value.progress.retries_used)
    || !nullableInteger(value.progress.redaction_count)
    || typeof value.progress.local_result_ready !== "boolean") invalidResponse();
  const numeric = [
    value.progress.scenarios_completed, value.progress.scenarios_total,
    value.progress.requests_started, value.progress.requests_completed,
    value.progress.remaining_requests, value.progress.remaining_wall_ms,
    value.progress.retries_used, value.progress.redaction_count,
  ];
  if ((!value.progress.available && numeric.some((item) => item !== null))
    || (value.progress.available && numeric.some((item) => item === null))) invalidResponse();
  if (value.progress.available && (
    (value.progress.scenarios_completed as number) > (value.progress.scenarios_total as number)
    || (value.progress.requests_completed as number) > (value.progress.requests_started as number)
  )) invalidResponse();
  return deepFreeze({
    approvalControlGeneration: value.approval_control_generation,
    run: parseRunStatus(value.run, expectedRun),
    progress: {
      available: value.progress.available,
      currentScenarioId: value.progress.current_scenario_id as string | null,
      scenariosCompleted: value.progress.scenarios_completed as number | null,
      scenariosTotal: value.progress.scenarios_total as number | null,
      requestsStarted: value.progress.requests_started as number | null,
      requestsCompleted: value.progress.requests_completed as number | null,
      remainingRequests: value.progress.remaining_requests as number | null,
      remainingWallMs: value.progress.remaining_wall_ms as number | null,
      retriesUsed: value.progress.retries_used as number | null,
      redactionCount: value.progress.redaction_count as number | null,
      localResultReady: value.progress.local_result_ready,
    },
  });
}

function validEnvironment(value: unknown): value is JsonRecord {
  if (!exact(value, ["environment_id", "verification_record_digest", "origin", "environment_class"])) return false;
  return typeof value.environment_id === "string" && ENVIRONMENT_REF.test(value.environment_id)
    && digest(value.verification_record_digest)
    && typeof value.origin === "string" && /^https:\/\/[a-z0-9.-]{1,253}$/.test(value.origin)
    && (value.environment_class === "staging" || value.environment_class === "sandbox");
}

function validBudgets(value: unknown): value is JsonRecord {
  return exact(value, ["maximum_requests", "maximum_concurrency", "action_timeout_ms", "wall_timeout_ms", "maximum_response_bytes"])
    && integer(value.maximum_requests, 1, 20) && value.maximum_concurrency === 1
    && integer(value.action_timeout_ms, 1, 5000) && integer(value.wall_timeout_ms, 1, 60000)
    && integer(value.maximum_response_bytes, 1, 256 * 1024);
}

function validRetry(value: unknown): value is JsonRecord {
  if (!exact(value, ["maximum_retries", "retryable_failure_codes"])
    || !integer(value.maximum_retries, 0, 1)) return false;
  const failureCodes = value.retryable_failure_codes;
  return Array.isArray(failureCodes) && failureCodes.length <= 2
    && failureCodes.every((item) => item === "connect_error" || item === "timeout")
    && new Set(failureCodes).size === failureCodes.length
    && failureCodes.every((item, index) => index === 0 || failureCodes[index - 1] < item);
}

function validEgress(value: unknown, origin: string): value is JsonRecord {
  return exact(value, ["hostname", "port", "redirect_policy"])
    && value.hostname === origin.slice(8) && value.port === 443 && value.redirect_policy === "deny";
}

function validSignature(value: JsonRecord, digestField: string): boolean {
  return digest(value[digestField]) && identifier(value.signing_key_id)
    && typeof value.signature_b64 === "string" && BASE64_SIGNATURE.test(value.signature_b64);
}

function sortedUniqueStrings(value: unknown, choices?: ReadonlySet<string>, maximum = 20): value is string[] {
  if (!Array.isArray(value) || value.length > maximum || !value.every((item) => typeof item === "string")) return false;
  if (new Set(value).size !== value.length || value.some((item, index) => index > 0 && value[index - 1] >= item)) return false;
  return choices === undefined || value.every((item) => choices.has(item));
}

const ERROR_CATEGORIES = new Set(["none", "platform_fault", "runner_fault", "target_unavailable", "proof_expired", "dns_changed", "credential_unavailable", "version_mismatch", "budget_exhausted", "containment_rejected", "cloud_disconnected"]);
const STOP_REASONS = new Set(["none", "local_emergency_stop", "cloud_stop", "runner_revoked", "target_revoked", "kill_switch"]);
const CONTAINMENT_CODES = new Set(["admitted", "action_started", "action_completed", "action_rejected", "budget_exhausted", "dns_changed", "stop_observed", "response_truncated", "redacted"]);
const BODY_SHAPES = new Set(["absent", "empty", "json_object", "json_array", "json_scalar", "text", "binary", "truncated", "invalid"]);

function validGrant(value: unknown, workspaceRef: string, projectRef: string, runRef: string): value is JsonRecord {
  if (!exact(value, [
    "schema_version", "grant_id", "run_id", "workspace_id", "project_id", "approval",
    "environment", "runner_binding", "approval_actor", "approval_reason", "consented_at_ms",
    "budgets", "egress", "retry_policy", "grant_nonce", "kill_switch_generation",
    "operational_receipt_policy", "issued_at_ms", "expires_at_ms", "grant_digest",
    "signing_key_id", "signature_b64",
  ]) || value.schema_version !== "heel.execution-grant.v1" || !identifier(value.grant_id)
    || value.run_id !== runRef || value.workspace_id !== workspaceRef || value.project_id !== projectRef
    || !exact(value.approval, ["projection_id", "projection_digest", "manifest_digest"])
    || !identifier(value.approval.projection_id) || !digest(value.approval.projection_digest)
    || !digest(value.approval.manifest_digest) || !validEnvironment(value.environment)
    || !exact(value.runner_binding, ["runner_id", "runner_key_id", "public_key_digest"])
    || !identifier(value.runner_binding.runner_id) || !identifier(value.runner_binding.runner_key_id)
    || !digest(value.runner_binding.public_key_digest)
    || !exact(value.approval_actor, ["user_id", "role"]) || !identifier(value.approval_actor.user_id)
    || !["owner", "admin"].includes(String(value.approval_actor.role))
    || !closedString(value.approval_reason, 500) || !integer(value.consented_at_ms)
    || !validBudgets(value.budgets) || !validEgress(value.egress, value.environment.origin as string)
    || !validRetry(value.retry_policy) || !identifier(value.grant_nonce)
    || !integer(value.kill_switch_generation)
    || !exact(value.operational_receipt_policy, ["schema_version", "maximum_bytes", "allowed_error_categories", "allowed_stop_reasons", "allowed_containment_codes"])
    || value.operational_receipt_policy.schema_version !== "heel.operational-run-projection.v1"
    || !integer(value.operational_receipt_policy.maximum_bytes, 1, 32768)
    || !sortedUniqueStrings(value.operational_receipt_policy.allowed_error_categories, ERROR_CATEGORIES)
    || !sortedUniqueStrings(value.operational_receipt_policy.allowed_stop_reasons, STOP_REASONS)
    || !sortedUniqueStrings(value.operational_receipt_policy.allowed_containment_codes, CONTAINMENT_CODES)
    || !integer(value.issued_at_ms) || !integer(value.expires_at_ms)
    || (value.expires_at_ms as number) <= (value.issued_at_ms as number)
    || (value.expires_at_ms as number) - (value.issued_at_ms as number) > 600_000
    || !validSignature(value, "grant_digest")) return false;
  return true;
}

type DisclosurePermitRecord = JsonRecord & { projection: JsonRecord };

function validDisclosurePermit(value: unknown, workspaceRef: string, projectRef: string, runRef: string): value is DisclosurePermitRecord {
  if (!exact(value, [
    "schema_version", "permit_id", "workspace_id", "project_id", "run_id", "grant_id",
    "runner_binding", "projection", "approved_by", "approved_at_ms", "issued_at_ms",
    "expires_at_ms", "permit_nonce", "permit_digest", "signing_key_id", "signature_b64",
  ]) || value.schema_version !== "heel.disclosure-permit.v1" || !identifier(value.permit_id)
    || value.workspace_id !== workspaceRef || value.project_id !== projectRef || value.run_id !== runRef
    || !identifier(value.grant_id) || !exact(value.runner_binding, ["runner_id", "runner_key_id"])
    || !identifier(value.runner_binding.runner_id) || !identifier(value.runner_binding.runner_key_id)
    || !exact(value.projection, ["schema_version", "projection_digest", "maximum_bytes", "scenario_count", "finding_count"])
    || value.projection.schema_version !== "heel.canary-findings-projection.v1"
    || !digest(value.projection.projection_digest) || !integer(value.projection.maximum_bytes, 1, 256 * 1024)
    || !integer(value.projection.scenario_count, 0, 4)
    || !integer(value.projection.finding_count, 0, value.projection.scenario_count as number)
    || !identifier(value.approved_by) || !integer(value.approved_at_ms) || !integer(value.issued_at_ms)
    || !integer(value.expires_at_ms) || (value.expires_at_ms as number) <= (value.issued_at_ms as number)
    || (value.expires_at_ms as number) - (value.issued_at_ms as number) > 600_000
    || !identifier(value.permit_nonce) || !validSignature(value, "permit_digest")) return false;
  return true;
}

function validFindings(value: unknown, workspaceRef: string, projectRef: string, runRef: string): value is JsonRecord {
  if (!exact(value, ["schema_version", "projection_id", "run_id", "grant_id", "workspace_id", "project_id", "environment_id", "manifest_digest", "approval_projection_digest", "grant_digest", "engine_version", "adapter_versions", "started_at_ms", "finished_at_ms", "assessment_outcome", "scenario_results", "containment_codes", "redaction_count", "projection_digest", "signing_key_id", "signature_b64"])
    || value.schema_version !== "heel.canary-findings-projection.v1" || value.run_id !== runRef
    || value.workspace_id !== workspaceRef || value.project_id !== projectRef || !identifier(value.projection_id)
    || !identifier(value.grant_id) || typeof value.environment_id !== "string" || !ENVIRONMENT_REF.test(value.environment_id)
    || !digest(value.manifest_digest) || !digest(value.approval_projection_digest) || !digest(value.grant_digest)
    || !identifier(value.engine_version) || !sortedUniqueStrings(value.adapter_versions)
    || !integer(value.started_at_ms) || !integer(value.finished_at_ms) || value.finished_at_ms < value.started_at_ms
    || !["blocked", "observed", "inconclusive"].includes(String(value.assessment_outcome))
    || !Array.isArray(value.scenario_results) || value.scenario_results.length > 4
    || !sortedUniqueStrings(value.containment_codes, CONTAINMENT_CODES)
    || !integer(value.redaction_count) || !validSignature(value, "projection_digest")) return false;
  let totalObservations = 0;
  const seen = new Set<string>();
  for (let index = 0; index < value.scenario_results.length; index += 1) {
    const item = value.scenario_results[index];
    if (!exact(item, ["ordinal", "scenario_id", "adapter_version", "assessment_outcome", "route", "observations", "finding", "containment_codes", "redaction_count", "local_evidence_refs"])
      || item.ordinal !== index || !identifier(item.scenario_id) || seen.has(item.scenario_id)
      || !identifier(item.adapter_version) || !["blocked", "observed", "inconclusive"].includes(String(item.assessment_outcome))
      || !exact(item.route, ["method", "route_template"]) || !["GET", "HEAD"].includes(String(item.route.method))
      || !closedString(item.route.route_template, 1024) || !Array.isArray(item.observations) || item.observations.length > 20
      || !sortedUniqueStrings(item.containment_codes, CONTAINMENT_CODES) || !integer(item.redaction_count)
      || !sortedUniqueStrings(item.local_evidence_refs, undefined, 10)
      || !(item.local_evidence_refs as string[]).every((ref) => /^ev1_[0-9a-f]{64}$/.test(ref))) return false;
    seen.add(item.scenario_id);
    totalObservations += item.observations.length;
    let previousObservation = "";
    const observationRoles = new Set<string>();
    for (const observation of item.observations) {
      if (!exact(observation, ["semantic_role", "status_code", "body_shape", "truncation_state"])
        || !identifier(observation.semantic_role) || !integer(observation.status_code, 100, 599)
        || !BODY_SHAPES.has(String(observation.body_shape))
        || !["complete", "truncated"].includes(String(observation.truncation_state))) return false;
      const key = `${observation.semantic_role}\0${observation.status_code}\0${observation.body_shape}\0${observation.truncation_state}`;
      if (key <= previousObservation || observationRoles.has(observation.semantic_role)) return false;
      previousObservation = key;
      observationRoles.add(observation.semantic_role);
    }
    if (item.finding !== null && (!exact(item.finding, ["title", "reachability_rationale", "confidence", "recommended_control", "regression_suggestion"])
      || !closedString(item.finding.title, 160) || !closedString(item.finding.reachability_rationale, 2000)
      || !["low", "medium", "high"].includes(String(item.finding.confidence))
      || !closedString(item.finding.recommended_control, 2000) || !closedString(item.finding.regression_suggestion, 2000))) return false;
  }
  return totalObservations <= 20;
}

const DISCLOSURE_STATUSES: ReadonlySet<string> = new Set([
  "local_result_ready", "awaiting_disclosure_approval", "permitted", "synchronized", "local_only", "expired",
]);
const DISCLOSURE_REQUEST_REF = /^cdr_[0-9a-f]{32}$/;

function parseDisclosureState(value: unknown, runRef: string): CanaryDisclosureState {
  if (!exact(value, ["schema_version", "request_id", "run_id", "status", "projection"])
    || value.schema_version !== "heel.canary-disclosure-preview.v1"
    || typeof value.request_id !== "string" || !DISCLOSURE_REQUEST_REF.test(value.request_id)
    || value.run_id !== runRef || !DISCLOSURE_STATUSES.has(String(value.status))
    || !exact(value.projection, ["schema_version", "projection_digest", "byte_count", "scenario_count", "finding_count"])
    || value.projection.schema_version !== "heel.canary-findings-projection.v1"
    || !digest(value.projection.projection_digest) || !integer(value.projection.byte_count, 1, 256 * 1024)
    || !integer(value.projection.scenario_count, 0, 4)
    || !integer(value.projection.finding_count, 0, value.projection.scenario_count as number)) invalidResponse();
  const projection = value.projection as JsonRecord;
  return deepFreeze({
    requestId: value.request_id,
    runId: runRef,
    status: value.status as CanaryDisclosureStatus,
    projection: {
      projectionDigest: projection.projection_digest as string,
      projectionBytes: projection.byte_count as number,
      scenarioCount: projection.scenario_count as number,
      findingCount: projection.finding_count as number,
    },
  });
}

function validApprovalScenario(value: unknown, index: number): value is JsonRecord {
  return exact(value, ["ordinal", "scenario_id", "adapter_version"])
    && value.ordinal === index && identifier(value.scenario_id) && identifier(value.adapter_version);
}

function validApprovalAction(value: unknown, index: number, scenarios: readonly JsonRecord[]): value is JsonRecord {
  if (!exact(value, ["ordinal", "scenario_id", "adapter_version", "method", "route_template", "semantic_auth_role", "assertion_class", "allowed_status_codes", "allowed_body_shapes", "side_effect_class"])
    || value.ordinal !== index || !identifier(value.scenario_id) || !identifier(value.adapter_version)
    || !scenarios.some((scenario) => scenario.scenario_id === value.scenario_id && scenario.adapter_version === value.adapter_version)
    || (value.method !== "GET" && value.method !== "HEAD") || !closedString(value.route_template, 1024)
    || !/^\/(?:[A-Za-z0-9._~!$&'()*+,;=:@{}-]+\/?)*$/.test(value.route_template)
    || value.route_template.includes("//") || !identifier(value.semantic_auth_role)
    || !["anonymous_authenticated", "object_ownership", "role_boundary", "plan_entitlement"].includes(String(value.assertion_class))
    || !sortedUniqueStrings(value.allowed_body_shapes, BODY_SHAPES)
    || value.side_effect_class !== "read_only") return false;
  const statuses = value.allowed_status_codes;
  return Array.isArray(statuses) && statuses.length <= 20
    && statuses.every((status) => integer(status, 100, 599))
    && new Set(statuses).size === statuses.length
    && statuses.every((status, statusIndex) => statusIndex === 0 || statuses[statusIndex - 1] < status);
}

function validApprovalProjection(value: unknown, workspaceRef: string, projectRef: string): value is JsonRecord {
  if (!exact(value, [
    "schema_version", "projection_id", "workspace_id", "project_id", "environment", "runner",
    "compiler", "scenarios", "actions", "budgets", "egress", "retry_policy", "compiled_at_ms",
    "manifest_digest", "projection_digest", "signing_key_id", "signature_b64",
  ]) || value.schema_version !== "heel.approval-manifest-projection.v1"
    || value.workspace_id !== workspaceRef || value.project_id !== projectRef
    || !identifier(value.projection_id) || !validEnvironment(value.environment)
    || !exact(value.runner, ["runner_id", "runner_key_id", "runner_version", "adapter_versions"])
    || !identifier(value.runner.runner_id) || !identifier(value.runner.runner_key_id)
    || !identifier(value.runner.runner_version) || !sortedUniqueStrings(value.runner.adapter_versions)
    || value.signing_key_id !== value.runner.runner_key_id
    || !exact(value.compiler, ["compiler_version", "engine_version"])
    || !identifier(value.compiler.compiler_version) || !identifier(value.compiler.engine_version)) return false;
  const scenarios = value.scenarios;
  if (!Array.isArray(scenarios) || scenarios.length > 4
    || !scenarios.every(validApprovalScenario)
    || new Set(scenarios.map((item) => item.scenario_id)).size !== scenarios.length) return false;
  const actions = value.actions;
  if (!Array.isArray(actions) || actions.length > 20
    || !actions.every((item, index) => validApprovalAction(item, index, scenarios))
    || !validBudgets(value.budgets) || !validEgress(value.egress, value.environment.origin as string)
    || !validRetry(value.retry_policy) || !integer(value.compiled_at_ms)
    || !digest(value.manifest_digest) || !validSignature(value, "projection_digest")) return false;
  return true;
}

function parseEnvironment(value: unknown): VerifiedEnvironmentRecord {
  if (!exact(value, [
    "schema_version", "environment_id", "origin", "environment_class", "status", "attestation",
    "attestation_version", "attestation_acknowledgement", "proof_method", "proof_version",
    "normalization_version", "challenge_generation", "challenge_expires_at", "last_failure_code",
    "verified_at", "proof_expires_at", "verification_record_digest", "revoked_at", "is_executable",
  ]) || value.schema_version !== "VerifiedEnvironment.v1"
    || typeof value.environment_id !== "string" || !ENVIRONMENT_REF.test(value.environment_id)
    || typeof value.origin !== "string" || !/^https:\/\/[a-z0-9.-]{1,253}$/.test(value.origin)
    || !["staging", "sandbox", "production"].includes(String(value.environment_class))
    || !["pending", "verified", "revoked"].includes(String(value.status))
    || value.attestation !== "ownership verified; environment classification supplied by you"
    || value.attestation_version !== "v1" || value.attestation_acknowledgement !== "accepted"
    || !["https-file", "dns-txt"].includes(String(value.proof_method))
    || value.proof_version !== (value.proof_method === "https-file" ? "https-file.v1" : "dns-txt.v1")
    || value.normalization_version !== "exact-origin.v1"
    || !integer(value.challenge_generation)
    || !nullableFiniteNonnegative(value.challenge_expires_at) || !(value.last_failure_code === null || closedString(value.last_failure_code, 64))
    || !nullableFiniteNonnegative(value.verified_at) || !nullableFiniteNonnegative(value.proof_expires_at)
    || !(value.verification_record_digest === null || digest(value.verification_record_digest))
    || !nullableFiniteNonnegative(value.revoked_at) || typeof value.is_executable !== "boolean") invalidResponse();
  return deepFreeze({
    schemaVersion: "VerifiedEnvironment.v1",
    environmentId: value.environment_id as string,
    origin: value.origin as string,
    environmentClass: value.environment_class as VerifiedEnvironmentRecord["environmentClass"],
    status: value.status as VerifiedEnvironmentRecord["status"],
    proofMethod: value.proof_method as VerifiedEnvironmentRecord["proofMethod"],
    challengeGeneration: value.challenge_generation as number,
    challengeExpiresAt: value.challenge_expires_at as number | null,
    proofExpiresAt: value.proof_expires_at as number | null,
    lastFailureCode: value.last_failure_code as string | null,
    verificationRecordDigest: value.verification_record_digest as string | null,
    isExecutable: value.is_executable as boolean,
  });
}

/** Binds a recovery or rotation response to the listed pending record it was requested for. */
function parsePendingProof(value: JsonRecord, listed: VerifiedEnvironmentRecord, rotated: boolean): PendingEnvironmentProof {
  const host = listed.origin.slice("https://".length);
  if (!exact(value, [
    "schema_version", "environment_id", "origin", "environment_class", "proof_method", "token", "http_url",
    "dns_record", "challenge_generation", "expires_at", "attestation", "attestation_version", "attestation_acknowledgement",
  ]) || value.schema_version !== "heel.verified-environment-challenge-recovery.v1"
    || value.environment_id !== listed.environmentId || value.origin !== listed.origin
    || value.environment_class !== listed.environmentClass || value.proof_method !== listed.proofMethod
    || !identifier(value.token) || !integer(value.challenge_generation, 1)
    || (rotated ? value.challenge_generation <= listed.challengeGeneration : value.challenge_generation !== listed.challengeGeneration)
    || value.http_url !== `${listed.origin}/.well-known/heel-verify.txt`
    || value.dns_record !== `_heel.${host} TXT heel-verify=${value.token}`
    || typeof value.expires_at !== "number" || !Number.isFinite(value.expires_at) || value.expires_at <= 0
    || value.attestation !== "ownership verified; environment classification supplied by you"
    || value.attestation_version !== "v1" || value.attestation_acknowledgement !== "accepted") invalidResponse();
  return deepFreeze({
    environmentId: listed.environmentId, origin: listed.origin, environmentClass: listed.environmentClass,
    proofMethod: listed.proofMethod, token: value.token as string, httpUrl: value.http_url as string,
    dnsRecord: value.dns_record as string, challengeGeneration: value.challenge_generation as number,
    expiresAt: value.expires_at as number,
  });
}

export class CanaryApi {
  readonly #transport: CanaryTransport;
  readonly #timeoutMs: number;

  constructor(options: CanaryApiOptions = {}) {
    this.#transport = options.transport ?? sameOriginCanaryFetch;
    if (!integer(options.timeoutMs ?? DEFAULT_TIMEOUT_MS, 1, 60_000)) invalidRequest();
    this.#timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  async listRunnerContextBindings(workspaceRef: string, projectRef: string): Promise<RunnerContextBindingDashboard> {
    const value = await this.#json(projectPath(workspaceRef, projectRef, "/runner-context-bindings"), "GET", undefined, 200);
    if (!exact(value, ["schema_version", "server_time_ms", "runners", "bindings"])
      || value.schema_version !== "heel.runner-context-binding-dashboard.v1" || !integer(value.server_time_ms)
      || !Array.isArray(value.runners) || !Array.isArray(value.bindings)) invalidResponse();
    const bindings = value.bindings.map((item): RunnerContextBindingRecord => {
      if (!exact(item, ["binding_id", "binding_digest", "environment_id", "origin", "environment_class", "verification_record_digest", "runner_id", "runner_key_id", "status", "issued_at_ms", "expires_at_ms", "first_claimed_at_ms"])) invalidResponse();
      const { binding_id, binding_digest, environment_id, origin, environment_class, verification_record_digest, runner_id, runner_key_id, status, issued_at_ms, expires_at_ms, first_claimed_at_ms } = item;
      if (typeof binding_id !== "string" || !/^rcb_[0-9a-f]{32}$/.test(binding_id)
        || !digest(binding_digest) || typeof environment_id !== "string" || !ENVIRONMENT_REF.test(environment_id)
        || typeof origin !== "string" || typeof environment_class !== "string" || !["staging", "sandbox"].includes(environment_class)
        || !digest(verification_record_digest) || !identifier(runner_id) || !identifier(runner_key_id)
        || typeof status !== "string" || !["active", "revoked", "expired"].includes(status) || !integer(issued_at_ms)
        || !integer(expires_at_ms) || expires_at_ms <= issued_at_ms || !nullableInteger(first_claimed_at_ms)) invalidResponse();
      return { bindingId: binding_id, bindingDigest: binding_digest, environmentId: environment_id,
        origin, environmentClass: environment_class as "staging" | "sandbox",
        verificationRecordDigest: verification_record_digest, runnerId: runner_id,
        runnerKeyId: runner_key_id, status: status as "active" | "revoked" | "expired",
        issuedAtMs: issued_at_ms, expiresAtMs: expires_at_ms, firstClaimedAtMs: first_claimed_at_ms };
    });
    const runners = value.runners.map((item): RunnerContextRunner => {
      if (!exact(item, ["runner_id", "runner_key_id", "display_name", "fingerprint", "runner_version", "adapter_versions", "status"])
        || !identifier(item.runner_id) || !identifier(item.runner_key_id) || !closedString(item.display_name, 128)
        || !digest(item.fingerprint) || !identifier(item.runner_version) || !sortedUniqueStrings(item.adapter_versions)
        || item.status !== "active") invalidResponse();
      return { runnerId: item.runner_id, runnerKeyId: item.runner_key_id, displayName: item.display_name,
        fingerprint: item.fingerprint, runnerVersion: item.runner_version, adapterVersions: item.adapter_versions, status: "active" };
    });
    return deepFreeze({ runners, bindings });
  }

  async createRunnerContextBinding(workspaceRef: string, projectRef: string, input: { environmentId: string; verificationRecordDigest: string; runnerId: string; runnerKeyId: string }): Promise<RunnerContextBindingRecord> {
    if (!ENVIRONMENT_REF.test(input.environmentId) || !digest(input.verificationRecordDigest) || !identifier(input.runnerId) || !identifier(input.runnerKeyId)) invalidRequest();
    const value = await this.#json(projectPath(workspaceRef, projectRef, "/runner-context-bindings"), "POST", { schema_version: "heel.runner-context-binding-create.v1", environment_id: input.environmentId, verification_record_digest: input.verificationRecordDigest, runner_id: input.runnerId, runner_key_id: input.runnerKeyId }, 201);
    if (!exact(value, ["schema_version", "context_binding"]) || value.schema_version !== "heel.runner-context-binding-created.v1") invalidResponse();
    const binding = parseRunnerContextBinding(value.context_binding);
    if (binding.environmentId !== input.environmentId || binding.verificationRecordDigest !== input.verificationRecordDigest
      || binding.runnerId !== input.runnerId || binding.runnerKeyId !== input.runnerKeyId
      || !exact(value.context_binding, ["schema_version", "binding_id", "workspace_id", "project_id", "environment", "runner_binding", "authorization", "issued_at_ms", "expires_at_ms", "binding_digest", "signing_key_id", "signature_b64"])
      || value.context_binding.workspace_id !== workspaceRef || value.context_binding.project_id !== projectRef) invalidResponse();
    return binding;
  }

  async revokeRunnerContextBinding(workspaceRef: string, projectRef: string, bindingId: string): Promise<void> {
    if (!/^rcb_[0-9a-f]{32}$/.test(bindingId)) invalidRequest();
    const value = await this.#json(projectPath(workspaceRef, projectRef, `/runner-context-bindings/${bindingId}/revoke`), "POST", { schema_version: "heel.runner-context-binding-revoke.v1", reason_code: "operator_requested" }, 200);
    if (!exact(value, ["schema_version", "binding_id", "status", "revoked_at_ms"])
      || value.schema_version !== "heel.runner-context-binding-revoked.v1" || value.binding_id !== bindingId
      || value.status !== "revoked" || !integer(value.revoked_at_ms)) invalidResponse();
  }

  async submitApprovalProjection(workspaceRef: string, projectRef: string, projection: unknown): Promise<Readonly<CanaryApprovalSummary>> {
    if (!validApprovalProjection(projection, workspaceRef, projectRef)) invalidRequest();
    const value = await this.#json(projectPath(workspaceRef, projectRef, "/canary-approval-projections"), "POST", projection, 201);
    if (!exact(value, ["schema_version", "approval_id", "run_id", "status", "projection_digest"])
      || value.schema_version !== "heel.canary-projection-submitted.v1" || !identifier(value.approval_id)
      || typeof value.run_id !== "string" || !RUN_REF.test(value.run_id)
      || value.status !== "awaiting_execution_approval" || value.projection_digest !== projection.projection_digest) invalidResponse();
    const routes = (projection.actions as JsonRecord[]).map((action) => `${action.method as string} ${action.route_template as string}`);
    const scenarios = (projection.scenarios as JsonRecord[]).map((scenario) => scenario.scenario_id as string);
    return deepFreeze({
      approvalId: value.approval_id as string,
      runId: value.run_id as string,
      projectionDigest: value.projection_digest as string,
      origin: (projection.environment as JsonRecord).origin as string,
      hostname: (projection.egress as JsonRecord).hostname as string,
      routes,
      scenarios,
      requestBudget: (projection.budgets as JsonRecord).maximum_requests as number,
      durationSeconds: Math.ceil(((projection.budgets as JsonRecord).wall_timeout_ms as number) / 1000),
      egress: `${(projection.egress as JsonRecord).hostname as string}:443`,
    });
  }

  async listPendingApprovalRequests(workspaceRef: string, projectRef: string, signal?: AbortSignal): Promise<{ request: Readonly<CanaryPendingApprovalRequest> | null; hasMore: boolean }> {
    const value = await this.#json(projectPath(workspaceRef, projectRef, "/canary-approval-requests"), "GET", undefined, 200, {}, signal);
    if (!exact(value, ["schema_version", "server_time_ms", "requests", "has_more"])
      || value.schema_version !== "heel.canary-approval-request-list.v1" || !integer(value.server_time_ms)
      || !Array.isArray(value.requests) || value.requests.length > 1 || typeof value.has_more !== "boolean") invalidResponse();
    if (value.requests.length === 0) return deepFreeze({ request: null, hasMore: value.has_more });
    const item = value.requests[0];
    if (!exact(item, ["approval_id", "run_id", "projection_digest", "status", "submitted_at_ms", "expires_at_ms", "origin", "hostname", "routes", "scenarios", "request_budget", "duration_seconds", "egress"])
      || !identifier(item.approval_id) || typeof item.run_id !== "string" || !RUN_REF.test(item.run_id)
      || !digest(item.projection_digest) || item.status !== "awaiting_execution_approval" || !integer(item.submitted_at_ms)
      || !integer(item.expires_at_ms) || item.expires_at_ms <= item.submitted_at_ms || typeof item.origin !== "string"
      || typeof item.hostname !== "string" || !/^[a-z0-9.-]{1,253}$/.test(item.hostname)
      || !Array.isArray(item.routes) || item.routes.length > 20 || !item.routes.every(validApprovalRouteSummary)
      || !Array.isArray(item.scenarios) || item.scenarios.length > 4 || !item.scenarios.every(identifier)
      || !integer(item.request_budget, 1, 20) || !integer(item.duration_seconds, 1, 60)
      || item.egress !== `${item.hostname}:443`) invalidResponse();
    return deepFreeze({ request: { approvalId: item.approval_id as string, runId: item.run_id as string,
      projectionDigest: item.projection_digest as string, origin: item.origin as string, hostname: item.hostname as string,
      routes: item.routes as string[], scenarios: item.scenarios as string[], requestBudget: item.request_budget as number,
      durationSeconds: item.duration_seconds as number, egress: item.egress as string,
      submittedAtMs: item.submitted_at_ms as number, expiresAtMs: item.expires_at_ms as number }, hasMore: value.has_more as boolean });
  }

  async approveRun(workspaceRef: string, projectRef: string, runRef: string, approval: {
    projectionDigest: string;
    hostnameRetype: string;
    reason: string;
    idempotencyKey: `ca1-${string}`;
    controlGeneration: number;
  }): Promise<Readonly<{ runId: string; grantId: string; reservationId: string; grant: JsonRecord }>> {
    if (!digest(approval.projectionDigest) || !/^[a-z0-9.-]{1,253}$/.test(approval.hostnameRetype)
      || !closedString(approval.reason, 500) || !/^ca1-[0-9a-f]{64}$/.test(approval.idempotencyKey)
      || !integer(approval.controlGeneration)) invalidRequest();
    const value = await this.#json(runPath(workspaceRef, projectRef, runRef, "/approve"), "POST", {
      schema_version: "heel.canary-execution-approval.v1",
      projection_digest: approval.projectionDigest,
      hostname_retype: approval.hostnameRetype,
      reason: approval.reason,
    }, 201, {
      "Idempotency-Key": approval.idempotencyKey,
      "If-Heel-Control-Generation": String(approval.controlGeneration),
    });
    if (!exact(value, ["schema_version", "run_id", "grant_id", "reservation_id", "grant"])
      || value.schema_version !== "heel.execution-approved.v1" || value.run_id !== runRef
      || !identifier(value.grant_id) || !identifier(value.reservation_id)
      || !validGrant(value.grant, workspaceRef, projectRef, runRef) || value.grant.grant_id !== value.grant_id) invalidResponse();
    return deepFreeze({ runId: runRef, grantId: value.grant_id as string, reservationId: value.reservation_id as string, grant: value.grant });
  }

  async getRun(workspaceRef: string, projectRef: string, runRef: string, signal?: AbortSignal): Promise<CanaryRunDashboard> {
    return parseRunDashboard(await this.#json(runPath(workspaceRef, projectRef, runRef), "GET", undefined, 200, {}, signal), runRef);
  }

  async listEvents(workspaceRef: string, projectRef: string, runRef: string): Promise<readonly Readonly<JsonRecord>[]> {
    const value = await this.#json(runPath(workspaceRef, projectRef, runRef, "/events"), "GET", undefined, 200);
    if (!exact(value, ["schema_version", "run_id", "events"])
      || value.schema_version !== "heel.canary-run-events.v1" || value.run_id !== runRef
      || !Array.isArray(value.events) || value.events.length > 2_000) invalidResponse();
    let prior = 0;
    for (const event of value.events) {
      if (!exact(event, ["sequence", "event_type", "event", "source_event_sequence", "actor_class", "actor_id", "reason_code", "created_at_ms"])
        || !integer(event.sequence, 1) || event.sequence <= prior || !closedString(event.event_type, 64)
        || !exact(event.event, ["schema_version", "event_type", "status", "reason_code"])
        || event.event.schema_version !== "heel.canary-run-event.v1" || event.event.event_type !== event.event_type
        || !closedString(event.event.status, 64)
        || !(event.event.reason_code === null || closedString(event.event.reason_code, 64))
        || !(event.source_event_sequence === null || integer(event.source_event_sequence))
        || !closedString(event.actor_class, 32) || !closedString(event.actor_id, 256)
        || !(event.reason_code === null || closedString(event.reason_code, 64)) || !integer(event.created_at_ms)) invalidResponse();
      prior = event.sequence;
    }
    return deepFreeze(value.events as JsonRecord[]);
  }

  async stopRun(workspaceRef: string, projectRef: string, runRef: string, controlGeneration: number): Promise<Readonly<JsonRecord>> {
    if (!integer(controlGeneration)) invalidRequest();
    const value = await this.#json(runPath(workspaceRef, projectRef, runRef, "/stop"), "POST", {
      schema_version: "heel.canary-stop-request.v1", reason_code: "operator_requested",
    }, 200, { "If-Heel-Control-Generation": String(controlGeneration) });
    if (!exact(value, ["schema_version", "run_id", "stop_generation", "deadline_ms", "reason"])
      || value.schema_version !== "heel.canary-stop-requested.v1" || value.run_id !== runRef
      || !integer(value.stop_generation) || !integer(value.deadline_ms) || value.reason !== "cloud_stop") invalidResponse();
    return deepFreeze(value);
  }

  async createDisclosurePermit(workspaceRef: string, projectRef: string, runRef: string, metadata: CanaryDisclosureMetadata): Promise<Readonly<JsonRecord>> {
    const value = await this.#json(runPath(workspaceRef, projectRef, runRef, "/disclosure-permits"), "POST", metadataBody("heel.canary-disclosure-request.v1", metadata), 201);
    if (!validDisclosurePermit(value, workspaceRef, projectRef, runRef)
      || value.projection.projection_digest !== metadata.projectionDigest
      || value.projection.maximum_bytes !== metadata.projectionBytes
      || value.projection.scenario_count !== metadata.scenarioCount
      || value.projection.finding_count !== metadata.findingCount) invalidResponse();
    return deepFreeze(value);
  }

  async markDisclosureLocalOnly(workspaceRef: string, projectRef: string, runRef: string, metadata: CanaryDisclosureMetadata): Promise<Readonly<JsonRecord>> {
    const value = await this.#json(runPath(workspaceRef, projectRef, runRef, "/disclosure-local-only"), "POST", metadataBody("heel.canary-disclosure-local-only.v1", metadata), 200);
    if (!exact(value, ["schema_version", "run_id", "status"])
      || value.schema_version !== "heel.canary-disclosure-state.v1" || value.run_id !== runRef
      || value.status !== "local_only") invalidResponse();
    return deepFreeze(value);
  }

  /** The disclosure status and runner-registered metadata of one run; 404 `canary_run_not_found` until registered. */
  async getDisclosure(workspaceRef: string, projectRef: string, runRef: string, signal?: AbortSignal): Promise<CanaryDisclosureState> {
    return parseDisclosureState(await this.#json(runPath(workspaceRef, projectRef, runRef, "/disclosure"), "GET", undefined, 200, {}, signal), runRef);
  }

  async getFindings(workspaceRef: string, projectRef: string, runRef: string, signal?: AbortSignal): Promise<Readonly<CanaryFindingsProjection>> {
    const value = await this.#json(runPath(workspaceRef, projectRef, runRef, "/findings"), "GET", undefined, 200, {}, signal);
    if (!validFindings(value, workspaceRef, projectRef, runRef)) invalidResponse();
    return deepFreeze(value as unknown as CanaryFindingsProjection);
  }

  async listEnvironments(workspaceRef: string, projectRef: string): Promise<readonly VerifiedEnvironmentRecord[]> {
    const value = await this.#json(environmentPath(workspaceRef, projectRef), "GET", undefined, 200);
    if (!exact(value, ["schema_version", "environments"])
      || value.schema_version !== "heel.verified-environment-list.v1"
      || !Array.isArray(value.environments) || value.environments.length > 100) invalidResponse();
    return deepFreeze(value.environments.map(parseEnvironment));
  }

  async startEnvironmentProof(workspaceRef: string, projectRef: string, request: {
    origin: string;
    environmentClass: "staging" | "sandbox";
    proofMethod: "https-file" | "dns-txt";
    attestationText: string;
    attestationVersion: string;
    attestationAcknowledgement: string;
  }): Promise<Readonly<JsonRecord>> {
    if (!/^https:\/\/[a-z0-9.-]{1,253}$/.test(request.origin) || !closedString(request.attestationText)
      || !closedString(request.attestationVersion, 64) || !closedString(request.attestationAcknowledgement, 128)) invalidRequest();
    const value = await this.#json(environmentPath(workspaceRef, projectRef), "POST", {
      schema_version: "heel.verified-environment-start.v1", origin: request.origin,
      environment_class: request.environmentClass, proof_method: request.proofMethod,
      attestation_text: request.attestationText, attestation_version: request.attestationVersion,
      attestation_acknowledgement: request.attestationAcknowledgement,
    }, 201);
    if (!exact(value, ["schema_version", "environment_id", "origin", "environment_class", "proof_method", "token", "http_url", "dns_record", "challenge_generation", "expires_at", "attestation"])
      || value.schema_version !== "heel.verified-environment-challenge.v1"
      || typeof value.environment_id !== "string" || !ENVIRONMENT_REF.test(value.environment_id)
      || value.origin !== request.origin || value.environment_class !== request.environmentClass
      || value.proof_method !== request.proofMethod || !identifier(value.token)
      || !closedString(value.http_url, 1200) || !closedString(value.dns_record, 1200)
      || !integer(value.challenge_generation, 1) || typeof value.expires_at !== "number"
      || !Number.isFinite(value.expires_at) || value.expires_at <= 0
      || value.attestation !== request.attestationText) invalidResponse();
    return deepFreeze(value);
  }

  async checkEnvironmentProof(workspaceRef: string, projectRef: string, environmentRef: string): Promise<boolean> {
    if (!ENVIRONMENT_REF.test(environmentRef)) invalidRequest();
    const value = await this.#json(environmentPath(workspaceRef, projectRef, `/${environmentRef}/check`), "POST", { schema_version: "heel.verified-environment-check.v1" }, 200);
    if (!exact(value, ["schema_version", "verified"]) || value.schema_version !== "heel.verified-environment-check-result.v1" || typeof value.verified !== "boolean") invalidResponse();
    return value.verified;
  }

  /** Read-only: shows the current challenge of one listed pending record again; it never rotates or checks it. */
  async recoverEnvironmentProof(workspaceRef: string, projectRef: string, listed: VerifiedEnvironmentRecord): Promise<PendingEnvironmentProof> {
    if (!ENVIRONMENT_REF.test(listed.environmentId) || listed.status !== "pending") invalidRequest();
    const value = await this.#json(environmentPath(workspaceRef, projectRef, `/${listed.environmentId}/challenge`), "POST", { schema_version: "heel.verified-environment-challenge-recover.v1" }, 200);
    return parsePendingProof(value, listed, false);
  }

  /** Explicit replacement of an expired or missing pending challenge in the same record. */
  async rotateEnvironmentProof(workspaceRef: string, projectRef: string, listed: VerifiedEnvironmentRecord): Promise<PendingEnvironmentProof> {
    if (!ENVIRONMENT_REF.test(listed.environmentId) || listed.status !== "pending") invalidRequest();
    const value = await this.#json(environmentPath(workspaceRef, projectRef, `/${listed.environmentId}/challenge/rotate`), "POST", { schema_version: "heel.verified-environment-challenge-rotate.v1" }, 201);
    return parsePendingProof(value, listed, true);
  }

  async createRunnerPairingInvitation(workspaceRef: string): Promise<Readonly<{ invitationToken: string; expiresAt: number }>> {
    if (!WORKSPACE_REF.test(workspaceRef)) invalidRequest();
    const value = await this.#json(`${CONTROL_PLANE_PREFIX}/v1/workspaces/${workspaceRef}/runner-pairings`, "POST", { schema_version: "heel.runner-pairing-invite.v1" }, 201);
    if (!exact(value, ["schema_version", "invitation_token", "expires_at"])
      || value.schema_version !== "heel.runner-pairing-invitation.v1"
      || typeof value.invitation_token !== "string" || !INVITATION_TOKEN.test(value.invitation_token)
      || typeof value.expires_at !== "number" || !Number.isFinite(value.expires_at) || value.expires_at <= 0) invalidResponse();
    return deepFreeze({ invitationToken: value.invitation_token as string, expiresAt: value.expires_at });
  }

  async inspectRunnerPairing(workspaceRef: string, pairingRef: string): Promise<Readonly<RunnerPairingView>> {
    if (!WORKSPACE_REF.test(workspaceRef) || !PAIRING_REF.test(pairingRef)) invalidRequest();
    const value = await this.#json(`${CONTROL_PLANE_PREFIX}/v1/workspaces/${workspaceRef}/runner-pairings/${pairingRef}`, "GET", undefined, 200);
    if (!exact(value, ["schema_version", "pairing_id", "runner_id", "pairing_phrase", "fingerprint", "status", "expires_at"])
      || value.schema_version !== "heel.runner-pairing-view.v1" || value.pairing_id !== pairingRef
      || !identifier(value.runner_id) || !closedString(value.pairing_phrase, 128) || !digest(value.fingerprint)
      || value.status !== "pending" || typeof value.expires_at !== "number" || !Number.isFinite(value.expires_at)) invalidResponse();
    return deepFreeze({ pairingId: pairingRef, runnerId: value.runner_id as string, pairingPhrase: value.pairing_phrase as string,
      fingerprint: value.fingerprint as string, status: "pending", expiresAt: value.expires_at as number });
  }

  async approveRunnerPairing(workspaceRef: string, pairingRef: string, phrase: string, fingerprint: string): Promise<void> {
    if (!WORKSPACE_REF.test(workspaceRef) || !PAIRING_REF.test(pairingRef) || !closedString(phrase, 128) || !digest(fingerprint)) invalidRequest();
    const value = await this.#json(`${CONTROL_PLANE_PREFIX}/v1/workspaces/${workspaceRef}/runner-pairings/${pairingRef}/approve`, "POST", {
      schema_version: "heel.runner-pairing-approve.v1", pairing_phrase: phrase, fingerprint,
    }, 200);
    if (!exact(value, ["schema_version", "status"]) || value.schema_version !== "heel.runner-pairing-approved.v1" || value.status !== "approved") invalidResponse();
  }

  /** Revokes one paired runner in the workspace (recent owner/admin); the server revokes its keys and requests a stop of its active runs. */
  async revokeRunner(workspaceRef: string, runnerId: string): Promise<void> {
    if (!WORKSPACE_REF.test(workspaceRef) || !RUNNER_REF.test(runnerId)) invalidRequest();
    const value = await this.#json(`${CONTROL_PLANE_PREFIX}/v1/workspaces/${workspaceRef}/runners/${runnerId}/revoke`, "POST", {
      schema_version: "heel.runner-revoke.v1", reason_code: "human_revocation",
    }, 200);
    if (!exact(value, ["schema_version", "revoked"]) || value.schema_version !== "heel.runner-revoke-result.v1" || value.revoked !== true) invalidResponse();
  }

  async listScenarioLibrary(workspaceRef: string, signal?: AbortSignal): Promise<Readonly<ScenarioLibrary>> {
    const value = await this.#json(workspacePath(workspaceRef, "/scenario-library"), "GET", undefined, 200, {}, signal);
    if (!exact(value, ["schema_version", "library_digest", "engine_version", "binding_version", "custom_coverage_statements", "scenarios"])
      || value.schema_version !== "heel.scenario-library.v1" || !digest(value.library_digest)
      || !identifier(value.engine_version) || value.binding_version !== 1
      || !exact(value.custom_coverage_statements, [...BINDABLE_CATALOG_IDS])
      || !BINDABLE_CATALOG_IDS.every((id) => closedString((value.custom_coverage_statements as JsonRecord)[id], 512))
      || !Array.isArray(value.scenarios) || value.scenarios.length > 400) invalidResponse();
    const scenarios = value.scenarios.map(parseLibraryEntry);
    if (new Set(scenarios.map((item) => item.id)).size !== scenarios.length) invalidResponse();
    return deepFreeze({
      libraryDigest: value.library_digest, engineVersion: value.engine_version, bindingVersion: 1,
      customCoverageStatements: value.custom_coverage_statements as Record<ScenarioBindableCatalogId, string>,
      scenarios,
    });
  }

  async createCustomScenario(workspaceRef: string, input: CustomScenarioInput): Promise<Readonly<ScenarioLibraryEntry & { warnings: readonly string[] }>> {
    const binding = input.executionBinding;
    if (!record(input.definition) || !plainJson(input.definition) || typeof input.definition.id !== "string"
      || !SCENARIO_ID.test(input.definition.id)
      || (input.supersedesRevision !== null && !integer(input.supersedesRevision, 1))
      || (binding !== null && (!BINDABLE_CATALOG_IDS.includes(binding.catalogScenarioId) || !closedString(binding.coverageAck, 512)))) invalidRequest();
    const definitionText = JSON.stringify(input.definition);
    if (new TextEncoder().encode(definitionText).byteLength > MAX_CUSTOM_DEFINITION_BYTES) invalidRequest();
    const body = JSON.stringify({
      definition: input.definition,
      execution_binding: binding === null ? null : { binding_version: 1, catalog_scenario_id: binding.catalogScenarioId, coverage_ack: binding.coverageAck },
      schema_version: "heel.custom-scenario.v1",
      supersedes_revision: input.supersedesRevision,
    });
    if (new TextEncoder().encode(body).byteLength > 16 * 1024) invalidRequest();
    const response = await this.#send(workspacePath(workspaceRef, "/scenario-library/custom"), "POST", new PreserializedJson(body), {});
    if (response.status !== 201) throw await this.#error(response);
    const value = await this.#parsed(response);
    if (!record(value) || !Array.isArray(value.warnings) || value.warnings.length > 32
      || !value.warnings.every((item) => closedString(item, 512))) invalidResponse();
    const { warnings, ...row } = value;
    const entry = parseLibraryEntry(row);
    if (entry.source !== "custom" || entry.id !== input.definition.id
      || (binding === null) !== (entry.catalogScenarioId === null)
      || (binding !== null && entry.catalogScenarioId !== binding.catalogScenarioId)) invalidResponse();
    return deepFreeze({ ...entry, warnings: warnings as string[] });
  }

  async getRunScenarioBindings(workspaceRef: string, projectRef: string, runRef: string, signal?: AbortSignal): Promise<RunScenarioBindingsView> {
    return parseBindingsView(await this.#json(runPath(workspaceRef, projectRef, runRef, "/scenario-bindings"), "GET", undefined, 200, {}, signal), runRef);
  }

  async freezeRunScenarioBindings(workspaceRef: string, projectRef: string, runRef: string, projectionDigest: string, items: readonly ScenarioBindingItem[]): Promise<RunScenarioBindingsView> {
    if (!digest(projectionDigest) || !Array.isArray(items) || items.length < 1 || items.length > MAX_SCENARIO_BINDING_ITEMS
      || new Set(items.map((item) => item.libraryScenarioId)).size !== items.length
      || !items.every((item) => identifier(item.catalogScenarioId) && (item.method === "GET" || item.method === "HEAD")
        && ROUTE_TEMPLATE.test(item.routeTemplate) && SCENARIO_ID.test(item.libraryScenarioId)
        && (item.source === "library" || item.source === "custom") && digest(item.definitionDigest))) invalidRequest();
    const value = await this.#json(runPath(workspaceRef, projectRef, runRef, "/scenario-bindings"), "POST", {
      schema_version: "heel.run-scenario-bindings.v1",
      projection_digest: projectionDigest,
      items: items.map((item) => ({
        binding_version: 1, catalog_scenario_id: item.catalogScenarioId, definition_digest: item.definitionDigest,
        library_scenario_id: item.libraryScenarioId, method: item.method, route_template: item.routeTemplate, source: item.source,
      })),
    }, 201);
    const view = parseBindingsView(value, runRef);
    if (view.projectionDigest !== projectionDigest || view.bindings.length !== items.length) invalidResponse();
    return view;
  }

  async #json(path: string, method: "GET" | "POST", body: unknown, expectedStatus: number, extraHeaders: Record<string, string> = {}, signal?: AbortSignal): Promise<JsonRecord> {
    const response = await this.#send(path, method, body, extraHeaders, signal);
    if (response.status !== expectedStatus) throw await this.#error(response);
    const value = await this.#parsed(response);
    if (!record(value)) invalidResponse();
    return value;
  }

  async #send(path: string, method: "GET" | "POST", body: unknown, extraHeaders: Record<string, string>, signal?: AbortSignal): Promise<Response> {
    if (!path.startsWith(`${CONTROL_PLANE_PREFIX}/v1/`) || path.includes("?") || path.includes("#")) invalidRequest();
    const headers = new Headers({ Accept: "application/json", ...extraHeaders });
    let payload: string | undefined;
    if (body !== undefined) {
      // Custom definitions carry fractional severities, which the integer-only canonical encoder refuses.
      payload = body instanceof PreserializedJson ? body.text : canonicalJson(body);
      if (new TextEncoder().encode(payload).byteLength > MAX_REQUEST_BYTES) invalidRequest();
      headers.set("Content-Type", "application/json");
    }
    const timeout = new AbortController();
    const timer = setTimeout(() => timeout.abort(new Error("canary request timeout")), this.#timeoutMs);
    const abort = () => timeout.abort(new Error("canary request cancelled"));
    if (signal?.aborted) abort();
    signal?.addEventListener("abort", abort, { once: true });
    try {
      return await this.#transport(path, {
        body: payload,
        cache: "no-store",
        credentials: "same-origin",
        headers,
        method,
        redirect: "error",
        signal: timeout.signal,
      });
    } catch {
      throw new CanaryApiError("unavailable", 0);
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
    }
  }

  async #boundedText(response: Response): Promise<string> {
    const declared = response.headers.get("Content-Length");
    if (declared !== null && (!/^(?:0|[1-9][0-9]*)$/.test(declared) || Number(declared) > MAX_RESPONSE_BYTES)) invalidResponse();
    const body = await response.text();
    if (new TextEncoder().encode(body).byteLength > MAX_RESPONSE_BYTES) invalidResponse();
    return body;
  }

  async #parsed(response: Response): Promise<unknown> {
    if (response.headers.get("Content-Type")?.split(";", 1)[0].trim().toLowerCase() !== "application/json") invalidResponse();
    try {
      return JSON.parse(await this.#boundedText(response));
    } catch (error) {
      if (error instanceof CanaryApiError) throw error;
      invalidResponse();
    }
  }

  async #error(response: Response): Promise<CanaryApiError> {
    let code = "unavailable";
    try {
      const value = await this.#parsed(response);
      if (exact(value, ["schema_version", "code"])
        && value.schema_version === "heel.canary-error.v1" && typeof value.code === "string"
        && PUBLIC_ERROR_CODES.has(value.code)) code = value.code;
      else if (exact(value, ["error", "code"]) && closedString(value.error, 512)
        && typeof value.code === "string" && PUBLIC_ERROR_CODES.has(value.code)) code = value.code;
      else if (record(value) && value.schema_version === "heel.scenario-library-error.v1"
        && typeof value.code === "string" && PUBLIC_ERROR_CODES.has(value.code)
        && (exact(value, ["schema_version", "code"]) || exact(value, ["schema_version", "code", "errors", "warnings"]))) {
        code = value.code;
        if (Array.isArray(value.errors) && value.errors.length <= 32 && value.errors.every((item) => closedString(item, 512))) {
          return new CanaryApiError(code, response.status, value.errors as string[]);
        }
      }
    } catch {
      // A malformed error response never widens the public error surface.
    }
    return new CanaryApiError(code, response.status);
  }
}
