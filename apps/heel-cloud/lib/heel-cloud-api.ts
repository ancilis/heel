// SPDX-License-Identifier: LicenseRef-Heel-Commercial

/** Closed same-origin client for Heel's authenticated findings continuity API. */

const CONTROL_PLANE_PREFIX = "/api/control-plane";
const MAX_RESPONSE_BYTES = 256 * 1024;
const USER_REF = /^usr_[0-9a-f]{16}$/;
const WORKSPACE_REF = /^ws_[0-9a-f]{16}$/;
const PROJECT_REF = /^prj_[0-9a-f]{32}$/;
const REVIEW_REF = /^synrev_[0-9a-f]{32}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const NAMESPACE_KEY = /^[0-9a-f]{64}$/;
const APPROVAL_REF = /^fsauth_[0-9a-f]{32}$/;
const ROLE = new Set(["owner", "admin", "member", "viewer", "billing"]);
const GATE = new Set(["pass", "warn", "block"]);
const DEVICE_USER_CODE = /^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/;
const DEVICE_FINGERPRINT = /^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/;
const DEVICE_CONFIRMATION = /^heel_dcn_[A-Za-z0-9_-]{43}$/;
const DEVICE_CAPABILITIES = ["sync_findings", "view_synced_reviews"] as const;

export type HeelCloudTransport = (path: string, init: RequestInit) => Promise<Response>;

export interface HeelCloudWorkspace {
  workspaceRef: string;
  role: "owner" | "admin" | "member" | "viewer" | "billing";
}

export interface HeelCloudSession {
  userId: string;
  workspaces: HeelCloudWorkspace[];
}

export interface HeelCloudProject {
  workspaceRef: string;
  projectRef: string;
  name: string;
  createdBy: string;
  createdAt: number;
}

export interface HeelCloudApproval {
  workspaceRef: string;
  projectRef: string;
  approvalId: string;
  requestDigest: string;
  approvedBy: string;
  approvedAt: number;
  expiresAt: number;
}

export interface HeelDeviceClaim {
  userCode: string;
  deviceName: string;
  deviceFingerprint: string;
  capabilities: typeof DEVICE_CAPABILITIES;
  expiresIn: number;
  confirmationNonce: string;
}

export interface HeelCloudReviewSummary {
  syncedReviewId: string;
  projectionHash: string;
  gateStatus: "pass" | "warn" | "block";
  findingsCount: number;
  blockersCount: number;
  createdAt: number;
}

export interface HeelCloudApiOptions {
  transport?: HeelCloudTransport;
}

type JsonRecord = Record<string, unknown>;


async function sameOriginControlPlaneFetch(path: string, init: RequestInit): Promise<Response> {
  return fetch(path, init);
}


function isRecord(value: unknown): value is JsonRecord {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}


function exactFields(value: JsonRecord, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return actual.length === wanted.length && actual.every((key, index) => key === wanted[index]);
}


function finiteNonnegative(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0;
}


function safeCount(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}


function closedString(value: unknown, maxLength = 160): value is string {
  return typeof value === "string"
    && value.length > 0
    && value.length <= maxLength
    && !/[\u0000-\u001f\u007f]/.test(value);
}


function projectPath(workspaceRef: string, suffix = ""): string {
  if (!WORKSPACE_REF.test(workspaceRef)) throw new HeelCloudApiError("invalid_request", 0);
  return `${CONTROL_PLANE_PREFIX}/v1/workspaces/${workspaceRef}/projects${suffix}`;
}


function projectResourcePath(workspaceRef: string, projectRef: string, suffix = ""): string {
  if (!PROJECT_REF.test(projectRef)) throw new HeelCloudApiError("invalid_request", 0);
  return projectPath(workspaceRef, `/${projectRef}${suffix}`);
}


function parseProject(value: unknown): HeelCloudProject {
  if (!isRecord(value) || !exactFields(
    value,
    ["workspace_id", "project_ref", "name", "created_by", "created_at"],
  )) throw new HeelCloudApiError("invalid_response", 502);
  if (
    typeof value.workspace_id !== "string" || !WORKSPACE_REF.test(value.workspace_id)
    || typeof value.project_ref !== "string" || !PROJECT_REF.test(value.project_ref)
    || !closedString(value.name, 120)
    || !closedString(value.created_by, 256)
    || !finiteNonnegative(value.created_at)
  ) throw new HeelCloudApiError("invalid_response", 502);
  return Object.freeze({
    workspaceRef: value.workspace_id,
    projectRef: value.project_ref,
    name: value.name,
    createdBy: value.created_by,
    createdAt: value.created_at,
  });
}


function parseReviewSummary(value: unknown): HeelCloudReviewSummary {
  if (!isRecord(value) || !exactFields(value, [
    "synced_review_id", "projection_hash", "gate_status", "findings_count",
    "blockers_count", "created_at",
  ])) throw new HeelCloudApiError("invalid_response", 502);
  if (
    typeof value.synced_review_id !== "string" || !REVIEW_REF.test(value.synced_review_id)
    || typeof value.projection_hash !== "string" || !DIGEST.test(value.projection_hash)
    || typeof value.gate_status !== "string" || !GATE.has(value.gate_status)
    || !safeCount(value.findings_count)
    || !safeCount(value.blockers_count)
    || (value.blockers_count as number) > (value.findings_count as number)
    || !finiteNonnegative(value.created_at)
  ) throw new HeelCloudApiError("invalid_response", 502);
  return Object.freeze({
    syncedReviewId: value.synced_review_id,
    projectionHash: value.projection_hash,
    gateStatus: value.gate_status as HeelCloudReviewSummary["gateStatus"],
    findingsCount: value.findings_count as number,
    blockersCount: value.blockers_count as number,
    createdAt: value.created_at,
  });
}


const PUBLIC_MESSAGES: Readonly<Record<string, string>> = Object.freeze({
  approval_expired: "That approval expired. Review the exact JSON and approve it again.",
  approval_required: "Confirm this exact findings-only preview before syncing.",
  auth_required: "Sign in to use Heel Cloud continuity.",
  conflict: "This local projection no longer matches its cloud record.",
  invalid_request: "Heel could not safely prepare that cloud request.",
  invalid_response: "Heel Cloud returned an invalid response.",
  invalid_grant: "That device code is invalid, expired, or already used.",
  quota_exceeded: "This workspace has reached its synced-review allowance.",
  unavailable: "Heel Cloud is temporarily unavailable. Your local result is unchanged.",
  recent_auth_required: "Sign in again before authorizing a device.",
});
const PUBLIC_ERROR_CODES = new Set(Object.keys(PUBLIC_MESSAGES));

export class HeelCloudApiError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(code: string, status: number) {
    const safeCode = PUBLIC_ERROR_CODES.has(code) ? code : "unavailable";
    super(PUBLIC_MESSAGES[safeCode]);
    this.name = "HeelCloudApiError";
    this.code = safeCode;
    this.status = status;
  }
}


export class HeelCloudApi {
  readonly #transport: HeelCloudTransport;

  constructor(options: HeelCloudApiOptions = {}) {
    this.#transport = options.transport ?? sameOriginControlPlaneFetch;
  }

  async signup(email: string, password: string): Promise<{ userId: string; workspaceRef: string }> {
    const value = await this.#json("/v1/signup", "POST", { email, password }, 201);
    if (!exactFields(value, ["user_id", "workspace_id"])
      || typeof value.user_id !== "string" || !USER_REF.test(value.user_id)
      || typeof value.workspace_id !== "string" || !WORKSPACE_REF.test(value.workspace_id)) {
      throw new HeelCloudApiError("invalid_response", 502);
    }
    return Object.freeze({ userId: value.user_id, workspaceRef: value.workspace_id });
  }

  async login(email: string, password: string): Promise<{ userId: string }> {
    const value = await this.#json("/v1/login", "POST", { email, password }, 200);
    if (!exactFields(value, ["user_id"])
      || typeof value.user_id !== "string" || !USER_REF.test(value.user_id)) {
      throw new HeelCloudApiError("invalid_response", 502);
    }
    return Object.freeze({ userId: value.user_id });
  }

  async logout(): Promise<void> {
    const value = await this.#json("/v1/logout", "POST", {}, 200);
    if (!exactFields(value, ["ok"]) || value.ok !== true) {
      throw new HeelCloudApiError("invalid_response", 502);
    }
  }

  async me(): Promise<HeelCloudSession> {
    const value = await this.#json("/v1/me", "GET", undefined, 200);
    if (!exactFields(value, ["user_id", "workspaces"])
      || typeof value.user_id !== "string" || !USER_REF.test(value.user_id)
      || !Array.isArray(value.workspaces) || value.workspaces.length > 100) {
      throw new HeelCloudApiError("invalid_response", 502);
    }
    const workspaces = value.workspaces.map((item) => {
      if (!isRecord(item) || !exactFields(item, ["workspace_id", "role"])
        || typeof item.workspace_id !== "string" || !WORKSPACE_REF.test(item.workspace_id)
        || typeof item.role !== "string" || !ROLE.has(item.role)) {
        throw new HeelCloudApiError("invalid_response", 502);
      }
      return Object.freeze({
        workspaceRef: item.workspace_id,
        role: item.role as HeelCloudWorkspace["role"],
      });
    });
    return Object.freeze({ userId: value.user_id, workspaces: Object.freeze(workspaces) as HeelCloudWorkspace[] });
  }

  async inspectDevice(userCode: string): Promise<HeelDeviceClaim> {
    if (!DEVICE_USER_CODE.test(userCode)) throw new HeelCloudApiError("invalid_request", 0);
    const value = await this.#json("/v1/device/verify", "POST", {
      schema_version: "heel.device-verify.v1",
      user_code: userCode,
      action: "inspect",
    }, 200);
    if (!exactFields(value, [
      "schema_version", "status", "user_code", "client_id", "device_name",
      "device_fingerprint", "capabilities", "expires_in", "confirmation_nonce",
    ])
      || value.schema_version !== "heel.device-verify-view.v1"
      || value.status !== "pending"
      || value.user_code !== userCode
      || value.client_id !== "heel-agent"
      || !closedString(value.device_name, 64)
      || typeof value.device_fingerprint !== "string"
      || !DEVICE_FINGERPRINT.test(value.device_fingerprint)
      || !Array.isArray(value.capabilities)
      || value.capabilities.length !== DEVICE_CAPABILITIES.length
      || value.capabilities.some((item, index) => item !== DEVICE_CAPABILITIES[index])
      || !Number.isSafeInteger(value.expires_in)
      || (value.expires_in as number) < 0
      || (value.expires_in as number) > 600
      || typeof value.confirmation_nonce !== "string"
      || !DEVICE_CONFIRMATION.test(value.confirmation_nonce)) {
      throw new HeelCloudApiError("invalid_response", 502);
    }
    return Object.freeze({
      userCode,
      deviceName: value.device_name,
      deviceFingerprint: value.device_fingerprint,
      capabilities: DEVICE_CAPABILITIES,
      expiresIn: value.expires_in as number,
      confirmationNonce: value.confirmation_nonce,
    });
  }

  async decideDevice(
    userCode: string,
    action: "approve" | "deny",
    confirmationNonce: string,
    workspaceRef?: string,
  ): Promise<"approved" | "denied"> {
    if (
      !DEVICE_USER_CODE.test(userCode)
      || !DEVICE_CONFIRMATION.test(confirmationNonce)
      || (action === "approve" && (workspaceRef === undefined || !WORKSPACE_REF.test(workspaceRef)))
      || (action === "deny" && workspaceRef !== undefined)
    ) throw new HeelCloudApiError("invalid_request", 0);
    const value = await this.#json("/v1/device/verify", "POST", {
      schema_version: "heel.device-verify.v1",
      user_code: userCode,
      action,
      ...(action === "approve" ? { workspace_id: workspaceRef } : {}),
      confirmation_nonce: confirmationNonce,
    }, 200);
    const status = action === "approve" ? "approved" : "denied";
    if (!exactFields(value, ["schema_version", "status"])
      || value.schema_version !== "heel.device-verify-response.v1"
      || value.status !== status) {
      throw new HeelCloudApiError("invalid_response", 502);
    }
    return status;
  }

  async createProject(workspaceRef: string, name: string): Promise<HeelCloudProject> {
    if (!closedString(name, 120)) throw new HeelCloudApiError("invalid_request", 0);
    const value = await this.#jsonPath(projectPath(workspaceRef), "POST", { name }, 201);
    const project = parseProject(value);
    if (project.workspaceRef !== workspaceRef) throw new HeelCloudApiError("invalid_response", 502);
    return project;
  }

  async listProjects(workspaceRef: string): Promise<HeelCloudProject[]> {
    const value = await this.#jsonPath(projectPath(workspaceRef), "GET", undefined, 200);
    if (!exactFields(value, ["projects"]) || !Array.isArray(value.projects) || value.projects.length > 500) {
      throw new HeelCloudApiError("invalid_response", 502);
    }
    const projects = value.projects.map(parseProject);
    if (projects.some((project) => project.workspaceRef !== workspaceRef)) {
      throw new HeelCloudApiError("invalid_response", 502);
    }
    return projects;
  }

  async namespaceKey(workspaceRef: string, projectRef: string): Promise<Uint8Array<ArrayBuffer>> {
    const value = await this.#jsonPath(
      projectResourcePath(workspaceRef, projectRef, "/namespace-key"), "GET", undefined, 200,
    );
    if (!exactFields(value, ["project_ref", "namespace_key_hex"])
      || value.project_ref !== projectRef
      || typeof value.namespace_key_hex !== "string" || !NAMESPACE_KEY.test(value.namespace_key_hex)) {
      throw new HeelCloudApiError("invalid_response", 502);
    }
    return Uint8Array.from(value.namespace_key_hex.match(/../g) ?? [], (byte) => Number.parseInt(byte, 16));
  }

  async approveFindings(
    workspaceRef: string,
    projectRef: string,
    requestDigest: string,
  ): Promise<HeelCloudApproval> {
    if (!DIGEST.test(requestDigest)) throw new HeelCloudApiError("invalid_request", 0);
    const value = await this.#jsonPath(
      projectResourcePath(workspaceRef, projectRef, "/findings-sync/approve"),
      "POST",
      { request_digest: requestDigest },
      201,
    );
    if (!exactFields(value, [
      "workspace_id", "project_ref", "approval_id", "request_digest", "approved_by",
      "approved_at", "expires_at",
    ])
      || value.workspace_id !== workspaceRef || value.project_ref !== projectRef
      || typeof value.approval_id !== "string" || !APPROVAL_REF.test(value.approval_id)
      || value.request_digest !== requestDigest || !closedString(value.approved_by, 256)
      || !finiteNonnegative(value.approved_at) || !finiteNonnegative(value.expires_at)
      || value.expires_at < value.approved_at || value.expires_at - value.approved_at > 600) {
      throw new HeelCloudApiError("invalid_response", 502);
    }
    return Object.freeze({
      workspaceRef,
      projectRef,
      approvalId: value.approval_id,
      requestDigest,
      approvedBy: value.approved_by,
      approvedAt: Math.round(value.approved_at * 1_000),
      expiresAt: Math.round(value.expires_at * 1_000),
    });
  }

  async sendFindings(
    workspaceRef: string,
    projectRef: string,
    requestJson: string,
    idempotencyKey: `fs1-${string}`,
    signal?: AbortSignal,
  ): Promise<string> {
    if (typeof requestJson !== "string"
      || new TextEncoder().encode(requestJson).byteLength > MAX_RESPONSE_BYTES
      || !/^fs1-[0-9a-f]{64}$/.test(idempotencyKey)) {
      throw new HeelCloudApiError("invalid_request", 0);
    }
    const response = await this.#request(
      projectResourcePath(workspaceRef, projectRef, "/findings-sync"),
      "POST",
      requestJson,
      { "Idempotency-Key": idempotencyKey },
      signal,
    );
    if (response.status !== 201) throw await this.#responseError(response);
    return this.#boundedText(response);
  }

  async listReviews(workspaceRef: string, projectRef: string): Promise<HeelCloudReviewSummary[]> {
    const value = await this.#jsonPath(
      projectResourcePath(workspaceRef, projectRef, "/reviews"), "GET", undefined, 200,
    );
    if (!exactFields(value, ["reviews"]) || !Array.isArray(value.reviews) || value.reviews.length > 2_000) {
      throw new HeelCloudApiError("invalid_response", 502);
    }
    return value.reviews.map(parseReviewSummary);
  }

  async #json(
    path: string,
    method: "GET" | "POST",
    body: JsonRecord | undefined,
    expectedStatus: number,
  ): Promise<JsonRecord> {
    return this.#jsonPath(`${CONTROL_PLANE_PREFIX}${path}`, method, body, expectedStatus);
  }

  async #jsonPath(
    path: string,
    method: "GET" | "POST",
    body: JsonRecord | undefined,
    expectedStatus: number,
  ): Promise<JsonRecord> {
    const response = await this.#request(
      path,
      method,
      body === undefined ? undefined : JSON.stringify(body),
    );
    if (response.status !== expectedStatus) throw await this.#responseError(response);
    const value = await this.#parsedJson(response);
    if (!isRecord(value)) throw new HeelCloudApiError("invalid_response", 502);
    return value;
  }

  async #request(
    path: string,
    method: "GET" | "POST",
    body?: string,
    extraHeaders: Record<string, string> = {},
    signal?: AbortSignal,
  ): Promise<Response> {
    if (!path.startsWith(`${CONTROL_PLANE_PREFIX}/v1/`) || path.includes("?") || path.includes("#")) {
      throw new HeelCloudApiError("invalid_request", 0);
    }
    const headers = new Headers({ Accept: "application/json", ...extraHeaders });
    if (body !== undefined) headers.set("Content-Type", "application/json");
    try {
      return await this.#transport(path, {
        body,
        cache: "no-store",
        credentials: "same-origin",
        headers,
        method,
        redirect: "error",
        signal,
      });
    } catch {
      throw new HeelCloudApiError("unavailable", 0);
    }
  }

  async #boundedText(response: Response): Promise<string> {
    const declared = response.headers.get("Content-Length");
    if (declared !== null && (!/^(?:0|[1-9][0-9]*)$/.test(declared) || Number(declared) > MAX_RESPONSE_BYTES)) {
      throw new HeelCloudApiError("invalid_response", 502);
    }
    const text = await response.text();
    if (new TextEncoder().encode(text).byteLength > MAX_RESPONSE_BYTES) {
      throw new HeelCloudApiError("invalid_response", 502);
    }
    return text;
  }

  async #parsedJson(response: Response): Promise<unknown> {
    const contentType = response.headers.get("Content-Type")?.split(";", 1)[0].trim().toLowerCase();
    if (contentType !== "application/json") throw new HeelCloudApiError("invalid_response", 502);
    try {
      return JSON.parse(await this.#boundedText(response));
    } catch (error) {
      if (error instanceof HeelCloudApiError) throw error;
      throw new HeelCloudApiError("invalid_response", 502);
    }
  }

  async #responseError(response: Response): Promise<HeelCloudApiError> {
    let code = response.status === 401 ? "auth_required"
      : response.status === 402 ? "quota_exceeded"
        : response.status === 409 ? "conflict"
          : "unavailable";
    try {
      const value = await this.#parsedJson(response);
      if (isRecord(value) && typeof value.code === "string" && PUBLIC_ERROR_CODES.has(value.code)) {
        code = value.code;
      }
    } catch {
      // The public status mapping remains bounded even for a malformed error body.
    }
    return new HeelCloudApiError(code, response.status);
  }
}
