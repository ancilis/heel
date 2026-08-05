// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import { describe, expect, test, vi } from "vitest";

import {
  HeelCloudApi,
  HeelCloudApiError,
  type HeelCloudTransport,
} from "../lib/heel-cloud-api";


const workspaceRef = "ws_0123456789abcdef";
const projectRef = `prj_${"a".repeat(32)}`;
const reviewRef = `synrev_${"b".repeat(32)}`;


function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}


function apiWith(responses: Response[]) {
  const transport = vi.fn<HeelCloudTransport>(async () => {
    const response = responses.shift();
    if (response === undefined) throw new Error("unexpected transport call");
    return response;
  });
  return { api: new HeelCloudApi({ transport }), transport };
}


describe("HeelCloudApi", () => {
  test("uses only same-origin no-store requests and validates a signed-in workspace", async () => {
    const { api, transport } = apiWith([jsonResponse({
      user_id: "usr_0123456789abcdef",
      workspaces: [{ workspace_id: workspaceRef, role: "owner" }],
    })]);

    await expect(api.me()).resolves.toEqual({
      userId: "usr_0123456789abcdef",
      workspaces: [{ workspaceRef, role: "owner" }],
    });
    const [path, init] = transport.mock.calls[0];
    expect(path).toBe("/api/control-plane/v1/me");
    expect(init.credentials).toBe("same-origin");
    expect(init.cache).toBe("no-store");
    expect(init.redirect).toBe("error");
    expect(new Headers(init.headers).get("authorization")).toBeNull();
  });

  test.each(["signup", "login"] as const)("posts closed %s credentials without reflecting them", async (action) => {
    const { api, transport } = apiWith([jsonResponse(
      action === "signup"
        ? { user_id: "usr_0123456789abcdef", workspace_id: workspaceRef }
        : { user_id: "usr_0123456789abcdef" },
      action === "signup" ? 201 : 200,
    )]);
    const secret = "correct-horse-staple-42";

    await api[action]("founder@example.com", secret);
    const [path, init] = transport.mock.calls[0];
    expect(path).toBe(`/api/control-plane/v1/${action}`);
    expect(init.method).toBe("POST");
    expect(new Headers(init.headers).get("content-type")).toBe("application/json");
    expect(JSON.parse(init.body as string)).toEqual({ email: "founder@example.com", password: secret });
  });

  test("creates, lists, and resolves a project namespace through exact tenant paths", async () => {
    const project = {
      workspace_id: workspaceRef,
      project_ref: projectRef,
      name: "Production API",
      created_by: "usr_0123456789abcdef",
      created_at: 1_786_000_000,
    };
    const { api, transport } = apiWith([
      jsonResponse(project, 201),
      jsonResponse({ projects: [project] }),
      jsonResponse({ project_ref: projectRef, namespace_key_hex: "ab".repeat(32) }),
    ]);

    await expect(api.createProject(workspaceRef, "Production API")).resolves.toMatchObject({
      workspaceRef,
      projectRef,
      name: "Production API",
    });
    await expect(api.listProjects(workspaceRef)).resolves.toHaveLength(1);
    await expect(api.namespaceKey(workspaceRef, projectRef)).resolves.toEqual(
      new Uint8Array(32).fill(0xab),
    );
    expect(transport.mock.calls.map(([path]) => path)).toEqual([
      `/api/control-plane/v1/workspaces/${workspaceRef}/projects`,
      `/api/control-plane/v1/workspaces/${workspaceRef}/projects`,
      `/api/control-plane/v1/workspaces/${workspaceRef}/projects/${projectRef}/namespace-key`,
    ]);
  });

  test("inspects then explicitly decides a closed device claim", async () => {
    const userCode = "ABCD-EFGH";
    const nonce = `heel_dcn_${"a".repeat(43)}`;
    const { api, transport } = apiWith([
      jsonResponse({
        schema_version: "heel.device-verify-view.v1",
        status: "pending",
        user_code: userCode,
        client_id: "heel-agent",
        device_name: "Alice's MacBook",
        device_fingerprint: "7J4D-QW9K",
        capabilities: ["sync_findings", "view_synced_reviews"],
        expires_in: 421,
        confirmation_nonce: nonce,
      }),
      jsonResponse({ schema_version: "heel.device-verify-response.v1", status: "approved" }),
    ]);

    await expect(api.inspectDevice(userCode)).resolves.toMatchObject({
      userCode,
      deviceName: "Alice's MacBook",
      deviceFingerprint: "7J4D-QW9K",
      confirmationNonce: nonce,
    });
    await expect(api.decideDevice(userCode, "approve", nonce, workspaceRef)).resolves.toBe("approved");
    expect(transport.mock.calls.map(([path]) => path)).toEqual([
      "/api/control-plane/v1/device/verify",
      "/api/control-plane/v1/device/verify",
    ]);
    expect(JSON.parse(transport.mock.calls[0][1].body as string)).toEqual({
      schema_version: "heel.device-verify.v1", user_code: userCode, action: "inspect",
    });
    expect(JSON.parse(transport.mock.calls[1][1].body as string)).toEqual({
      schema_version: "heel.device-verify.v1",
      user_code: userCode,
      action: "approve",
      workspace_id: workspaceRef,
      confirmation_nonce: nonce,
    });
  });

  test("rejects malformed device claims and never decides without a confirmation nonce", async () => {
    const { api } = apiWith([jsonResponse({
      schema_version: "heel.device-verify-view.v1",
      status: "pending",
      user_code: "ABCD-EFGH",
      client_id: "heel-agent",
      device_name: "CLI",
      device_fingerprint: "7J4D-QW9K",
      capabilities: ["sync_findings", "view_synced_reviews", "admin"],
      expires_in: 421,
      confirmation_nonce: `heel_dcn_${"a".repeat(43)}`,
    })]);
    await expect(api.inspectDevice("ABCD-EFGH")).rejects.toMatchObject({ code: "invalid_response" });
    await expect(api.decideDevice("ABCD-EFGH", "approve", "", workspaceRef))
      .rejects.toMatchObject({ code: "invalid_request" });
  });

  test("binds approval and findings transport to exact bytes without adding client approval claims", async () => {
    const requestDigest = "c".repeat(64);
    const requestJson = JSON.stringify({ schema_version: "heel.findings-sync.v1" });
    const { api, transport } = apiWith([
      jsonResponse({
        workspace_id: workspaceRef,
        project_ref: projectRef,
        approval_id: `fsauth_${"d".repeat(32)}`,
        request_digest: requestDigest,
        approved_by: "usr_0123456789abcdef",
        approved_at: 1_786_000_000,
        expires_at: 1_786_000_600,
      }, 201),
      new Response("receipt-json", { status: 201, headers: { "Content-Type": "application/json" } }),
    ]);

    await expect(api.approveFindings(workspaceRef, projectRef, requestDigest)).resolves.toMatchObject({
      workspaceRef,
      projectRef,
      requestDigest,
      approvedAt: 1_786_000_000_000,
      expiresAt: 1_786_000_600_000,
    });
    const controller = new AbortController();
    await expect(api.sendFindings(
      workspaceRef,
      projectRef,
      requestJson,
      `fs1-${requestDigest}`,
      controller.signal,
    )).resolves.toBe("receipt-json");
    const approvalInit = transport.mock.calls[0][1];
    expect(JSON.parse(approvalInit.body as string)).toEqual({ request_digest: requestDigest });
    expect(approvalInit.body).not.toContain("approved");
    const syncInit = transport.mock.calls[1][1];
    expect(syncInit.body).toBe(requestJson);
    expect(syncInit.signal).toBe(controller.signal);
    expect(new Headers(syncInit.headers).get("idempotency-key")).toBe(`fs1-${requestDigest}`);
  });

  test("lists hosted history and rejects extra response fields", async () => {
    const summary = {
      synced_review_id: reviewRef,
      projection_hash: "d".repeat(64),
      gate_status: "warn",
      findings_count: 1,
      blockers_count: 0,
      created_at: 1_786_000_000,
    };
    const { api } = apiWith([
      jsonResponse({ reviews: [summary] }),
      jsonResponse({ reviews: [summary], raw_review: "never-cross" }),
    ]);
    await expect(api.listReviews(workspaceRef, projectRef)).resolves.toEqual([{
      syncedReviewId: reviewRef,
      projectionHash: "d".repeat(64),
      gateStatus: "warn",
      findingsCount: 1,
      blockersCount: 0,
      createdAt: 1_786_000_000,
    }]);
    await expect(api.listReviews(workspaceRef, projectRef)).rejects.toBeInstanceOf(HeelCloudApiError);
  });

  test("turns backend and transport failures into bounded non-echoing public errors", async () => {
    const secret = "private-backend-response-never-echo";
    const { api } = apiWith([
      jsonResponse({ error: secret, code: "approval_required" }, 403),
    ]);
    let failure: unknown;
    try {
      await api.listProjects(workspaceRef);
    } catch (error) {
      failure = error;
    }
    expect(failure).toBeInstanceOf(HeelCloudApiError);
    expect((failure as Error).message).not.toContain(secret);
    expect(failure).toMatchObject({ status: 403, code: "approval_required" });

    const offline = new HeelCloudApi({ transport: async () => { throw new Error(secret); } });
    await expect(offline.listProjects(workspaceRef)).rejects.toMatchObject({ code: "unavailable" });
    await expect(offline.listProjects(workspaceRef)).rejects.not.toThrow(secret);
  });

  test("preserves the closed approval-expired code so the UI can request fresh consent", async () => {
    const { api } = apiWith([
      jsonResponse({ code: "approval_expired", error: "private-detail" }, 403),
    ]);
    await expect(api.listProjects(workspaceRef)).rejects.toMatchObject({
      code: "approval_expired",
      status: 403,
      message: "That approval expired. Review the exact JSON and approve it again.",
    });
  });
});
