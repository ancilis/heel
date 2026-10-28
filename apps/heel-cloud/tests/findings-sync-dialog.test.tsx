// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { afterEach, describe, expect, test, vi } from "vitest";

import sampleReview from "../data/sample-review.v1.json";
import { FindingsSyncDialog, type FindingsSyncDialogServices } from "../components/review/FindingsSyncDialog";
import { HeelCloudApiError } from "../lib/heel-cloud-api";
import type { PreparedFindingsSyncV1 } from "../lib/findings-sync-client";
import type { FindingsSyncReceiptV1, FindingsSyncRequestV1 } from "../lib/findings-sync-v1";
import type { ReviewEnvelopeV1 } from "../lib/review-v1";


const workspaceRef = "ws_0123456789abcdef";
const projectRef = "prj_0123456789abcdef0123456789abcdef";
const requestJson = readFileSync(
  resolve(process.cwd(), "../../tests/fixtures/findings_sync/request-one-finding.json"),
  "utf8",
).trim();
const request = JSON.parse(requestJson) as FindingsSyncRequestV1;
const requestDigest = createHash("sha256").update(requestJson, "utf8").digest("hex");
const prepared: PreparedFindingsSyncV1 = {
  request,
  requestJson,
  requestDigest,
  idempotencyKey: `fs1-${requestDigest}`,
};
const receipt = JSON.parse(readFileSync(
  resolve(process.cwd(), "../../tests/fixtures/findings_sync/receipt-created.json"),
  "utf8",
)) as FindingsSyncReceiptV1;
const project = {
  workspaceRef,
  projectRef,
  name: "Production API",
  createdBy: "usr_0123456789abcdef",
  createdAt: 1_786_000_000,
};


function services(overrides: Partial<FindingsSyncDialogServices> = {}) {
  const api = {
    me: vi.fn().mockResolvedValue({
      userId: "usr_0123456789abcdef",
      workspaces: [{ workspaceRef, role: "owner" }],
    }),
    signup: vi.fn().mockResolvedValue({ userId: "usr_0123456789abcdef", workspaceRef }),
    login: vi.fn().mockResolvedValue({ userId: "usr_0123456789abcdef" }),
    logout: vi.fn().mockResolvedValue(undefined),
    listProjects: vi.fn().mockResolvedValue([project]),
    createProject: vi.fn().mockResolvedValue(project),
    namespaceKey: vi.fn().mockResolvedValue(new Uint8Array(32).fill(0xab)),
    approveFindings: vi.fn().mockResolvedValue({
      workspaceRef,
      projectRef,
      approvalId: `fsauth_${"b".repeat(32)}`,
      requestDigest,
      approvedBy: "usr_0123456789abcdef",
      approvedAt: Date.now() - 1_000,
      expiresAt: Date.now() + 60_000,
    }),
    sendFindings: vi.fn().mockResolvedValue(JSON.stringify(receipt)),
    listReviews: vi.fn()
      .mockResolvedValueOnce([])
      .mockResolvedValue([{
        syncedReviewId: receipt.synced_review_id,
        projectionHash: receipt.projection_hash,
        gateStatus: request.gate_status,
        findingsCount: request.summary.findings,
        blockersCount: request.summary.blockers,
        createdAt: 1_786_000_000,
      }]),
  };
  const projector = {
    preview: vi.fn().mockResolvedValue(prepared),
    dispose: vi.fn(),
  };
  const lease = {
    leaseToken: `fsl_${"c".repeat(32)}`,
    leaseExpiresAt: Date.now() + 30_000,
    record: {
      workspace_ref: workspaceRef,
      project_ref: projectRef,
      request_digest: requestDigest,
    },
  };
  const queue = {
    enqueue: vi.fn().mockResolvedValue({}),
    claim: vi.fn().mockResolvedValue(lease),
    claimNext: vi.fn().mockResolvedValue(null),
    list: vi.fn().mockResolvedValue([]),
    renew: vi.fn().mockResolvedValue(lease),
    complete: vi.fn().mockResolvedValue(true),
    scheduleRetry: vi.fn().mockResolvedValue(true),
  };
  return { api, projector, queue, ...overrides } as unknown as FindingsSyncDialogServices;
}


function durableRetryLease() {
  const approvedAt = Date.now() - 1_000;
  const leaseExpiresAt = Date.now() + 30_000;
  return {
    leaseToken: `fsl_${"d".repeat(32)}`,
    leaseExpiresAt,
    record: {
      schema_version: "heel.findings-sync-queue.v1",
      workspace_ref: workspaceRef,
      project_ref: projectRef,
      request_digest: requestDigest,
      request_json: requestJson,
      approved_at: approvedAt,
      expires_at: approvedAt + 5 * 60_000,
      retry: {
        attempts: 2,
        next_attempt_at: approvedAt,
        last_error_code: "transport_error",
        lease_token: `fsl_${"d".repeat(32)}`,
        lease_expires_at: leaseExpiresAt,
      },
      receipt: null,
    },
  };
}


afterEach(() => {
  vi.useRealTimers();
  cleanup();
});


describe("FindingsSyncDialog", () => {
  test("requires a human click on an exact findings-only preview before any sync request", async () => {
    const deps = services();
    const synced = vi.fn();
    render(<FindingsSyncDialog
      open
      review={sampleReview as ReviewEnvelopeV1}
      services={deps}
      onClose={() => {}}
      onSynced={synced}
    />);

    const prepare = await screen.findByRole("button", { name: /Prepare findings-only preview/i });
    expect(deps.api.approveFindings).not.toHaveBeenCalled();
    expect(deps.api.sendFindings).not.toHaveBeenCalled();
    fireEvent.click(prepare);

    const approve = await screen.findByRole("button", { name: /Approve and sync these findings/i });
    const dialogText = screen.getByRole("dialog").textContent ?? "";
    expect(dialogText).toContain("local model flagged");
    expect(dialogText).toContain("not declared");
    expect(dialogText).toContain("OpenAPI document stays in this browser");
    expect(screen.getByText((_content, element) => (
      element?.tagName === "PRE" && element.textContent === requestJson
    ))).toBeTruthy();
    expect(dialogText).not.toContain((sampleReview as ReviewEnvelopeV1).product_id);
    expect(deps.api.approveFindings).not.toHaveBeenCalled();
    fireEvent.click(approve);

    await screen.findByText(/Findings continuity is available/i);
    expect(deps.api.approveFindings).toHaveBeenCalledWith(workspaceRef, projectRef, requestDigest);
    expect(deps.queue.enqueue).toHaveBeenCalledOnce();
    expect(deps.queue.claim).toHaveBeenCalledWith(workspaceRef, projectRef, requestDigest);
    expect(deps.api.sendFindings).toHaveBeenCalledWith(
      workspaceRef,
      projectRef,
      requestJson,
      `fs1-${requestDigest}`,
      expect.any(AbortSignal),
    );
    expect(deps.queue.complete).toHaveBeenCalledWith(expect.anything(), receipt);
    expect(synced).toHaveBeenCalledWith(receipt);
    expect((await screen.findAllByText(/1 locally flagged finding/i)).length).toBeGreaterThanOrEqual(1);
  });

  test("shows account creation only after the user opens continuity and loads projects after signup", async () => {
    const deps = services();
    deps.api.me = vi.fn()
      .mockRejectedValueOnce(new HeelCloudApiError("auth_required", 401))
      .mockResolvedValue({
        userId: "usr_0123456789abcdef",
        workspaces: [{ workspaceRef, role: "owner" }],
      });
    render(<FindingsSyncDialog
      open
      review={sampleReview as ReviewEnvelopeV1}
      services={deps}
      onClose={() => {}}
      onSynced={() => {}}
    />);

    expect(await screen.findByRole("heading", { name: /Sign in to keep findings/i })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /Create account instead/i }));
    fireEvent.change(screen.getByLabelText("Work email"), { target: { value: "founder@example.com" } });
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "correct-horse-staple-42" } });
    fireEvent.click(screen.getByRole("button", { name: "Create Heel account" }));

    await screen.findByRole("button", { name: /Prepare findings-only preview/i });
    expect(deps.api.signup).toHaveBeenCalledWith("founder@example.com", "correct-horse-staple-42");
    expect(deps.api.listProjects).toHaveBeenCalledWith(workspaceRef);
    expect(deps.api.sendFindings).not.toHaveBeenCalled();
  });

  test("focuses the modal, traps reverse tabbing, and closes with Escape", async () => {
    const deps = services();
    const closed = vi.fn();
    const view = render(<>
      <button type="button" data-testid="behind-dialog">Behind dialog</button>
      <FindingsSyncDialog
        open
        review={sampleReview as ReviewEnvelopeV1}
        services={deps}
        onClose={closed}
        onSynced={() => {}}
      />
    </>);

    const behind = screen.getByTestId("behind-dialog");
    const close = await screen.findByRole("button", { name: /Close findings continuity/i });
    await screen.findByRole("button", { name: /Prepare findings-only preview/i });
    expect(behind.inert).toBe(true);
    expect(behind.getAttribute("aria-hidden")).toBe("true");
    expect(close.ownerDocument.activeElement).toBe(close);
    fireEvent.keyDown(close, { key: "Tab", shiftKey: true });
    expect(close.ownerDocument.activeElement).not.toBe(close);
    fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });
    expect(closed).toHaveBeenCalledOnce();
    view.unmount();
    expect(behind.inert).toBeFalsy();
    expect(behind.getAttribute("aria-hidden")).toBeNull();
  });

  test("keeps an approved immutable retry when transport fails", async () => {
    const deps = services();
    deps.api.sendFindings = vi.fn().mockRejectedValue(new HeelCloudApiError("unavailable", 503));
    render(<FindingsSyncDialog
      open
      review={sampleReview as ReviewEnvelopeV1}
      services={deps}
      onClose={() => {}}
      onSynced={() => {}}
    />);
    fireEvent.click(await screen.findByRole("button", { name: /Prepare findings-only preview/i }));
    fireEvent.click(await screen.findByRole("button", { name: /Approve and sync these findings/i }));

    await screen.findByText(/saved locally for a safe retry/i);
    expect(deps.queue.scheduleRetry).toHaveBeenCalledWith(
      expect.anything(),
      expect.any(Number),
      "transport_error",
    );
  });

  test("surfaces expired approval precisely and leaves the exact preview ready to approve again", async () => {
    const deps = services();
    deps.api.sendFindings = vi.fn().mockRejectedValue(
      new HeelCloudApiError("approval_expired", 403),
    );
    render(<FindingsSyncDialog
      open
      review={sampleReview as ReviewEnvelopeV1}
      services={deps}
      onClose={() => {}}
      onSynced={() => {}}
    />);
    fireEvent.click(await screen.findByRole("button", { name: /Prepare findings-only preview/i }));
    fireEvent.click(await screen.findByRole("button", { name: /Approve and sync these findings/i }));

    expect((await screen.findByRole("alert")).textContent).toMatch(/approval expired/i);
    expect(deps.queue.scheduleRetry).toHaveBeenCalledWith(
      expect.anything(),
      expect.any(Number),
      "approval_expired",
    );
    expect((screen.getByRole("button", {
      name: /Approve and sync these findings/i,
    }) as HTMLButtonElement).disabled).toBe(false);
  });

  test("wakes a scheduled transport retry while the dialog remains open", async () => {
    const deps = services();
    const storedLease = durableRetryLease();
    deps.api.sendFindings = vi.fn()
      .mockRejectedValueOnce(new HeelCloudApiError("unavailable", 503))
      .mockResolvedValue(JSON.stringify(receipt));
    deps.queue.claimNext = vi.fn()
      .mockResolvedValueOnce(null)
      .mockResolvedValueOnce(storedLease)
      .mockResolvedValue(null);
    deps.queue.renew = vi.fn().mockResolvedValue(storedLease);
    render(<FindingsSyncDialog
      open
      review={sampleReview as ReviewEnvelopeV1}
      services={deps}
      onClose={() => {}}
      onSynced={() => {}}
    />);
    fireEvent.click(await screen.findByRole("button", { name: /Prepare findings-only preview/i }));
    const approve = await screen.findByRole("button", { name: /Approve and sync these findings/i });
    vi.useFakeTimers();
    fireEvent.click(approve);
    await vi.waitFor(() => expect(deps.queue.scheduleRetry).toHaveBeenCalled());

    await vi.advanceTimersByTimeAsync(30_000);
    await vi.waitFor(() => expect(deps.api.sendFindings).toHaveBeenCalledTimes(2));
    await vi.waitFor(() => expect(deps.queue.complete).toHaveBeenCalledWith(
      expect.anything(), receipt,
    ));
  });

  test("resumes a previously approved exact retry without re-reading source or re-approving", async () => {
    const deps = services();
    const storedLease = durableRetryLease();
    deps.queue.claimNext = vi.fn()
      .mockResolvedValueOnce(storedLease)
      .mockResolvedValue(null);
    deps.queue.renew = vi.fn().mockResolvedValue(storedLease);
    const synced = vi.fn();

    render(<FindingsSyncDialog
      open
      review={sampleReview as ReviewEnvelopeV1}
      services={deps}
      onClose={() => {}}
      onSynced={synced}
    />);

    await screen.findByText(/Findings continuity is available/i);
    expect(deps.queue.claimNext).toHaveBeenCalledWith(workspaceRef);
    expect(deps.projector.preview).not.toHaveBeenCalled();
    expect(deps.api.approveFindings).not.toHaveBeenCalled();
    expect(deps.api.sendFindings).toHaveBeenCalledWith(
      workspaceRef,
      projectRef,
      requestJson,
      `fs1-${requestDigest}`,
      expect.any(AbortSignal),
    );
    expect(deps.queue.complete).toHaveBeenCalledWith(expect.anything(), receipt);
    expect(synced).not.toHaveBeenCalled();
  });
});
