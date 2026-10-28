// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, test, vi } from "vitest";

import { ProjectHistory } from "../components/projects/ProjectHistory";
import { FindingsSyncStatus } from "../components/review/FindingsSyncStatus";


afterEach(cleanup);


describe("findings continuity presentation", () => {
  test("states that preparation has sent nothing", () => {
    render(<FindingsSyncStatus state="awaiting_consent" />);
    expect(screen.getByRole("status").textContent).toContain("no findings have been sent");
  });

  test("describes exact-reuse metering without claiming a vulnerability", () => {
    render(<FindingsSyncStatus state="synced" receipt={{
      schema_version: "heel.findings-sync-receipt.v1",
      receipt_id: `fsr_${"a".repeat(32)}`,
      project_ref: `prj_${"b".repeat(32)}`,
      request_digest: "c".repeat(64),
      projection_hash: "d".repeat(64),
      synced_review_id: `synrev_${"e".repeat(32)}`,
      disposition: "reused",
      metered: false,
      accepted_at: "2026-08-04T12:00:00.000Z",
    }} />);
    expect(screen.getByRole("status").textContent).toContain("Matched existing hosted review");
    expect(screen.getByRole("status").textContent).toContain("not counted again");
    expect(screen.getByRole("status").textContent).not.toMatch(/proven|vulnerability/i);
  });

  test("renders bounded hosted summaries with precise model language", () => {
    const refresh = vi.fn();
    render(<ProjectHistory
      projectName="Production API"
      reviews={[{
        syncedReviewId: `synrev_${"a".repeat(32)}`,
        projectionHash: "b".repeat(64),
        gateStatus: "warn",
        findingsCount: 2,
        blockersCount: 0,
        createdAt: 1_786_000_000,
      }]}
      onRefresh={refresh}
    />);
    expect(screen.getByRole("heading", { name: "Production API" })).toBeTruthy();
    expect(screen.getByText("2 locally flagged findings")).toBeTruthy();
    expect(screen.getByText(/not proof of a production vulnerability or reachability/i)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
    expect(refresh).toHaveBeenCalledOnce();
  });
});
