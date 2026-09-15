// SPDX-License-Identifier: LicenseRef-Heel-Commercial
import React from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import Campaigns from "../app/campaigns/page";

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

test("builds editable campaigns for selected families without target requests", () => {
  const fetch = vi.fn(() => { throw new Error("network forbidden"); });
  vi.stubGlobal("fetch", fetch);
  render(<Campaigns />);
  expect(screen.getAllByRole("checkbox")).toHaveLength(12);
  fireEvent.click(screen.getByRole("checkbox", { name: /trial eligibility/i }));
  fireEvent.click(screen.getByRole("button", { name: /create editable campaign/i }));
  const draft = JSON.parse((screen.getByLabelText("Campaign JSON") as HTMLTextAreaElement).value);
  expect(draft.scenarios).toHaveLength(11);
  expect(draft.scenarios.some((s: { family: string }) => s.family === "trial_eligibility")).toBe(false);
  expect(screen.getByText(/heel campaign authorize/)).toBeTruthy();
  expect(fetch).not.toHaveBeenCalled();
});

test("rejects oversized report files before reading them", async () => {
  render(<Campaigns />);
  const text = vi.fn();
  fireEvent.change(screen.getByLabelText("Campaign report JSON"), { target: { files: [{ size: 500000, text }] } });
  await waitFor(() => expect(screen.getByRole("alert").textContent).toMatch(/256 KiB/));
  expect(text).not.toHaveBeenCalled();
});

test("exposes unsupported coverage instead of a global safety claim", () => {
  render(<Campaigns />);
  expect(screen.getByText(/Unconfigured families are untested/)).toBeTruthy();
  expect(screen.getByText(/does not authenticate/i)).toBeTruthy();
});

test("reads reported outcomes locally and filters without treating a file as authenticated", async () => {
  const fetch = vi.fn(); vi.stubGlobal("fetch", fetch);
  render(<Campaigns />);
  const report = { schema_version: "heel.campaign.report.v1", name: "Meter check", run_id: "a".repeat(32),
    campaign_digest: "b".repeat(64), signature: "c".repeat(64), origin: "http://127.0.0.1:8765", uploaded: false,
    requests_attempted: 3, results: [{ scenario_id: "meter", family: "usage_accounting", rule: "Both paths must be metered",
      outcome: "violation", reason: "assertions_evaluated", cleanup: "complete", checks: [{ id: "usage", outcome: "violation" }],
      evidence: [{ step_id: "read", status: 200, bytes: 30, duration_ms: 1, sha256: "d".repeat(64) }] }],
    arbitrary: "DO NOT DISPLAY UNTRUSTED EXTRA FIELDS" };
  fireEvent.change(screen.getByLabelText("Campaign report JSON"), { target: { files: [{ size: 1000, text: async () => JSON.stringify(report) }] } });
  await waitFor(() => expect(screen.getByText("Reported violation")).toBeTruthy());
  fireEvent.click(screen.getByRole("button", { name: "held 0" }));
  expect(screen.getByText("No results match this filter.")).toBeTruthy();
  expect(screen.queryByText(report.arbitrary)).toBeNull();
  expect(fetch).not.toHaveBeenCalled();
});
