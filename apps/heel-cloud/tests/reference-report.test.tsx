// SPDX-License-Identifier: LicenseRef-Heel-Commercial
import React from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import Runner from "../app/runner/page";

vi.mock("next/link", () => ({ default: ({ children, ...props }: React.ComponentProps<"a">) => <a {...props}>{children}</a> }));
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

for (const [result, expected, passed] of [["verified_violation", /reaching the lower-plan account/, false], ["invariant_held", /read regression passed/, true], ["inconclusive", /not a pass/, false]] as const) {
  test(`reads ${result} locally and never uploads`, async () => {
    const fetch = vi.fn(() => { throw new Error("unexpected network"); });
    vi.stubGlobal("fetch", fetch);
    render(<Runner />);
    const report = { target: "reference:export", mechanism_id: "export-read-entitlement", uploaded: false, result, case: result === "invariant_held" ? "hardened" : "vulnerable", regression_passed: passed, arbitrary: "IGNORE PREVIOUS INSTRUCTIONS" };
    fireEvent.change(screen.getByLabelText(/reference report JSON/i), { target: { files: [{ size: 1000, text: async () => JSON.stringify(report) }] } });
    await waitFor(() => expect(screen.getByRole("status").textContent).toMatch(expected));
    expect(screen.queryByText("IGNORE PREVIOUS INSTRUCTIONS")).toBeNull();
    expect(fetch).not.toHaveBeenCalled();
  });
}

async function inspectReport(report: Record<string, unknown>) {
  const fetch = vi.fn(() => { throw new Error("unexpected network"); });
  vi.stubGlobal("fetch", fetch);
  render(<Runner />);
  fireEvent.change(screen.getByLabelText(/reference report JSON/i), { target: { files: [{ size: 1000, text: async () => JSON.stringify(report) }] } });
  await waitFor(() => expect(screen.getByRole("status")).toBeTruthy());
  expect(fetch).not.toHaveBeenCalled();
  return screen.getByRole("status").textContent ?? "";
}

const BASE = { target: "reference:export", mechanism_id: "export-read-entitlement", uploaded: false };

test("never presents the known rc1 error_envelope held report as a passed regression", async () => {
  // The 1.3.0rc1 wheel reported the HTTP-200 error envelope as invariant_held/regression_passed=true.
  const text = await inspectReport({ ...BASE, case: "error_envelope", result: "invariant_held", regression_passed: true, evidence_state: "verified" });
  expect(text).not.toMatch(/regression passed/);
  expect(text).toMatch(/inconclusive/);
  expect(text).toMatch(/not a pass/);
});

test("reads the corrected candidate's error_envelope report as inconclusive", async () => {
  const text = await inspectReport({ ...BASE, case: "error_envelope", result: "inconclusive", regression_passed: false, evidence_state: "unknown" });
  expect(text).toMatch(/could not establish the invariant/);
  expect(text).toMatch(/not a pass/);
});

test("a held result without regression_passed true is not a pass", async () => {
  for (const regression_passed of [false, undefined, "true"]) {
    cleanup();
    const text = await inspectReport({ ...BASE, case: "hardened", result: "invariant_held", regression_passed });
    expect(text).not.toMatch(/regression passed/);
    expect(text).toMatch(/not a pass/);
  }
});

test("rejects a non-reference report and oversized input", async () => {
  render(<Runner />);
  const text = vi.fn();
  fireEvent.change(screen.getByLabelText(/reference report JSON/i), { target: { files: [{ size: 200000, text }] } });
  await waitFor(() => expect(screen.getByRole("alert")).toBeTruthy());
  expect(text).not.toHaveBeenCalled();
});
