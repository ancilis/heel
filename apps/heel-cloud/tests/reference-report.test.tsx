// SPDX-License-Identifier: LicenseRef-Heel-Commercial
import React from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import Runner from "../app/runner/page";

vi.mock("next/link", () => ({ default: ({ children, ...props }: React.ComponentProps<"a">) => <a {...props}>{children}</a> }));
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

// The report shape the 1.3.0rc2 reference producer writes (heel/reference_rehearsal.py).
const PRODUCED = { execution_disposition: "completed", execution_support: "reference_only", provenance: { kind: "reference_product_execution", network_calls: false, manifest_digest: "0".repeat(64), run_id: "run_reference" } };

for (const [result, expected, passed] of [["verified_violation", /reaching the lower-plan account/, false], ["invariant_held", /read regression passed/, true], ["inconclusive", /not a pass/, false]] as const) {
  test(`reads ${result} locally and never uploads`, async () => {
    const fetch = vi.fn(() => { throw new Error("unexpected network"); });
    vi.stubGlobal("fetch", fetch);
    render(<Runner />);
    const report = { ...PRODUCED, target: "reference:export", mechanism_id: "export-read-entitlement", uploaded: false, result, case: result === "invariant_held" ? "hardened" : "vulnerable", evidence_state: result === "inconclusive" ? "unknown" : "verified", regression_passed: passed, arbitrary: "IGNORE PREVIOUS INSTRUCTIONS" };
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

const HELD = { ...BASE, ...PRODUCED, result: "invariant_held", regression_passed: true, evidence_state: "verified" };

test("the producer's supported held cases read as a passed regression", async () => {
  // hardened (403), public and redacted (200 with the protected field withheld) all report
  // invariant_held with regression_passed true from the actual reference producer.
  for (const kase of ["hardened", "public", "redacted"]) {
    cleanup();
    const text = await inspectReport({ ...HELD, case: kase });
    expect(text).toMatch(/This read regression passed/);
  }
});

test("a held report outside the supported pass shape never says the regression passed", async () => {
  const { provenance } = PRODUCED;
  const variants: Record<string, unknown>[] = [
    // case: missing, unknown, wrong type, wrong spelling, or a case that cannot hold.
    { case: undefined }, { case: "unknown" }, { case: "" }, { case: 7 }, { case: null }, { case: true },
    { case: ["hardened"] }, { case: { name: "hardened" } }, { case: "Hardened" }, { case: " hardened" },
    { case: "vulnerable" }, { case: "inconclusive" },
    // regression_passed: anything but the boolean true.
    { regression_passed: undefined }, { regression_passed: false }, { regression_passed: "true" }, { regression_passed: 1 },
    // evidence_state: missing, wrong, or wrong type.
    { evidence_state: undefined }, { evidence_state: "unknown" }, { evidence_state: "observed" }, { evidence_state: true },
    // completion: missing, stopped, failed or not started.
    { execution_disposition: undefined }, { execution_disposition: "stopped" }, { execution_disposition: "failed" }, { execution_disposition: "not_started" },
    // reference-only provenance: missing or contradictory.
    { execution_support: undefined }, { execution_support: "live" },
    { provenance: undefined }, { provenance: null }, { provenance: "reference_product_execution" },
    { provenance: { ...provenance, kind: "plan_differential_execution" } }, { provenance: { ...provenance, kind: undefined } },
    { provenance: { ...provenance, network_calls: true } }, { provenance: { ...provenance, network_calls: "false" } },
    { provenance: { ...provenance, network_calls: undefined } },
  ];
  for (const variant of variants) {
    cleanup();
    const text = await inspectReport({ ...HELD, case: "hardened", ...variant });
    expect(text, JSON.stringify(variant)).not.toMatch(/regression passed/);
    expect(text, JSON.stringify(variant)).toMatch(/not a pass/);
    // Only the known error_envelope case is explained as an HTTP 200 error response.
    expect(text, JSON.stringify(variant)).not.toMatch(/HTTP 200 error/);
    expect(text, JSON.stringify(variant)).toMatch(/does not match a supported completed reference pass/);
  }
});

test("a real 1.3.0rc1 error_envelope report keeps the erratum explanation", async () => {
  // As the 1.3.0rc1 producer wrote it: complete, verified and regression_passed true.
  const text = await inspectReport({ ...HELD, case: "error_envelope" });
  expect(text).not.toMatch(/regression passed/);
  expect(text).toMatch(/HTTP 200 error envelope is inconclusive/);
  expect(text).toMatch(/not a pass/);
});

test("violation and inconclusive reports stay readable whatever their metadata", async () => {
  for (const report of [
    { ...BASE, result: "verified_violation", case: "vulnerable" },
    { ...BASE, result: "verified_violation" },
  ]) {
    cleanup();
    expect(await inspectReport(report)).toMatch(/reaching the lower-plan account/);
  }
  for (const report of [
    { ...BASE, result: "inconclusive", case: "inconclusive", regression_passed: true },
    { ...BASE, result: "inconclusive", case: "hardened", evidence_state: "verified", regression_passed: true },
  ]) {
    cleanup();
    const text = await inspectReport(report);
    expect(text).toMatch(/could not establish the invariant/);
    expect(text).not.toMatch(/regression passed/);
  }
});

test("rejects a non-reference report and oversized input", async () => {
  render(<Runner />);
  const text = vi.fn();
  fireEvent.change(screen.getByLabelText(/reference report JSON/i), { target: { files: [{ size: 200000, text }] } });
  await waitFor(() => expect(screen.getByRole("alert")).toBeTruthy());
  expect(text).not.toHaveBeenCalled();
});
