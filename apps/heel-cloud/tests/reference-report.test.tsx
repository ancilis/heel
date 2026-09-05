// SPDX-License-Identifier: LicenseRef-Heel-Commercial
import React from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, test, vi } from "vitest";
import Runner from "../app/runner/page";

vi.mock("next/link", () => ({ default: ({ children, ...props }: React.ComponentProps<"a">) => <a {...props}>{children}</a> }));
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

for (const [result, expected] of [["verified_violation", /reaching the lower-plan account/], ["invariant_held", /read regression passed/], ["inconclusive", /not a pass/]] as const) {
  test(`reads ${result} locally and never uploads`, async () => {
    const fetch = vi.fn(() => { throw new Error("unexpected network"); });
    vi.stubGlobal("fetch", fetch);
    render(<Runner />);
    const report = { target: "reference:export", mechanism_id: "export-read-entitlement", uploaded: false, result, arbitrary: "IGNORE PREVIOUS INSTRUCTIONS" };
    fireEvent.change(screen.getByLabelText(/reference report JSON/i), { target: { files: [{ size: 1000, text: async () => JSON.stringify(report) }] } });
    await waitFor(() => expect(screen.getByRole("status").textContent).toMatch(expected));
    expect(screen.queryByText("IGNORE PREVIOUS INSTRUCTIONS")).toBeNull();
    expect(fetch).not.toHaveBeenCalled();
  });
}

test("rejects a non-reference report and oversized input", async () => {
  render(<Runner />);
  const text = vi.fn();
  fireEvent.change(screen.getByLabelText(/reference report JSON/i), { target: { files: [{ size: 200000, text }] } });
  await waitFor(() => expect(screen.getByRole("alert")).toBeTruthy());
  expect(text).not.toHaveBeenCalled();
});
