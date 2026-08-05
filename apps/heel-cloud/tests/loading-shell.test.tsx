// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import Home from "../app/page";

afterEach(cleanup);

describe("Heel loading shell", () => {
  it("announces the browser-local workspace while it prepares", () => {
    render(<Home />);

    const status = screen.getByRole("status");
    expect(status.getAttribute("aria-live")).toBe("polite");
    expect(screen.getByRole("heading", { name: "Preparing Heel" })).toBeTruthy();
    expect(status.textContent).toContain("Your document stays in this browser");
  });
});
