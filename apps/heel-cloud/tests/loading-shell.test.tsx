// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import Home from "../app/page";

afterEach(cleanup);

describe("Heel server-rendered product shell", () => {
  it("announces useful example evidence while the local engine prepares", () => {
    render(<Home />);

    const status = screen.getByRole("status");
    expect(status.getAttribute("aria-live")).toBe("polite");
    expect(screen.getByRole("heading", { name: /find the abuse hiding/i })).toBeTruthy();
    expect(status.textContent).toContain("Example review complete");
    expect(screen.getAllByText(/global beyond intended tenant/i).length).toBeGreaterThan(0);
  });
});
