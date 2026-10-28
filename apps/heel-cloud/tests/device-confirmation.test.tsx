// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, test, vi } from "vitest";

import {
  DeviceConfirmation,
  type DeviceConfirmationServices,
} from "../components/device/DeviceConfirmation";


const workspaceRef = "ws_0123456789abcdef";
const claim = {
  userCode: "ABCD-EFGH",
  deviceName: "Alice's MacBook",
  deviceFingerprint: "7J4D-QW9K",
  capabilities: ["sync_findings", "view_synced_reviews"] as const,
  expiresIn: 421,
  confirmationNonce: `heel_dcn_${"a".repeat(43)}`,
};

afterEach(cleanup);


function services(): DeviceConfirmationServices {
  return {
    api: {
      me: vi.fn().mockResolvedValue({
        userId: "usr_0123456789abcdef",
        workspaces: [{ workspaceRef, role: "owner" }],
      }),
      login: vi.fn(),
      signup: vi.fn(),
      inspectDevice: vi.fn().mockResolvedValue(claim),
      decideDevice: vi.fn().mockResolvedValue("approved"),
    },
  };
}


describe("DeviceConfirmation", () => {
  test("code entry only inspects; a separate explicit action approves the selected workspace", async () => {
    const deps = services();
    render(<DeviceConfirmation services={deps} />);
    await screen.findByRole("heading", { name: /connect heel agent/i });

    fireEvent.change(screen.getByLabelText(/one-time code/i), { target: { value: "abcdefgh" } });
    fireEvent.click(screen.getByRole("button", { name: /review device/i }));
    await screen.findByText("Alice's MacBook");
    expect(deps.api.inspectDevice).toHaveBeenCalledWith("ABCD-EFGH");
    expect(deps.api.decideDevice).not.toHaveBeenCalled();
    expect(screen.getByText(/never uploads your openapi/i)).toBeTruthy();
    expect(screen.getByText(/untrusted device label/i)).toBeTruthy();

    fireEvent.click(screen.getByRole("button", { name: /approve this device/i }));
    await screen.findByRole("heading", { name: /device connected/i });
    expect(deps.api.decideDevice).toHaveBeenCalledWith(
      "ABCD-EFGH", "approve", claim.confirmationNonce, workspaceRef,
    );
  });

  test("offers login inline and returns directly to code entry", async () => {
    const deps = services();
    deps.api.me = vi.fn()
      .mockRejectedValueOnce({ code: "auth_required" })
      .mockResolvedValueOnce({
        userId: "usr_0123456789abcdef",
        workspaces: [{ workspaceRef, role: "owner" }],
      });
    deps.api.login = vi.fn().mockResolvedValue({ userId: "usr_0123456789abcdef" });
    render(<DeviceConfirmation services={deps} />);
    await screen.findByRole("heading", { name: /sign in to connect/i });
    fireEvent.change(screen.getByLabelText(/email/i), { target: { value: "a@example.test" } });
    fireEvent.change(screen.getByLabelText(/password/i), { target: { value: "correct-horse-staple" } });
    fireEvent.click(screen.getByRole("button", { name: /^sign in$/i }));
    await screen.findByLabelText(/one-time code/i);
    expect(deps.api.login).toHaveBeenCalledWith("a@example.test", "correct-horse-staple");
  });

  test("deny is explicit, terminal, and carries no workspace", async () => {
    const deps = services();
    deps.api.decideDevice = vi.fn().mockResolvedValue("denied");
    render(<DeviceConfirmation services={deps} />);
    await screen.findByLabelText(/one-time code/i);
    fireEvent.change(screen.getByLabelText(/one-time code/i), { target: { value: "ABCD-EFGH" } });
    fireEvent.click(screen.getByRole("button", { name: /review device/i }));
    await screen.findByText("Alice's MacBook");
    fireEvent.click(screen.getByRole("button", { name: /deny/i }));
    await waitFor(() => expect(deps.api.decideDevice).toHaveBeenCalledWith(
      "ABCD-EFGH", "deny", claim.confirmationNonce,
    ));
    expect(screen.getByRole("heading", { name: /request denied/i })).toBeTruthy();
  });
});
