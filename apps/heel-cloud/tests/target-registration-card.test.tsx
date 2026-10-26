// SPDX-License-Identifier: LicenseRef-Heel-Commercial

/**
 * Target-registration card states.
 *
 * SEAM: the card is rendered alone with spy callbacks; no client, transport or target is involved. The
 * dashboard flow through the existing proof contract is covered in `account-onboarding.test.tsx`.
 */

import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, test, vi } from "vitest";

import { TargetRegistrationCard, type TargetRegistrationCardProps } from "../components/onboarding/TargetRegistrationCard";


afterEach(cleanup);

const BOUNDARY = "Target verified. Managed scanning, credentials, discovery, and scan approval are not available in this build.";

function props(overrides: Partial<TargetRegistrationCardProps> = {}): TargetRegistrationCardProps {
  return {
    verifiedOrigin: null, origin: "", proofMethod: "https-file", instruction: null, busy: false,
    onOriginChange: vi.fn(), onProofMethodChange: vi.fn(), onCreateProof: vi.fn(), onCheckProof: vi.fn(),
    pendingTargets: [], selectedPendingId: null, replacementPendingId: null,
    onSelectPendingTarget: vi.fn(), onResumeProof: vi.fn(), onReplaceProof: vi.fn(),
    ...overrides,
  };
}

function createButton(): HTMLButtonElement {
  return screen.getByRole("button", { name: "Create ownership proof" }) as HTMLButtonElement;
}


describe("target registration card", () => {
  test("before submission it asks for one public HTTPS target and an ownership proof method", () => {
    const onOriginChange = vi.fn();
    const onProofMethodChange = vi.fn();
    render(<TargetRegistrationCard {...props({ onOriginChange, onProofMethodChange })} />);

    expect(screen.getByRole("heading", { name: "Add target" })).toBeTruthy();
    expect(document.body.textContent).toMatch(/publicly reachable/);
    expect(document.body.textContent).toMatch(/Ownership proof is required/);
    const method = screen.getByRole("combobox", { name: "Ownership proof method" }) as HTMLSelectElement;
    expect(Array.from(method.options, (option) => [option.value, option.textContent])).toEqual([["https-file", "HTTPS file"], ["dns-txt", "DNS TXT"]]);

    fireEvent.change(screen.getByLabelText("Target URL"), { target: { value: "https://staging.example.test" } });
    expect(onOriginChange).toHaveBeenCalledWith("https://staging.example.test");
    fireEvent.change(method, { target: { value: "dns-txt" } });
    expect(onProofMethodChange).toHaveBeenCalledWith("dns-txt");
    expect(screen.queryByRole("button", { name: "Check ownership proof" })).toBeNull();
    expect(screen.queryByRole("status")).toBeNull();
  });

  test.each([
    ["", true],
    ["http://staging.example.test", true],
    ["https://staging.example.test/login", true],
    ["https://Staging.example.test", true],
    ["https://staging.example.test", false],
    ["  https://staging.example.test  ", false],
  ])("the existing shape gate decides whether %j can be submitted", (origin, disabled) => {
    render(<TargetRegistrationCard {...props({ origin })} />);
    expect(createButton().disabled).toBe(disabled);
  });

  test("a valid target submits through the supplied action only, and busy blocks it", () => {
    const onCreateProof = vi.fn();
    const { rerender } = render(<TargetRegistrationCard {...props({ origin: "https://staging.example.test", onCreateProof })} />);
    fireEvent.click(createButton());
    expect(onCreateProof).toHaveBeenCalledOnce();

    rerender(<TargetRegistrationCard {...props({ origin: "https://staging.example.test", onCreateProof, busy: true })} />);
    expect(createButton().disabled).toBe(true);
  });

  test("after a challenge it shows only the returned instruction, a pending status and the check action", () => {
    const onCheckProof = vi.fn();
    const instruction = "Publish this exact record: _heel-proof.staging.example.test TXT synthetic-token";
    const { rerender } = render(<TargetRegistrationCard {...props({ origin: "https://staging.example.test", instruction, onCheckProof })} />);

    expect(screen.getByRole("heading", { name: "Add target" })).toBeTruthy();
    expect(screen.getByRole("status").textContent).toMatch(/^Target verification pending\./);
    expect(screen.getByText(instruction)).toBeTruthy();
    expect(screen.queryByLabelText("Target URL")).toBeNull();
    expect(screen.queryByRole("button", { name: "Create ownership proof" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Check ownership proof" }));
    expect(onCheckProof).toHaveBeenCalledOnce();

    rerender(<TargetRegistrationCard {...props({ instruction, onCheckProof, busy: true })} />);
    expect((screen.getByRole("button", { name: "Check ownership proof" }) as HTMLButtonElement).disabled).toBe(true);
  });

  test("a persisted verified target states the exact availability boundary and no runner default", () => {
    render(<TargetRegistrationCard {...props({ verifiedOrigin: "https://staging.example.test", instruction: "stale" })} />);

    expect(screen.getByRole("status").textContent).toBe(BOUNDARY);
    expect(screen.getByText("https://staging.example.test")).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "Add target" })).toBeNull();
    expect(screen.queryByText("stale")).toBeNull();
    expect(screen.queryAllByRole("button")).toEqual([]);
    // Private-connector information is an optional link, never a pairing or install action.
    expect(screen.getByRole("link", { name: "About private connectors" }).getAttribute("href")).toBe("/runner");
    expect(document.body.textContent).not.toMatch(/pair the local runner|install|open pairing guide/i);
  });

  const ALPHA = { environmentId: `env_${"a".repeat(32)}`, origin: "https://alpha.example.test", proofMethod: "dns-txt" as const };
  const BETA = { environmentId: `env_${"b".repeat(32)}`, origin: "https://beta.example.test", proofMethod: "https-file" as const };

  test("after a reload, the one pending target is preselected and resuming it is an explicit action", () => {
    const onResumeProof = vi.fn();
    const onCreateProof = vi.fn();
    render(<TargetRegistrationCard {...props({ pendingTargets: [ALPHA], selectedPendingId: ALPHA.environmentId, onResumeProof, onCreateProof })} />);

    const pending = screen.getByRole("group", { name: "Pending ownership proof" });
    expect(within(pending).getByRole("status").textContent).toMatch(/^Ownership proof pending for a registered target\./);
    expect(within(pending).getByText(ALPHA.origin)).toBeTruthy();
    expect(within(pending).getByText(/DNS TXT/)).toBeTruthy();
    expect(within(pending).queryByRole("combobox")).toBeNull();
    expect(within(pending).queryByRole("button", { name: "Issue replacement proof" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Check ownership proof" })).toBeNull();
    fireEvent.click(within(pending).getByRole("button", { name: "Resume ownership proof" }));
    expect(onResumeProof).toHaveBeenCalledOnce();
    // A new registration stays available, but only as the user's own choice.
    expect(screen.getByText(/register a different target/i)).toBeTruthy();
    expect(createButton().disabled).toBe(true);
    expect(onCreateProof).not.toHaveBeenCalled();
  });

  test("with several pending targets nothing is chosen for the user", () => {
    const onSelectPendingTarget = vi.fn();
    const onResumeProof = vi.fn();
    const { rerender } = render(<TargetRegistrationCard {...props({ pendingTargets: [ALPHA, BETA], onSelectPendingTarget, onResumeProof })} />);
    const select = screen.getByRole("combobox", { name: "Pending target" }) as HTMLSelectElement;
    expect(select.value).toBe("");
    expect(Array.from(select.options, (option) => option.value)).toEqual(["", ALPHA.environmentId, BETA.environmentId]);
    const resume = screen.getByRole("button", { name: "Resume ownership proof" }) as HTMLButtonElement;
    expect(resume.disabled).toBe(true);
    fireEvent.change(select, { target: { value: BETA.environmentId } });
    expect(onSelectPendingTarget).toHaveBeenCalledWith(BETA.environmentId);

    rerender(<TargetRegistrationCard {...props({ pendingTargets: [ALPHA, BETA], selectedPendingId: BETA.environmentId, onSelectPendingTarget, onResumeProof })} />);
    expect((screen.getByRole("combobox", { name: "Pending target" }) as HTMLSelectElement).value).toBe(BETA.environmentId);
    fireEvent.click(screen.getByRole("button", { name: "Resume ownership proof" }));
    expect(onResumeProof).toHaveBeenCalledOnce();
    rerender(<TargetRegistrationCard {...props({ pendingTargets: [ALPHA, BETA], selectedPendingId: BETA.environmentId, busy: true })} />);
    expect((screen.getByRole("button", { name: "Resume ownership proof" }) as HTMLButtonElement).disabled).toBe(true);
  });

  test("an expired pending proof offers only an explicit replacement for that same target", () => {
    const onReplaceProof = vi.fn();
    render(<TargetRegistrationCard {...props({ pendingTargets: [ALPHA, BETA], selectedPendingId: ALPHA.environmentId, replacementPendingId: ALPHA.environmentId, onReplaceProof })} />);
    const pending = screen.getByRole("group", { name: "Pending ownership proof" });
    expect(within(pending).queryByRole("button", { name: "Resume ownership proof" })).toBeNull();
    expect(pending.textContent).toMatch(/keeps this target and makes the old proof invalid/);
    fireEvent.click(within(pending).getByRole("button", { name: "Issue replacement proof" }));
    expect(onReplaceProof).toHaveBeenCalledOnce();
  });

  test("a resumed instruction or a verified target hides the pending chooser", () => {
    const { rerender } = render(<TargetRegistrationCard {...props({ pendingTargets: [ALPHA], selectedPendingId: ALPHA.environmentId, instruction: "Publish this exact record: x" })} />);
    expect(screen.queryByRole("group", { name: "Pending ownership proof" })).toBeNull();
    expect(screen.getByRole("button", { name: "Check ownership proof" })).toBeTruthy();
    rerender(<TargetRegistrationCard {...props({ pendingTargets: [ALPHA], selectedPendingId: ALPHA.environmentId, verifiedOrigin: BETA.origin })} />);
    expect(screen.queryByRole("group", { name: "Pending ownership proof" })).toBeNull();
    expect(screen.queryAllByRole("button")).toEqual([]);
  });
});
