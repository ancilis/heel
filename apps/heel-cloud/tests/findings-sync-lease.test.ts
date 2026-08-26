// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import { describe, expect, test, vi } from "vitest";

import {
  FindingsSyncLeaseLostError,
  runWithRenewingFindingsSyncLease,
  type FindingsSyncLeaseClock,
} from "../lib/findings-sync-lease";
import type { FindingsSyncLeaseV1 } from "../lib/findings-sync-queue";


function lease(token: string, expiresAt: number): FindingsSyncLeaseV1 {
  return {
    leaseToken: `fsl_${token.repeat(32)}`,
    leaseExpiresAt: expiresAt,
    record: {
      schema_version: "heel.findings-sync-queue.v1",
      workspace_ref: "ws_0123456789abcdef",
      project_ref: `prj_${"a".repeat(32)}`,
      request_digest: "b".repeat(64),
      request_json: "{}",
      approved_at: 900,
      expires_at: 10_000,
      retry: {
        attempts: 1,
        next_attempt_at: 900,
        last_error_code: null,
        lease_token: `fsl_${token.repeat(32)}`,
        lease_expires_at: expiresAt,
      },
      receipt: null,
    },
  };
}


function manualClock() {
  let now = 1_000;
  let callback: (() => void) | null = null;
  let delay = -1;
  const clock: FindingsSyncLeaseClock = {
    now: () => now,
    setTimer: (next, nextDelay) => {
      callback = next;
      delay = nextDelay;
      return 1;
    },
    clearTimer: () => {
      callback = null;
    },
  };
  return {
    clock,
    get delay() { return delay; },
    advanceTo(value: number) { now = value; },
    fire() {
      const next = callback;
      callback = null;
      if (next === null) throw new Error("no scheduled renewal");
      next();
    },
  };
}


describe("runWithRenewingFindingsSyncLease", () => {
  test("renews halfway through the lease and completes with the newest fenced token", async () => {
    const scheduler = manualClock();
    const initial = lease("c", 1_100);
    const renewed = lease("d", 1_200);
    const renew = vi.fn().mockResolvedValue(renewed);
    let finishOperation!: (value: string) => void;
    const operation = vi.fn((signal: AbortSignal) => new Promise<string>((resolve) => {
      void signal;
      finishOperation = resolve;
    }));
    const onLeaseRenewed = vi.fn();

    const pending = runWithRenewingFindingsSyncLease(
      initial, renew, operation, scheduler.clock, onLeaseRenewed,
    );
    expect(scheduler.delay).toBe(50);
    scheduler.advanceTo(1_050);
    scheduler.fire();
    await vi.waitFor(() => expect(renew).toHaveBeenCalledWith(initial));
    finishOperation("receipt");

    await expect(pending).resolves.toEqual({ value: "receipt", lease: renewed });
    expect(onLeaseRenewed).toHaveBeenCalledWith(renewed);
  });

  test("aborts transport and refuses a result when lease ownership is lost", async () => {
    const scheduler = manualClock();
    const initial = lease("c", 1_100);
    const renew = vi.fn().mockResolvedValue(null);
    const operation = vi.fn((signal: AbortSignal) => new Promise<string>((_resolve, reject) => {
      signal.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
    }));

    const pending = runWithRenewingFindingsSyncLease(initial, renew, operation, scheduler.clock);
    scheduler.advanceTo(1_050);
    scheduler.fire();

    await expect(pending).rejects.toBeInstanceOf(FindingsSyncLeaseLostError);
    expect(operation.mock.calls[0][0].aborted).toBe(true);
  });
});
