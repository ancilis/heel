// SPDX-License-Identifier: LicenseRef-Heel-Commercial

/** Keeps one durable retry lease fenced while its exact idempotent transport is in flight. */

import type { FindingsSyncLeaseV1 } from "./findings-sync-queue";


export interface FindingsSyncLeaseClock {
  now(): number;
  setTimer(callback: () => void, delayMs: number): unknown;
  clearTimer(timer: unknown): void;
}


const systemClock: FindingsSyncLeaseClock = {
  now: Date.now,
  setTimer: (callback, delayMs) => setTimeout(callback, delayMs),
  clearTimer: (timer) => clearTimeout(timer as ReturnType<typeof setTimeout>),
};


export class FindingsSyncLeaseLostError extends Error {
  constructor() {
    super("The approved findings retry is no longer owned by this browser task.");
    this.name = "FindingsSyncLeaseLostError";
  }
}


export async function runWithRenewingFindingsSyncLease<T>(
  initialLease: FindingsSyncLeaseV1,
  renew: (lease: FindingsSyncLeaseV1) => Promise<FindingsSyncLeaseV1 | null>,
  operation: (signal: AbortSignal) => Promise<T>,
  clock: FindingsSyncLeaseClock = systemClock,
  onLeaseRenewed: (lease: FindingsSyncLeaseV1) => void = () => {},
): Promise<{ value: T; lease: FindingsSyncLeaseV1 }> {
  let activeLease = initialLease;
  let timer: unknown = null;
  let renewal: Promise<void> | null = null;
  let finishing = false;
  let ownershipLost = false;
  const controller = new AbortController();

  function loseOwnership(): void {
    ownershipLost = true;
    controller.abort();
  }

  function scheduleRenewal(): void {
    const remaining = activeLease.leaseExpiresAt - clock.now();
    if (!Number.isFinite(remaining) || remaining <= 0) {
      loseOwnership();
      return;
    }
    const delay = Math.max(1, Math.floor(remaining / 2));
    timer = clock.setTimer(() => {
      timer = null;
      const leaseBeingRenewed = activeLease;
      renewal = (async () => {
        try {
          const nextLease = await renew(leaseBeingRenewed);
          if (nextLease === null || nextLease.leaseExpiresAt <= clock.now()) {
            loseOwnership();
            return;
          }
          activeLease = nextLease;
          onLeaseRenewed(nextLease);
          if (!finishing) scheduleRenewal();
        } catch {
          loseOwnership();
        }
      })().finally(() => {
        renewal = null;
      });
    }, delay);
  }

  scheduleRenewal();
  if (ownershipLost) throw new FindingsSyncLeaseLostError();

  let value: T | undefined;
  let operationError: unknown;
  let operationSucceeded = false;
  try {
    value = await operation(controller.signal);
    operationSucceeded = true;
  } catch (error) {
    operationError = error;
  } finally {
    finishing = true;
    if (timer !== null) clock.clearTimer(timer);
    if (renewal !== null) await renewal;
    if (timer !== null) clock.clearTimer(timer);
  }

  if (ownershipLost) throw new FindingsSyncLeaseLostError();
  if (!operationSucceeded) throw operationError;
  return { value: value as T, lease: activeLease };
}
