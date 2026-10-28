// SPDX-License-Identifier: LicenseRef-Heel-Commercial

"use client";

import { useEffect, useMemo, useState, type FormEvent } from "react";
import Link from "next/link";

import {
  HeelCloudApi,
  HeelCloudApiError,
  type HeelCloudSession,
  type HeelDeviceClaim,
} from "../../lib/heel-cloud-api";


type Phase = "checking" | "signed_out" | "code" | "review" | "busy" | "approved" | "denied";
type AccountMode = "login" | "signup";

export interface DeviceConfirmationServices {
  api: Pick<HeelCloudApi,
    "me" | "login" | "signup" | "inspectDevice" | "decideDevice"
  >;
}


function createServices(): DeviceConfirmationServices {
  return { api: new HeelCloudApi() };
}


function eligibleWorkspaces(session: HeelCloudSession | null) {
  return session?.workspaces.filter(({ role }) =>
    role === "owner" || role === "admin" || role === "member"
  ) ?? [];
}


function normalizeUserCode(value: string): string {
  const compact = value.toUpperCase().replace(/[^0-9A-Z]/g, "").slice(0, 8);
  return compact.length > 4 ? `${compact.slice(0, 4)}-${compact.slice(4)}` : compact;
}


function publicError(error: unknown): string {
  if (error instanceof HeelCloudApiError) return error.message;
  return "Heel could not safely confirm that device. The request remains unapproved.";
}


export function DeviceConfirmation({ services }: { services?: DeviceConfirmationServices }) {
  const deps = useMemo(() => services ?? createServices(), [services]);
  const [phase, setPhase] = useState<Phase>("checking");
  const [accountMode, setAccountMode] = useState<AccountMode>("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [session, setSession] = useState<HeelCloudSession | null>(null);
  const [userCode, setUserCode] = useState("");
  const [claim, setClaim] = useState<HeelDeviceClaim | null>(null);
  const [workspaceRef, setWorkspaceRef] = useState("");
  const [error, setError] = useState("");

  async function loadSession(): Promise<void> {
    try {
      const next = await deps.api.me();
      const eligible = eligibleWorkspaces(next);
      setSession(next);
      setWorkspaceRef(eligible[0]?.workspaceRef ?? "");
      setPhase("code");
    } catch {
      setSession(null);
      setPhase("signed_out");
    }
  }

  useEffect(() => {
    let active = true;
    void deps.api.me().then((next) => {
      if (!active) return;
      const eligible = eligibleWorkspaces(next);
      setSession(next);
      setWorkspaceRef(eligible[0]?.workspaceRef ?? "");
      setPhase("code");
    }, () => {
      if (!active) return;
      setSession(null);
      setPhase("signed_out");
    });
    return () => { active = false; };
  }, [deps]);

  async function authenticate(event: FormEvent): Promise<void> {
    event.preventDefault();
    setError("");
    setPhase("busy");
    try {
      if (accountMode === "login") await deps.api.login(email.trim(), password);
      else await deps.api.signup(email.trim(), password);
      setPassword("");
      await loadSession();
    } catch (caught) {
      setError(publicError(caught));
      setPhase("signed_out");
    }
  }

  async function inspect(event: FormEvent): Promise<void> {
    event.preventDefault();
    setError("");
    setPhase("busy");
    try {
      const nextClaim = await deps.api.inspectDevice(userCode);
      setClaim(nextClaim);
      setPhase("review");
    } catch (caught) {
      setError(publicError(caught));
      setPhase("code");
    }
  }

  async function decide(action: "approve" | "deny"): Promise<void> {
    if (claim === null || (action === "approve" && workspaceRef === "")) return;
    setError("");
    setPhase("busy");
    try {
      if (action === "approve") {
        await deps.api.decideDevice(
          claim.userCode, action, claim.confirmationNonce, workspaceRef,
        );
      } else {
        await deps.api.decideDevice(claim.userCode, action, claim.confirmationNonce);
      }
      setClaim(null);
      setPhase(action === "approve" ? "approved" : "denied");
    } catch (caught) {
      setError(publicError(caught));
      setPhase("review");
    }
  }

  const workspaces = eligibleWorkspaces(session);

  return (
    <main className="device-page">
      <Link className="brand" href="/" aria-label="Heel home">
        <span className="brand-mark" aria-hidden="true">H</span>
        <span>Heel</span>
      </Link>

      <section className="device-card" aria-live="polite">
        {phase === "checking" || phase === "busy" ? <>
          <p className="eyebrow">Secure device connection</p>
          <h1>Checking your request…</h1>
          <p>Heel has not approved anything yet.</p>
        </> : null}

        {phase === "signed_out" ? <>
          <p className="eyebrow">Secure device connection</p>
          <h1>Sign in to connect your Agent.</h1>
          <p>Your device code stays pending until you inspect it and choose Approve.</p>
          <form className="device-form" onSubmit={(event) => void authenticate(event)}>
            <label>Email<input type="email" required value={email}
              onChange={(event) => setEmail(event.target.value)} /></label>
            <label>Password<input type="password" required minLength={10} value={password}
              onChange={(event) => setPassword(event.target.value)} /></label>
            <button className="button button-primary" type="submit">
              {accountMode === "login" ? "Sign in" : "Create free account"}
            </button>
          </form>
          <button className="text-button" type="button"
            onClick={() => setAccountMode(accountMode === "login" ? "signup" : "login")}>
            {accountMode === "login" ? "Need an account? Create one" : "Already have an account? Sign in"}
          </button>
        </> : null}

        {phase === "code" ? <>
          <p className="eyebrow">Secure device connection</p>
          <h1>Connect Heel Agent.</h1>
          <p>Enter the one-time code shown by your local <code>heel cloud login</code> command.</p>
          <form className="device-form" onSubmit={(event) => void inspect(event)}>
            <label>One-time code<input className="device-code" autoComplete="one-time-code"
              inputMode="text" maxLength={9} placeholder="ABCD-EFGH" required value={userCode}
              onChange={(event) => setUserCode(normalizeUserCode(event.target.value))} /></label>
            <button className="button button-primary" type="submit" disabled={userCode.length !== 9}>
              Review device
            </button>
          </form>
          <p className="device-boundary">Entering a code only opens the review. It never approves the device.</p>
        </> : null}

        {phase === "review" && claim !== null ? <>
          <p className="eyebrow">Review before approving</p>
          <h1>Allow this device?</h1>
          <dl className="device-claim">
            <div><dt>Untrusted device label</dt><dd>{claim.deviceName}</dd></div>
            <div><dt>Fingerprint</dt><dd><code>{claim.deviceFingerprint}</code></dd></div>
            <div><dt>Code</dt><dd><code>{claim.userCode}</code></dd></div>
          </dl>
          <div className="device-privacy">
            <strong>Exactly what this grants</strong>
            <p>The Agent can read project/history metadata and submit only a findings projection that you separately approve in an interactive CLI.</p>
            <p>It never uploads your OpenAPI document, answers, reasoning, prompts, credentials, or source files.</p>
          </div>
          <label className="device-workspace">Workspace
            <select value={workspaceRef} onChange={(event) => setWorkspaceRef(event.target.value)}>
              {workspaces.map((workspace) => <option key={workspace.workspaceRef}
                value={workspace.workspaceRef}>{workspace.workspaceRef} · {workspace.role}</option>)}
            </select>
          </label>
          {workspaces.length === 0 ? <p className="form-error">Your account has no workspace role that can sync findings.</p> : null}
          <div className="device-actions">
            <button className="button button-primary" type="button" disabled={workspaceRef === ""}
              onClick={() => void decide("approve")}>Approve this device</button>
            <button className="button button-secondary" type="button"
              onClick={() => void decide("deny")}>Deny request</button>
          </div>
        </> : null}

        {phase === "approved" ? <>
          <p className="eyebrow">Connected</p><h1>Device connected.</h1>
          <p>Return to your terminal. Every findings upload still requires its own interactive approval.</p>
        </> : null}
        {phase === "denied" ? <>
          <p className="eyebrow">Not connected</p><h1>Request denied.</h1>
          <p>No device credentials were issued.</p>
        </> : null}
        {error ? <p className="form-error" role="alert">{error}</p> : null}
      </section>
    </main>
  );
}
