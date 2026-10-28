// SPDX-License-Identifier: LicenseRef-Heel-Commercial

"use client";

import { useState, type FormEvent } from "react";

import { HeelCloudApiError, type HeelCloudApi } from "../../lib/heel-cloud-api";


type AccountMode = "login" | "signup";

export interface AccountAccessProps {
  api: Pick<HeelCloudApi, "login" | "signup">;
  /** Called after the server set the HttpOnly session cookie; the caller re-reads `/v1/me`. */
  onAuthenticated: () => Promise<void>;
}


function publicError(error: unknown): string {
  if (error instanceof HeelCloudApiError) return error.message;
  return "Heel Cloud is temporarily unavailable. Nothing was created.";
}


export function AccountAccess({ api, onAuthenticated }: AccountAccessProps) {
  const [mode, setMode] = useState<AccountMode>("signup");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function submit(event: FormEvent): Promise<void> {
    event.preventDefault();
    if (busy) return;
    const submittedPassword = password;
    // The password lives only in this one request; it is cleared before any await settles.
    setPassword("");
    setError("");
    setBusy(true);
    try {
      if (mode === "signup") await api.signup(email.trim(), submittedPassword);
      else await api.login(email.trim(), submittedPassword);
      await onAuthenticated();
    } catch (caught) {
      setError(publicError(caught));
      if (caught instanceof HeelCloudApiError && caught.code === "account_exists") setMode("login");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="account-access" aria-labelledby="account-access-title">
      <p className="canary-kicker">{mode === "signup" ? "Free account" : "Welcome back"}</p>
      <h2 id="account-access-title">{mode === "signup" ? "Create your Heel account" : "Sign in to Heel"}</h2>
      <p>{mode === "signup"
        ? "Signing up creates your account and a default workspace. You add projects next."
        : "Sign in to return to your workspaces and projects."}</p>
      <form className="device-form" aria-busy={busy} onSubmit={(event) => void submit(event)}>
        <label>Email<input autoComplete="email" disabled={busy} inputMode="email" maxLength={254}
          name="email" onChange={(event) => setEmail(event.target.value)} required type="email" value={email} /></label>
        <label>Password<input autoComplete={mode === "signup" ? "new-password" : "current-password"} disabled={busy}
          maxLength={1024} minLength={mode === "signup" ? 10 : undefined} name="password"
          onChange={(event) => setPassword(event.target.value)} required type="password" value={password} /></label>
        {mode === "signup" ? <p className="account-hint">At least 10 characters.</p> : null}
        {error ? <p className="form-error" role="alert">{error}</p> : null}
        <button className="button button-primary" disabled={busy} type="submit">
          {busy ? (mode === "signup" ? "Creating account…" : "Signing in…") : mode === "signup" ? "Create free account" : "Sign in"}
        </button>
      </form>
      <button className="text-button" disabled={busy} type="button"
        onClick={() => { setMode(mode === "signup" ? "login" : "signup"); setError(""); }}>
        {mode === "signup" ? "Already have an account? Sign in" : "Need an account? Create one"}
      </button>
    </section>
  );
}
