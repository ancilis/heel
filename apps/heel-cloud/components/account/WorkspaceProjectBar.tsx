// SPDX-License-Identifier: LicenseRef-Heel-Commercial

"use client";

import { useState, type FormEvent } from "react";

import { canCreateProject, type AccountWorkspaceView } from "../../lib/account-context";
import { HeelCloudApiError, type HeelCloudProject } from "../../lib/heel-cloud-api";


export interface WorkspaceProjectBarProps {
  account: AccountWorkspaceView;
  projects: readonly HeelCloudProject[];
  projectRef: string | null;
  disabled: boolean;
  onSelectWorkspace: (workspaceRef: string) => void;
  onSelectProject: (projectRef: string) => void;
  /** Resolves after the server created the project; rejects with the server's closed error. */
  onCreateProject: (name: string) => Promise<void>;
  onSignOut: () => void;
}


export function workspaceLabel(workspaceRef: string, role: string): string {
  return `Workspace ${workspaceRef.slice(3, 11)} · ${role}`;
}


function publicError(error: unknown): string {
  if (error instanceof HeelCloudApiError) return error.message;
  return "Heel Cloud is temporarily unavailable. No project was created.";
}


export function WorkspaceProjectBar({
  account, projects, projectRef, disabled, onSelectWorkspace, onSelectProject, onCreateProject, onSignOut,
}: WorkspaceProjectBarProps) {
  const [name, setName] = useState("");
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState("");
  const role = account.workspace.role;
  const mayCreate = canCreateProject(role);
  const trimmed = name.trim();
  const busy = disabled || creating;

  async function create(event: FormEvent): Promise<void> {
    event.preventDefault();
    if (busy || trimmed.length === 0 || trimmed.length > 120) return;
    setCreating(true);
    setError("");
    try {
      await onCreateProject(trimmed);
      setName("");
    } catch (caught) {
      setError(publicError(caught));
    } finally {
      setCreating(false);
    }
  }

  return (
    <section className="account-bar" aria-label="Workspace and project">
      <label className="account-field">Workspace
        <select disabled={busy || account.workspaces.length < 2} onChange={(event) => onSelectWorkspace(event.target.value)}
          value={account.workspace.workspaceRef}>
          {account.workspaces.map((item) => <option key={item.workspaceRef} value={item.workspaceRef}>
            {workspaceLabel(item.workspaceRef, item.role)}</option>)}
        </select>
      </label>
      {projects.length > 0 && projectRef !== null ? <label className="account-field">Project
        <select disabled={busy} onChange={(event) => onSelectProject(event.target.value)} value={projectRef}>
          {projects.map((item) => <option key={item.projectRef} value={item.projectRef}>{item.name}</option>)}
        </select>
      </label> : null}
      {mayCreate ? <form className="account-create" onSubmit={(event) => void create(event)}>
        <label className="account-field">New project
          <input autoComplete="off" disabled={busy} maxLength={120} onChange={(event) => setName(event.target.value)}
            placeholder="e.g. Billing staging" required value={name} /></label>
        <button className="button button-secondary" disabled={busy || trimmed.length === 0} type="submit">
          {creating ? "Creating…" : "Create project"}</button>
      </form> : <p className="account-hint" role="note">Your {role} role can view this workspace but cannot create projects. Ask a workspace owner or admin.</p>}
      <button className="text-button account-signout" disabled={disabled} onClick={onSignOut} type="button">Sign out</button>
      {error ? <p className="form-error" role="alert">{error}</p> : null}
    </section>
  );
}
