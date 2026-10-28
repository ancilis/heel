// SPDX-License-Identifier: LicenseRef-Heel-Commercial

/**
 * Account, workspace and project resolution for the dashboard.
 *
 * Every identifier comes from the live control plane: the signed-in user and memberships from
 * `/v1/me`, projects from the workspace's project list. A requested selection (from the page
 * URL) is only a hint; it is honored only when the current server identity still lists it.
 * Role helpers mirror `heel/saas/tenancy.py` for presentation only — the server remains the
 * authority and every action still handles its 403.
 */

import {
  HeelCloudApiError,
  type HeelCloudApi,
  type HeelCloudProject,
  type HeelCloudSession,
  type HeelCloudWorkspace,
} from "./heel-cloud-api";


const WORKSPACE_REF = /^ws_[0-9a-f]{16}$/;
const PROJECT_REF = /^prj_[0-9a-f]{32}$/;
const PROJECT_WRITERS = new Set<HeelCloudWorkspace["role"]>(["owner", "admin", "member"]);
const PROJECT_READERS = new Set<HeelCloudWorkspace["role"]>(["owner", "admin", "member", "viewer"]);
const DEFAULT_ROLE_ORDER: readonly HeelCloudWorkspace["role"][] = ["owner", "admin", "member", "viewer", "billing"];

export const WORKSPACE_PARAM = "workspace";
export const PROJECT_PARAM = "project";

export interface AccountSelection {
  workspaceRef?: string;
  projectRef?: string;
}

export interface AccountWorkspaceView {
  userId: string;
  workspaces: readonly HeelCloudWorkspace[];
  workspace: HeelCloudWorkspace;
}

export type AccountResolution =
  | { phase: "sign_in" }
  | { phase: "no_workspace"; userId: string }
  | { phase: "forbidden"; account: AccountWorkspaceView }
  | { phase: "select_project"; account: AccountWorkspaceView }
  | { phase: "ready"; account: AccountWorkspaceView; projects: readonly HeelCloudProject[]; project: HeelCloudProject };

export type AccountApi = Pick<HeelCloudApi, "me" | "listProjects">;


export function canCreateProject(role: HeelCloudWorkspace["role"]): boolean {
  return PROJECT_WRITERS.has(role);
}


export function canListProjects(role: HeelCloudWorkspace["role"]): boolean {
  return PROJECT_READERS.has(role);
}


/** Read only well-formed opaque refs; anything else in the URL is ignored. */
export function selectionFromParams(params: { get(name: string): string | null } | null): AccountSelection {
  const workspaceRef = params?.get(WORKSPACE_PARAM) ?? "";
  const projectRef = params?.get(PROJECT_PARAM) ?? "";
  return {
    ...(WORKSPACE_REF.test(workspaceRef) ? { workspaceRef } : {}),
    ...(WORKSPACE_REF.test(workspaceRef) && PROJECT_REF.test(projectRef) ? { projectRef } : {}),
  };
}


/** The exact query string for a selection; never carries anything but the two opaque refs. */
export function selectionQuery(selection: AccountSelection): string {
  if (selection.workspaceRef === undefined || !WORKSPACE_REF.test(selection.workspaceRef)) return "";
  const params = new URLSearchParams({ [WORKSPACE_PARAM]: selection.workspaceRef });
  if (selection.projectRef !== undefined && PROJECT_REF.test(selection.projectRef)) {
    params.set(PROJECT_PARAM, selection.projectRef);
  }
  return `?${params.toString()}`;
}


export function defaultWorkspace(session: HeelCloudSession): HeelCloudWorkspace | undefined {
  for (const role of DEFAULT_ROLE_ORDER) {
    const match = session.workspaces.find((item) => item.role === role);
    if (match !== undefined) return match;
  }
  return undefined;
}


/**
 * Resolve the signed-in context. `auth_required` becomes `sign_in`; a 403 on the project list
 * becomes `forbidden` for that workspace; every other failure propagates to the caller.
 */
export async function resolveAccount(api: AccountApi, requested: AccountSelection): Promise<AccountResolution> {
  let session: HeelCloudSession;
  try {
    session = await api.me();
  } catch (error) {
    if (error instanceof HeelCloudApiError && error.code === "auth_required") return { phase: "sign_in" };
    throw error;
  }
  const requestedWorkspace = session.workspaces.find((item) => item.workspaceRef === requested.workspaceRef);
  const workspace = requestedWorkspace ?? defaultWorkspace(session);
  if (workspace === undefined) return { phase: "no_workspace", userId: session.userId };
  const account: AccountWorkspaceView = { userId: session.userId, workspaces: session.workspaces, workspace };
  let projects: HeelCloudProject[];
  try {
    projects = await api.listProjects(workspace.workspaceRef);
  } catch (error) {
    if (error instanceof HeelCloudApiError && error.code === "auth_required") return { phase: "sign_in" };
    if (error instanceof HeelCloudApiError && error.code === "forbidden") return { phase: "forbidden", account };
    throw error;
  }
  if (projects.length === 0) return { phase: "select_project", account };
  // A project hint counts only together with the workspace hint the server just confirmed.
  const project = (requestedWorkspace === undefined ? undefined
    : projects.find((item) => item.projectRef === requested.projectRef)) ?? projects[0];
  return { phase: "ready", account, projects, project };
}
