// SPDX-License-Identifier: LicenseRef-Heel-Commercial

import { describe, expect, test, vi } from "vitest";

import {
  canCreateProject,
  canListProjects,
  confirmedRunRef,
  resolveAccount,
  selectionFromParams,
  selectionQuery,
  type AccountApi,
} from "../lib/account-context";
import { HeelCloudApiError, type HeelCloudProject, type HeelCloudSession } from "../lib/heel-cloud-api";


const userId = "usr_0123456789abcdef";
const ownerWs = "ws_00000000000000a1";
const viewerWs = "ws_00000000000000b2";
const billingWs = "ws_00000000000000c3";
const projectA = `prj_${"a".repeat(32)}`;
const projectB = `prj_${"b".repeat(32)}`;
const run = `crun_${"c".repeat(32)}`;


function project(workspaceRef: string, projectRef: string, name: string): HeelCloudProject {
  return { workspaceRef, projectRef, name, createdBy: `membership:${userId}`, createdAt: 1 };
}


// SEAM: AccountApi is the real HeelCloudApi surface; responses are scripted here.
function apiWith(session: HeelCloudSession | Error, projects: Record<string, HeelCloudProject[] | Error>) {
  const api: AccountApi = {
    me: vi.fn(async () => { if (session instanceof Error) throw session; return session; }),
    listProjects: vi.fn(async (workspaceRef: string) => {
      const value = projects[workspaceRef];
      if (value === undefined) throw new Error("unexpected workspace");
      if (value instanceof Error) throw value;
      return value;
    }),
  };
  return api;
}


const session: HeelCloudSession = {
  userId,
  workspaces: [
    { workspaceRef: viewerWs, role: "viewer" },
    { workspaceRef: ownerWs, role: "owner" },
    { workspaceRef: billingWs, role: "billing" },
  ],
};


describe("account context resolution", () => {
  test("an unauthenticated /v1/me is the sign-in state, not an error", async () => {
    const api = apiWith(new HeelCloudApiError("auth_required", 401), {});
    await expect(resolveAccount(api, {})).resolves.toEqual({ phase: "sign_in" });
    expect(api.listProjects).not.toHaveBeenCalled();
  });

  test("defaults to the strongest server-reported role and its first project", async () => {
    const api = apiWith(session, { [ownerWs]: [project(ownerWs, projectA, "A"), project(ownerWs, projectB, "B")] });
    const resolved = await resolveAccount(api, {});
    expect(resolved).toMatchObject({ phase: "ready", account: { workspace: { workspaceRef: ownerWs, role: "owner" } } });
    expect(resolved.phase === "ready" && resolved.project.projectRef).toBe(projectA);
  });

  test("restores a requested selection only while the server still lists it", async () => {
    const api = apiWith(session, {
      [ownerWs]: [project(ownerWs, projectA, "A"), project(ownerWs, projectB, "B")],
      [viewerWs]: [project(viewerWs, projectA, "Shared")],
    });
    const restored = await resolveAccount(api, { workspaceRef: ownerWs, projectRef: projectB });
    expect(restored.phase === "ready" && restored.project.projectRef).toBe(projectB);

    const foreignWorkspace = await resolveAccount(api, { workspaceRef: "ws_ffffffffffffffff", projectRef: projectB });
    expect(foreignWorkspace).toMatchObject({ phase: "ready", account: { workspace: { workspaceRef: ownerWs } } });
    expect(foreignWorkspace.phase === "ready" && foreignWorkspace.project.projectRef).toBe(projectA);

    const goneProject = await resolveAccount(api, { workspaceRef: viewerWs, projectRef: projectB });
    expect(goneProject).toMatchObject({ phase: "ready", account: { workspace: { workspaceRef: viewerWs, role: "viewer" } } });
    expect(goneProject.phase === "ready" && goneProject.project.name).toBe("Shared");
  });

  test("an empty workspace asks for a project and a role refusal is forbidden for that workspace", async () => {
    const api = apiWith(session, {
      [ownerWs]: [],
      [billingWs]: new HeelCloudApiError("forbidden", 403),
    });
    await expect(resolveAccount(api, {})).resolves.toMatchObject({ phase: "select_project", account: { workspace: { workspaceRef: ownerWs } } });
    await expect(resolveAccount(api, { workspaceRef: billingWs })).resolves.toMatchObject({
      phase: "forbidden", account: { workspace: { workspaceRef: billingWs, role: "billing" } },
    });
  });

  test("a session that expires between /v1/me and the project list returns to sign-in", async () => {
    const api = apiWith(session, { [ownerWs]: new HeelCloudApiError("auth_required", 401) });
    await expect(resolveAccount(api, {})).resolves.toEqual({ phase: "sign_in" });
  });

  test("an account with no memberships is reported, never given a fabricated workspace", async () => {
    const api = apiWith({ userId, workspaces: [] }, {});
    await expect(resolveAccount(api, { workspaceRef: ownerWs })).resolves.toEqual({ phase: "no_workspace", userId });
  });

  test("service failures propagate instead of becoming a signed-out state", async () => {
    const api = apiWith(new HeelCloudApiError("unavailable", 503), {});
    await expect(resolveAccount(api, {})).rejects.toMatchObject({ code: "unavailable" });
  });
});


describe("account selection in the URL", () => {
  test("accepts only exact opaque refs and drops a project without its workspace", () => {
    expect(selectionFromParams(new URLSearchParams({ workspace: ownerWs, project: projectA }))).toEqual({ workspaceRef: ownerWs, projectRef: projectA });
    expect(selectionFromParams(new URLSearchParams({ project: projectA }))).toEqual({});
    expect(selectionFromParams(new URLSearchParams({ workspace: "ws_<script>", project: "../x" }))).toEqual({});
    expect(selectionFromParams(new URLSearchParams({ workspace: ownerWs, project: "prj_short" }))).toEqual({ workspaceRef: ownerWs });
    expect(selectionFromParams(null)).toEqual({});
  });

  test("serializes nothing but the three refs", () => {
    expect(selectionQuery({ workspaceRef: ownerWs, projectRef: projectA })).toBe(`?workspace=${ownerWs}&project=${projectA}`);
    expect(selectionQuery({ workspaceRef: ownerWs, projectRef: projectA, runRef: run })).toBe(`?workspace=${ownerWs}&project=${projectA}&run=${run}`);
    expect(selectionQuery({ workspaceRef: ownerWs })).toBe(`?workspace=${ownerWs}`);
    expect(selectionQuery({})).toBe("");
    expect(selectionQuery({ workspaceRef: "not-a-ref", projectRef: projectA })).toBe("");
  });

  test("a run ref is read only as an exact opaque ref together with a well-formed workspace and project", () => {
    expect(selectionFromParams(new URLSearchParams({ workspace: ownerWs, project: projectA, run })))
      .toEqual({ workspaceRef: ownerWs, projectRef: projectA, runRef: run });
    expect(selectionFromParams(new URLSearchParams({ workspace: ownerWs, run }))).toEqual({ workspaceRef: ownerWs });
    expect(selectionFromParams(new URLSearchParams({ run }))).toEqual({});
    expect(selectionFromParams(new URLSearchParams({ workspace: ownerWs, project: "prj_short", run }))).toEqual({ workspaceRef: ownerWs });
    for (const bad of [`crun_${"C".repeat(32)}`, `crun_${"c".repeat(31)}`, `${run}x`, "crun_../x", `run_${"c".repeat(32)}`]) {
      expect(selectionFromParams(new URLSearchParams({ workspace: ownerWs, project: projectA, run: bad })))
        .toEqual({ workspaceRef: ownerWs, projectRef: projectA });
    }
  });

  test("a run ref is never serialized without its workspace and project, nor when malformed", () => {
    expect(selectionQuery({ workspaceRef: ownerWs, runRef: run })).toBe(`?workspace=${ownerWs}`);
    expect(selectionQuery({ runRef: run })).toBe("");
    expect(selectionQuery({ workspaceRef: ownerWs, projectRef: projectA, runRef: "crun_bad" })).toBe(`?workspace=${ownerWs}&project=${projectA}`);
  });

  test("a requested run ref counts only for the exact workspace and project the server confirmed", () => {
    const requested = { workspaceRef: ownerWs, projectRef: projectB, runRef: run };
    expect(confirmedRunRef(requested, ownerWs, projectB)).toBe(run);
    // The server fell back to another project or workspace: the run ref is not carried over to it.
    expect(confirmedRunRef(requested, ownerWs, projectA)).toBeNull();
    expect(confirmedRunRef(requested, viewerWs, projectB)).toBeNull();
    expect(confirmedRunRef({ workspaceRef: ownerWs, projectRef: projectB }, ownerWs, projectB)).toBeNull();
    expect(confirmedRunRef({ ...requested, runRef: "crun_bad" }, ownerWs, projectB)).toBeNull();
  });
});


describe("role presentation mirrors heel/saas/tenancy.py", () => {
  test("project creation is owner/admin/member and listing excludes billing", () => {
    expect((["owner", "admin", "member", "viewer", "billing"] as const).map(canCreateProject)).toEqual([true, true, true, false, false]);
    expect((["owner", "admin", "member", "viewer", "billing"] as const).map(canListProjects)).toEqual([true, true, true, true, false]);
  });
});
