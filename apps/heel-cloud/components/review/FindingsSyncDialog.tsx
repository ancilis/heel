// SPDX-License-Identifier: LicenseRef-Heel-Commercial

"use client";

import {
  useEffect,
  useMemo,
  useRef,
  useState,
  type FormEvent,
  type KeyboardEvent,
} from "react";

import { ProjectHistory } from "../projects/ProjectHistory";
import {
  FindingsSyncClient,
  sendApprovedFindingsSyncV1,
  type FindingsSyncApprovalV1,
  type PreparedFindingsSyncV1,
} from "../../lib/findings-sync-client";
import {
  FindingsSyncQueue,
  type FindingsSyncLeaseV1,
} from "../../lib/findings-sync-queue";
import { runWithRenewingFindingsSyncLease } from "../../lib/findings-sync-lease";
import type { FindingsSyncReceiptV1, FindingsSyncRequestV1 } from "../../lib/findings-sync-v1";
import {
  HeelCloudApi,
  HeelCloudApiError,
  type HeelCloudProject,
  type HeelCloudReviewSummary,
  type HeelCloudSession,
} from "../../lib/heel-cloud-api";
import type { ReviewEnvelopeV1 } from "../../lib/review-v1";
import { FindingsSyncStatus, type FindingsSyncUiState } from "./FindingsSyncStatus";


type AccountMode = "login" | "signup";
type DialogPhase = "checking" | "signed_out" | "projects" | "busy" | "error";
const RETRY_DELAY_MS = 30_000;
const FOCUSABLE = [
  "button:not([disabled])",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  "a[href]",
  "summary",
  "[tabindex]:not([tabindex='-1'])",
].join(",");


function wallClockMs(): number {
  return Date.now();
}

export interface FindingsSyncDialogServices {
  api: Pick<HeelCloudApi,
    | "me"
    | "signup"
    | "login"
    | "logout"
    | "listProjects"
    | "createProject"
    | "namespaceKey"
    | "approveFindings"
    | "sendFindings"
    | "listReviews"
  >;
  projector: Pick<FindingsSyncClient, "preview" | "dispose">;
  queue: Pick<FindingsSyncQueue,
    "enqueue" | "claim" | "claimNext" | "renew" | "complete" | "scheduleRetry" | "list"
  >;
}


function createServices(): FindingsSyncDialogServices {
  return {
    api: new HeelCloudApi(),
    projector: new FindingsSyncClient(),
    queue: new FindingsSyncQueue(),
  };
}


function publicError(error: unknown): string {
  if (error instanceof HeelCloudApiError) return error.message;
  return "Heel could not safely complete that cloud action. Your local result is unchanged.";
}


function canSync(session: HeelCloudSession | null, workspaceRef: string): boolean {
  const role = session?.workspaces.find((workspace) => workspace.workspaceRef === workspaceRef)?.role;
  return role === "owner" || role === "admin" || role === "member";
}


export function FindingsSyncDialog({
  open,
  review,
  services,
  onClose,
  onSynced,
}: {
  open: boolean;
  review: ReviewEnvelopeV1;
  services?: FindingsSyncDialogServices;
  onClose(): void;
  onSynced(receipt: FindingsSyncReceiptV1): void;
}) {
  const deps = useMemo(() => services ?? createServices(), [services]);
  const [phase, setPhase] = useState<DialogPhase>("checking");
  const [accountMode, setAccountMode] = useState<AccountMode>("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [session, setSession] = useState<HeelCloudSession | null>(null);
  const [workspaceRef, setWorkspaceRef] = useState("");
  const [projects, setProjects] = useState<HeelCloudProject[]>([]);
  const [projectRef, setProjectRef] = useState("");
  const [projectName, setProjectName] = useState("");
  const [prepared, setPrepared] = useState<PreparedFindingsSyncV1 | null>(null);
  const [receipt, setReceipt] = useState<FindingsSyncReceiptV1 | null>(null);
  const [history, setHistory] = useState<HeelCloudReviewSummary[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [syncState, setSyncState] = useState<FindingsSyncUiState>("local_only");
  const [error, setError] = useState("");
  const backdropRef = useRef<HTMLDivElement>(null);
  const closeButtonRef = useRef<HTMLButtonElement>(null);
  const retryTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  function clearRetryTimer(): void {
    if (retryTimerRef.current !== null) clearTimeout(retryTimerRef.current);
    retryTimerRef.current = null;
  }

  function scheduleResume(
    nextWorkspace: string,
    visibleProjectRef: string,
    delayMs: number,
  ): void {
    clearRetryTimer();
    retryTimerRef.current = setTimeout(() => {
      retryTimerRef.current = null;
      void resumeApprovedRetry(nextWorkspace, visibleProjectRef);
    }, Math.max(250, delayMs));
  }

  async function scheduleStoredRetry(
    nextWorkspace: string,
    visibleProjectRef: string,
  ): Promise<void> {
    const now = wallClockMs();
    const queued = await deps.queue.list(nextWorkspace);
    const futureAttempts = queued.flatMap((item) => {
      if (
        item.receipt !== null
        || item.expires_at < now
        || item.retry.next_attempt_at === null
        || item.retry.last_error_code === "approval_expired"
      ) return [];
      const afterLease = item.retry.lease_expires_at !== null && item.retry.lease_expires_at > now
        ? Math.max(item.retry.next_attempt_at, item.retry.lease_expires_at)
        : item.retry.next_attempt_at;
      return [afterLease];
    });
    if (futureAttempts.length === 0) return;
    scheduleResume(nextWorkspace, visibleProjectRef, Math.min(...futureAttempts) - now);
  }

  async function refreshHistory(nextWorkspace = workspaceRef, nextProject = projectRef): Promise<void> {
    if (nextWorkspace === "" || nextProject === "") return;
    setHistoryLoading(true);
    try {
      setHistory(await deps.api.listReviews(nextWorkspace, nextProject));
    } catch (caught) {
      setError(publicError(caught));
    } finally {
      setHistoryLoading(false);
    }
  }

  async function loadProjects(nextSession: HeelCloudSession, nextWorkspace: string): Promise<void> {
    clearRetryTimer();
    const nextProjects = await deps.api.listProjects(nextWorkspace);
    setProjects(nextProjects);
    setWorkspaceRef(nextWorkspace);
    const firstProject = nextProjects[0];
    setProjectRef(firstProject?.projectRef ?? "");
    setPrepared(null);
    setReceipt(null);
    setSyncState("local_only");
    setPhase("projects");
    setSession(nextSession);
    if (firstProject !== undefined) {
      setHistoryLoading(true);
      try {
        setHistory(await deps.api.listReviews(nextWorkspace, firstProject.projectRef));
      } finally {
        setHistoryLoading(false);
      }
    } else setHistory([]);
    void resumeApprovedRetry(nextWorkspace, firstProject?.projectRef ?? "");
  }

  async function resumeApprovedRetry(
    nextWorkspace: string,
    visibleProjectRef: string,
  ): Promise<void> {
    let lease: FindingsSyncLeaseV1 | null = null;
    let transportFailure: unknown = null;
    try {
      lease = await deps.queue.claimNext(nextWorkspace);
      if (lease === null) {
        await scheduleStoredRetry(nextWorkspace, visibleProjectRef);
        return;
      }
      const retryProjectRef = lease.record.project_ref;
      if (retryProjectRef === visibleProjectRef) setSyncState("syncing");
      const request = JSON.parse(lease.record.request_json) as FindingsSyncRequestV1;
      const retryPrepared: PreparedFindingsSyncV1 = {
        request,
        requestJson: lease.record.request_json,
        requestDigest: lease.record.request_digest,
        idempotencyKey: `fs1-${lease.record.request_digest}`,
      };
      const retryApproval: FindingsSyncApprovalV1 = {
        workspaceRef: lease.record.workspace_ref,
        projectRef: retryProjectRef,
        requestDigest: lease.record.request_digest,
        approvedAt: lease.record.approved_at,
        expiresAt: lease.record.expires_at,
      };
      const transported = await runWithRenewingFindingsSyncLease(
        lease,
        (currentLease) => deps.queue.renew(currentLease),
        (signal) => sendApprovedFindingsSyncV1(
          retryPrepared,
          retryApproval,
          nextWorkspace,
          async (requestJson, idempotencyKey) => {
            try {
              return await deps.api.sendFindings(
                nextWorkspace, retryProjectRef, requestJson, idempotencyKey, signal,
              );
            } catch (caught) {
              transportFailure = caught;
              throw caught;
            }
          },
        ),
        undefined,
        (renewedLease) => {
          lease = renewedLease;
        },
      );
      lease = transported.lease;
      if (!await deps.queue.complete(lease, transported.value)) {
        throw new Error("approved retry lease expired");
      }
      if (retryProjectRef === visibleProjectRef) {
        setReceipt(transported.value);
        setSyncState("synced");
        await refreshHistory(nextWorkspace, visibleProjectRef);
      }
      void resumeApprovedRetry(nextWorkspace, visibleProjectRef);
    } catch (caught) {
      const retryCode = transportFailure instanceof HeelCloudApiError
        && transportFailure.code === "approval_expired"
        ? "approval_expired"
        : "transport_error";
      let retryScheduled = false;
      if (lease !== null) {
        try {
          retryScheduled = await deps.queue.scheduleRetry(
            lease, wallClockMs() + RETRY_DELAY_MS, retryCode,
          );
        } catch {
          retryScheduled = false;
        }
      }
      if (lease?.record.project_ref === visibleProjectRef) {
        setSyncState(retryScheduled && retryCode !== "approval_expired" ? "retry_pending" : "local_only");
        setError(publicError(transportFailure ?? caught));
      }
      if (retryScheduled && retryCode !== "approval_expired") {
        scheduleResume(nextWorkspace, visibleProjectRef, RETRY_DELAY_MS);
      }
    }
  }

  async function loadAccount(): Promise<void> {
    setPhase("checking");
    setError("");
    try {
      const nextSession = await deps.api.me();
      if (nextSession.workspaces.length === 0) throw new HeelCloudApiError("invalid_response", 502);
      await loadProjects(nextSession, nextSession.workspaces[0].workspaceRef);
    } catch (caught) {
      if (caught instanceof HeelCloudApiError && caught.status === 401) {
        setSession(null);
        setPhase("signed_out");
      } else {
        setError(publicError(caught));
        setPhase("error");
      }
    }
  }

  useEffect(() => {
    if (!open) return undefined;
    const timer = setTimeout(() => void loadAccount(), 0);
    return () => clearTimeout(timer);
    // Dependencies are intentionally service-identity bound; product state refreshes on open.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, deps]);

  useEffect(() => {
    if (open) closeButtonRef.current?.focus();
  }, [open]);

  useEffect(() => {
    if (!open) return undefined;
    const backdrop = backdropRef.current;
    const siblings = backdrop === null || backdrop.parentElement === null
      ? []
      : [...backdrop.parentElement.children].filter((element): element is HTMLElement => (
        element instanceof HTMLElement && element !== backdrop
      ));
    const previous = siblings.map((element) => ({
      element,
      inert: element.inert,
      ariaHidden: element.getAttribute("aria-hidden"),
    }));
    for (const item of previous) {
      item.element.inert = true;
      item.element.setAttribute("aria-hidden", "true");
    }
    return () => {
      for (const item of previous) {
        item.element.inert = item.inert;
        if (item.ariaHidden === null) item.element.removeAttribute("aria-hidden");
        else item.element.setAttribute("aria-hidden", item.ariaHidden);
      }
    };
  }, [open]);

  useEffect(() => {
    return () => {
      clearRetryTimer();
      if (services === undefined) deps.projector.dispose();
    };
  }, [deps, services]);

  if (!open) return null;

  async function submitAccount(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setError("");
    setPhase("busy");
    try {
      if (accountMode === "signup") await deps.api.signup(email.trim(), password);
      else await deps.api.login(email.trim(), password);
      setPassword("");
      await loadAccount();
    } catch (caught) {
      setError(publicError(caught));
      setPhase("signed_out");
    }
  }

  async function createProject(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setError("");
    setPhase("busy");
    try {
      const project = await deps.api.createProject(workspaceRef, projectName.trim());
      const nextProjects = [...projects, project];
      setProjects(nextProjects);
      setProjectRef(project.projectRef);
      setProjectName("");
      setHistory([]);
      setPhase("projects");
    } catch (caught) {
      setError(publicError(caught));
      setPhase("projects");
    }
  }

  async function selectProject(nextProjectRef: string): Promise<void> {
    setProjectRef(nextProjectRef);
    setPrepared(null);
    setReceipt(null);
    setSyncState("local_only");
    setError("");
    await refreshHistory(workspaceRef, nextProjectRef);
  }

  async function preparePreview(): Promise<void> {
    if (projectRef === "" || !canSync(session, workspaceRef)) return;
    setPhase("busy");
    setSyncState("preparing");
    setError("");
    let namespaceKey: Uint8Array | null = null;
    try {
      namespaceKey = await deps.api.namespaceKey(workspaceRef, projectRef);
      const nextPrepared = await deps.projector.preview(review, projectRef, namespaceKey);
      setPrepared(nextPrepared);
      setSyncState("awaiting_consent");
      setPhase("projects");
    } catch (caught) {
      setSyncState("local_only");
      setError(publicError(caught));
      setPhase("projects");
    } finally {
      namespaceKey?.fill(0);
    }
  }

  async function approveAndSync(): Promise<void> {
    if (prepared === null || prepared.request.project_ref !== projectRef) return;
    setPhase("busy");
    setSyncState("syncing");
    setError("");
    let lease: FindingsSyncLeaseV1 | null = null;
    let transportFailure: unknown = null;
    try {
      const serverApproval = await deps.api.approveFindings(
        workspaceRef, projectRef, prepared.requestDigest,
      );
      const approval: FindingsSyncApprovalV1 = {
        workspaceRef,
        projectRef,
        requestDigest: prepared.requestDigest,
        approvedAt: serverApproval.approvedAt,
        expiresAt: serverApproval.expiresAt,
      };
      await deps.queue.enqueue(prepared, approval);
      lease = await deps.queue.claim(workspaceRef, projectRef, prepared.requestDigest);
      if (lease === null) throw new Error("approved retry could not be claimed");
      const transported = await runWithRenewingFindingsSyncLease(
        lease,
        (currentLease) => deps.queue.renew(currentLease),
        (signal) => sendApprovedFindingsSyncV1(
          prepared,
          approval,
          workspaceRef,
          async (requestJson, idempotencyKey) => {
            try {
              return await deps.api.sendFindings(
                workspaceRef, projectRef, requestJson, idempotencyKey, signal,
              );
            } catch (caught) {
              transportFailure = caught;
              throw caught;
            }
          },
        ),
        undefined,
        (renewedLease) => {
          lease = renewedLease;
        },
      );
      lease = transported.lease;
      const accepted = transported.value;
      if (!await deps.queue.complete(lease, accepted)) {
        throw new Error("approved retry lease expired");
      }
      setReceipt(accepted);
      setSyncState("synced");
      setPhase("projects");
      await refreshHistory(workspaceRef, projectRef);
      onSynced(accepted);
    } catch (caught) {
      const retryCode = transportFailure instanceof HeelCloudApiError
        && transportFailure.code === "approval_expired"
        ? "approval_expired"
        : "transport_error";
      let retryScheduled = false;
      if (lease !== null) {
        try {
          retryScheduled = await deps.queue.scheduleRetry(
            lease, wallClockMs() + RETRY_DELAY_MS, retryCode,
          );
        } catch {
          retryScheduled = false;
        }
      }
      setSyncState(retryScheduled && retryCode !== "approval_expired" ? "retry_pending" : "local_only");
      setError(publicError(transportFailure ?? caught));
      setPhase("projects");
      if (retryScheduled && retryCode !== "approval_expired") {
        scheduleResume(workspaceRef, projectRef, RETRY_DELAY_MS);
      }
    }
  }

  function handleDialogKeyDown(event: KeyboardEvent<HTMLElement>): void {
    if (event.key === "Escape") {
      event.preventDefault();
      onClose();
      return;
    }
    if (event.key !== "Tab") return;
    const focusable = [...event.currentTarget.querySelectorAll<HTMLElement>(FOCUSABLE)];
    const first = focusable[0];
    const last = focusable.at(-1);
    if (first === undefined || last === undefined) return;
    if (event.shiftKey && event.target === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && event.target === last) {
      event.preventDefault();
      first.focus();
    }
  }

  const activeProject = projects.find((project) => project.projectRef === projectRef) ?? null;
  const syncAllowed = canSync(session, workspaceRef);

  return (
    <div className="sync-dialog-backdrop" ref={backdropRef}>
      <section
        className="sync-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="sync-dialog-title"
        aria-describedby="sync-dialog-description"
        onKeyDown={handleDialogKeyDown}
      >
        <button
          ref={closeButtonRef}
          className="sync-dialog-close"
          type="button"
          onClick={onClose}
          aria-label="Close findings continuity"
        >
          ×
        </button>
        <p className="eyebrow">Optional Heel Cloud continuity</p>
        <h2 id="sync-dialog-title">Keep findings, not source.</h2>
        <p className="sync-dialog-lede" id="sync-dialog-description">
          Your OpenAPI document stays in this browser. Heel Cloud receives only the exact
          pseudonymous fields shown before you approve.
        </p>

        {phase === "checking" ? <p role="status">Checking your Heel session…</p> : null}

        {phase === "signed_out" ? (
          <form className="account-form" onSubmit={(event) => void submitAccount(event)}>
            <h3>Sign in to keep findings across devices</h3>
            <label>
              Work email
              <input
                type="email"
                autoComplete="email"
                required
                value={email}
                onChange={(event) => setEmail(event.target.value)}
              />
            </label>
            <label>
              Password
              <input
                type="password"
                autoComplete={accountMode === "signup" ? "new-password" : "current-password"}
                minLength={12}
                required
                value={password}
                onChange={(event) => setPassword(event.target.value)}
              />
            </label>
            <button className="button button-primary" type="submit">
              {accountMode === "signup" ? "Create Heel account" : "Sign in"}
            </button>
            <button
              className="text-button"
              type="button"
              onClick={() => setAccountMode((current) => current === "login" ? "signup" : "login")}
            >
              {accountMode === "login" ? "Create account instead" : "Sign in instead"}
            </button>
          </form>
        ) : null}

        {(phase === "projects" || phase === "busy") && session !== null ? (
          <div className="sync-dialog-body">
            <div className="cloud-account-row">
              <label>
                Workspace
                <select
                  value={workspaceRef}
                  disabled={phase === "busy"}
                  onChange={(event) => {
                    const next = event.target.value;
                    const nextSession = session;
                    setPhase("busy");
                    void loadProjects(nextSession, next).catch((caught) => {
                      setError(publicError(caught));
                      setPhase("projects");
                    });
                  }}
                >
                  {session.workspaces.map((workspace) => (
                    <option key={workspace.workspaceRef} value={workspace.workspaceRef}>
                      {workspace.workspaceRef} · {workspace.role}
                    </option>
                  ))}
                </select>
              </label>
              <button
                className="text-button"
                type="button"
                onClick={() => void deps.api.logout().then(() => {
                  clearRetryTimer();
                  setSession(null);
                  setPhase("signed_out");
                  setPrepared(null);
                  setReceipt(null);
                  setSyncState("local_only");
                }, (caught) => setError(publicError(caught)))}
              >
                Sign out
              </button>
            </div>

            {projects.length === 0 ? (
              <form className="project-create" onSubmit={(event) => void createProject(event)}>
                <h3>Create your first project</h3>
                <p>A project keeps pseudonymous finding identity stable without storing the source.</p>
                <label>
                  Project name
                  <input
                    required
                    maxLength={120}
                    value={projectName}
                    onChange={(event) => setProjectName(event.target.value)}
                    placeholder="Production API"
                  />
                </label>
                <button className="button button-primary" type="submit" disabled={phase === "busy"}>
                  Create project
                </button>
              </form>
            ) : (
              <>
                <label className="project-select">
                  Project
                  <select
                    value={projectRef}
                    disabled={phase === "busy"}
                    onChange={(event) => void selectProject(event.target.value)}
                  >
                    {projects.map((project) => (
                      <option key={project.projectRef} value={project.projectRef}>{project.name}</option>
                    ))}
                  </select>
                </label>

                <FindingsSyncStatus state={syncState} receipt={receipt} />

                {!syncAllowed ? (
                  <p className="cloud-role-note">Your workspace role can view history but cannot sync findings.</p>
                ) : prepared === null ? (
                  <button
                    className="button button-primary"
                    type="button"
                    onClick={() => void preparePreview()}
                    disabled={phase === "busy"}
                  >
                    Prepare findings-only preview
                  </button>
                ) : (
                  <section className="sync-preview" aria-labelledby="sync-preview-title">
                    <p className="eyebrow">Exact approval preview</p>
                    <h3 id="sync-preview-title">
                      {prepared.request.summary.findings} locally flagged finding{prepared.request.summary.findings === 1 ? "" : "s"}
                    </h3>
                    <p>
                      Gate {prepared.request.gate_status} · {prepared.request.summary.blockers} local blocker flag.
                      Reachability is “not declared” unless the row explicitly says locally declared reachable.
                    </p>
                    <ul className="sync-preview-list">
                      {prepared.request.findings.map((finding) => (
                        <li key={finding.finding_id}>
                          <strong>{finding.risk_code.replaceAll("_", " ")}</strong>
                          <span>
                            local model flagged · {finding.surface_type.replaceAll("_", " ")} · {finding.severity}
                            {" · "}{finding.reachable ? "locally declared reachable" : "reachability not declared"}
                          </span>
                          <span>recommended control · {finding.control_code.replaceAll("_", " ")}</span>
                        </li>
                      ))}
                    </ul>
                    <div className="sync-exact-json">
                      <h4>Exact JSON that will cross the boundary</h4>
                      <pre>{prepared.requestJson}</pre>
                    </div>
                    <button
                      className="button button-primary"
                      type="button"
                      onClick={() => void approveAndSync()}
                      disabled={phase === "busy" || syncState === "synced"}
                    >
                      Approve and sync these findings
                    </button>
                  </section>
                )}

                {activeProject !== null ? (
                  <ProjectHistory
                    projectName={activeProject.name}
                    reviews={history}
                    loading={historyLoading}
                    onRefresh={() => void refreshHistory()}
                  />
                ) : null}
              </>
            )}
          </div>
        ) : null}

        {error !== "" ? <p className="error-message" role="alert">{error}</p> : null}
        {phase === "error" ? (
          <button className="button button-secondary" type="button" onClick={() => void loadAccount()}>
            Retry session check
          </button>
        ) : null}
      </section>
    </div>
  );
}
