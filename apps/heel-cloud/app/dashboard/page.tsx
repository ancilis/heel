// SPDX-License-Identifier: LicenseRef-Heel-Commercial

"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";

import { AccountAccess } from "../../components/account/AccountAccess";
import { WorkspaceProjectBar } from "../../components/account/WorkspaceProjectBar";
import { ActivationCard, type ActivationSnapshot } from "../../components/canary/ActivationCard";
import { ApprovalDialog } from "../../components/canary/ApprovalDialog";
import { DisclosureDialog } from "../../components/canary/DisclosureDialog";
import { FindingsCard } from "../../components/canary/FindingsCard";
import { RunProgress, type RunPhase } from "../../components/canary/RunProgress";
import { RunnerPairingCard, pairingPhraseMatches } from "../../components/canary/RunnerPairingCard";
import { TargetRegistrationCard, type OwnershipProofMethod, type PendingTarget } from "../../components/onboarding/TargetRegistrationCard";
import {
  CanaryApi, CanaryApiError, type CanaryApprovalSummary, type CanaryDisclosureState, type CanaryFindingsProjection,
  type CanaryPendingApprovalRequest, type CanaryRunDashboard, type PendingEnvironmentProof, type RunnerContextBindingDashboard, type RunnerPairingView,
  type VerifiedEnvironmentRecord,
} from "../../lib/canary-api";
import {
  canCreateProject, confirmedRunRef, resolveAccount, selectionFromParams, selectionQuery, type AccountSelection, type AccountWorkspaceView,
} from "../../lib/account-context";
import { HeelCloudApi, HeelCloudApiError, type HeelCloudProject } from "../../lib/heel-cloud-api";


const OWNERSHIP_ATTESTATION = "ownership verified; environment classification supplied by you";
const SIGN_IN_MESSAGE = "Create a free account or sign in to set up your first project.";
const SESSION_ENDED_MESSAGE = "Your session ended. Sign in again to continue; nothing from the previous session is shown.";
const SIGNED_OUT_MESSAGE = "You signed out. Sign in again to continue.";
const CANARY_LOCKED_MESSAGE = "You are still signed in. Staging verification, runner access and rehearsals stay locked until it loads; nothing has been approved or executed.";
const PROJECT_CREATED_READY = "Project created. Add a target next.";
const PROOF_RECENT_AUTH_MESSAGE = "For your security, showing or replacing a pending proof needs a sign-in from the last 15 minutes. The proof is kept on the server: sign out, sign in again, then resume it.";
const PAIRING_RECENT_AUTH_MESSAGE = "For your security, pairing or revoking a runner needs an owner or admin sign-in from the last 15 minutes. Sign out, sign in again, then create a new invitation.";
const RUN_RECENT_AUTH_MESSAGE = "For your security, approving a rehearsal needs an owner or admin sign-in from the last 15 minutes. Nothing was approved or run, and the plan is kept on the server: sign in again, then review the exact plan and approve it.";
const RUN_REAUTH_SIGN_IN_MESSAGE = "Sign in again to return to this project. Nothing was approved or run; review the exact plan again before approving it.";
const DISCLOSURE_RECENT_AUTH_MESSAGE = "For your security, sharing a result summary or keeping it local needs an owner or admin sign-in from the last 15 minutes. Nothing was shared: sign in again, then review the summary.";
const DISCLOSURE_REAUTH_SIGN_IN_MESSAGE = "Sign in again to return to this rehearsal result. Nothing was shared; review the summary again before sharing it.";
const PAIRING_GONE_MESSAGE = "That pairing request is no longer available: it expired, was already used, or belongs to another workspace. Create a new invitation and run the pair command again.";
const PROJECT_CREATED_BLOCKED = "Project created. Canary setup is unavailable right now, so target verification is blocked; use Try again shortly.";
const cloudApi = new HeelCloudApi();
const canaryApi = new CanaryApi();

type Context = {
  account: AccountWorkspaceView;
  workspaceRef: string;
  project: HeelCloudProject;
  projects: readonly HeelCloudProject[];
  environments: readonly VerifiedEnvironmentRecord[];
  contextBindings: RunnerContextBindingDashboard;
};

type Connection =
  | { phase: "checking" }
  | { phase: "sign_in"; message: string }
  | { phase: "no_workspace"; message: string }
  | { phase: "forbidden"; account: AccountWorkspaceView; message: string }
  | { phase: "select_project"; account: AccountWorkspaceView }
  | { phase: "ready"; context: Context }
  // The account and project resolved, but a canary read failed: account controls stay, canary stays locked.
  | { phase: "canary_unavailable"; account: AccountWorkspaceView; projects: readonly HeelCloudProject[]; project: HeelCloudProject; message: string }
  | { phase: "error"; message: string };

type ProofChallenge = { environmentId: string; instruction: string };
/** One pairing ceremony, bound to the workspace and project it started in; kept only in page memory. */
type PairingSession = {
  workspaceRef: string;
  projectRef: string;
  invitation: { token: string; expiresAt: number } | null;
  pairing: RunnerPairingView | null;
  approved: boolean;
};
/** The run ref the address carried, kept only in page memory until the tenant-scoped run read re-authorizes it. */
type RunHint = { workspaceRef: string; projectRef: string; runRef: string; unavailable: boolean };
/**
 * What the control plane last said about one run's disclosure, bound to the context and run it was read for:
 * `waiting` is its 404 before the paired runner registered the local result, `unavailable` an outage or a response
 * the strict parser refused. Findings are only ever the strict `getFindings` value for a synchronized run.
 */
type DisclosureView = {
  workspaceRef: string;
  projectRef: string;
  runId: string;
  read: { kind: "waiting" } | { kind: "unavailable" } | { kind: "state"; state: CanaryDisclosureState };
  findings: Readonly<CanaryFindingsProjection> | null;
  findingsUnavailable: boolean;
};
type ReauthReason = "run" | "disclosure";
type ApprovalDialogState = { requestKey: string; open: boolean } | null;
type PendingApproval = {
  requestKey: string;
  workspaceRef: string;
  projectRef: string;
  summary: CanaryPendingApprovalRequest;
  run: CanaryRunDashboard;
};


function messageOf(error: unknown): string {
  if (error instanceof CanaryApiError || error instanceof HeelCloudApiError) return error.message;
  return "Heel Cloud is temporarily unavailable. Your local setup is unchanged.";
}

/** Server rejected the session itself (expired, revoked, or signed out elsewhere). */
function isSessionLoss(error: unknown): boolean {
  return (error instanceof HeelCloudApiError && error.code === "auth_required")
    || (error instanceof CanaryApiError && error.status === 401);
}

/** The one place a proof instruction is worded; it is shown on screen only and never stored. */
function proofInstruction(method: OwnershipProofMethod, httpUrl: string, token: string, dnsRecord: string): string {
  return method === "https-file" ? `Place the one-time token at ${httpUrl}: ${token}` : `Publish this exact record: ${dnsRecord}`;
}

/** Wall-clock seconds, the unit of the pairing invitation and request expiry. */
type PairedRunner = { runnerId: string; key: string; label: string; name: string };

/**
 * Every runner the workspace can revoke: the server's bindable runners plus the runner of each active, unexpired
 * binding (the bindable selector omits a runner while it is bound). A binding carries no display name or fingerprint,
 * so its runner is shown by id. The pairing offer, the revoke list and the revoke precondition all use this one set.
 */
function pairedRunnersOf(dashboard: RunnerContextBindingDashboard, nowMs: number): PairedRunner[] {
  const paired: PairedRunner[] = dashboard.runners.map((item) => ({
    runnerId: item.runnerId, key: `${item.runnerId}:${item.runnerKeyId}`,
    label: `${item.displayName} · ${item.fingerprint.slice(0, 12)}`, name: item.displayName,
  }));
  for (const item of dashboard.bindings) {
    if (item.status !== "active" || item.expiresAtMs <= nowMs || paired.some((entry) => entry.runnerId === item.runnerId)) continue;
    paired.push({ runnerId: item.runnerId, key: `${item.runnerId}:${item.runnerKeyId}`, label: item.runnerId, name: item.runnerId });
  }
  return paired;
}

function currentSeconds(): number {
  return Date.now() / 1000;
}

function idempotencyKey(): `ca1-${string}` {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return `ca1-${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

/** Run statuses after which the control plane changes nothing the dashboard shows; a settled run is not re-read. */
const SETTLED_RUN_STATUSES: ReadonlySet<string> = new Set(["terminal", "cancelled", "expired"]);
/** A run in these statuses is reached only through the pending-approval list, never through an address ref. */
const PRE_APPROVAL_STATUSES: ReadonlySet<string> = new Set(["prepared", "awaiting_execution_approval"]);
/** Disclosure statuses after which nothing the dashboard shows changes (synchronized settles once findings load). */
const SETTLED_DISCLOSURE_STATUSES: ReadonlySet<string> = new Set(["local_only", "expired"]);

function approvalRequestKey(workspaceRef: string, projectRef: string, approval: CanaryApprovalSummary): string {
  return `${workspaceRef}\0${projectRef}\0${approval.approvalId}\0${approval.runId}\0${approval.projectionDigest}`;
}

async function loadConnection(requested: AccountSelection): Promise<Connection> {
  try {
    const resolved = await resolveAccount(cloudApi, requested);
    if (resolved.phase === "sign_in") return { phase: "sign_in", message: SIGN_IN_MESSAGE };
    if (resolved.phase === "no_workspace") {
      return { phase: "no_workspace", message: "This account is not a member of any workspace. Ask a workspace owner to invite you; creating additional workspaces is not available in this release." };
    }
    if (resolved.phase === "forbidden") {
      return { phase: "forbidden", account: resolved.account, message: `Your ${resolved.account.workspace.role} role cannot open projects in this workspace. Choose another workspace or ask an owner for access.` };
    }
    if (resolved.phase === "select_project") return { phase: "select_project", account: resolved.account };
    const { account, projects, project } = resolved;
    try {
      const environments = await canaryApi.listEnvironments(account.workspace.workspaceRef, project.projectRef);
      const contextBindings = await canaryApi.listRunnerContextBindings(account.workspace.workspaceRef, project.projectRef);
      return { phase: "ready", context: { account, workspaceRef: account.workspace.workspaceRef, project, projects, environments, contextBindings } };
    } catch (error) {
      if (isSessionLoss(error)) throw error;
      return { phase: "canary_unavailable", account, projects, project, message: `${messageOf(error)} ${CANARY_LOCKED_MESSAGE}` };
    }
  } catch (error) {
    return isSessionLoss(error)
      ? { phase: "sign_in", message: SESSION_ENDED_MESSAGE }
      : { phase: "error", message: messageOf(error) };
  }
}

/** The address's run ref, kept only for the exact workspace and project the server just confirmed. */
function runHintFor(requested: AccountSelection, next: Connection): RunHint | null {
  if (next.phase !== "ready") return null;
  const runRef = confirmedRunRef(requested, next.context.workspaceRef, next.context.project.projectRef);
  return runRef === null ? null : { workspaceRef: next.context.workspaceRef, projectRef: next.context.project.projectRef, runRef, unavailable: false };
}

const STATUS_TITLES: Readonly<Record<Exclude<Connection["phase"], "ready">, string>> = Object.freeze({
  checking: "Checking your session.",
  sign_in: "Sign in to continue.",
  no_workspace: "No workspace is available.",
  forbidden: "This workspace is not available to your role.",
  select_project: "Create a project first.",
  canary_unavailable: "Canary setup could not be loaded.",
  error: "Heel Cloud could not load your workspace.",
});

function connectionSelection(connection: Connection): AccountSelection {
  if (connection.phase === "ready") {
    return { workspaceRef: connection.context.workspaceRef, projectRef: connection.context.project.projectRef };
  }
  if (connection.phase === "canary_unavailable") {
    return { workspaceRef: connection.account.workspace.workspaceRef, projectRef: connection.project.projectRef };
  }
  if (connection.phase === "select_project" || connection.phase === "forbidden") {
    return { workspaceRef: connection.account.workspace.workspaceRef };
  }
  return {};
}


export default function Dashboard() {
  const [connection, setConnection] = useState<Connection>({ phase: "checking" });
  const [notice, setNotice] = useState<string | null>(null);
  // The action that owns the busy state; only that action, or a context transition, releases it.
  const [busyOperation, setBusyOperation] = useState<number | null>(null);
  const working = busyOperation !== null;
  const [origin, setOrigin] = useState("");
  const [proofMethod, setProofMethod] = useState<OwnershipProofMethod>("https-file");
  const [proofChallenge, setProofChallenge] = useState<ProofChallenge | null>(null);
  // Which listed pending record the user chose, and which one the server said can only be replaced.
  const [selectedPendingId, setSelectedPendingId] = useState<string | null>(null);
  const [replacementPendingId, setReplacementPendingId] = useState<string | null>(null);
  const [pendingApproval, setPendingApproval] = useState<PendingApproval | null>(null);
  const [approvalDialog, setApprovalDialog] = useState<ApprovalDialogState>(null);
  const [observedRun, setObservedRun] = useState<CanaryRunDashboard | null>(null);
  const [runHint, setRunHint] = useState<RunHint | null>(null);
  const [disclosure, setDisclosure] = useState<DisclosureView | null>(null);
  const [disclosureOpen, setDisclosureOpen] = useState(false);
  // Bumped after a sharing decision so the disclosure status is re-read at once instead of on the next tick.
  const [disclosureTick, setDisclosureTick] = useState(0);
  const [selectedRunner, setSelectedRunner] = useState("");
  const [selectedBindingEnvironment, setSelectedBindingEnvironment] = useState("");
  const [pendingHasMore, setPendingHasMore] = useState(false);
  const [pairingSession, setPairingSession] = useState<PairingSession | null>(null);
  const [revokeCandidate, setRevokeCandidate] = useState<string | null>(null);
  const [nowSeconds, setNowSeconds] = useState(currentSeconds);

  const clearPendingApproval = useCallback((): void => {
    setPendingApproval(null);
    setApprovalDialog(null);
    setPendingHasMore(false);
  }, []);

  const clearApprovalIdentity = useCallback((): void => {
    clearPendingApproval();
    setObservedRun(null);
    setRunHint(null);
    setDisclosure(null);
    setDisclosureOpen(false);
  }, [clearPendingApproval]);

  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const searchQuery = searchParams?.toString() ?? "";
  const [initialSelection] = useState(() => selectionFromParams(searchParams));
  // The address the current connection was resolved from or last wrote. A same-document change
  // to anything else (Back/Forward, a link) is incoming navigation, not a stale address to undo.
  const appliedQuery = useRef(searchQuery);
  // Addresses this page wrote that the router has not echoed back yet; an echo can arrive after a
  // newer write, so it is recognized by value rather than by being the latest.
  const pendingWrites = useRef<string[]>([]);
  const latestQuery = useRef(searchQuery);
  // Every account transition (sign-in, sign-out, session loss, workspace or project switch)
  // takes a new generation; a response that settles for an older generation is dropped.
  const generation = useRef(0);
  const operations = useRef(0);
  // Only the "Sign in again" recovery for a rehearsal approval or a sharing decision keeps the account's opaque refs
  // (workspace, project and the shown run) across its sign-out; the next sign-in passes them to `connect` as hints
  // that the server re-resolves like any address, and the run ref is re-authorized by the run read before it shows.
  const reauthSelection = useRef<AccountSelection | null>(null);

  /** Marks the page busy for one action; the returned token is what that action's finally releases. */
  const beginWork = useCallback((): number => {
    const operation = ++operations.current;
    setBusyOperation(operation);
    return operation;
  }, []);

  /** Releases busy only if this action still owns it, so an obsolete finally cannot unblock a newer action. */
  const endWork = useCallback((operation: number): void => {
    setBusyOperation((current) => current === operation ? null : current);
  }, []);

  const resetProjectState = useCallback((): void => {
    setSelectedRunner(""); setSelectedBindingEnvironment("");
    setPairingSession(null); setRevokeCandidate(null);
    setProofChallenge(null);
    setSelectedPendingId(null); setReplacementPendingId(null);
    setOrigin("");
  }, []);

  useEffect(() => {
    const ticket = ++generation.current;
    void loadConnection(initialSelection).then((next) => {
      if (ticket !== generation.current) return;
      if (next.phase !== "ready") clearApprovalIdentity();
      setConnection(next);
      setRunHint(runHintFor(initialSelection, next));
    });
    return () => { generation.current += 1; };
  }, [clearApprovalIdentity, initialSelection]);

  /** Resolves to the applied connection, or null when a newer transition superseded this one. */
  const connect = useCallback(async (requested: AccountSelection): Promise<Connection | null> => {
    const ticket = ++generation.current;
    // Actions still pending belong to the previous context; they no longer block this one.
    setBusyOperation(null);
    clearApprovalIdentity();
    // An invitation, opened pairing request or revoke confirmation never survives a context transition.
    setPairingSession(null); setRevokeCandidate(null);
    setConnection({ phase: "checking" });
    const next = await loadConnection(requested);
    if (ticket !== generation.current) return null;
    setConnection(next);
    setRunHint(runHintFor(requested, next));
    return next;
  }, [clearApprovalIdentity]);

  const sessionEnded = useCallback((): void => {
    generation.current += 1;
    setBusyOperation(null);
    clearApprovalIdentity();
    resetProjectState();
    setNotice(null);
    setConnection({ phase: "sign_in", message: SESSION_ENDED_MESSAGE });
  }, [clearApprovalIdentity, resetProjectState]);

  /** Handles an action failure only while the session that started the action is still current. */
  function recover(error: unknown, ticket: number): void {
    if (ticket !== generation.current) return;
    if (isSessionLoss(error)) sessionEnded();
    else setNotice(messageOf(error));
  }

  // The run the address names: the run shown past approval, else a hint still awaiting its re-authorizing read. A
  // pending approval for any run wins, and only a ready, server-confirmed context ever carries a run ref.
  const readyContext = connection.phase === "ready" ? connection.context : null;
  const shownRunRef = readyContext !== null && pendingApproval === null && observedRun !== null
    && !PRE_APPROVAL_STATUSES.has(observedRun.run.status) ? observedRun.run.runId : null;
  const hintedRunRef = readyContext !== null && pendingApproval === null && observedRun === null && runHint !== null
    && runHint.workspaceRef === readyContext.workspaceRef && runHint.projectRef === readyContext.project.projectRef
    ? runHint.runRef : null;
  const addressRunRef = shownRunRef ?? hintedRunRef;

  // Declared before the sync below so it sees this render's address.
  useEffect(() => { latestQuery.current = searchQuery; }, [searchQuery]);

  // Keep the address bar on the server-confirmed selection (opaque refs only) so a reload
  // restores it; signed-out states carry no refs at all. This runs when the connection changes,
  // never merely because the address did.
  useEffect(() => {
    if (connection.phase === "checking" || connection.phase === "error") return;
    const wanted = selectionQuery({ ...connectionSelection(connection), ...(addressRunRef === null ? {} : { runRef: addressRunRef }) }).slice(1);
    appliedQuery.current = wanted;
    if (wanted === latestQuery.current) return;
    pendingWrites.current = [...pendingWrites.current.slice(-7), wanted];
    router.replace(`${pathname}${wanted ? `?${wanted}` : ""}`, { scroll: false });
  }, [addressRunRef, connection, pathname, router]);

  // Same-document navigation to a different address is re-resolved from /v1/me and the project
  // list like any other hint; the refs themselves grant nothing. `connect` takes a new generation,
  // so an overlapping navigation or account change drops this one.
  useEffect(() => {
    const echoed = pendingWrites.current.indexOf(searchQuery);
    if (echoed >= 0) { pendingWrites.current = pendingWrites.current.slice(echoed + 1); return; }
    if (searchQuery === appliedQuery.current) return;
    appliedQuery.current = searchQuery;
    resetProjectState();
    setNotice(null);
    void connect(selectionFromParams(new URLSearchParams(searchQuery)));
  }, [connect, resetProjectState, searchQuery]);

  // A follow-up refresh runs for the action that requested it: the caller passes the context and generation it
  // captured when the action began. Reading the live generation here would let an old context adopt a newer one.
  const refreshEnvironments = useCallback(async (context: Context, ticket: number): Promise<void> => {
    if (ticket !== generation.current) return;
    const environments = await canaryApi.listEnvironments(context.workspaceRef, context.project.projectRef);
    if (ticket !== generation.current) return;
    setConnection({ phase: "ready", context: { ...context, environments } });
  }, []);

  const refreshContextBindings = useCallback(async (context: Context, ticket: number): Promise<void> => {
    if (ticket !== generation.current) return;
    const contextBindings = await canaryApi.listRunnerContextBindings(context.workspaceRef, context.project.projectRef);
    if (ticket !== generation.current) return;
    setConnection({ phase: "ready", context: { ...context, contextBindings } });
    setNowSeconds(currentSeconds());
    setSelectedRunner((current) => contextBindings.runners.some((runner) => runner.runnerId === current) ? current : "");
  }, []);

  useEffect(() => {
    if (connection.phase !== "ready" || pendingApproval !== null || working) return;
    let cancelled = false;
    let inFlight = false;
    let controller: AbortController | null = null;
    const discover = async (): Promise<void> => {
      if (cancelled || inFlight || document.visibilityState !== "visible") return;
      inFlight = true;
      controller = new AbortController();
      try {
        const pending = await canaryApi.listPendingApprovalRequests(connection.context.workspaceRef, connection.context.project.projectRef, controller.signal);
        if (cancelled) return;
        setPendingHasMore(pending.hasMore);
        const request = pending.request;
        if (request === null) return;
        const status = await canaryApi.getRun(connection.context.workspaceRef, connection.context.project.projectRef, request.runId, controller.signal);
        if (cancelled) return;
        if (status.run.runId !== request.runId || status.run.approvalId !== request.approvalId || status.run.status !== "awaiting_execution_approval") {
          setObservedRun(status);
          clearPendingApproval();
          return;
        }
        const summary = request as CanaryPendingApprovalRequest;
        // A plan awaiting approval wins over a run ref from the address; that ref is dropped, not resumed later.
        setRunHint(null);
        setPendingApproval({
          requestKey: approvalRequestKey(connection.context.workspaceRef, connection.context.project.projectRef, summary),
          workspaceRef: connection.context.workspaceRef,
          projectRef: connection.context.project.projectRef,
          summary,
          run: status,
        });
        setObservedRun(status);
      } catch (error) {
        if (cancelled) return;
        if (isSessionLoss(error)) sessionEnded();
        else if (!(error instanceof CanaryApiError && error.code === "unavailable")) setNotice(messageOf(error));
      } finally { inFlight = false; controller = null; }
    };
    const visibility = () => { if (document.visibilityState === "visible") void discover(); };
    void discover();
    const timer = setInterval(() => void discover(), 2_000);
    document.addEventListener("visibilitychange", visibility);
    return () => { cancelled = true; controller?.abort(); clearInterval(timer); document.removeEventListener("visibilitychange", visibility); };
  }, [clearPendingApproval, connection, pendingApproval, sessionEnded, working]);

  useEffect(() => {
    if (connection.phase !== "ready" || pendingApproval === null) return;
    let cancelled = false;
    const timer = setInterval(() => {
      void canaryApi.getRun(connection.context.workspaceRef, connection.context.project.projectRef, pendingApproval.summary.runId)
        .then((next) => { if (!cancelled) {
          if (next.run.runId !== pendingApproval.summary.runId || next.run.approvalId !== pendingApproval.summary.approvalId
            || next.run.status !== "awaiting_execution_approval") {
            setObservedRun(next);
            clearPendingApproval();
            return;
          }
          setPendingApproval((current) => current?.requestKey === pendingApproval.requestKey
            ? { ...current, run: next } : current);
          setObservedRun(next);
        } })
        .catch((error: unknown) => { if (!cancelled) {
          if (error instanceof CanaryApiError && (error.status === 401 || error.status === 403)) {
            if (error.status === 401) sessionEnded();
            else void connect(connectionSelection(connection));
          } else if (error instanceof CanaryApiError && error.status === 404) clearPendingApproval();
          else setNotice(messageOf(error));
        } });
    }, 1_000);
    return () => { cancelled = true; clearInterval(timer); };
  }, [clearPendingApproval, connect, connection, pendingApproval, sessionEnded]);

  // An approved run leaves the pending list, so nothing above reads it again. Follow that run's own status until the
  // control plane reports it settled; the counters shown are only what its read model returns.
  const followedRunId = observedRun !== null && pendingApproval === null && !SETTLED_RUN_STATUSES.has(observedRun.run.status)
    ? observedRun.run.runId : null;
  useEffect(() => {
    if (connection.phase !== "ready" || followedRunId === null) return;
    const ticket = generation.current;
    let cancelled = false;
    let inFlight = false;
    let controller: AbortController | null = null;
    const follow = async (): Promise<void> => {
      if (cancelled || inFlight || document.visibilityState !== "visible") return;
      inFlight = true;
      controller = new AbortController();
      try {
        const next = await canaryApi.getRun(connection.context.workspaceRef, connection.context.project.projectRef, followedRunId, controller.signal);
        if (cancelled || ticket !== generation.current) return;
        setObservedRun((current) => current?.run.runId === followedRunId ? next : current);
      } catch (error) {
        if (cancelled || ticket !== generation.current) return;
        if (isSessionLoss(error)) sessionEnded();
        else if (error instanceof CanaryApiError && error.status === 403) void connect(connectionSelection(connection));
        else if (error instanceof CanaryApiError && error.status === 404) setObservedRun((current) => current?.run.runId === followedRunId ? null : current);
        else if (!(error instanceof CanaryApiError && error.code === "unavailable")) setNotice(messageOf(error));
      } finally { inFlight = false; controller = null; }
    };
    const visibility = () => { if (document.visibilityState === "visible") void follow(); };
    const timer = setInterval(() => void follow(), 1_000);
    document.addEventListener("visibilitychange", visibility);
    return () => { cancelled = true; controller?.abort(); clearInterval(timer); document.removeEventListener("visibilitychange", visibility); };
  }, [connect, connection, followedRunId, sessionEnded]);

  // A run ref from the address is shown only after the tenant-scoped run read, under the server-confirmed context,
  // returns that exact run past approval. 401 ends the session; 403 or 404 drops the ref and shows nothing; an outage
  // or malformed response keeps it and retries without inventing a status.
  useEffect(() => {
    if (connection.phase !== "ready" || hintedRunRef === null) return;
    const ticket = generation.current;
    const { workspaceRef } = connection.context;
    const { projectRef } = connection.context.project;
    let cancelled = false;
    let inFlight = false;
    let controller: AbortController | null = null;
    const restore = async (): Promise<void> => {
      if (cancelled || inFlight || document.visibilityState !== "visible") return;
      inFlight = true;
      controller = new AbortController();
      try {
        const next = await canaryApi.getRun(workspaceRef, projectRef, hintedRunRef, controller.signal);
        if (cancelled || ticket !== generation.current) return;
        setRunHint(null);
        if (next.run.runId !== hintedRunRef || PRE_APPROVAL_STATUSES.has(next.run.status)) return;
        setObservedRun((current) => current ?? next);
      } catch (error) {
        if (cancelled || ticket !== generation.current) return;
        if (isSessionLoss(error)) sessionEnded();
        else if (error instanceof CanaryApiError && (error.status === 403 || error.status === 404)) setRunHint(null);
        else setRunHint((current) => current?.runRef === hintedRunRef ? { ...current, unavailable: true } : current);
      } finally { inFlight = false; controller = null; }
    };
    const visibility = () => { if (document.visibilityState === "visible") void restore(); };
    void restore();
    const timer = setInterval(() => void restore(), 2_000);
    document.addEventListener("visibilitychange", visibility);
    return () => { cancelled = true; controller?.abort(); clearInterval(timer); document.removeEventListener("visibilitychange", visibility); };
  }, [connection, hintedRunRef, sessionEnded]);

  // Once the shown run is terminal with a local result, read its disclosure status (metadata only) until it settles.
  // A synchronized status is followed by the strict findings read; nothing is shown that these two reads did not return.
  const disclosureRunId = readyContext !== null && pendingApproval === null && observedRun !== null
    && observedRun.run.status === "terminal" && observedRun.progress.localResultReady ? observedRun.run.runId : null;
  const disclosureForRun = disclosure !== null && readyContext !== null && disclosure.runId === disclosureRunId
    && disclosure.workspaceRef === readyContext.workspaceRef && disclosure.projectRef === readyContext.project.projectRef
    ? disclosure : null;
  const disclosureState = disclosureForRun?.read.kind === "state" ? disclosureForRun.read.state : null;
  const disclosureSettled = disclosureState !== null && (SETTLED_DISCLOSURE_STATUSES.has(disclosureState.status)
    || (disclosureState.status === "synchronized" && disclosureForRun?.findings !== null));
  useEffect(() => {
    if (connection.phase !== "ready" || disclosureRunId === null || disclosureSettled) return;
    const ticket = generation.current;
    const { workspaceRef } = connection.context;
    const { projectRef } = connection.context.project;
    const runId = disclosureRunId;
    let cancelled = false;
    let inFlight = false;
    let controller: AbortController | null = null;
    const apply = (read: DisclosureView["read"], findings: Readonly<CanaryFindingsProjection> | null, findingsUnavailable: boolean): void => {
      // A review left open when the server's status moves on (decided elsewhere, shared, expired, unreadable) is
      // closed, so it never reappears by itself if the choice is offered again later.
      if (read.kind !== "state" || !(read.state.status === "local_result_ready" || read.state.status === "awaiting_disclosure_approval")) {
        setDisclosureOpen(false);
      }
      setDisclosure((current) => {
        const same = current !== null && current.runId === runId && current.workspaceRef === workspaceRef && current.projectRef === projectRef;
        return { workspaceRef, projectRef, runId, read, findings: findings ?? (same ? current.findings : null), findingsUnavailable };
      });
    };
    const poll = async (): Promise<void> => {
      if (cancelled || inFlight || document.visibilityState !== "visible") return;
      inFlight = true;
      controller = new AbortController();
      const { signal } = controller;
      try {
        const state = await canaryApi.getDisclosure(workspaceRef, projectRef, runId, signal);
        if (cancelled || ticket !== generation.current) return;
        let findings: Readonly<CanaryFindingsProjection> | null = null;
        let findingsUnavailable = false;
        if (state.status === "synchronized") {
          try {
            findings = await canaryApi.getFindings(workspaceRef, projectRef, runId, signal);
          } catch (error) {
            if (cancelled || ticket !== generation.current) return;
            if (isSessionLoss(error)) { sessionEnded(); return; }
            findingsUnavailable = true;
          }
          if (cancelled || ticket !== generation.current) return;
        }
        apply({ kind: "state", state }, findings, findingsUnavailable);
      } catch (error) {
        if (cancelled || ticket !== generation.current) return;
        if (isSessionLoss(error)) sessionEnded();
        else if (error instanceof CanaryApiError && error.status === 403) void connect(connectionSelection(connection));
        else if (error instanceof CanaryApiError && error.status === 404) apply({ kind: "waiting" }, null, false);
        else apply({ kind: "unavailable" }, null, false);
      } finally { inFlight = false; controller = null; }
    };
    const visibility = () => { if (document.visibilityState === "visible") void poll(); };
    void poll();
    const timer = setInterval(() => void poll(), 2_000);
    document.addEventListener("visibilitychange", visibility);
    return () => { cancelled = true; controller?.abort(); clearInterval(timer); document.removeEventListener("visibilitychange", visibility); };
  }, [connect, connection, disclosureRunId, disclosureSettled, disclosureTick, sessionEnded]);

  // Expiry is re-evaluated while a pairing ceremony is open; the server still decides.
  useEffect(() => {
    if (pairingSession === null) return;
    const timer = setInterval(() => setNowSeconds(currentSeconds()), 5_000);
    return () => clearInterval(timer);
  }, [pairingSession]);

  const executable = connection.phase === "ready"
    ? connection.context.environments.find((item) => item.isExecutable) : undefined;
  const pendingRecords = connection.phase === "ready"
    ? connection.context.environments.filter((item) => item.status === "pending" && item.environmentClass !== "production") : [];
  // Only the user's explicit choice, or the single pending record, is ever acted on.
  const chosenPending = pendingRecords.find((item) => item.environmentId === selectedPendingId)
    ?? (pendingRecords.length === 1 ? pendingRecords[0] : undefined);
  const pendingTargets: PendingTarget[] = pendingRecords.map((item) => ({ environmentId: item.environmentId, origin: item.origin, proofMethod: item.proofMethod }));
  const selectedRunnerAvailable = connection.phase === "ready"
    && connection.context.contextBindings.runners.some((runner) => runner.runnerId === selectedRunner);
  const approvalKey = connection.phase === "ready" && pendingApproval !== null
    ? pendingApproval.requestKey : null;
  const approvalDialogOpen = approvalKey !== null && approvalDialog?.requestKey === approvalKey && approvalDialog.open;
  const hasPlan = pendingApproval !== null && pendingApproval.run.run.status === "awaiting_execution_approval";
  // Progress comes from the server's active records for this project: a runner is paired while its key is active (the
  // bindable list omits a bound runner, so `pairedRunnersOf` adds it back), and it is authorized only by an active,
  // unexpired binding for this exact verified environment and proof. Liveness and local credentials are not visible.
  const pairedRunners = connection.phase === "ready" ? pairedRunnersOf(connection.context.contextBindings, nowSeconds * 1000) : [];
  const authorizedForTarget = connection.phase === "ready" && executable !== undefined
    && connection.context.contextBindings.bindings.some((item) => item.status === "active" && item.expiresAtMs > nowSeconds * 1000
      && item.environmentId === executable.environmentId && item.verificationRecordDigest === executable.verificationRecordDigest);
  // A run the control plane holds past approval proves its runner submitted a signed plan with canary access ready;
  // only a terminal, completed run counts as a finished rehearsal.
  const executedStatus = observedRun !== null && pendingApproval === null && !["prepared", "awaiting_execution_approval"].includes(observedRun.run.status)
    ? observedRun.run.status : null;
  const rehearsalComplete = executedStatus === "terminal" && observedRun?.run.executionDisposition === "completed";
  const rehearsalRunning = executedStatus !== null && !SETTLED_RUN_STATUSES.has(executedStatus);
  const snapshot: ActivationSnapshot = {
    environment: executable ? "verified" : proofChallenge ? "checking" : "unverified",
    runner: executable ? (hasPlan ? "online" : pairedRunners.length > 0 ? "paired" : "unpaired") : "locked",
    canaryAccess: hasPlan || rehearsalComplete || rehearsalRunning ? "ready" : !executable || pairedRunners.length === 0 ? "locked" : authorizedForTarget ? "authorized" : "unauthorized",
    rehearsal: hasPlan ? "awaiting_approval" : rehearsalComplete ? "complete" : rehearsalRunning ? "running" : "locked",
  };
  const completedSteps = [snapshot.environment === "verified", snapshot.runner === "paired" || snapshot.runner === "online",
    snapshot.canaryAccess === "ready", hasPlan || rehearsalComplete].filter(Boolean).length;

  const runPhase: RunPhase | null = useMemo(() => {
    if (observedRun === null) return null;
    if (observedRun.run.status === "terminal") return observedRun.run.executionDisposition === "stopped" ? "stopped" : "complete";
    if (observedRun.run.status === "stop_requested" || observedRun.run.status === "finalizing") return "stopping";
    if (["cancelled", "expired"].includes(observedRun.run.status)) return "error";
    return "running";
  }, [observedRun]);

  async function selectProject(projectRef: string): Promise<void> {
    const projects = connection.phase === "ready" ? connection.context.projects
      : connection.phase === "canary_unavailable" ? connection.projects : [];
    const project = projects.find((item) => item.projectRef === projectRef);
    const workspaceRef = connectionSelection(connection).workspaceRef;
    if (project === undefined || workspaceRef === undefined) return;
    resetProjectState();
    setNotice(null);
    // Re-resolve from /v1/me so the switch is bound to the current server identity and role.
    await connect({ workspaceRef, projectRef: project.projectRef });
  }

  async function selectWorkspace(workspaceRef: string): Promise<void> {
    if (connection.phase !== "ready" && connection.phase !== "canary_unavailable"
      && connection.phase !== "select_project" && connection.phase !== "forbidden") return;
    resetProjectState();
    setNotice(null);
    await connect({ workspaceRef });
  }

  async function createProject(name: string): Promise<void> {
    const workspaceRef = connectionSelection(connection).workspaceRef;
    if (workspaceRef === undefined) return;
    const ticket = generation.current;
    let project: HeelCloudProject;
    try {
      project = await cloudApi.createProject(workspaceRef, name);
    } catch (error) {
      // A failure that settles after sign-out, account switch or navigation belongs to that older
      // session; it must not end or annotate the current one.
      if (ticket !== generation.current) return;
      if (isSessionLoss(error)) { sessionEnded(); return; }
      throw error;
    }
    if (ticket !== generation.current) return;
    resetProjectState();
    const next = await connect({ workspaceRef, projectRef: project.projectRef });
    if (next?.phase === "ready") setNotice(PROJECT_CREATED_READY);
    else if (next?.phase === "canary_unavailable") setNotice(PROJECT_CREATED_BLOCKED);
  }

  /** Retries the canary reads and brings the outage notice in line with what actually loaded. */
  async function retryCanarySetup(): Promise<void> {
    if (connection.phase !== "canary_unavailable") return;
    const next = await connect(connectionSelection(connection));
    if (next === null || next.phase === "canary_unavailable") return;
    setNotice((current) => {
      if (next.phase !== "ready") return null;
      if (current !== PROJECT_CREATED_BLOCKED) return current;
      return next.context.environments.some((item) => item.isExecutable) ? null : PROJECT_CREATED_READY;
    });
  }

  async function signOut(reauthReason: ReauthReason | null = null): Promise<void> {
    const previous = connectionSelection(connection);
    const reauth = reauthReason !== null;
    // Only opaque refs survive, and only in page memory: the shown run ref is re-authorized after the next sign-in.
    reauthSelection.current = reauth ? { ...previous, ...(addressRunRef === null ? {} : { runRef: addressRunRef }) } : null;
    const reauthMessage = reauthReason === "disclosure" ? DISCLOSURE_REAUTH_SIGN_IN_MESSAGE : RUN_REAUTH_SIGN_IN_MESSAGE;
    const ticket = ++generation.current;
    clearApprovalIdentity();
    resetProjectState();
    setNotice(null);
    const operation = beginWork();
    setConnection({ phase: "checking" });
    try {
      await cloudApi.logout();
      if (ticket === generation.current) setConnection({ phase: "sign_in", message: reauth ? reauthMessage : SIGNED_OUT_MESSAGE });
    } catch (error) {
      if (ticket !== generation.current) return;
      if (isSessionLoss(error)) setConnection({ phase: "sign_in", message: reauth ? reauthMessage : SIGNED_OUT_MESSAGE });
      else {
        reauthSelection.current = null;
        if (await connect(previous) !== null) setNotice("Heel Cloud could not confirm sign-out, so you are still signed in. Try again.");
      }
    } finally { endWork(operation); }
  }

  async function createContextBinding(): Promise<void> {
    if (connection.phase !== "ready") return;
    const { context } = connection;
    const environment = context.environments.find((item) => item.environmentId === selectedBindingEnvironment);
    const runner = context.contextBindings.runners.find((item) => item.runnerId === selectedRunner);
    if (!environment?.isExecutable || environment.verificationRecordDigest === null || runner === undefined) return;
    const ticket = generation.current;
    const operation = beginWork(); setNotice(null);
    try {
      await canaryApi.createRunnerContextBinding(context.workspaceRef, context.project.projectRef, {
        environmentId: environment.environmentId, verificationRecordDigest: environment.verificationRecordDigest,
        runnerId: runner.runnerId, runnerKeyId: runner.runnerKeyId,
      });
      await refreshContextBindings(context, ticket);
      if (ticket !== generation.current) return;
      setNotice("Canary access was authorized for this exact paired runner and verified environment.");
    } catch (error) { recover(error, ticket); } finally { endWork(operation); }
  }

  async function revokeContextBinding(bindingId: string): Promise<void> {
    if (connection.phase !== "ready") return;
    const { context } = connection;
    const ticket = generation.current;
    const operation = beginWork(); setNotice(null);
    try {
      await canaryApi.revokeRunnerContextBinding(context.workspaceRef, context.project.projectRef, bindingId);
      await refreshContextBindings(context, ticket);
      if (ticket !== generation.current) return;
      setNotice("Canary access was revoked. Issued grants and active work were not changed.");
    } catch (error) { recover(error, ticket); } finally { endWork(operation); }
  }

  /** Handles a pairing or runner-revoke failure for the context that started it. */
  function recoverPairing(error: unknown, ticket: number): void {
    if (ticket !== generation.current) return;
    if (error instanceof CanaryApiError && error.code === "recent_auth_required") setNotice(PAIRING_RECENT_AUTH_MESSAGE);
    else if (error instanceof CanaryApiError && (error.code === "runner_pairing_not_found" || error.code === "invalid_runner_pairing")) {
      setPairingSession((current) => current === null ? null : { ...current, pairing: null, approved: false });
      setNotice(PAIRING_GONE_MESSAGE);
    } else recover(error, ticket);
  }

  async function createPairingInvitation(): Promise<void> {
    if (connection.phase !== "ready") return;
    const { context } = connection;
    const ticket = generation.current;
    const operation = beginWork(); setNotice(null);
    try {
      const invitation = await canaryApi.createRunnerPairingInvitation(context.workspaceRef);
      if (ticket !== generation.current) return;
      setNowSeconds(currentSeconds());
      setPairingSession({ workspaceRef: context.workspaceRef, projectRef: context.project.projectRef,
        invitation: { token: invitation.invitationToken, expiresAt: invitation.expiresAt }, pairing: null, approved: false });
    } catch (error) { recoverPairing(error, ticket); } finally { endWork(operation); }
  }

  async function inspectPairing(pairingId: string): Promise<void> {
    if (connection.phase !== "ready") return;
    const { context } = connection;
    const ticket = generation.current;
    const operation = beginWork(); setNotice(null);
    try {
      const pairing = await canaryApi.inspectRunnerPairing(context.workspaceRef, pairingId);
      if (ticket !== generation.current) return;
      // The invitation was consumed by the runner's exchange; its token is not shown again.
      setNowSeconds(currentSeconds());
      setPairingSession({ workspaceRef: context.workspaceRef, projectRef: context.project.projectRef, invitation: null, pairing, approved: false });
    } catch (error) { recoverPairing(error, ticket); } finally { endWork(operation); }
  }

  async function approvePairing(typedPhrase: string): Promise<void> {
    const session = pairingSession;
    if (connection.phase !== "ready" || session === null || session.pairing === null || session.approved
      || session.workspaceRef !== connection.context.workspaceRef || session.projectRef !== connection.context.project.projectRef) return;
    const { pairing } = session;
    // Only the person's own match of the server's words, before the request's expiry, ever sends an approval.
    if (!pairingPhraseMatches(typedPhrase, pairing.pairingPhrase) || currentSeconds() >= pairing.expiresAt) return;
    const { context } = connection;
    const ticket = generation.current;
    const operation = beginWork(); setNotice(null);
    try {
      await canaryApi.approveRunnerPairing(session.workspaceRef, pairing.pairingId, pairing.pairingPhrase, pairing.fingerprint);
      if (ticket !== generation.current) return;
      setPairingSession((current) => current?.pairing?.pairingId === pairing.pairingId ? { ...current, approved: true } : current);
      await refreshContextBindings(context, ticket);
    } catch (error) { recoverPairing(error, ticket); } finally { endWork(operation); }
  }

  async function refreshPairedRunners(): Promise<void> {
    if (connection.phase !== "ready") return;
    const ticket = generation.current;
    const operation = beginWork(); setNotice(null);
    try {
      await refreshContextBindings(connection.context, ticket);
    } catch (error) { recover(error, ticket); } finally { endWork(operation); }
  }

  async function revokeRunner(runnerId: string): Promise<void> {
    if (connection.phase !== "ready" || revokeCandidate !== runnerId) return;
    const { context } = connection;
    if (!pairedRunnersOf(context.contextBindings, nowSeconds * 1000).some((item) => item.runnerId === runnerId)) return;
    const ticket = generation.current;
    setRevokeCandidate(null);
    const operation = beginWork(); setNotice(null);
    try {
      await canaryApi.revokeRunner(context.workspaceRef, runnerId);
      if (ticket !== generation.current) return;
      setPairingSession(null);
      await refreshContextBindings(context, ticket);
      if (ticket !== generation.current) return;
      setNotice("Runner revoked. Heel Cloud no longer accepts its keys and requests a stop of its active rehearsals; run heel runner unpair on that machine to remove its local identity.");
    } catch (error) { recoverPairing(error, ticket); } finally { endWork(operation); }
  }

  async function startProof(): Promise<void> {
    if (connection.phase !== "ready") return;
    const ticket = generation.current;
    const operation = beginWork(); setNotice(null);
    try {
      const value = await canaryApi.startEnvironmentProof(connection.context.workspaceRef, connection.context.project.projectRef, {
        origin: origin.trim(), environmentClass: "staging", proofMethod,
        attestationText: OWNERSHIP_ATTESTATION, attestationVersion: "v1", attestationAcknowledgement: "accepted",
      });
      if (ticket !== generation.current) return;
      setReplacementPendingId(null);
      setProofChallenge({
        environmentId: value.environment_id as string,
        instruction: proofInstruction(proofMethod, value.http_url as string, value.token as string, value.dns_record as string),
      });
    } catch (error) { recover(error, ticket); } finally { endWork(operation); }
  }

  /**
   * Shows a listed pending record's proof again (resume) or replaces it in the same record (replace). Neither
   * registers a target or checks the proof; the instruction is kept only in this page's memory.
   */
  async function pendingProofAction(replace: boolean): Promise<void> {
    if (connection.phase !== "ready" || chosenPending === undefined) return;
    const { context } = connection;
    const record = chosenPending;
    const ticket = generation.current;
    const operation = beginWork(); setNotice(null);
    try {
      const proof: PendingEnvironmentProof = replace
        ? await canaryApi.rotateEnvironmentProof(context.workspaceRef, context.project.projectRef, record)
        : await canaryApi.recoverEnvironmentProof(context.workspaceRef, context.project.projectRef, record);
      if (ticket !== generation.current) return;
      setReplacementPendingId(null);
      setProofChallenge({ environmentId: proof.environmentId, instruction: proofInstruction(proof.proofMethod, proof.httpUrl, proof.token, proof.dnsRecord) });
    } catch (error) {
      if (ticket !== generation.current) return;
      if (error instanceof CanaryApiError && (error.code === "environment_challenge_expired" || error.code === "environment_challenge_missing")) {
        setReplacementPendingId(record.environmentId);
        setNotice(error.message);
      } else if (error instanceof CanaryApiError && error.code === "recent_auth_required") {
        setNotice(PROOF_RECENT_AUTH_MESSAGE);
      } else if (error instanceof CanaryApiError && ["environment_challenge_closed", "environment_challenge_live", "invalid_response"].includes(error.code)) {
        // The listed record is out of date (verified, revoked or replaced elsewhere): show its current state.
        setReplacementPendingId(null);
        setNotice(error.message);
        try { await refreshEnvironments(context, ticket); } catch (refreshError) { recover(refreshError, ticket); }
      } else recover(error, ticket);
    } finally { endWork(operation); }
  }

  async function checkProof(): Promise<void> {
    if (connection.phase !== "ready" || proofChallenge === null) return;
    const { context } = connection;
    const ticket = generation.current;
    const operation = beginWork(); setNotice(null);
    try {
      const verified = await canaryApi.checkEnvironmentProof(context.workspaceRef, context.project.projectRef, proofChallenge.environmentId);
      if (ticket !== generation.current) return;
      setNotice(verified ? "Target ownership verified. No product route was contacted." : "Proof did not match yet. No product route was contacted.");
      await refreshEnvironments(context, ticket);
      if (ticket !== generation.current) return;
      if (verified) setProofChallenge(null);
    } catch (error) { recover(error, ticket); } finally { endWork(operation); }
  }

  async function approveRun(requestKey: string, reason: string): Promise<void> {
    const pending = pendingApproval;
    if (connection.phase !== "ready" || pending === null
      || pending.requestKey !== requestKey
      || pending.workspaceRef !== connection.context.workspaceRef
      || pending.projectRef !== connection.context.project.projectRef
      || pending.run.run.status !== "awaiting_execution_approval") return;
    clearPendingApproval();
    const ticket = generation.current;
    const operation = beginWork(); setNotice(null);
    try {
      await canaryApi.approveRun(pending.workspaceRef, pending.projectRef, pending.summary.runId, {
        projectionDigest: pending.summary.projectionDigest, hostnameRetype: pending.summary.hostname, reason,
        idempotencyKey: idempotencyKey(), controlGeneration: pending.run.approvalControlGeneration,
      });
      const run = await canaryApi.getRun(pending.workspaceRef, pending.projectRef, pending.summary.runId);
      if (ticket === generation.current) setObservedRun(run);
    } catch (error) {
      if (ticket !== generation.current) return;
      if (error instanceof CanaryApiError && error.status === 403 && error.code === "recent_auth_required") {
        // The session is still valid but too old for this ceremony. Nothing was approved; the plan stays pending on the
        // server and is rediscovered with the dialog closed, so approving always takes a fresh review.
        setNotice(RUN_RECENT_AUTH_MESSAGE);
      } else if (error instanceof CanaryApiError && (error.status === 401 || error.status === 403)) {
        if (error.status === 401) sessionEnded();
        else void connect({ workspaceRef: pending.workspaceRef, projectRef: pending.projectRef });
      } else setNotice(messageOf(error));
    } finally { endWork(operation); }
  }

  async function stopRun(): Promise<void> {
    if (connection.phase !== "ready" || observedRun === null) return;
    const ticket = generation.current;
    const operation = beginWork(); setNotice(null);
    try {
      await canaryApi.stopRun(connection.context.workspaceRef, connection.context.project.projectRef, observedRun.run.runId, observedRun.run.killSwitchGeneration);
      const run = await canaryApi.getRun(connection.context.workspaceRef, connection.context.project.projectRef, observedRun.run.runId);
      if (ticket === generation.current) setObservedRun(run);
    } catch (error) { recover(error, ticket); } finally { endWork(operation); }
  }

  /** Share or keep local exactly the summary the paired runner registered; only an explicit click calls this. */
  async function decideDisclosure(share: boolean): Promise<void> {
    if (connection.phase !== "ready" || disclosureForRun === null || disclosureState === null
      || !(disclosureState.status === "local_result_ready" || disclosureState.status === "awaiting_disclosure_approval")) return;
    const { workspaceRef, projectRef, runId } = disclosureForRun;
    const metadata = disclosureState.projection;
    const ticket = generation.current;
    const operation = beginWork(); setNotice(null);
    try {
      if (share) await canaryApi.createDisclosurePermit(workspaceRef, projectRef, runId, metadata);
      else await canaryApi.markDisclosureLocalOnly(workspaceRef, projectRef, runId, metadata);
      if (ticket !== generation.current) return;
      setDisclosureOpen(false);
    } catch (error) {
      if (ticket !== generation.current) return;
      if (error instanceof CanaryApiError && error.code === "recent_auth_required") {
        setDisclosureOpen(false);
        setNotice(DISCLOSURE_RECENT_AUTH_MESSAGE);
      } else if (error instanceof CanaryApiError && ["permit_consumed", "canary_state_conflict", "disclosure_permit_expired", "invalid_canary_projection"].includes(error.code)) {
        // The server's state moved on (shared or decided elsewhere, or the summary changed): show its current status.
        setDisclosureOpen(false);
        setNotice(error.message);
      } else recover(error, ticket);
    } finally {
      endWork(operation);
      if (ticket === generation.current) setDisclosureTick((value) => value + 1);
    }
  }

  const context = connection.phase === "ready" ? connection.context : null;
  const accountView = context?.account
    ?? (connection.phase === "select_project" || connection.phase === "forbidden" || connection.phase === "canary_unavailable"
      ? connection.account : null);
  const selectedProject = context?.project ?? (connection.phase === "canary_unavailable" ? connection.project : null);
  // A paired runner or binding the account already has keeps the private-connector tools; a customer without one,
  // and any visitor whose account is still loading, signed out or unresolved, is never sent to runner pairing.
  const privateConnectorInUse = context !== null
    && (context.contextBindings.runners.length > 0 || context.contextBindings.bindings.length > 0);
  const showActivation = context !== null && (privateConnectorInUse || pendingApproval !== null || observedRun !== null);
  // Pairing is offered only after the project's target is verified, only to a workspace owner or admin (the server
  // also requires a recent sign-in), and only while the workspace has no active runner.
  const canPairRunner = context !== null && executable !== undefined && pendingApproval === null
    && pairedRunners.length === 0
    && (context.account.workspace.role === "owner" || context.account.workspace.role === "admin");
  const pairingForContext = context !== null && pairingSession !== null && pairingSession.workspaceRef === context.workspaceRef
    && pairingSession.projectRef === context.project.projectRef ? pairingSession : null;
  const progress = observedRun?.progress;
  const disclosureDecisionOpen = disclosureState !== null
    && (disclosureState.status === "local_result_ready" || disclosureState.status === "awaiting_disclosure_approval");
  const disclosureStatusCopy: string = disclosureForRun === null
    ? "Checking whether the paired runner reported the local result."
    : disclosureForRun.read.kind === "waiting"
      ? "Waiting for the paired runner to report the local result. Keep heel runner serve running on the runner machine; while it is offline the result stays there and nothing is shared."
      : disclosureForRun.read.kind === "unavailable" || disclosureState === null
        ? "Heel Cloud returned no readable sharing status for this result, so none is shown. Retrying; the local result is unchanged."
        : disclosureDecisionOpen
          ? `The paired runner reported a redacted summary: ${disclosureState.projection.scenarioCount} ${disclosureState.projection.scenarioCount === 1 ? "scenario" : "scenarios"}, ${disclosureState.projection.findingCount} ${disclosureState.projection.findingCount === 1 ? "finding" : "findings"}. Nothing has been shared. Share it or keep it local.`
          : disclosureState.status === "permitted"
            ? "Share approved. The paired runner uploads this exact summary when it next checks for approval, normally within a minute while heel runner serve is running."
            : disclosureState.status === "local_only"
              ? "Result kept local. No summary bytes were uploaded."
              : disclosureState.status === "expired"
                ? "The sharing window for this result has closed. It stays on the runner machine; nothing was uploaded."
                : disclosureForRun.findings !== null
                  ? "Redacted summary shared with this workspace."
                  : disclosureForRun.findingsUnavailable
                    ? "The summary was shared, but Heel Cloud could not return it right now, so none is shown. Retrying."
                    : "Loading the shared summary.";

  return (
    <main className="canary-dashboard">
      <header className="dashboard-nav"><Link className="brand" href="/" aria-label="Heel home"><span className="brand-mark" aria-hidden="true">H</span><span>Heel</span></Link>
        <div className="dashboard-context"><span className="dashboard-workspace">{selectedProject ? selectedProject.name : "Workspace not connected"}</span><span className="dashboard-presence"><i aria-hidden="true" /> {context ? "Cloud connected" : "Local-first"}</span></div></header>

      <p className="runner-recovery">Supported validation: <Link href="/runner">export entitlement reference and local report viewer</Link>.</p>
      <section className="dashboard-intro" aria-labelledby="dashboard-title"><div><p className="canary-kicker">Verified target setup</p><h1 id="dashboard-title">Cross the boundary <em>before</em> your customers do.</h1><p>Add one publicly reachable staging or sandbox HTTPS target and prove you own it. Heel Cloud only checks that ownership proof: approved read-only GET and HEAD rehearsals run from a runner on your own machine, and credentials and raw evidence stay there.</p></div>
        <aside className="preview-notice" aria-label="Connection status"><span className="preview-pulse" aria-hidden="true" /><div><strong>{connection.phase === "ready" ? "Ready for customer setup" : "Connect to begin"}</strong><p>{connection.phase === "checking" ? "Checking signed-in context · no request sent" : connection.phase === "ready" ? "Live account state · operational metadata only" : "No sample data is shown"}</p></div></aside></section>

      {connection.phase !== "ready" ? <section className="next-action" role="status"><span aria-hidden="true">↳</span><p><strong>{STATUS_TITLES[connection.phase]}</strong> {"message" in connection ? connection.message
        : connection.phase === "select_project" ? (canCreateProject(connection.account.workspace.role)
          ? "Name your first project below. Nothing has been approved or executed."
          : "No projects exist yet. A workspace owner, admin or member must create one.")
          : "Nothing has been approved or executed."}
        {connection.phase === "error" ? <> <button className="text-button" onClick={() => void connect(selectionFromParams(searchParams))} type="button">Try again</button></> : null}
        {connection.phase === "canary_unavailable" ? <> <button className="text-button" disabled={working} onClick={() => void retryCanarySetup()} type="button">Try again</button></> : null}
        {connection.phase === "no_workspace" || connection.phase === "error" ? <> <button className="text-button" disabled={working} onClick={() => void signOut()} type="button">Sign out</button></> : null}</p></section> : null}

      {connection.phase === "sign_in" ? <AccountAccess api={cloudApi} onAuthenticated={async () => {
        const resume = reauthSelection.current ?? {};
        reauthSelection.current = null;
        await connect(resume);
      }} /> : null}
      {accountView ? <WorkspaceProjectBar account={accountView} disabled={working} onCreateProject={createProject}
        onSelectProject={(projectRef) => void selectProject(projectRef)} onSelectWorkspace={(workspaceRef) => void selectWorkspace(workspaceRef)}
        onSignOut={() => void signOut()} projectRef={selectedProject?.projectRef ?? null}
        projects={context?.projects ?? (connection.phase === "canary_unavailable" ? connection.projects : [])} /> : null}
      {notice ? <p className="next-action" role="status">{notice}{notice === RUN_RECENT_AUTH_MESSAGE || notice === DISCLOSURE_RECENT_AUTH_MESSAGE ? <> <button className="text-button" disabled={working} onClick={() => void signOut(notice === DISCLOSURE_RECENT_AUTH_MESSAGE ? "disclosure" : "run")} type="button">Sign in again</button></> : null}</p> : null}
      {pendingHasMore ? <p className="next-action" role="status">Another pending approval is waiting after this one.</p> : null}

      <div className="dashboard-grid"><div>
        {context ? <TargetRegistrationCard busy={working} privateConnector={privateConnectorInUse} instruction={proofChallenge?.instruction ?? null}
          onCheckProof={() => void checkProof()} onCreateProof={() => void startProof()} onOriginChange={setOrigin}
          onProofMethodChange={setProofMethod} origin={origin} proofMethod={proofMethod} verifiedOrigin={executable?.origin ?? null}
          pendingTargets={pendingTargets} selectedPendingId={chosenPending?.environmentId ?? null} replacementPendingId={replacementPendingId}
          onSelectPendingTarget={(environmentId) => { setSelectedPendingId(environmentId || null); setNotice(null); }}
          onResumeProof={() => void pendingProofAction(false)} onReplaceProof={() => void pendingProofAction(true)} /> : null}
        {canPairRunner && context ? <RunnerPairingCard key={`${context.workspaceRef}/${context.project.projectRef}`}
          approved={pairingForContext?.approved ?? false} busy={working}
          invitation={pairingForContext?.invitation ?? null} nowSeconds={nowSeconds} onApprove={(typed) => void approvePairing(typed)}
          onCreateInvitation={() => void createPairingInvitation()} onInspect={(pairingId) => void inspectPairing(pairingId)}
          onRefreshRunners={() => void refreshPairedRunners()} pairing={pairingForContext?.pairing ?? null} /> : null}
        {showActivation ? <ActivationCard completedSteps={completedSteps} environmentOrigin={executable?.origin}
          onReviewApproval={hasPlan && approvalKey ? () => setApprovalDialog({ requestKey: approvalKey, open: true }) : undefined}
          scenarioCount={pendingApproval?.summary.scenarios.length ?? 0} snapshot={snapshot} /> : null}
        {disclosureState?.status === "synchronized" && disclosureForRun?.findings ? <FindingsCard findings={disclosureForRun.findings} /> : null}
        {context && executable && !pendingApproval && privateConnectorInUse ? <section className="runner-recovery"><p className="canary-kicker">Paired runner authorization</p><h2>Add canary access</h2><p>Authorize one active paired runner for one verified staging or sandbox environment. The runner alone may submit its signed plan; this dashboard never accepts projection file uploads.</p><p>This runner is fixed to its first claimed environment. To move it, stop and re-pair a fresh runner, then authorize access here.</p>
          <label>Verified environment<select disabled={working} onChange={(event) => setSelectedBindingEnvironment(event.target.value)} value={selectedBindingEnvironment}><option value="">Select environment</option>{context.environments.filter((item) => item.isExecutable && item.verificationRecordDigest !== null).map((item) => <option key={item.environmentId} value={item.environmentId}>{item.origin}</option>)}</select></label>
          <label>Paired runner<select disabled={working} onChange={(event) => setSelectedRunner(event.target.value)} value={selectedRunnerAvailable ? selectedRunner : ""}><option value="">Select runner</option>{context.contextBindings.runners.map((item) => <option key={`${item.runnerId}:${item.runnerKeyId}`} value={item.runnerId}>{item.displayName} · {item.fingerprint.slice(0, 12)}</option>)}</select></label>
          <button className="button button-primary" disabled={working || !selectedBindingEnvironment || !selectedRunnerAvailable} onClick={() => void createContextBinding()} type="button">Authorize paired runner</button>
          {context.contextBindings.runners.length === 0 && authorizedForTarget ? <p>Your paired runner is already authorized and listed below; a runner is offered here only while it has no active authorization.</p> : null}
          {context.contextBindings.bindings.length > 0 ? <ul className="context-binding-list">{context.contextBindings.bindings.map((item) => <li key={item.bindingId}><span>{item.origin} · {item.runnerId} · {item.status}</span>{item.status === "active" ? <button disabled={working} onClick={() => void revokeContextBinding(item.bindingId)} type="button">Revoke</button> : null}</li>)}</ul> : null}
        </section> : null}
        {context && !pendingApproval && pairedRunners.length > 0 ? <section className="runner-recovery" aria-labelledby="paired-runners-title"><p className="canary-kicker">Local runner</p><h2 id="paired-runners-title">Paired runners</h2>
          <p>Revoking a runner stops Heel Cloud accepting its keys right away, whether or not a target is verified.</p>
          <ul aria-label="Paired runners">{pairedRunners.map((item) => <li key={item.key}><span>{item.label}</span>
            {revokeCandidate === item.runnerId
              ? <><button disabled={working} onClick={() => void revokeRunner(item.runnerId)} type="button">Confirm revoke {item.name}</button><button disabled={working} onClick={() => setRevokeCandidate(null)} type="button">Keep runner</button></>
              : <button disabled={working} onClick={() => setRevokeCandidate(item.runnerId)} type="button">Revoke runner</button>}</li>)}</ul>
        </section> : null}
      </div>

      <aside className="dashboard-rail" aria-label="Safety boundaries"><section className="boundary-ledger"><p className="canary-kicker">Always enforced</p>
        {showActivation ? <><h2>The paired runner owns target traffic.</h2><dl><div><dt>Origin</dt><dd>{executable?.origin ?? "One verified host"}</dd></div><div><dt>Methods</dt><dd>GET + HEAD</dd></div><div><dt>Egress</dt><dd>Staging :443 only</dd></div><div><dt>Cloud view</dt><dd>Operational status; a redacted summary only if you share it</dd></div></dl></>
          : <><h2>Heel Cloud only verifies ownership; rehearsals run on your machine.</h2><dl><div><dt>Origin</dt><dd>{executable?.origin ?? "One verified host"}</dd></div><div><dt>Ownership check</dt><dd>One proof file or DNS record</dd></div><div><dt>Cloud view</dt><dd>Operational status only</dd></div></dl></>}</section>
         {runPhase && progress?.available ? <RunProgress phase={runPhase} completedScenarios={progress.scenariosCompleted ?? 0} totalScenarios={progress.scenariosTotal ?? 0} requestsUsed={progress.requestsStarted ?? 0} requestBudget={(progress.requestsStarted ?? 0) + (progress.remainingRequests ?? 0)} secondsRemaining={Math.ceil((progress.remainingWallMs ?? 0) / 1000)} onStop={runPhase === "running" ? () => void stopRun() : undefined} /> : null}
         {observedRun && !observedRun.progress.available ? <p className="run-recovery" role="alert">Signed progress is unavailable. The cloud will not invent metrics; inspect the local runner and retry status.</p> : null}
        {disclosureRunId !== null ? <section aria-label="Result sharing" aria-live="polite" className="disclosure-entry"><span>Result sharing</span>{disclosureStatusCopy}
          {disclosureDecisionOpen ? <> <button className="text-button" disabled={working} onClick={() => setDisclosureOpen(true)} type="button">Review sharing</button></> : null}</section> : null}
        {hintedRunRef !== null && runHint?.unavailable ? <p className="run-recovery" role="status">Heel Cloud could not read that rehearsal right now, so nothing is shown for it. Retrying.</p> : null}
      </aside></div>

      {pendingApproval && hasPlan && approvalKey ? <ApprovalDialog key={approvalKey} durationSeconds={pendingApproval.summary.durationSeconds} egress={pendingApproval.summary.egress} onApprove={(reason) => void approveRun(approvalKey, reason)} onClose={() => setApprovalDialog(null)} open={approvalDialogOpen} origin={pendingApproval.summary.origin} requestBudget={pendingApproval.summary.requestBudget} routes={pendingApproval.summary.routes} scenarios={pendingApproval.summary.scenarios} /> : null}
      {disclosureDecisionOpen && disclosureState ? <DisclosureDialog busy={working} byteCount={disclosureState.projection.projectionBytes} completedScenarios={disclosureState.projection.scenarioCount} findingCount={disclosureState.projection.findingCount} onClose={() => setDisclosureOpen(false)} onKeepLocal={() => void decideDisclosure(false)} onPermit={() => void decideDisclosure(true)} open={disclosureOpen} /> : null}
    </main>
  );
}
