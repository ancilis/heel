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
import { RunProgress, type RunPhase } from "../../components/canary/RunProgress";
import {
  CanaryApi, CanaryApiError, type CanaryApprovalSummary, type CanaryDisclosureMetadata, type CanaryPendingApprovalRequest,
  type CanaryRunDashboard, type RunnerContextBindingDashboard, type VerifiedEnvironmentRecord,
} from "../../lib/canary-api";
import {
  canCreateProject, resolveAccount, selectionFromParams, selectionQuery, type AccountSelection, type AccountWorkspaceView,
} from "../../lib/account-context";
import { HeelCloudApi, HeelCloudApiError, type HeelCloudProject } from "../../lib/heel-cloud-api";


const OWNERSHIP_ATTESTATION = "ownership verified; environment classification supplied by you";
const SIGN_IN_MESSAGE = "Create a free account or sign in to set up your first project.";
const SESSION_ENDED_MESSAGE = "Your session ended. Sign in again to continue; nothing from the previous session is shown.";
const SIGNED_OUT_MESSAGE = "You signed out. Sign in again to continue.";
const CANARY_LOCKED_MESSAGE = "You are still signed in. Staging verification, runner access and rehearsals stay locked until it loads; nothing has been approved or executed.";
const PROJECT_CREATED_READY = "Project created. Verify a staging origin next.";
const PROJECT_CREATED_BLOCKED = "Project created. Canary setup is unavailable right now, so staging verification is blocked; use Try again shortly.";
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
type DisclosurePreview = CanaryDisclosureMetadata & {
  completedScenarios: number;
  outcomeCounts: { blocked: number; observed: number; inconclusive: number };
};
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

function idempotencyKey(): `ca1-${string}` {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return `ca1-${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

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
  const [proofMethod, setProofMethod] = useState<"https-file" | "dns-txt">("https-file");
  const [proofChallenge, setProofChallenge] = useState<ProofChallenge | null>(null);
  const [pendingApproval, setPendingApproval] = useState<PendingApproval | null>(null);
  const [approvalDialog, setApprovalDialog] = useState<ApprovalDialogState>(null);
  const [observedRun, setObservedRun] = useState<CanaryRunDashboard | null>(null);
  const [disclosurePreview, setDisclosurePreview] = useState<DisclosurePreview | null>(null);
  const [disclosureOpen, setDisclosureOpen] = useState(false);
  const [selectedRunner, setSelectedRunner] = useState("");
  const [selectedBindingEnvironment, setSelectedBindingEnvironment] = useState("");
  const [pendingHasMore, setPendingHasMore] = useState(false);

  const clearPendingApproval = useCallback((): void => {
    setPendingApproval(null);
    setApprovalDialog(null);
    setPendingHasMore(false);
  }, []);

  const clearApprovalIdentity = useCallback((): void => {
    clearPendingApproval();
    setObservedRun(null);
    setDisclosurePreview(null);
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
    setProofChallenge(null);
    setOrigin("");
  }, []);

  useEffect(() => {
    const ticket = ++generation.current;
    void loadConnection(initialSelection).then((next) => {
      if (ticket !== generation.current) return;
      if (next.phase !== "ready") clearApprovalIdentity();
      setConnection(next);
    });
    return () => { generation.current += 1; };
  }, [clearApprovalIdentity, initialSelection]);

  /** Resolves to the applied connection, or null when a newer transition superseded this one. */
  const connect = useCallback(async (requested: AccountSelection): Promise<Connection | null> => {
    const ticket = ++generation.current;
    // Actions still pending belong to the previous context; they no longer block this one.
    setBusyOperation(null);
    clearApprovalIdentity();
    setConnection({ phase: "checking" });
    const next = await loadConnection(requested);
    if (ticket !== generation.current) return null;
    setConnection(next);
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

  // Declared before the sync below so it sees this render's address.
  useEffect(() => { latestQuery.current = searchQuery; }, [searchQuery]);

  // Keep the address bar on the server-confirmed selection (opaque refs only) so a reload
  // restores it; signed-out states carry no refs at all. This runs when the connection changes,
  // never merely because the address did.
  useEffect(() => {
    if (connection.phase === "checking" || connection.phase === "error") return;
    const wanted = selectionQuery(connectionSelection(connection)).slice(1);
    appliedQuery.current = wanted;
    if (wanted === latestQuery.current) return;
    pendingWrites.current = [...pendingWrites.current.slice(-7), wanted];
    router.replace(`${pathname}${wanted ? `?${wanted}` : ""}`, { scroll: false });
  }, [connection, pathname, router]);

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

  const refreshEnvironments = useCallback(async (): Promise<void> => {
    if (connection.phase !== "ready") return;
    const { context } = connection;
    const ticket = generation.current;
    const environments = await canaryApi.listEnvironments(context.workspaceRef, context.project.projectRef);
    if (ticket !== generation.current) return;
    setConnection({ phase: "ready", context: { ...context, environments } });
  }, [connection]);

  const refreshContextBindings = useCallback(async (): Promise<void> => {
    if (connection.phase !== "ready") return;
    const { context } = connection;
    const ticket = generation.current;
    const contextBindings = await canaryApi.listRunnerContextBindings(context.workspaceRef, context.project.projectRef);
    if (ticket !== generation.current) return;
    setConnection({ phase: "ready", context: { ...context, contextBindings } });
    setSelectedRunner((current) => contextBindings.runners.some((runner) => runner.runnerId === current) ? current : "");
  }, [connection]);

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

  const executable = connection.phase === "ready"
    ? connection.context.environments.find((item) => item.isExecutable) : undefined;
  const selectedRunnerAvailable = connection.phase === "ready"
    && connection.context.contextBindings.runners.some((runner) => runner.runnerId === selectedRunner);
  const approvalKey = connection.phase === "ready" && pendingApproval !== null
    ? pendingApproval.requestKey : null;
  const approvalDialogOpen = approvalKey !== null && approvalDialog?.requestKey === approvalKey && approvalDialog.open;
  const hasPlan = pendingApproval !== null && pendingApproval.run.run.status === "awaiting_execution_approval";
  const snapshot: ActivationSnapshot = {
    environment: executable ? "verified" : proofChallenge ? "checking" : "unverified",
    runner: executable ? (hasPlan ? "online" : "unpaired") : "locked",
    canaryAccess: hasPlan ? "ready" : executable ? "missing" : "locked",
    rehearsal: hasPlan ? "awaiting_approval" : "locked",
  };
  const completedSteps = [snapshot.environment === "verified", snapshot.runner === "online", snapshot.canaryAccess === "ready", hasPlan]
    .filter(Boolean).length;

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

  async function signOut(): Promise<void> {
    const previous = connectionSelection(connection);
    const ticket = ++generation.current;
    clearApprovalIdentity();
    resetProjectState();
    setNotice(null);
    const operation = beginWork();
    setConnection({ phase: "checking" });
    try {
      await cloudApi.logout();
      if (ticket === generation.current) setConnection({ phase: "sign_in", message: SIGNED_OUT_MESSAGE });
    } catch (error) {
      if (ticket !== generation.current) return;
      if (isSessionLoss(error)) setConnection({ phase: "sign_in", message: SIGNED_OUT_MESSAGE });
      else {
        if (await connect(previous) !== null) setNotice("Heel Cloud could not confirm sign-out, so you are still signed in. Try again.");
      }
    } finally { endWork(operation); }
  }

  async function createContextBinding(): Promise<void> {
    if (connection.phase !== "ready") return;
    const environment = connection.context.environments.find((item) => item.environmentId === selectedBindingEnvironment);
    const runner = connection.context.contextBindings.runners.find((item) => item.runnerId === selectedRunner);
    if (!environment?.isExecutable || environment.verificationRecordDigest === null || runner === undefined) return;
    const ticket = generation.current;
    const operation = beginWork(); setNotice(null);
    try {
      await canaryApi.createRunnerContextBinding(connection.context.workspaceRef, connection.context.project.projectRef, {
        environmentId: environment.environmentId, verificationRecordDigest: environment.verificationRecordDigest,
        runnerId: runner.runnerId, runnerKeyId: runner.runnerKeyId,
      });
      await refreshContextBindings();
      if (ticket !== generation.current) return;
      setNotice("Canary access was authorized for this exact paired runner and verified environment.");
    } catch (error) { recover(error, ticket); } finally { endWork(operation); }
  }

  async function revokeContextBinding(bindingId: string): Promise<void> {
    if (connection.phase !== "ready") return;
    const ticket = generation.current;
    const operation = beginWork(); setNotice(null);
    try {
      await canaryApi.revokeRunnerContextBinding(connection.context.workspaceRef, connection.context.project.projectRef, bindingId);
      await refreshContextBindings();
      if (ticket !== generation.current) return;
      setNotice("Canary access was revoked. Issued grants and active work were not changed.");
    } catch (error) { recover(error, ticket); } finally { endWork(operation); }
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
      setProofChallenge({
        environmentId: value.environment_id as string,
        instruction: proofMethod === "https-file"
          ? `Place the one-time token at ${value.http_url as string}: ${value.token as string}`
          : `Publish this exact record: ${value.dns_record as string}`,
      });
    } catch (error) { recover(error, ticket); } finally { endWork(operation); }
  }

  async function checkProof(): Promise<void> {
    if (connection.phase !== "ready" || proofChallenge === null) return;
    const ticket = generation.current;
    const operation = beginWork(); setNotice(null);
    try {
      const verified = await canaryApi.checkEnvironmentProof(connection.context.workspaceRef, connection.context.project.projectRef, proofChallenge.environmentId);
      if (ticket !== generation.current) return;
      setNotice(verified ? "Staging ownership verified. Pair the local runner next." : "Proof did not match yet. No product route was contacted.");
      await refreshEnvironments();
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
      if (error instanceof CanaryApiError && (error.status === 401 || error.status === 403)) {
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

  async function loadDisclosurePreview(file: File | undefined): Promise<void> {
    if (file === undefined || file.size > 256 * 1024) { setNotice("Choose the signed local summary (maximum 256 KB)."); return; }
    // The read belongs to the account and project that chose the file; after a transition it is dropped.
    const ticket = generation.current;
    try {
      const text = await file.text();
      if (ticket !== generation.current) return;
      const value = JSON.parse(text) as Record<string, unknown>;
      const results = Array.isArray(value.scenario_results) ? value.scenario_results : [];
      if (value.schema_version !== "heel.canary-findings-projection.v1" || typeof value.projection_digest !== "string"
        || !/^[0-9a-f]{64}$/.test(value.projection_digest) || results.length > 4) throw new Error("invalid preview");
      const counts = { blocked: 0, observed: 0, inconclusive: 0 };
      let findings = 0;
      for (const item of results) {
        if (item === null || typeof item !== "object" || Array.isArray(item)) throw new Error("invalid preview");
        const record = item as Record<string, unknown>;
        if (!(record.assessment_outcome === "blocked" || record.assessment_outcome === "observed" || record.assessment_outcome === "inconclusive")) throw new Error("invalid preview");
        counts[record.assessment_outcome] += 1;
        if (record.finding !== null) findings += 1;
      }
      setDisclosurePreview({ projectionDigest: value.projection_digest, projectionBytes: file.size, scenarioCount: results.length, findingCount: findings, completedScenarios: results.length, outcomeCounts: counts });
      setDisclosureOpen(true);
    } catch { if (ticket === generation.current) setNotice("That file is not a closed signed canary summary."); }
  }

  async function decideDisclosure(share: boolean): Promise<void> {
    if (connection.phase !== "ready" || observedRun === null || disclosurePreview === null) return;
    const ticket = generation.current;
    const operation = beginWork(); setNotice(null);
    try {
      if (share) await canaryApi.createDisclosurePermit(connection.context.workspaceRef, connection.context.project.projectRef, observedRun.run.runId, disclosurePreview);
      else await canaryApi.markDisclosureLocalOnly(connection.context.workspaceRef, connection.context.project.projectRef, observedRun.run.runId, disclosurePreview);
      if (ticket !== generation.current) return;
      setDisclosureOpen(false);
      setNotice(share ? "One-use disclosure permit created. Return to the local runner to upload this exact summary." : "Result kept local. No summary bytes were uploaded.");
    } catch (error) { recover(error, ticket); } finally { endWork(operation); }
  }

  const context = connection.phase === "ready" ? connection.context : null;
  const accountView = context?.account
    ?? (connection.phase === "select_project" || connection.phase === "forbidden" || connection.phase === "canary_unavailable"
      ? connection.account : null);
  const selectedProject = context?.project ?? (connection.phase === "canary_unavailable" ? connection.project : null);
  const progress = observedRun?.progress;

  return (
    <main className="canary-dashboard">
      <header className="dashboard-nav"><Link className="brand" href="/" aria-label="Heel home"><span className="brand-mark" aria-hidden="true">H</span><span>Heel</span></Link>
        <div className="dashboard-context"><span className="dashboard-workspace">{selectedProject ? selectedProject.name : "Workspace not connected"}</span><span className="dashboard-presence"><i aria-hidden="true" /> {context ? "Cloud connected" : "Local-first"}</span></div></header>

      <p className="runner-recovery">Supported validation: <Link href="/runner">export entitlement reference and local report viewer</Link>. No customer-target pairing command is available in this release.</p>
      <section className="dashboard-intro" aria-labelledby="dashboard-title"><div><p className="canary-kicker">Verified canary rehearsal</p><h1 id="dashboard-title">Cross the boundary <em>before</em> your customers do.</h1><p>Cloud runner onboarding is an incomplete preview. Use the local export reference to validate a supported synthetic workflow.</p></div>
        <aside className="preview-notice" aria-label="Connection status"><span className="preview-pulse" aria-hidden="true" /><div><strong>{connection.phase === "ready" ? "Ready for customer setup" : "Connect to begin"}</strong><p>{connection.phase === "checking" ? "Checking signed-in context · no request sent" : connection.phase === "ready" ? "Live account state · operational metadata only" : "No sample data is shown"}</p></div></aside></section>

      {connection.phase !== "ready" ? <section className="next-action" role="status"><span aria-hidden="true">↳</span><p><strong>{STATUS_TITLES[connection.phase]}</strong> {"message" in connection ? connection.message
        : connection.phase === "select_project" ? (canCreateProject(connection.account.workspace.role)
          ? "Name your first project below. Nothing has been approved or executed."
          : "No projects exist yet. A workspace owner, admin or member must create one.")
          : "Nothing has been approved or executed."}
        {connection.phase === "error" ? <> <button className="text-button" onClick={() => void connect(selectionFromParams(searchParams))} type="button">Try again</button></> : null}
        {connection.phase === "canary_unavailable" ? <> <button className="text-button" disabled={working} onClick={() => void retryCanarySetup()} type="button">Try again</button></> : null}
        {connection.phase === "no_workspace" || connection.phase === "error" ? <> <button className="text-button" disabled={working} onClick={() => void signOut()} type="button">Sign out</button></> : null}</p></section> : null}

      {connection.phase === "sign_in" ? <AccountAccess api={cloudApi} onAuthenticated={async () => { await connect({}); }} /> : null}
      {accountView ? <WorkspaceProjectBar account={accountView} disabled={working} onCreateProject={createProject}
        onSelectProject={(projectRef) => void selectProject(projectRef)} onSelectWorkspace={(workspaceRef) => void selectWorkspace(workspaceRef)}
        onSignOut={() => void signOut()} projectRef={selectedProject?.projectRef ?? null}
        projects={context?.projects ?? (connection.phase === "canary_unavailable" ? connection.projects : [])} /> : null}
      {notice ? <p className="next-action" role="status">{notice}</p> : null}
      {pendingHasMore ? <p className="next-action" role="status">Another pending approval is waiting after this one.</p> : null}

      <div className="dashboard-grid"><div>
        <ActivationCard completedSteps={completedSteps} environmentOrigin={executable?.origin}
          onReviewApproval={hasPlan && approvalKey ? () => setApprovalDialog({ requestKey: approvalKey, open: true }) : undefined}
          scenarioCount={pendingApproval?.summary.scenarios.length ?? 0} snapshot={snapshot} />
        {context && !executable ? <section className="runner-recovery" id="verify-origin" aria-labelledby="verify-origin-title"><p className="canary-kicker">Exact public HTTPS origin</p><h2 id="verify-origin-title">Verify staging now</h2>
          <label>Staging origin<input autoComplete="url" onChange={(event) => setOrigin(event.target.value)} placeholder="https://staging.yourcompany.com" value={origin} /></label>
          <label>Proof method<select onChange={(event) => setProofMethod(event.target.value as "https-file" | "dns-txt")} value={proofMethod}><option value="https-file">HTTPS file</option><option value="dns-txt">DNS TXT</option></select></label>
          {proofChallenge ? <><p><code>{proofChallenge.instruction}</code></p><button className="button button-primary" disabled={working} onClick={() => void checkProof()} type="button">Check exact proof</button></> : <button className="button button-primary" disabled={working || !/^https:\/\/[a-z0-9.-]+$/.test(origin.trim())} onClick={() => void startProof()} type="button">Create proof challenge</button>}
        </section> : null}
        {context && executable && !pendingApproval ? <section className="runner-recovery"><p className="canary-kicker">Paired runner authorization</p><h2>Add canary access</h2><p>Authorize one active paired runner for one verified staging or sandbox environment. The runner alone may submit its signed plan; this dashboard never accepts projection file uploads.</p><p>This runner is fixed to its first claimed environment. To move it, stop and re-pair a fresh runner, then authorize access here.</p>
          <label>Verified environment<select disabled={working} onChange={(event) => setSelectedBindingEnvironment(event.target.value)} value={selectedBindingEnvironment}><option value="">Select environment</option>{context.environments.filter((item) => item.isExecutable && item.verificationRecordDigest !== null).map((item) => <option key={item.environmentId} value={item.environmentId}>{item.origin}</option>)}</select></label>
          <label>Paired runner<select disabled={working} onChange={(event) => setSelectedRunner(event.target.value)} value={selectedRunnerAvailable ? selectedRunner : ""}><option value="">Select runner</option>{context.contextBindings.runners.map((item) => <option key={`${item.runnerId}:${item.runnerKeyId}`} value={item.runnerId}>{item.displayName} · {item.fingerprint.slice(0, 12)}</option>)}</select></label>
          <button className="button button-primary" disabled={working || !selectedBindingEnvironment || !selectedRunnerAvailable} onClick={() => void createContextBinding()} type="button">Authorize paired runner</button>
          {context.contextBindings.bindings.length > 0 ? <ul className="context-binding-list">{context.contextBindings.bindings.map((item) => <li key={item.bindingId}><span>{item.origin} · {item.runnerId} · {item.status}</span>{item.status === "active" ? <button disabled={working} onClick={() => void revokeContextBinding(item.bindingId)} type="button">Revoke</button> : null}</li>)}</ul> : null}
        </section> : null}
      </div>

      <aside className="dashboard-rail" aria-label="Rehearsal safety boundaries"><section className="boundary-ledger"><p className="canary-kicker">Always enforced</p><h2>The runner owns target traffic.</h2><dl><div><dt>Origin</dt><dd>{executable?.origin ?? "One verified host"}</dd></div><div><dt>Methods</dt><dd>GET + HEAD</dd></div><div><dt>Egress</dt><dd>Staging :443 only</dd></div><div><dt>Cloud view</dt><dd>Operational status only</dd></div></dl></section>
         {runPhase && progress?.available ? <RunProgress phase={runPhase} completedScenarios={progress.scenariosCompleted ?? 0} totalScenarios={progress.scenariosTotal ?? 0} requestsUsed={progress.requestsStarted ?? 0} requestBudget={(progress.requestsStarted ?? 0) + (progress.remainingRequests ?? 0)} secondsRemaining={Math.ceil((progress.remainingWallMs ?? 0) / 1000)} onStop={runPhase === "running" ? () => void stopRun() : undefined} localResultUrl={progress.localResultReady && observedRun ? `http://127.0.0.1:7331/runs/${observedRun.run.runId}` : undefined} /> : null}
         {observedRun && !observedRun.progress.available ? <p className="run-recovery" role="alert">Signed progress is unavailable. The cloud will not invent metrics; inspect the local runner and retry status.</p> : null}
        {progress?.localResultReady ? <label className="disclosure-entry"><span>Optional history</span><strong>Load local summary to review separate sharing →</strong><input accept="application/json,.json" hidden onChange={(event) => void loadDisclosurePreview(event.target.files?.[0])} type="file" /></label> : null}
      </aside></div>

      {pendingApproval && hasPlan && approvalKey ? <ApprovalDialog key={approvalKey} durationSeconds={pendingApproval.summary.durationSeconds} egress={pendingApproval.summary.egress} onApprove={(reason) => void approveRun(approvalKey, reason)} onClose={() => setApprovalDialog(null)} open={approvalDialogOpen} origin={pendingApproval.summary.origin} requestBudget={pendingApproval.summary.requestBudget} routes={pendingApproval.summary.routes} scenarios={pendingApproval.summary.scenarios} /> : null}
      {disclosurePreview ? <DisclosureDialog byteCount={disclosurePreview.projectionBytes} completedScenarios={disclosurePreview.completedScenarios} onClose={() => setDisclosureOpen(false)} onKeepLocal={() => void decideDisclosure(false)} onPermit={() => void decideDisclosure(true)} open={disclosureOpen} outcomeCounts={disclosurePreview.outcomeCounts} /> : null}
    </main>
  );
}
