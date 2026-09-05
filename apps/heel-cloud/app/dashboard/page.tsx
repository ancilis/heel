// SPDX-License-Identifier: LicenseRef-Heel-Commercial

"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";

import { ActivationCard, type ActivationSnapshot } from "../../components/canary/ActivationCard";
import { ApprovalDialog } from "../../components/canary/ApprovalDialog";
import { DisclosureDialog } from "../../components/canary/DisclosureDialog";
import { RunProgress, type RunPhase } from "../../components/canary/RunProgress";
import {
  CanaryApi, CanaryApiError, type CanaryApprovalSummary, type CanaryDisclosureMetadata, type CanaryPendingApprovalRequest,
  type CanaryRunDashboard, type RunnerContextBindingDashboard, type VerifiedEnvironmentRecord,
} from "../../lib/canary-api";
import { HeelCloudApi, HeelCloudApiError, type HeelCloudProject } from "../../lib/heel-cloud-api";


const OWNERSHIP_ATTESTATION = "ownership verified; environment classification supplied by you";
const cloudApi = new HeelCloudApi();
const canaryApi = new CanaryApi();

type Context = {
  workspaceRef: string;
  project: HeelCloudProject;
  projects: readonly HeelCloudProject[];
  environments: readonly VerifiedEnvironmentRecord[];
  contextBindings: RunnerContextBindingDashboard;
};

type Connection =
  | { phase: "checking" }
  | { phase: "sign_in"; message: string }
  | { phase: "select_project"; workspaceRef: string }
  | { phase: "ready"; context: Context }
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

function idempotencyKey(): `ca1-${string}` {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return `ca1-${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

function approvalRequestKey(workspaceRef: string, projectRef: string, approval: CanaryApprovalSummary): string {
  return `${workspaceRef}\0${projectRef}\0${approval.approvalId}\0${approval.runId}\0${approval.projectionDigest}`;
}

async function loadConnection(): Promise<Connection> {
  try {
    const session = await cloudApi.me();
    const workspace = session.workspaces.find((item) => item.role === "owner" || item.role === "admin")
      ?? session.workspaces[0];
    if (workspace === undefined) {
      return { phase: "sign_in", message: "Sign in or create a workspace to begin your first rehearsal." };
    }
    const projects = await cloudApi.listProjects(workspace.workspaceRef);
    if (projects.length === 0) return { phase: "select_project", workspaceRef: workspace.workspaceRef };
    const environments = await canaryApi.listEnvironments(workspace.workspaceRef, projects[0].projectRef);
    const contextBindings = await canaryApi.listRunnerContextBindings(workspace.workspaceRef, projects[0].projectRef);
    return { phase: "ready", context: { workspaceRef: workspace.workspaceRef, project: projects[0], projects, environments, contextBindings } };
  } catch (error) {
    const message = messageOf(error);
    return error instanceof HeelCloudApiError && error.code === "auth_required"
      ? { phase: "sign_in", message }
      : { phase: "error", message };
  }
}


export default function Dashboard() {
  const [connection, setConnection] = useState<Connection>({ phase: "checking" });
  const [notice, setNotice] = useState<string | null>(null);
  const [working, setWorking] = useState(false);
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

  useEffect(() => {
    let cancelled = false;
    void loadConnection().then((next) => {
      if (cancelled) return;
      if (next.phase !== "ready") clearApprovalIdentity();
      setConnection(next);
    });
    return () => { cancelled = true; };
  }, [clearApprovalIdentity]);

  async function connect(): Promise<void> {
    clearApprovalIdentity();
    setConnection(await loadConnection());
  }

  const refreshEnvironments = useCallback(async (): Promise<void> => {
    if (connection.phase !== "ready") return;
    const { context } = connection;
    const environments = await canaryApi.listEnvironments(context.workspaceRef, context.project.projectRef);
    setConnection({ phase: "ready", context: { ...context, environments } });
  }, [connection]);

  const refreshContextBindings = useCallback(async (): Promise<void> => {
    if (connection.phase !== "ready") return;
    const { context } = connection;
    const contextBindings = await canaryApi.listRunnerContextBindings(context.workspaceRef, context.project.projectRef);
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
        if (!cancelled && !(error instanceof CanaryApiError && error.code === "unavailable")) setNotice(messageOf(error));
      } finally { inFlight = false; controller = null; }
    };
    const visibility = () => { if (document.visibilityState === "visible") void discover(); };
    void discover();
    const timer = setInterval(() => void discover(), 2_000);
    document.addEventListener("visibilitychange", visibility);
    return () => { cancelled = true; controller?.abort(); clearInterval(timer); document.removeEventListener("visibilitychange", visibility); };
  }, [clearPendingApproval, connection, pendingApproval, working]);

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
            clearApprovalIdentity();
            setConnection({ phase: "checking" });
            void loadConnection().then((next) => { if (!cancelled) setConnection(next); });
          } else if (error instanceof CanaryApiError && error.status === 404) clearPendingApproval();
          else setNotice(messageOf(error));
        } });
    }, 1_000);
    return () => { cancelled = true; clearInterval(timer); };
  }, [clearApprovalIdentity, clearPendingApproval, connection, pendingApproval]);

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
    if (connection.phase !== "ready") return;
    const project = connection.context.projects.find((item) => item.projectRef === projectRef);
    if (project === undefined) return;
    clearApprovalIdentity();
    setWorking(true);
    setNotice(null);
    try {
      const environments = await canaryApi.listEnvironments(connection.context.workspaceRef, project.projectRef);
      const contextBindings = await canaryApi.listRunnerContextBindings(connection.context.workspaceRef, project.projectRef);
      setConnection({ phase: "ready", context: { ...connection.context, project, environments, contextBindings } });
      setSelectedRunner(""); setSelectedBindingEnvironment("");
      setProofChallenge(null);
    } catch (error) { setNotice(messageOf(error)); } finally { setWorking(false); }
  }

  async function createContextBinding(): Promise<void> {
    if (connection.phase !== "ready") return;
    const environment = connection.context.environments.find((item) => item.environmentId === selectedBindingEnvironment);
    const runner = connection.context.contextBindings.runners.find((item) => item.runnerId === selectedRunner);
    if (!environment?.isExecutable || environment.verificationRecordDigest === null || runner === undefined) return;
    setWorking(true); setNotice(null);
    try {
      await canaryApi.createRunnerContextBinding(connection.context.workspaceRef, connection.context.project.projectRef, {
        environmentId: environment.environmentId, verificationRecordDigest: environment.verificationRecordDigest,
        runnerId: runner.runnerId, runnerKeyId: runner.runnerKeyId,
      });
      await refreshContextBindings();
      setNotice("Canary access was authorized for this exact paired runner and verified environment.");
    } catch (error) { setNotice(messageOf(error)); } finally { setWorking(false); }
  }

  async function revokeContextBinding(bindingId: string): Promise<void> {
    if (connection.phase !== "ready") return;
    setWorking(true); setNotice(null);
    try {
      await canaryApi.revokeRunnerContextBinding(connection.context.workspaceRef, connection.context.project.projectRef, bindingId);
      await refreshContextBindings();
      setNotice("Canary access was revoked. Issued grants and active work were not changed.");
    } catch (error) { setNotice(messageOf(error)); } finally { setWorking(false); }
  }

  async function startProof(): Promise<void> {
    if (connection.phase !== "ready") return;
    setWorking(true); setNotice(null);
    try {
      const value = await canaryApi.startEnvironmentProof(connection.context.workspaceRef, connection.context.project.projectRef, {
        origin: origin.trim(), environmentClass: "staging", proofMethod,
        attestationText: OWNERSHIP_ATTESTATION, attestationVersion: "v1", attestationAcknowledgement: "accepted",
      });
      setProofChallenge({
        environmentId: value.environment_id as string,
        instruction: proofMethod === "https-file"
          ? `Place the one-time token at ${value.http_url as string}: ${value.token as string}`
          : `Publish this exact record: ${value.dns_record as string}`,
      });
    } catch (error) { setNotice(messageOf(error)); } finally { setWorking(false); }
  }

  async function checkProof(): Promise<void> {
    if (connection.phase !== "ready" || proofChallenge === null) return;
    setWorking(true); setNotice(null);
    try {
      const verified = await canaryApi.checkEnvironmentProof(connection.context.workspaceRef, connection.context.project.projectRef, proofChallenge.environmentId);
      setNotice(verified ? "Staging ownership verified. Pair the local runner next." : "Proof did not match yet. No product route was contacted.");
      await refreshEnvironments();
      if (verified) setProofChallenge(null);
    } catch (error) { setNotice(messageOf(error)); } finally { setWorking(false); }
  }

  async function approveRun(requestKey: string, reason: string): Promise<void> {
    const pending = pendingApproval;
    if (connection.phase !== "ready" || pending === null
      || pending.requestKey !== requestKey
      || pending.workspaceRef !== connection.context.workspaceRef
      || pending.projectRef !== connection.context.project.projectRef
      || pending.run.run.status !== "awaiting_execution_approval") return;
    clearPendingApproval();
    setWorking(true); setNotice(null);
    try {
      await canaryApi.approveRun(pending.workspaceRef, pending.projectRef, pending.summary.runId, {
        projectionDigest: pending.summary.projectionDigest, hostnameRetype: pending.summary.hostname, reason,
        idempotencyKey: idempotencyKey(), controlGeneration: pending.run.approvalControlGeneration,
      });
      setObservedRun(await canaryApi.getRun(pending.workspaceRef, pending.projectRef, pending.summary.runId));
    } catch (error) {
      if (error instanceof CanaryApiError && (error.status === 401 || error.status === 403)) {
        clearApprovalIdentity();
        setConnection({ phase: "checking" });
        void loadConnection().then(setConnection);
      } else setNotice(messageOf(error));
    } finally { setWorking(false); }
  }

  async function stopRun(): Promise<void> {
    if (connection.phase !== "ready" || observedRun === null) return;
    setWorking(true); setNotice(null);
    try {
      await canaryApi.stopRun(connection.context.workspaceRef, connection.context.project.projectRef, observedRun.run.runId, observedRun.run.killSwitchGeneration);
      setObservedRun(await canaryApi.getRun(connection.context.workspaceRef, connection.context.project.projectRef, observedRun.run.runId));
    } catch (error) { setNotice(messageOf(error)); } finally { setWorking(false); }
  }

  async function loadDisclosurePreview(file: File | undefined): Promise<void> {
    if (file === undefined || file.size > 256 * 1024) { setNotice("Choose the signed local summary (maximum 256 KB)."); return; }
    try {
      const value = JSON.parse(await file.text()) as Record<string, unknown>;
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
    } catch { setNotice("That file is not a closed signed canary summary."); }
  }

  async function decideDisclosure(share: boolean): Promise<void> {
    if (connection.phase !== "ready" || observedRun === null || disclosurePreview === null) return;
    setWorking(true); setNotice(null);
    try {
      if (share) await canaryApi.createDisclosurePermit(connection.context.workspaceRef, connection.context.project.projectRef, observedRun.run.runId, disclosurePreview);
      else await canaryApi.markDisclosureLocalOnly(connection.context.workspaceRef, connection.context.project.projectRef, observedRun.run.runId, disclosurePreview);
      setDisclosureOpen(false);
      setNotice(share ? "One-use disclosure permit created. Return to the local runner to upload this exact summary." : "Result kept local. No summary bytes were uploaded.");
    } catch (error) { setNotice(messageOf(error)); } finally { setWorking(false); }
  }

  const context = connection.phase === "ready" ? connection.context : null;
  const progress = observedRun?.progress;

  return (
    <main className="canary-dashboard">
      <header className="dashboard-nav"><Link className="brand" href="/" aria-label="Heel home"><span className="brand-mark" aria-hidden="true">H</span><span>Heel</span></Link>
        <div className="dashboard-context"><span className="dashboard-workspace">{context ? context.project.name : "Workspace not connected"}</span><span className="dashboard-presence"><i aria-hidden="true" /> {context ? "Cloud connected" : "Local-first"}</span></div></header>

      <p className="runner-recovery">Supported validation: <Link href="/runner">export entitlement reference and local report viewer</Link>. No customer-target pairing command is available in this release.</p>
      <section className="dashboard-intro" aria-labelledby="dashboard-title"><div><p className="canary-kicker">Verified canary rehearsal</p><h1 id="dashboard-title">Cross the boundary <em>before</em> your customers do.</h1><p>Cloud runner onboarding is an incomplete preview. Use the local export reference to validate a supported synthetic workflow.</p></div>
        <aside className="preview-notice" aria-label="Connection status"><span className="preview-pulse" aria-hidden="true" /><div><strong>{connection.phase === "ready" ? "Ready for customer setup" : "Connect to begin"}</strong><p>{connection.phase === "checking" ? "Checking signed-in context · no request sent" : connection.phase === "ready" ? "Live account state · operational metadata only" : "No sample data is shown"}</p></div></aside></section>

      {connection.phase !== "ready" ? <section className="next-action" role="status"><span aria-hidden="true">↳</span><p><strong>{connection.phase === "checking" ? "Checking your session." : connection.phase === "select_project" ? "Create a project first." : "Connect your signed-in workspace."}</strong> {"message" in connection ? connection.message : "Nothing has been approved or executed."} <button className="text-button" onClick={() => { setConnection({ phase: "checking" }); void connect(); }} type="button">Try again</button></p></section> : null}

      {context && context.projects.length > 1 ? <label className="dashboard-context">Project<select disabled={working} onChange={(event) => void selectProject(event.target.value)} value={context.project.projectRef}>{context.projects.map((project) => <option key={project.projectRef} value={project.projectRef}>{project.name}</option>)}</select></label> : null}
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
