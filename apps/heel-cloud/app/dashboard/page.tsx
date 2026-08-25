// SPDX-License-Identifier: LicenseRef-Heel-Commercial

"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";

import { ActivationCard, type ActivationSnapshot } from "../../components/canary/ActivationCard";
import { ApprovalDialog } from "../../components/canary/ApprovalDialog";
import { DisclosureDialog } from "../../components/canary/DisclosureDialog";
import { RunProgress, type RunPhase } from "../../components/canary/RunProgress";
import {
  CanaryApi, CanaryApiError, type CanaryApprovalSummary, type CanaryDisclosureMetadata,
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


function messageOf(error: unknown): string {
  if (error instanceof CanaryApiError || error instanceof HeelCloudApiError) return error.message;
  return "Heel Cloud is temporarily unavailable. Your local setup is unchanged.";
}

function idempotencyKey(): `ca1-${string}` {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return `ca1-${Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
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
  const [approval, setApproval] = useState<CanaryApprovalSummary | null>(null);
  const [approvalOpen, setApprovalOpen] = useState(false);
  const [run, setRun] = useState<CanaryRunDashboard | null>(null);
  const [disclosurePreview, setDisclosurePreview] = useState<DisclosurePreview | null>(null);
  const [disclosureOpen, setDisclosureOpen] = useState(false);
  const [selectedRunner, setSelectedRunner] = useState("");
  const [selectedBindingEnvironment, setSelectedBindingEnvironment] = useState("");

  useEffect(() => {
    let cancelled = false;
    void loadConnection().then((next) => { if (!cancelled) setConnection(next); });
    return () => { cancelled = true; };
  }, []);

  async function connect(): Promise<void> {
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
  }, [connection]);

  useEffect(() => {
    if (connection.phase !== "ready" || approval === null || run === null
      || ["terminal", "cancelled", "expired"].includes(run.run.status)) return;
    let cancelled = false;
    const timer = setInterval(() => {
      void canaryApi.getRun(connection.context.workspaceRef, connection.context.project.projectRef, approval.runId)
        .then((next) => { if (!cancelled) setRun(next); })
        .catch((error: unknown) => { if (!cancelled) setNotice(messageOf(error)); });
    }, 1_000);
    return () => { cancelled = true; clearInterval(timer); };
  }, [approval, connection, run]);

  const executable = connection.phase === "ready"
    ? connection.context.environments.find((item) => item.isExecutable) : undefined;
  const hasPlan = approval !== null;
  const snapshot: ActivationSnapshot = {
    environment: executable ? "verified" : proofChallenge ? "checking" : "unverified",
    runner: executable ? (hasPlan ? "online" : "unpaired") : "locked",
    canaryAccess: hasPlan ? "ready" : executable ? "missing" : "locked",
    rehearsal: hasPlan ? (run === null ? "awaiting_approval" : run.run.status === "terminal" ? "complete" : run.run.status === "running" || run.run.status === "claimed" || run.run.status === "approved" ? "running" : run.run.status === "stop_requested" || run.run.status === "finalizing" ? "running" : "error") : "locked",
  };
  const completedSteps = [snapshot.environment === "verified", snapshot.runner === "online", snapshot.canaryAccess === "ready", hasPlan]
    .filter(Boolean).length;

  const runPhase: RunPhase | null = useMemo(() => {
    if (run === null) return null;
    if (run.run.status === "terminal") return run.run.executionDisposition === "stopped" ? "stopped" : "complete";
    if (run.run.status === "stop_requested" || run.run.status === "finalizing") return "stopping";
    if (["cancelled", "expired"].includes(run.run.status)) return "error";
    return "running";
  }, [run]);

  async function selectProject(projectRef: string): Promise<void> {
    if (connection.phase !== "ready") return;
    const project = connection.context.projects.find((item) => item.projectRef === projectRef);
    if (project === undefined) return;
    setWorking(true);
    setNotice(null);
    try {
      const environments = await canaryApi.listEnvironments(connection.context.workspaceRef, project.projectRef);
      const contextBindings = await canaryApi.listRunnerContextBindings(connection.context.workspaceRef, project.projectRef);
      setConnection({ phase: "ready", context: { ...connection.context, project, environments, contextBindings } });
      setApproval(null); setRun(null); setProofChallenge(null); setDisclosurePreview(null);
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

  async function approveRun(reason: string): Promise<void> {
    if (connection.phase !== "ready" || approval === null || run === null) return;
    setWorking(true); setNotice(null);
    try {
      await canaryApi.approveRun(connection.context.workspaceRef, connection.context.project.projectRef, approval.runId, {
        projectionDigest: approval.projectionDigest, hostnameRetype: approval.hostname, reason,
        idempotencyKey: idempotencyKey(), controlGeneration: run.approvalControlGeneration,
      });
      setApprovalOpen(false);
      setRun(await canaryApi.getRun(connection.context.workspaceRef, connection.context.project.projectRef, approval.runId));
    } catch (error) { setNotice(messageOf(error)); } finally { setWorking(false); }
  }

  async function stopRun(): Promise<void> {
    if (connection.phase !== "ready" || approval === null || run === null) return;
    setWorking(true); setNotice(null);
    try {
      await canaryApi.stopRun(connection.context.workspaceRef, connection.context.project.projectRef, approval.runId, run.run.killSwitchGeneration);
      setRun(await canaryApi.getRun(connection.context.workspaceRef, connection.context.project.projectRef, approval.runId));
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
    if (connection.phase !== "ready" || approval === null || disclosurePreview === null) return;
    setWorking(true); setNotice(null);
    try {
      if (share) await canaryApi.createDisclosurePermit(connection.context.workspaceRef, connection.context.project.projectRef, approval.runId, disclosurePreview);
      else await canaryApi.markDisclosureLocalOnly(connection.context.workspaceRef, connection.context.project.projectRef, approval.runId, disclosurePreview);
      setDisclosureOpen(false);
      setNotice(share ? "One-use disclosure permit created. Return to the local runner to upload this exact summary." : "Result kept local. No summary bytes were uploaded.");
    } catch (error) { setNotice(messageOf(error)); } finally { setWorking(false); }
  }

  const context = connection.phase === "ready" ? connection.context : null;
  const progress = run?.progress;

  return (
    <main className="canary-dashboard">
      <header className="dashboard-nav"><Link className="brand" href="/" aria-label="Heel home"><span className="brand-mark" aria-hidden="true">H</span><span>Heel</span></Link>
        <div className="dashboard-context"><span className="dashboard-workspace">{context ? context.project.name : "Workspace not connected"}</span><span className="dashboard-presence"><i aria-hidden="true" /> {context ? "Cloud connected" : "Local-first"}</span></div></header>

      <section className="dashboard-intro" aria-labelledby="dashboard-title"><div><p className="canary-kicker">Verified canary rehearsal</p><h1 id="dashboard-title">Cross the boundary <em>before</em> your customers do.</h1><p>Verify one staging environment, pair one local runner, and complete a bounded read-only rehearsal.</p></div>
        <aside className="preview-notice" aria-label="Connection status"><span className="preview-pulse" aria-hidden="true" /><div><strong>{connection.phase === "ready" ? "Ready for customer setup" : "Connect to begin"}</strong><p>{connection.phase === "checking" ? "Checking signed-in context · no request sent" : connection.phase === "ready" ? "Live account state · operational metadata only" : "No sample data is shown"}</p></div></aside></section>

      {connection.phase !== "ready" ? <section className="next-action" role="status"><span aria-hidden="true">↳</span><p><strong>{connection.phase === "checking" ? "Checking your session." : connection.phase === "select_project" ? "Create a project first." : "Connect your signed-in workspace."}</strong> {"message" in connection ? connection.message : "Nothing has been approved or executed."} <button className="text-button" onClick={() => { setConnection({ phase: "checking" }); void connect(); }} type="button">Try again</button></p></section> : null}

      {context && context.projects.length > 1 ? <label className="dashboard-context">Project<select disabled={working} onChange={(event) => void selectProject(event.target.value)} value={context.project.projectRef}>{context.projects.map((project) => <option key={project.projectRef} value={project.projectRef}>{project.name}</option>)}</select></label> : null}
      {notice ? <p className="next-action" role="status">{notice}</p> : null}

      <div className="dashboard-grid"><div>
        <ActivationCard completedSteps={completedSteps} environmentOrigin={executable?.origin}
          onReviewApproval={approval ? () => setApprovalOpen(true) : undefined}
          scenarioCount={approval?.scenarios.length ?? 0} snapshot={snapshot} />
        {context && !executable ? <section className="runner-recovery" id="verify-origin" aria-labelledby="verify-origin-title"><p className="canary-kicker">Exact public HTTPS origin</p><h2 id="verify-origin-title">Verify staging now</h2>
          <label>Staging origin<input autoComplete="url" onChange={(event) => setOrigin(event.target.value)} placeholder="https://staging.yourcompany.com" value={origin} /></label>
          <label>Proof method<select onChange={(event) => setProofMethod(event.target.value as "https-file" | "dns-txt")} value={proofMethod}><option value="https-file">HTTPS file</option><option value="dns-txt">DNS TXT</option></select></label>
          {proofChallenge ? <><p><code>{proofChallenge.instruction}</code></p><button className="button button-primary" disabled={working} onClick={() => void checkProof()} type="button">Check exact proof</button></> : <button className="button button-primary" disabled={working || !/^https:\/\/[a-z0-9.-]+$/.test(origin.trim())} onClick={() => void startProof()} type="button">Create proof challenge</button>}
        </section> : null}
        {context && executable && !approval ? <section className="runner-recovery"><p className="canary-kicker">Paired runner authorization</p><h2>Add canary access</h2><p>Authorize one active paired runner for one verified staging or sandbox environment. The runner alone may submit its signed plan; this dashboard never accepts projection file uploads.</p>
          <label>Verified environment<select disabled={working} onChange={(event) => setSelectedBindingEnvironment(event.target.value)} value={selectedBindingEnvironment}><option value="">Select environment</option>{context.environments.filter((item) => item.isExecutable && item.verificationRecordDigest !== null).map((item) => <option key={item.environmentId} value={item.environmentId}>{item.origin}</option>)}</select></label>
          <label>Paired runner<select disabled={working} onChange={(event) => setSelectedRunner(event.target.value)} value={selectedRunner}><option value="">Select runner</option>{context.contextBindings.runners.map((item) => <option key={`${item.runnerId}:${item.runnerKeyId}`} value={item.runnerId}>{item.displayName} · {item.fingerprint.slice(0, 12)}</option>)}</select></label>
          <button className="button button-primary" disabled={working || !selectedBindingEnvironment || !selectedRunner} onClick={() => void createContextBinding()} type="button">Authorize paired runner</button>
          {context.contextBindings.bindings.length > 0 ? <ul className="context-binding-list">{context.contextBindings.bindings.map((item) => <li key={item.bindingId}><span>{item.origin} · {item.runnerId} · {item.status}</span>{item.status === "active" ? <button disabled={working} onClick={() => void revokeContextBinding(item.bindingId)} type="button">Revoke</button> : null}</li>)}</ul> : null}
        </section> : null}
      </div>

      <aside className="dashboard-rail" aria-label="Rehearsal safety boundaries"><section className="boundary-ledger"><p className="canary-kicker">Always enforced</p><h2>The runner owns target traffic.</h2><dl><div><dt>Origin</dt><dd>{executable?.origin ?? "One verified host"}</dd></div><div><dt>Methods</dt><dd>GET + HEAD</dd></div><div><dt>Egress</dt><dd>Staging :443 only</dd></div><div><dt>Cloud view</dt><dd>Operational status only</dd></div></dl></section>
        {runPhase && progress?.available ? <RunProgress phase={runPhase} completedScenarios={progress.scenariosCompleted ?? 0} totalScenarios={progress.scenariosTotal ?? 0} requestsUsed={progress.requestsStarted ?? 0} requestBudget={(progress.requestsStarted ?? 0) + (progress.remainingRequests ?? 0)} secondsRemaining={Math.ceil((progress.remainingWallMs ?? 0) / 1000)} onStop={runPhase === "running" ? () => void stopRun() : undefined} localResultUrl={progress.localResultReady && approval ? `http://127.0.0.1:7331/runs/${approval.runId}` : undefined} /> : null}
        {run && !run.progress.available ? <p className="run-recovery" role="alert">Signed progress is unavailable. The cloud will not invent metrics; inspect the local runner and retry status.</p> : null}
        {progress?.localResultReady ? <label className="disclosure-entry"><span>Optional history</span><strong>Load local summary to review separate sharing →</strong><input accept="application/json,.json" hidden onChange={(event) => void loadDisclosurePreview(event.target.files?.[0])} type="file" /></label> : null}
      </aside></div>

      {approval ? <ApprovalDialog durationSeconds={approval.durationSeconds} egress={approval.egress} onApprove={(reason) => void approveRun(reason)} onClose={() => setApprovalOpen(false)} open={approvalOpen} origin={approval.origin} requestBudget={approval.requestBudget} routes={approval.routes} scenarios={approval.scenarios} /> : null}
      {disclosurePreview ? <DisclosureDialog byteCount={disclosurePreview.projectionBytes} completedScenarios={disclosurePreview.completedScenarios} onClose={() => setDisclosureOpen(false)} onKeepLocal={() => void decideDisclosure(false)} onPermit={() => void decideDisclosure(true)} open={disclosureOpen} outcomeCounts={disclosurePreview.outcomeCounts} /> : null}
    </main>
  );
}
