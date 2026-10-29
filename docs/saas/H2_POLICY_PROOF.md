# H2-2 isolated generation-policy proof (`h2-policy-v1`)

Status: **source candidate, component evidence only.** The Linux run is **UNRUN**: nothing in this
document is a runtime verdict. It becomes evidence only after an independent source review, an
Astra-only manual dispatch of the fixed job on the literal proof branch, and an independent runtime
review of the artifact. Even a PASS is not H3 composition, H6 host qualification, managed
deployment, customer admission or launch evidence.

Design: `H2-POLICY-FABLE-REFRESH/DECISION.md` revision 5, section 6.2 (items E and H), with the
installer contract of `docs/saas/H2_POLICY_INSTALLATION.md` (H2-1, accepted as source at
`7dcad343` + `4bce9513`; this unit changes none of it).

**H2-3 amendment** (accepted H3 composition design `b168458c`, section 8.1): the installer gains the
fixed control accept (slot source → slot gateway, TCP 443, no mark or set) and the `control_only`
shape. The same job and launcher re-prove it on the H2-3 candidate's own bytes: the pinned H2 source
hash changes, so the staged closure digest is new and no earlier run (cycles 1-3) covers this code.
The case names and the record table are unchanged; P1, P2 and P5 gain the gateway and control-only
records described below. Until that run is reviewed, everything H2-3 adds is **UNRUN**.

## Question

Does the real, unmodified H2-1 `install(fd, input)` (the real `Popen` helper, the real `setns` into a
descriptor-held generation namespace, the real nft) write a table whose **real** readback the product
oracle (`readback_matches`) accepts; is it the only table in that namespace; and do that table and
the real H1 `LeaseDomain.prepare`/`activate` of the slot hop together admit only fresh IPv4 TCP 443
connections to the pinned targets while the lease is live, for the unchanged `TargetHTTPSClient` as
well? No installer, helper, nft, validator or socket layer is replaced, and there is **no fallback**:
a refused install, another readback form, a missing capability or an unclean teardown is FAIL/HOLD.

H2-1 review observation **O1** (the strict readback oracle has only been compared with the H2K1F1
shape, not with a real nft 1.0.9 listing of this table) is answered only by this run. If the real
listing differs, `install` returns `readback_mismatch` → `cleaned`/`quarantined` with no receipt and
P1-P4/P7 fail. The evidence is kept as it is; the H2-1 oracle is not relaxed from here.

## Dependency refresh

The current candidate pins cryptography 50.0.1 in both the package and the proof wheel closure.
Only that wheel record changes in the H0 runtime lock; the source, tool, and other Python pins remain fixed.
Existing proof records do not qualify this refreshed dependency set; the Linux proof and its independent
runtime review remain required before host qualification.

## Launcher

`python scripts/host_h2_policy_proof.py` — zero arguments, one fixed profile `h2-policy-v1`, built on
H2K1's launcher (`scripts/host_lease_key_shape.py`), which stays unchanged. The unprivileged parent:

1. refuses any `GITHUB_REF` but `refs/heads/codex/self-serve-host-h2-policy-proof`;
2. requires a clean checkout, `STAGE_FILES` tracked, and `HEEL_TREE_FILES` equal to `git ls-files heel`
   (109 paths at the candidate);
3. checks the pinned Python 3.13.5 and the host tools, lints `codeql.yml` with H0's pinned actionlint;
4. fetches the **eight wheels** byte-pinned in the H0 lock (`deploy/host/ingress/runtime-lock.json`):
   the H1F pytest closure (iniconfig, packaging, pluggy, pygments, pytest 9.0.2) plus cryptography
   50.0.1, cffi 2.1.1 and pycparser 3.11. No new dependency: name, version, file and SHA-256 are
   pinned in the launcher and must equal the lock entry.

One fixed privileged child (`sudo -n`) takes stable host fingerprints, creates an outer
network+mount+PID namespace with only loopback and a private tmpfs, stages exactly
`HEEL_TREE_FILES` + `STAGE_FILES` (the H1 domain and profile, `deploy/host/h2_policy.py`, the proof
module and launcher, the **unmodified** `tests/support/edge_tls_harness.py`, the H1F/H0 launchers and
lock, `codeql.yml`, this document and the H2-1 document), installs the closure offline into a private
venv, runs the **isolated import smoke** and then
`HEEL_REQUIRE_HOST_H2_POLICY_PROOF=1 python -m pytest -q tests/linux/test_host_h2_policy.py` with the
staged root as the working directory. `summary.json` carries the SHA-256 of every staged file and one
`staged_closure_sha256` over all of them.

Isolated import smoke (`IMPORT_SMOKE`, the same code in ordinary CI and in the child): `python -I`
puts neither the cwd nor `PYTHONPATH` on `sys.path`; only the staged root is inserted; then
`heel.runner.http_transport`, `tests.support.edge_tls_harness` and `cryptography` are imported and
every `sys.path` entry and every loaded module's file must lie in the staged root, the closed
environment or the interpreter's stdlib, with `heel.*`/`tests.*` from the root only and cryptography
50.0.1 from the environment. There is no host-checkout fallback. In ordinary CI the third-party
wheels come from the CI test environment; the exact eight-wheel venv exists only in the Linux child.

Acceptance: PASS only if every required case ran with zero skips, every record holds, the import
smoke passed, the host fingerprints are unchanged, no process is left and `kernel_profile pinned`
(profile from the production `deploy/host/profile.py`); a clean run on an unsupported profile is
INCOMPLETE, never PASS. `runtime_assumption running-kernel` is recorded. Public files are the five
allow-listed artifacts only (`summary.json`, `cases.jsonl`, `versions.txt`, `cleanup.json`,
`report.txt`), closed-grammar records, scanned for the run token, paths and raw tool text.

## Fixture

- Generation namespace L: the namespace `LeaseDomain.create()` made, used through a dup of the
  public `ns_fd`; the H2 table is written there **only** by `H2.install` and removed only by
  `H2.cleanup` (P6's labelled seed is the one fixture nft write).
- Peer namespace R: `unshare` on a fixture thread, held only by descriptor; one veth by raw rtnetlink
  with `IFLA_NET_NS_FD` (a dup the fixture closes). No namespace path, name, PID lookup or host
  namespace execution; no default route, uplink or DNS in either namespace.
- Addresses: the slot hop `198.51.100.20` → gateway `192.0.2.1` (documentation addresses, as
  H2K1). H2-3: R holds the gateway address (and the ULA `fd48:4b31::1` as its IPv6 twin) with fixed
  listeners on `192.0.2.1` TCP 443, TCP 8443, UDP 443 and `[fd48:4b31::1]` TCP 443, and L routes to them
  from the slot source; Astra's recorded public pick (FIXTURE-LITERALS.json) — targets `8.8.4.4`/`8.8.8.8`,
  unapproved `1.1.1.1`, wrong source `9.9.9.9`, dual-stack AAAA `2001:4860:4860::8888` — assigned only
  inside L/R, never contacted outside them. L's IPv6 source is ULA `fd48:4b31::20`.
- Input: every admitting case installs the canonical dual-stack tuple
  `select_public_addresses([8.8.4.4, 8.8.8.8, 2001:4860:4860::8888])` (the trusted-constructor
  precondition); the kernel allow-list is the two IPv4 members, the AAAA stays in the tuple.
- Whole-namespace check vs product readback: `nft -j list ruleset` in L must hold exactly one
  `inet heel_lease` table of eight objects, seven for the H2-3 control-only shape (a fixture assertion), and, separately, the product's
  `readback_matches` must accept `nft -j list table inet heel_lease` (the narrower product claim).
- P4's TLS origin: listeners on both IPv4 targets and the AAAA in R using the harness's
  `EphemeralCA` leaf for `h2-policy-proof.example.com` and its `raw_json_response`. The harness's
  `ScriptedTLSServer` is not used: it binds `127.0.0.1` and answers POST only, while the unchanged
  client sends GET/HEAD to the pinned address; the harness file stays byte-unchanged (pinned SHA-256).
  The client is the real `TargetHTTPSClient` with its `resolver` seam (the injected tuple; no DNS),
  the real `TLSTransport` with the harness CA added, and its default sockets.

## Cases (one record each, no skip under the required switch)

- **P0** profile captured through the real H1 self-test, fresh `create()` namespace with an empty
  ruleset; provenance: the staged H2-1 source hash and its helper constant's hash (located in the
  pinned file's AST), the computed platform guard passing by behaviour (a cleanup of a never-installed
  input returns `refused_input`/`not_installed`, not `refused_platform`), the system nft, the client
  and harness imported from the staged root, cryptography outside it, no `.git` in the staged root.
  No H2-2 module names H2-1's two private seams: H2-1's accepted guard
  (`tests/test_host_h2_policy.py`, the tracked-file scan) admits no other tracked module that does,
  and H2-2 forbids itself any assignment, deletion or private read of an H2 name instead.
- **P1** real install → exact receipt (the H2-A canonical document), whole ruleset exactly one table,
  product readback exact; then H1 `prepare`/`activate` admits only the two pinned targets on TCP 443
  while live, nothing after the bound, and interleaved unapproved/8443 probes stay closed. H2-3: the
  slot source reaches the gateway on TCP 443 without any key (before `prepare`), while the key is
  live and after its bound, every probe admitted and delivered.
- **P2** with every listener reachable before the table: the table alone and a prepared-only key
  admit nothing; with a live key the wrong source, the unapproved target, port 8443, UDP 443 and IPv6
  are denied while the controls admit; after `H2.cleanup` every kind reaches its listener again.
  H2-3 gateway cases (the existing `wrong_port`/`udp` kinds target a TLS peer, not the gateway): the
  slot source → gateway TCP 443 is admitted with and without a key, while wrong source → gateway 443,
  gateway TCP 8443, gateway UDP 443 and gateway IPv6 are denied without a key and under the live key.
- **P3** a short key admits while live and no fresh connection after the conservative bound; an
  expired key activated late revives nothing; a fresh key admits and closing it denies again.
- **P4** (mandatory) the unchanged client: succeeds before any table (topology control); with the
  table, is denied without a key and with a prepared-only key (`connect_error`, or `timeout` because
  TCP retries a dropped SYN to the client deadline) while no listener sees a connection; with a fresh
  live key succeeds for a reordered and the canonical answer, dialing the IPv4 selection `8.8.4.4` of the
  dual-stack tuple (the AAAA listener sees nothing); refuses a dropped AAAA, an added or replaced
  member (`dns_changed`) and a private or loopback member (`unsafe_dns`) without connecting; resolves
  once per attempt; is denied again after the key is closed.
- **P5** an IPv6-only tuple returns `unsupported_ipv6_only` with no receipt and no helper, the ruleset
  stays empty, and the H1 `prepare` is refused without a table. H2-3 control-only shape in the same
  namespace: `control_only` with the empty tuple installs with an exact receipt, the whole ruleset is
  one table of seven objects with no target rule, the product readback is exact, the gateway TCP 443 is
  admitted and both targets are denied without a key and under a live key; `H2.cleanup` empties it.
- **P6** faults never receipt. **FAULT-INJECTION** (the one labelled seam, `LAUNCHER.SEAMS`): (a) an
  input naming another namespace → `identity_mismatch`, nothing installed; (b) a pre-seeded
  conflicting chain → the real readback differs → `cleaned`, ruleset empty; (c) the public `clock`
  argument reads 4000 ms late from the readback step → `quarantined` (`timeout`, cleanup
  `out_of_budget`), the table only in L; (d) after a real receipt, the cleanup child's first clock
  read is 2000 ms late → killed, `quarantined`, a repeat is a no-op. Helpers all reaped, outer
  namespace unchanged. This proves the fail-closed state machine on real nft, never a kernel timeout.
- **P7** cleanup is fd-bound: A's input through B's descriptor is refused (`identity_mismatch`,
  quarantined) and both tables stay exact; B's own cleanup empties only B; a repeat is a no-op; an
  injected failure in a live fixture resolves; then no fixture, domain, namespace descriptor, veth,
  socket, thread, helper, child process or outer-namespace change remains.

## Workflow

`.github/workflows/codeql.yml` gains one job, `host-h2-policy-proof (h2-policy-v1)`, appended after
the five existing jobs (whose bytes are unchanged): `workflow_dispatch` on
`refs/heads/codex/self-serve-host-h2-policy-proof` only, the three pinned actions, `contents: read`,
no inputs, secrets, cache, services or environment, `run: python scripts/host_h2_policy_proof.py`,
the five artifacts with three-day retention. Ordinary PR CI never runs the privileged proof (the job
is gated; the dynamic cases skip outside the launcher). The static oracles that pin `codeql.yml`
(`tests/linux/test_host_lease_key_shape.py`, `tests/linux/test_host_authority_proof.py`,
`tests/test_host_authority.py`) accept exactly this sixth block by its bytes and hash; the full
composition and mutation matrix is `tests/test_host_h2_policy_proof.py`.

## Limits

L3/L4 policy plus one unchanged-client path in disposable namespaces under the running-kernel
assumption. Not proven here: H3 (the controller/worker composition, receipt sending, teardown order
against `close_generation`, the five DECISION 4.8 obligations), H6 (provider/host/kernel
qualification, the host-level egress policy), real DNS, Host/SNI enforcement by the kernel, IPv6
egress (refused by design, not covered), deployment, customer admission or launch.
