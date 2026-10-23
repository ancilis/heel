# Host lease-key shape proof (H2K1, `lease-key-v1`)

Status: proof source only. The kernel outcome is **UNRUN** until an independently reviewed manual
run of the fixed launcher on the literal proof branch. Nothing here is accepted H2 behaviour.

## Question

Can the real H1 `LeaseDomain.prepare(SLOT_PEER, SLOT_ADDRESS, ttl)` and `activate(handle)` gate IPv4
TCP 443 packets whose actual destination is one of two distinct approved targets, neither of which is
SLOT_ADDRESS, when the activated-map lookup and the prepared-set membership both concatenate the
immediate constant SLOT_ADDRESS instead of `ip daddr`? This is Option A from FableH2D: a fixed
logical lease key for arbitrary approved wire addresses. There is **no fallback**. If nft rejects
the shape, reads it back without a verdict structure the oracle recognises, or the packets disagree,
the run is FAIL or HOLD. It never switches to a different semantics (no Option B).

The owned gate the fixture installs (proof fixture, not a production chain):

```
table inet heel_lease {
  set prepared { type ipv4_addr . ipv4_addr . mark ; flags timeout ; }
  map activated { type ipv4_addr . ipv4_addr : mark ; }
  chain gate {
    type filter hook output priority 0 ; policy drop ;
    meta mark set 0
    meta mark set ip saddr . 192.0.2.1 map @activated
    ip saddr . 192.0.2.1 . meta mark @prepared ip daddr { 203.0.113.11, 203.0.113.12 } tcp dport 443 accept
  }
}
```

The table and its contents use the exported names `TABLE`, `PREPARED_SET`, `ACTIVATED_MAP` and
`GATE_CHAIN`, so H1's frozen batches (`create element` into the prepared set, `destroy`/`add` into the
activated map) write into it unchanged. `LeaseDomain.create()` only creates a fresh namespace held by
a descriptor; it installs nothing. `_gate_table_fixture` is the H1 self-test's own throwaway shape,
installed only into self-test namespaces. It is not used here and it is not a production chain. K0
checks that a fresh domain's ruleset is empty and stays empty across the real self-test.

## Fixture

- Generation namespace L is the domain's own namespace, reached through `os.dup(domain.ns_fd)`.
  Peer namespace R is created by `unshare(CLONE_NEWNET)` on a fixture thread and held only by
  descriptor. No helper process, name or PID is involved.
- The one veth is created by raw rtnetlink `RTM_NEWLINK` from a socket inside L, with the peer
  created directly in R by `IFLA_NET_NS_FD`. That descriptor is a dup that is closed in a `finally`.
  Addresses, routes and permanent neighbours are set with `ip` entered by `setns` on a descriptor.
  Nothing uses a named namespace, `ip netns`, `nsenter`, a numeric PID or a default route.
- Fixed documentation addresses only: SLOT_PEER 198.51.100.20, wrong source 198.51.100.21, logical
  gateway SLOT_ADDRESS 192.0.2.1 (assigned to no interface), approved targets 203.0.113.11 and
  203.0.113.12, unapproved 203.0.113.13, IPv6 fd48:4b31::20 to fd48:4b31::11. Listeners in R take
  TCP 443 on every target, TCP 8443, UDP 443 and IPv6 TCP 443. Before the gate exists, every probe
  kind connects and delivers, so a later denial comes from the gate and not from the topology.
- Probes are fresh connections. Admission is the client's connect (or `sendto`) verdict inside its
  own CLOCK_MONOTONIC bracket; delivery of a per-run nonce to the expected listener only confirms it.
  A delivery without an admission, or a delivery to another listener, is an anomaly.
- The fixture uses only the public domain API (`LeaseDomain.create`, `prepare`, `activate`, `close`,
  `close_generation`, `ns_fd`) and exported names. It does not capture private fields, use
  `CycleSeams`, adopt a foreign handle, call a raw mark API or mutate the counter. No H1 source or
  API changes. Each case gets a fresh domain and fixture.

## Cases (each writes exactly one record)

- **K0** `provenance`: the real `generation_self_test` on this kernel passes and
  `profile.grade_self_test` grades the captured runtime `pinned` (kernel source tag, nft release,
  CONFIG_HZ, re-add semantics). The tick from the report gives every later bound. A fresh `create()`
  namespace is distinct and has an empty ruleset. No provider, SKU, host or power qualification is
  claimed.
- **K1** `admission`: the shape installs and its readback has the required structure. After a real
  prepare and activate (3000 ms), fresh TCP 443 connections to both approved targets are admitted and
  delivered (at least five each, 95 % or more) while the lease is valid. None is admitted after the
  conservative bound.
- **K2** `negative`: a prepared key without activation admits nothing, including connections whose
  caller-supplied `SO_MARK` equals the prepared element's mark (the reset, lookup and membership
  gate cannot be bypassed). Activating the same handle then admits (positive control).
- **K3** `expiry`: with a 1000 ms lease there is a positive before the bound. After
  `after_prepare + ttl + 2 ticks` (the commit lies inside the prepare bracket; expiry has jiffy
  granularity), at least eight fresh connections are admitted zero times. This is a claim about
  synthetic packets only, not about the control plane, the SaaS or signed requests.
- **K4** `negative`: a 300 ms key is activated through the public API after its bound. Whether
  `activate` succeeds (the outcome is recorded) or refuses, the expired membership does not revive
  egress. A fresh key then admits, and `close` of that key denies again. Durations are never
  rewritten.
- **K5** `confinement`: with a live lease, a fixed round of a wrong source, an unapproved target,
  TCP 8443, UDP 443 and IPv6 TCP 443 is denied twice each, inside the live window and between
  admitted controls. This is an L3/L4 proof. It is not Host/SNI/TLS, method, route or attempt
  enforcement; the trusted runner's existing checks are unchanged.
- **K6** `cleanup`: an injected failure inside a live fixture with an active key resolves like a
  normal exit. Afterwards no fixture, domain, namespace descriptor, socket, fixture thread, child
  process, registry entry or owned link survives, and the outer namespace's links, addresses, routes
  and ruleset hash the same as before K0. The baseline loopback count is recorded separately from
  owned residual links.

## Launcher and evidence

`python scripts/host_lease_key_shape.py` takes no inputs. It reuses the H1A-1 launcher structure,
H1F's H0-locked pytest closure and helpers by path, and `deploy/host/profile.py` by path. It stages
exactly ten files (`STAGE_FILES`): the H1 domain and profile, this unit's module, launcher, workflow
and this document, and the H1F/H0 launchers and lock they import. The test module runs as root with
`HEEL_REQUIRE_HOST_LEASE_KEY_PROOF=1` inside an outer network+mount+PID namespace that has only
loopback. In that mode every case must execute, and a missing capability fails rather than skips.
Locally and in the ordinary suite the dynamic cases skip, and the run says so.

The result is PASS only when every case ran and passed, every record holds, the host fingerprints are
unchanged, nothing was left over and the report shows `kernel_profile pinned`. A clean run on an
unpinned profile is INCOMPLETE. Since K0 also requires `pinned`, such a run is FAIL here. The report
states `runtime_assumption running-kernel`. The published artifacts (summary, cases, versions,
cleanup, report) are closed-grammar tokens and integers bound to the candidate SHA and the staged
file hashes. Raw packets, listings, paths, names and addresses are never published. The readback
listing appears only as its SHA-256 and parsed structural tokens.

## Installation diagnostics (H2K1D1)

The first reviewed run (39895297766 at c653e6b) remains **FAIL**: 12 passed, 5 failed, 0 skipped.
K0 and K6 passed. K1 to K5 reached seven reachable baselines and then recorded `install=other` with
an empty readback. That token says only that the exit was nonzero and the stderr matched no listed
needle. It does not show a parser rejection, a kernel refusal or a capability limit, and this
revision does not regrade it. The kernel outcome of the unchanged gate is still unproven.

This diagnostic revision changes no gate byte (409 bytes, SHA-256 `3e08d90e…0f758a48`, pinned by a
static test with the parent's `gate_table`, `install_error_token`, `readback_shape`, `gate_ready` and
the launcher's `evaluate`). Before the unchanged install, the fixture runs one `nft -c -f -` of the
same text in the same owned namespace. In nft 1.0.9 `-c` parses, evaluates and sends the batch
without its end marker, so it commits nothing. The check's outcome never gates the install. The
install, the readback, the `install` token, `gate_ready` and the PASS rule are unchanged. A
diagnostic run is not a proof success unless the full K0 to K6 contract also passes.

Each record that reached the gate adds closed fields for the phases `check`, `install` and
`readback`, bound to `gate_input_sha256` (the SHA-256 of the exact input):

- `<phase>_status`: `exit`, `signal`, `timeout`, `missing` (no return code: the tool did not start or
  the call raised) or `invalid` (a return code outside both ranges).
- `<phase>_exit`: the normal exit code 0 to 255 when the status is `exit`, otherwise -1.
  `<phase>_signal`: 1 to 64 when the status is `signal` (Python's negative return code), otherwise 0.
  A negative return code is never recorded as an exit.
- `<phase>_class`: `accepted`, `parser_syntax`, `parser_datatype`, `parser_other`, `netlink_einval`,
  `netlink_eopnotsupp`, `permission`, `tool_missing`, `timeout` or `unknown`. The classes come only
  from nft 1.0.9's fixed texts: bison's `syntax error`, the evaluator's `datatype mismatch`, the
  batch path's `Could not process rule: <strerror>`, the base-chain EOPNOTSUPP message and
  `cache initialization failed`. `parser_other` needs a located error with no system error text.
  Any other errno, an unlocated message, a signal or unparsable output is `unknown`. It is never a
  parser claim.
- `<phase>_line` and `<phase>_column`: nft's own locator (`/dev/stdin` for check and install,
  `<cmdline>` for readback), kept only when it lies inside that input. 0/0 means absent.
- `<phase>_stderr_sha256`: the SHA-256 of stderr. Stderr itself, listings, paths, addresses,
  namespace names and exception text never leave the fixture.
- `install_phase`: the first phase whose class is not `accepted`, or `none`.

The launcher's sanitizer drops any record whose diagnostic fields are partial, outside this grammar
or inconsistent with each other. The artifact allowlist and the per-record limits are unchanged.
Reading the next run: the same parser class and locator in check and install points to the fixed
grammar or evaluator (map it to the pinned source before saying more). `check=accepted` with a netlink
class at install points to the kernel transaction. `permission`, `tool_missing`, `timeout` and
`unknown` call for a HOLD and an evidence or fixture repair, not a gate change.

Workflow: the job `host-lease-key-shape (lease-key-v1)` is appended to `.github/workflows/codeql.yml`
(5 jobs: analyze plus four proofs). It runs only on manual `workflow_dispatch` at the literal ref
`refs/heads/codex/self-serve-host-lease-key-shape-proof`, with read-only contents,
`persist-credentials: false`, `github.sha` checkout, the pinned existing actions, 25/20-minute
timeouts, and no inputs, secrets, cache or services. Artifact retention is 3 days. The earlier job
blocks are byte-identical.

## Not claimed (later gates)

This proof covers no DNS behaviour (resolution, TTL, rebinding), no refresher, discovery or parser,
no H2 production guard, no HostCycle-to-H3 handoff or channel integration, no H3 controller-worker,
no transport rewrite, credentials or real SaaS traffic, no production network, and no H2, H3 or
launch completion. Each remains a separate reviewed gate.
