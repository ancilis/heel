# Host lease feasibility proof (H1F, `lease-v1`)

Status: proof-only source candidate. Runtime verdict: NOT RUN. The Linux run happens only after
independent review, on one manual dispatch of the exact reviewed SHA on the literal branch
`codex/self-serve-host-lease-proof`. Nothing here is H1A product code, an allocator, a service, H2
network isolation, H3 lifecycle, credential custody, a deployment or a launch claim.

## What is measured

The proof asks one question about the Linux kernel and nftables: does the prepared-gate primitive
of H1DR section 4 behave as the design argues, with the Astra H1DR disposition corrections applied?

```
table inet heel_lease {
  set prepared  { type ipv4_addr . ipv4_addr . mark ; flags timeout ; }
  map activated { type ipv4_addr . ipv4_addr : mark ; }
  chain gate {
    type filter hook output priority 0 ; policy drop ;
    meta mark set 0
    meta mark set ip saddr . ip daddr map @activated
    ip saddr . ip daddr . meta mark @prepared accept
  }
}
```

A key `S . D . M` is written once, with `create element` (`NLM_F_EXCL`) and its lifetime, before
any authority exists. Activation writes only a reference into the timeout-free map
(`destroy element` + `add element` in one transaction) and carries no lifetime. The gate shape is a
proof fixture; H2 owns any production table layout.

It also records peer-credential facts for the host-only Unix channel (`SO_PEERCRED`), as seen from
the checking side's user and PID namespaces.

## Commands

```
python scripts/host_lease_feasibility.py
```

from the repository root, with no arguments (one fixed `lease-v1` profile; any argument exits 2).
The unprivileged parent:

1. verifies a clean checkout and Python 3.13.5;
2. confirms that `nft`, `ip` and `iptables-save` already exist on the fixed `PATH` (nothing is
   installed; a missing tool fails before any fingerprint or namespace exists). util-linux is
   recorded in A12 but never invoked: namespaces are entered with `os.unshare`/`os.setns`;
3. lints `.github/workflows/codeql.yml` with H0's pinned actionlint;
4. fetches the pytest 9.0.2 closure (iniconfig, packaging, pluggy, pygments, pytest) from the
   URLs and SHA-256 values that `deploy/host/ingress/runtime-lock.json` already pins for H0. The
   launcher carries its own copy of each entry and refuses to run if the lock differs.

One fixed privileged child (`sudo -n`, schema-checked JSON on stdin, owned private scratch paths
only) re-checks the tools, takes two host fingerprints two seconds apart (H0's helper: links,
addresses, routes, netns list, `nft -s list ruleset`, normalised `iptables-save`, hosts, resolver,
trust store, sysctls, mounts) and creates an outer network+mount+PID namespace with only loopback
and a private tmpfs. Inside, as PID 1, it copies exactly the fixed `STAGE_FILES` from this checkout,
re-hashes the wheels in memory, installs them with `pip --no-index --no-deps` into a private venv and
runs `HEEL_REQUIRE_HOST_LEASE_PROOF=1 python -m pytest -q tests/linux/test_host_lease_primitive.py`.
Afterwards it reaps and kills every leftover process and compares the host fingerprints. Kernel
modules that appear during the run (a veth or nft object can autoload one on the shared kernel)
are listed in `cleanup.json` as `kernel_modules_loaded`: recorded, not graded, never hidden.

Local, unprivileged (any OS): `python -m pytest -q -p no:cacheprovider tests/linux/test_host_lease_primitive.py`
runs the static cases and skips the dynamic ones. The skip is the single guarded path; under
`HEEL_REQUIRE_HOST_LEASE_PROOF=1` a missing platform, root, launcher environment, tool or namespace
capability fails instead. The dynamic cases also refuse to run in any network namespace that has an
interface other than loopback, so they cannot touch a real host's networking.

## Fixture and measurement model

Each packet case creates a fresh pair of inner network namespaces: L (`198.51.100.10`) and R
(`203.0.113.10`), one veth with fixed MACs, `/32` routes and permanent neighbours (no ARP timing).
The gate is installed in L's output hook with `policy drop`, so a missing or failed gate denies.
Probes are 64-byte UDP datagrams at 100 per second carrying the run token.

- **Admission instant.** The output hook runs synchronously inside `sendto`: success means the gate
  accepted the probe and EPERM means it dropped it. Each probe's admission therefore lies inside its
  own CLOCK_MONOTONIC bracket `[t_before, t_after]`. R's receive time only confirms delivery; it is
  never an admission time, so receiver scheduling or a queued old datagram cannot look like new
  authority. This bounds the kernel admission instant; it does not prove the precise instant.
- **Expiry bound.** `E_max = t_pq + T`, where `t_pq` is the return of the prepare batch (the commit
  happens inside the bracket). A probe is "admitted after the bound" when it was accepted or
  delivered with `t_before > E_max + 1 tick`. The tick (`CONFIG_HZ`) is the kernel's expiry
  granularity (H1DR 4.3), the only allowance, and never a measurement allowance. An unknown
  `CONFIG_HZ` uses the coarsest supported tick and makes the profile unpinned.
- **Stale activation.** Graded with no allowance at all: zero admissions over the whole window, with
  the activation committed only after `E_max + 1 tick`, cleanup withheld (no test write inside the
  window is checked), the installer killed with SIGKILL, and a live positive control afterwards.
- **Positive delivery.** Counted only for probes wholly inside an interval where the element was
  certainly live and activated: from the activation's return to `t_pp + T - 2 ticks`. At least
  95 % must be admitted and delivered, and the interval must hold a minimum number of probes.
  Probes the sender never attempted are absent, not lost.
- **Integers.** Oracles compare nanoseconds. Published millisecond values round lateness up and
  margins down, so a rounded figure can never hide a violation.
- **Marks.** Distinct nonzero 32-bit values for one proof run, issued once, never wrapped; exhaustion
  fails closed. This is not an H1A allocator: no wrapping layout, watchdog or pause assumption is
  accepted, and H1A still owes a non-wrapping allocation domain with fail-closed exhaustion and
  loss, rollback and restart handling. A key is written twice only in the named controls (A7, N3, the
  A12 self-test and the A8 informative re-add).

## Cases

Every case runs; a skip is a failure in the required profile. Negative controls pass when their
hazard is shown, so a fixture that cannot see an open gate fails them.

- **A12** provenance and compatibility self-test. Bounded parsed fields only: `uname -r` token and
  major.minor, the matching source tag, the SHA-256 of `/proc/version`, `nft --version`, the dpkg
  package version, util-linux, `CONFIG_HZ`, `overflowuid`, Python and pytest. Self-test (H1DR 3.4,
  corrected): a 200 ms key, a duplicate `create` refused with EEXIST while the key is live, traffic
  before expiry and none after, then a fresh `create` of the expired key succeeds, which is why keys
  must never repeat. The expectation is never relaxed to get a pass.
- **N1** negative control, H1D's relative TTL: the installer computes `R = D - t_pre`, stalls 6 s at a
  pipe barrier, adds the element and is killed before any post-delete. At least 50 probes must be
  admitted after `D + 1 tick` and none before the element exists.
- **N2** negative control: without `meta mark set 0`, a socket mark equal to a live prepared key passes
  with no activation, which shows the reset rule is load-bearing.
- **N3** negative control (Astra 1): the map references an expired key; recreating that same key
  revives the stale reference. The gap between expiry and recreation must be closed.
- **A1** the composition parses and installs; readback `timeout` and `expires` are at most 2850 ms;
  the chain lists the map statement.
- **A2** prepared only, with a plain socket and with a socket carrying the key's own mark: zero
  admitted while the key is certainly live; then the same key, activated, admits (live control).
- **A3** prompt activation admits at least 95 % in the live interval (deny-all cannot pass).
- **A4** stale activation: the activator reads its clock, stalls at the barrier until after
  `E_max + 1 tick`, commits successfully and is killed; zero admissions over 10 s, the map points at
  the expired key, then a fresh key admits.
- **A5** activation, then supervisor death: delivery in the live interval, none after `E_max + 1 tick`.
- **A6** renewal swap: no attempted probe lost, delivery past the old key's expiry, none past the new.
- **A7** a `create` of a live key inside a batch with an activation fails the whole batch with
  EEXIST and leaves the map unchanged (checked while live); a `create` of an expired key held in
  memory (`gc-interval 1h`) succeeds with a fresh lifetime.
- **A8** activation of an expired key admits nothing; informative: a non-EXCL re-add of a live key
  with a different timeout is recorded as `refresh` or `noop`.
- **A9** an 800 ms key cuts off by `E_max + 1 tick`.
- **A10** 200 prepare and 200 activation batch brackets (p50/p95/p99/max, microseconds and rounded-up
  milliseconds) while a sibling process commits unrelated transactions; sizes `GUARD_MS` for
  liveness only.
- **A11** 100 random timeouts in [500, 3000] ms (fixed seed); readback never exceeds the request.
- **A13** (Astra 1) the map references an expired key while a different fresh key is live: nothing
  passes; then a delayed activator overwrites a live activation with the stale key and traffic stops
  (fail-closed liveness blip, never authority).
- **B1** informative only: a `meta time` absolute rule installed after a stall with a past deadline,
  and with a future one. Never grades the run.
- **P1** production profile (socket 0600 and parent 0700, both owned by uid 10001; the root client
  connects through its own privilege, no permission is relaxed): the server sees uid 0 and the
  client's pid; the client sees uid 10001 and the listener's pid; uid 10002 is refused (EACCES).
- **P2** (Astra 3) the checking server runs in a user namespace that maps only its own uid
  (0 -> 10001), keeps the production permissions, and sees the root client as `overflowuid`; the
  root client still sees 10001. Converse, through `SEAM-PERMISSIVE-SOCKET` (a 0666 socket in a 0755
  directory used only to expose kernel mapping, not the production profile): a client in a namespace
  that maps only 0 -> 10002 sees the server as `overflowuid`, and the server sees 10002.
- **P3** (Astra 3) the checking server runs as pid 1 of a child PID namespace with the production
  permissions; it sees the correct root uid and pid 0 for the client outside, while the client sees
  the server's outer pid. A blanket "pid != 0" rule would therefore reject the intended
  host -> container topology; this proof records the fact and accepts no pid rule.
- **C1** no owned pair, child process, socket or veth survives in the outer namespace.

## Evidence

The job uploads exactly `host-lease-feasibility/{summary.json,cases.jsonl,versions.txt,cleanup.json,report.txt}`
(3-day retention, missing files are an error). Every public value is a fixed case id, a verdict
(`pass`, `fail`, `info`), a control class, a bounded integer or a token matching
`[a-z0-9][a-z0-9_.:-]{0,79}`. A record with any other key, type or character is dropped whole, and a
dropped record fails the run. Raw pytest output, tracebacks, nft stderr, rulesets, `/proc/version`
text, paths and environment stay in private memory. Every public file is scanned for the run token,
paths, tracebacks and tool error text before upload.

Result rule: **PASS** only when the child exits 0, every required case passed with zero skips, every
case wrote exactly one record with its expected verdict, the host fingerprints are unchanged, no
process is left and `kernel_profile` is `pinned`. A run that is clean except for an unsupported
profile is **INCOMPLETE** (exit 1), never PASS. Anything else is FAIL.

`kernel_profile` is `pinned` only when the captured kernel's major.minor is one of the pinned source
tags (`6.8`, `6.17`, `7.0`), nft is 1.0.9, `CONFIG_HZ` is 100, 250 or 1000, the A12 self-test
passed, and the A8 re-add observation matches what that tag's source implies (`noop` on 6.8,
`refresh` on 6.17 and 7.0). The version label alone never pins a profile: the measured behaviour
must agree, and a kernel outside the tags is held until a reviewer pins the same properties against
it. The Ubuntu kernel is a patched build of its tag; a reviewer still compares the cited functions
against Ubuntu's tree for the captured release before H1A relies on the run.

## Limits

- Kernel primitive and peer-credential facts only, in private namespaces. No H1A allocator,
  supervisor, CP route or service; no H2 executor-path table, DNS view or TLS stream; no H3
  lifecycle, suspend handling or restart flush; no five-second product stop bound.
- Admission instants are bounded by the userspace `sendto` bracket, not measured inside the kernel.
- One runner, one kernel, one run: timing distributions (A10) are context, not a guarantee.
- The permissive seam socket in P2 exists only to expose kernel mapping; it is not the production
  profile and supports no authentication claim.
- No provider resource, customer traffic, credential, parser or discovery work, deployment or spend.
