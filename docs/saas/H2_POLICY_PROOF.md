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

**C4 P01 inventory amendment** (private managed codec): the commercial, inert codec moved
byte-for-byte to `heel/saas/managed_authority_contracts.py`, so the tracked `heel/` tree and
`HEEL_TREE_FILES` are now 110 paths (was 109) and the ordered staged closure is 110 + 14 = 124 files.
The 14 `STAGE_FILES`, the profile, the reviewed ref, the wheel closure and every case are unchanged.
**Runner rc3 integration amendment:** the public runner module `heel/runner/regressions.py` makes the
tree 111 paths (closure 111 + 14 = 125), and the accepted plan-submit change re-pins the TLS harness
(`edge_tls_harness.py`, test support only) at `b8887b86…`; that closure is likewise **UNRUN**.
The new staged closure digest is **UNRUN**: no earlier run, including the cycles above and any H2-3
run, covers it. It becomes evidence only after a fresh, unfiltered launcher run on the literal proof
branch (all 18 cases, eight p0-p7 records, zero skips) and an independent runtime review. Earlier
records stay historical evidence of their own closures only. The codec is not imported by any staged
proof path; staging it is inventory, not use.

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
   (111 paths at the candidate, including the private `heel/saas/managed_authority_contracts.py`);
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

## Host-link diagnostics (H2-LINK-DIAGNOSTICS-R1, corrected in R2, R3, R4 and R5, supplementary)

Run 41621515465 failed the host audit on `links` with no evidence of what changed (the original
FAIL stands; its cause is underdetermined). This addition describes the same captured text; it does
not change the gate. Its new closure is **UNRUN** until a reviewed execution. R2 corrects three
source-review findings: diagnostic work is bounded before it starts (F1), a name/MAC registry match
is a correlation only (F2), and sysfs reads are descriptor-anchored and rechecked (F3). R3 extends
the early bounds to every other diagnostic input (fixture listing and registry, ancillary listing,
the child's cleanup file and the parent's closed check) and reports device facts only under a
verified, supported sysfs mount, with claims limited to the sampled objects. R4 corrects the third
review's finding that the namespace init still copied the registry with an unbounded whole-file read
(and followed a symlink) before the host's 64-KiB reader ran: the registry now has its own bounded
transfer, and the R3 claim that every diagnostic input was bounded before copy was false until then.
R5 corrects the fourth review's findings at that transfer's destination: H1F's shared writer ignored
a short write, so a real kernel short write delivered one valid record of four and the diagnostics
accepted it as complete (F1), and its blocking open waited on a writerless FIFO at the destination
name (F2). The registry now has its own complete-or-failed writer.

- **Same capture.** H0 `host_fingerprints(observer=None)` gains a default-disabled observer. With an
  observer, H0 hands it each fixed command's status (`ok`, `nonzero`, `timeout`, `oserror`), return
  code, the exact stdout object the digest was computed from, that digest and monotonic bounds. The
  digest, normalization, commands and `unavailable` rule are unchanged. The observer is called
  outside the capture's `try`, and its exceptions are swallowed, so it cannot alter or hide a
  digest. H0's own child and the H1F/H1/key-shape launchers pass no observer. Invalid UTF-8 still
  aborts the capture exactly as before. This is a shared-helper change, so H0/H1F regressions and a
  fresh H0 qualification are required.
- **Same baseline.** The privileged child calls `stable_fingerprints(snapshot=..., pause=...)`. That
  is two H0 snapshots before fork/unshare and one after the namespace child exits, with the same
  `differing` rule. The first snapshot's metadata is sampled inside at most 1.5 s of the 2 s pause,
  and the rest of the pause is slept. The three phases are `baseline_first`, `baseline_second` and
  `after_namespace_exit`.
- **Bounded before work (R2).** The diagnostics make one scan over each captured text, and the
  gate's own digest of the full text is unchanged. The scan:
  - reads at most 64 lines, finding each newline with a search confined to 4096 characters past the
    line's start, and at most 65536 characters in all;
  - copies, encodes, commits and (for a successful capture) parses only those bounded slices, so
    at most 64 lines per capture are ever parsed and committed;
  - stops as `truncated` on more lines (`line_cap`), an oversized line (`line_length_cap`), the
    aggregate bound (`scan_cap`) or an unencodable line (`unsupported_encoding`).
  - A truncated scan reports the exact character length of the captured text (`chars`, no pass over
    it), but its total `bytes` and `line_count` are `null`, never estimated, and it has no multiset
    commitment. Order-only is claimed only between two complete scans.
- **Closed output.** `cleanup.json` gains `link_diagnostics`
  (`heel.host-h2-policy-proof.link-diagnostics.v2`), and the parent re-checks it all or nothing.
  - Top level: `attribution` is always `correlation_only` (see the ownership registry below).
  - Per capture it records:
    - run-local namespace identities before and after;
    - start/end ms relative to the parent's monotonic start;
    - status, return code and gate digest;
    - `chars`, `bytes` and `line_count` (both `null` unless the scan is complete), `lines_scanned`
      and `scan` (`complete` or `truncated`);
    - per-line keyed commitments for the scanned lines, and a sorted multiset commitment only for a
      complete scan;
    - up to 64 links of exactly 16 fields: keyed id/peer/MAC/master/line/other commitments, bounded
      ifindex/iflink/MTU/qlen/netnsid, closed flag/operstate/link-type enums, an unknown count and
      provenance.
  - Per pair (`baseline`, `audit`) it records:
    - whether the gate digests are equal;
    - status-change and order-only flags;
    - added/removed/changed counts;
    - up to 64 changes with closed field labels;
    - `proof_identity` (always `unknown`, or `not_applicable` in the baseline pair), `correlation`
      (`fixture_name_mac`, `ambiguous`, `none`, `not_applicable`) and `hardware`;
    - enrichment-only changes;
    - delta classes from `none`, `command_status_change`, `order_only_text_change`,
      `fixture_name_mac_correlation`, `hardware_backed_change` and `unknown`.
  - Raw names, MACs, aliases, altnames, addresses, bus paths, inodes, the HMAC key and command
    output are never exported.
  - Commitments are HMAC-SHA256 under a run-private 32-byte key. The parent creates it, sends it only
    to the child and the fixture, and scans every artifact for it.
- **Metadata (read-only, bounded).**
  - One fixed listing, `ip -d -j link show`, is used for the link kind: at most 64 KiB read (no
    single read asks past the bound), 2 s per command, 5 s in total; more than 64 entries is `cap`
    before any entry is visited, and an `ifname` over 64 characters is `invalid`.
  - Supported layout only (R3). Device facts are reported (`status=ok`) only on Linux and only when
    the sysfs root descriptor is the root of a verified real sysfs mount: its `mnt_id` (from
    `/proc/self/fdinfo/<fd>`, at most 1024 bytes read) names exactly one `/proc/self/mountinfo` entry
    (at most 64 KiB read, otherwise unsupported) whose filesystem type is `sysfs`, whose mount root is
    `/`, whose mount point is the root path and whose major:minor is the descriptor's device. Every
    descriptor opened afterwards (each directory on every walk, each endpoint, each attribute file,
    the re-opened root) must be on that same device and mount id. Anything else (another platform,
    another filesystem type, a bind of a subdirectory, an overmount anywhere on the walked path,
    oversized or malformed /proc text) is `unknown`. These reads use the existing 64 KiB and 5 s
    ancillary budgets; no mount path, mount id, inode or error text is exported.
  - Fixed sysfs attributes give `ifindex`, `device`, `subsystem` and `driver` (R2: descriptor-anchored):
    - every read starts from one descriptor of the sysfs root and walks real directories one
      component at a time (`O_DIRECTORY | O_NOFOLLOW` at each parent descriptor), so a substituted
      parent or ancestor fails instead of being followed;
    - only the four intended links are read (`class/net/<name>`, `device`, `subsystem`, `driver`),
      each resolved lexically against its own directory, at most 512 characters and 32 components,
      and required to stay in its tree: `devices/…/net/<name>`, `devices/…`, `bus/<bus>`,
      `bus/<bus>/drivers/<driver>`;
    - every descriptor opened must be on the root's device and verified mount (above);
    - `ifindex` is read at the link directory's descriptor (a regular file on the verified mount, at
      most 64 bytes, `O_NOFOLLOW`) before and after;
    - a second full pass must reach the same objects (device, inode), locations and facts, and the
      root must still be the same object;
    - the bus is an enum, and the driver comes from an allowlist (otherwise `unknown`).
  - The namespace identity is rechecked around the enrichment. A failed check, a difference between
    the two passes or the deadline gives `unknown`, which marks the diagnostics incomplete
    (`enrichment_unknown`).
  - What `ok` means (sampled objects only): each object was, when it was sampled, an object of the
    verified sysfs mount at an intended location, and the two passes agreed. Because the mount root
    is the filesystem root, no object reached on that mount lies outside it. It is not lifecycle
    identity: an object replaced by another with the same (device, inode) between samples, or a
    change after the second pass, is not excluded, and the facts describe the sample, not the link's
    history. The synthetic tests model the mount contract on fake trees (labelled as a model); they
    are not mount proof. Linux verification of the contract on a real `/sys` is UNRUN (it belongs to
    the parent-controlled diagnostic proof). No raw path leaves the launcher.
  - Metadata is sampled next to the capture, never atomically with it.
  - There is no module loading, probing, mutation, dmesg or network path.
- **Ownership registry.**
  - After each successful veth creation, the fixture appends two entries to `ownership.raw.jsonl`
    beside the records. Each entry holds:
    - the requested name/MAC commitments;
    - a read-only post-creation listing of the endpoint in its own namespace (by descriptor), run by
      the launcher's bounded command on a thread inside that namespace: at most 4097 bytes in 2 s,
      and its length is checked before any split or parse (more than one line is unobserved);
    - the L/R and outer namespace commitments.
  - The registry is supplementary only: it is not a case, record or verdict, and the
    18-case/eight-record inventory is unchanged.
  - Transfer out of the namespace (R4). The original JUnit/records copy loop is unchanged (its exact
    945537 bytes, whole-file reads). The registry is no longer in that loop: `handoff_ownership`
    reads it with the same reader the host child uses (`read_ownership`) before anything is
    allocated for its contents or copied. The source must be a regular file opened `O_NOFOLLOW` and
    `O_NONBLOCK`, at most 64 KiB by its size before any read, never more than 64 KiB + 1 bytes read,
    with bytes read equal to its size and identity, size and times unchanged after the read. An
    absent registry is not written (the host reports `ownership_missing`, as before). An oversized,
    non-regular (FIFO, directory), symlinked, short, growing or rewritten source is refused: the one
    byte `\xff` marker is written in its place, so the host reports `ownership_invalid`, never any
    of the refused bytes. The host child reads the copy again with the same reader; its own refusal
    is the same marker.
  - Delivery (R5). The copy and the marker are written by `deliver_ownership`, not H1F's shared
    `_write_out` (unchanged, and still used by the legacy loop and `inner.json`). The payload must be
    1 byte to 64 KiB. The destination name is created with `O_CREAT|O_EXCL|O_NOFOLLOW|O_NONBLOCK`
    relative to the host's out directory descriptor, so any existing entry there (a FIFO, symlink,
    directory or file) is refused at the open, which never follows, truncates or waits for a reader;
    the descriptor must then be an empty regular file with one link, owned by the writer. A short
    write is continued from the next byte; a zero, negative or over-long count, any write error
    (`EFBIG`, `ENOSPC`, `EIO`, ...) and any exception raised by a signal handler fail the transfer,
    as does a final size different from the payload. On failure the created file is emptied through
    its own descriptor, its name is unlinked only while it is still that file, and the error is
    raised: `_inside` exits 70, so the gate's child exit is nonzero (FAIL), and the host finds no
    registry (`ownership_missing`, incomplete) or, if the destination entry was preexisting, refuses
    or reads that entry as it is. A valid prefix is never left as the registry by this writer.
    Limits: regular-file writes are kernel I/O with no deadline here (`O_NONBLOCK` has no effect on
    them, and Python retries `EINTR` unless a handler raises); the writer bounds the bytes and the
    loop, not wall-clock time. The best-effort cleanup can itself fail (then a prefix may remain, but
    the transfer has still raised and the gate still fails). A preexisting entry is evidence that
    something else wrote the private out directory; it is refused, not diagnosed.
  - The change detection is a same-descriptor comparison of `fstat` before and after one bounded
    read. It does not detect a same-size rewrite whose modification and change times are both
    unchanged (finer than the file system's timestamps), and it is not a lock: the registry stays a
    bounded, supplementary, correlation-only input either way.
  - The registry records creation in a fixture namespace only. No capture witnesses that endpoint's
    later existence, move into the host or teardown, so proof (lifecycle) identity is never
    asserted: `proof_identity` is `unknown`. A reused name/MAC, a stale record, a moved endpoint and
    a separate hardware lookalike are indistinguishable here.
  - `correlation` is `fixture_name_mac` when exactly one corroborated entry's name and MAC
    commitments both match a link that was added in the audit pair and was absent from both
    baselines. It is a correlation only, reported beside (never instead of) the hardware class.
    Two or more such entries give `ambiguous`.
  - A name prefix, MAC alone, ifindex/iflink equality, link type or module never sets it. Index
    reuse, a registry entry that claims the host namespace, an unobserved entry or an invalid
    registry give `none`. The fixture namespace, ifindex and iflink stay bounded registry data;
    their presence alone proves no continuity.
  - Completeness (`complete`) describes the captures and inputs only, never attribution certainty.
  - Reading the registry (R3, R4): the file is read as above; then at most 32 lines (newline
    separated; the final newline is optional), each at most 2048 printable-ASCII bytes, are counted
    and shaped before any decode or JSON parse. More than 32 lines is `ownership_cap` with nothing
    parsed.
- **Limits and reasons.**
  - Limits: 64 links per capture, 4096 characters per line, 65536 scanned characters per capture,
    3 captures, 32 fixture endpoints, 64 changed entries, 16 fields per link, 64-character driver
    tokens, 64-hex commitments, and 256 KiB payload (over that, details are dropped with
    `payload_cap`).
  - The gate still hashes the whole original output (the one unchanged exception: H0's own digest).
  - Early bounds (R3): every diagnostic input is bounded before work that grows with it. The parent
    reads `cleanup.raw.json` only as a regular file of at most 1 MiB by its size (bounded read, before
    any decode or JSON parse); larger, not regular or a symlink gives no cleanup fields (the gate
    fails closed) and `diagnostics_invalid`. The parent's closed check requires exact JSON types and
    checks dict key counts, list lengths, set cardinality and every string's length before any
    traversal, membership, hash, set or sort.
  - Every overflow, unsupported syntax, enrichment failure, namespace mismatch, collector or observer
    failure and ownership gap sets `complete=false` with a closed reason.
- **Acceptance.** `evaluate` is unchanged and its verdict is reported as `gate_result`. A gate PASS
  with incomplete diagnostics is held as FAIL (`diagnostic_hold link_diagnostics_incomplete`), and
  no other result moves.
- **What it does not prove.**
  - A change class describes an observation, not who caused it.
  - `hardware_backed_change` means observed device evidence, not provider responsibility. A device
    can still be changed by proof-triggered shared-kernel effects.
  - An endpoint registry cannot attribute every transient event.
  - Hardware correlation alone never justifies a retry.

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
