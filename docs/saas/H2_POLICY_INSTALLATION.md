# H2-1 generation policy installation

Status: source candidate, component evidence only. No runtime verdict, no deployment, no customer
enablement and no launch claim. **H2 remains HOLD** until a fresh Fable source review of this commit,
the separate H2-2 isolated Linux proof and its runtime review. This change adds
no `Enablement` member, no customer mode, no environment variable, flag or entry point, no daemon or
runner wiring, no controller/worker protocol change and no production bypass. Contract: H2-POLICY-FABLE-REFRESH
`DECISION.md` revision 5, sections 4 and 6.1, with Astra's design disposition, amended by **H2-3**
(accepted H3 composition design `b168458c`, section 8.1): one fixed control accept and the
`control_only` shape (below). H2-3 is a source candidate too: it needs a fresh Fable source review,
a fresh closed-set digest and a reviewed Linux run of the existing H2-2 job on its own bytes; no
earlier runtime evidence covers it.

`deploy/host/h2_policy.py` is the policy builder, installer and readback oracle the future H3
bootstrap worker calls after H2-A hands it one generation namespace descriptor. It loads
`deploy/host/authority.py` and the codec of `heel/saas/host_authority.py` by file path, under the
same module names the cycle uses, and reads only their public names.

## Input ownership (`H2PolicyInput`)

A frozen, slotted, keyword-only local worker type, not a wire schema. Construction validates it
(`build_input(**fields)` raises `ValueError(token)`); no field can be invented.

| Field | Owner / source | Validation |
|---|---|---|
| `generation_id` | `GenerationBootstrap.request()` | `[0-9a-f]{32}` |
| `namespace_identity` | request `(namespace_dev, namespace_ino)` | two non-negative ints |
| `slot_id` | request | ASCII, 1-80, `[a-z0-9][a-z0-9_.:-]*` |
| `slot_hop_src`, `slot_hop_dst` | request (= the H1 lease-key `src`/`dst`) | canonical dotted IPv4, distinct |
| `bootstrap_fence` | request | `[0-9a-f]{32}` |
| `egress_hostname`, `egress_port` | the validated `CycleContext` | lowercase hostname characters; port exactly 443 |
| `observed_public_addresses` | trusted constructor (H3) | canonical shape only, below; `()` iff `control_only` |
| `control_only` | the H3 worker's `pin` (H2-3), keyword-only, default `False` | exactly a `bool` (`control_only_invalid`) |
| `ipv4_egress_targets` | derived: the IPv4 members | never passed in; empty means IPv6-only, or the control-only shape |

**Trust precondition (H3, trusted constructor):** `observed_public_addresses` is the tuple the unchanged `select_public_addresses` returned for the preflight of the validated `egress_hostname`, unmodified.

The builder enforces shape only: every element is an `IPv4Address` or `IPv6Address`, the tuple is
strictly increasing by `(version, packed)` (no duplicates), and 1 to 16 long; under `control_only`
it is exactly the empty tuple. The two are a biconditional: `()` without `control_only` and
`control_only=True` with any non-empty tuple (IPv4, dual-stack or IPv6-only) are both
`observed_public_addresses_invalid`; an IPv6-only tuple without `control_only` stays
`unsupported_ipv6_only` at render and install. It performs no DNS or
network request, imports no resolver and never judges public-ness; a sorted private tuple passes the
shape check, and only the precondition above keeps it out. Route, method, budget, scope expiry,
claim, bundle, nonce, path, PID and controller capability are not fields.

## Policy shape

One table, four rules, two accepts, both key uses carrying the typed gateway of the slot's `dst`:

```
table inet heel_lease {
  set prepared { type ipv4_addr . ipv4_addr . mark ; flags timeout ; }
  map activated { type ipv4_addr . ipv4_addr : mark ; }
  chain gate {
    type filter hook output priority 0 ; policy drop ;
    meta mark set 0
    meta mark set ip saddr . (ip daddr & 0.0.0.0 | <slot_hop_dst>) map @activated
    ip saddr <slot_hop_src> ip daddr <slot_hop_dst> tcp dport 443 accept
    ip saddr . (ip daddr & 0.0.0.0 | <slot_hop_dst>) . meta mark @prepared ip daddr { <sorted IPv4 targets> } tcp dport 443 accept
  }
}
```

The target set is compile-time data from the validated input. H1 alone writes `prepared` and
`activated` elements through `LeaseDomain`'s public API; this module writes none. No NAT, redirect,
forward or input chain, second table or chain, accept other than these two, dynamic set mutation,
IPv6 accept or `ip6` rule. IPv6 drops by the chain policy, which is not an IPv6 coverage claim.

**H2-3 control accept.** Immediately before the target accept, one rule admits the slot source to
the slot gateway itself on TCP 443 (the per-slot runner control listener the executor's control
transport dials). It has no mark condition, no set or map reference and no lease: one fixed source,
one fixed destination (`slot_hop_dst`, the same literal as the typed-gateway key) and one port. It is
not generic or wildcard forwarding: nothing else is admitted to the gateway (another port, UDP,
another source, IPv6), and the target accept, the typed gateway key, the single table and the exact
readback keep their semantics. The host-side INPUT restriction to that gateway and port is H6's.

**H2-3 control-only shape (`control_only`).** A binding generation, whose origin is not yet known,
installs the same table without the target accept: three rules, one accept (the control accept).
`render_table`, `install()` and the readback accept an empty IPv4 target set only under
`control_only`.

## Dual stack

The full canonical tuple is retained for the unchanged client's equality check; the kernel allow
list is its IPv4 members only. A tuple with no IPv4 member returns `unsupported_ipv6_only` before any
launch. A mixed set's client selection is the lowest IPv4 (`current[0]`); AAAA is never dropped from
the comparison.

## Lifetime: helper, descriptors, deadlines

Each nft step (check `-c -f -`, install `-f -`, readback `-j list table inet heel_lease`, cleanup
`-f -` with `delete table inet heel_lease`) is one `subprocess.Popen` of a fresh Python helper
`[sys.executable, -I, -S, -B, -c, _HELPER_SOURCE, <dup fd>, NFT_PATH, <args>]` with no `preexec_fn`,
`close_fds=True`, `pass_fds=(dup,)`, `cwd="/"` and the fixed environment `PATH`/`LC_ALL=C`. The
parent never calls `fork`. The production helper imports `os` and `sys` only and always runs one
sequence: `setns(fd, CLONE_NEWNET)`, close the duplicate, `execve` nft. Its only outputs are exit
codes `124` (argv, `helper_argv_invalid`), `125` (`setns_failed`) and `126` (close/exec,
`helper_exec_failed`); any other nonzero code is nft's and is classified by phase.

| Resource | Created by | Closed by |
|---|---|---|
| received namespace fd | H3 | H3 after a terminal outcome; the installer only `fstat`s and `dup`s it |
| one duplicate per helper | the parent, checked by `fstat` against the input identity before the hand-off | the parent right after `Popen` returns or raises; the helper closes its copy before `execve` |
| helper stdin | `Popen` | written non-blocking (at most 4096 bytes) under the deadline, then closed |
| helper output | `Popen` | drained non-blocking to `MAX_OUTPUT_BYTES` under the deadline, then closed |
| helper process | `Popen` | polled to the deadline; SIGKILL; reap grace; else kept in the unreaped list |

The received fd's identity is checked at entry, each duplicate's identity is checked before it is
passed (a borrowed fd closed and its number reused cannot substitute another namespace), and the
received fd is checked again before a receipt.

Budgets are algorithmic monotonic budgets from `install()` entry (injectable `clock`): each helper
at most 1000 ms with its startup included plus a 250 ms reap grace after the SIGKILL; check, install
and readback together 2500 ms (`H2_INSTALL_BUDGET_MS`); the failure cleanup at most 1000 + 250 ms;
the worst-case return `H2_WORKER_BUDGET_MS` = 2500 + 250 + 1000 + 250 = 4000 ms. Two OS
assumptions are named, not hidden: process creation (until `Popen` returns) is not interruptible and
is charged to the phase, so a slow creation can only end in `timeout`; and a SIGKILLed child is reaped
within the grace unless the kernel holds it, in which case it is quarantined. An exit observed after
its deadline is never a success. The worker learns no deadline from the cycle, so a success receipt
is not promised in time; a late one is harmless because the cycle's cancellation and revoke stay
authoritative.

## States and the receipt

Success: `new` → `identity_ok` → `checked` → `installed` → `readback_ok` → `receipt_ready`.
Failure states (fixed tokens, never nft text or addresses): `refused_input`, `refused_platform`,
`refused_reused_input`, `unsupported_ipv6_only`, `identity_mismatch`, `helper_argv_invalid`,
`setns_failed`, `helper_exec_failed`, `check_refused`, `install_refused`, `readback_mismatch`,
`timeout`, `cleaned`, `quarantined`.

- After an install was launched, a failure runs one bounded cleanup only if the failed child was
  reaped (its exit is known) and the namespace identity still matches: success is `cleaned`,
  anything else `quarantined`. Before an install was launched, nothing is cleaned. An unreaped child
  is `quarantined` and counted by `unresolved_helpers()`.
- The readback is exact for the named table only: metainfo, the table, the empty typed `prepared`
  set and `activated` map, the output/drop chain and exactly the rules in the order reset, lookup,
  control, admit (eight items after the metainfo; seven, the admit absent, iff `control_only`), the
  typed gateway readback `(ip daddr & dst) | int(dst)` in both keys, the control rule's `expr` exactly
  `[ip saddr == src, ip daddr == dst, tcp dport == 443, accept]` (no `meta`, no set reference, `dst`
  byte-equal to the key's literal), exactly the input's IPv4 targets and TCP 443. The readback part
  tokens gain `control_rule` between `lookup_rule` and `admit_rule`. Handles are ignored; the
  enumerated alternative encodings are a `timeout` flag as a string or list, a mark of 0 as an
  integer or `0x00000000`, `==` or `in` for the two set lookups and the control source, and one
  target as a bare string or a one-member set. Anything else is `readback_mismatch`. Whether the namespace holds
  other tables is an H2-2 fixture check (`nft -j list ruleset`), not a product claim. The exact nft
  1.0.9 listing is confirmed only by H2-2.
- `Outcome(state, receipt, tokens)` is frozen and sealed: constructing it outside the module raises
  `TypeError`, and `receipt` is bytes if and only if the state is `receipt_ready`, reached only after
  the exact readback and the final identity check. The receipt is the canonical H2-A receipt
  (`GenerationBootstrap.receipt()`); there is no public receipt factory.
- There is no negative receipt: every failure sends nothing, and the cycle's deadline and revoke do
  the rest. H2-1 has no sending API.
- `install()` is single-use per `(generation_id, bootstrap_fence)` in the process
  (`refused_reused_input` without a launch); `cleanup()` acts only after `receipt_ready` and is a
  no-op on a cleaned, quarantined or never-installed input.

Public surface, exactly: `build_input`, `render_table`, `readback_matches`, `install`, `cleanup`,
`unresolved_helpers` (plus the record types `H2PolicyInput` and `Outcome`).

## Platform and test seams

`install()` and `cleanup()` return `refused_platform` before any launch unless the platform is Linux
with `os.setns`, `NFT_PATH` is an absolute path and `sys.executable` is absolute. No environment
variable, flag or input can bypass this; macOS never enforces a namespace. The private seams
`NFT_PATH`, `_PLATFORM_OK` and `_HELPER_SOURCE` are assigned only by `tests/test_host_h2_policy.py`:
unprivileged tests point `NFT_PATH` at an owned fake nft and replace only the `setns` line of the
helper with a labelled no-op, so the real launch, pipe, deadline, kill and reap paths run. Ordinary
Linux CI runs the unmodified production helper to its `setns` failure on a regular file (exit 125).
Source unit seams are never packet-path proof.

## Non-goals and later gates

- **H2-2** (separate fresh task after this source review): the isolated Linux proof with a real
  namespace and nft, the whole-ruleset fixture check, the staged `heel/` closure and the mandatory real
  unchanged `TargetHTTPSClient`/TLS case. Nothing here was run in a namespace or against nft.
- **H3** obligations, proven by H3's own tests against the real cycle:
  `test_worker_sends_receipt_once_only_from_receipt_ready`,
  `test_worker_failed_send_is_final_cleanup_once_no_reinstall`,
  `test_worker_cleanup_order_against_close_generation_is_the_contracted_one`,
  `test_worker_is_supervised_under_the_cycle_deadline_and_revoke`,
  `test_worker_reports_unresolved_when_unresolved_helpers_is_nonzero`. Teardown order after a
  successful generation against `LeaseDomain.close_generation` is H3's.
- **H6** provider, host and kernel qualification; hosted deployment; real authorized SaaS acceptance;
  the final Fable gate. C3 (provider-refused discovery parser) stays STOP.

## Gates (section 5)

1. Source review: this offline commit (module, tests, this document) is a review candidate, not
   acceptance. Astra publishes it and a fresh Fable source review checks the exhaustive file list,
   public-API-only use, no invented fields, no unsafe flags and the unchanged H2-A receipt.
2. Runtime: only after 1 passes, H2-2's fixed launcher job is dispatched by Astra and its artifact
   gets an independent runtime review.
