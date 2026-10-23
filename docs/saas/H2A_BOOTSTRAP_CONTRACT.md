# H2-A generation bootstrap contract

Status: source candidate, awaiting independent review. Component evidence only: no runtime verdict,
no deployment, no launch claim. **HOLD** remains on H2-0, H2-1, H3 and launch until this change is
independently reviewed at its commit. It adds no `Enablement` member, no customer mode, no
environment variable, flag or entry point, and it installs no rules.

## What H2-A adds to `deploy/host/cycle.py`

A typed, cycle-owned, pre-ready boundary between one H1 generation and two H3 processes that do not
exist yet: the **bootstrap worker** (installs the generation's gate table in its namespace) and the
**root controller** (sole writer of the slot's root `enabled` marker). The cycle runs no caller
code: there is no bootstrap callback. Everything below is the cycle's side of the wire.

- `BootstrapChannel(worker=…, controller=…)`: two connected AF_UNIX `SOCK_DGRAM` sockets, distinct
  (different socket identities). The constructor adopts both descriptors (the caller's socket
  objects are detached), so only the channel can close them. Anything else raises
  `bootstrap_channel_invalid` and adopts nothing. The controller socket never reaches the worker;
  that the peers are the real H3 worker and root controller is H3's obligation.
- `HostCycle.register_bootstrap(channel)`: one channel for the next generation, only while the
  phase is `created` or `closed`, never after a quarantine, never a channel already claimed or
  closed; otherwise `bootstrap_registration_refused` and the channel stays the caller's. The first
  registration puts the cycle in **registered mode for good**: a later `start()` without a fresh
  registration raises `bootstrap_unregistered` before any generation is spent. It never falls back
  to the legacy `ready`. A start refused before the hand-off (budget, profile, K9, witness, …)
  closes its unused channel; nothing was sent on it.
- `GenerationBootstrap`: frozen record of what the worker learns, published as its request:
  `generation_id`, `namespace_identity` (`st_dev`, `st_ino` of the domain's descriptor), `slot_id`,
  `slot_hop_src`, `slot_hop_dst`, `bootstrap_fence` (fresh 128-bit per generation). No path, PID,
  domain object, `operation_nonce` or controller capability.
- `HostCycle.bootstrap_status()`: fixed tokens `mode` (`legacy`/`registered`), `registered`,
  `state` (`none`/`pending`/`receipted`/`cancelled`/`unresolved`), `root`
  (`none`/`not_armed`/`armed`/`absent`/`unknown`, the controller's word only), `worker`
  (`none`/`not_contacted`/`contacted`/`reaped`/`unresolved`/`unknown`). `status()` keys are
  unchanged; `generation_phase` gains `bootstrapping` in registered mode only.

A legacy `NON_CUSTOMER` caller that never registers keeps the accepted H1 lifecycle, events, status
keys and proof behaviour unchanged. H3 must require registered mode; nothing here can enforce that.

## Sequence (one absolute monotonic deadline)

At the old `ready` point (after domain, self-test, profile, K9 and witness), under the cycle lock,
the cycle takes **one** `os.dup(domain.ns_fd)` and gives it, the channel and a fresh
`operation_nonce` to the generation's private `_Handoff`, with
`deadline = now + BOOTSTRAP_DEADLINE_MS` (5000 ms). The phase is `bootstrapping`: `install_context`
is refused, `start` is `generation_active`, `tick` does nothing, `stop()` / `stop_context()` record
the request, and `status()` reads normally. `start()` then runs the hand-off
outside the cycle lock:

1. controller ← `{"schema":"heel.h2a.controller.v1","op":"arm",generation_id,namespace_dev,
   namespace_ino,slot_id,bootstrap_fence,operation_nonce,deadline_monotonic_ns}`; it must answer
   exactly `{schema,"op":"armed",generation_id,bootstrap_fence,operation_nonce}`. No descriptor
   leaves the cycle before this ack.
2. worker ← the `GenerationBootstrap` request (`"schema":"heel.h2a.bootstrap.v1"`) plus the
   duplicate as `SCM_RIGHTS`, after `fstat` confirms the duplicate's identity. The cycle closes its
   duplicate right after that one `sendmsg`; the kernel holds the in-flight copy.
3. worker → exactly `{"schema":"heel.h2a.receipt.v1",generation_id,namespace_dev,namespace_ino,
   bootstrap_fence,"installed":true}` as canonical bytes (sorted keys, no whitespace, no
   duplicates, no NaN, ≤ `MAX_BOOTSTRAP_BYTES`, no ancillary data), read before the deadline with
   no stop requested. Exactly one datagram is read. Strings are compared in constant time.
4. Success: both sockets are closed (single use), the phase becomes `ready`, event `ready`, then the
   usual poll point (a stop that arrived after the receipt ends the generation at once). The
   controller is told nothing more; its nonce expires at `deadline_monotonic_ns`.

Receives and sends poll the stop flags (`stop`, `stop_context`, the signal flag) at least
every `BOOTSTRAP_POLL_MS` (50 ms): each socket operation is given at most one 50 ms slice, and a
send to a full peer queue (which may block, as observed on macOS for the hand-off send, or be
refused with `ENOBUFS`/`EAGAIN`) is retried slice by slice until the deadline, never one wait as long
as the deadline. The revoke ignores the stop flags
and is bounded by `REVOKE_DEADLINE_MS` alone. Receipt matching is total: any datagram, including
ASCII bytes that escape non-ASCII or lone-surrogate strings, is accepted or refused, never an
exception. Every received descriptor is closed before the message is looked at,
and a message that carried one is refused. Nothing received is logged, kept or raised: logs and
status carry fixed tokens only.

## Cancellation

Timeout, stop, transport error, late, malformed, mismatched, `installed` not `true`, or a replayed
receipt (another generation's fence) is a cancellation, not an after-the-fact observation:

1. burn the duplicate (closed if not yet sent; it can never be issued again:
   `bootstrap_capability_spent`) and close the worker's socket (a late receipt cannot be delivered);
2. if the arm was sent, controller ← `{…,"op":"revoke",generation_id,namespace_dev,namespace_ino,
   slot_id,bootstrap_fence,operation_nonce}` (same nonce), and read one ack within
   `REVOKE_DEADLINE_MS` (1000 ms): `{…,"op":"revoked","enabled":"absent","worker":"reaped"|"unresolved"}`;
   then close the controller socket and forget the nonce;
3. under the lock: `revoked`+`reaped` (or an arm never sent) → `close_generation()` through the
   normal path, `start_refused:h2_bootstrap_failed` (`generation_class_end = start_refused`,
   `last_reason = h2_bootstrap_failed`). Anything else (no ack, malformed ack, `worker:"unresolved"`)
   → `lost_child`, quarantine `bootstrap_unresolved`: terminal for the process, no new generation,
   no zero-residual claim.

An exception escaping the hand-off closes the duplicate and channel, quarantines
`operation_interrupted` and is re-raised. `ready` and `install_context()` are never reachable while
pending, failed or unresolved.

## Boundary statements (what this is not)

- The worker is not a child of the cycle's process, and the H1 registry's public API
  (`unresolved_children`, `sweep_unresolved_children`) only reads. So H2-A does not reap the worker
  through the H1 registry. The worker's end comes only from the controller's typed `revoked` ack.
  An unknown or `unresolved` worker follows the existing terminal quarantine and no-new-generation
  path. Amendment to the draft: "reap it through the same child registry H1 uses" becomes "the root
  controller reports reaped/unresolved under the burned nonce; unknown is quarantine".
- The namespace descriptor goes to the worker only. Handing it to the root controller for the fd-only
  veth request (design addendum §4) is H3 work. A worker that holds its copy, or never reads the
  in-flight copy, keeps the namespace alive. `close_generation()` closes only the H1 owner
  descriptor. This is **not a claim** that the namespace is destroyed.
- The root controller and the worker exist in no production code today. The fakes in the tests only
  speak the wire. Nothing here proves that a root `enabled` marker is removed, that kernel state is
  revoked or that a stopped worker is reaped. Root `enabled` removal at the end of a *successful*
  generation is H3's, together with the receipt's authenticity: the receipt is bound by the
  connected socketpair and the per-generation fence, not by a cryptographic signature.
- No DNS, target-set, nft, network-policy or veth behaviour is implemented (H2-0/H2-1/H3).

## Tests

`tests/test_host_cycle.py`, the `test_bootstrap_*` functions. They use real unprivileged AF_UNIX
datagram socketpairs and real `SCM_RIGHTS` passing of the harness's stand-in descriptor (a regular
file, never a namespace), and one real `python -I` subprocess as the receiving process.
`FakeController` and `FakeWorker` are labelled **CONTRACT FAKE**: they stand in for the future H3
processes, and their "absent"/"reaped" words are scripted. The tests cover the success ordering
(receipt before `ready`), one-owner descriptor accounting via `/dev/fd` identity counts, the worker
never seeing `operation_nonce`, 18 malformed/mismatched receipts (including escaped non-ASCII and
lone-surrogate strings), the totality of receipt matching, deadline/late/descriptor-carrying/
junk-then-valid replies, a full worker queue (stop cancels within slices; a queue that drains
in time still succeeds), concurrent `stop`/`stop_context`/signal flag while the lock is free, arm
without ack (no descriptor sent, revoke still sent), unresolved/silent revoke → quarantine with no
reaped claim and no new generation, the late writer and cross-generation replay, registration rules
and no legacy fallback, the typed channel, an escaped exception, and this document.

## Validation (recorded by the implementing session)

Interpreter `/Users/hellohelloalbus/.cache/heel-h1f-venv/bin/python` (Python 3.13.5, pytest 9.0.2),
macOS (Darwin 24.1.0), `TMPDIR` a short external directory.

| Command | Before H2-A (63c6096) | After |
|---|---|---|
| `python -m pytest tests/test_host_cycle.py -q -p no:cacheprovider -k bootstrap` | none | 38 passed |
| `python -m pytest tests/test_host_cycle.py -q -p no:cacheprovider` | 131 passed, 2 skipped | 169 passed, 2 skipped |
| `python -m pytest tests/test_host_*.py -q -p no:cacheprovider` | 296 passed, 197 skipped | 334 passed, 197 skipped |

The two skips in `tests/test_host_cycle.py` are the Linux-only real-control-plane tests. The full
suite result and the Linux CI requirement are in the implementing session's closing report, not
here.
