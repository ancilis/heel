# Managed host handoff (H6-IF): container boundary, aggregate storage, enrollment and the trusted lifecycle fence

2026-11-04. GPT-6 Astra (medium), bounded H6-IF **R3** design correction from
`256242f807bef3a6d85daf66fcfca92922f523f2` (R2, independent FAIL R2-F1).
The project owner approved one extra design/review cycle after the initial `b12eefe`, R1 `324ba03` and R2 failures.
Those three H6 failures and the three original C4 failures remain recorded. Another failure returns to
the project owner; no automatic next cycle. R2's Opus authorship and prior repairs are retained as history.
**Interface-only candidate. Fresh independent whole-interface and Q/EA-amendment review pending. Not
accepted. Every ownership/requirement amendment below is a proposal awaiting that review; this author
accepts nothing. No implementation, provisioning, runtime, restore, image, release or provider claim.**
All B0/H2/P01/H3/Worker source, CI, integration and runtime gates remain; C3 STOP is unchanged.
All 25 real oracles, 15 customer outcomes and 12 safety properties remain mandatory.

## 0. Status, precedence and tags

H6-IF is the milestone at P line 162. It freezes the host contract consumed by P02 (schema, §8), P05/P06
(capacity §5, enrollment authenticator §7), P11/P12 (storage, slots, markers, root signer), P14 (fence,
gate, offline modes, verifier), P15/P16 (real proof), H6-LAUNCH/H6-RUNTIME/H6-IMAGE and P17. It widens no
Q/EA/S/P bound. It **does** propose one explicit Q/EA transport-authentication amendment (§7, A-ENR2)
that adds no body field, route, digest, receipt or method; that amendment is pending independent review
and is not in force by virtue of this document. It does not choose H3 architecture.

| Alias | Pin | Use |
|---|---|---|
| P | `38e6bf1a3bc6ed2d923f878561140cda928b56d0` tree `385b47e67c236aa0ce633d328dd6306ba8e1b405`, plan blob `8950b27ac8f64bde5cc4a1190772af9f530e7806`, SHA-256 `405984bc838c04eb1f7f7338f0687cd0fd7db951a3dc5776b6489d7bc1812d2c` | Accepted plan (C4-PRIVATE-PLAN-COUNT-R1-REVIEW PLAN-AMENDMENT-PASS). Supersedes `806dee1`/`f3721d2` on private paths/counts: 36 chain, 60 grant rule, 73 admission, 78 storage, 93–94 bounds/custody, 116 counts (106 entries, P11 = 7+3), 118 separate three-path inventory packets, 162 H6-IF row, 165–173 handoffs/topology, 175–191 private delivery contract, P02 220, P05 302, P06 329, P09 415, P11 476, P12 511, P14 567, P15 596, P16 623, P17 650, P18 686, outcomes 718 |
| Q | `46cefba00192ea5fe3efb663fea89ee9561b6422` | Accepted admission design: §3 56–68 (three managed routes), §6 110–140 (caps: W 2048, Q 2560, ceremony 4096, responses 4096, head 8192), §7 142–154, §8 172–174 |
| EA | `c54f872a48f5ea85eab2b0279074b800e1519a61` | Retained §4 ceremony channel 110–121, §5 capacity 122–143, §6 removal/migration 145–172, §7 restore 174–190 (182 fresh 256-bit enrollment secret, 184 old-host rejection, 186 same-pending-id recovery) |
| S | `2a71221704f3b7b5d1f893df6ced5fb972b2cf57` | Retained custody/ceremony only: §4.1–4.2, §4.8 565–575, §4.9 576–637, §5 704–728, §14.2 |
| B | `f736279a33bc1b8bd094e301ddd52045eb96a149` tree `6274eb979880bec238fe7058d43597794c96880b` | Accepted main (`server.py`, `host_authority.py`, `compose.yaml`, RUNBOOKS, Customer spec) |
| Customer | B `docs/superpowers/specs/2026-10-19-customer-ready-self-serve-launch.md` | §2.4 custody 183–190, §5.2 deployment 489–519, §6.1 twelve properties |
| M | `86c612a7ada2f8cd563936c4b9ce0e15d5061c31` | Accepted H1/H2 lineage, unchanged |
| H | `d929888271ab2f14236ffc68a7d906c49fe48138` | **UNACCEPTED** H3 candidate; inventory only |
| BIR | `.worktrees/heel-task-evidence/CONTROL-PLANE-BUILD-INPUT-REVIEW/REPORT.md` SHA-256 `1575d215…edfb945` | Accepted CP immutable-build-input design and temporal ownership amendment (§10). B0 `5eefa25` implementation is **not** accepted (review waiting) |
| REV1 | `.worktrees/heel-task-evidence/H6-HOST-INTERFACE-REVIEW/REPORT.md` | Original F1–F7 |
| REV3 | `.worktrees/heel-task-evidence/H6-HOST-INTERFACE-R2-REVIEW/REPORT.md` | R2-F1 actual artifact omitted on ordinary startup; precision notes retained below |
| REV2 | `.worktrees/heel-task-evidence/H6-HOST-INTERFACE-R1-REVIEW/REPORT.md` | R1-F1–R1-F4 and nonblocking grammar items closed here |
| ENR | `.worktrees/heel-task-evidence/H6-ENROLLMENT-DECISION/{DECISION,AMENDMENT-DRAFT,OWNERSHIP-TEST-MATRIX}.md` | Separate Astra trust decision, **FEASIBLE-TO-SPECIFY only, unaccepted**; selected by the parent as the proposed basis for §7 |
| P01C | `df903403` | Active P01 private code correction; not accepted; no file of it is changed or assumed here |

Tags: **[B]** fact at B; **[H]** fact only in unaccepted H; **[R:x]** retained requirement of x;
**[P]** proposed contract value awaiting review and, where stated, runtime measurement; **[U]** unknown
until an authorized real qualification (§11). A **[P]** value is never runtime fact. **CONFIRMED**
claims cite a pinned source line or a task witness; **INFERRED** claims name their next proof.

Discovery: R3 graph search/architecture resolved current `build_server`, not proposed
`evaluate_startup_gate`; immutable base Git and retained reviews govern this documentation revision.
R2 discovery: graph-first. `search_graph` (project `local repository graph`) resolved
`heel.saas.server.build_server` and `ProductionConfiguration` but not the host-authority framing or any
pinned revision; fixed-Git `git show <pin>:<path>` supplied every cited line (B
`heel/saas/host_authority.py:39–47,236,350–424`).

## 1. Correction index

| Finding | Closed by |
|---|---|
| R2-F1 actual artifact on every launch | §7.4a host measurement of the exact live child, immutable artifact lease, private one-launch observation, ordinary gate rows 3a/11a; E16–E20; A-ART3 (proposed) |
| R1-F1 enrollment trust, missing config gate input, pre-completion smoke cycle | §7: distinct 32-byte K, request-bound HMAC header on the three Q routes in addition to SO_PEERCRED; trusted `EnrollmentObservation`/`VerificationObservation` gate inputs (§6.7); listener-free actual-consumer verification over private pipes with root process/mount inspection (§7.4); acyclic ack → complete → listeners → edge smoke; operation-identity reconciliation (§7.5); K replacement only by domain replacement |
| R1-F2 committed reconciliation cannot resume | §6.6 durable reconciliation **result** stored in the domain row in the same transaction; exact same-operation recovery predicate (§6.7) for bootstrap, migration, pre-domain and domain-bearing restore; receipt = stable result + fresh check; §8 closed DDL extension inside P02's four paths; pre-domain provenance variants (§6.10) |
| R1-F3 partial creation and uncertain serving publication | §6.1 idempotent pristine-L creation/repair (never unlink/replace); §6.4 durable operation intent (same key/epoch reuse); §6.3 publication journal J: no reader serves while J is visible; fresh-inode rewrite after any failed fsync; `recover_publication`; §6.9 crash-cut tables for initialize, adopt, complete, leave-maintenance, config and receipt |
| R1-F4 inode exhaustion | §5.5 kernel-enforced ext4 usrquota inode hard limit for the executor uid leaving a 64-inode root reserve inside the existing 32 MiB device (no extra bytes); worst-case root obligations 27 inodes / 179 blocks; capability probe with refusal `slot_inode_reserve_unavailable`; H6-RUNTIME/P12 real oracles |
| REV2 nonblocking | §3.4 device-size bound/immutability for every layout entry; §6.6 field-grammar vs accepted physical maxima with `measured_free_inodes` 0..2^53−1; §9 counts **25** named oracles; §4.2/§10 private prefix `/opt/heel/deploy/host/executor.py` + `/opt/heel/heel/{runner,saas}`; §4.3 three artifact kinds; §12 recount |
| Original F1–F7 | Retained from R1 as amended below (container §4, aggregate §5, lock §6.1, closed records §6, markers §7.7–7.9, DAG §9, build-input §10) |

Withdrawn from R1: A-ENR (edge-credential interpretation, rejected by REV2/ENR); `/etc/heel/private/
enrollment-handoff`; `HEEL_MANAGED_ENROLLMENT_ID` env binding; authenticated smoke before ack; the
"crash-visible new record is always pending/maintenance" claim (R1 §6.7); `O_EXCL` lock creation with
"no lock file" precondition; resync-by-re-fsync; receipt v1 digest over physical measurements;
`secret_rotation` maintenance reason; host rootfs store under `/opt/heel/executor/rootfs`.

## 2. Principals and numeric UID/GID matrix

| Principal | Where | UID:GID | Groups | Basis |
|---|---|---|---|---|
| Host root: supervisor, worker, root ceremony/signer, H6 tools | host initial namespaces | 0:0 | n/a | [H] `supervisor.py:9`; [B] CP requires peer uid 0 (`server.py:306,354`) |
| Control plane (CP), P14 offline entries incl. verifier | CP container, identity uid map, own PID ns (`external-pidns`) | 10001:10001 | none | [B] `Dockerfile.control-plane:8–9`, `host_authority.py:47,165–172`, `server.py:306–313,354–357` |
| Lifecycle/fence/enrollment reader group | — | gid 10001 | — | [P] reuse of CP primary group |
| Ingress (nginx/njs H0) | host, P13-rendered | 10002:10002 [P] | none | gets no §3 path; never sees K or the enrollment header |
| Executor of slot ordinal n | per-workspace container (§4) | (71000+n):(71000+n), n ∈ 0..999 [P] | none | [H] `supervisor.py:124–131,244–245` |
| Signer / vault / raw-evidence writer | executor UID of that slot | same | — | [R:S §5 708–728; Customer 186; S 579–587] |

Invariants [P]: pairwise distinct; executor UID == GID; no executor in group 0, 10001, 10002, `docker`;
ordinal/UID/`slot_id`/`workspace_id` bound for the host lifetime (§3.4), never reused; ordinal 1000
exhaustion refuses. S 726–728 trust statement retained. K (§7) is readable only by uid 0 and gid 10001.

## 3. Host paths, modes and root records

### 3.1 Host namespace

Executor-related ancestors are root 0700 [R:S 569, 590–592]; the executor never resolves a host path (§4).

| Path | Type / bound | Owner:group | Mode | FS | Writer → readers |
|---|---|---|---|---|---|
| `/etc/heel/` | dir | 0:0 | 0755 | root FS | H6 provisioning |
| `/etc/heel/host-layout.json` | §3.4, ≤ 524 288 B | 0:0 | 0600 | root FS | H6 layout tool → H6 tools, P12 |
| `/etc/heel/.layout.lock` | empty, never replaced | 0:0 | 0600 | root FS | H6 layout tool only |
| `/etc/heel/executor-rootfs.json` | §4.3, ≤ 1024 B | 0:0 | 0600 | root FS | H6 layout tool → supervisor |
| `/etc/heel/slots/`, `<slot>.json` | ≤ 16 384 B | 0:0 | 0700 / 0600 | root FS | H6 static fields → supervisor [H] `supervisor.py:285–300` |
| `/etc/heel/maintenance/` | dir | 0:10001 | 0750 | root FS | H6 → CP (read-only bind) |
| `…/maintenance/lifecycle.lock` (L) | empty, never unlinked/renamed/replaced | 0:10001 | 0640, nlink 1 | root FS | §6.1 holders |
| `…/maintenance/fence.json` | §6.2, ≤ 2048 B | 0:10001 | 0640, nlink 1 | root FS | fence mutators → gate, offline entries, supervisors |
| `…/maintenance/fence.publication.json` (J) | §6.3, ≤ 4096 B, present only while a publication is uncertain | 0:0 | 0600 | root FS | fence mutators; every reader refuses while it exists (presence via `lstat`; dir search permission suffices) |
| `…/maintenance/enrollment-verified.json` | §7.4 receipt, ≤ 1024 B | 0:10001 | 0640, nlink 1 | root FS | `verify_and_record_enrollment` → gate |
| `…/maintenance/.*.tmp` | ≤ 1 per record kind | 0:0 or 0:10001 | 0600/0640 | root FS | removed under L(EX) before the next write of that kind |
| `/etc/heel/enrollment/` | dir, the **only** secret directory bound into a container (CP, read-only) | 0:10001 | 0750 | root FS | H6 → CP |
| `/etc/heel/enrollment/current.json` | §7.1 config incl. K, ≤ 1024 B, exactly one | 0:10001 | 0640, nlink 1, regular | root FS | H6 under L(EX) → CP loader, root signer/verifier |
| `/etc/heel/private/` | dir, never bound | 0:0 | 0700 | root FS | H6 tools |
| `/etc/heel/private/operation-intent.json` | §6.4, ≤ 1024 B, at most one; carries K only until ack | 0:0 | 0600 | root FS | H6 creators → H6 |
| `/etc/heel/private/receipts/<operation_id>.json` | ≤ 1024 B, ≤ 2 retained | 0:0 | 0600 | root FS | fence tool (provenance only) |
| `/srv/heel/deploy/.env.production` | edge/tunnel secrets only, never K | 0:0 | 0600 | root FS | operator [B] `compose.yaml:11–12` |
| `/srv/heel/volumes/` | preallocated backing images | 0:0 | 0700 | root FS | H6 layout tool |
| `/srv/heel/cp/<vol_id>/` | mount point = D_CP root | 10001:10001 | 0700 | D_CP `nodev,nosuid,noexec` | CP; root reads only for online backup |
| `…/<vol_id>/.heel-volume-id` | exactly 37 B (§7.8) | 0:10001 | 0440 | D_CP | H6 at volume creation → gate |
| `…/<vol_id>/control-plane.sqlite3` (+ sidecars, `.lock`) | SQLite | 10001:10001 | 0600 lock | D_CP | CP [B] `server.py:94–125,445–475` |
| `…/<vol_id>/host/`, `authority.sock` | dir / socket | 10001:10001 | 0700 / 0600 | D_CP | CP [B] `host_authority.py:271–305` |
| `/srv/heel/backups/` | ≤ 1 staged encrypted backup | 0:0 | 0700 | root FS | trusted backup job (§5.2) |
| `/opt/heel/` | immutable private runtime prefix for **host root** processes (§10) | 0:0 | dirs 0755, files 0644 | root FS, read-only after install | release provisioning |
| `/var/lib/heel/executor-rootfs/<hex64>/` | immutable executor rootfs store (§4.3), contains its own `/opt/heel` prefix | 0:0 | 0700 store dir; tree dirs 0755, files 0644/0755 | read-only mount `nodev,nosuid` | H6 `install-rootfs` |
| `/var/lib/heel/launch/<slot_id>/` | empty mountpoint | 0:0 | 0700 | root FS | provisioning; mounted only in the helper's private mount ns |
| `/var/lib/heel/slots/`, `<slot>/` | dir / D_SLOT root | 0:0 | 0700 | root FS / D_SLOT `nodev,nosuid,noexec,usrquota` | H6 provisioning [R:S 569] |
| `…/<slot>/.lifecycle.lock` | S per-slot lock | 0:0 | 0600 | D_SLOT | root ceremony [R:S 599] |
| `…/<slot>/ceremony.json` | ≤ 4096 B | 0:0 | 0600 | D_SLOT | P12 [R:S §14.2] |
| `…/<slot>/domain.json` | §7.7, ≤ 1024 B | 0:0 | 0600 | D_SLOT | P12 |
| `…/<slot>/executor-input.json` | ≤ 1024 B | 0:(71000+n) | 0640 | D_SLOT | supervisor → bound read-only |
| `…/<slot>/epochs/`, `epoch_<hex32>/` | dirs, ≤ 17 epochs | 0:0 | 0700 | D_SLOT | root ceremony [R:S 590–591, 612–615] |
| `…/epoch_<hex32>/home/` and `runner-daemon/identity.seed` | `HEEL_HOME`; 32 B seed | executor | 0700 / 0600 | D_SLOT | executor; root writer [R:S 312, 718–720] |
| `…/<slot>/vault/` | C5 vault | executor | 0700 | D_SLOT | executor [R:S 613] |

### 3.2 CP container

[B] `compose.yaml:21–29`: `/var/lib/heel` = read-write bind of `/srv/heel/cp/<vol_id>`; read-only root FS;
`/tmp` tmpfs 16 MiB; `cap_drop: ALL`; `no-new-privileges`. Added facts for P17 [P]: `/etc/heel/maintenance`
read-only bind at the same path; `/etc/heel/enrollment` read-only **directory** bind at
`/run/heel-enrollment` (a single-file bind would pin an obsolete inode across atomic replacement);
the named volume (`compose.yaml:54–56`) is replaced by the D_CP bind. Never bound: `/etc/heel/private`,
slots, host-layout. No secret env, argv, image layer or Docker secret-env copy of K; public configuration
names only the fixed mount path. The executor and ingress receive neither directory.

### 3.3 Root records outside the aggregate

Caps 2048 (fence) + 4096 (J) + 1024 (verification receipt) + 1024 (config) + 1024 (intent) + 524 288
(layout) + 1024 (rootfs record) + 1000 × 16 384 (slot configs) + 2 × 1024 (receipts) + 2 × 4 × 4096
(stale temps) + 0 (locks) ≤ 16.95 MiB, no growth path beyond caps. Outside the restored volume because EA
180–186 requires it; outside the 1 GiB aggregate by explicit bound. Provisioning reserves this plus the
host prefix, rootfs store and image layers (sized by H6-IMAGE facts) in the H6-RUNTIME root-FS budget.

### 3.4 Host layout record `heel.managed-host-layout.v2` [P]

Canonical ASCII JSON (sorted keys, compact, exact key sets, duplicates/extras rejected, byte-identical
re-encoding, integers never booleans, no floats). Cap **524 288 B**; legal maximum with 1000 lifetime
entries **266 500 B** (`witness-records.json`, every entry at the grammar maximum). Top-level keys exactly
`{schema_version, installation_id, host_id, layout_revision, next_ordinal, principals, storage, slots,
updated_at_ms}`.

| Field | Grammar / rule |
|---|---|
| `installation_id` / `host_id` | `inst_[0-9a-f]{32}` / `hst_[0-9a-f]{32}`; equal the fence values |
| `layout_revision` | int 1..2147483647, +1 per write; exhaustion refuses writes |
| `next_ordinal` | int 0..1000; equals `len(slots)`; never decreases |
| `principals` | exactly `{cp_uid:10001, cp_gid:10001, ingress_uid:10002, ingress_gid:10002}` |
| `storage` | exactly `{aggregate_bytes:1073741824, cp_device_bytes:805306368, slot_pool_bytes:268435456, cp_terminal_reserve_bytes:134217728, slot_root_reserve_bytes:2097152, min_slot_device_bytes:33554432, slot_inode_count:4096, slot_root_inode_reserve:64, cp_inode_count:16384}`; immutable after creation |
| `slots[]` | ≤ 1000 entries ordered by `ordinal`, exact keys `{ordinal, slot_id, workspace_id, uid, gid, device_bytes, state, created_at_ms, retired_at_ms, released_at_ms}` |
| `slots[].ordinal` / `uid` / `gid` | ordinal = array index; uid = gid = 71000 + ordinal |
| `slots[].slot_id` / `workspace_id` | B codec grammars (`host_authority.py:60,63`); each unique over all entries ever |
| `slots[].device_bytes` | **every** entry, including `released`: int multiple of 4096 in [33 554 432, 268 435 456]; **immutable once written** (a released entry keeps the size the device had); Σ over `active`+`retired` ≤ `slot_pool_bytes` |
| `slots[].state` | `active → retired → released` only; `released` = device destroyed after a C5/C6 root-verified release decision [R:S 628–630]; never removed |
| timestamps | ms 1..9007199254740991; `retired_at_ms` null iff `active`; `released_at_ms` null iff not `released` |

Writers hold `/etc/heel/.layout.lock` `LOCK_EX` (bounded 30 s, else `layout_busy`) across read–validate–
write (temp, fsync, rename, dir fsync, readback; on any fsync failure rewrite a fresh temp, §6.3 rule);
the layout tool never takes L, so no lock-order cycle. Provisioning/release keep their root-verified
release precondition and never mutate a live epoch. Verifier (H6-RUNTIME) cross-checks `/etc/passwd`
/`/etc/group`, `findmnt`, `blockdev --getsize64` equal to `device_bytes`, quota limits (§5.5) and slot
root owners. Oracles: add/retire/release positive; duplicate ordinal/uid/slot_id/workspace_id, rebinding,
`retired→active`, deletion, pool overflow, released-size change, size outside range, cap+1,
noncanonical bytes, bool-as-int.

## 4. Mandatory per-workspace executor container

### 4.1 Boundary (retained from R1)

[R:Customer 188, 512–514] container per workspace, read-only root FS, no shell; [R:S 591–592] root binds
only the selected home; [R:S 599–616] quiescence and sealing. Own mount, PID, IPC and UTS namespaces plus
the root-owned generation network namespace (H1/H2 lineage unchanged); no user namespace; no capabilities;
`no_new_privs`; exactly the FDs of §4.5; old root detached after `pivot_root`. Not claimed: seccomp,
cgroup memory/pids limits. A Docker/OCI container per workspace is rejected (moves netns ownership to
dockerd).

### 4.2 Exact host → container mapping

| Container path | Source (host) | Mount flags |
|---|---|---|
| `/` | `/var/lib/heel/executor-rootfs/<rootfs_tree_digest>/` | bind, remount `ro,nodev,nosuid` |
| `/heel/home` | `/var/lib/heel/slots/<slot_id>/epochs/<epoch_id>/home` | bind `rw,nodev,nosuid,noexec` |
| `/heel/vault` | `/var/lib/heel/slots/<slot_id>/vault` | bind `rw,nodev,nosuid,noexec` |
| `/heel/input.json` | `/var/lib/heel/slots/<slot_id>/executor-input.json` | bind file `ro,nodev,nosuid,noexec` |
| `/tmp` | new tmpfs 16 MiB, owner executor, 0700 | `nodev,nosuid,noexec` |
| `/dev` | tmpfs 64 KiB; binds of `/dev/null`, `/dev/zero`, `/dev/urandom` only | `ro,nosuid,noexec` after population |
| `/proc` | own-PID-ns procfs | `ro,nosuid,nodev,noexec,hidepid=invisible,subset=pid` |

Nothing else: no `/sys`, host `/tmp`, `/run`, other slot, `epochs/` parent, sealed epoch, `/etc/heel`
(hence never K). Source paths derive from plan identifiers by fixed grammar; each component opened
`O_PATH|O_NOFOLLOW|O_DIRECTORY` from the pinned parent with owner/mode/`st_dev` checks.

**Private prefix reconciliation (closes REV2 delta).** Executor argv is exactly
`/usr/bin/python3 -I -S -B /opt/heel/deploy/host/executor.py /heel/home /heel/input.json <link_fd>`
inside the rootfs. [H] `executor.py:40–44` computes its package root as `_HERE.parents[1]`; for this entry
that is `/opt/heel`, where the rootfs contains exactly `/opt/heel/heel/runner` (public wheel content),
`/opt/heel/heel/saas` (reviewed private closure) and `/opt/heel/deploy/host` (host entry closure), matching
P 183. Under `-I -S` there is no site-packages, user-site, `PYTHONPATH`, script-directory or checkout
fallback. Third-party dependencies (if any) are installed hash-locked inside the rootfs at one fixed
directory under `/opt/heel` frozen by H6-IMAGE; if the entry must add that directory to `sys.path`, that
is an `executor.py` change owned by the existing executor writers (P09→P10→P11→P12, P 169), not by H6.
R1's `/opt/heel/executor/executor.py` entry (package root `/opt`) is withdrawn. Host root processes run
`/usr/bin/python3 -I -S -B /opt/heel/deploy/host/<entry>.py` from the host prefix with the same layout.
CP keeps its separately pinned `/app` closure (B0/BIR).

### 4.3 Serialized handoff records [P]

**Launch plan `heel.managed-launch-plan.v2`** (supervisor → helper over an inherited pipe FD, read to EOF,
closed; canonical; cap 1024, legal max 316): exact keys `{schema_version, slot_id, uid, gid, epoch_id,
rootfs_tree_digest, rootfs_kind, tmp_bytes}`; `rootfs_kind` ∈ {`qualification_fixture`,
`integrated_source`, `release`}; other grammars as R1.

**Rootfs record `heel.managed-executor-rootfs.v2`** (cap 1024, legal max 405): exact keys
`{schema_version, kind, tree_digest, image_digest, entry_path, entry_sha256, installed_at_ms}`;
`entry_path` = `/opt/heel/deploy/host/executor.py` literal; `image_digest` = `sha256:`+hex64 iff
`kind=release`, else null. Install verifier refusals as R1 (root-owned only, no group/world-write,
setuid/setgid, device, socket, FIFO, escaping symlink, no shell names `sh, bash, dash, ash, zsh, ksh, csh,
busybox, toybox, su, sudo, env`).

**Kinds.** `qualification_fixture`: source-built by H6-LAUNCH/H6-RUNTIME harnesses for capability only.
`integrated_source`: built from the exact P14/P15 integration tree for integrated proofs. `release`: only
from the P17-built executor image digest. Evidence carries the kind; no fixture or integrated-source
evidence is ever cited as delivered-image proof; P17 must re-prove on `release` and P18 requires
`release`. The same three kinds label the CP consumer recipe (§7.4).

### 4.4–4.6 Helper sequence, FD/process boundary, oracles

Retained from R1 unchanged except the entry path above: argv `ns_fd link_fd plan_fd`; unshare
NEWNS|NEWPID|NEWIPC|NEWUTS; fork; PID-1 child with `PDEATHSIG`; build §4.2; `pivot_root`; detach old;
`setns(ns_fd, CLONE_NEWNET)`; drop to executor ids; verify caps zero; `execve`; exit codes 122–127 only.
Executor holds exactly fds 0–2 (`/dev/null`) and `link_fd`; "no surviving process" = PID namespace has no
member. `test_workspace_container_selected_home_and_host_path_denial` with mutants (missing pivot_root,
writable root, extra bind, extra FD, shell present, plan path injection, wrong UID) plus: K and the
enrollment header absent from every executor FD, mount, env and `/heel/input.json`.

### 4.7 Producer: proposed precursor H6-LAUNCH (A-LAUNCH, retained)

Owner fresh Opus, acceptor fresh Astra. Base: the accepted H3 commit, after H3 acceptance; never pending H.
Position: accepted H3 → H6-LAUNCH → I (composes accepted P07 + accepted H3 + accepted H6-LAUNCH) → P09.
Six nonmechanical paths, 0 mechanical: `deploy/host/supervisor.py` (modify: helper/launch-plan/rootfs
checks only), `deploy/host/managed_container.py` (create), `tests/test_managed_container_plan.py`
(create), `tests/test_host_h3.py` (modify: launch-helper expectations only),
`tests/linux/test_managed_container_boundary.py` (create), `scripts/managed_container_proof.py` (create,
`--output DIR --max-seconds 600`, fixture rootfs only). supervisor.py chain: accepted H3 → H6-LAUNCH →
P09 → P12. H1 `host_authority_proof.py`, H2 `host_h2_policy_proof.py` and the accepted H3 proof rerun
(not rebuilt) on H6-LAUNCH and again on I. P15 reruns `managed_container_proof.py` (A-P15, no path).

## 5. Aggregate storage

### 5.1 Partition (retained)

[R:P 78] footprint ≤ 1 GiB, admission ≤ 896 MiB, exclusive terminal reserve 128 MiB; [R:Q 150; EA 143,
190; S 626–627].

| Term | Bytes |
|---|---:|
| Aggregate = D_CP + Σ D_SLOT | 1 073 741 824 |
| D_CP device [P] | 805 306 368 (768 MiB) |
| — exclusive CP terminal/R/cleanup/checkpoint reserve | 134 217 728 |
| — CP admission ceiling | 671 088 640 |
| — ledger physical sublimit | 536 870 912 |
| Slot pool, Σ `active`+`retired` device bytes [P] | ≤ 268 435 456; each slot ∈ [32 MiB, pool] |
| Admission-eligible = ceiling + pool | 939 524 096 (= 896 MiB) |

Lifetime caps, epochs (1 live + 16), 28 KiB evidence, cleanup budgets unchanged [R:Q 146–154, P 93].

### 5.2 Inclusion and exclusion (retained)

D_CP counts every CP byte (pages, freelist, indexes, WAL incl. blocked-checkpoint growth, shm, journal,
lock, socket inode, `.heel-volume-id`, FS metadata/journal/inode tables). Each D_SLOT counts its epochs,
runtime DB, evidence, vault, input, ceremony/domain records, metadata and root reserves. SQLite temp
files and executor `/tmp`: bounded tmpfs. Root records: §3.3. **One** retained old D_CP (fence
`retained_volume_id`; `begin_restore` refuses while non-null) and **one** staged backup are bounded
operator-recovery allocations in the provider-disk budget, not serving storage. "Expand the volume"
([B] `RUNBOOKS.md:112`) is unavailable for managed D_CP; replacement is equal-size via restore (A-RUN,
P14 RUNBOOKS text).

### 5.3 Device-to-allocatable accounting [P]

`used(X) = device_bytes(X) − f_bavail × f_frsize`, `free_inodes(X) = f_favail` from `statvfs`;
`(f_blocks − f_bavail) × f_frsize` is not used. Provisioning: ext4 `mkfs.ext4 -F -b 4096 -I 256
-E lazy_itable_init=0,lazy_journal_init=0`; D_CP `-m 0 -N 16384`; D_SLOT `-N 4096 -O quota
-E quotatype=usrquota` then `tune2fs -r 512 -u 0 -g 0` (512 × 4096 B = 2 MiB uid-0 reserved blocks;
corrects R1's misuse of mkfs `-r`, which sets the revision). Image files `fallocate`d. Measurement error or
unsupported device → `capacity_unmeasurable`, refuse. Physical qualification is P06 (CP) and H6-RUNTIME.

### 5.4 CP admission and serialization (retained; consumers P05/P06)

One CP-process capacity mutex, order *capacity mutex → BEGIN IMMEDIATE*; `statvfs` sampled under the mutex
before BEGIN. The CP uid 10001 is the only D_CP writer, so a sample under the mutex is a valid reservation
for D_CP (unlike slots, §5.5). Admission requires `used + insert_cost + wal_allowance ≤ 671 088 640` and
`free_inodes − insert_inodes ≥ 1024`; Σ outstanding terminal cost + new ≤ 64 MiB (durable aggregate);
`-wal` ≤ 64 MiB; ledger ≤ 512 MiB. Costs are P06-measured worst cases or admission refuses.
Terminal/R/cleanup never refused for admission pressure; no deletion/VACUUM/pruning [R:Q 148, EA 190].
Owner note (INFERRED, must be confirmed at the P05 grant): the mutex is introduced in P05's
`host_snapshot.py`/`canary_runs.py`; any terminal/R writer located in a file outside P05's five-plus-one
list (§12) needs a revised serialized grant before P05, not hidden work.

### 5.5 Slot devices: block **and inode** reservation (R1-F4)

**Mechanism (kernel-enforced, inside the existing 32 MiB/2 MiB/1 GiB, no extra bytes):**

| Resource | Executor uid (71000+n) | Root (uid 0) |
|---|---|---|
| Blocks | ext4 reserved blocks: 512 blocks (2 MiB) usable only by `resuid 0` (`tune2fs -r 512 -u 0 -g 0`) | the 2 MiB reserve |
| Inodes | ext4 **usrquota inode hard limit** `LX = I0 − 64`, where `I0` = `f_ffree` measured on the freshly made, empty slot FS (expected 4085 for `-N 4096`; measured, never assumed); soft limit = hard limit; grace irrelevant | the remaining ≥ 64 inodes (`slot_root_inode_reserve`), never chargeable to the executor |

Root never relies on a quota exemption: executor-owned inodes are capped at LX by the kernel, root-owned
inodes are bounded by design below, and `LX + 64 = I0`. An inode-count sample is not used as a
reservation anywhere.

**Worst-case root obligations per slot (witness `witness-inodes.json`):** persistent root-owned inodes
`.lifecycle.lock`, `ceremony.json`, `domain.json`, `executor-input.json`, `epochs/`, ≤ 17 epoch dirs
(1 live + 16 retained/orphan, quarantined orphans included) = 22; ≤ 1 live atomic-replacement temp (S
lock serializes replacements); ≤ 4 stale temps (one per replaced kind: ceremony/journal, domain marker,
input, receipt-bearing ceremony rewrite) surviving any crash, each removed by the next attempt **before**
it creates its own; six retry attempts and restarts reuse, never accumulate. Total **27 ≤ 64** inodes and
**179 ≤ 512** blocks (one block per ≤ 4096 B record plus 8 blocks of directory growth per touched
directory). Seed destroy (overwrite + unlink) and sealing (chmod) need no new inode.

**Executor-charged root writes:** a fresh epoch needs a new executor-owned `home/`, `home/runner-daemon/` and `identity.seed`
(all three charged to LX; REV3 precision correction). If `executor_inodes_used − 1 (destroyed seed) + 3 > LX` or blocks are short, fresh
allocation returns `managed_capacity_unavailable` [R:S 631–637] **after** retirement/receipts completed;
no deletion, no replay/history deletion, no `cleanup_failed` used as a guarantee. Usefulness then waits
for the accepted C5/C6 release policy (S §4.9 dependency), exactly as for blocks.

**Capability test and refusal.** At slot provisioning H6-RUNTIME (`managed_host_layout.py`) must: verify
`tune2fs -l` features include `quota` and reserved-block uid 0 = 512 blocks; mount with `usrquota`; set
limits via `quotactl(Q_SETQUOTA)`; read back with `Q_GETQUOTA`; and run a functional probe as the slot's
executor uid before first use — create empty files until `EDQUOT` occurs at exactly LX, then confirm root
can still create and atomically replace a 4096 B file, then remove all probe files and re-measure `I0`.
Any deviation → `slot_inode_reserve_unavailable`, the slot is not provisioned, and the layout entry is not
written. Eight slots repeat this independently (one quota per device).

**Real oracles (later, not here):** H6-RUNTIME `test_slot_inode_and_block_exhaustion_root_reserve` on a real
Linux ext4 slot device: executor fills inodes to `EDQUOT` and, separately, blocks to `ENOSPC`, then root
performs every S cleanup stage including crash-and-restart with stale temps; P12
`tests/test_managed_root_ceremony.py` proves the protocol through all six attempts and restart with the
real quota mount. Witness `witness_inodes.py` is an abstract counterexample check (R1 design consumes all
inodes and root temp creation fails; R2 keeps 42 free with 27 needed), not ext4 evidence.

### 5.6 Capacity consequence (reported, unchanged)

At most 8 concurrent 32 MiB slots; larger capacity needs a separately reviewed amendment of P 78/Q 150/EA
143/S 626. Per-slot executor inodes ≈ 4021 is a further usefulness limit to be measured by H6-RUNTIME/P15.

## 6. Trusted maintenance fence and lifecycle (R1-F2, R1-F3)

Authority: host operator as root through H6-RUNTIME `deploy/host/managed_fence.py`. The fence is never on
D_CP or in any backup; a restored completion marker is never permission [R:EA 181, 186]. Security rests on
operator fencing and configuration replacement [R:EA 182]; simultaneous malicious rollback of fence,
configuration and DB is outside the model [R:EA 188].

### 6.1 Host lifecycle lock L: creation, repair, holders

**Creation is idempotent and never replaces.** `ensure_lifecycle_lock()` (inside every creator, under no
other lock): `open(L, O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC, 0640)` — **no `O_EXCL`**; `flock(LOCK_EX)`
bounded 30 s; `fstat` must be regular, nlink 1, size 0, owner uid 0, not a symlink, same `(st_dev,st_ino)`
as `lstat(L)`; then `fchown(0,10001)`, `fchmod(0640)`, `fsync(fd)`, `fsync(dir)`. An existing L that is
pristine (empty regular uid-0 single-link file) is adopted as-is: an empty lock file carries no state, so
an orphan L from a crashed initializer is indistinguishable from a fresh one and needs no reconciliation.
A non-pristine L (size > 0, nlink ≠ 1, wrong type, owner ≠ 0, symlink) → `lock_invalid`; operator
escalation, never unlink. L is never unlinked, renamed or replaced for the installation lifetime.

Every holder opens `O_RDONLY|O_NOFOLLOW|O_CLOEXEC`, takes `flock`, verifies `fstat == lstat` identity and
the exact profile (0:10001, 0640, nlink 1, size 0); otherwise releases and returns `lock_invalid`. Lock
FDs are `O_CLOEXEC` and every spawn uses `close_fds=True`, so no child inherits a parent's lock (a shared
open file description would share the flock).

| Holder | Mode | Held | Bound |
|---|---|---|---|
| CP `main()` | `LOCK_SH` | before DB lock until exit | 5 s, else `lifecycle_busy` |
| P14 offline entries (bootstrap/migration/restore/verify) | `LOCK_SH` | whole process | 5 s |
| Root supervisors (P12) and root signer | `LOCK_SH` | whole process | 5 s |
| Verification orchestrator parent (§7.4) | initial `LOCK_SH` released before dispatch; §7.4a launch phase reacquires SH | launch through child exit; releases before ack EX | 5 s |
| Root actual-artifact launcher (§7.4a) | `LOCK_SH`, then artifact lease | before spawn through child reaping; every restart anew | 5 s each, else `lifecycle_busy` |
| Every fence/config/receipt/intent mutator | `LOCK_EX` | whole mutation incl. J removal | 30 s, else `lifecycle_busy` |

Order everywhere: L → artifact lease (launch/ack only) → CP DB `.lock` → SQLite; mutators never take the DB lock; layout tool never takes L;
per-slot S lock only after L(SH). No holder upgrades SH→EX: a process that held SH releases it, then
acquires EX as a new bounded acquisition and re-validates `fence_revision`. No parent holds EX while
waiting for a child that needs SH (`witness-cuts.json` D: 19 683 schedule prefixes, 0 stuck, negative
control stuck 16 432). Cross-container flock on one inode is [U] F17.

### 6.2 Fence record `heel.managed-fence.v2` — closed variants

File checks: `O_RDONLY|O_NOFOLLOW`, regular, 0:10001, 0640, nlink 1, size ≤ **2048**, parent 0:10001 0750,
`st_dev` ≠ D_CP (`fence_on_restored_volume`). Canonical rules §3.4. **26** structural variant classes
(state × stage × origin/adoption × reason × nullable verification digest); legal maximum **1397 B**
(adopted `restore_pending/enrollment_installed`, `witness-records.json`).

Common keys C (non-null): `schema_version`, `installation_id` inst, `state`, `fence_revision` int
1..2147483647, `restore_epoch` hex64, `enrollment_secret_id` `enr_[0-9a-f]{32}` (random, never derived
from K), `cp_volume_id` vol, `host_id` hst, `updated_at_ms` ms.

| `state` | Exact key set = C ∪ | Rules |
|---|---|---|
| `serving` | `domain_operation_id` rop; `domain_receipt_digest` hex64; `enrollment_verification_digest` hex64; `retained_volume_id` vol\|null | retained ≠ `cp_volume_id` |
| `maintenance` | serving keys + `reason_code` ∈ {`enrollment_reverification`,`disk_pressure`,`operator_hold`}; `entered_at_ms` | `enrollment_verification_digest` null **only** if reason = `enrollment_reverification` |
| `bootstrap_pending` | `operation_id`; `operation_stage` ∈ {entered, reconciled, enrollment_installed}; `reconciliation_digest`\|null; `enrollment_verification_digest`\|null; `tunnel_rotated_at_ms`\|null; `entered_at_ms` | reconciliation null iff entered; verification non-null iff enrollment_installed; tunnel null if entered |
| `migration_pending` | `operation_id`; stage ∈ {entered, backup_verified, reconciled, enrollment_installed}; `origin` ∈ {`same_host`,`new_host`}; `backup_digest`\|null; `reconciliation_digest`\|null; `enrollment_verification_digest`\|null; `tunnel_rotated_at_ms`\|null; `fencing`\|null; `entered_at_ms` | backup null iff entered; reconciliation null iff stage < reconciled; verification as bootstrap; tunnel null if stage < reconciled; fencing: same_host ⇒ `{host_id: C.host_id, method: same_host_reaped}`; new_host ⇒ `{host_id: null, method: destroyed\|powered_off_detached}` |
| `restore_pending` | `operation_id`; stage ∈ {entered, backup_verified, domain_rotated, reconciled, enrollment_installed}; `previous_host_id` hst\|null; `pending_cp_volume_id` vol; `backup_digest`\|null; `backup_provenance` ∈ {`pre_domain`,`domain`}\|null; `pending_restore_epoch`\|null; `pending_enrollment_secret_id`\|null; `reconciliation_digest`\|null; `enrollment_verification_digest`\|null; `tunnel_rotated_at_ms`\|null; `fencing`\|null; `entered_at_ms` | pending volume ≠ C volume; backup digest/provenance null iff entered; `pre_domain` only if `previous_host_id` null (§6.10); pending epoch/enrollment null iff stage < domain_rotated, then ≠ C; reconciliation/verification/tunnel as above; fencing same-host ⇒ this host/`same_host_reaped`, adopted ⇒ `previous_host_id`/`destroyed`\|`powered_off_detached` |

`fencing` keys `{host_id, method, evidence_digest, fenced_at_ms}`; evidence = SHA-256 of the redacted
operator attestation. In pending variants C holds the values being **replaced**; targets are C
(bootstrap/migration) or the pending values (restore). No other states, keys or nulls.

### 6.3 Publication protocol with journal J (closes the serving-durability gap)

Every fence mutation (and the first fence creation) under L(EX):

1. Remove stale `.fence.*.tmp`/`.fencepub.*.tmp` (unlink, `fsync(dir)`).
2. Write J = `heel.managed-fence-publication.v1` `{schema_version, operation_id|null, prior_digest
   hex64|null, intended, intended_digest, created_at_ms}` (`intended` = the full new fence object; cap 4096,
   max 1717 B) to a fresh temp (`O_CREAT|O_EXCL|O_NOFOLLOW`, 0600), `fsync`, rename to J, `fsync(dir)`.
3. Write the new fence to a fresh temp (0640, `fchown(0,10001)` before write), `fsync`, rename onto
   `fence.json`, `fsync(dir)`, reopen with §6.2 checks and compare bytes to `intended`.
4. Unlink J, `fsync(dir)`. Only now return the record (the durable acknowledgement).

**Reader rule (gate, offline entries, supervisors):** after taking L(SH), `lstat(J)`; if J exists (any
content) → `FenceError fence_publication_uncertain` → refuse. Because J is unlinked only after step 3's
directory fsync returned success, a reader that sees no J and a `serving` fence sees a record whose rename
was made durable; a later power loss can at most make J reappear (refuse until recovery), never revert the
fence under a running server (`witness-cuts.json` A: 68 cuts incl. kill, fsync failure and power loss;
0 non-durable serves; R1 negative control 4 non-durable serves).

**Failed sync.** After any `fsync`/dir-`fsync` error, the possibly poisoned inode is never re-fsynced and
trusted: recovery rewrites a **fresh** temp of `intended` and repeats steps 3–4. A readback alone is never
an acknowledgement. **Permissions/FD ownership:** temps are created by root with exact mode, `fchown` before
content, `O_CLOEXEC`; all FDs closed before L(EX) is released; a holder or reader never inherits them.

`recover_publication(*, now_ms)` (root, L(EX)): J absent → no-op; J valid and `fence.json` bytes ==
`intended` or == the record with `prior_digest` → rewrite `intended` fresh (steps 3–4); J unparsable or
fence matches neither → `fence_invalid` (operator escalation; no guessing). Every mutator begins with this
recovery. For first creation, `prior_digest=null` means expected fence **absence**, not a hash of a
missing file; absent fence + valid first-creation J rewrites intended fresh. Non-null prior with absent
fence, or null prior with an unrelated existing fence, refuses. Thus a retry of the same call completes the earlier publication before evaluating its own
precondition. **Startup durability qualification** is therefore part of the gate: no listener and no
offline write runs while J exists, and the only way out is root recovery under EX.

### 6.4 Operation intent (closes the creation gap and binds K before use)

`/etc/heel/private/operation-intent.json`, `heel.managed-operation-intent.v1`, root 0600, cap 1024 (max
576): exact keys `{schema_version, operation_kind (bootstrap|migration|restore), origin
(same_host|new_host|null; migration only, else null), operation_id, installation_id, host_id,
target_cp_volume_id, target_restore_epoch|null, target_enrollment_secret_id|null, secret_b64|null,
created_at_ms}`. Restore targets/secret are null until `rotate_domain`; `secret_b64` (44-char strict
base64 of 32 bytes) is non-null from target generation until the enrollment ack (§7.4), then rewritten
null. Written with the §6.3 temp/fsync/rename/dir-fsync/readback/fresh-rewrite rule (no J needed: no
reader acts on it). **Randomness rule:** operation id, installation/host id (fresh only), restore epoch,
enrollment id and K are drawn exactly once, inside the mutation that first makes the intent **visible**.
An unpublished temp is discarded unread; filenames never carry or select randomness. A visible intent is
always reused, never redrawn (`witness-cuts.json` C: every cut, one visible draw, one L inode, fence ==
intent == config; R1 negative control 9 stuck cuts).

### 6.5 Callables (H6-RUNTIME `deploy/host/managed_fence.py`, uid 0)

Keyword-only; mutators take `expected_revision` (except creators) and `now_ms`; return the re-read
validated record; raise `FenceError(code)` (§6.8). Every mutator: ensure/verify L, L(EX), recover J,
validate, write per §6.3/§6.4.

| Callable | Inputs | Precondition | Result |
|---|---|---|---|
| `read_fence(*, db_dir)` | — | caller holds L(SH) | record or error incl. `fence_publication_uncertain` |
| `recover_publication` | — | L(EX) | §6.3 |
| `initialize_installation(*, kind, origin, cp_volume_id)` | kind ∈ {`fresh`,`legacy_migration`}; origin ∈ {`same_host`,`new_host`} for legacy only | no fence (or a fence equal to this intent's record → idempotent return); intent absent **or** intent of this kind/origin/volume; `.heel-volume-id` = `cp_volume_id`; fresh: DB absent or (intent present and DB written only by offline bootstrap); legacy: DB present | ensure L; intent (draw once: op, inst, host, epoch, enr id, K); config `current.json` = intent targets (§7.1); fence revision 1 `bootstrap_pending/entered` or `migration_pending/entered` |
| `adopt_for_restore(*, previous_installation_id, previous_host_id, previous_cp_volume_id, previous_restore_epoch, previous_enrollment_secret_id, new_cp_volume_id)` | previous values **read from the verified backup's domain row** by P14's read-only observer | no fence on this host (or a fence equal to this intent's record → idempotent return); intent absent or same | ensure L; intent (op, host drawn once; targets null); fence `restore_pending/entered`, C = previous values, `host_id` = this host |
| `enter_maintenance(*, reason_code)` | — | `serving` | `maintenance`, digests carried |
| `invalidate_enrollment_verification()` | — | `maintenance/enrollment_reverification` | removes receipt file, digest ← null |
| `reinstall_enrollment_config()` | — | `maintenance/enrollment_reverification`, digest null | rewrites `current.json` from the **current** loaded bytes to a fresh inode (same K/ids/op); never generates K |
| `leave_maintenance()` | — | `maintenance`; verification digest non-null and equal to `SHA256(J(receipt))`; current config binding/profile/context equal the receipt | `serving`, same domain |
| `begin_restore(*, new_cp_volume_id)` | — | `maintenance`, retained null | intent (op drawn once) ; `restore_pending/entered`, previous null |
| `record_backup_verified(*, operation_id, backup_digest, backup_provenance)` | provenance from P14 observer: `pre_domain`\|`domain` (restore), `pre_domain` (migration) | stage entered; restore+adopted requires `domain` | `backup_verified` |
| `rotate_domain(*, operation_id)` | — | restore `backup_verified` | intent targets + K drawn once; config installed for pending targets; `domain_rotated` |
| `record_reconciled(*, operation_id, receipt: bytes)` | ≤ 1024 B | reconcile stage (bootstrap entered / migration backup_verified / restore domain_rotated) **or** stage ≥ reconciled with equal digest (idempotent); receipt valid (§6.6) | `reconciled`; `reconciliation_digest` ← `SHA256(J(result))`; receipt copy to `private/receipts/` |
| `record_fencing(*, operation_id, host_id, method, evidence_digest, fenced_at_ms)` | per §6.2 | migration/restore, any stage; null or byte-identical | `fencing` set |
| `record_tunnel_rotated(*, operation_id, tunnel_rotated_at_ms)` | operator rotation evidence time; **not** proof of K | stage ≥ reconciled; null or equal | set |
| `verify_and_record_enrollment(*, operation_id\|None, expected_revision)` | none from caller beyond ids; consumes its own observation (§7.4) | pending stage `reconciled` (or `enrollment_installed` for re-ack) **or** `maintenance/enrollment_reverification` with digest null | receipt written, then fence: pending → `enrollment_installed`; maintenance → digest set, stays maintenance; intent `secret_b64` → null after fence durable |
| `complete_operation(*, operation_id)` | — | stage `enrollment_installed`; tunnel non-null; migration/restore fencing non-null; config binding/profile/context re-checked equal to the receipt | `serving`: `domain_operation_id` ← `operation_id`; restore ⇒ C ← pending, `retained_volume_id` ← previous volume; `domain_receipt_digest` ← `reconciliation_digest`; verification digest carried; then intent unlinked + dir fsync |
| `release_retained_volume(*, volume_id, evidence_digest)` | — | serving\|maintenance; retained = volume_id | retained null |

No pending state is left except by `complete_operation`; no abort. Interruption keeps ingress disabled and
resumes under the same `operation_id` [R:EA 186, Q 172]. Restore is the only domain replacement; ordinary
restart never rotates. A stale intent whose `operation_id` equals a serving fence's `domain_operation_id`
is removed by the next mutator; any other intent/fence mismatch → `operation_mismatch`.

### 6.6 Reconciliation result and receipt (P14 producer, fence consumer)

**Result** `heel.managed-reconciliation-result.v1` (stable, stored durably in the domain row by the same
SQLite transaction that reconciles): exact keys `{schema_version, operation_kind, operation_id,
installation_id, restore_epoch, enrollment_secret_id, cp_volume_id, backup_provenance, db_schema_version,
terminalized_reservations, revoked_runner_keys, closed_generations, revoked_grants, stopped_runs,
reconciled_at_ms}` plus `previous_restore_epoch` hex64 **only** for restore. `backup_provenance`:
bootstrap `none`, migration `pre_domain`, restore `pre_domain|domain`; `db_schema_version` = `user_version`
at commit, int 1..2147483647; counts int 0..2147483647 (all 0 for bootstrap). `reconciliation_digest` =
`SHA256(J(result))`, stored in the row.

**Receipt** `heel.managed-reconciliation-receipt.v2` = `{schema_version, result, check}`; `check` exact
`{integrity_check:"ok", open_managed_authority_rows:0, measured_used_bytes, measured_free_inodes,
measured_at_ms}` re-measured at **every** emission (after commit, read-only connection). The digest covers
`result` only, so re-emission after a lost stdout yields the same digest. Field grammar: measured values
0..9007199254740991 (int, never bool). **Accepted physical range** (checked by `record_reconciled`, else
`capacity_reserve_unavailable`): `measured_used_bytes ≤ 671 088 640`; `1024 ≤ measured_free_inodes ≤
16 384` (`cp_inode_count`). Maxima (`witness-records.json`): field-grammar 852/903/993 B, accepted
physical 834/875/965 B for bootstrap/migration/restore; cap 1024. Neither maximum is a measured
device value. `record_reconciled` requires result ids equal the fence targets (restore: pending values,
`previous_restore_epoch` = C.`restore_epoch`), provenance equal the fence's, and digest idempotency.

**Offline transaction (P14):** one `BEGIN IMMEDIATE` with `PRAGMA synchronous=FULL`: terminalize all
managed rows incl. null-runner reservations, revoke keys/nonces/proofs/receipts/grants, close generations,
stop runs, then INSERT (bootstrap, migration, pre-domain restore) or UPDATE (domain-bearing restore) the
domain row with targets **and** result columns, COMMIT. Neither listener, reaper, tunnel nor host-authority
service is constructed; emit the receipt on stdout; exit 0. The migrator's own commits precede it; a crash
between leaves `pre_domain` with an empty domain table, which §6.7 accepts as initial.

### 6.7 CP startup gate (consumer P14: `server.py`, `managed_restore.py`)

Placement in B `build_server`: L(SH) first (new, before `server.py:436`), DB lock (436), enrollment load
(once, §7.3), gate — all before the migrator (449), HTTP `serve()` (477) and `HostAuthorityService`
(519–527). Every managed entry is launched through §7.4a; absence of its live channel refuses before either
listener constructor. There is no raw container restart/autostart bypass. Only when `HEEL_MANAGED_HOST=1` ([B] `server.py:291–313`); connector-only unchanged.

`evaluate_startup_gate(*, mode, fence: FenceRecord | FenceError, db: DbObservation, volume:
VolumeObservation, enrollment: EnrollmentObservation, verification: VerificationObservation,
artifact: ArtifactObservation) ->
GateDecision` — pure, total.

- `mode` ∈ {`ordinary`, `offline_bootstrap`, `offline_migration`, `offline_restore`,
  `offline_verify_enrollment`}; only P14's explicit offline CLI passes non-ordinary; no bool fallback.
- `VolumeObservation` = vol id | `volume_id_missing` | `volume_id_invalid`.
- `DbObservation` (read `mode=ro` before any migration) = `empty` (no file or zero tables) |
  `pre_domain(schema_version, table_present: bool)` (no domain table, or table with zero rows) |
  `domain(row, schema_version)` (exactly one row and stored digest == `SHA256(J(result-from-columns))`) |
  `invalid`.
- `EnrollmentObservation`, `VerificationObservation`: §7.3. `ArtifactObservation`: §7.4a;
  production cannot manufacture it from JSON, env, CLI digest, receipt or an old decision.

Decision records `heel.managed-startup-gate.v2`, canonical, cap 1024 (max 489): `refuse_unidentified`
`{schema_version, mode, decision:"refuse", reason_code}`; `refuse` + `{installation_id, fence_revision,
fence_state}`; `serve` `{schema_version, mode:"ordinary", decision:"serve", installation_id,
fence_revision, restore_epoch, enrollment_secret_id, cp_volume_id, domain_operation_id}`;
`offline_proceed` `{schema_version, mode, decision:"offline_proceed", installation_id, fence_revision,
operation_id, recovery: bool, target_restore_epoch, target_enrollment_secret_id, target_cp_volume_id}`.
35 closed reason codes retained (`witness-records.json`) plus the eight artifact codes in §7.4a.
The 489-byte gate bound is unchanged; artifact facts are not added to persistent decisions. No nullable field; no secret, binding or path dump.

Evaluation order (first match):

| # | Condition | Decision |
|---|---|---|
| 1 | fence error (`fence_missing`, `fence_invalid`, `fence_profile`, `fence_on_restored_volume`, `lock_invalid`, `lifecycle_busy`, `fence_publication_uncertain`) | `refuse_unidentified` |
| 2 | volume error | `refuse volume_id_missing\|volume_id_invalid` |
| 3 | enrollment error (`config_missing`, `config_unavailable`, `config_invalid`, `config_profile`, `config_changed`) in any mode | `refuse <code>` |
| 3a | any mode: artifact error, or observation does not bind this live process/mode/fence revision/config/recipe/volume and receipt bytes (including absence for offline) | `refuse <artifact code>` (§7.4a); binding disagreement → `artifact_binding_changed` |
| 4 | **ordinary**: state ≠ serving | `maintenance_active` / `bootstrap_pending` / `operation_pending` |
| 5 | ordinary: verification error | `verification_missing\|verification_invalid\|verification_unavailable` |
| 6 | ordinary: volume ≠ C volume | `volume_mismatch` |
| 7 | ordinary: db `empty`\|`pre_domain` / `invalid` | `domain_absent` / `domain_invalid` |
| 8 | ordinary: row installation/epoch/enrollment/volume/operation_id/digest ≠ fence C / `domain_operation_id` / `domain_receipt_digest` | `installation_mismatch\|epoch_mismatch\|enrollment_mismatch\|volume_mismatch\|operation_mismatch\|receipt_mismatch` |
| 9 | ordinary: loaded config C ≠ fence C (installation, host, epoch, enrollment id, volume) or config `operation_id` ≠ `domain_operation_id` | `enrollment_mismatch` |
| 10 | ordinary: `SHA256(J(receipt))` ≠ fence verification digest, or receipt C/operation ≠ loaded, or receipt recipe digest ≠ measured | `enrollment_verification_mismatch` |
| 11 | ordinary: receipt `file_binding` ≠ loaded binding | `enrollment_config_changed` |
| 11a | ordinary: measured artifact kind/digest ≠ receipt kind/digest | `artifact_mismatch` |
| 12 | ordinary: all equal | **`serve`** |
| 13 | offline: state not matching mode | `mode_mismatch` |
| 14 | offline: volume ≠ target volume, or loaded config C/operation ≠ targets/`operation_id` | `volume_mismatch` / `enrollment_mismatch` |
| 15 | offline_bootstrap, stage entered: **recovery** if db `domain` with `operation_id` = fence op, kind bootstrap, ids = targets; **initial** if db `empty` or `pre_domain` (bootstrap DB written only by this entry); `pre_domain` containing any managed row → `bootstrap_db_not_fresh` | `offline_proceed` (recovery flag) |
| 16 | offline_migration, stage backup_verified: recovery as 15 (kind migration); initial if `pre_domain` | `offline_proceed` |
| 17 | offline_restore, stage domain_rotated: recovery if db `domain` with op = fence op, kind restore, ids = pending, `previous_restore_epoch` = C epoch; initial if (`pre_domain` and fence provenance `pre_domain`) or (`domain` with installation = C, epoch = C epoch, op ≠ fence op, and provenance `domain`); `domain` with other installation/epoch → `restored_domain_mismatch`; provenance disagreeing with db → `backup_provenance_mismatch` | `offline_proceed` |
| 18 | offline_* at stage ≥ reconciled: recovery predicate only (read-only re-emission of the stored result) | `offline_proceed` (recovery) or `operation_mismatch` |
| 19 | offline_verify_enrollment: pending stage ∈ {reconciled, enrollment_installed} with db recovery predicate true, **or** `maintenance/enrollment_reverification` with digest null and ordinary rows 6–9 true | `offline_proceed` (recovery = true) |
| 20 | otherwise | `stage_invalid` |

Recovery mode never opens a write transaction; it re-runs `integrity_check`, re-measures and re-emits the
stored result. This is the exact same-operation predicate: a row is accepted only if its `operation_id`
equals the fence's fresh random `operation_id` **and** every target and the recomputed digest match; an
arbitrary new-domain row is not accepted (`witness-cuts.json` B: four journeys × every cut, 0 unrecovered,
≤ 1 commit; R1 rule reproduces REV2's restore counterexample and a migrator-partial cut). Only `serve`
reaches line 449 in `main()`; direct oracle: no TCP listen and no socket inode for every non-serve
decision (P 570).

### 6.8 Closed errors and retry

`FenceError(code)`, code ∈ {`fence_missing`, `fence_invalid`, `fence_profile`, `fence_on_restored_volume`,
`lock_invalid`, `lifecycle_busy`, `fence_publication_uncertain`, `fence_exists`, `revision_conflict`,
`transition_invalid`, `operation_mismatch`, `backup_unverified`, `backup_provenance_mismatch`,
`receipt_invalid`, `reconciliation_incomplete`, `capacity_reserve_unavailable`, `fencing_missing`,
`tunnel_unrecorded`, `enrollment_unverified`, `enrollment_binding_changed`, `config_io`,
`retained_volume_present`, `revision_exhausted`, `io_failed`}.

- `lifecycle_busy`: stop holders, retry; no state change.
- `revision_conflict`: after J recovery, if the record already equals this exact transition with the same
  ids, return it (idempotent); else stop.
- `io_failed`: J remains (if written) and every reader refuses; retry the same call → J recovery rewrites
  fresh; never a second epoch, enrollment id, K or operation.
- `config_io`: config/receipt write failed; fence unchanged or J-protected; retry rewrites fresh from the
  intent (pending) or from current bytes (reinstall).
- `revision_exhausted`: operator escalation.

### 6.9 Crash-cut tables (separately modelled cuts, not an atomic write)

Abbreviations: V = visible, D = durable after power loss; "retry" = same callable, same ids.

**Initialize / adopt**

| Cut | State left | Recovery |
|---|---|---|
| I1 L created, before fchown/fsync | L pristine-but-wrong-profile or absent after power loss | retry repairs profile under EX or recreates; holders refuse `lock_invalid` meanwhile |
| I2 intent temp written, not renamed | no visible intent | retry discards temp unread and draws once |
| I3 intent V not D | power loss may remove it | retry: if visible reuse; else draw (no value was ever used) |
| I4 config written (bootstrap/migration) | config ≠ fence (no fence) | gate `fence_missing`; retry rewrites identical config from intent |
| I5 J written, fence not | readers `fence_publication_uncertain` | J recovery completes fence |
| I6 fence V before dir fsync | J present | J recovery rewrites fresh |
| I7 J unlink V not D | power loss → J reappears | refuse until recovery; never reverts fence |

**Offline reconciliation (all four journeys)**: crash before COMMIT → initial predicate reruns; migrator
commit only → `pre_domain(table_present)` initial; COMMIT D, stdout lost → recovery predicate re-emits the
same result; receipt delivered, `record_reconciled` J present → recovery; fence D, reply lost → idempotent
`record_reconciled`. SQLite reporting COMMIT success that the device later loses is outside the model
([U] F20).

**Enrollment / complete / leave-maintenance**

| Cut | Recovery |
|---|---|
| E1 rotate: intent with K D, config not installed | retry installs once from intent |
| E2 config rename V, dir fsync fails | `config_io`; retry rewrites fresh; startup binding check refuses meanwhile |
| E3 verifier passed, parent/child dies before EX | observation lost; retry runs the actual verifier again |
| E4 receipt file D, fence not | gate digest mismatch refuses; retry re-verifies and replaces the receipt |
| E5 fence `enrollment_installed` D, intent `secret_b64` still set | next mutator nulls it; config remains the only K copy |
| C1 complete: J written, fence not | readers refuse; J recovery |
| C2 complete: fence `serving` V, dir fsync fails or process dies | J present → **no reader serves** (the R1 defect) until recovery rewrites |
| C3 complete: J unlink not D | refuse after power loss until recovery; fence stays serving |
| C4 complete: intent unlink lost | stale intent with op = `domain_operation_id` removed by next mutator |
| L1–L3 leave-maintenance | identical to C1–C3 |

### 6.10 Procedures and pre-domain provenance

**Fresh bootstrap:** create D_CP + `.heel-volume-id`; `initialize_installation(fresh)` (intent, config,
fence); operator rotates tunnel; P14 `offline_bootstrap` → `record_reconciled` → `record_tunnel_rotated` →
`verify_and_record_enrollment` → `complete_operation` → start CP → gate `serve` → listeners → readiness →
edge smoke → ingress opens.
**Legacy migration, same host:** stop/reap every legacy process/FD [R:EA 172]; `initialize_installation
(legacy_migration, same_host)`; fresh backup → `record_backup_verified(pre_domain)`; `record_fencing
(same_host_reaped)`; `offline_migration`; then as bootstrap.
**Legacy migration, new host** (journey preserved for a pre-domain backup whose original host is lost):
restore the legacy DB into a fresh D_CP; `initialize_installation(legacy_migration, new_host)`;
`record_backup_verified(pre_domain)`; `record_fencing({host_id: null, destroyed|powered_off_detached})`
— the old host is identified only by the operator's evidence digest, no invented `hst_` id; continue as
migration. A new K means any old managed installation's credential never authenticates here.
**Restore, same host:** stop tunnel/CP/supervisors; old volume read-only; `enter_maintenance
(operator_hold)` + `begin_restore`; verify backup into the new D_CP → `record_backup_verified(pre_domain|
domain)` → `rotate_domain` → `offline_restore` → `record_reconciled` → `record_fencing(same_host_reaped)` →
`record_tunnel_rotated` → `verify_and_record_enrollment` → `complete_operation` → start exactly one CP →
fresh S seed/pair/bind/approval [R:EA 185]. Pre-domain backup: previous epoch is the **current fence**
`restore_epoch`, not a value invented for the backup.
**Restore, adopted (new host):** `adopt_for_restore` with values read from a **domain-bearing** backup
row; a pre-domain backup is refused (`backup_provenance_mismatch`) and must use the new-host legacy
migration journey above.
**Positive/refused provenance variants:** positive = {same-host pre_domain, same-host domain, adopted
domain, new-host legacy migration}; refused = {adopted pre_domain, domain row of another installation or
epoch, bootstrap with managed rows, provenance disagreeing with the DB}.
**K replacement (compromise or loss):** only by a full domain replacement — same-host restore of a fresh
verified backup onto a new equal-size volume (one retained old volume). No same-id regeneration, no
dual-key grace, no leave-maintenance shortcut.
**Ordinary restart/reboot:** invoke the root launch verifier (§7.4a) afresh; measure and bind the
actual child artifact; fence serving; load current config; compare exact artifact to receipt; gate `serve`; epoch, counters and terminal
history unchanged; executors burn their old generation [R:Q 83]. Device renumbering that changes the config
`file_binding` refuses (`enrollment_config_changed`) until maintenance re-verification.

## 7. Installation enrollment (R1-F1; A-ENR2, pending Q/EA amendment review)

Source: ENR (unaccepted, selected as basis). Deviations from ENR are listed in §7.6. Everything here is
INFERRED design; the enrollment amendment to Q §3/§6.7 and EA §4/§7 is **explicit and pending fresh
independent review**; this author does not accept it.

### 7.1 Key and configuration

K: exactly 32 bytes from the OS CSPRNG, drawn once per durable operation intent (§6.4) at fresh bootstrap,
legacy migration or `rotate_domain`. `enrollment_secret_id` is an independent random 16 bytes (`enr_`+32
hex), never K, a hash, MAC or fingerprint. K is never the Worker/edge key, tunnel token, runner seed or a
target credential, and no such key ever serves as K.

`/etc/heel/enrollment/current.json`, `heel.host-enrollment-config.v1`, exact keys `{schema_version,
operation_id, installation_id, host_id, restore_epoch, enrollment_secret_id, cp_volume_id, secret_b64}`;
all strings; grammars inst/hst/hex64/enr/vol/rop; `secret_b64` RFC 4648 standard base64 with padding, 44
chars, strict decode/re-encode equality incl. zero pad bits; canonical compact sorted ASCII JSON, no
newline; cap 1024 (471 B). Profile: regular, 0:10001, 0640, nlink 1; dir 0:10001 0750; no symlink at any
component; descriptor-relative no-follow opens; bounded read; `fstat` before/after read equal and equal to
`lstat`. Errors never echo rejected bytes. LoadedEnrollment is opaque; K excluded from repr/debug/
exceptions; no public export or public-wheel inclusion.

`FileBinding` = `{device, inode, size, mtime_ns, ctime_ns}`, ints 0..2^63−1 (inode > 0, size 1..1024),
never bool; from `fstat` of the opened inode. Root source and CP destination must resolve the same
`(st_dev, st_ino)` in one kernel (verified by §7.4). No secret-file hash substitutes for the binding.

### 7.2 Header and authenticator (three Q managed routes only)

Routes exactly `POST /host/v3/managed-ceremony`, `POST /host/v3/managed-operation`, `POST
/host/v1/managed-attempt` [R:Q 56], HTTP/1.1, AF_UNIX. SO_PEERCRED admission ([B]
`host_authority.py:165–172`, uid 0 + external pidns) still runs first and denies before any read. Legacy
`/host/v1/authority-snapshot` and any v2 managed route never accept managed provenance even with a proof.

Exactly one header `X-Heel-Host-Enrollment: v1 <enrollment_secret_id> <mac_hex>`: value = `v1 ` + 36-char
`enr_` id + SP + 64 lowercase hex = **104 B**; complete line 130 B incl. CRLF. Managed-route header set is
closed: `Host` (exactly `localhost`, new managed-only rule — B drops Host unread), `Content-Length`,
`Content-Type` (exactly `application/json`), optional `Connection: close`, `X-Heel-Host-Enrollment`;
case-insensitive duplicate detection; no tabs, folding, extra whitespace, `Transfer-Encoding`, `Expect`,
`Upgrade`, cookies, `Authorization` or edge header. The B parser is not widened for other routes.

`D` = `{schema_version:"heel.host-enrollment-auth.v1", installation_id, host_id, restore_epoch,
enrollment_secret_id, cp_volume_id, method:"POST", path, body_sha256: SHA256-hex(exact received body)}`;
`mac_hex = HMAC-SHA256(K, b"heel-host-enrollment-request-v1\x00" + J(D))`; constant-time compare after
strict grammar; header id = loaded C id; body hashed before any parse. Authentication yields C only — never
a runner, workspace, slot, job or request authority; slot/epoch in the body must still match the
authenticated installation and the trusted slot join, and every Q/EA guard (runner PoP, binding, scope,
grant, W/Q, sequence, one-shot, terminal-before-replay) runs unchanged. A replayed valid MAC is not a
fresh operation; no replay table or receipt stores the header or a hash of it; Q `request_digest` still
hashes the body only.

Errors (each closes the connection, calls no decider, allocates/charges nothing, increments one fixed
nonsecret counter, logs no bytes): framing/unknown/duplicate/grammar → 400 `{"error":"managed_protocol_
error"}`; over cap → 413 same body; missing or mismatched proof on a well-formed request → **401**
`{"error":"host_enrollment_required"}` (P05 adds 401 to B's `_STATUS`); unknown path → existing 404.
Caps unchanged: W 2048, Q 2560, ceremony 4096, responses 4096, head 8192 (B `MAX_HEAD_BYTES`, excludes the
terminating CRLFCRLF; maximal managed head 261 B), one request/connection, backlog 64, 5 s.

### 7.3 Trusted observations into the gate

`EnrollmentObservation` = `loaded(C, operation_id, file_binding, consumer_recipe_digest)` from the **same**
production LoadedEnrollment object later passed to `HostAuthorityService` (P05 constructor parameter,
P14 wiring), or one of `{config_missing, config_unavailable, config_invalid, config_profile,
config_changed}`. `consumer_recipe_digest` is recomputed at startup from self-measured facts (§7.4); never
read from env. No bool, env id or caller tuple can produce `loaded` in production composition; secret
bytes never enter gate inputs/results.

`VerificationObservation` = parsed `/etc/heel/maintenance/enrollment-verified.json` (same file rules as the
fence) or `{verification_missing, verification_invalid, verification_unavailable}`.

### 7.4 Listener-free actual-consumer verification and ack

`verify_and_record_enrollment` (H6-RUNTIME orchestrator, uid 0), acyclic and never holding EX while a
child needs SH:

1. Parent: L(SH); read fence (no J), capture `fence_revision`, operation/targets, config inode/bytes
   binding; release SH.
2. Through the host launch verifier (§7.4a, explicit offline mode; no old receipt equality required),
   spawn the pinned P14 `offline_verify_enrollment` entry in the configured CP launch recipe (uid/gid
   10001, identity uid map, own PID ns, read-only enrollment and maintenance binds, D_CP bind) with exactly
   two private pipes (no Docker exec/stdio logging, tee, terminal, network socket or listener). Child: L(SH)
   for its whole life; loads the real `ProductionConfiguration`, the production P05 loader and
   authenticator; runs the gate in `offline_verify_enrollment` (row 19); constructs no HTTP server, reaper
   or Unix listener; writes no DB.
3. At the rendezvous, root inspects the live child: `/proc/<pid>/ns/*`, `uid_map`, `status` uids/caps,
   `/proc/<pid>/root/run/heel-enrollment/current.json` `(st_dev, st_ino)` = the host source inode and
   profile, fixed volume/fence binds, executable/argv and code/dependency manifests against the pinned
   recipe. Any uninspectable fact → `config_unavailable`; never assumed.
4. Challenge `heel.host-enrollment-check.v1` `{schema_version, operation_id, installation_id, host_id,
   restore_epoch, enrollment_secret_id, cp_volume_id, nonce}` (fresh 32-byte hex nonce, cap 1024, 485 B);
   child checks fields against its loaded object and answers `{schema_version:"heel.host-enrollment-check-
   response.v1", mac}` (cap 256, 132 B), `mac = HMAC-SHA256(K, b"heel-host-enrollment-check-v1\x00" +
   J(challenge))`, plus in-process production-authenticator self-tests on synthetic requests for all three
   paths (valid accepts authentication; one-bit wrong key/proof and changed C/path/body deny; no decider).
   Parent computes with its separately loaded K. One exchange, ≤ 5 s; timeout/EOF/excess → fail. Challenge
   and response are never persisted, hashed into a record or logged.
5. Child exits; parent confirms no survivor/FD, releases launch SH and the artifact lease, then takes
   L(EX) as a new acquisition and performs J recovery. Require the same revision, operation, targets,
   config bytes/inode/binding and recipe as inspected. Acquire a new artifact lease after EX and fully
   remeasure the retained stopped snapshot/store against the recorded identity before publication;
   missing/changed snapshot or profile → re-verify. Hold EX and this new lease through ack; any change →
   re-verify, never replay.
6. Write receipt `heel.host-enrollment-verified.v2` `{schema_version, operation_id, installation_id,
   host_id, restore_epoch, enrollment_secret_id, cp_volume_id, file_binding, consumer_recipe_digest,
   artifact_kind, artifact_digest, verified_at_ms}` (cap 1024, max 819 B; no nonce, MAC, key, key hash or
   transcript); artifact kind/digest come only from §7.4a host measurement of that verifier child,
   never its request or self-report. Publish with temp/fsync/rename/dir-fsync/readback; then fence (via §6.3) with
   `enrollment_verification_digest = SHA256(J(receipt))`; then null intent `secret_b64`.

**Consumer recipe** `heel.host-enrollment-consumer-recipe.v2` (cap 2048, 483 B), self-measurable by the CP
at every startup: `{schema_version, artifact_kind (qualification_fixture|integrated_source|release),
code_manifest_digest, dependency_manifest_digest, entrypoint:"heel.saas.server", uid:10001, gid:10001,
peer_profile:"external-pidns", credential_target:"/run/heel-enrollment", receipt_target:"/etc/heel/
maintenance/enrollment-verified.json"}`; manifests are nonsecret files whose exact layout H6-IMAGE/P17
freeze (inspected to contain no rendered secret or secret-file digest). `artifact_digest` has the exact §7.4a identity for every kind. The CP does not self-measure an image
digest: the trusted host verifier measures and binds it on **every** launch, including ordinary, restart
and boot, and the CP gate compares that observation with the receipt. Recipe equality never substitutes
for artifact equality. P17 parity and re-verification are additional obligations.

The receipt is durable provenance of root's own observation, not attestation against malicious root. No
caller-supplied JSON, bare id or saved success replaces the actual verifier; no arbitrary root signing API.

### 7.4a Actual artifact launch contract (R2-F1; A-ART3, proposed)

**Identity and measurement.** All three CP kinds (`qualification_fixture`, `integrated_source`,
`release`) must be materialized as a single-platform OCI image before execution. No live source bind,
editable installation, bare checkout or arbitrary tar/tree is an admitted CP artifact. Fixture and
integrated images are local test products, not release proof. For each kind, `artifact_digest` is
`sha256:` followed by exactly 64 lowercase hex characters: SHA-256 of the **exact single-platform OCI
manifest bytes**, not an index, tag, config ID, source commit, code manifest, label or requested digest.
Kind is separately bound by the root-selected launch mode and compared exactly; a caller label cannot
upgrade fixture provenance to release. The platform descriptor is selected before launch; ambiguous
selection, unsupported media type/compression/features or multiple candidate manifests refuse.

The host verifier is trusted uid 0 code installed with H6-RUNTIME, invoking the qualified local runtime
through its root-only API. It reads the manifest, config and every referenced compressed layer blob
from the runtime's actual content store, hashes bytes against their descriptors (size and sha256),
accepts only an OCI image manifest (schemaVersion 2) and image config, sha256 descriptors and uncompressed or gzip
OCI tar layers (no foreign layers, nested indexes or runtime conversion); other formats are unsupported.
It checks config rootfs diff_ids against the decompressed streams and verifies the platform. It derives
the complete expected merged root tree by ordered OCI layer/whiteout application, including every file
byte, path/type, symlink target, hardlink relation, mode, uid/gid, mtime and supported xattr. Tree identity excludes host inode/device numbers and atime/ctime,
which are not image metadata; hardlink groups must match and have no external links. Unsupported archive
entries or metadata refuse; no skipping unknown fields with filesystem effects. Hash/descriptor/parse
failure is `artifact_measurement_invalid`. The manifest bytes are the identity even where two manifests
extract to the same root tree. No claimed digest is evidence until these checks and live binding succeed.

Before starting any image entrypoint, root creates a stopped container/snapshot under the lease,
validates the content and complete staged root tree as above, and in ordinary mode compares its measured
kind/digest to the enrolled receipt. A mismatch/tampered object never executes CP code. Root supplies the
fixed trusted P14 entry, explicit mode and managed configuration (`HEEL_MANAGED_HOST=1`); no image
entrypoint, env override, user command or restart policy can select an ungated path. The runtime must
support this stopped-snapshot inspection; otherwise unsupported. The subsequent live rendezvous checks
that precisely that staged immutable snapshot and launch profile were used, not a new resolution of a tag.

At the child rendezvous, root obtains the runtime's immutable container ID and init process identity,
pins the process (pidfd plus start time; no PID-only lookup), and inspects its mount namespace and actual
root through that pinned process. Root enumerates and compares the **entire** live immutable image tree
against the derived tree, including files outside the recipe closure; missing/extra/changed bytes or
metadata refuse. Runtime snapshot ancestry must resolve uniquely to the measured manifest and layers;
an image tag or inspect-reported image string alone is insufficient. An opaque snapshot backend whose
association/contents cannot be checked is unsupported. Runtime-generated files and mounts are not
silently exempt: the closed CP mount profile is exactly §3.2 plus the two private launch pipes. Each
allowed mounted subtree (D_CP, enrollment, maintenance, tmpfs and runtime proc/dev/etc entries) is checked
against that profile and its existing context/inode rules; the obscured image paths are still checked
in the underlying snapshot. No mount may shadow the interpreter, entrypoint, modules or dependencies.
H6-IMAGE records the concrete proc/dev/etc mount list and metadata normalization rules for the chosen
runtime before P17; H6-RUNTIME freezes the fixture profile before qualification, P14 the integrated
profile before its proof. Unspecified mounts/normalization are refusals, not implementation discretion.

**Use-time binding.** Before snapshot creation/inspection the verifier obtains L(SH), then an exclusive
runtime artifact lease (root-only runtime lock/lease object, no new filesystem record). Lock order is
L → artifact lease → child DB lock → SQLite. GC, snapshot/image replacement and mount-profile mutation
must honor the same lease; mutators needing L take EX before any artifact lease. The lease pins the
manifest/blob descriptors, immutable snapshot and launch profile through child exit. Store bytes and
snapshot contents have no writable alias accessible to CP/executor/ingress; runtime rootfs is read-only,
with no writable upper tree, code bind or post-measurement mount mutation. Root store maintenance must
quiesce/reap the child and release its lease before changing those objects. A read-only bind alone is
not evidence of immutability. The qualified backend must supply immutable snapshots plus enforced lease
exclusion, or launch refuses `artifact_measurement_unsupported`. This is a trusted root/runtime contract,
not tamper resistance against compromised root/runtime/kernel. Recipe checks still measure actual loaded
code/dependencies; trusted Python startup must not import from D_CP/tmp/env/PYTHONPATH or mutable paths.

The child starts the trusted P14 entry with neither listener nor reaper constructed, acquires its own
L(SH) and DB lock in the existing order, loads enrollment once, and sends a fresh 32-byte nonce on its
inherited private child→root pipe as exactly
`{schema_version:"heel.cp-artifact-ready.v1", nonce}` (cap 256, canonical, no extra keys).
Frames use a four-byte unsigned big-endian length followed by exactly that many bytes; reject length
above the phase cap before reading its body. No EOF-delimited frame on these lifetime pipes.
Root independently reads fence/J/config/receipt/volume and the live
child facts; it compares child facts rather than trusting a claimed image or tuple. Both sides read the
same receipt inode/bytes under L(SH); for offline modes receipt may be absent and is bound as null.
Root sends exactly one launch frame on the root→child pipe:
`{schema_version:"heel.cp-artifact-launch.v1", nonce, mode, fence_revision, receipt_digest,
artifact_kind, artifact_digest, consumer_recipe_digest, file_binding, cp_volume_id}`.
`nonce`/recipe/receipt digests are hex64, receipt_digest nullable only for offline modes; other types
are the already closed types in §6–§7; cap 2048 bytes, no extra keys, EOF/duplicate/oversize reject.
Frame schema_version is the fixed literal above; mode is the §6.7 enum, fence_revision int
1..2147483647 (never bool), artifact kind/digest as above, and nonce exactly 32 fresh random bytes
encoded as hex64. No secret, proof, credential hash or arbitrary path enters this frame. It is ephemeral, never stored,
logged, exported to cloud or accepted through a socket, CLI or environment variable. Root compares
receipt kind/digest before sending in ordinary mode; CP independently compares them in row 11a.
The ready/launch pair is one-shot. Only `offline_verify_enrollment` subsequently uses the same two
pipes for §7.4's one challenge/response pair, after its offline gate; phase-specific schema and caps
are enforced. Other modes accept no further payload; liveness uses open/closed state only. This does
not create four pipes or recursively invoke enrollment verification during ordinary startup.

`ArtifactObservation` is an opaque in-process value produced by the P14 private-channel adapter:
`measured(kind, digest, binding)` or one of the eight errors below. Binding comprises the fresh nonce,
exact child/mode, L generation (stable inode), fence revision, receipt digest/absence, loaded FileBinding,
recipe and volume; local kernel channel ownership and root's pinned child handle bind the frame to this
process (process IDs need not be serialized). The adapter checks the full frame against its local
observations and consumes it once. The same LoadedEnrollment and immutable observation reach the gate
and listener composition; no reload/spawn/exec may occur between measurement and constructing either
listener. A child exec, exit, namespace/root/config change or re-created pipe invalidates the rendezvous.
The host and child recheck pinned process/mount/lease and context at the permit boundary; changes after
that boundary are excluded by lifetime leases/SH and read-only snapshots, not by a timestamp comparison.
A direct invocation with no inherited root-created channel always fails closed. Test constructors are
never reachable in production composition.

Parent holds L(SH) and the artifact lease for the entire child lifetime. Enrollment ack follows
§7.4 step 5: after reaping release both, acquire fresh EX then a new lease and remeasure; never acquire
L while retaining an artifact lease. Child retains its own
SH and DB lock as before. Parent never takes the child's DB lock or waits under EX. Stop waits for child
exit and reaping before lease release; EX mutation times out `lifecycle_busy` while holders survive.
The private pipes remain open as liveness channels; parent loss/EOF before gate means refuse, after
startup means supervised shutdown/reap. Runtime restart policies and boot units start the **root
verifier**, never an old CP container directly. Each replacement child (including runtime auto-restart,
service restart and reboot) gets a fresh nonce, new measurement and receipt comparison. No disk cache
of a permit is valid. Parent death must not let a surviving child outlive its lease: the backend retains
the lease until that child is reaped, and supervision terminates it. F23 must test this, including
restart recovery of orphaned leases; if unavailable there is no managed launch. No instantaneous
post-start shutdown latency or perfect antirollback claim is made.

**Closed failures and recovery.** Artifact errors are exactly:
`artifact_measurement_missing` (no channel/actual object); `artifact_measurement_unavailable` (I/O,
inspection failure or deadline); `artifact_measurement_invalid` (malformed/tampered manifest/blob/tree);
`artifact_measurement_unsupported` (kind/backend/platform/immutability capability not admitted);
`artifact_measurement_ambiguous` (nonunique manifest/snapshot/process association);
`artifact_mismatch` (measured kind/digest differs from enrolled receipt);
`artifact_binding_changed` (process/context/lease changes);
`artifact_channel_invalid` (nonce/frame/peer/liveness failure).
All refuse before **both** TCP server and Unix listener construction, with no socket inode, DB mutation,
reaper, domain rotation or automatic enrollment. Host emits only the fixed code and exits on errors
before a child exists; after spawn it closes pipes, kills/reaps the unserved child and releases leases.
CP emits only the corresponding fixed gate refusal. Lock acquisition keeps §6.1 bounds; measurement
and rendezvous have a 60-second total deadline after lock acquisition (channel reply after child's
ready frame ≤ 5 s). Timeout refuses and reaps, never falls back to claimed metadata. Large artifacts
that cannot be measured within the bound are unavailable until separately reviewed; no unbounded wait.
Missing/corrupt receipt retains §6.7 row 5 errors. Exact artifact mismatch needs deliberate maintenance
re-verification (§7.5), while transient inspection failures may retry a fresh complete launch. Receipt
replacement requires L(EX), so cannot race a live child or measurement. A same-recipe A′ never borrows
A's receipt; a valid A launch changes no epoch/counter/history. Pending/offline paths measure identically
but do not compare to an old receipt; they never construct listeners and cannot mint ordinary permits.

**Qualification boundary.** F23 [U] is this complete runtime-store/live-snapshot/lease/process/channel
capability, not presumed from an inspect API. H6-RUNTIME proves it with fixture images; P14 proves real
entry/adapter/gate composition; P17 repeats on release artifacts. All scans stream within the declared H6-RUNTIME root-FS/image and memory budgets, including any
comparison index/snapshot scratch; no extra D_CP/slot allocation or unbounded verifier cache is allowed.
Concrete image sizes and measurement resource maxima must be recorded in H6-IMAGE facts and qualified
by the stage owner before launch admission; unavailable capacity refuses. A source recipe, offline model or
one-time image smoke proves none of F23. Missing capability blocks launch; no weaker equivalence policy.
R3 `base-countermodel.json` reproduces the R2 A/A′ serve/serve defect before amendment.
`witness-artifact.json` checks 56 synthetic cases and a 695-byte maximal launch frame; its JSON trees
are not an OCI extractor. `witness-interleavings.json` enumerates 27 schedules (zero stale constructions
under modeled locks; six without enforcement). They check design consistency only; F23 is still unknown.

### 7.5 Operation identities and repair

| Situation | config `operation_id` | fence | DB row `operation_id` | receipt `operation_id` |
|---|---|---|---|---|
| bootstrap/migration pending | intent op | `operation_id` | same op after reconcile | same op |
| restore pending (after `rotate_domain`) | restore op | `operation_id` | same op after reconcile | same op |
| serving / ordinary boot | completed op | `domain_operation_id` | same | same |
| maintenance re-verification (recipe or binding changed, same K) | unchanged domain op | `domain_operation_id` | same | same; new receipt replaces old |

Re-verification creates **no** operation id and no new cycle: `enter_maintenance(enrollment_reverification)`
→ `invalidate_enrollment_verification` → optional `reinstall_enrollment_config` (same bytes, fresh inode)
→ `verify_and_record_enrollment` → `leave_maintenance`. Missing/corrupt/mismatched K is not repairable
this way; it requires domain replacement (§6.10). An artifact or kind change requires this maintenance re-verification even when the recipe is equal.
The ordinary host launch comparison (§7.4a), not recipe inequality, prevents using A's receipt for A';
P17 re-verifies on release. A failed launch never auto-enrolls the newly requested artifact.

Sequence: pending intent → config → offline reconcile/recovery → `record_reconciled` → tunnel record →
offline actual-consumer verify and exit → EX ack → `complete_operation` (J-protected) → ordinary startup
host artifact measurement + bound load/gate → both listeners → readiness → edge smoke → ingress. Authenticated HTTP smoke is after
completion and is never an ack prerequisite; a failed smoke keeps ingress closed and the operator returns to
maintenance only after quiescing holders. Edge/tunnel rotation remains separately owned
([B] `RUNBOOKS.md:117–128`) and never acknowledges enrollment.

### 7.6 Deviations from ENR (explicit) and preserved properties

D-E1 recipe split into a startup-self-measurable digest plus root-observed `artifact_digest` (ENR put the
image digest inside the startup-checked recipe, which the CP cannot measure from inside). R3 adds
mandatory host-side actual-artifact measurement and comparison at every startup (§7.4a); this corrects
R2's unenforced ordinary-start promise without weakening exact identity to recipe equivalence. D-E2 maintenance
reason `enrollment_reverification` replaces `secret_rotation` (K rotation is domain replacement). D-E3 fence
gains `domain_operation_id` so config/DB/receipt operation ids can be compared in serving. D-E4 K staging
lives in the operation intent rather than a separate staging file. D-E5 tunnel evidence is a separate
callable. D-E6 receipt schema v2 adds `artifact_kind`/`artifact_digest` (819 ≤ 1024). Preserved: Customer
§6.1's twelve properties, all 15 outcomes, Q GET/HEAD/one-shot/terminal semantics, no target POST, S
§14.2 nullability/predecessor/expiry, 1 live + 16 retained, 28 KiB, 64 deliveries/10 min, six cleanup
attempts. Threat boundary: protects against an old installation, stale mount/image, executor, ingress or a
holder of ids/receipts/DB snapshots; not against compromised current root, CP or operator, or simultaneous
rollback of fence + config + DB. Old hosts remain powered off/detached/destroyed under operator fencing.

### 7.7 Slot marker `heel.managed-slot-domain.v1` (P12 writer, retained)

`/var/lib/heel/slots/<slot>/domain.json`, root 0600, cap 1024 (max 381), keys `{schema_version, slot_id,
installation_id, restore_epoch, enrollment_secret_id, epoch_id, adopted_at_ms}`. Match → ordinary S
ceremony (authority still from CP); missing with no epoch → write then allocate; missing with epoch,
mismatched or corrupt → close admission, S §4.9 retirement (`local_state_invalid`), then marker, fresh epoch,
seed, pairing/binding/approval; retirement that cannot validate → `cleanup_failed`, no new epoch; fence not
serving → supervisor cannot run.

### 7.8 Volume identity `.heel-volume-id`: exactly 37 bytes (`vol_` + 32 hex + LF), written once, 0:10001 0440.

### 7.9 Denial/provenance-only rule (retained)

`domain.json`, `.heel-volume-id`, the verification receipt and every id may only deny or record provenance;
none selects a runner, reloads a permit, recreates W/Q, resurrects a receipt or authorizes a target request
[R:EA 151, 158–168; P 501; Q 68, 83, 148].

## 8. Early H6-IF → P02 schema amendment (A-P02R2, before the P02 grant)

P02's four paths unchanged (`heel/saas/migrate.py`, `heel/saas/canary_store.py`,
`heel/saas/managed_authority_ledger.py`, `tests/test_managed_authority_migrations.py`). R2 extends R1's
DDL with the durable result columns, provenance and an update rule (explains R1-F2: the result must survive
a lost receipt inside the same transaction). P02 implements it identically in migration and runtime DDL at
its next migration number; P14 is the only writer; readers are the gate and CP runtime epoch checks.

```sql
CREATE TABLE managed_restore_domain (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  installation_id TEXT NOT NULL CHECK (typeof(installation_id)='text' AND length(installation_id)=37
    AND substr(installation_id,1,5)='inst_' AND substr(installation_id,6) NOT GLOB '*[^0-9a-f]*'),
  restore_epoch TEXT NOT NULL CHECK (typeof(restore_epoch)='text' AND length(restore_epoch)=64
    AND restore_epoch NOT GLOB '*[^0-9a-f]*'),
  enrollment_secret_id TEXT NOT NULL CHECK (typeof(enrollment_secret_id)='text' AND length(enrollment_secret_id)=36
    AND substr(enrollment_secret_id,1,4)='enr_' AND substr(enrollment_secret_id,5) NOT GLOB '*[^0-9a-f]*'),
  cp_volume_id TEXT NOT NULL CHECK (typeof(cp_volume_id)='text' AND length(cp_volume_id)=36
    AND substr(cp_volume_id,1,4)='vol_' AND substr(cp_volume_id,5) NOT GLOB '*[^0-9a-f]*'),
  operation_kind TEXT NOT NULL CHECK (typeof(operation_kind)='text'
    AND operation_kind IN ('bootstrap','migration','restore')),
  operation_id TEXT NOT NULL CHECK (typeof(operation_id)='text' AND length(operation_id)=36
    AND substr(operation_id,1,4)='rop_' AND substr(operation_id,5) NOT GLOB '*[^0-9a-f]*'),
  previous_restore_epoch TEXT CHECK ((operation_kind='restore') = (previous_restore_epoch IS NOT NULL)
    AND (previous_restore_epoch IS NULL OR (typeof(previous_restore_epoch)='text'
      AND length(previous_restore_epoch)=64 AND previous_restore_epoch NOT GLOB '*[^0-9a-f]*'
      AND previous_restore_epoch <> restore_epoch))),
  backup_provenance TEXT NOT NULL CHECK (typeof(backup_provenance)='text' AND (
    (operation_kind='bootstrap' AND backup_provenance='none')
    OR (operation_kind='migration' AND backup_provenance='pre_domain')
    OR (operation_kind='restore' AND backup_provenance IN ('pre_domain','domain')))),
  db_schema_version INTEGER NOT NULL CHECK (typeof(db_schema_version)='integer'
    AND db_schema_version BETWEEN 1 AND 2147483647),
  terminalized_reservations INTEGER NOT NULL CHECK (typeof(terminalized_reservations)='integer'
    AND terminalized_reservations BETWEEN 0 AND 2147483647),
  revoked_runner_keys INTEGER NOT NULL CHECK (typeof(revoked_runner_keys)='integer'
    AND revoked_runner_keys BETWEEN 0 AND 2147483647),
  closed_generations INTEGER NOT NULL CHECK (typeof(closed_generations)='integer'
    AND closed_generations BETWEEN 0 AND 2147483647),
  revoked_grants INTEGER NOT NULL CHECK (typeof(revoked_grants)='integer'
    AND revoked_grants BETWEEN 0 AND 2147483647),
  stopped_runs INTEGER NOT NULL CHECK (typeof(stopped_runs)='integer'
    AND stopped_runs BETWEEN 0 AND 2147483647),
  reconciliation_digest TEXT NOT NULL CHECK (typeof(reconciliation_digest)='text'
    AND length(reconciliation_digest)=64 AND reconciliation_digest NOT GLOB '*[^0-9a-f]*'),
  reconciled_at_ms INTEGER NOT NULL CHECK (typeof(reconciled_at_ms)='integer'
    AND reconciled_at_ms BETWEEN 1 AND 9007199254740991),
  CHECK (operation_kind <> 'bootstrap' OR (terminalized_reservations = 0 AND revoked_runner_keys = 0
    AND closed_generations = 0 AND revoked_grants = 0 AND stopped_runs = 0))
);
CREATE TRIGGER managed_restore_domain_no_delete BEFORE DELETE ON managed_restore_domain
BEGIN SELECT RAISE(ABORT, 'managed_restore_domain_immutable'); END;
CREATE TRIGGER managed_restore_domain_update_rule BEFORE UPDATE ON managed_restore_domain
WHEN NEW.operation_kind <> 'restore' OR NEW.backup_provenance <> 'domain'
  OR NEW.operation_id = OLD.operation_id OR NEW.installation_id <> OLD.installation_id
  OR NEW.previous_restore_epoch IS NOT OLD.restore_epoch OR NEW.singleton <> OLD.singleton
BEGIN SELECT RAISE(ABORT, 'managed_restore_domain_update_invalid'); END;
```

Writes: only the P14 offline entry, inside its single reconciliation transaction: `INSERT` (bootstrap,
migration, pre-domain restore) or `UPDATE … WHERE singleton=1` (domain-bearing restore: kind restore,
provenance domain, new operation id, same installation, `previous_restore_epoch` = old epoch). Reader
contract: exactly one row and stored `reconciliation_digest` = `SHA256(J(result-from-columns))`, else
`domain_invalid`; the fence decides completion. SQLite INTEGER affinity converts `True`, `1.0` and `"1"` to integer 1 before
any CHECK runs (`witness-sql.json`), so rejecting bool/float/str is the P14 pre-binding validator's job,
tested by P02/P14, not a DDL guarantee. P02 tests: schema parity
(`test_fresh_runtime_and_upgraded_database_schema_parity`) and
`test_managed_restore_domain_constraints_and_singleton` (all `witness-sql.json` cases) within the existing
test file. Witness `witness_sql.py` extracts this exact block and runs it in-memory (SQLite 3.x):
5 accepted shapes, 26 rejections, 3 recorded affinity coercions, stale-digest reader rejection;
not P02 parity.

## 9. Staged acceptance, DAG and named oracles

```
accepted H3 ─▶ H6-LAUNCH ─▶ I ─▶ P09 ─▶ P10 ─▶ … ─▶ P12 ─▶ P13 ─┐
H6-IF R3 + Q/EA amendment ─▶ plan amendment ─▶ P02 … P05 ─▶ P06/P07  │
                     P05 + H6-LAUNCH ─▶ H6-RUNTIME (provider authz) ─┴─▶ P14 ─▶ P15 ─▶ P16 ─┐
                     H6-IMAGE (H6-IF + accepted, merged B0/BIR handoff) ────────────────────┴─▶ P17 ─▶ P18
```

No stage consumes a later stage's evidence. **H6-RUNTIME** is a prerequisite capability qualification on a
real host with a labelled source-pinned `qualification_fixture`: provisioning/layout/UIDs, devices, §5.3
measurements, slot quota capability and inode/block exhaustion, fence/J/intent callables with fault
injection, cross-container flock with a minimal holder container, mount/pipe/process-inspection capability
for §7.4/§7.4a with a fixture verifier (including actual OCI measurement and lease binding), kernel/nft/HZ/setns profile, container capability, pause behaviour,
provider power-off/destroy, backup exclusion. It neither requires nor claims P14 integrated restore, P15
transport, P16 browser, P17 artifact or P18 customer proof. **P14** proves the actual integrated
loader/verifier/gate/offline entries on `integrated_source`; **P17** proves packaged identity and
re-verifies enrollment on `release`; **P18** customer use. Mocked consumers never discharge a real gate.

**25 named oracles** (17 original + 8 review; all PENDING until their owners execute them in authorized
environments):

| # | Test | Owner (file) | Oracle |
|---|---|---|---|
| 1 | T-P01 `test_accepted_host_useful_path` | P15 (`tests/linux/test_managed_authority_proof.py`) + P16 | real CP/root/container; inert pairing → W → Q lower GET → Q higher GET → redacted findings |
| 2 | T-P02 `test_restore_complete_then_fresh_pairing_useful` | P14 → P15 | full restore incl. enrollment verify; fresh seed/pair/bind/approval; useful GET pair; old grants refused |
| 3 | T-P03 `test_reboot_keeps_epoch_and_counters` | H6-RUNTIME fence half; P14 CP half | same fence/epoch/counters; uncertain-completion cut C2 refuses until recovery |
| 4 | T-N01 `test_maintenance_or_pending_publishes_neither_listener` | P14 | every non-serve decision incl. J present and verifier mode: no TCP listen, no socket inode |
| 5 | T-N02 `test_fence_missing_invalid_profile_symlink_hardlink_same_device_refused` | H6-RUNTIME (`tests/test_managed_fence.py`) + P14 | each fence error incl. `fence_publication_uncertain`; orphan/wrong-profile L repair |
| 6 | T-N03 `test_executor_uid_collision_or_group_membership_refused` | H6-RUNTIME (`tests/test_managed_host_layout.py`) | uid ∈ {0,10001,10002,65534, reused} or any group → refuse |
| 7 | T-N04 `test_epoch_parent_symlink_mount_or_mode_drift_refused` | H6-LAUNCH + P12 | drift at any component → refuse |
| 8 | T-N05 `test_cp_admission_refuses_at_ceiling_terminal_still_commits` | P06 + H6-RUNTIME | §5.4; R commits in reserve |
| 9 | T-N06 `test_blocked_checkpoint_wal_cap_refuses_admission` | P06 | long reader, WAL > 64 MiB → refuse |
| 10 | T-N07 `test_slot_quota_exhaustion_capacity_unavailable_no_deletion` | H6-RUNTIME + P12 | block **and inode** exhaustion by executor writes; root cleanup completes; fresh allocation honest |
| 11 | T-N08 `test_restored_db_with_old_live_host_rejected` | P14 | old holder → `lifecycle_busy`; old epoch → `restore_mismatch`; old K → 401 |
| 12 | T-N09 `test_provider_pause_longer_than_window_never_extends_authority` | H6-RUNTIME facts + P15 | pause > 3 s; no packet without fresh Q; STOP ≤ 5 s |
| 13 | T-N10 `test_interrupted_operation_each_stage_stays_disabled` | H6-RUNTIME + P14 | every §6.9 cut; same op id; one epoch/K |
| 14 | T-N11 `test_executor_host_tmp_and_host_root_unreachable` | H6-LAUNCH | during-run denial |
| 15 | T-N12 `test_rotation_old_host_and_old_slot_identity_rejected` | P12 + P14 | old marker/epoch refused; old K/id/receipt cannot authenticate |
| 16 | T-N13 `test_backup_excludes_slot_fs_fence_and_secrets` | H6-RUNTIME | backup contains only CP DB; no K/intent/config/receipt |
| 17 | T-N14 `test_restored_completion_marker_is_not_permission` | P14 | restored row + pending fence → refuse |
| 18 | `test_workspace_container_selected_home_and_host_path_denial` | H6-LAUNCH; P15 rerun; P18 `release` | §4.6; no K in executor |
| 19 | `test_aggregate_physical_budget_and_terminal_reserve` | H6-RUNTIME + P06 | partition; data + inode fill; WAL reader; reserve intact |
| 20 | `test_fence_cas_two_writers_and_startup_interleavings` | H6-RUNTIME + P14 | lock schedules incl. verifier SH/parent EX, old/new volumes |
| 21 | `test_fresh_bootstrap_and_restore_schema_parity` | P02 + P14 | bootstrap, both migrations, pre-domain and domain restore incl. lost-receipt recovery |
| 22 | `test_fence_closed_records_crossfield_mutations` | H6-RUNTIME + P14 | every variant/record of §6–§7 constructible; mutants and cap+1 reject |
| 23 | `test_enrollment_rotation_and_domain_markers_never_authorize` | P05 + H6-RUNTIME + P12 + P14 | E01–E15 below; markers/ids never authorize |
| 24 | `test_restore_interruption_and_old_host_exclusion` | P14 on qualified host | crash/reboot each stage; fenced old host/image cannot rejoin |
| 25 | `test_layout_lifetime_binding_and_hostile_mutations` | H6-RUNTIME | §3.4 incl. released device size |

Final artifact journey (P17 parity + P18 clean room, `release`) is an additional obligation, not a row.

**Enrollment oracles (from ENR, owners per §12):** E01 P05 `tests/test_host_enrollment.py` correct
key/C/path/body accepts on all three routes; old/wrong key, copied ids/receipt/DB → 401 before
decider/charge/sequence. E02 same: wrong uid, overflowuid, wrong pidns deny before read (P15 proves real
SO_PEERCRED). E03 same: header/config grammar mutants, cap+1, framing ambiguity reject; no bytes logged.
E04 same + `tests/test_managed_attempt_admission.py`: altered path/body/epoch/host/volume under captured
MAC reject; valid replay cannot execute Q twice. E05 H6-RUNTIME `tests/test_managed_fence.py`: §6.9 cuts
for key/config/receipt/fence. E06 H6-RUNTIME layout test + qualification script: root/CP inode equality,
wrong bind/profile/uid map/symlink/hardlink refuse; executor/ingress cannot read K; pipes never logged.
E07 P14 `tests/test_managed_restore.py`: same fence/DB/volume with different loaded binding → serve vs
refuse; listener gets the gate's object. E08 P14 + `scripts/managed_restore_proof.py`: actual entry/mount/key
positive; same-id wrong K, old bind/image, stale/forged receipt, wrong recipe, EOF/timeout/killed child
cannot ack; no listener before completion. E09 P14: revision/config change between verify and EX forces
re-verify; receipt-before-fence and lost ack recover. E10 P14: four journeys positive, all
volume×config×state mismatches deny, lost receipt recovers. E11 P12 `tests/test_managed_root_ceremony.py`:
key/header absent from executor IPC; marker retirement; cleanup under inode exhaustion. E12 P14→P15 old
credential rejected with authorized old-host fencing evidence. E13 P14/P15 complete → useful GET pair.
E14 P17 `tests/test_managed_artifact_parity.py` release loader/verifier/prefix, no secret in
layers/wheel/logs. E15 existing owner tests: K/proof absent from DB, diagnostics, traces, CI, cloud.
E16 H6-RUNTIME + P14: A/A′ same recipe but different manifest, same A positive and kind mismatch;
compare actual content/snapshot, not requested tag; every refusal opens neither listener.
E17 same: missing/ambiguous/unsupported backend, tampered blob/tree, wrong receipt, forged/replayed
frame/nonce, direct CLI, EOF and timeout fail closed. E18 same: ordinary/restart/runtime restart/boot all
measure anew; no permit cache, no receipt means no serve. E19 same: concurrent tag replacement, snapshot
mutation/GC and receipt/config mutation at every rendezvous cut; lifetime lease/SH block replacement or
binding drift refuses; parent kill and orphan restart never release a live child's artifact.
E20 P17 E14 parity extension: same checks for release with no source checkout; P14 verifies offline
bootstrap/reconcile/verifier → ack → complete → ordinary host launch → listeners remains acyclic.
These extend rows 3, 4, 11, 20, 23, 24, not the count of 25 real oracles.

All customer O01–O15 and safety S01–S12 (P 718–755) remain required; this interface waives none.
P18 needs synthetic layer 1 and an authorized real SaaS unprepared for Heel at layer 2, plus actual
C3/DA/C5/C6/H3/H6 gates. C3 STOP and pending H3/B0 reviews are unchanged.

## 10. Image and build-input handoff

BIR (accepted) grants B0 exactly five paths; B0 `5eefa25` is not accepted. After B0 independent
source/provenance review, exact-tree CI image acceptance and merge, `deploy/Dockerfile.control-plane` and
`.github/workflows/ci.yml` pass to P17; `deploy/requirements-control-plane.txt`,
`scripts/verify_control_plane_image.py`, `tests/test_saas_deployment.py` stay read-only for P17. P17 keeps
exactly **10 + 3** paths (P 650); nothing appended. A current-CP image is never final managed evidence.

H6-IMAGE (fresh Opus/Astra; after H6-IF and the accepted, merged B0 handoff; 2 paths:
`docs/saas/MANAGED_HOST_IMAGE_FACTS.md`, `tests/test_managed_host_image_facts.py`) writes **facts only**:
executor base and BuildKit frontend digests; hash-locked runtime closure with no test packages and no shell;
the `/opt/heel` prefix layout (§4.2: `/opt/heel/deploy/host/executor.py`, `/opt/heel/heel/{runner,saas}`,
fixed dependency directory, interpreter path); rootfs contract §4.3; CP enrollment directory bind and
receipt path; consumer-recipe manifest layout (§7.4); mount table; rollback inputs. Executor lock: hash-
locked requirement lines embedded in `deploy/Dockerfile.executor` as a BuildKit heredoc consumed by `pip
install --require-hashes --only-binary=:all: --no-index` (inside P17's existing path); fallback
`deploy/requirements-executor.txt` only via a separately reviewed handoff before P17. H6-IMAGE writes no
Dockerfile/compose/env/lock/builder/CI path and no artifact; `install-rootfs` later consumes the P17 image.
Public wheel exclusion and commercial classification preserved; no public shim or relicensing.

## 11. Host/provider fact manifest

| ID | Fact | Status | Evidence / action |
|---|---|---|---|
| F1 | DigitalOcean Basic 2 vCPU/4 GiB/80 GiB + Spaces intent; nothing purchased | historical intent | `CONTROL-PLANE-HOST-PROPOSAL/ASTRA-NOTE.md` |
| F2 | Billing incomplete at last check | historical | owner re-check |
| F3 | Regional availability | [U] | provider console under H6-RUNTIME authorization |
| F4 | Railway containers unverified for setns/nft/fencing | CONFIRMED absence of proof | Customer 615 |
| F5 | Local Docker daemon unavailable | historical | — |
| F6 | Kernel ∈ {6.8, 6.17, 7.0}, nft 1.0.9, HZ | requirement [B] `profile.py:14–17`; target [U] | self-test |
| F7 | CP identity uid map | [U] | `/proc/<pid>/uid_map` |
| F8 | Host Python `os.setns` (3.12+) | [U] | target check |
| F9 | Fixed-size devices, ext4 reserved-block control, preallocation | [U] | `findmnt`, `blockdev`, `tune2fs -l`, `statvfs` |
| F10 | `/run` tmpfs | [U] | `findmnt -T /run` |
| F11 | Egress outside the executor | [U] | H6-RUNTIME + P15 |
| F12 | Pause semantics | [U] | T-N09 |
| F13 | Provider snapshot scope; Spaces encryption | [U] | docs + drill |
| F14 | Provider power-off/destroy/detach | [U] | authorized capability |
| F15 | CP immutable inputs | BIR accepted design; B0 not accepted | BIR |
| F16 | No executor image/Dockerfile at B | CONFIRMED | `git ls-tree f736279 -- deploy` |
| F17 | flock exclusion across the CP read-only bind | [U] | lock-holder container test |
| F18 | Namespaces/pivot_root/procfs subset/PDEATHSIG/ctypes | [U] | `managed_container_proof.py` |
| F19 | `statvfs` behaviour, ext4 overhead on 768/32 MiB | [U] | H6-RUNTIME |
| F20 | fsync/dir-fsync honesty after success; behaviour after a failed fsync | [U] (design assumes fsync success ⇒ durable; failure ⇒ fresh rewrite) | fault-injection on target FS |
| F21 | ext4 usrquota inode hard limit enforced for the executor uid inside the container; `I0` value | [U] | §5.5 probe |
| F23 | Every-launch content-store/live-root measurement, immutable snapshot lease, pinned process and private channel including parent-loss/restart | [U] | §7.4a; E16–E20, fail closed if unavailable |
| F22 | Root inspection of a CP container child (`/proc/<pid>/root`, ns, uid_map) and private pipes under the chosen runtime | [U] | H6-RUNTIME fixture verifier; P14 actual |

No credential, target request, provider login, Docker or SSH action was used for this document.

## 12. Proposed amendment manifest, ownership and counts (awaiting fresh review)

| ID | Amendment | Affected owner |
|---|---|---|
| A-LAUNCH | H6-LAUNCH 6 paths (§4.7) between accepted H3 and I | I manifest; P 36/173 topology text |
| A-LOCK2 | L creation/repair, holders, no upgrade, verifier SH (§6.1) | H6-RUNTIME; P12 supervisor/signer; P14 server/offline entries |
| A-STORE2 | Partition (§5.1); capacity mutex (§5.4); D_CP `-N 16384`; slot quota/inode reserve (§5.5) | P05, P06, H6-RUNTIME, P12; P17 compose facts |
| A-FENCE2 | fence v2, J protocol, intent, callables, crash cuts (§6.2–6.5, 6.9) | H6-RUNTIME |
| A-RECON2 | result/receipt v2, recovery predicate, provenance variants (§6.6, 6.7, 6.10) | P14 |
| A-P02R2 | DDL extension (§8) in the P02 grant text before P02 starts | P02 (four paths unchanged) |
| A-ART3 | Every-launch actual artifact observation, exact receipt comparison and lifetime binding (§7.4a); all three CP kinds OCI | H6-RUNTIME producer, P14 adapter/gate, H6-IMAGE facts, P17 release wiring/parity; proposed plan text amendment only |
| A-ENR2 | **Q §3/§6.7 and EA §4/§7 transport-auth amendment** + config/observations/verifier/receipt (§7) | Q/EA owners (review), P05, P12, P14, H6-RUNTIME, H6-IMAGE, P17 |
| A-PREFIX | `/opt/heel/deploy/host/executor.py`, `/opt/heel/heel/{runner,saas}`, rootfs store relocation (§4.2, §10) | H6-LAUNCH, H6-IMAGE, P09–P12 executor writers, P17 |
| A-P15 | P15 reruns `managed_container_proof.py` | P15 rerun list |
| A-RUN | D_CP not expandable; restore-only replacement; K replacement = domain replacement | P14 `RUNBOOKS.md` text |

**Plan recount.** Accepted P (38e6bf1) = 106 entries. A-ENR2 adds exactly one P05 entry,
`tests/test_host_enrollment.py` (create; a private test, not a `heel/` path, so `HEEL_TREE_FILES` is
unchanged): P05 5 → 6, plan total **107**, all packets ≤ 10 + 3. No P01 codec edit; P01C `df903403` files
untouched. P02 stays 4 (+3 only via its separately granted inventory packet per P 118). No other plan
packet gains a path. The plan amendment itself is one separately serialized document change after whole H6R3
acceptance (not made here).

**External packets (not in the 106/107 ledger):** H6-LAUNCH 6+0; H6-RUNTIME 6+0 (`deploy/host/
managed_fence.py`, `deploy/host/managed_host_layout.py`, `scripts/managed_host_qualification.py`,
`tests/test_managed_fence.py`, `tests/test_managed_host_layout.py`, `docs/saas/MANAGED_HOST_RUNTIME.md`);
H6-IMAGE 2+0; per-addition H2 inventory packets 3+0 each (P 118). H6-RUNTIME writes no
`deploy/host/{executor,executor_link,supervisor,cycle}.py`, `managed_identity.py`, `managed_pairing.py`,
`managed_migration.py`, `heel/saas/*`, `RUNBOOKS.md`, P02 or P17 path.

**Same-file handoffs and wiring.** `deploy/host/supervisor.py`: H3 → H6-LAUNCH → P09 → P12 (P12 adds L(SH)
and root signer). `deploy/host/executor.py`: P09 → P10 → P11 → P12 (+ any dependency `sys.path` line).
`heel/saas/managed_authority_ledger.py`: P02 → P05. `heel/saas/host_authority.py`: P05 only (loader,
authenticator, 401 status, `HostAuthorityService(enrollment=LoadedEnrollment)` constructor parameter
required in managed mode). `heel/saas/server.py`: P14 only (load once, gate, pass the same object to the
service; offline modes). Capacity mutex: P05 introduces, P06 proves (owner caveat §5.4). H6-RUNTIME imports
the P05 loader/authenticator from `/opt/heel/heel/saas` and therefore follows P05 acceptance; it never
imports P14 code at import time and uses a fixture verifier until P14. P17 compose/env-example carry only
mount paths, never K.

**A-ART3 ownership within these same lists (proposed, not a grant):** root launch/measurement/lease
orchestration is `deploy/host/managed_fence.py`; layout/runtime adapter in
`deploy/host/managed_host_layout.py`; fixture proof in `scripts/managed_host_qualification.py` and the
two existing H6-RUNTIME tests. P14 `heel/saas/server.py` owns the private-channel adapter and ordinary/
offline entry wiring; `tests/test_managed_restore.py` and `scripts/managed_restore_proof.py` own its
integrated witnesses. H6-IMAGE's two facts paths freeze the OCI/snapshot/mount profile; P17's existing
compose/Dockerfile/parity paths wire the root launcher and disable direct CP restart. The launcher runs
on the host via the private `/opt/heel` closure; it does not add root credentials/runtime sockets to CP.
The plan amendment must state those responsibilities and root service invocation in existing H6-RUNTIME
runtime documentation/P17 deployment wiring; if those existing paths cannot express deployment, stop
for reviewed ownership amendment, never invent an extra systemd/unit path. P14 code is not imported by
H6-RUNTIME before P14; the fixture implements the channel protocol for capability tests only. Counts
remain 6/6/2, P05 6, P11 7+3, P17 10+3, proposed total 107, inventory packets separately 3. No new dependency
on P17 is introduced into H6-RUNTIME: fixture manifests/profile precede integrated and release proofs.

**Test owners (no unowned work):** P05 E01–E04; P12 E11 + T-N04/T-N07/T-N12; P14 E07–E10, E12–E13 + T-P02,
T-N01, T-N08, T-N10, T-N14, rows 20–24 CP halves; H6-RUNTIME E05–E06 + T-P03, T-N02, T-N03, T-N05,
T-N07, T-N09, T-N10, T-N13, rows 19–25 host halves; H6-LAUNCH rows 14, 18, T-N04; P02 row 21 DDL; P06
T-N05/T-N06/row 19; P15 T-P01, T-N09, E12–E13 reruns; P17 E14; P18 final journey. Nothing here claims any
of them ready.

## 13. F1–F4 response matrix

| Required by REV2 / assignment | Where | Evidence kind |
|---|---|---|
| F1 distinct K, private root/config/context | §7.1, §3.1 | design; `witness-records.json` sizes |
| F1 HMAC header on 3 Q routes + SO_PEERCRED, body/receipt/method unchanged, ≤ 8192 | §7.2 | HMAC mutation witness (36 distinct); head 261 B |
| F1 authentication only, no secret in receipts/logs/DB/cloud/executor IPC, no edge reuse | §7.2, §7.4, §4.2 | design; E14/E15 later |
| F1 production-loaded object into gate + listener; trusted observations | §6.7, §7.3 | gate rows 3, 9–11 |
| F1 listener-free actual verifier, private pipes, root inspection, same-id wrong secret | §7.4, E08 | design; F22 [U] |
| F1 SH child → exit → EX ack, revision/binding recheck | §7.4 steps 1–5 | `witness-cuts.json` D |
| F1 operation identities for boot/replacement/repair; K replacement = domain replacement | §7.5, §6.10 | table |
| F1 Q/EA amendment explicit and pending | §0, §7, §12 A-ENR2 | — |
| F2 durable same-operation result/recovery for 4 journeys | §6.6, §6.7 rows 15–18, §8 | `witness-cuts.json` B; `witness-sql.json` |
| F2 no arbitrary new-domain row; no atomic DB+fence assumption | §6.7, §6.9 | B negative control |
| F2 P02 closed DDL inside 4 paths | §8 | in-memory SQLite |
| F2 pre-domain provenance positive/refused variants without invented ids; journeys preserved | §6.10 | design |
| F3 orphan L, durable intent, same key/epoch reuse | §6.1, §6.4 | `witness-cuts.json` C |
| F3 uncertain serving publication; failed sync; startup qualification | §6.3, §6.7 row 1 | `witness-cuts.json` A |
| F3 L→DB→SQLite, all holders, bounded, no upgrade/deadlock | §6.1 | D |
| F3 initialize/adopt/complete/leave-maintenance cuts, volumes, secret/config/receipt | §6.9 | tables + A/B/C |
| F4 concrete inode/metadata reservation within 32 MiB/2 MiB/1 GiB; worst case | §5.5 | `witness-inodes.json` (27 ≤ 64 inodes, 179 ≤ 512 blocks; R1 negative control fails cleanup) |
| F4 capability test with refusal; later H6/P12 real exhaustion tests | §5.5, T-N07 | F21 [U] |
| Nonblocking grammar items | §3.4, §6.6, §9, §4.2/§10, §12 | records witness |

## 14. Qualified unknowns and smallest blockers (not waivers)

- All [U] facts and every runtime row of §9 are pending; witnesses prove contract arithmetic and finite
  models only, never ext4, kernel, SQLite durability, container runtime or provider behaviour.
- F20/F21/F22 and F23 are load-bearing capability facts. F23 failure denies every managed launch
  with the corresponding artifact error; no self-reported image identity or recipe fallback. Smallest concrete blocker if F21 fails on the chosen
  host: no slot can be provisioned (`slot_inode_reserve_unavailable`); the next smallest alternative is a
  separately reviewed second fixed-size root-only filesystem per slot carved from the same 32 MiB (no
  aggregate change). If F22 fails (runtime cannot expose child process identity/mounts to root, or no
  private pipes), A-ENR2 is unsatisfiable on that runtime and enrollment acceptance is blocked; no weaker
  verifier is substituted.
- §5.6 capacity (≤ 8 slots, ≈ 4021 executor inodes each) may be unacceptable for launch; only a reviewed
  requirements amendment can change it.
- The A-ENR2 Q/EA amendment, the P05 test addition and the plan recount become effective only after fresh
  independent acceptance and a separately serialized plan amendment.
- Capacity-mutex terminal/R writer placement (§5.4) must be confirmed against P05's list before its grant.

R3 evidence: `.worktrees/heel-task-evidence/H6-HOST-INTERFACE-R3/` (base countermodel, artifact
witness, regression reruns, ownership matrix, REPORT/CLOSING/COMMANDS and seal). R2 historical evidence:
`.worktrees/heel-task-evidence/H6-HOST-INTERFACE-R2/` (REPORT, CLOSING, COMMANDS, source and
hash manifests, four witnesses). Final `ACCEPTANCE.json` is reviewer-owned.
