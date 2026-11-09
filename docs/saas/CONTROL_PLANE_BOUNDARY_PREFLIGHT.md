# Control-plane boundary preflight (read-only Ubuntu 24.04 facts)

Status: R4 source candidate for a fresh independent source/contract/privacy review. It corrects the
fourth preflight source-review FAIL (candidate 5b6c80eb: malformed mount records were reported as
complete facts), which followed the failures of db2e9c05, 47adfb08 and ee2979b5. This is the one
additional correction cycle that was explicitly approved; any further failure returns for a human
decision rather than starting another cycle. It has not been run on a hosted runner.
B0 source remains FAIL after two failed R1/R2 review cycles (candidate be95cb3c / tree b293cc1b). The actual
image/runtime boundary remains NO-GO. This preflight changes neither.

## What it is

`scripts/control_plane_boundary_preflight.py` is a standalone, stdlib-only collector of the finite
read-only observations in `CONTROL-PLANE-BOUNDARY-FEASIBILITY/PROPOSED-SCOPE.md`. It records
installed configuration facts for a future private-boundary decision.
It is not runtime qualification. Every report declares `runtime_qualified` as always `false`, `verdict` as `UNPROVEN`
and `b0_effect` as `none`. A complete observation with no listed gap is still UNPROVEN.

Installed configuration is not effective delegation, isolation, access denial, cleanup or latency.
None of these facts establishes a private Docker lifecycle, a hard deadline, reaping, positive
cleanup or terminal evidence publication. The parent adjudication of catastrophic-failure semantics
is not used, weakened or exercised by this collector, and it does not excuse an ordinary collector
fact being reported complete when it is not.

## Invocation and refusal

The script takes no arguments, paths, selectors or input. Run it only as
`/usr/bin/python3 -I -B scripts/control_plane_boundary_preflight.py` from the repository root. It
uses the image's existing Python and records its version. It never installs anything.

Before any host file read or command, it refuses (exit 2) in four cases: arguments are present, the
platform is not `linux`/`x86_64`, `GITHUB_ACTIONS` is not `true` or `RUNNER_ENVIRONMENT` is not
`github-hosted`, or Python is older than 3.10. The refusal still writes the closed report.

| Exit | Meaning |
|---|---|
| 0 | complete observation: every fact is observed or determinately absent (see the contract below). It does not mean any prerequisite is met. |
| 1 | internal error: the output directory already exists (earlier evidence is never reused, removed or overwritten), a contract check failed, or finalization ran past the cooperative deadline. No artifact is published. |
| 2 | refused before host reads (unsupported platform, arguments or Python) |
| 3 | incomplete observation: at least one fact is unknown; `incomplete_reasons` names each one |

Only exit 0 means complete observation. Exit 0 never means PASS.

## Observation-completion contract

Every fact has exactly one of three states:

* **observed**: a value, reduced to a closed enum, number, approved version token or SHA-256.
* **determinately absent**: the literal `absent`, used only where absence is itself a documented
  fact. These are ENOENT on a fixed path, such as an optional sysctl, a tool directory entry, a
  profile file, a shared endpoint, `cgroup.kill` or `/etc/subuid`. They also include a name that is
  missing from a fully and strictly parsed local file.
* **unknown**: one of `denied`, `error`, `malformed`, `oversize`, `not_regular`,
  `deadline_exhausted`, `deadline_overrun`, `aggregate_exhausted`, `unrecognized`, `ambiguous`,
  `unavailable`, `unsupported` or `command_failed`.

The rules are:

* Every unknown value has an `incomplete_reasons` entry in its own area, and the observation is then
  `incomplete`. The collector raises an internal error rather than emit an unknown value without its
  reason.
* Completion is checked structurally, fact by fact, by a checker that is independent of the producers
  (`_fact_contract_violations`). It does not rely on spotting an unknown token. A required fact that
  is null where its controlling state says it applies (for example rule facts of a `listed` sudo
  query, or the fstype of a `resolved` mount) is an internal error, never a silent complete. Only two
  os-release fields (`point_version`, `codename`) are optional.
* An observed free-grammar string (`ImageOS`, os-release `ID` or `VERSION_CODENAME`) that equals an
  unknown token or `absent` is `malformed`. Observed values and unknown states never share a spelling.
* There is no exception for denial. For example, a root-only AppArmor loaded-policy list answering
  `denied` is recorded as the query outcome. Its content is still unknown, so the observation is
  incomplete. A normal unprivileged hosted run is therefore expected to be incomplete there. The
  report stays useful: every other fact is still present.
* Missing required provenance is unknown: an unset `ImageVersion`, run ID or attempt is
  `unavailable`, not a null that could read as absence.
* Malformed or unrecognized `sudo -n -l`, AppArmor list, `/etc/passwd`, `/etc/group` or ID-map
  input is unknown, never a negative fact.
* A known query outcome does not make its unread content known. `sudo -n -l` answering
  `password_required` keeps `state=password_required` but `rule_facts=unavailable` with the reason
  `sudo_rules:unavailable`, so the run is incomplete. No retry or escalation is attempted.
* `prerequisite_gaps` are derived only from observed or absent facts. A denied `cgroup.kill` stat
  never produces `self_cgroup_kill_absent`, and an unreadable os-release never produces
  `os_not_ubuntu_24_04`.
* Report fields are never silently dropped. A failing field keeps its key, holding its unknown state
  or null.

## Observations and how each is obtained

Most proposed shell commands are replaced by bounded reads in Python. That removes program execution
and output parsing for those facts. The only executed programs are the five fixed argv tuples in
`COMMANDS`:

* `/usr/bin/systemctl --version --no-pager`
* `/usr/bin/systemctl show --property=Version --no-pager`
* `/usr/bin/sudo -n -l`
* `/usr/bin/git rev-parse HEAD HEAD^{tree}`
* `/usr/bin/git -c core.fsmonitor=false status --porcelain=v1 --untracked-files=no`. The
  `core.fsmonitor=false` setting keeps `git status` from starting a filesystem-monitor daemon.

| Proposed observation | Implementation | Emitted |
|---|---|---|
| `uname -srm`, `getconf _NPROCESSORS_ONLN`, `/etc/os-release` | `os.uname()`, `os.sysconf`, bounded read | sysname/machine enums, kernel release token, CPU count, os-release state, `ID`/`VERSION_ID`/`VERSION_CODENAME` and the numeric point version |
| `/proc/1/comm`, `systemctl --version`, `systemctl show --property=Version` | bounded read plus two fixed commands | PID 1 name enum, systemd major and version tokens |
| `stat -fc %T /sys/fs/cgroup`, controllers, `/proc/self/cgroup` | mount topology resolution of `/sys/fs/cgroup` from `/proc/self/mountinfo`, bounded reads | visible fstype, whether that mount is at the target, unified flag, controller enums, own-cgroup depth/class/suffix/SHA-256 of path, `cgroup.kill` presence (stat only), own controllers and subtree_control |
| `command -v` the ten tools plus `sha256sum` | selected-path inventory: the first existing entry among `/usr/local/sbin`, `/usr/local/bin`, `/usr/sbin`, `/usr/bin`, `/sbin`, `/bin`; hashlib streaming | per-tool state (`found_regular`, `absent`, `first_entry_not_regular`, `dangling_symlink`, `outside_fixed_roots` or unknown), directory index, symlink flag, size, SHA-256, mode, owner, setuid, any-execute-bit, file-capability presence |
| userns sysctls, rootlesskit AppArmor profile | bounded reads of fixed `/proc/sys` files, three fixed profile paths, the loaded-profile list | integers, profile size/SHA-256, lexical `userns`-rule and unconfined-flag hints, loaded profile count and rootlesskit mode enum |
| `id -u`, `id -G`, `sudo -n -l` | `os.getuid`/`getgroups`, strict bounded parse of local `/etc/group`, one fixed command | numeric IDs, up to 64 sorted groups with total and truncation marker, local docker-group presence and membership, sudo classification |
| `/etc/subuid`, `/etc/subgid` for `heel-image-proof` | strict bounded parse of local `/etc/passwd` and `/etc/group`, bounded reads | account presence, login-shell class, privileged groups, start/count/sufficiency/overlap/multiplicity for that name only |
| `findmnt --target`, `df -B1`, `df -i` for `/run` and `/home/runner/work` | topology resolution over `/proc/self/mountinfo`, `os.statvfs` | resolution state, visible mount point enum and whether it is the target, fstype enum, propagation enum, `ro`/`rw` booleans (exactly one true), `nosuid`/`nodev`/`noexec` booleans or `unrecognized`, bytes and inodes, 5 GiB floor flag |
| `stat -Lc '%u %g %a %F'` for the four shared endpoints | `os.lstat` and `os.stat` | state, type, uid, gid, mode, symlink flag |
| source identity, runner identity | the two git commands; allowlisted environment variables | 40- or 64-hex head/tree, clean flag and dirty-entry count; `RUNNER_OS`, `RUNNER_ARCH`, `ImageOS`, `ImageVersion`, run id and attempt checked against fixed grammars |

The account `heel-image-proof` is an explicitly proposed non-login, non-sudo, non-Docker-group
identity. Its absence is the expected fact. The collector never creates or edits an account, group,
range or policy.

### Mount topology, not path prefixes

The `/proc/self/mountinfo` mount and parent IDs are kept. The visible mount at a target is found by
walking down from the single root mount, one path component at a time. At each step the walk follows
only a mount whose parent is the mount currently visible there, and climbs stacks at the same mount
point. The rules follow from that:

* A mount below a covered (hidden) ancestor is never chosen.
* Input order is irrelevant.
* Ambiguous topology is `ambiguous`, never guessed. That covers no unique root, two siblings on one
  point, a cycle, and a mount that does not reach the root.
* The same resolver decides what is visible at `/sys/fs/cgroup`. Own-cgroup files are read there
  only when the visible mount is cgroup2 mounted at its own root. Otherwise their mapping is
  `ambiguous` or `unavailable`.

This is the collector's own resolution of the kernel's table. It is not `findmnt` output.

### Mount records: every consumed field validated first

No mount fact is derived until every record of the table has passed the grammar below. It follows
the Linux v6.8 printer: `show_mountinfo`, `show_mnt_opts` and `show_type` (fs/proc_namespace.c),
`show_path` and `mnt_alloc_id` (fs/namespace.c), `mangle_path` (fs/seq_file.c), `MAJOR`/`MINOR`
(include/linux/kdev_t.h) and proc_pid_mountinfo(5). Ubuntu's patched kernel and the hosted image
kernel are not pinned; equivalence to them is inferred, not observed.

* Framing. A record is one LF-terminated ASCII line of at most 4096 bytes and 64 space-separated
  fields, counted before the split. An empty record, or a CR before the LF, is malformed.
* IDs and device. Mount and parent IDs are canonical decimals (no sign, no leading zero) from 0 to
  2^31-1. The device is `MAJOR:MINOR` in the same form, major at most 4095 and minor at most 2^20-1.
  A repeated mount ID is malformed.
* Root and mount point. Each is non-empty with no NUL. Every backslash must start a three-digit
  octal escape of a non-NUL byte. The mount point decodes only the printer's escapes (space, tab,
  LF, backslash) and must be canonical absolute: `/`, or no trailing, empty, `.` or `..` component.
  The root must start with `/`. It is not required to be canonical, because the kernel prints an
  unlinked root as `<path>//deleted`, and its escapes may come from a filesystem's own `show_path`.
* Per-mount options. The field is non-empty with at most 64 comma components, counted before the
  split. The first component is exactly one access mode, `ro` or `rw`. Every later component is a
  unique token `[a-z][a-z0-9_]{0,31}` that is neither `ro` nor `rw`. The recognized tokens
  (`nosuid nodev noexec noatime nodiratime relatime nosymfollow idmapped`) keep the kernel's order.
  An empty component, a second access mode, a duplicate, an order violation or any other character
  makes the table malformed.
* Optional fields, then propagation. See below.
* Separator and the remaining fields. A lone `-` follows the optional fields, then exactly three
  fields: filesystem type, source and super options. The filesystem type is non-empty and decodes
  only the printer's escapes (space, tab, LF, backslash, `#`). It is reported as an enum or `other`.
  The source may be empty, because `mount(2)` accepts an empty source string; it is never stored. The
  super options must start with `ro` or `rw`, ending at a comma or the field. The rest is
  filesystem-specific and is never stored or interpreted.
* Any violation anywhere makes the whole table `malformed` with `mountinfo:malformed`. Every mount
  fact is then `unavailable`, and the run is incomplete with exit 3. The facts that do not depend
  on the table, such as existence, file type and space, are still reported.

The access mode is taken from the single leading token, so `ro` and `rw` are always exactly one
`true`. The output contract also refuses a resolved mount that has both or neither. That refusal is
an internal error, not a substitute for the grammar.

A well-formed token that the kernel's printer does not list is future syntax. It is not malformed.
If it is on the mount resolved for a target, that target keeps its mount state, mount point, fstype,
propagation and access mode. Its `nosuid`, `nodev` and `noexec` become `unrecognized` with
`mount_options:<target>:unrecognized`, because an absent known token may no longer mean "off". The
token's text is never stored or emitted. On any other mount it changes nothing. Atime exclusivity
and other relationships between tokens the collector does not consume are not checked.

Propagation is derived only after every optional field of the table is validated against
proc_pid_mountinfo(5) and the kernel's printer (fs/proc_namespace.c):

* `shared:N`, `master:N` and `propagate_from:N` need a positive peer-group id (1 to 2^31-1, no sign,
  no leading zero). `unbindable` takes no value.
* No tag repeats, recognized tags keep the kernel's order (shared, master, propagate_from,
  unbindable), `propagate_from` needs a different `master`, `shared` and `master` differ, and
  `unbindable` excludes both (fs/pnode.c).
* Any violation, an empty field or a malformed tag name makes the whole table `malformed`. No mount
  fact is then derived.
* A well-formed unrecognized optional field is ignored for parsing, as the format requires. It is
  not propagation evidence either: if it is on the mount resolved for a target, that target's
  propagation is `unrecognized` with `mount_propagation:<target>:unrecognized`, while its other mount
  facts stay. Its text is never stored or emitted. On any other mount it changes nothing.

Limits of this grammar. Raw non-ASCII bytes in any field make the whole table malformed. That is
narrower than the kernel, which prints them unescaped. Filesystem-specific printers of the source
and super options are not modelled. A table that passes the grammar is only well formed. It is not
proof that the kernel produced it, or that the mounts are effective isolation.

### Own cgroup: every record validated first

`/proc/self/cgroup` is accepted only after every record passes, before any count or path fact is
derived. The grammar follows Linux v6.8 `proc_cgroup_show` (kernel/cgroup/cgroup.c) and the v1 mount
option rules (kernel/cgroup/cgroup-v1.c), pinned by version tag in the task evidence:

* A record is `<hierarchy-id>:<controllers>:<path>`. The id is decimal with no sign or leading zero,
  0 to 2^31-1, and unique. The path is everything after the second colon, so it may contain colons.
* Id 0 is the unified (v2) hierarchy and has an empty controller field. A v1 id (1 or more) has a
  non-empty comma list of subsystem legacy names, then at most one `name=<[A-Za-z0-9._-]{1,63}>`
  last. Tokens are unique, a subsystem appears in one hierarchy, and a name in one hierarchy.
* The path is absolute and canonical: no empty (repeated or trailing `/`) or `.` component.
* Bounds come before any split: the path is at most 512 characters and 16 components (counted
  as `/` separators), and a controller field at most 512 characters and 16 tokens (the 15 v6.8
  subsystems plus one name, counted as commas).
* Outcomes, most severe first when records disagree: `malformed` (framing, grammar, duplicate or
  contradiction), `oversize` (a sub-bound), `unrecognized` (kernel-valid but outside the supported
  grammar: a `/..` path outside the reader's cgroup namespace, a ` (deleted)` suffix, a subsystem
  name that v6.8 does not define, or a component outside the closed component grammar), and
  `unsupported` (valid input with no v2 record, including empty input: the own-cgroup facts are
  unified-hierarchy facts). Each is unknown with `self_cgroup:<kind>`, so the run is incomplete.
* A valid v1 record is counted in `v1_entries` only when every record is valid. Mixed valid and
  malformed input is never observed, complete or exit 0.
* Subsystem order is not checked, and non-ASCII names are `malformed` at the decode step. These are
  conservative choices, not claims about what a kernel emits. Kernels other than v6.8 may define other
  subsystems; those are `unrecognized`, never guessed.

`cgroup.controllers` and `cgroup.subtree_control` values are matched on bytes against a bounded
grammar (at most 64 tokens of `[a-z_]{1,32}`) before they are decoded or split.

The schema dispatcher in `validate_output` admits an exact `dict`, its cardinality and exact-`str`
keys before it looks up or compares a discriminator. It compares a discriminator only when that value
is an exact `str`, so no user-defined equality runs before admission.

### Selected-path inventory, not executable resolution

The tool search is a selected-path inventory over the fixed directories above. It stops at the first
existing entry, whatever its type. It does not reproduce `command -v`, `PATH` search or execute
permission rules. Presence never implies that a tool is runnable or has a capability.

`file_capability` is reported only from a determinate answer, and only presence is determinate:

* `true`: a `security.capability` value was delivered.
* `ambiguous` (unknown, `binary:<tool>:ambiguous`): ENODATA. getxattr(2) documents ENODATA both for
  a missing attribute and for one the process cannot access. On the pinned Linux v6.8 path
  (fs/xattr.c `vfs_getxattr`, then the LSM `inode_getxattr` hooks, then `xattr_getsecurity`, then
  commoncap `cap_inode_getsecurity`, then `vfs_getxattr_alloc` and the filesystem's handler), the
  errno comes from whichever LSMs and filesystem serve the tool's file. The collector does not bind
  that filesystem/LSM stack. A single ENODATA cannot tell the causes apart, so it is never read as
  absence. The on-exec capability loader (`get_vfs_caps_from_disk`) is a different path and is not
  used as evidence here. There is no `false` value, and the schema refuses one.
* Unknown: `denied`, `unsupported`, `oversize` (E2BIG/ERANGE, or a value above 64 KiB), `error`, or
  `aggregate_exhausted`.

Consequently a hosted run where any found tool answers ENODATA (a tool without a file capability, or
one the process cannot read) is expected to be incomplete there, with exit 3, like the AppArmor
loaded-policy denial. That is the honest result of a required fact the collector cannot settle. It
is not masked or made optional.

`os.getxattr` takes no size cap. It is therefore called only when the remaining aggregate allowance
is at least 65536 bytes, the documented maximum it can deliver (`XATTR_SIZE_MAX` in
include/uapi/linux/limits.h; fs/xattr.c clamps to it; CPython's `os.getxattr` only tries 128 and
`XATTR_SIZE_MAX` byte buffers). Below that it is `aggregate_exhausted` and never invoked. The
admission reserves and debits nothing; the delivered length is charged before any error return and
never refunded. A delivered value larger than the remaining allowance cannot be accounted and is an
internal error (exit 1). Where `os.getxattr` does not exist, nothing native is attempted.

### Accounts and groups: local files only

`/etc/passwd` and `/etc/group` are read with bounded, strict parsers. NSS (`pwd`/`grp`), network
name services and other sources are not consulted. An NSS-compat `+`/`-` entry makes the file
`unrecognized`. The facts are therefore local files only, not global or effective account policy.

Group membership is computed from the kernel's full supplementary-group list (at most 65536)
*before* the emitted list is truncated to 64 entries. The truncation is marked with `groups_total`
and `groups_truncated`.

### sudo and AppArmor: recognized listings, not effective policy

`sudo -n -l` output is accepted only when every line is recognized: the Defaults sections, exactly
one `User … may run the following commands on …:` header, rule lines and their continuations.
Anything else is `unrecognized`. The emitted facts are only these:

* the number of listed rules
* whether a rule exactly `(ALL[:ALL]) NOPASSWD: ALL` is listed

They are not proof of effective authority. No additional sudo read or escalation is attempted.

`rule_facts` names the basis of those two fields:

| `state` | `rule_facts` | Rule fields | Completion |
|---|---|---|---|
| `listed` | `from_listing` | set | complete |
| `not_permitted` | `sudo_reported_no_permission` | null | complete: a narrower determinate negative, sudo's own explicit no-permission sentence, not an inferred empty listing |
| `tool_absent` | `not_applicable_tool_absent` | null | complete |
| `password_required` | `unavailable` | null | incomplete (`sudo_rules:unavailable`) |
| any unknown | the same unknown kind | null | incomplete (`sudo_list:…`) |

`not_permitted` is recognized only from sudo's exact sentences (`may not run sudo on`, `is not in the
sudoers file`, `is not allowed to run sudo on`), not from any text containing "not allowed to".

An AppArmor loaded-policy list is used only when every line is `name (mode)`. Profile-file regexes
are reported as lexical hints only.

## Docker and shared endpoints

The collector never executes Docker, `dockerd`, `containerd` or any helper. It never connects to a
socket and never sends a Docker API request. `dockerd` and the rootless helpers are read only to
compute a SHA-256. The four shared endpoints are examined with `stat` only. Their presence is
recorded as `shared_docker_endpoint_present`: something to exclude, not something to use.

## Bounds and accounting

* **Cooperative deadline.** The aggregate deadline is 90 seconds. It is cooperative, not a hard
  local bound.
  * Every read, stat, realpath, statvfs, hash, xattr, identity and command call is admitted only
    before the deadline.
  * Each call is postchecked after it returns. A value obtained late is kept, but its area gets
    `deadline_overrun` and nothing further is admitted.
  * Finalization is postchecked. A report finished, or written, after the deadline exits 1 and is
    not published.
  * Synchronous I/O, `Popen` and the up-to-1-second leader reap wait cannot be pre-empted. The
    3-minute step and 5-minute job timeouts are cancellation settings. They are not a proven local
    termination bound or a cleanup witness.
* **Commands.** Each command gets the lesser of 5 seconds and the remaining aggregate time. It runs
  with stdin closed, a closed environment and `close_fds`, as the leader of a new session/process
  group:
  * The environment is a fixed `PATH` and `LC_ALL=C`. git adds `GIT_CONFIG_NOSYSTEM`,
    `GIT_CONFIG_GLOBAL=/dev/null` and `GIT_OPTIONAL_LOCKS=0`. systemctl adds pager and colour off.
  * Stdout is capped at 64 KiB and stderr at 8 KiB, before parsing. Stderr is never emitted; it is
    reduced to a closed class.
* **Read accounting.** File reads share one aggregate allowance of 1 GiB. The rules are:
  * Every delivered byte is charged before the next read. That includes the oversize sentinel byte
    and the bytes of a read that later fails, grows or errors.
  * Nothing is refunded.
  * Each read requests at most the remaining allowance. Once the allowance is spent, no further
    read is issued, even to observe EOF, and the fact becomes `aggregate_exhausted`.
  * Per-file caps are 64 KiB for small files and 1 MiB for mountinfo, the AppArmor list, the ID
    maps, `/etc/passwd` and `/etc/group`. A hash is capped at 256 MiB per file, refused from `fstat`
    size before reading when it cannot fit. A non-regular file is refused.
  * The report's `accounting` block records the cap, the delivered bytes, the read calls, the
    elapsed time and any overrun.
* **Parsing bounds.** Records are LF-terminated. The record count includes a final unterminated
  line, so 8193 lines fail an 8192 limit with or without a final newline. A final LF adds no empty
  record, empty records are kept for the parser to skip, and a CR is content (each strict grammar
  then rejects it or, where it lands in an unconsumed field, ignores it). The record count and every
  line's byte length are checked on the raw bytes before decoding or splitting. Option and group-member
  counts are checked by counting separators before splitting. sudo continuations are joined once.
* **Data-producing APIs.** The aggregate allowance covers the two APIs that return variable-length
  file data: `os.read` (each request capped by the remaining allowance) and `os.getxattr` (admitted
  only with room for its documented maximum). Fixed-size kernel structures (`stat`, `lstat`,
  `fstat`, `statvfs`, `uname`, `sysconf`, IDs), `os.getgroups` (at most NGROUPS_MAX 65536 entries,
  checked), `realpath` on the fixed tool paths (component lookups bounded by PATH_MAX 4096) and
  the allowlisted environment values (at most 64 characters, checked before matching) are
  deadline-admitted but not byte-charged. Command output has its own 64 KiB/8 KiB pipe caps.
* **Output schema.** Both files are checked against a closed schema before JSON serialization, and
  before the report is copied. Values must have the exact builtin type (no subclass of dict, list,
  str, int or bool). Each dictionary is admitted as a node and checked for cardinality before any of
  its keys is enumerated, so at most the spec's own field count is visited. The schema fixes the
  allowed fields, types, enums and string grammars, the list lengths, at most 2048 nodes, and a
  conservative size estimate. The schema identifier is `heel.control-plane-boundary-preflight.v3`; R2
  added `sudo.rule_facts` and unknown propagation states, so v2 readers must not accept it. The 2048-node and 160-character string bounds keep that
  estimate under 64 KiB, so serialization cannot allocate beyond the cap. Any unexpected field is
  refused, even a short printable ASCII one. Each file is at most 64 KiB.
* **Output files.** They go into a freshly created mode-0700 directory, written with
  `O_EXCL|O_NOFOLLOW` and mode 0600: `commands.json` first, then `report.json`. The report carries
  `pair.commands_sha256`, the SHA-256 of the exact `commands.json` bytes. `commands.json` carries
  the run ID, attempt and head.

## Process cleanup: what is and is not established

The leader is kept unreaped (`waitid WNOWAIT`) until the collector sends SIGKILL to its original
process group, so the PGID cannot belong to an unrelated process when the signal is sent. That
signal goes on deadline, on a cap breach, or when a pipe is still held 0.5 seconds after the leader
exits. The leader is then reaped within 1 second, or the state is `leader_unreaped`. Each command
summary records `leader_reaped` and `group_signal` (`sent`, `no_process` or `denied`).

This bounds the leader and the members still in its group. It does **not** prove whole-descendant
containment or reaping, and it does not detect every escape. A descendant that calls `setsid` (or
otherwise leaves the group) and closes the captured pipes is not observed. The command can then
report `ok` while that descendant keeps running. Every summary therefore states
`descendants_outside_group: not_observed`. The focused tests reproduce exactly this with a tiny,
self-terminating owned child.

The collector runs only the five fixed, trusted, non-daemonizing utilities above, on a fresh,
single-use hosted VM. That is why this limitation is accepted for a finite read-only fact collector.
It is a scope judgment for independent review, not a containment proof. No guardian or privileged
containment is added.

## Privacy

Only closed enums, integers, approved version tokens and SHA-256 digests are emitted. The closed
schema refuses any other field or string. The collector does not emit the environment, process
command lines, account or group lists, customer files, hostnames, serials, raw sudo rules, profile
text, full mount options or command stderr. Other `/etc/subuid` entries are used only to compute an
overlap boolean.

Tests inject synthetic credential canaries into stdout, stderr, the environment, mount sources and
options, sudo output, os-release, profiles, account files and the ID maps. They assert that no
canary reaches either file.

## Known side effects and limits (for review)

* `sudo -n -l` is a listing and changes no policy. sudo itself may write an audit/log record of the
  listing. The output is classified in memory and discarded.
* `systemctl show --property=Version` is a read-only manager query over the system manager's
  interface. No unit is started, stopped, reloaded or enabled.
* The git commands run with optional locks and fsmonitor disabled, so `git status` does not refresh
  the index or start a daemon.
* The deadline is cooperative (see Bounds), and descendants outside the group are not observed (see
  Process cleanup).
* Symlink resolution, stat and hashing of a tool are separate operations. No adversarial mutation of
  system roots between them is defended against or claimed.
* A missing or denied capability is recorded as data. It is never treated as permission to operate,
  escalate or change it.

## Workflow

`.github/workflows/control-plane-boundary-preflight.yml` has only a `pull_request` trigger to
`main`, filtered to the four preflight paths. The job also requires a same-repository head and
`head_ref == codex/control-plane-boundary-preflight`. There is no `pull_request_target`,
`workflow_dispatch`, `schedule` or push trigger, no secret, environment, cache, setup action or
installation. Path filtering means at least one matching path changed. It does not guarantee that
only those paths changed, so the full diff must be checked separately.

The job runs on `ubuntu-24.04` with `contents: read` and a 5-minute timeout. Its steps are:

1. Check out the exact pull request head with the repository's existing full-SHA pins and
   `persist-credentials: false`.
2. Verify the executed head against the event.
3. Require that `control-plane-boundary-preflight` does not already exist (as a path or a symlink).
4. Run the collector under a 3-minute step timeout, recording its exit as the step output
   `collector_exit`.
5. Upload `report.json` and `commands.json` (3-day retention), in an artifact named with the run ID
   and attempt. This step runs only when `collector_exit` is 0, 3 or 2.

The upload condition is what keeps old output from being published. It is skipped for exit 1 (for
example an existing output directory, or late finalization) and for a cancelled or timed-out step.
Old output is never reused or published, and it is never removed or overwritten either.

A consumer must independently check that the artifact belongs to the reviewed run and attempt:

* The report's run ID, attempt and head equal the run's.
* `pair.commands_sha256` matches `commands.json`.
* Both files are at most 64 KiB and match the closed schema.

Existing CI and CodeQL jobs are unchanged. Opening the pull request also triggers the repository's
existing pull-request workflows. That is a parent publication decision.

## Next decision inputs

A future reviewed artifact from this workflow can answer installed-configuration questions only:

* Kernel, os-release point version, image version and CPU count for the intended `ubuntu-24.04`
  image (distinct from the `ubuntu-latest` 26.04 main CI image).
* Whether PID 1 is systemd, and which version.
* Whether cgroup v2 is unified with the cpu/memory/pids controllers, and the shape of the job's own
  cgroup.
* Which rootless helpers are present in the fixed directories, with their hashes.
* The userns and AppArmor restriction state, as far as unprivileged reads allow.
* Whether the sudo listing shows a NOPASSWD-ALL rule.
* That `heel-image-proof` and its ranges are absent (the exact provisioning need).
* The `/run` and work filesystem types, propagation and free space.
* Which shared Docker/containerd endpoints exist and must be excluded.

Every missing, denied, malformed or late fact is named in `incomplete_reasons`.

Partial native facts are expected rather than masked. The unprivileged AppArmor loaded-policy list is
expected to be `denied`, so a normal hosted run is expected to exit 3 with every other fact present.
An ENODATA capability answer is `ambiguous`, so a found tool without a readable capability makes the
run incomplete too. `password_required` from sudo, an `unrecognized` propagation from a newer kernel,
or an `unrecognized` own-cgroup record would also be honest partial results with exit 3. None of
these is a reason to make a fact optional. Effective delegation, access denial, daemon isolation,
cleanup, latency, descendant containment and the failure-domain consumer remain unproved. They need a
separately reviewed runtime scope, which is not granted here.
