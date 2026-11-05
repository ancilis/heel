# Managed design status

Updated 2026-11-05. This page indexes two internal engineering documents for the managed
control-plane and host-authority work. Both have completed an independent design-level or
plan-level review. Neither is a customer guide, an install procedure or a launch announcement:
no managed service, backend, release or customer journey is claimed here.

## Documents

| Document | Accepted as | Review | Source commit |
|---|---|---|---|
| [Managed host handoff (H6-IF R3)](../superpowers/specs/managed-host-handoff.md) | DESIGN-PASS, exact design only | H6-HOST-INTERFACE-R3-REVIEW | `3b03721a47d1e816d2ed082f62fdeeaa1429e1b1` |
| [Managed authority implementation plan](../superpowers/plans/2026-11-02-managed-authority-implementation.md) | PLAN-PASS, whole exact plan only | C4-MANAGED-PLAN-H6-R3-F2-REVIEW | `722f901e28f420f14e8fbf0d7b6bc4e539575fcf` |

| Document | Accepted original SHA-256 | Published copy SHA-256 |
|---|---|---|
| Managed host handoff | `39b32f5a87ddaa343e70e812bd19499309d2d5dcec880bd4ea55846b69482456` | `efb7bef4bfd893331909b14da082d03ad56fbe6f5969aaaf9781f6b04e8121d1` |
| Managed authority plan | `4bfd2fbde04bffe831b1fc36d617142ff938bf1ac1630695c9729c860d1c5674` | `88c022405b0c1f6e3bc9d43e87398dfc5cb5d7229c53a18dc21d4177b6e078ba` |

The reviews accepted the original bytes. The published copies differ from them only by five
privacy substitutions in non-normative text:

- In two places, one in each document, a local tool-index name recorded as discovery provenance
  now reads `local repository graph`.
- In three places, a personal name in an approval or escalation note now reads "the project
  owner": two in the H6 opening history and one in a plan correction-status note.

No field, bound, protocol, owner, scope, gate or other requirement changed. Every other byte is
identical to the accepted original.

The source commits and original hashes record provenance. They are not deployed revisions, and
the source commits are not necessarily reachable on the public remote. Only these two documents
were imported; the product code on the design branches was not accepted and is not part of this
repository change. An independent publication and scope review is still required before this
change is published.

GPT-6 Astra authored the latest accepted revision of each document. Earlier revisions and their
authorship are kept in each document's history; for example, the H6 snapshot records that Claude
Opus authored its R2 round. Separate GPT-6 Astra review sessions issued both verdicts.

## Reading the snapshots

- **Historical status labels.** Each snapshot still says what its author wrote before review, for
  example "Interface-only candidate … review pending", "PROPOSED plan amendment" or "Ready for
  fresh whole-plan review". Those labels are historical. The separate exact reviews accepted the
  H6 design and the whole plan.
- **Plan scope.** The accepted plan (`722f901e`) already incorporates the accepted H6 design,
  including its Q/EA transport amendment, and its 120-entry ownership proposal (110 primary plus
  10 CP-WRITERS entries). That amended plan is accepted at plan level. Implementing any part of
  it still requires a bounded grant and accepted predecessors. The external H6-LAUNCH,
  H6-RUNTIME and H6-IMAGE packets and the per-addition inventory remain separately bounded
  grants.
- **Internal references.** The snapshots cite review-evidence directories, line pins and other
  commits by name. That evidence is kept privately and is not in this repository. Fixed paths
  such as `/etc/heel/...` and the record schemas are normative design values. They are not
  credentials or a description of any running host.

## What the acceptances do not cover

Neither review grants implementation, accepts product source or its ancestry, or qualifies a
runtime backend. Neither accepts a measured filesystem profile, provider or image work, restore
execution, a release, a deployment or a customer launch. Both reviews rest on bounded offline
evidence and finite models. They are not runtime, storage, concurrency or STOP proofs.

## Remaining gates and dependencies

- **P01 → P02.** P01 (PR 70) has passed its component source reviews and ordinary CI. Its whole
  acceptance still awaits H2, runtime and current-composition qualification. P02 stays locked
  until then. Later packets follow the plan's dependency graph, and each needs its own grant and
  acceptance.
- **H2.** The H2 and preflight reviews completed with FAIL verdicts. Their findings and the
  required corrections are unresolved.
- **H3.** H3, DNS and Worker holds remain. H6-LAUNCH and the future composition `I` depend on an
  accepted H3.
- **B0.** B0 is NO-GO. H6-IMAGE and P17 depend on an accepted, merged B0 handoff.
- **C3.** C3 is at STOP. The browser path (DA-IMPL/P16) and the two clean-room customer layers
  (P18) depend on clearing it.
- **Runtime qualification.** No runtime backend is qualified. Launch is refused without the
  capabilities the designs require, including F23's runtime-enforced artifact lease. All 25 real
  oracles, E01–E20 and F17/F20/F21/F22/F23 are pending. So are the P12–P18 storage, adapter,
  transport, browser, release-parity and clean-room proofs.
- **Authorizations.** Provider, billing, target, deployment, release and customer actions each
  need their own specific approval. These reviews do not grant any such approval. All 15 customer
  outcomes and 12 safety properties remain requirements.

CI status for the change that adds this page is reported on its pull request.
