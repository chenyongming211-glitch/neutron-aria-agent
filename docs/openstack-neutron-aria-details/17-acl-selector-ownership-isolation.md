# ACL Selector Ownership Isolation

Status: implementation and hosted CI are complete, but privileged field
evidence is pending. The transaction repair landed in commit `49081c6`; the
checker/CI verification head is `65b1dc5`. Exact-head GitHub Actions run
[`29670301941`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29670301941)
completed `fast-contracts`, `rust-behavior`, and `rust-build` successfully.
No privileged Linux managed/standalone field environment is available, so
`REVIEW-ACL-046` remains not fixed and the PR remains Draft.

Order: after Batch 2C and before `REVIEW-ACL-057` / `REVIEW-ACL-059`.

## Decision Summary

Keep the existing physical general-group and ACL LPM maps, but give their
managed publication different contracts. Compile ACL source/destination
selectors only from final ACL rule references. General maps retain every
non-conflicting persisted group for QoS, Mirror, group stats, and PASS trace,
while a local/general candidate takes precedence where an ACL-only selector
would otherwise exact-match or more-specifically shadow it. The ACL projection
and conflict-aware general projection become the managed inputs for staging,
group mutation, replay, inventory, skip eligibility, and upgrade repair.

The repair does not add an eBPF map, split the group-ID allocator, change
`PolicyKey`, change the CT ABI, or add a state/WAL schema field. Persisted
groups remain shared. Non-conflicting ACL selector observability remains in
general maps. At an unrepresentable cross-domain overlap, general-domain
enforcement/identity wins; ACL identity remains available through ACL rule
stats and drop evidence. No LPM lookup can return two group IDs.

Standalone direct ACL publication keeps its current in-place compatibility
behavior in this batch. `REVIEW-ACL-057` remains responsible for moving direct
add/update/delete/batch operations to one shadow-bank transaction. This narrow
transition avoids fixing `REVIEW-ACL-057` out of order while closing the proven
Neutron cross-domain bypass.

## Confirmed Defect

The maps are already physically separate:

- general lookup uses `SRC_IPV4_TRIE`, `DST_IPV4_TRIE`, `SRC_IPV6_TRIE`, and
  `DST_IPV6_TRIE`;
- ACL lookup uses `ACL_SRC_IPV4_TRIE`, `ACL_DST_IPV4_TRIE`,
  `ACL_SRC_IPV6_TRIE`, and `ACL_DST_IPV6_TRIE`;
- ACL selector keys and policy keys use the active ACL bank.

The missing boundary is in userspace publication:

1. A local non-`neutron:*` group remains valid on an ACL-managed tap because it
   may belong to QoS or Mirror.
2. The local group path writes that group to both general maps and the active
   ACL source/destination maps.
3. Owned ACL replace also writes those selectors into general maps. Managed
   shadow staging, fresh replay, pinned-map replay, and inventory validation
   copy every persisted group into both ACL directions and general maps.
4. An exact local CIDR can replace the selector value for the same LPM key. A
   more-specific local CIDR wins longest-prefix lookup.
5. The policy table still expects the Neutron selector group ID. Lookup with
   the unrelated local group ID misses and the current policy evaluator falls
   through to PASS.
6. The erroneous PASS may then be cached in CT. A local active-bank group write
   neither rotates the bank nor invalidates that CT entry.

The shared allocator remains globally unique. This is selector namespace/value
interference, not a numeric group-ID collision. The proven P1 is local/general
group data corrupting managed ACL lookup. General-map single-membership
limitations remain visible and are tracked separately; they do not justify
allowing ACL-only data to override a local general-domain identity.

## Alternatives Considered

### Filter by `neutron:<port>:` group name

This is a small patch, but it makes a security boundary depend on a naming
convention and on transient in-memory authority. Replay, future owners, or a
referenced standalone group can drift from that rule. Rejected.

### Compile ACL selectors from final rule references

This is the selected design. It expresses ownership in the same state that
defines ACL policy keys, preserves the existing general observability, bank,
and CT machinery, and can be reused by mutation, staging, replay, inventory,
and repair without an ABI migration.

### Add a second Neutron-only family of eBPF maps

This gives another physical namespace but requires new pinned maps, loader and
capability changes, mixed-version rollout rules, and rollback handling. The
current physical ACL maps are sufficient once their input is correct. Rejected
for this batch.

### Split or reserve group-ID ranges

Different IDs already exist. ID partitioning cannot prevent an exact LPM key
from being replaced or a more-specific key from winning. Rejected.

## Managed ACL Projection and General Candidate Index

Add pure core helpers, named here for design purposes as
`compile_acl_selector_projection(&FirewallState)` and
`compile_general_group_projection(&FirewallState)`. Exact names may change
during implementation, but the following contracts may not.

Each result contains parsed kernel CIDR keys, persisted group IDs, and stable
group identity for deterministic diagnostics.

ACL projection is derived as follows:

1. Scan the final `state.rules` once.
2. Collect every non-zero ACL `src_group_id` into the ACL source reference set
   and every non-zero ACL `dst_group_id` into the ACL destination reference
   set. Their union is the ACL-referenced set.
3. Resolve every referenced ID to exactly one persisted `GroupInfo`. Group ID
   `0` remains `any` and never creates an LPM entry. A missing, duplicate, or
   otherwise ambiguous referenced ID fails before any map mutation.
4. Parse each referenced group's CIDRs and mask host bits to canonical IPv4/IPv6
   network bytes before dedupe, overlap checks, sorting, comparison, or managed
   map insertion. The persisted input string is not rewritten in this batch.
   Thus `10.0.0.1/24` and `10.0.0.2/24` are the same managed kernel key.
5. Within one ACL direction, reject a kernel CIDR key that maps to different group
   IDs. Reject nested/overlapping CIDRs owned by different referenced IDs,
   because the current datapath cannot represent simultaneous selector
   membership or numeric-priority arbitration.
6. Nested CIDRs inside one referenced ACL group are allowed; they map to the same
   selector ID. Source and destination projections are validated separately.
7. Sort by address family, network bytes, prefix length, group ID, and stable
   group identity so `HashMap` iteration order can never choose the published
   result.

General projection preserves non-conflicting all-group observability but makes
cross-domain precedence and its single-value LPM representation explicit:

1. Every persisted non-zero group contributes candidates to both general
   directions. Build the ACL-referenced set and the explicit QoS/Mirror
   referenced set. ACL-only means `ACL references - QoS/Mirror references`;
   every other ID, including an explicitly dual-used ID, is a general-domain
   candidate.
2. Canonicalize candidates to the same masked kernel key used by managed
   insertion. More-specific keys coexist and keep existing LPM behavior.
3. Include every general-domain candidate. Exclude an ACL selector candidate
   when it is exact to, or more-specific than, an overlapping general-domain
   candidate; otherwise retain it for existing group stats/PASS trace. Thus a
   local `/24` wins over an ACL `/24` or ACL `/32`, while a local `/32` already
   wins over a broader ACL `/24` without removing the broader candidate.
4. For multiple same-priority candidates on one exact canonical key, choose the
   highest persisted group ID as a deterministic compatibility winner. This is
   not a new priority API. Duplicate persisted IDs or invalid CIDRs fail before
   mutation.
5. Keep the full candidate set and exclusion reason for migration
   classification. A legacy runtime containing any persisted candidate is
   explainable, but fixed replay and publication normalize it to the
   conflict-aware result.
6. This projection is not multi-group membership or QoS priority. An excluded
   conflicting ACL selector cannot receive general group stats/PASS identity
   for that prefix; ACL rule stats and drop evidence remain authoritative. A
   later observability expansion requires a separate design, not an ACL046
   map-layout change.

Explicit dual-use keeps the existing shared-group lifetime contract. If an
owned ACL selector is removed from the Neutron plan while QoS/Mirror still
references its ID, owned replace retains its last committed group/CIDRs as a
general-only retained-owned group. A selector CIDR update while it is dual-used
updates the shared group and therefore the QoS/Mirror identity as it does
today. When the last QoS/Mirror reference disappears and no ACL rule references
the ID, the corresponding retained-owned group is garbage-collected through
the same general projection delta. Local CIDR mutation remains blocked while
the ID is ACL-referenced.

The helper validates the persisted representation used by all publication
paths. It does not replace the existing Neutron translator's canonical
selector interning and overlap preflight. It is a final fail-closed defense
against malformed or legacy state reaching kernel maps.

The ACL helper must not use a `neutron:*` prefix or `neutron_authorities` to
decide membership. A group is an ACL selector in a direction only when the
final rule set references its ID in that direction. General candidates remain
name- and domain-agnostic.

## Publication and Local Group Writes

### Managed replace

`stage_acl_shadow_bank` receives the already compiled projection instead of
iterating `state.groups`. It writes `acl_src` entries only to `ACL_SRC_*`,
`acl_dst` entries only to `ACL_DST_*`, and then writes the final rules.

Owned ACL rule/group changes, local group CIDR changes, and QoS/Mirror
reference transitions use the before/after conflict-aware general projection
delta. The first or last QoS/Mirror reference can promote or demote a dual-used
group's general priority. For an exact alias, repair performs an upsert of the
desired winner instead of delete-then-insert, so the key has no empty window.

General mutation records require complete preimages. Add a `Replaced` form (or
an equivalent representation) containing direction, canonical key, old group
ID, and new group ID. Rollback of a successful upsert restores the old value;
it must not use the existing `Added` compensation that deletes the key. Source
success followed by destination failure, and both-direction success followed
by shadow/persistence failure, must restore both original values.

Every group-mutation rollback helper is ownership-aware. In particular,
`rollback_group_deletes` may restore only general entries in managed mode; it
must never reinsert a local group into the active ACL bank after a partial
general-map failure. Promotion, mutation, and rollback read ownership under the
same serialization boundary.

Before the first kernel mutation that can change managed ACL projection or a
general winner, transition `ManagedVerified` to `ManagedUnverified`. Restore
verified only after maps and durable state agree and, for ACL publication, the
strict CT flush succeeds. Mutation, compensation, persistence, or compensation
failure leaves health non-verified so an outer scoped/equal update cannot skip.

The existing managed publication order remains normative:

```text
quiesce ACL/CT
  -> build and validate final state
  -> compile ACL and conflict-aware general projections
  -> apply the conflict-aware general delta with complete preimages
  -> scrub and stage inactive ACL bank
  -> verify TC ACL links
  -> switch active bank
  -> persist final state
  -> strict tap-scoped CT flush
  -> publish ACL/CT gate
```

Any projection, general mutation, staging, switch, persistence, or strict-flush
failure keeps the gate quiesced. General-delta failure or any later failure
restores its complete preimages; existing rollback restores the old active bank
when persistence fails. No path may publish `ready` from a partially repaired
projection.

### Local group add/delete on a managed tap

Managed selector ownership is an explicit runtime lifecycle state, not an
attach-time boolean and not an inference from `neutron_authorities`:

```text
StandaloneCompatibility
  -> ManagedUnverified
  -> ManagedRepairRequired | ManagedVerified
```

Promotion to `ManagedUnverified` is serialized by the same lifecycle and
instance locks used by group mutation. It occurs before ACL domain reconcile
or any skip decision whenever an existing attach-only or standalone instance
becomes Neutron ACL-managed. Promotion immediately quiesces ACL/CT, invalidates
skip eligibility, and cannot publish the gate until a clean projection and
strict CT flush complete.

`attach_with_mode` must update/check ownership even when the interface is
already registered; its current idempotent early return may not discard a mode
promotion. The existing-port snapshot update path must synchronize desired
ownership before calling `can_skip_neutron_domain_reconcile`.

Demotion is not a plain boolean flip and must not drop Neutron attach
authority. Add an internal mode that means `NeutronAttachOwned` plus
`StandaloneCompatibility` ACL publication. Transition to it only after the
managed ACL gate is quiesced, owned ACL state is purged, the all-group
standalone-compatible selector view is staged into the inactive bank, the bank
is switched, and CT is strictly flushed. Logical Neutron attach/WAL ownership
remains unchanged. A pre-switch failure keeps the previous managed mode and
gate quiesced; a post-switch persistence failure uses the existing bank
rollback. Detach/unregister clears both attach and ACL ownership. This lifecycle
conversion does not change direct add/update/delete publication in
`REVIEW-ACL-057`.

While this mode is active:

- local group and QoS/Mirror mutations that can change projection candidates,
  precedence, or retained-owned lifetime are accepted only in
  `ManagedVerified`. `ManagedUnverified` and `ManagedRepairRequired` return a
  not-ready error without changing state, WAL, or maps; internal full-resync,
  repair, and demotion transactions are the only exceptions;
- a local CIDR mutation of any group ID currently referenced by an ACL rule is
  rejected, regardless of group name;
- an allowed ACL-unreferenced local group add/delete updates persisted state
  and the before/after general projection delta;
- QoS/Mirror add/delete applies the same general delta when the first or last
  reference changes dual-use priority or triggers retained-owned group GC;
- it never inserts into or deletes from the active ACL bank, and a later
  managed resync still excludes it from the ACL projection;
- the existing `neutron:*` ownership guard remains unchanged;
- non-Neutron local groups remain available to QoS and Mirror when they do not
  alias an ACL-referenced group ID;
- local ACL policy mutation remains blocked by existing ACL authority rules.

This removes both exact active-bank overwrite and more-specific active-bank
interference without banning valid cross-domain groups.

Standalone runtime mode keeps the existing direct group/policy coupling in
this batch, including the current replayed representation of an unreferenced
standalone group. A referenced non-Neutron standalone group therefore remains
enforceable. The later direct-publication transaction must adopt a
rule-derived projection when `REVIEW-ACL-057` is implemented.

## Semantic No-op and Legacy Repair

Changing staging alone is insufficient. An upgraded node may already have an
unreferenced local CIDR in its active ACL bank, while the next Neutron snapshot
is semantically identical to persisted desired state. The current early no-op
would leave that contamination live.

Add a pure projection-drift planner with the closed result vocabulary
`Clean`, `RepairRequired`, and `Fatal`. Its inputs are captured runtime entries,
the committed-state ACL/general projections and legacy candidate sets, and the
proposed final-state ACL/general projections. This makes migration decisions
unit-testable without privileged maps and keeps upgrade repair valid when the
first full snapshot also changes ACL semantics.

Classification first asks whether captured runtime is clean or explainably
legacy relative to committed state. A selector that the proposed snapshot
legitimately deletes or changes is not judged against the proposed projection.
After classification, build general mutations from captured runtime directly
to the proposed conflict-aware general result, and stage the proposed ACL
projection into the inactive bank. Thus repair and a real selector
add/delete/CIDR change complete in one transaction.

Before the semantic no-op return, managed replace must run that planner:

- `Clean`: preserve the existing no-op;
- `RepairRequired`: repair explainable ACL selector drift and general-map alias
  drift relative to committed state, then force one clean proposed shadow-bank
  stage and switch even when group and policy deltas are empty;
- inability to read or validate the active projection: return an error while
  the Neutron gate remains quiesced;
- `Fatal`: reject unknown keys/values or non-projection drift; any broader
  validator remains fail-closed and cannot be overridden by repair.

Repairable legacy/runtime states include:

- an unreferenced local exact key replacing the referenced ACL selector value;
- an unreferenced local more-specific ACL entry;
- a referenced selector key missing after legacy exact-local deletion;
- a general key containing either persisted candidate of an ACL-only versus
  local exact alias, or missing because the legacy delete removed that alias;
- a legacy general-map ACL-only more-specific entry that the conflict-aware
  projection now excludes in favor of a broader general-domain candidate;
- a clean selector key with a stale, persisted all-group candidate value.

An actual non-zero group value that does not resolve to the persisted candidate
set for that kernel key is fatal. An unknown extra key, invalid desired CIDR,
duplicate persisted group ID, unreadable map, policy/general entry unrelated to
the explainable alias set, link drift, or tap-config drift is also fatal.

The internal reconcile report may expose a `selector_repair_performed` boolean
for logs and tests. It is not a new northbound or UDS contract field.

The first equal snapshot after upgrade repairs a polluted bank and is followed
by the caller's existing strict CT flush. The next equal snapshot may no-op.
Removing the early return unconditionally is not allowed: that would cause
needless bank flips and partially absorb the separate metadata-only issue in
`REVIEW-ACL-044`.

The repair state also gates the outer snapshot optimization. The runtime keeps
an in-memory managed projection health value. Promotion and restart begin
unverified; repairable inventory drift sets `ManagedRepairRequired`; only an
exact inventory match or successful clean publication followed by successful
strict CT flush sets `ManagedVerified`. `can_skip_neutron_domain_reconcile`
must receive this evidence and return false for every ACL-managed port unless
it is verified. A scoped/equal ready update therefore cannot skip over an
upgrade repair. Full snapshot apply tests must exercise this outer entry, not
only call `replace_owned_acl` directly.

This health value is not a live anti-tamper monitor. An out-of-process map
write after `ManagedVerified` does not update it and may remain behind the
existing equal-domain skip until restart/re-attach or another non-skipped ACL
reconcile. ACL046 guarantees upgrade/restart migration and all in-process
managed writers; continuous external map-integrity attestation is a separate
operational feature.

## Replay, Inventory, and Attach Migration

Managed fresh-object and pinned-map replay must build ACL entries from the
direction-specific rule projection and general entries from the conflict-aware
general projection. Rules and port bitmaps keep their existing replay
semantics.

Inventory validation must separate these expected sets:

- managed general expected entries: the conflict-aware general projection in
  both directions;
- managed ACL expected entries: the direction-specific compiled projection;
- standalone general and ACL expected entries during the compatibility window:
  the current all-group representation.

Preexisting live managed runtime needs a repairable migration classification.
Attach validation reuses the same committed-state drift planner and complete
legacy candidate set described above; it must not maintain a narrower second
classifier.
If TC links, tap identity/config, policy table, and all unrelated inventory are
valid, but ACL maps differ or general maps contain an explainable exact,
more-specific, or missing persisted legacy candidate, attach must:

1. classify only that difference as `managed ACL selector repair required`;
2. quiesce ACL and CT;
3. complete registration in `AwaitNeutronResync` rather than aborting attach;
4. require the next full Neutron resync to perform the clean bank publication
   and strict CT flush before readiness.

Missing referenced selectors caused by legacy exact deletion and known
ACL-only general entries excluded by the conflict-aware projection are
repairable. Only keys or values outside the complete persisted candidate set,
unexplained general-map drift, unreadable maps, policy-table drift, or
link/config mismatch remain fatal and fail closed. A repairable classification
must never preserve a live ACL/CT gate.

Fresh managed startup is already quiesced pending full resync. It may replay a
clean ACL projection plus the conflict-aware general view for inventory
consistency, but replay alone does not establish Neutron readiness.

The rollout changes no persisted schema, so no state-file migration is needed.
Transactional rollback inside one binary remains safe through the old-bank
restore. Deployment is roll-forward-only for managed ACL service. An older
binary republishes all groups and must not resume managed ACL. Emergency
downgrade requires draining or detaching the port, proving ACL/CT gates are
closed, and keeping the old version out of managed ACL service until the fixed
version returns and completes full resync.

## CT Safety

No CT ABI or selector generation field is added.

- A managed repair switches the ACL bank. Existing CT entries whose
  `matched_bank` differs from the active bank are stale and cannot authorize a
  packet.
- Neutron reconcile then executes the existing strict tap-scoped IPv4/IPv6 CT
  flush before re-enabling the gate.
- If strict flush fails, readiness is not published.
- Local cross-domain group operations no longer mutate an active managed ACL
  bank, so they cannot create an untracked selector change that would require
  a CT epoch.

## RED-to-GREEN Test Contract

Implementation starts with failing tests and keeps local verification free of
Cargo commands. Rust and eBPF compilation run only in GitHub Actions.

### Pure projection and compatibility tests

1. A referenced selector `/24` plus unreferenced local exact `/24` and
   more-specific `/32` yields only the referenced selector in the ACL
   projection. Persisted state and the general candidate index retain all
   three; the general exact `/24` winner is the local/general-domain ID and the
   `/32` coexists.
2. A referenced non-`neutron:*` ACL group is retained in ACL projection. A
   local CIDR mutation of that referenced ID is rejected, proving both
   projection and write authority are reference-driven rather than name-driven.
3. A non-conflicting ACL-only selector remains in both general directions for group
   stats/PASS trace, while a source-only ACL group is absent from destination
   ACL projection and vice versa.
4. A local `/24` removes an exact or more-specific ACL-only general candidate;
   a local `/32` coexists with a broader ACL `/24`. In all cases ACL projection
   remains unchanged.
5. Group ID `0` emits no entry; missing non-zero referenced IDs, duplicate
   persisted IDs, and invalid CIDRs fail closed.
6. Same-group nested CIDRs are accepted; exact/nested overlap across different
   ACL-referenced IDs is rejected with stable diagnostics.
7. Host-bit variants such as `10.0.0.1/24` and `10.0.0.2/24` canonicalize to
   one key and conflict when owned by different referenced IDs; include IPv6
   host-bit variants.
8. Two same-priority general candidates on one canonical exact key select the
   highest group ID regardless of `HashMap` insertion order; deleting the
   winner restores the next candidate.
9. An ACL+QoS/Mirror dual-used ID always has general-domain priority, including
   when exact to or more-specific than another local group. Its deterministic
   general/general alias outcome follows rule 8; ACL projection is unchanged.
10. Equivalent states constructed with different `HashMap` insertion orders
   produce identical sorted projection.
11. IPv4 and IPv6 exact/nested cases receive equivalent projection and drift
   classification coverage.
12. Standalone replay tests include both a referenced and an unreferenced local
   group, cover system and tap modes, and prove the current all-group
   representation remains unchanged. Merely proving the referenced group
   enforces is insufficient.

### Drift planner tests

1. Exact selector value replaced by a persisted local ID returns
   `RepairRequired`.
2. More-specific persisted local ACL entry returns `RepairRequired`.
3. Referenced selector key missing after legacy exact-local deletion returns
   `RepairRequired`.
4. Explainable exact general-map alias value or deletion returns
   `RepairRequired` and produces a desired local upsert/delete delta.
5. For IPv4 and IPv6, legacy general `local=/24 + ACL-only=/32` classifies as
   `RepairRequired`: the plan deletes only the general `/32` while retaining
   it in ACL projection.
6. Unknown key, unknown value, unrelated general-map drift, invalid desired
   projection, or unreadable inventory returns `Fatal`.
7. Exact desired runtime returns `Clean`.
8. A repair-required committed runtime plus a proposed full snapshot that adds,
   deletes, or changes a selector classifies against committed state and emits
   one repair-to-proposed plan; the next equal snapshot is clean.

### Control-plane and migration tests

1. ACL ownership promotion on an already attached instance is serialized
   before group mutation, quiesces the gate, sets unverified health, and forces
   domain reconcile. Idempotent attach cannot swallow the transition.
2. Demotion cannot flip attach authority. Only successful
   quiesce/purge/standalone-compatible shadow publication/strict flush enters
   internal Neutron-attach-owned standalone ACL mode. Failure remains in the
   prior logical mode with the gate quiesced.
3. Managed ACL-unreferenced local group add/delete changes persisted state and
   general projection but performs no ACL network mutation. A later resync
   still excludes it. Mutation of an ACL-referenced group ID is rejected.
4. In `ManagedUnverified` or `ManagedRepairRequired`, attempted local group
   delete/add and QoS/Mirror reference transition return not-ready with
   byte-identical state/WAL/maps. The following full resync remains repairable.
5. Dual-use lifetime covers QoS/Mirror reference counts `0→1→2→1→0`: removing
   the ACL selector retains the group while a general-domain reference exists;
   only the final reference removal garbage-collects it. ACL CIDR update while
   dual-used updates the shared general identity under the same transaction.
6. Inject source general replacement success plus destination failure, then a
   both-direction replacement followed by shadow/persistence failure. The
   `Replaced` preimage restores original source/destination values and active
   ACL maps remain byte-for-byte unchanged.
7. Start from `ManagedVerified` and inject local-group, owned-replace,
   persistence, compensation, and compensation-rollback failures. Health is
   invalidated before mutation, never remains verified after failure, and the
   next scoped equal update cannot outer-skip.
8. A clean equal Neutron reconcile with verified health remains a no-op.
9. An outer full/scoped snapshot entry with repair-required health cannot take
   the domain-hash skip. Its equal reconcile repairs exactly once; the next
   equal reconcile with verified health may skip/no-op.
10. Active-projection read failure, projection validation failure, shadow-write
   failure, bank-switch failure, persistence failure, and strict-flush failure
   never mark projection verified or publish the new gate; old bank/general
   values are retained or restored as applicable.
11. Preexisting managed explainable ACL/general drift is quiesced and admitted
   in `AwaitNeutronResync`; broader inventory drift aborts attach.
12. Complete restart cycle: legacy pins enter quiesced repair-required state,
   full resync repairs and verifies, then a second clean restart passes
   inventory without another repair. Cover both an ACL-bank alias and a
   general-only legacy `local=/24 + ACL-only=/32` entry that the new projection
   excludes.
13. After a repair bank switch, old-bank CT is stale; only a successful strict
   flush permits `ManagedVerified` and gate publication.

### Static and field gates

- Extend the Stage 1 static checker to require the ACL projection/general
  candidate helpers or mode-aware wrappers at managed shadow staging, fresh
  replay, pinned replay, inventory, managed group add/delete, QoS/Mirror
  reference add/delete, projection-health transitions, and `Replaced`
  compensation. Mutation tests must catch both direct and aliased raw-group
  iteration.
- Exact local API field fixture: while the active bank remains unchanged, add
  an allowed non-Neutron local group with the selector's exact CIDR. Assert
  persisted/general state changes, the ACL key still contains the selector ID,
  deny/drop evidence grows, controlled-flow CT stays empty, and cleanup passes.
  Cleanup also proves the removed local winner reveals the retained
  non-conflicting ACL selector's general observability again.
- More-specific shadow-staging field fixture: in an independent fixture, add a
  local `/32`, then apply a real owned-ACL semantic delta that does not change
  the target deny. Assert the inactive bank is staged and switched, `/32` is
  absent from the new ACL projection, deny remains effective, CT is empty, and
  cleanup passes.
- Legacy equal-no-op field fixture: use `bpftool` to write a persisted local
  group ID into the active ACL map (or use a proven old binary), send
  controlled traffic to establish the bad PASS/CT evidence, then restart or
  re-attach with the fixed binary so projection health becomes unverified or
  repair-required. Submit a full snapshot with equal ACL semantics. Assert one
  bank switch, strict CT cleanup, restored deny, and no second switch on the
  next equal snapshot. Restart the repaired binary once more and prove pinned
  inventory is clean without another repair. Direct bpftool pollution after
  `ManagedVerified` without a lifecycle transition is explicitly not this
  fixture.
- RED smoke helpers must capture return code, maps, counters, bank, and CT
  before asserting unexpected PASS, so a failure preserves diagnostic evidence.
- Exact, more-specific, and legacy-repair fixtures must not share damaged map
  state. Each starts from a reverified deny baseline.
- Extend `check_tc_acl_smoke.py --self-test` to statically require all three
  independent fixtures and their bank/map/drop/CT/cleanup evidence.
- Extend the standalone TC smoke to prove a referenced non-Neutron group still
  enforces and an unreferenced group retains current representation after
  restart/replay in system and tap modes.
- GitHub Actions must pass the maintained Stage 1 and Stage 2 checkers, target
  Rust tests, userspace/agent builds, eBPF build, static binary checks, and the
  warning-deny gate at the exact implementation head.
- Privileged OpenStack evidence must show an ingress deny still denies after
  the exact local API mutation and after the more-specific shadow publication,
  then show a separately injected legacy polluted bank is repaired once. Drop
  counters must grow and no erroneous allow CT entry may survive.

## Scope Guardrails

This batch does not:

- add maps, change map layout, `PolicyKey`, `TapConfig`, CT, WAL, or the public
  northbound/UDS product API; workspace-internal Rust projection interfaces are
  allowed;
- split or remap group IDs;
- ban all local groups from an ACL-managed tap;
- implement multi-selector membership, ordered rule scan, numeric priority, or
  source-port matching;
- convert direct ACL add/update/delete/batch into a shadow transaction
  (`REVIEW-ACL-057`);
- change bitmap quarantine (`REVIEW-ACL-059`);
- change fragment semantics (`REVIEW-ACL-056`);
- broaden CIDR/address-set northbound validation (`REVIEW-ACL-058`);
- remove the clean semantic no-op or fix metadata-only bank flips
  (`REVIEW-ACL-044`).

Any implementation need that crosses one of these boundaries is a design
change and must pause before production code is expanded.

## Completion Conditions

`REVIEW-ACL-046` may move to fixed only when all of the following are true:

1. managed general and ACL producers consume one reference-derived projection;
   non-conflicting ACL selectors retain observability while conflicting
   ACL-only candidates cannot shadow general-domain identity;
2. permitted ACL-unreferenced local group mutations cannot alter managed ACL
   maps, while ACL-referenced group mutations are blocked by ID rather than
   name;
3. ownership promotion, demotion, restart, and outer skip cannot bypass the
   unverified/repair-required gate;
4. legacy polluted active banks and explainable general aliases are repaired
   through a fail-closed bank switch and strict CT flush, including the
   semantic no-op case;
5. replay and inventory agree with staged runtime after a complete repair and
   second restart;
6. standalone compatibility tests stay green without implementing
   `REVIEW-ACL-057`;
7. exact active-write isolation, more-specific shadow staging, and injected
   legacy equal-reconcile repair are independently proven by hosted tests and
   privileged field evidence;
8. the exact implementation head passes GitHub Actions with no project
   Rust/eBPF warnings.

Checkpoint 2026-07-19: hosted implementation evidence is complete at
transaction commit `49081c6` and checker/CI head `65b1dc5`; exact-head Actions
run
[`29670301941`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29670301941)
passed `fast-contracts`, `rust-behavior`, and `rust-build`. Completion condition
7 still lacks privileged managed and standalone field evidence. No field run,
environment, command transcript, timestamp, or artifact is claimed by this
checkpoint; the finding remains not fixed and the PR remains Draft.
