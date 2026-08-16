# Aria ACL IPv6 Restoration Design

**Status:** approved v2 design; implementation and field evidence not started

**Scope:** restore complete IPv6 support to the existing Neutron-managed and
standalone Aria ACL product while preserving the current banked TC/eBPF
architecture, failure boundaries, Python 2.7 compatibility, and default-off
production enablement discipline.

## 1. Objective

Aria ACL must support IPv4-only, IPv6-only, and dual-stack OpenStack ports
without one address family changing the other family's verdict. The public
model follows Neutron semantics: every ACL rule belongs to exactly one address
family, selected by `ethertype=IPv4|IPv6`; a dual-stack policy contains
separate rules for the two families.

Restoration is complete only when the family is preserved through API
validation, snapshots, Rust normalization and planning, selector groups,
policy keys, conntrack cache entries, drop/counter rows, persistence,
capability negotiation, runtime upgrade, and operator-visible output.

This work does not redesign ACL itself. Source-port matching stays unsupported,
priority remains metadata rather than datapath arbitration, and overlap or
different-action ambiguity remains a controller-side validation responsibility.

## 2. Current State and Root Cause

The repository already contains substantial IPv6 datapath support:

- IPv6 packet parsing and `CtKey6` conntrack keys;
- banked `ACL_SRC_IPV6_TRIE` and `ACL_DST_IPV6_TRIE` maps;
- IPv6 ACL selector lookup through `load_acl_packet_ids_v6`;
- IPv6 fragment handling and flow statistics; and
- an `ethertype` field in Neutron snapshots and the server database.

IPv6 is nevertheless not a valid end-to-end ACL product today:

- Python validation and CLI choices are restricted to IPv4;
- Rust uses `AclIpv4Cidr` and explicitly rejects IPv6 CIDRs;
- the policy bucket key does not contain an address-family discriminator;
- selector group names and selector ordinals are not family-qualified; and
- persistence, capability, counters, and upgrade contracts do not carry the
  new family semantics.

The missing policy-key discriminator is a correctness defect, not just an API
gap. An IPv4 wildcard rule compiles with `src_id=0,dst_id=0`. An IPv6 packet
with no trie match also reaches the shared policy map with those IDs. Without
family in `PolicyKey`, an IPv4 wildcard deny can match IPv6 traffic, and the
inverse is also possible.

The family-less selector group namespace is a second isolation defect. Current
names such as `__neutron_acl:<port>:src:selector:0` can identify both an IPv4
and an IPv6 selector. `StateManager::add_group` appends a new CIDR to an
existing same-name group and retains its ID. The network writer does select
the correct IPv4 or IPv6 trie from each CIDR, so mixed membership does not by
itself force an IPv6 CIDR into the IPv4 map. It still violates the single-family
group contract and couples group lifetime, deletion, persistence, and counter
translation across families. The namespace must therefore be family-qualified.

## 3. Product Contract

### 3.1 Rule family model

- `ethertype` accepts exactly `IPv4` or `IPv6`, case-normalized at the API
  boundary.
- An omitted `ethertype` continues to mean `IPv4` for backward compatibility.
- One rule belongs to one family. The implementation never automatically
  derives an IPv6 rule from an IPv4 rule or the reverse.
- A dual-stack port uses separate IPv4 and IPv6 rules. The CLI always displays
  `ethertype` so the family is visible even when the input used the default.
- Direct remote CIDRs must match the rule family and are stored canonically.
- IPv4-mapped IPv6 addresses and IPv6 zone identifiers are rejected rather
  than normalized into a different identity.

### 3.2 Address sets

- Every non-empty address set is single-family.
- A mixed-family address set is rejected.
- Updating an address set revalidates every enabled rule that references it;
  an update that would change the set to the wrong family is rejected before
  publication.
- An empty address set may exist, but an enabled rule cannot reference it
  because its family is not provable.
- Address-set membership is canonicalized before equality, overlap, limit, and
  snapshot calculations.

### 3.3 Protocol semantics

Protocol names are resolved with the rule family:

| Input | IPv4 rule | IPv6 rule |
| --- | --- | --- |
| omitted / `any` | wildcard `0` | wildcard `0` |
| `tcp` | `6` | `6` |
| `udp` | `17` | `17` |
| `icmp` | `1` | `58` |
| `icmpv6` / `ipv6-icmp` | reject | `58` |
| numeric `1` | accept | reject |
| numeric `58` | reject | accept |

ICMPv6 type/code matching is outside this restoration. There is no hidden
allowlist for Neighbor Discovery, Router Advertisement, or MLD. An IPv6
deny-any rule can therefore block those protocols, and product documentation
must state that behavior explicitly.

### 3.4 Existing ACL boundaries retained

- Public source-port fields remain rejected.
- Destination port/range behavior is unchanged.
- Rule priority remains stored metadata and does not select a datapath winner.
- Selector overlap with conflicting actions is rejected by controller-side
  validation before a snapshot is published.
- Existing limits remain 1,000 effective rules per port and 2,048 address-set
  members unless a separate capacity design changes them.

## 4. Address-Family Type and Values

All new internal family fields use one closed vocabulary:

```text
IpFamily::Ipv4  <-> 4
IpFamily::Ipv6  <-> 6
```

`PolicyKey` and persisted matched-policy state never use `0`. A family value of
`0` is invalid for a policy bucket and is treated as stale/unsupported during
replay or conntrack validation.

`DropKey` is deliberately different. Its family field accepts:

```text
0 = unspecified, non-IP, or failure occurred before family was known
4 = IPv4
6 = IPv6
```

This distinction lets parser and non-IP drop accounting remain honest without
creating a family-zero policy rule.

## 5. ABI and Datapath Isolation

### 5.1 ABI layout

The semantic ABI changes while the relevant structure sizes remain unchanged:

```rust
#[repr(C)]
pub struct PolicyKey {
    pub tap_id: u32,
    pub src_id: u32,
    pub dst_id: u32,
    pub proto: u8,
    pub direction: u8,
    pub bank: u8,
    pub ip_family: u8, // replaces pad[0], only 4 or 6
}

#[repr(C)]
pub struct CtValue {
    // existing fields unchanged ...
    pub matched_bank: u8,
    pub matched_family: u8,
    pub _pad: [u8; 2],
    // timestamps and counters unchanged ...
}

#[repr(C)]
pub struct DropKey {
    pub tap_id: u32,
    pub reason: u8,
    pub direction: u8,
    pub proto: u8,
    pub ip_family: u8, // replaces pad; 0, 4, or 6
    pub src_id: u32,
    pub dst_id: u32,
}
```

`PipelineCtx._pad2[0]` becomes `ip_family`; the two-byte `_pad` after
`drop_reason` stays reserved.
`MatchedPolicy` and every Rust-side constructor or comparison carry the same
family. Compile-time layout assertions and `repr(C)` contract checks continue
to enforce the existing sizes and offsets.

### 5.2 Policy lookup

- The IPv4 parse path sets `PipelineCtx.ip_family=4`; the IPv6 path sets it to
  `6` before selector or policy evaluation.
- Every exact and wildcard policy candidate includes that value in
  `PolicyKey`.
- Userspace refuses to insert a policy key whose family is not `4` or `6`.
- The eBPF evaluator treats an impossible family as no valid ACL decision; it
  does not fall back to a family-zero lookup.
- Rule statistics remain keyed by the complete `PolicyKey`, so the same
  selector IDs and protocol in different families produce distinct buckets.

### 5.3 Conntrack

- A policy-created conntrack entry records the matched family and bank.
- A cached entry is current only when its family equals the parsed packet
  family and its bank satisfies the existing bank-validation rule.
- `matched_family=0`, an unknown value, or a family mismatch makes the cache
  stale and forces policy re-evaluation.
- Stable two-snapshot conntrack comparison includes `matched_family`; the
  existing LRU concurrency repair is not weakened.
- Reverse-flow/stateful semantics remain otherwise unchanged for `CtKey4` and
  `CtKey6`.

### 5.4 Drop accounting

- ACL verdict drops use family `4` or `6`.
- IPv4/IPv6 fragment and family-known parse drops use `4` or `6`.
- ARP, unknown EtherType, and failures before a trustworthy family is parsed
  use `0`.
- Consumers render family `0` as `non-ip/unknown`, never as IPv4.

### 5.5 Stack and program constraints

The change reuses structure padding and per-CPU scratch space. It must retain
the existing 448-byte linked TC stack gate, warning-denied hosted builds, and
supported 4.18-kernel verifier behavior. No new parser or large stack-local
object is introduced.

## 6. Family-Qualified Selector Groups

### 6.1 Namespace

Owned Neutron selector groups use canonical names:

```text
__neutron_acl:<port-id>:src:selector:ipv4:<ordinal>
__neutron_acl:<port-id>:src:selector:ipv6:<ordinal>
__neutron_acl:<port-id>:dst:selector:ipv4:<ordinal>
__neutron_acl:<port-id>:dst:selector:ipv6:<ordinal>
```

`any` remains the reserved selector with group ID `0`; family isolation for
that selector is provided by `PolicyKey.ip_family`.

### 6.2 Selector identity

`AclSelectorId` becomes a compound identity:

```rust
struct AclSelectorId {
    family: IpFamily,
    ordinal: Option<usize>,
}
```

`None` represents `any`; `Some(0)` is the first concrete selector. Concrete
ordinals are allocated independently inside each `(side,family)` namespace.
The same ordinal in IPv4 and IPv6 never resolves to the same group name.

Every `GroupInfo` created by the Neutron ACL compiler must contain CIDRs from
one family only. Plan validation checks the group-name family, every member
CIDR family, and every policy reference before staging maps. Deleting or
replacing one family's group cannot remove the other family's CIDRs or display
mapping.

Legacy family-less owned selector groups are not renamed in place. A full
transaction removes and rebuilds them from the authoritative snapshot using
the new namespace.

## 7. Rust Control-Plane Compiler

A focused `agent/src/neutron_acl_ip.rs` module owns family-aware IP logic and
reduces further growth in `neutron_api.rs`. It defines:

```rust
enum IpFamily { Ipv4, Ipv6 }
enum AclCidr { V4(...), V6(...) }
```

The module owns strict parsing, canonicalization, family matching, selector
interval/overlap operations, and family-aware protocol normalization. It does
not become a new general-purpose IP parser; standard library address parsing
remains authoritative.

Family is explicit in all normalized and planned objects, including:

- `CanonicalAclRule` and `NormalizedAclRule`;
- `AclEffectivePolicyKey` and validation-cache/hash inputs;
- `AclPolicyPlan`, `OwnedAclPolicySpec`, and `OwnedAclPolicyKey`;
- `AclSelectorId` and selector registries; and
- all map preimages and verification records used by apply/rollback.

Standalone ACL accepts `ethertype=IPv4`, `IPv6`, or `any`. `any` expands into
two concrete family-qualified policy keys and never inserts family `0` into a
kernel policy map.

For the existing standalone durability boundary, family becomes part of the
four-map preimage target identity:

```text
(plane, direction, family, canonical CIDR)
```

The compensation order and algorithm are unchanged; this restoration does not
expand into a redesign of `DEBT-ACL-001`.

## 8. Atomic Publication and Failure Semantics

IPv4 and IPv6 are one policy generation. Publication follows the existing
banked transaction model:

1. Validate and normalize every rule and address-set reference.
2. Build all family-qualified groups and policy buckets in memory.
3. Quiesce and scrub the inactive bank according to the existing transaction
   protocol.
4. Stage IPv4 and IPv6 selector tries plus the shared family-qualified policy
   map in the inactive bank.
5. Verify group-name family, member CIDR family, policy-key family, counts, and
   preimages for the entire generation.
6. Switch the port's active bank exactly once.
7. Scrub or revalidate conntrack using bank and family.
8. Clean obsolete owned state after the switch is proven.

The agent never reports a generation ready after publishing only one family.
Any validation or staging failure leaves the old complete bank authoritative
and reports the existing degraded/pending outcome. A new IPv6 error must not
turn a partial new generation into active policy.

This feature does not claim that every historical general ACL failure already
converges to true datapath bypass. Status fields alone are not proof that old
pinned links, maps, or pre-policy drop paths are inactive. IPv6 restoration
preserves the existing transaction and failure contract; broader fail-open
closure remains separate work.

## 9. Persistence and Replay

### 9.1 Core state and local WAL

- `RuleInfo` gains `#[serde(default)] ip_family`.
- local `AddRule` and `RemoveRule` WAL records carry family.
- Historical Neutron-managed family-zero records are migrated to IPv4 because
  the old accepted input contract was IPv4-only.
- Historical standalone records infer IPv4 or IPv6 from concrete CIDRs.
- A historical standalone wildcard/any rule expands to two concrete rules.
- Mixed or ambiguous historical input fails migration safely; it is never
  replayed as a family-zero kernel policy.
- Family normalization is checkpointed only after a complete WAL scan with no
  selected-tail failures. If malformed or unsupported WAL data blocks that
  checkpoint, startup returns the typed
  `legacy_acl_family_checkpoint_blocked_by_wal_failure` error before runtime
  replay or later state writers can reserialize family zero. No compaction is
  attempted in that blocked case, so both durable files retain their previous
  bytes; concrete-family snapshots retain the existing best-effort
  malformed-WAL behavior.
- Atomic publication of the normalized cursor-bearing `state.json` is the
  migration commit point. A failure before the checkpoint marker is appended
  and synced preserves both files byte-for-byte. A failure after that sync but
  before state publication is still fatal and leaves the old snapshot bytes and
  cursor authoritative, but the WAL legally retains one unmatched orphan
  marker. Replay ignores a marker unless its ID matches the snapshot cursor, so
  restart reconstructs the same prior effective state and can retry migration
  with a later checkpoint ID. The orphan marker must not be truncated or rolled
  back because doing so would weaken the crash-safe marker-before-publication
  order. WAL truncation, fsync, or checkpoint-header failures after publication
  are recoverable committed outcomes: startup uses the normalized state and the
  next load converges through cursor/marker replay without attempting durable
  byte rollback.

### 9.2 Neutron transaction WAL

The Neutron WAL stores committed managed-port state, snapshots, and pending
snapshot/delete intents rather than `RuleInfo`. Before any runtime
materialization:

- normalize committed snapshots;
- normalize pending snapshot and delete intents;
- treat missing historical `ethertype` as IPv4;
- rebuild family-less owned selector names from the authoritative snapshot;
  and
- verify no planned runtime policy has family `0`.

Pending intents are part of the migration boundary. Replaying only committed
state and then accepting an old pending intent would reintroduce invalid
family-zero semantics.

### 9.3 Migration order

Startup with the new runtime executes this sequence before accepting new
snapshots:

1. Read runtime and persistence schema metadata.
2. Migrate core state and local WAL.
3. Normalize/replay committed Neutron WAL state and every pending intent.
4. Plan replacement of legacy family-less selector groups.
5. Prove that all materializable policy records have family `4` or `6`.
6. Rebuild the runtime maps under the new schema.
7. Accept and apply a fresh authoritative Neutron snapshot.

Migration is crash-restartable and idempotent. A failure leaves the gate off
and reports a schema/migration reason; it must not partially attach enforcement.

## 10. Runtime ABI Upgrade and Rollback

Reusing padding preserves byte sizes but not map semantics. Existing pinned
maps cannot be adopted by the new program.

Runtime metadata advances to schema `3` and records
`acl_policy_key_schema=2`. Upgrade per host is:

1. Stop admitting ACL transactions.
2. Turn the ACL gate off and verify quiescence.
3. Detach the managed TC links.
4. Perform the state, local-WAL, Neutron-WAL, and pending-intent migrations in
   the order defined in section 9.3.
5. Verify that no old Aria ACL program remains attached.
6. Delete only the resolved dormant Aria runtime pin directory.
7. Load the new programs and create fresh maps.
8. Request a full authoritative snapshot and stage both banks.
9. Verify both banks and the family-qualified selector registry.
10. Attach links, enable the gate, and resume transactions.

If old live links remain, automatic rebuild stops with
`acl_runtime_schema_mismatch_live`; the installer must not delete pins that
may still be used by a live program.

Rollback is symmetric: gate off, detach, remove the new dormant runtime,
restore compatible software/state, rebuild from an authoritative snapshot,
verify, attach, and only then enable. Neither direction reuses maps from the
other policy-key schema.

## 11. Python API, Database, and CLI

Python uses `netaddr>=0.7.19,<1.0.0`, declared in both
`openstack/neutron_aria/requirements.txt` and package installation metadata.
This range retains Python 2.7 compatibility and avoids a handwritten IPv6
parser.

The API/plugin layer performs strict family validation and canonicalization at
write time, including reverse-reference validation for address-set updates.
Snapshots always carry an explicit normalized `ethertype`.

The Neutron CLI expands `--ethertype` choices to `IPv4` and `IPv6`. Create,
update, show, and list output always expose the effective family. Existing
commands and resource names remain unchanged.

The existing rules-table `ethertype` column is reused. Address-set family is
deterministically derived from canonical non-empty membership; this design
does not add a second writable family field or a new address-set DB column.
Address-set API/CLI output exposes a computed `ethertype` (`IPv4`, `IPv6`, or
`null` for an empty set). Reverse-reference validation always uses the same
derivation, so storage, snapshots, and display cannot disagree about family.

## 12. Capability and Enablement Contract

Two separate concepts are exposed:

- capability: `acl_ipv6_v1=true` means the installed datapath and agent
  understand the complete family-aware ABI and snapshot contract;
- enablement: `[acl] ipv6_acl_enabled=false` controls whether the host may
  accept IPv6 ACL snapshots.

Capability never implies enablement. The new configuration is packaged and
documented with default `false`. A host with the gate disabled rejects or
defers IPv6 ACL activation honestly; it does not silently omit IPv6 rules and
report the port ready.

The UDS capability hash advances. Compatibility is delivered with an
expand-contract rollout because the current Python client strictly checks the
hash:

1. Deploy compatibility Python that accepts the old and new capability hashes
   and counters schemas, while `ipv6_acl_enabled=false`.
2. Deploy the new Rust/eBPF runtime and rebuild pinned state under schema 3.
3. Verify `acl_ipv6_v1` on every intended compute host.
4. Enable IPv6 API use and the host gate only on the test environment.
5. Promote production enablement only after the field matrix passes.

Deploying the new Rust capability before a compatible Python decoder is not a
supported order.

The following contract gates change together:

- packaged INI validation requires `ipv6_acl_enabled=false`;
- documented-INI validation requires the new option and its semantics;
- status/UDS fixtures retain old-hash compatibility and add the new hash,
  `acl_ipv6_v1`, and counters-v2 cases; and
- `docs/neutron-uds-contract.json`, runbooks, and product documentation use the
  same vocabulary.

## 13. Counters Schema v2

Family isolation must be visible in counter identity, not only enforcement.
The UDS counters section advances to schema version `2`:

```text
bucket identity = (family, src_id, dst_id, proto, direction)
reason identity = (family, reason, proto, direction)
```

Bucket family is `4` or `6`. Reason family accepts `0`, `4`, or `6` under the
`DropKey` contract.

The Python decoder explicitly dispatches v1 and v2. v2 reuses the existing v1
strict timestamp, reset, size, and row-isolation checks instead of creating a
looser parser. Invalid payloads remain isolated and are reported with the
schema-specific reason `invalid_counters_v1` or `invalid_counters_v2`.

Server storage gains nullable `ip_family` on `aria_acl_port_counters`; its
logical unique identity includes that column. Historical v1 rows keep
`ip_family=NULL` and display as `unknown`. v2 bucket rows store `4` or `6`; v2
reason rows store `0`, `4`, or `6`.

The database unique index remains an approximate constraint for nullable v1
rows because supported backends may treat NULL values as distinct. Existing
single-writer atomic replace-all behavior remains authoritative for v1 row
identity. v2 always supplies a non-null family and therefore has stable
family-qualified uniqueness.

Counter reporting remains Phase B and default-off. Counters correctness is an
acceptance requirement for IPv6, but counter enablement is not a prerequisite
for ACL enforcement.

## 14. Verification Strategy

### 14.1 Required CI behavior tests

The implementation uses RED-before-GREEN behavior tests. Required negative and
positive cases include:

- IPv4 wildcard deny never drops IPv6, and IPv6 wildcard deny never drops
  IPv4;
- opposite IPv4/IPv6 actions coexist for the same protocol/direction;
- exact CIDR, subnet CIDR, wildcard, and empty-selector behavior in both
  families;
- direct CIDR and address-set family mismatch rejection;
- mixed address-set, IPv4-mapped IPv6, and zone-ID rejection;
- family-aware `icmp`, `icmpv6`, numeric `1`, and numeric `58` behavior;
- independently numbered family-qualified src/dst selector names;
- every owned `GroupInfo` is single-family and deleting one family does not
  alter the other;
- bank staging/switch/rollback publishes both families atomically;
- conntrack family mismatch, family zero, and stale bank force re-evaluation;
- first and non-first IPv4 and IPv6 fragments in both TC directions;
- stateful reply behavior for IPv4 and IPv6;
- `DropKey` family zero is accepted for pre-family/non-IP reasons while
  `PolicyKey` and matched conntrack family zero are rejected or stale;
- standalone `IPv4`, `IPv6`, and `any` behavior, with `any` expanding to two
  keys;
- four-map preimage and rollback identity includes family;
- historical core state, local WAL, committed Neutron WAL, and pending intents
  migrate before runtime materialization;
- old and new capability hashes follow the defined rollout window;
- counters v1/v2 decode, DB migration, family-qualified replacement, and CLI
  rendering; and
- packaged/documented INI and status-contract checkers enforce the new gate and
  capabilities.

Tests must use public behavior where possible and must not depend on private
helper names or source-string markers as substitutes for execution.

### 14.2 Hosted build gates

No local Cargo build, check, or test is run. GitHub Actions must provide:

- Rust and eBPF tests with warnings denied;
- ABI layout and `repr(C)` checks;
- linked TC 448-byte stack-budget verification;
- Python 2.7-compatible unit/contract tests;
- migration and CLI tests; and
- the existing repository quality gates.

### 14.3 Field acceptance

Field evidence is executed on the real OpenStack test environment and the
maintained 4.18 kernel. Until executed, every field row is
`deferred/pending`, and `ipv6_acl_enabled` remains false by default.

The field matrix covers:

- IPv4-only, IPv6-only, and dual-stack VM ports;
- ingress and egress TC directions on tap interfaces;
- allow/deny, wildcard, CIDR, address-set, TCP, UDP, ICMP, and ICMPv6;
- Neighbor Discovery behavior under explicit allow and deny-any policies;
- IPv6 first/non-first fragments and stateful replies;
- bank update, agent restart, host reboot, detach/reattach, and rollback;
- mixed-version expand-contract deployment; and
- counters v2 identity when the separate counters gate is enabled for testing.

No production-ready claim is made until the field matrix records actual
commands, expected results, observed results, timestamps, host/kernel identity,
and artifacts.

## 15. Delivery Batches

Implementation is divided into independently reviewable batches:

| Batch | Deliverable |
| --- | --- |
| B0 | Freeze product/ABI/group/capability contracts, dependencies, gates, migration order, and exact RED tests. |
| B1 | Add family to ABI, normalized persistence, local WAL, Neutron WAL/pending-intent migration, and runtime schema checks. |
| B2 | Update eBPF/core policy, conntrack, drop, replay, preimage, layout, and stack-budget behavior. |
| B3 | Implement the Rust dual-stack compiler, family-qualified group namespace, and per-family selector numbering. |
| B4 | Enable strict Python API/DB/CLI dual-stack validation with the pinned `netaddr` range. |
| B5 | Complete capability expand-contract support, contract checkers, counters v2, DB migration, and operator documentation. |
| B6 | Execute the real OpenStack/4.18 field matrix and decide whether to enable the production gate. |

Each batch ends with a focused commit and its own hosted evidence. A later
batch does not retroactively turn an earlier unverified field row into PASS.

## 16. Explicit Non-Goals

This restoration does not add:

- ICMPv6 type/code matching;
- automatic ND/RA/MLD bypass;
- automatic IPv4-to-IPv6 rule mirroring;
- mixed-family address sets;
- public source-port matching;
- priority-based datapath arbitration;
- Neutron security-group replacement;
- a second family-specific policy map;
- DDoS or broadcast-storm behavior;
- Prometheus export, historical counters, or top-N flows; or
- a broad rewrite of existing ACL recovery and compensation machinery.

## 17. Completion Criteria

IPv6 ACL restoration is complete when all of the following are true:

- the family is explicit from public rule input through every runtime key,
  cache entry, group, persistence record, counter row, and display path;
- IPv4/IPv6 wildcard and selector isolation tests pass;
- no family-zero policy can be inserted or replayed;
- legacy committed and pending state migrates idempotently before runtime
  materialization;
- runtime schema 3 upgrade and symmetric rollback refuse unsafe live-map reuse;
- the Python/Rust mixed-version rollout is contract-tested;
- all applicable hosted CI gates pass at the exact implementation head;
- the real OpenStack/4.18 field matrix passes with evidence; and
- production enablement remains default-off until that field evidence is
  reviewed and accepted.
