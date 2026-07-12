# ACL Batch 6 TC-Unified ACL/CT Datapath Design

Date: 2026-07-12

Status: implemented; GitHub Build green; real managed-tap evidence pending

## Goal

Close the ACL conntrack-path gap by making TC ingress and TC egress the two
authoritative ACL/CT enforcement hooks for Neutron-managed taps.

XDP remains attached, but Neutron TC-ACL mode does not run ACL or conntrack in
XDP. XDP is reserved as an independent early-drop layer for future DDoS and
coarse abuse protection. Batch 6 establishes that boundary but does not add a
DDoS rules API, maps, agent domain, or mitigation policy.

## Why The Previous Design Was Replaced

The previous Batch 6 design proposed bank-aware conntrack lookup in XDP, TC
ingress, and TC egress. That would be safe against stale ACL banks, but it
would still leave three architectural problems:

1. A packet accepted at XDP and then observed at TC ingress would execute a
   mutating CT lookup twice. The current lookup also updates `last_seen`, CT
   state, packet count, and byte count, so ingress accounting would be
   duplicated.
2. XDP cannot run TC-only QoS, Mirror, skb Trace, or TCP-RT post-processing.
   Creating CT in XDP therefore cannot mean that the complete hook pipeline
   accepted the packet.
3. Ingress and egress ACL would continue to have different accounting,
   tracing, attach-readiness, and failure semantics. The existing dead TC CT
   helpers are evidence that these paths have already drifted once.

For Neutron tap ACL, semantic consistency and a single bidirectional pipeline
are more valuable than retaining XDP as the ingress ACL authority. Established
traffic still receives a TC CT fast path, so repeated packets avoid ACL LPM and
policy-table lookup.

## Confirmed Product Boundaries

1. Neutron ACL is authoritative in TC ingress and TC egress.
2. XDP remains installed but is ACL/CT-neutral for Neutron TC-ACL taps.
3. Future XDP DDoS processing is an independent earlier layer. It must not use
   ACL banks, ACL rule statistics, or ACL conntrack entries as its rule model.
4. The public ACL remains service-oriented and priority-independent. Source
   port, ordered priority resolution, and new QoS/Mirror product functionality
   remain outside Batch 6.
5. `NeutronAclSnapshot.stateful=false` continues to publish
   `conntrack_enabled=false` while leaving ACL enabled.
6. Existing `CtKey4`, `CtKey6`, `CtValue`, `PolicyKey`, `PolicyValue`, and
   pinned-map sizes and offsets remain unchanged.
7. `TapConfig` remains exactly 8 bytes. Its final padding byte becomes an
   ingress-hook selector without moving any existing field.
8. Legacy standalone taps default to XDP ingress ACL. Neutron-managed taps
   explicitly publish TC ingress ACL.
9. QoS/Mirror managed domains remain rejected. Their existing standalone TC
   datapath behavior is preserved, not expanded.
10. GitHub Actions remains the Rust/eBPF build authority; no local Cargo build,
    check, or test is allowed.

## Considered Approaches

### A. TC-Unified Neutron ACL — Selected

Neutron-managed taps run ACL/CT once in TC ingress and once in TC egress. XDP
passes Neutron traffic without ACL or CT work. Both TC directions share the
same decision contract and differ only in direction-specific post-processing.

This gives one enforcement point, one CT accounting point, and one statistics
contract per direction.

### B. XDP Ingress Plus TC Egress

This preserves the earliest ingress drop and can be valid with a strict
handoff contract. It was rejected for Neutron mode because it keeps two ACL
implementations and cannot create ingress CT after TC-only drop stages.

### C. CT Lookup In XDP And Both TC Hooks

This gives superficially symmetric hit/miss metrics but repeats CT side
effects on ingress packets and makes packet/byte counters hook observations
rather than connection traffic. It was rejected.

## Runtime Mode And ABI Compatibility

The last byte of `TapConfig` is currently padding. It becomes:

```text
acl_ingress_hook = 0  -> legacy XDP ingress ACL
acl_ingress_hook = 1  -> TC ingress ACL
```

Constants are mirrored in `ebpf/src/common.rs` and `core/src/common.rs`:

```rust
pub const ACL_INGRESS_HOOK_XDP: u8 = 0;
pub const ACL_INGRESS_HOOK_TC: u8 = 1;
```

Unknown values normalize to `ACL_INGRESS_HOOK_XDP`. That makes existing pinned
entries, whose padding byte is zero, retain legacy behavior after upgrade.

`TapConfig` stays 8 bytes and every existing field keeps its offset. CI tests
must assert size, normalization, fresh-runtime XDP default, active-bank
updates, and runtime partial-update preservation.

Neutron runtime publication always requests `ACL_INGRESS_HOOK_TC`, including
empty/bypass snapshots. ACL-disabled taps do no ACL work, but retaining the
mode makes later non-empty publication deterministic.

The hook selector is derived runtime state, not a new public config, WAL, or
snapshot field. Fresh generic replay initializes XDP compatibility mode. The
existing restart invalidation keeps ACL disabled until Neutron full-resync
atomically republishes TC mode, so an old persisted state cannot reactivate
Neutron ACL in XDP.

## Datapath Architecture

### 1. XDP Role

The XDP entry point resolves `tap_id` and reads `acl_ingress_hook` before any CT
lookup.

For `ACL_INGRESS_HOOK_TC`:

```text
future independent DDoS stage (not implemented in Batch 6)
  -> no DDoS verdict in this batch
  -> XDP_PASS
```

The path must not call:

- `phase_ct_v4` / `phase_ct_v6`;
- `ct_lookup_v4` / `ct_lookup_v6`;
- ACL selector LPM lookup;
- `phase_policy_xdp`;
- `ct_create_v4` / `ct_create_v6`.

For `ACL_INGRESS_HOOK_XDP`, existing standalone XDP ACL/CT behavior is retained
and receives the same bank-safety fix as TC. This compatibility path is not the
Neutron authority path.

XDP DDoS is deliberately a separate future stage because its model is expected
to be coarse and attack-oriented: source/rate reputation, prefix blocks,
protocol anomalies, SYN/UDP flood controls, and early-drop metrics. It must not
silently become a second Neutron ACL implementation.

### 2. TC Ingress And Egress Decision Contract

Each live TC family/direction wrapper constructs one CT key and invokes the
same logical decision sequence:

```text
resolve tap and runtime flags
  -> build CtKey4 / CtKey6
  -> bank-aware CT lookup when conntrack is enabled
     |
     +-- current-bank hit
     |     -> restore cached matched policy and policy-hit bit
     |     -> skip ACL selectors and policy evaluation
     |     -> run direction-specific QoS
     |     -> QoS drop: record QoS/drop stats and return
     |     -> run passed-flow stats, group stats, Mirror, Trace, TCP-RT
     |     -> return pass
     |
     +-- disabled / not-found / expired / stale-bank
           -> load selectors from current active ACL bank
           -> evaluate ACL when enabled
           -> ACL drop: account and return; no CT create
           -> run direction-specific QoS
           -> QoS drop: account and return; no CT create
           -> run passed-flow stats, group stats, Mirror, Trace, TCP-RT
           -> create CT only when conntrack is enabled
           -> return pass
```

The Rust source may retain family-specific and direction-specific leaf
functions to satisfy verifier stack/call constraints. The decision contract,
ordering, naming, and static tests must remain unified.

TC ingress uses this contract only when `acl_ingress_hook` is TC. In legacy
XDP mode, TC ingress runs only its non-ACL post-processing and performs no CT
lookup, preventing duplicate ingress CT accounting.

TC egress is always the egress ACL/CT hook because XDP has no egress hook.

### 3. Conntrack Decision Semantics

CT lookup returns explicit internal outcomes instead of forcing callers to
reconstruct the reason:

```text
Hit {
  matched_policy,
  policy_hit,
  state,
  is_forward
}

Miss(Disabled | NotFound | Expired | StaleBank)
```

The exact Rust enum representation may be BPF-friendly variants rather than a
heap-allocated object, but callers must receive all four miss reasons.

Bank validation occurs before `last_seen`, state, flags, packet count, or byte
count changes. A stale forward or reverse entry is removed using the exact key,
then the packet evaluates the current bank.

`FLAG_CT_HIT`, not a fabricated `ct_state=2`, controls the fast-path branch.
The actual `CT_NEW` or `CT_ESTABLISHED` state is preserved for Trace.

CT entry packet and byte counters mean packets observed by the authoritative
CT hooks. They include a current-entry hit even if a later QoS stage drops that
packet. QoS statistics separately describe the drop. A miss rejected by ACL or
QoS creates no CT entry.

### 4. Cached Policy-Hit Semantics

`evaluate_policy` distinguishes an actual policy match from default pass. CT
must preserve this distinction so hit-path rule accounting does not create a
phantom all-wildcard rule.

No map layout change is required. The existing `CtValue.flags` byte uses:

```text
bit 0 -> seen reply
bit 1 -> original accepted packet matched a real ACL policy
```

The internal `MatchedPolicy`/pipeline result carries `policy_hit`. On a CT hit,
rule statistics update only when both ACL monitoring is enabled and
`policy_hit=true`.

### 5. Statistics And Observability

Metric meanings are separated:

- CT entry `pkt_count/byte_count`: packets observed by authoritative CT hooks;
- ACL rule stats: actual matched-rule ACL decisions, including ACL drops;
- flow/group stats: packets that pass ACL and QoS at the TC hook;
- QoS stats: QoS pass/drop/shape outcome;
- Mirror stats: clone outcome;
- CT contract stats: diagnostic proof of hit/miss/disabled/stale behavior.

Routine `ct_hit`, `ct_miss`, and `ct_disabled` contract events are recorded only
when the packet matches an enabled Trace filter. `stale_bank` remains
unconditionally recorded because it is a rare security-relevant event.

The real-tap smoke enables a narrow Trace filter for its controlled flow before
reading CT contract deltas. Production traffic therefore does not pay an extra
per-packet `CT_CONTRACT_STATS` hash lookup by default.

### 6. TC Link Readiness

The shared runtime may continue describing TC programs as optional for generic
standalone use. Neutron ACL publication adds a stricter conditional boundary:

- non-empty Neutron ACL requires live/pinned TC ingress and TC egress links;
- missing either link fails before ACL/CT publication;
- the port must not report `enforce` or `ready` with only one TC direction;
- compensation leaves `conntrack=false, acl=false` if a post-quiesce failure
  occurs.

The existing XDP required-program contract remains during Batch 6 so XDP stays
available for the future DDoS role and legacy standalone mode.

### 7. Atomic Neutron Transition

The existing quiesce/stage/flush/publish flow is extended with ingress-hook
mode:

```text
validate TC ingress + TC egress live links
  -> publish quiesce: conntrack=false, acl=false, hook=TC
  -> stage next ACL bank
  -> switch active bank while ACL remains disabled
  -> strict scrub CT V4/V6
  -> atomic publish: desired conntrack, desired ACL, hook=TC
  -> persist WAL/status
```

Empty/bypass snapshots publish ACL disabled and retain hook=TC. Stateful false
publishes `conntrack=false, acl=true, hook=TC`.

No packet may observe ACL enabled with XDP still acting as the Neutron ingress
authority.

## Failure Semantics

| Condition | Handling |
| --- | --- |
| TC ingress or TC egress link missing | Fail before enforcement publication; never report enforced/ready. |
| CT disabled | Evaluate ACL on every packet; never create CT. |
| CT not found or expired | Evaluate current-bank ACL; create only after ACL and QoS pass. |
| CT bank stale | Delete exact entry before mutation, record stale event, evaluate current bank. |
| ACL drop | Account matched rule/drop and return; do not run later allow-only stages or create CT. |
| QoS drop | Account QoS/drop and return; do not create CT on a miss. Existing hit remains valid ACL state. |
| CT insert failure | Current fully validated packet may pass; next packet misses and revalidates. |
| Metrics update failure | Never changes packet verdict. |
| Failure after quiesce | Keep ACL and CT disabled; report degraded/bypass according to existing reconcile semantics. |

## Testing Strategy

### 1. Host-Side Pure Contracts

Rust tests cover:

- `TapConfig` remains 8 bytes and legacy zero selects XDP;
- TC hook mode survives active-bank and partial runtime updates;
- Neutron transitions always publish TC mode;
- non-empty ACL cannot publish without both TC links;
- current/stale bank and policy-hit decisions;
- runtime inventory/replay preserves hook mode.

### 2. Source-Structure Contracts

A brace-aware Python checker verifies function bodies rather than file-wide
markers:

- XDP TC mode returns before CT/ACL calls;
- TC ingress TC mode and TC egress perform family-correct CT lookup;
- hit helpers contain no ACL selector or policy evaluation;
- miss helpers order ACL drop, QoS drop, passed-flow hooks, then CT create;
- legacy TC ingress contains no CT lookup;
- routine CT contract writes are Trace-gated;
- stale-bank validation precedes every entry mutation.

### 3. GitHub Build Gates

GitHub Actions runs the exact Rust contracts, existing `neutron_acl_` tests,
Python stages, nightly BPF release build, eBPF artifact verification, and static
userspace/agent builds. Local Cargo remains prohibited.

### 4. Real Managed-Tap Smoke

The smoke must prove both TC directions with IPv4 and IPv6 when available:

- XDP does not change ACL/CT counters in TC mode;
- stateful first packet misses and later packets hit in TC ingress and egress;
- stateless traffic has no CT hit/create;
- deny traffic creates no CT;
- QoS-drop ordering is covered only in a standalone fixture because Neutron
  managed QoS is rejected;
- bank transition captures the pre-existing controlled-flow CT entry before
  Neutron resync, proves the strict publication flush leaves zero matching CT,
  then requires a first `ct_miss`, exact counter recreation, and later hits;
- CT packet/byte deltas are not doubled on ingress;
- both required TC link pins are present before enforcement; missing-link
  rejection is proved by the exact host-side readiness tests without
  destructively removing a live link during smoke.

`stale_bank` behavior remains covered by the exact host-side CT contract tests.
The real Neutron bank smoke cannot require a stale lookup because Neutron ACL
publication deliberately performs a strict CT flush before publishing the new
bank. Exercising a real stale entry therefore requires a separate standalone or
non-Neutron fixture that does not run the Neutron strict-flush transaction.

Code/CI evidence moves the item to `likely-fixed`. Only successful real-tap
evidence moves it to `fixed`.

Current evidence state: `REVIEW-ACL-055` is `likely-fixed`. GREEN Build
[29204424678](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29204424678)
passed the exact Rust metric-label test, nightly eBPF build, static
userspace/agent builds, binary verification, Python stages, and the fail-closed
smoke structure/mutation checks, including strict-flush→miss→hit bank evidence.
`real-tap smoke pending` remains explicit because this development environment
does not provide the guarded Kolla credentials, Neutron UDS, managed tap, VM,
or pinned live TC links required to run the smoke safely.

## Separate Finding: Fragment-Safe ACL/CT Keys

The parser currently does not inspect the IPv4 fragment offset before reading
TCP/UDP ports, while non-first IPv6 fragments use zero ports. Port ACL and CT
keys can therefore differ across fragments. This is a separate ACL defect and
must be recorded in the backlog, but it is not bundled into the TC-unification
implementation. A dedicated fragment design must define first/non-first
fragment policy and CT behavior.

## Expected Files

- `ebpf/src/common.rs`, `core/src/common.rs`: ingress hook constants and
  ABI-compatible `TapConfig` byte.
- `ebpf/src/runtime.rs`, `core/src/ebpf_ops/runtime.rs`: normalized hook reads
  and atomic updates.
- `core/src/ebpf_ops/replay.rs`: fresh generic replay defaults to legacy XDP
  mode while Neutron resync republishes TC mode.
- `ebpf/src/conntrack.rs`: bank-aware explicit outcomes and policy-hit cache.
- `ebpf/src/lib.rs`: XDP bypass plus unified live TC paths.
- `agent/src/instance.rs`, `agent/src/control_plane.rs`: TC link readiness.
- `agent/src/neutron_api.rs`: TC-mode quiesce/publish transition.
- `agent/src/api_handlers/metrics.rs`: diagnostic CT contract labels/help.
- `ci/check_tc_acl_datapath.py`, `ci/check_neutron_stage1.py`: persistent
  source contracts.
- `deploy/kolla/smoke/neutron_aria_acl_tc_datapath_smoke.sh`: real-tap proof.
- `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`: Batch 6 state
  and separate fragment finding.

## Acceptance Criteria

1. Neutron-managed ACL is evaluated only in TC ingress and TC egress.
2. XDP in Neutron TC mode performs no ACL or CT lookup/create.
3. Legacy zero-valued taps preserve XDP ingress ACL compatibility.
4. Every direction performs at most one authoritative CT lookup per packet.
5. Current-bank CT hits skip ACL; miss/disabled/expired/stale paths evaluate
   the current bank.
6. Stale entries are removed before mutation.
7. Misses create CT only after ACL and QoS pass.
8. Rule, flow, group, QoS, Mirror, Trace, and CT counters have documented,
   non-duplicated meanings.
9. Routine CT contract writes add no default per-packet hash lookup.
10. Non-empty Neutron ACL cannot publish without both TC links.
11. `TapConfig`, CT, and policy pinned-map sizes and offsets remain stable.
12. XDP DDoS remains an explicit independent future boundary; no unapproved
    DDoS product surface is added.
13. GitHub Rust/eBPF/static gates pass and real-tap evidence controls the final
    backlog status.
