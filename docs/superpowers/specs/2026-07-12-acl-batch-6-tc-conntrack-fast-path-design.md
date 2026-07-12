# ACL Batch 6 TC Conntrack Fast-Path Design

Date: 2026-07-12

Status: approved in conversation; pending written-spec review

## Goal

Close `REVIEW-ACL-055` by connecting the live TC ingress and egress packet
paths to the existing conntrack lookup, established-flow fast path, and
accepted-flow creation behavior.

The completed path must give stateful ACL traffic consistent XDP and TC
forward/reply behavior without changing the public ACL match model, map ABI,
or Batch 4 stateless contract.

## Verified Current Defect

The four live functions in `ebpf/src/lib.rs`:

- `try_tc_ingress_v4`;
- `try_tc_ingress_v6`;
- `try_tc_egress_v4`;
- `try_tc_egress_v6`;

currently load ACL selector IDs and call `phase_policy_tc` directly. They do
not construct a CT key, call `phase_ct_v4` / `phase_ct_v6`, select an
established fast path, or call the CT-creating post-accept functions.

Several TC CT helpers already exist, but wiring them unchanged is not a valid
fix. In particular, the current TC ingress fast-path helpers reload ACL IDs
and call `phase_policy_tc` on a CT hit, so they still repeat full ACL matching.
The helpers also do not reject a cached matched-policy decision from an
obsolete ACL bank.

## Confirmed Product Boundaries

1. The public ACL remains priority-independent and service-oriented.
2. Source-port matching, ordered priority resolution, IPv6 product expansion,
   QoS implementation, and Mirror implementation are outside this batch.
3. The packet five tuple remains an internal CT key for forward/reply flow
   identity.
4. `NeutronAclSnapshot.stateful=false` remains authoritative through the
   existing per-tap `conntrack_enabled=false` runtime guard.
5. Selector interning, the 1000-rule/2048-member limits, shadow-bank
   publication, force-bypass behavior, and all Batch 1-5 contracts remain
   unchanged.
6. `CtKey4`, `CtKey6`, `CtValue`, `PolicyKey`, `PolicyValue`, pinned map
   layouts, WAL, and Neutron UDS DTOs must not change.
7. Packet-time CT failure may fall back to full ACL evaluation, but it must
   never become an unvalidated stateful fast-path allow.

## Considered Approaches

### A. Bank-Aware Shared TC Pipeline — Selected

Every live TC family/direction constructs a CT key, performs a bank-aware
lookup, and selects one of two paths:

- a current-bank established hit skips ACL and continues non-ACL hooks;
- miss, expiry, disabled CT, or stale bank evaluates the current ACL bank and
  creates CT only after all drop-capable stages accept.

This reuses the existing CT maps and matched-policy cache without an ABI
change.

### B. Minimal Existing-Helper Wiring — Rejected

This is a smaller diff, but the existing ingress fast-path helper repeats ACL
on hits and lacks stale-bank validation. It would not close the defect.

### C. CT Policy Generation In The Map ABI — Rejected

A new policy generation in `CtKey` or `CtValue` would provide stronger
versioning, but it requires pinned-map migration and wider recovery changes.
The existing matched bank plus strict Batch 4 CT scrub is sufficient for this
bounded fix.

## Architecture

### 1. Bank-Aware CT Lookup

`ebpf/src/conntrack.rs` keeps the current forward and reverse lookup behavior,
but lookup receives two BPF-friendly scalar inputs:

```text
validate_acl_bank
expected_acl_bank
```

When ACL is active, the caller sets `validate_acl_bank=true` and passes the
normalized per-tap `acl_active_bank`. When ACL is not active, bank validation
is disabled so independent conntrack/monitoring behavior is not coupled to an
irrelevant ACL bank.

For both forward and reverse entries, validation happens before mutating
`last_seen`, state, flags, packet count, or byte count:

```text
entry absent or expired
  -> NotFound

entry present + bank validation disabled
  -> current Established / SeenReply behavior

entry present + matched_bank == expected_acl_bank
  -> current Established / SeenReply behavior

entry present + matched_bank != expected_acl_bank
  -> remove the exact forward or reverse entry
  -> StaleBank
```

`StaleBank` is an internal lookup result. It is handled as a miss by policy
evaluation but remains distinct for metrics and regression tests.

A small pure bank-decision helper lives in the eBPF common source and is used
by the live lookup. Host-side Rust tests include that exact source helper so
the bank equality/normalization decision is executable in CI without creating
a new shared crate or duplicating the decision.

### 2. Live TC Control Flow

Each of the four live TC functions follows the same family-specific structure:

```text
construct CtKey4 / CtKey6
  -> phase_ct with expected active bank when ACL is on
     |
     +-- Established / SeenReply from current bank
     |     -> restore cached MatchedPolicy
     |     -> record ct_hit
     |     -> TC fast path (no ACL selector lookup, no phase_policy_tc)
     |     -> run applicable TCP-RT, QoS, Mirror, statistics, and trace hooks
     |
     +-- NotFound / StaleBank / CT disabled
           -> record ct_miss / stale_bank / ct_disabled
           -> load selectors from the current active ACL bank
           -> phase_policy_tc
           -> ACL drop: return, do not create CT
           -> load ordinary group IDs when required by non-ACL hooks
           -> QoS stage
           -> QoS drop: return, do not create CT
           -> Mirror, statistics, trace, and TCP-RT as currently applicable
           -> create or refresh CT only after acceptance
```

Ingress and egress retain their existing hook-specific QoS, mirror, stats,
trace, and TCP-RT behavior. This batch changes only when ACL is evaluated and
when accepted stateful traffic is cached.

### 3. Established Fast Path

On a current-bank CT hit:

- `MatchedPolicy` is restored from CT;
- ACL LPM selector lookup and `phase_policy_tc` are skipped;
- rule and flow statistics may use the cached policy key;
- ordinary group IDs are loaded only when QoS, Mirror, group statistics, or
  trace behavior needs them;
- QoS remains independently drop-capable;
- no second CT entry is created for the hit.

The current ingress helper condition that includes `FLAG_ACL_ON` in its
post-hit ID/ACL work is removed or split into an explicitly non-ACL ID need.

### 4. Miss And Accepted-Flow Creation

On a miss, expired entry, stale bank, or disabled CT:

1. evaluate the current active-bank ACL when ACL is enabled;
2. stop immediately on ACL drop;
3. run the hook's existing QoS path and stop on QoS drop;
4. run the existing non-drop post-accept hooks;
5. call `ct_create_v4` / `ct_create_v6` only after acceptance.

The existing CT create guard remains authoritative. With
`conntrack_enabled=false`, create is a no-op, so stateless ACL traffic always
evaluates ACL and never becomes a CT hit.

### 5. Active-Bank Safety

Batch 4 already quiesces ACL and CT, strictly scrubs CT, stages the shadow ACL
bank, and atomically publishes the desired CT/ACL flags. Batch 6 does not
replace that transaction boundary.

The packet-path bank check is defense in depth for races, legacy entries, and
unexpected residual state. A stale entry is deleted and the packet is
evaluated against the current bank. The accepted packet then creates a new CT
entry containing the current matched bank.

## Failure Semantics

| Condition | Handling |
| --- | --- |
| CT disabled | Treat as miss, evaluate ACL, never create CT. |
| CT entry absent or expired | Evaluate ACL; create CT only after acceptance. |
| CT entry bank is stale | Delete exact hit, record `stale_bank`, evaluate current ACL. |
| ACL rejects miss/stale packet | Drop; do not create CT. |
| QoS rejects accepted ACL packet | Drop; do not create CT. |
| CT insert fails at packet time | Current packet has passed full ACL and may pass; later packets miss and revalidate. It is never reported as a CT hit. |
| Required CT pins fail during ACL publication | Preserve Batch 4 strict reconcile failure; ACL must not publish ready/enforce. |
| Metrics update fails | Do not change packet verdict; metrics cannot authorize a fast path. |

No new packet-path RPC or readiness channel is introduced. Runtime readiness
continues to rely on the strict control-plane CT foundation established in
Batch 4.

## Observability

The existing `CT_CONTRACT_STATS` map layout is retained. Its key already
contains `tap_id`, `hook`, `family`, and `reason`, so Batch 6 only adds constant
values and label mapping:

- hook: `tc_ingress`, `tc_egress`;
- family: `ipv4`, `ipv6`;
- reason: `ct_hit`, `ct_miss`, `ct_disabled`, `stale_bank`.

Prometheus keeps the existing metric names and exposes the new hook/reason
labels. Help text is updated from fallback-only wording to TC conntrack path
wording.

These counters are behavioral evidence:

- a warmed stateful flow must accumulate hits rather than repeated misses;
- a stateless flow must not accumulate hits;
- a stale-bank packet must not be counted as a hit.

## Testing Strategy

### 1. RED Contracts

Before production edits, add failing contracts that require:

1. all four live TC functions build family-correct CT keys and perform CT
   lookup before policy evaluation;
2. established hit paths contain no ACL selector load and no
   `phase_policy_tc` call;
3. miss/stale paths evaluate current-bank ACL;
4. ACL/QoS drop paths do not reach CT create;
5. accepted miss paths reach CT create;
6. stale-bank lookup is rejected before entry counters/state mutate;
7. source and reverse entries remove the exact stale key;
8. stateful/stateless and current/stale bank decisions pass the exact eBPF
   common helper tests;
9. metrics labels cover ingress/egress and all four reasons.

The source-contract checker must extract and inspect specific function bodies;
plain file-wide substring presence is insufficient.

### 2. GitHub GREEN Gate

GitHub Actions is the Rust/eBPF authority and must run:

- Python Stage 1/2/3 and the new precise TC/CT source contract;
- host-side Rust tests for the exact bank-decision helper and metrics mapping;
- the existing `neutron_acl_` Rust family;
- nightly BPF-target release build;
- eBPF artifact discovery;
- static userspace build;
- static agent build and binary verification.

No local `cargo build`, `cargo check`, or `cargo test` command is allowed.

### 3. Real-Traffic Smoke

A dedicated smoke script is added for a real managed tap. It records counters
before and after controlled traffic and covers:

- IPv4 and IPv6 when the environment provides both;
- TC ingress and egress;
- forward and reply directions;
- stateful first miss followed by hits;
- stateless disabled/miss with zero hits;
- ACL deny with no CT creation;
- policy/bank transition with no stale fast-path allow.

After warm-up, the functional performance gate compares counts rather than an
environment-sensitive absolute latency threshold: the repeated stateful flow
must produce predominantly `ct_hit`, with misses bounded to initial/revalidation
events. Absolute throughput/latency remains reportable evidence, not a flaky
generic CI threshold.

The generic GitHub runner cannot prove a production tap data path. The smoke
script is syntax/contract checked in GitHub and must be run in the target
environment before the backlog item is marked fixed.

## Closure States

`REVIEW-ACL-055` moves through explicit evidence states:

- `open`: current live TC paths bypass CT;
- `likely-fixed`: code, precise contracts, Rust tests, eBPF build, and static
  binaries pass, but real-tap traffic evidence is not yet attached;
- `fixed`: stateful/stateless forward/reply smoke and counter-based hit/miss
  evidence pass on the target TC data path.

The backlog must not claim fixed from source markers or compilation alone.

## Expected Files

- Modify `ebpf/src/lib.rs` for live TC path selection and helper cleanup.
- Modify `ebpf/src/conntrack.rs` for bank-aware forward/reverse lookup.
- Modify `ebpf/src/common.rs` for internal decision/flag and telemetry constants.
- Mirror public map constants in `core/src/common.rs` without changing struct
  layouts.
- Modify `agent/src/api_handlers/metrics.rs` for hook/reason labels and tests.
- Add a precise CI contract checker under `ci/` and wire it into Build/Stage 1.
- Add a dedicated real-traffic smoke under `deploy/kolla/smoke/`.
- Update `docs/openstack-neutron-aria-details/12-review-bug-backlog.md` with
  RED/GREEN and runtime evidence state.

The whole external local commit `78a0346` is not cherry-picked. It also
contains northbound semantic changes outside this approved Batch 6 scope. This
design carries forward only the independently verified `REVIEW-ACL-055`
boundary while leaving the main checkout and its dirty `README.md` untouched.

## Acceptance Criteria

1. Current-bank CT hits skip ACL on all four TC family/direction paths.
2. Miss, expiry, disabled CT, and stale bank evaluate the current active-bank
   ACL.
3. Stale entries are removed before their state or counters mutate.
4. Only packets accepted by ACL and other drop-capable stages can create CT.
5. `stateful=false` produces no CT hit/create behavior.
6. QoS, Mirror, statistics, trace, and TCP-RT retain their existing hook
   behavior.
7. No CT/policy/map ABI, WAL, DTO, selector, priority, QoS, or Mirror feature
   expansion occurs.
8. GitHub Rust/eBPF/static gates pass without local Cargo execution.
9. `likely-fixed` and `fixed` are reported according to the documented
   evidence boundary.
10. The main checkout's external commit and uncommitted README remain
    untouched.
