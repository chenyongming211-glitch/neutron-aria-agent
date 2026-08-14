# REVIEW-ACL-098/099 Fragment Attribution Implementation Plan

**Status:** complete; exact RED/GREEN hosted evidence recorded

**Goal:** Attribute fragment-subsystem drops distinctly from ACL policy drops
and preserve available source/destination group identity on resolve-stage
fragment failures.

**Architecture:** Extend the existing trace result vocabulary additively with
numeric value `5`. Keep every trace record layout unchanged. Resolve-stage
IPv4 and IPv6 failures enter small no-inline attribution phases that read the
existing general source/destination LPM maps, write the results into
`PipelineCtx`, and then reuse the existing fragment drop recorder. Missing
group membership remains ID `0`. Fragment context-install failures and normal
ACL/CT/QoS ordering are unchanged.

## Constraints

- Work only on `v0.9-neutron-agent`.
- Do not modify QoS, Mirror, TCP-RT, generic trace deletion, or generic flush
  behavior.
- Do not change `TraceEvent`, `TraceEventV6`, `TraceStreamEvent`, map keys, or
  map values.
- Keep trace result values `0..4` unchanged; append fragment drop as `5`.
- Use general group maps for fragment-subsystem attribution, not banked ACL
  selector maps.
- Do not run Cargo locally. Hosted CI owns Rust behavior, warning-denied
  userspace/eBPF builds, and the linked 448-byte stack-budget gate.

## Task 1: RED Behavior Contracts

**Files:**

- Modify: `abi/tests/fragment_context_contract.rs`
- Modify: `core/src/trace_ops.rs`

- [x] Add an ABI contract that requires `TRACE_RESULT_DROP_FRAGMENT == 5`,
  proves existing trace-result values remain `0..4`, and reasserts all three
  trace event sizes.
- [x] Add a shared `PipelineCtx` behavior contract requiring resolve-stage
  attribution to overwrite poisoned IDs with exact map hits and use `0` for a
  missing side.
- [x] Add a core observation contract requiring result `5` to render as
  `drop:fragment`, never `drop:acl` or `result:5`.
- [x] Commit and push RED tests. Require hosted `rust-behavior` failure only on
  the missing additive ABI/helper behavior; unrelated build lanes must remain
  healthy.

## Task 2: GREEN Shared ABI And Userspace Projection

**Files:**

- Modify: `abi/src/lib.rs`
- Modify: `core/src/trace_ops.rs`

- [x] Append `TRACE_RESULT_DROP_FRAGMENT = 5` and export it through the stable
  userspace module without changing any structure.
- [x] Add one inline shared helper that replaces both `PipelineCtx` group IDs
  from optional general-map lookup results, using zero only for a miss.
- [x] Render result `5` as `drop:fragment` in every v4/v6/stream projection
  through the existing common `result_name` path.

## Task 3: GREEN eBPF Resolve-Drop Attribution

**File:** `ebpf/src/lib.rs`

- [x] Import the additive trace constant and shared ID-assignment helper.
- [x] Add no-inline IPv4 and IPv6 resolve-drop phases. Each performs exactly
  two existing general-map lookups, writes both IDs through the shared helper,
  then invokes the existing fragment drop phase.
- [x] Route only the four ingress/egress resolve-stage drop branches through
  the new family-specific phases. Leave context-install failure calls on the
  existing phase.
- [x] Make the common fragment drop phase emit
  `TRACE_RESULT_DROP_FRAGMENT`; keep exact `drop_reason` values unchanged.

## Task 4: Hosted Verification And Closure

- [x] Push GREEN and require exact-head `rust-behavior` and `rust-build`.
- [x] Require the linked eBPF stack-budget report to keep both TC entry paths
  at or below 448 bytes and require warning-denied ABI/core/agent/eBPF builds.
- [x] Mark only `REVIEW-ACL-098/099` fixed with RED/GREEN evidence. Keep
  `REVIEW-ACL-086`, `REVIEW-ACL-083/084`, and `REVIEW-TXN-035` as evidence
  gates; keep every excluded non-ACL finding open.
- [x] Push the documentation closure, require exact-head CI, and finish with a
  clean worktree and `0 0` local/remote divergence.
