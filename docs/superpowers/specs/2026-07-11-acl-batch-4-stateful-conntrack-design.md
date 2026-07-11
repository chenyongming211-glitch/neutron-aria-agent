# ACL Batch 4 Stateful Conntrack Contract Design

Date: 2026-07-11

Status: approved for implementation

## Goal

Close `REVIEW-ACL-050` and `REVIEW-ACL-054` by making conntrack mode an
internal dependency of the Neutron-managed ACL lifecycle and by honoring the
ACL snapshot's `stateful` field on each managed tap.

The required end states are:

```text
stateful=true  + enforced ACL -> conntrack enabled + ACL enabled
stateful=false + enforced ACL -> conntrack disabled + ACL enabled
empty/bypass ACL              -> ACL disabled; conntrack follows the snapshot
missing ACL payload           -> ACL disabled; preserve the prior conntrack mode
```

## Scope

- `REVIEW-ACL-050`: ACL can currently report ready/enforce while the tap's
  conntrack foundation is disabled, and local configuration may change CT
  because only `acl` is listed in `managed_domains`.
- `REVIEW-ACL-054`: Rust receives `NeutronAclSnapshot.stateful` but ignores it,
  so `stateful=false` still uses the eBPF CT lookup/create fast path.
- Protect local CT writes while Neutron owns the ACL domain without advertising
  or accepting a separate `managed_domains=conntrack` capability.

## Non-Goals

- Do not implement ACL rule priority (`REVIEW-ACL-047`).
- Do not implement QoS or Mirror.
- Do not add `conntrack` to the Python agent's allowed `managed_domains` or the
  Rust capabilities response.
- Do not change the global CT key/value schema or add a new eBPF map.
- Do not change monitoring, TCP-RT, QoS, or Mirror feature ownership.
- Do not address Neutron WAL growth (`REVIEW-OPS-019`).
- Do not run local Cargo build, check, or test commands; GitHub Actions remains
  the Rust compilation and test authority for this checkout.

## Confirmed Root Causes

### Stateful Is Dropped at Translation

`NeutronAclSnapshot.stateful` is present in the UDS DTO and is populated by the
Python effective ACL projection. `translate_neutron_acl` produces only groups
and policies, while `reconcile_neutron_acl` updates only the ACL feature flag.
No step derives or applies a per-tap conntrack mode from the snapshot.

The eBPF datapath already has the required per-tap behavior. Both CT lookup and
CT create return immediately when `TAP_CONFIG_MAP.conntrack_enabled` is false.
Therefore true stateless ACL does not require a new datapath schema; the missing
piece is an authoritative and correctly ordered control-plane transition.

### ACL Authority Does Not Protect Its CT Dependency

Local config writes are blocked only when the requested local domain name is
present in the port's normalized `managed_domains`. A port managed as
`managed_domains=["acl"]` therefore blocks local ACL writes but permits local
conntrack writes. A local CT disable can invalidate a stateful ACL after the
ACL domain has reported ready.

Conntrack must remain an internal ACL dependency. Treating ACL ownership as a
reason to reject local CT toggles closes the race without claiming that the
standalone `conntrack` domain is implemented for Neutron snapshots.

### CT Can Be Recreated Between Flush and ACL Enable

The eBPF `should_create_ct` path is true when ACL, monitoring, or TCP-RT is
enabled. Merely disabling the ACL gate does not quiesce CT creation if another
local feature still needs flow state. A sequence of `strict CT flush -> ACL
enable` can therefore race with traffic that recreates a CT entry after the
flush and before ACL activation.

`update_runtime_config` rewrites the entire per-tap config value in one map
insert. Passing conntrack and ACL values in the same `update_config` call gives
the control plane an atomic per-tap feature transition and removes that gap.

## Approved Design

### 1. Carry Conntrack Intent in the ACL Apply Plan

Extend the translated ACL plan with an optional desired conntrack mode:

- an ACL payload sets it to `Some(acl.stateful)`, including degraded, disabled,
  and empty-policy payloads;
- a missing ACL payload sets it to `None`, meaning preserve the currently
  configured conntrack mode;
- ACL groups and policies retain their existing translation rules.

The reconcile path reads the current per-tap config before mutation only when
the plan requests preservation. A config-read failure is a pre-mutation ACL
error with `effective_action=unchanged`.

### 2. Quiesce ACL and Conntrack Together

After successful translation, every ACL replacement begins with one per-tap
config update:

```text
conntrack=false, acl=false
```

This single map update prevents both CT lookup and CT creation while the policy
bank is replaced. Failure at this step occurs before the new ACL mutation and
reports `effective_action=unchanged`.

The existing availability-first boundary remains: OVS forwarding continues
while Aria ACL and CT are quiesced.

### 3. Replace, Strictly Flush, Then Atomically Publish the End State

The mutation order is:

```text
translate and determine desired CT mode
  -> atomically set CT=false and ACL=false
  -> replace the Neutron-owned ACL policy
  -> strictly flush both CT maps while CT creation is disabled
  -> atomically publish desired CT mode and final ACL gate
```

For a non-empty enforce plan, the final update is one map write:

```text
conntrack=acl.stateful, acl=true
```

For an empty or bypass plan, the final update is:

```text
conntrack=acl.stateful (or preserved prior mode), acl=false
```

The final update is required even when ACL remains disabled because CT was
temporarily quiesced. A final-update failure leaves both features in the
quiesced state and reports ACL error/bypass.

The existing post-enable fault compensation must disable both ACL and CT. It
must never leave CT active after an uncommitted ACL activation. If compensation
itself fails, report the proven effective action rather than claiming bypass.

### 4. Protect the Internal Dependency at the Local API Boundary

`ensure_local_write_allowed(instance, Conntrack)` rejects the write when the
port authority manages either `conntrack` directly or `acl`. Other local
domains remain governed by their own selected-domain authority.

The error remains the existing HTTP 409 local-write-blocked classification,
but its message identifies conntrack as an ACL-managed dependency. Internal
Neutron reconciliation calls `ControlPlane::update_config` directly and is not
blocked by the local API guard.

Clearing Neutron port authority on detach restores ordinary local conntrack
write behavior.

## Failure Semantics

| Failure point | Datapath state | ACL result |
| --- | --- | --- |
| Translation/current-config read | unchanged | error/unchanged |
| CT+ACL quiesce | prior state or atomic write failure | error/unchanged |
| Replace or strict flush | CT off, ACL off | error/bypass |
| Final atomic publish | CT off, ACL off | error/bypass |
| Post-publish fault, compensation succeeds | CT off, ACL off | error/bypass |
| Post-publish fault, compensation fails | publish may still be active | error/enforce |

No failure may report ready/enforce unless the control plane has proof that the
final atomic config write is still active.

## Invariants

1. `stateful=true` ACL enforcement implies per-tap conntrack is enabled.
2. `stateful=false` ACL enforcement implies per-tap conntrack is disabled, so
   the eBPF fast path neither looks up nor creates CT entries.
3. CT creation is disabled continuously from before replacement through the
   strict V4/V6 flush and final feature publication.
4. CT and ACL final flags are published by one per-tap map insert.
5. Local CT writes are rejected while the same tap is Neutron ACL-managed.
6. ACL ownership of CT is internal and does not expand advertised Neutron
   managed-domain capabilities.
7. A missing ACL payload does not permanently change the prior CT mode.
8. OVS forwarding remains available during ACL/CT failure or transition.

## Verification

Rust regression coverage must prove:

- translation carries `stateful=true`, `stateful=false`, and missing-payload
  preservation intent;
- ACL apply quiesces conntrack and ACL in the same config operation;
- a stateful enforced plan atomically publishes CT on plus ACL on;
- a stateless enforced plan atomically publishes CT off plus ACL on;
- empty/bypass plans restore the desired or preserved CT mode while keeping
  ACL off;
- replace, strict-flush, final-publish, and compensation failures cannot claim
  false enforcement;
- ACL authority blocks local conntrack writes without adding `conntrack` to
  `managed_domains`;
- non-ACL authority retains existing local conntrack behavior.

Repository contract checks and backlog accounting are updated only after the
implementation. Rust compilation and tests are verified through GitHub
Actions, while allowed Python/static checks and `git diff --check` run locally.
