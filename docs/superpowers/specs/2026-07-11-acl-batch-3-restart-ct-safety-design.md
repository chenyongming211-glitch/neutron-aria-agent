# ACL Batch 3 Restart and Conntrack Safety Design

Date: 2026-07-11

Status: approved for implementation

## Goal

Close the third ACL repair batch by preventing restart recovery from claiming
ACL readiness without Neutron-domain replay confirmation, and by making
conntrack clearing a strict prerequisite for a successful Neutron ACL update.

The required boundaries are:

```text
runtime attach/replay succeeds
  -> attach is ready
  -> ACL remains degraded/unchanged and its skip hash is invalidated
  -> same-generation or same-hash full resync must execute ACL reconcile
  -> ACL gate is disabled before replacement
  -> strict CT clear succeeds
  -> ACL may become ready/enforce
```

## Scope

This batch fixes two P1 findings:

- `REVIEW-ACL-035`: restart recovery can use Neutron WAL hash/status as proof
  that a tap-local ACL replay is current even though the two WALs do not share
  a commit identity.
- `REVIEW-ACL-053`: Neutron ACL reconcile uses lenient `ct_flush`, which treats
  missing or invalid CT map pins as `Ok(0)` and can leave established flows on
  the old policy fast path.

## Non-Goals

- Do not add a shared transaction ID or desired hash to the tap-local state
  schema. That larger cross-WAL identity design is deferred.
- Do not disable or scrub a successfully restored ACL merely because the
  process restarted. Preserve its current datapath action until resync begins.
- Do not claim that attach readiness proves ACL readiness.
- Do not change the public/general-purpose lenient conntrack flush behavior;
  strict failure semantics are required specifically for Neutron ACL apply.
- Do not implement or change QoS, Mirror, ACL priority, stateless ACL, or
  conntrack-foundation behavior tracked by other backlog items.
- Do not run local Cargo build, check, or test commands; GitHub Actions remains
  the Rust compilation and test authority for this checkout.

## Confirmed Root Causes

### Restart Readiness Uses the Wrong Proof

`reconcile_committed_runtime` restores committed interfaces through the normal
attach path. The attach path either replays tap-local persisted state into the
pinned maps or validates a pre-existing pinned runtime against that tap-local
state. This is useful evidence, but it proves only that the kernel runtime
matches the tap-local state.

The Neutron WAL separately stores the managed port, ACL desired hash, and
ready/enforce status. It does not store the ACL payload, and the tap-local WAL
does not store the Neutron desired hash. Therefore no shared commit identity
proves that the restored tap-local ACL is the ACL represented by the Neutron
hash.

Despite that gap, successful attach currently rewrites every managed domain to
`ready`. A later snapshot with the same ACL domain hash then satisfies
`can_skip_neutron_domain_reconcile`, so ACL translation, replacement, CT
clearing, and enablement are skipped.

### Neutron Uses Lenient Conntrack Clearing

`flush_neutron_acl_conntrack` calls `ControlPlane::flush_conntrack`, which calls
`core::ct_ops::ct_flush`. The lenient core function ignores failures to open or
convert both `CT_TABLE_V4` and `CT_TABLE_V6` and returns `Ok(0)`.

`scrub_ct_tables_strict` already implements the required behavior: missing,
invalid, uniterable, or unremovable CT state returns an error. It is currently
used by managed runtime scrub but not by Neutron ACL reconcile.

## Approved Design

### 1. Restart Invalidation Is Domain-Scoped

After a committed interface is successfully claimed:

- keep the `attach` domain `ready`;
- for a managed `acl` domain, set status to `degraded`;
- set ACL `effective_action=unchanged` because restart recovery does not
  mutate the restored ACL gate or policy;
- use a stable reason such as `acl_restart_replay_requires_resync`;
- remove only the `acl` entry from that port's `domain_desired_hashes`;
- leave unrelated domain hashes and port binding identity intact.

The overall port status becomes `degraded`, while the process-wide authority
state becomes `runtime_reconcile_requires_full_resync`. This prevents the
same-generation early no-op path, and the missing ACL domain hash prevents the
per-port same-hash skip path.

The invalidated runtime is appended to the Neutron WAL before it is published
to RAM. A second restart therefore cannot recover the previous false-ready ACL
hash/status from the older commit.

If that WAL append fails, publish the invalidated port/hash/status state to RAM
with `authority_state=wal_runtime_reconcile_commit_failed` and
`wal_status=commit_failed`. The durable WAL remains older and the next restart
will repeat invalidation, but the live process must not retain a ready ACL hash
that can satisfy the per-port skip path.

If attach itself fails, retain the existing blocked classification. The new
degraded/unchanged classification applies only to successfully restored ACL
ports.

Ports that do not manage ACL keep their existing runtime-reconcile behavior.
An empty reconcile result remains a no-op.

### 2. Resync Restores Readiness

The Python agent's existing startup/periodic full-resync remains the source of
the ACL payload. No ACL payload is reconstructed from the Neutron WAL.

Because authority is not `ready` and the ACL domain hash is absent, a snapshot
at the currently applied generation/hash is not returned as already applied.
The normal apply path performs ACL translation and replacement. Only a
successfully committed reconcile restores the ACL hash and ready/enforce
status.

### 3. Strict CT Clear Is Neutron-Specific

Add a strict control-plane operation that delegates to
`scrub_ct_tables_strict`. `flush_neutron_acl_conntrack` uses this strict method;
the existing public/general `flush_conntrack` method remains unchanged.

For both empty-policy/bypass and non-empty-policy/enforce ACL updates:

- disable the ACL gate before ACL replacement begins;
- CT clearing runs after ACL replacement;
- any V4 or V6 open, conversion, iteration, or removal failure returns an ACL
  reconcile error;
- for a non-empty policy, enable the ACL gate only after strict CT clearing
  succeeds;
- on replacement or CT-clear failure, keep the gate disabled and report the
  ACL domain as error with `effective_action=bypass`;
- the snapshot transaction uses its existing classified failure semantics.

This batch does not attempt best-effort success when only one address family
was cleared. Partial CT clearing is still a failure because the caller cannot
prove that old-policy established flows are gone.

Pre-disable intentionally creates a short, explicit fail-open interval during
every Neutron ACL update. That is the approved option A and is consistent with
the project's availability-first OVS enhancement boundary. A shadow-bank plus
CT-quiesce atomic activation design would avoid that interval, but requires a
larger ACL/WAL transaction redesign and is out of scope.

## Invariants

1. `attach=ready` never implies `acl=ready` after restart by itself.
2. Restart invalidation changes only ACL readiness/hash metadata; it does not
   scrub or disable a successfully restored ACL.
3. No same-generation or same-hash shortcut may bypass the first ACL resync
   after restart.
4. ACL `ready/enforce` after an update requires successful replacement and
   strict clearing of both CT address-family maps while the ACL gate is
   disabled.
5. A missing or invalid CT pin is an ACL apply failure, never `Ok(0)`.
6. Any Neutron ACL update failure after pre-disable leaves the ACL gate disabled
   and reports bypass; it never reports enforcement with uncleared CT.
7. Existing OVS forwarding and the approved availability-first ACL boundary
   remain unchanged.

## Verification

Rust regression coverage must prove:

- restart invalidation keeps attach ready but marks ACL degraded/unchanged;
- only the ACL desired hash is removed;
- the runtime authority is not ready, so same-generation early no-op is
  rejected;
- the same ACL payload cannot satisfy the domain hash skip after invalidation;
- ports without managed ACL retain their existing recovery status;
- strict CT clearing rejects missing V4 and V6 pins;
- the Neutron ACL path uses the strict control-plane operation.
- a non-empty ACL update disables the gate before replacement and enables it
  only after strict CT clearing;
- a strict CT failure leaves the gate disabled and is surfaced as ACL
  error/bypass.

Repository contract checks and backlog accounting must be updated after the
implementation. Rust compilation and tests are verified only through GitHub
Actions in accordance with `AGENTS.md`.
