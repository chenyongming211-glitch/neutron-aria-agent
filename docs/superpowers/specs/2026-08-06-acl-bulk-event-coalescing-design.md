# ACL Bulk Event Coalescing Design

Status: approved implementation design.

## Goal

Prevent ACL rule bursts from producing one Neutron RPC notification and one
host full-resync per object, while preserving prompt handling of ordinary
sparse changes.

## Evidence And Root Cause

The controlled 100/500/1000-rule benchmark showed that the standard bulk API
was emulated by the target Neutron release. It called the singular plugin
create method for every rule, so every row emitted an `aria_acl_update` fanout.
The agent then measured its merge window from the first pending event. During a
sustained stream, the window was already expired when each full-resync ended,
which caused another immediate full-resync.

The 1000-rule create generated about 63 event batches and 62 full-resyncs. The
datapath apply itself remained below 0.5 seconds, so the repeated control-plane
work is the optimization target.

## Design

### Native Bulk Notification

`AriaAclPlugin` advertises the old Neutron native bulk contract and implements
bulk create entry points for policies, rules, address sets, bindings, and port
statuses. ACL object bulk creation runs inside one database transaction and
emits exactly one `bulk_create` notification after successful commit. Port
status bulk creation does not emit an ACL desired-state notification.

If any row fails, the transaction rolls back and no notification is emitted.
Singular create/update/delete behavior remains unchanged.

### Trailing-Edge Event Merge

`EventMerger` retains both first and last pending timestamps. Every accepted
event refreshes the last timestamp. A batch becomes ready only after no new
event has arrived for `event_merge_interval`.

The existing synchronous service loop already permits only one full-resync at
a time. Events received by the RPC callback during that resync remain in the
merger and become one follow-up batch after the trailing quiet window. No new
worker queue, executor, or persistent event journal is introduced.

Periodic `resync_interval` remains the recovery mechanism if an event stream
does not become quiet.

## Compatibility

- Python 2 syntax and the target pre-`neutron-lib` plugin model remain required.
- Existing singular REST and CLI operations keep their response and RPC shape.
- `incremental_rpc_enabled` remains unchanged; this optimization is valid for
  the current RPC-triggered full-resync path.
- OVS, the OVS agent, and the Rust datapath are not restarted or modified by
  this change.

## Verification

Automated tests must prove:

1. A later event moves the ready deadline.
2. A sustained burst produces one batch after the quiet window.
3. A native ACL bulk create emits one notification containing the row count.
4. A failed native bulk create emits no notification and leaves no partial rows.
5. Singular operations retain their existing notification behavior.

The field benchmark then repeats the same 100/500/1000-rule workload and
compares API duration, event batches, full-resync count, convergence, resource
peaks, traffic correctness, and cleanup behavior with the saved baseline.

## Guardrails

- Do not add a message broker, scheduler, DB bulk-insert abstraction, or new
  datapath apply mode.
- Do not tune the merge interval solely for the benchmark.
- Do not enable scoped incremental apply as part of this change.
- Do not trade atomic bulk semantics for notification reduction.

