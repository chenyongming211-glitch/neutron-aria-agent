# REVIEW-ACL-008/033 Fail-Safe Status Publication Design

## Status

Fixed in production and verified by exact-head hosted CI. This is a fail-safe
ordering contract, not a claim of distributed RabbitMQ/SQL atomicity.

## Scope

This design fixes:

- `REVIEW-ACL-008`: global degradation retains stale ready/enforce port rows;
- `REVIEW-ACL-033`: sequential heartbeat then port-row publication can expose
  a new ready heartbeat while per-port publication failed.

It covers the in-process runtime status and the existing heartbeat/port-status
reporters. It does not claim a distributed atomic transaction across RabbitMQ
and the Neutron database and does not add a new REST resource.

## Confirmed Current Failures

`AgentRuntimeStatus.mark_degraded` changes only global fields and aggregate
reasons. It retains `last_port_statuses`, including nested ACL
`ready/enforce` rows.

`CompositeStatusReporter` invokes reporters in constructor order. The factory
constructs heartbeat first and port-status second. If the second reporter
fails, the new ready heartbeat has already become visible while the database
rows remain old or partially updated.

## Global Degradation Projection

`mark_degraded(reason, error)` rewrites every cached port status into a
conservative runtime projection while preserving identity fields:

- top-level `status=degraded`;
- top-level `effective_action=bypass`;
- top-level `reason=<global reason>`;
- every managed-domain row becomes `status=degraded`,
  `effective_action=bypass`, and the same reason;
- port, policy, binding, host, generation, and desired-hash identity fields
  remain intact.

It then recomputes `domain_counts` and `degraded_reasons` from the transformed
rows. An empty cache remains empty.

No stale cached row can therefore be emitted as ready/enforce after a global
degradation transition.

## Fail-Safe Composite Commit Points

The factory constructs a role-aware composite with an explicit heartbeat
reporter and port-status reporter.

For a ready runtime:

1. publish all port-status rows;
2. only if that succeeds, publish the ready heartbeat as the visibility commit
   point.

If port publication fails, no new ready heartbeat is sent. The failure is
returned to `report_status` and retried by the existing loop.

For a degraded or not-ready runtime:

1. publish the heartbeat first so global readiness closes immediately;
2. publish the conservative per-port rows second.

If per-port publication fails, the already-published heartbeat remains
degraded/not-ready. Stale rows cannot be paired with a newly published ready
heartbeat.

If the first phase fails, the second phase is not attempted. A multi-row
port-status failure remains explicit; this batch does not pretend individual
REST upserts are database-atomic.

The composite returns results in stable semantic keys rather than relying on
constructor-order array positions.

## Failure And Retry Contract

- reporter exceptions remain visible as `heartbeat.ok=false`;
- ready publication never sends the heartbeat after a port-row failure;
- degraded publication never sends port rows before the degraded heartbeat;
- `NeutronStatusReporter.start_flag` changes only after its own successful
  report as today;
- a later retry republishes the complete current runtime status idempotently.

## RED/GREEN Coverage

Python behavior tests must prove:

1. ready followed by global degradation transforms top-level and nested ACL
   rows to degraded/bypass;
2. identities survive transformation and aggregates are recomputed;
3. ready publication calls port rows before heartbeat;
4. a ready port-row failure prevents a heartbeat call;
5. degraded publication calls heartbeat before port rows;
6. a degraded port-row failure leaves a successfully published degraded
   heartbeat;
7. a first-phase failure prevents the second phase;
8. successful reports retain both result payloads and existing factory
   behavior.

## Delivery Evidence

- RED commit `c847761` and Build
  [`30615481157`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30615481157)
  proved stale cached ready rows and unsafe reporter ordering as part of the 11
  intended Python failures.
- GREEN commit `2bd1726` projects all cached rows conservatively during global
  degradation and gives ready publication a per-port-first/heartbeat-last
  commit point while degraded publication closes heartbeat readiness first.
- Build
  [`30615746741`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30615746741)
  passed 176 targeted tests and the complete 515-test fast-contract path;
  combined exact-head Build
  [`30616520693`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30616520693)
  remained GREEN.

## Acceptance

- targeted RED tests fail on current ordering/transformation;
- production implementation turns them GREEN without a new API;
- all Python fast contracts pass;
- `REVIEW-ACL-008` and `REVIEW-ACL-033` are marked fixed only after exact-head
  hosted CI.
