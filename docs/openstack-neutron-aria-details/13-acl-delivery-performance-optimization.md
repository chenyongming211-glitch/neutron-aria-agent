# 13. ACL Delivery Performance Optimization Detail Plan

Status: design record for ACL strategy delivery performance optimization.

This plan targets the observed slow ACL convergence when one VM port carries
hundreds of ACL rules. It does not change the product boundary: Neutron remains
the northbound authority, `neutron-aria-agent` remains the OpenStack adapter,
and `aria-datapath` remains the local eBPF executor.

## 1. Problem Statement

On 2026-07-07, a CirrOS VM on a normal OVS tap port was used for real ACL
capacity probing.

Observed behavior:

| Rule count | Mode | Result |
| ---: | --- | --- |
| 10 | manual full-resync | passed, about 3.0 s |
| 50 | manual full-resync | passed, about 6.8 s |
| 100 | manual full-resync | passed, about 11.7 s |
| 120 | resident service full-resync | passed, about 20.5 s |
| 200 | resident service full-resync | eventually passed, about 218.6 s |

The 218.6 seconds must not be interpreted as a single eBPF map write duration.
The log sequence shows repeated timeout, pending recovery, and generation bump:

```text
generation 273 -> status did not converge
generation 275 -> status did not converge
generation 277 -> status did not converge
generation 279 -> status did not converge
generation 281 -> pending_snapshot_recovered
generation 281 -> full_resync_complete
```

Root cause at design level:

```text
large full-host snapshot
  |
Rust apply exceeds Python UDS request_timeout=3s
  |
Python treats submit as timeout and enters convergence recovery
  |
status has not converged within current window
  |
Python bumps generation and submits another full snapshot
  |
Rust apply_lock serializes old and new snapshot work
  |
total convergence time is amplified by repeated full-host apply
```

## 2. Timing Definitions

The product must use precise timing terms.

| Term | Meaning |
| --- | --- |
| API create time | Neutron Server DB/API time to create policy/rule/binding objects. |
| Agent read time | Time for `neutron-aria-agent` to read Neutron ports and `aria_acl` objects. |
| Snapshot build time | Time to compute effective per-port desired state and desired hash. |
| Submit latency | Time for Python to submit a UDS request and receive an accepted response. |
| Datapath apply time | Time Rust spends reconciling attach, ACL group/policy maps, WAL, and runtime status. |
| Status convergence time | Time until `/api/v1/neutron/status` reports expected generation/hash and port states. |
| End-to-end convergence | API object change until port status and datapath behavior are correct. |

The 200-rule result is end-to-end convergence under the current retry model. It
is not the raw datapath apply time.

### 2.1 2026-07-08 Optimization Update

The first datapath optimization has been implemented and smoke-tested on
`ostack2` against the same test VM port.

Implemented changes:

- Per-port ACL/domain desired hash so unchanged ports skip ACL domain rewrite
  during full-resync.
- Python accepted/pending convergence wait so a long-running same-hash apply is
  observed instead of being resubmitted as a new generation.
- Rust Neutron-owned ACL batch replace path:
  - translate ACL once;
  - replace only the current port's Neutron-owned ACL groups/policies;
  - keep one instance write lock;
  - avoid per-group/per-policy WAL fsync;
  - compact local state once after successful map apply.

Same-host before/after evidence:

| Scenario | Before | After |
| --- | ---: | ---: |
| 200-rule target port apply profile | `total_ms=28116` | `total_ms=123` |
| 200-rule target port cleanup profile | about `24944 ms` apply path in earlier run | `total_ms=442` |
| Manual full-resync command wall time | about `31 s` in the profiled run | `3212 ms` |
| Cleanup full-resync command wall time | about `27 s` in the profiled run | `2782 ms` |

Representative optimized log:

```text
neutron_acl_apply_profile
  status="enforced"
  group_count=400
  policy_count=200
  group_add_count=400
  policy_add_count=200
  replace_ms=65
  compact_ms=44
  total_ms=123

neutron_acl_apply_profile
  status="bypass"
  reason="empty_policy"
  group_delete_count=400
  policy_delete_count=200
  replace_ms=283
  compact_ms=265
  total_ms=442
```

This changes the immediate product guidance:

- 200 rules per port is no longer blocked by the Rust datapath write path.
- 1000 rules per port is still the product target, but it still needs a
  dedicated gate because every ACL rule currently creates up to two CIDR groups
  and both source/destination LPM entries.
- The next optimization layer remains rule/group-level diff apply and shadow
  generation. Batch replace removes the worst WAL/fsync cost, but it still
  rewrites the changed port's full owned ACL set.

## 3. OVS-Inspired Design Principles

Aria should borrow several ideas from OVS without copying the whole OVS agent:

| OVS pattern | Aria interpretation |
| --- | --- |
| Desired-state database | Neutron DB remains desired state; Aria local state is a projection. |
| Atomic transaction / bundle | A port should see either previous committed ACL or next committed ACL, not a partial rule set. |
| Monitor/event-driven updates | RPC/incremental apply should reduce polling and avoid whole-host work for one-port changes. |
| Sequence/revision based retry | Retry only after observing state progress or version change; do not blindly resubmit full snapshots. |
| Idempotent operations | Same generation/hash must be treated as already accepted or in progress. |
| Periodic reconciliation | Full-resync remains the recovery path, not the normal path for every small change. |

Target Aria semantics:

```text
Neutron desired state
  |
revision/hash-aware adapter
  |
single accepted generation/hash per host or per port
  |
async local datapath apply
  |
status convergence / retry only after state observation
```

## 4. Current Apply Path

Current simplified path:

```text
Neutron API creates / updates aria_acl objects
  |
neutron-aria-agent periodic full-resync
  |
read all local host ports
  |
read all aria_acl objects
  |
build full-host snapshot
  |
PUT /api/v1/neutron/snapshot
  |
Rust apply_lock
  |
for each affected port:
  attach / update
  purge existing neutron ACL
  translate ACL
  add groups one by one
  add policies one by one
  update runtime status
  |
WAL commit
  |
Python polls status and reports heartbeat
```

Current risk points:

- One port ACL change becomes a full-host snapshot.
- `request_timeout=3s` is shorter than large ACL apply.
- Timeout is mixed with apply failure semantics.
- Pending generation may lead to generation bump and repeated submit.
- ACL reconcile uses purge plus rebuild instead of diff apply.
- Status convergence checks generation/hash/managed ports, but not enough
  per-domain applied count detail.

## 5. Target Apply Path

Target optimized path:

```text
Neutron aria_acl change
  |
RPC event / targeted poll
  |
agent computes affected port(s)
  |
if one local port and revision safe:
  build port-scoped snapshot
else:
  schedule debounced full-resync
  |
PUT scoped/full snapshot
  |
Rust returns accepted generation/hash quickly
  |
Rust background apply under apply_lock
  |
Python polls status without resubmitting same desired state
  |
status converged:
  report ready/enforce
status timeout but pending:
  report applying or degraded-after-deadline according to policy
```

## 6. Workstream A: Observability And Profiling First

Before changing algorithms, make the slow path measurable.

### 6.1 Python Timing Logs

Add structured timing logs to `neutron-aria-agent`.

Required fields:

```text
host
sync_mode
generation
desired_hash
snapshot_scope = full_host | port_scoped
snapshot_ports
managed_ports_expected
acl_policy_count
acl_rule_count
acl_binding_count
acl_address_set_count
effective_rule_count
```

Required timing spans:

| Span | Start | End |
| --- | --- | --- |
| capability_ms | before `capabilities()` | after response |
| remote_status_ms | before initial `status()` | after response |
| neutron_port_read_ms | before local port read | after port list |
| acl_source_read_ms | before ACL source read | after payload/index build |
| snapshot_build_ms | before candidate build | after desired hash |
| uds_submit_ms | before UDS PUT | after accepted/response/timeout |
| status_poll_ms | first status poll | converged or timeout |
| heartbeat_report_ms | before status report to Neutron | after report |
| total_full_resync_ms | `full_resync()` entry | return |

Log examples:

```text
acl_resync_profile_start host=... generation=... scope=full_host
acl_resync_profile_counts host=... ports=19 managed=16 rules=200 effective_rules=200
acl_resync_profile_timing host=... generation=... neutron_port_read_ms=...
acl_resync_status_poll host=... generation=... attempt=... status_generation=...
acl_resync_profile_done host=... generation=... total_ms=... converged=true
```

### 6.2 Rust Timing Logs

Add structured logs in `aria-datapath` / Rust `neutron_api`.

Required fields:

```text
generation
desired_hash
scope
requested_ports
affected_ports
rules
groups
policies
queue_wait_ms
```

Required timing spans:

| Span | Meaning |
| --- | --- |
| route_accept_ms | JSON parsed and request accepted. |
| apply_lock_wait_ms | Wait time before acquiring apply lock. |
| preflight_ms | Schema/generation/hash/scope validation. |
| plan_ms | Snapshot plan and affected-port calculation. |
| wal_intent_ms | WAL intent append. |
| attach_ms | Tap attach/update work. |
| acl_translate_ms | Neutron ACL to datapath group/policy plan. |
| acl_purge_ms | Existing Neutron ACL cleanup. |
| acl_group_write_ms | Group CIDR map writes. |
| acl_policy_write_ms | Policy map writes. |
| acl_stats_cleanup_ms | Stats cleanup, if any. |
| wal_commit_ms | WAL commit append. |
| status_commit_ms | Runtime status update. |
| total_apply_ms | Whole Rust apply duration. |

Log examples:

```text
neutron_snapshot_apply_start generation=281 scope=full_host ports=19 affected_ports=16
neutron_acl_apply_start port_id=... ifname=... groups=200 policies=200
neutron_acl_apply_phase port_id=... phase=group_write elapsed_ms=...
neutron_acl_apply_phase port_id=... phase=policy_write elapsed_ms=...
neutron_snapshot_apply_done generation=281 total_apply_ms=... status=ready
```

### 6.3 Metrics

Expose Prometheus-style metrics:

```text
aria_neutron_snapshot_apply_seconds_bucket{scope, result}
aria_neutron_snapshot_queue_depth
aria_neutron_snapshot_pending_generation
aria_neutron_acl_groups_applied_total
aria_neutron_acl_policies_applied_total
aria_neutron_acl_apply_failures_total{phase, reason}
```

## 7. Workstream B: Duplicate Submit Suppression

The current largest amplification comes from repeated full snapshot submissions
while an older generation is still applying.

### 7.1 Required Rule

If datapath status shows an in-flight apply, Python must not blindly submit a
new full-host snapshot.

In-flight indicators:

```text
pending_generation is not null
authority_state in applying / accepted / recovered_pending_full_resync
applied_generation < accepted_generation
same desired_hash already accepted but not applied
```

### 7.2 Decision Table

| Local desired state | Datapath status | Agent action |
| --- | --- | --- |
| same generation/hash already applied | applied | no-op, commit local pending if needed |
| same desired_hash accepted and pending | pending | wait/poll, do not submit |
| different desired_hash while pending | pending | merge locally and mark dirty; do not submit until current pending finishes or max wait expires |
| pending too old but progressing | status_generation advancing | keep waiting; report applying |
| pending too old and stuck | no progress past deadline | mark degraded, require manual/full recovery, do not spin generations |
| no pending, newer desired state | idle | submit once |

### 7.3 Python Algorithm

Pseudo-flow:

```text
full_resync():
  desired = build_snapshot()
  remote = status()

  if remote.pending_generation:
      if remote.desired_hash == desired.hash:
          wait_for_convergence(remote.pending_generation, desired.hash)
          return

      if pending_age < max_pending_wait:
          record_dirty_desired(desired)
          report status=applying
          return

      mark degraded reason=PENDING_SNAPSHOT_STUCK
      return

  if remote.applied_hash == desired.hash:
      commit local state
      report ready
      return

  submit_snapshot_once(desired)
```

### 7.4 Generation Lease

Add a local generation lease in Python state:

```json
{
  "kind": "snapshot",
  "generation": 281,
  "desired_hash": "...",
  "scope": "full_host",
  "submitted_at": "...",
  "last_status_generation": 277,
  "last_progress_at": "...",
  "submit_attempts": 1
}
```

Rules:

- Same generation/hash may be recovered.
- Same hash must not be resubmitted as a new generation while pending.
- New hash during pending becomes `dirty_desired`, not a new immediate submit.
- A later full-resync may submit only after pending completes, fails hard, or
  is explicitly abandoned by an operator-safe recovery path.

## 8. Workstream C: UDS Async Accepted Contract

The UDS PUT should separate request acceptance from datapath convergence.

### 8.1 Current Problem

Current `PUT /api/v1/neutron/snapshot` waits for apply to complete. If the
client times out, Rust still continues the apply task. Python sees timeout and
may submit another generation.

### 8.2 Target Contract

`PUT /api/v1/neutron/snapshot` should return quickly once Rust has:

1. parsed and validated the request;
2. rejected stale/hash-conflicting input if applicable;
3. recorded accepted generation/hash and WAL intent or durable queue entry;
4. queued the apply task.

Response shape:

```json
{
  "status": "accepted",
  "generation": 281,
  "desired_hash": "sha256:...",
  "scope": "full_host",
  "pending": true,
  "accepted_generation": 281,
  "applied_generation": 280,
  "queue_depth": 1
}
```

Then Python polls:

```text
GET /api/v1/neutron/status
```

until:

```text
applied_generation >= generation
applied_desired_hash == desired_hash
pending_generation is null
port_statuses contain expected target ports
```

### 8.3 Backward Compatibility

Keep current synchronous behavior behind a compatibility switch for old smoke
scripts:

```ini
[aria]
snapshot_submit_mode = async_accepted | synchronous
```

Product default should become:

```ini
snapshot_submit_mode = async_accepted
```

### 8.4 Timeout Semantics

After this change:

- UDS request timeout means "submit request outcome unknown".
- It does not mean datapath apply failed.
- Python must read `/status` before deciding retry.
- Retry with same generation/hash is idempotent.
- Retry with different hash while old generation is pending must be delayed or
  merged, not blindly submitted.

## 9. Workstream D: Port-Scoped And Incremental Apply

Full-host snapshot should not be the normal path for a single port ACL change.

### 9.1 Enablement Path

Use the existing P3 work as the base:

```ini
[neutron]
rpc_events_enabled = true
incremental_rpc_enabled = true
```

Safe cases for port-scoped apply:

- exactly one local `port.update`;
- revision is newer and trustworthy;
- binding host is local;
- ACL object revision can be associated with this port;
- no event overflow;
- no network-wide ambiguity.

Fallback cases:

- multiple ports in event batch;
- network binding change affects many local ports;
- missing or stale revision;
- unknown projected state;
- scoped UDS error;
- datapath capability missing;
- status convergence mismatch.

### 9.2 Target Read Path

P3 should avoid reading all ACL objects for one port when possible.

Minimum improvement:

```text
local port update
  |
read target port
  |
read effective ACL for target port
  |
submit PUT /api/v1/neutron/ports/{port_id}/snapshot
```

Longer term:

```text
Neutron Server exposes effective ACL by port
GET /v2.0/aria-acl-effective/{port_id}
```

This avoids full payload scan for every small change.

## 10. Workstream E: Rust ACL Diff Apply

The original ACL reconcile was purge plus rebuild. The 2026-07-08 optimization
replaced the slow per-group/per-policy control-plane path with a Neutron-owned
batch replace path. That is a major improvement, but it is still not full
rule/group-level diff apply.

### 10.1 Current Behavior

For a Neutron-managed ACL port:

```text
translate new ACL
replace_owned_acl(port)
  compute old owned ACL groups/policies
  compute desired owned ACL groups/policies
  delete old owned map entries
  add desired owned map entries
  compact local state once
```

This means that unchanged ports are skipped, and a changed port no longer pays
hundreds of WAL fsyncs. However, adding one rule to a 200-rule policy can still
rewrite that port's full owned ACL set.

### 10.2 Target Behavior

Store the last applied ACL plan per port:

```json
{
  "port_id": "...",
  "ifname": "...",
  "acl_plan_hash": "...",
  "groups": [
    {"name": "...", "cidrs": ["..."]}
  ],
  "policies": [
    {"src_group": "...", "dst_group": "...", "proto": 1, "direction": 1}
  ]
}
```

Compute diff:

```text
groups_to_add
groups_to_update
groups_to_delete
policies_to_add
policies_to_update
policies_to_delete
```

Apply order:

1. Add new groups.
2. Add new policies that reference existing or newly added groups.
3. Delete old policies no longer needed.
4. Delete old groups no longer referenced.
5. Commit new plan hash.

This preserves traffic behavior during incremental changes and avoids dropping
old rules before new rules exist.

### 10.3 No-Op Detection

If translated ACL plan hash equals last applied plan hash:

```text
skip purge
skip group writes
skip policy writes
update status only if needed
```

This is critical for periodic full-resync, because most full-resync cycles
should become no-op at datapath level.

### 10.4 Required Tests

| Test | Expected |
| --- | --- |
| same ACL plan | no eBPF mutation |
| add one rule to 100-rule policy | only one group/policy delta is written |
| delete one rule | only target policy/group is removed when unreferenced |
| reorder rules without semantic change | no mutation if canonical plan hash is same |
| failed add | old committed plan remains active |
| failed delete | old committed plan remains active or status degraded without false ready |

## 11. Workstream F: Shadow Generation / Bundle-Like Commit

This is the deeper optimization and should follow observability, duplicate
suppression, async accepted, port-scoped apply, and diff apply.

Goal:

```text
packets observe old ACL generation
  or
packets observe new ACL generation
never an in-between partial generation
```

### 11.1 Option A: Active Generation In Policy Key

Extend datapath policy lookup so policy keys include generation or bank:

```text
active_acl_generation[port_id] = N
policy_key = (port_id, generation=N, src_group, dst_group, proto, direction)
```

Apply flow:

1. Write all new groups/policies under generation `N+1`.
2. Validate counts and map write success.
3. Atomically switch `active_acl_generation[port_id]` to `N+1`.
4. Garbage collect generation `N` after grace period.

Pros:

- Strongest packet semantics.
- Closest to bundle-style commit.

Cons:

- Requires eBPF key/schema change.
- More map memory.
- Requires garbage collection and version-aware stats.

### 11.2 Option B: Double-Buffer Per Port

Maintain two banks per port:

```text
active_bank = 0 | 1
write inactive bank
switch active_bank
clear old bank later
```

Pros:

- Simpler mental model.
- Good for bounded per-port ACL count.

Cons:

- Requires map key changes.
- Doubles peak policy/group capacity during update.

### 11.3 Option C: Userspace Staging Only

Build complete plan in userspace first, then write maps in current format.

Pros:

- Low implementation cost.

Cons:

- Does not prevent packets from seeing partial map state while writes are in
  progress.

Recommendation:

- Implement Option C immediately as part of diff apply planning.
- Implement Option A or B only after ACL performance P1/P2 is stable and after
  map capacity impact is measured.

## 12. Workstream G: Limits, Backpressure, And Quota

Performance optimization must be paired with backpressure.

### 12.1 Product Limits

Use two limit profiles.

The first profile is a temporary protection profile for the current
implementation before duplicate-submit suppression, async accepted UDS,
port-scoped incremental apply, and Rust ACL diff apply are complete. It is not
the final product claim.

| Scope | Default hard limit |
| --- | ---: |
| rules per ACL policy | 100 |
| effective ACL rules per port | 100 |
| address-set members per set | 256 |
| ACL rules per project | 1000 |
| effective datapath policies per host | 5000 |

The product target profile must be designed around at least 1000 rules per ACL
policy and per VM port.

| Scope | Candidate raised limit |
| --- | ---: |
| rules per ACL policy | 1000 |
| effective ACL rules per port | 1000 |
| address-set members per set | 2048 |
| ACL rules per project | 10000 |
| effective datapath policies per host | 50000 |

Reaching the product target is an engineering goal, not a config-only change.
The current `POLICY_TABLE` and `RULE_STATS` are 65536 entries, but the IPv4
source/destination LPM tries are 10000 entries each. If every rule creates a
unique per-port CIDR group, LPM entries can become the first host-level ceiling.
Therefore the 1000-rule product profile requires at least one of:

- larger LPM maps, for example 65536 or higher after memory validation;
- shared address-set compilation so common CIDRs are not duplicated per rule and
  per port;
- a more compact group/member representation that avoids one unique LPM entry
  per effective per-port rule when policy semantics allow sharing.

### 12.2 Backpressure

Datapath status should expose:

```text
pending_generation
accepted_generation
applied_generation
queue_depth
current_phase
current_phase_elapsed_ms
pending_age_ms
last_progress_at
```

If queue depth exceeds one full snapshot:

- collapse queued full snapshots to the newest desired hash;
- preserve only latest desired state;
- do not run every intermediate generation.

This is the key behavior needed to avoid 200-rule changes turning into multiple
serialized full-host applies.

## 13. Status Semantics

Avoid false ready.

Port status should include:

```json
{
  "status": "ready",
  "effective_action": "enforce",
  "generation": 281,
  "desired_hash": "...",
  "acl_expected_groups": 200,
  "acl_applied_groups": 200,
  "acl_expected_policies": 200,
  "acl_applied_policies": 200,
  "apply_phase": "complete",
  "apply_elapsed_ms": 12345
}
```

If counts mismatch:

```text
status=degraded
effective_action=bypass or previous_committed
reason=ACL_APPLY_INCOMPLETE
```

For async apply:

```text
status=applying
effective_action=previous_committed
```

Only after generation/hash/counts match may status become:

```text
ready/enforce
```

## 14. Implementation Sequence

### Phase 0: Evidence And Logging

Files:

- `openstack/neutron_aria/neutron_aria/agent/event_loop.py`
- `openstack/neutron_aria/neutron_aria/agent/service.py`
- `openstack/neutron_aria/neutron_aria/agent/uds_client.py`
- `agent/src/neutron_api.rs`

Deliverables:

- Python timing logs.
- Rust apply phase logs.
- Counter fields in status.
- Capacity smoke records per phase.

Exit gate:

- 200-rule test can show where time is spent without reading code manually.

### Phase 1: Duplicate Submit Suppression

Files:

- `openstack/neutron_aria/neutron_aria/agent/event_loop.py`
- `openstack/neutron_aria/neutron_aria/agent/state.py`
- `openstack/neutron_aria/neutron_aria/tests/unit/test_event_loop.py`
- `openstack/neutron_aria/neutron_aria/tests/unit/test_state.py`

Deliverables:

- Pending generation lease.
- Same hash pending wait/no-submit behavior.
- Dirty desired state merge.
- Stuck pending threshold.

Exit gate:

- A 200-rule change produces at most one accepted full snapshot plus status
  polling, not repeated 273/275/277/279/281 style generation churn.

### Phase 2: Async Accepted UDS

Files:

- `agent/src/neutron_api.rs`
- `agent/src/neutron_wal.rs`
- `openstack/neutron_aria/neutron_aria/agent/uds_client.py`
- `docs/neutron-uds-contract.json`
- `docs/openstack-neutron-aria-details/04-uds-contract-security.md`

Deliverables:

- Accepted response.
- Background apply queue.
- Status fields for pending/applying phases.
- Idempotent retry by generation/hash.

Exit gate:

- Python request timeout no longer causes duplicate snapshot submit.

### Phase 3: Port-Scoped Incremental Default Candidate

Files:

- `openstack/neutron_aria/neutron_aria/agent/service.py`
- `openstack/neutron_aria/neutron_aria/agent/event_merge.py`
- `openstack/neutron_aria/neutron_aria/agent/inventory.py`
- `agent/src/neutron_api.rs`

Deliverables:

- Safe single-port ACL change uses `PUT /api/v1/neutron/ports/{port_id}/snapshot`.
- Full-host full-resync remains startup/recovery path.
- Production config canary for `incremental_rpc_enabled=true`.

Exit gate:

- One-port ACL rule add/delete no longer logs `snapshot_ports=19` for normal
  operation.

### Phase 4: Rust ACL Diff Apply

Files:

- `agent/src/neutron_api.rs`
- `agent/src/control_plane.rs`
- state serialization files that persist last applied ACL plan
- Rust unit tests around ACL plan diff

Deliverables:

- Last applied ACL plan per port.
- Canonical ACL plan hash.
- Add/update/delete diff operations.
- No-op detection for periodic full-resync.

Exit gate:

- Adding one ACL rule to an existing 100-rule policy writes only the delta.

### Phase 5: Shadow Generation / Bundle-Like Commit

Files:

- eBPF policy key/value definitions.
- map access helpers.
- `agent/src/control_plane.rs`
- runtime status/stats exporters.

Deliverables:

- active ACL generation or bank per port.
- inactive generation write.
- atomic active generation switch.
- old generation garbage collection.

Exit gate:

- Fault injection during ACL map write proves packets see old committed state
  until final activation, not a partial new policy set.

## 15. Test Plan

### 15.1 Unit Tests

Python:

- same pending hash waits instead of resubmit;
- different desired hash while pending is merged and delayed;
- stuck pending becomes degraded without generation spin;
- async accepted response is handled as pending/applying;
- request timeout is followed by status read before retry.

Rust:

- async accepted records pending generation before apply;
- duplicate same generation/hash is idempotent;
- different hash for same generation is rejected;
- ACL plan diff add/delete/no-op cases;
- apply phase status reports expected/applied counts;
- shadow generation switch, when implemented.

### 15.2 Smoke Tests

Add smoke:

```text
deploy/kolla/smoke/neutron_aria_acl_delivery_perf_smoke.sh
```

Required cases:

| Case | Expected |
| --- | --- |
| 100 rules | one accepted generation, ready, no duplicate submit |
| 200 rules | no generation spin, status shows applying then ready |
| add one rule after 100 | port-scoped or diff path writes only delta |
| delete one rule after 100 | only delta removed, traffic recovers if matching rule removed |
| client timeout injection | Python reads status and does not duplicate submit |
| datapath restart mid-apply | WAL recovery reports recovered/degraded without false ready |

### 15.3 Capacity Gates

Gate targets after Phase 1/2:

| Rules | Target |
| ---: | --- |
| 100 | less than 15 s end-to-end |
| 200 | less than 45 s end-to-end, no generation churn |
| 1000 | no duplicate generation churn; may remain lab-only until Phase 3/4 |

Gate targets after Phase 3/4:

| Operation | Target |
| --- | --- |
| add one rule to existing 100-rule policy | less than 5 s |
| delete one rule from existing 100-rule policy | less than 5 s |
| 200-rule initial apply | less than 30 s |
| 1000-rule initial apply | less than 90 s |
| add one rule to existing 1000-rule policy | less than 5 s |
| delete one rule from existing 1000-rule policy | less than 5 s |

Lab-only stress:

| Rules | Purpose |
| ---: | --- |
| 1000 | product target proof |
| 5000 | lab ceiling exploration and host-level map-capacity validation |

## 16. Rollout Plan

| Stage | Default | Notes |
| --- | --- | --- |
| Logging | on | Low risk; should be merged first. |
| Duplicate suppression | on | Safety improvement; should not require feature flag. |
| Async accepted | config-gated then default | Start canary on one host. |
| Port-scoped incremental | config-gated | Keep full-resync fallback. |
| Diff apply | on after tests | Must preserve rollback and WAL behavior. |
| Shadow generation | later phase | Requires eBPF schema change and CI build. |

Rollback:

- Disable `incremental_rpc_enabled`.
- Disable async accepted if needed and return to synchronous UDS behavior.
- Keep full-resync available.
- Keep existing ACL quota limits until performance gates pass.

## 17. Acceptance Criteria

The optimization is accepted only when all of the following are true:

- 200-rule test no longer creates multiple generation bumps for the same
  desired state.
- `/api/v1/neutron/status` exposes pending/applying/ready phases clearly.
- Python logs show one submit plus polling, not repeated full snapshot submit.
- Rust logs show per-phase apply cost.
- Port status cannot report `ready/enforce` if expected/applied ACL counts do
  not match.
- Cleanup returns datapath policy/group count to zero and VM connectivity
  recovers.
- Full-resync recovery remains available and passes rollback smoke.
