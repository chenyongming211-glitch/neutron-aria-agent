# P5 Two-Node Current-Candidate Evidence

Date: 2026-08-11

Status: partial pass. The two available computes passed current-candidate
rollout, rollback, readiness, ACL traffic, UDS hardening, and production-agent
RPC lifecycle checks. The third target compute was unavailable at the host
and agent layers, so this evidence does not close the three-node P5 gate.

## Candidate Identity

The source record is branch `v0.9-neutron-agent` at
`baa37f4c11bc4bdc4c8cb554d25bf754f01c0779`. The deployed components were
verified independently on both available computes:

| Component | SHA-256 |
| --- | --- |
| Rust `aria-agent` | `ba9cdb3f5b01390533c1f7868027b1a8dd994df930e584598e9145e067202c15` |
| eBPF object | `140ec66ae9d8f40db2804b3f17538a1ee967e54b9ce70839faf0aa116d2ea1cd` |
| Python `main.py` | `30b2957f3370d8ec956d1d2093187fffb27efab51fb885f9ceb8b0df157770b2` |
| Python 2.7 egg | `07d22cd62bb490e5f0fa4222b07043fd019c1a32b92842f589eebdb6e331fa3f` |

The exact-head GitHub workflow `31450147544` passed the fast contracts,
Neutron DB contracts, clean agent install, Rust behavior, and Rust build lanes.

## Available-Compute Results

| Check | Compute A | Compute C |
| --- | --- | --- |
| Candidate component hashes | passed | passed |
| Composite readiness | passed | passed |
| UDS permissions and peer credentials | passed | passed |
| Real RPC-triggered ACL traffic | previously accepted in this P5 run | passed |
| Final traffic canary | passed | passed; 30 replies, zero loss |
| Actual old-version rollback and RC restore | P4 accepted | passed |
| Active authentication-header log scan | passed | passed; zero matching files |
| OVS and OVS-agent identity unchanged | passed | passed |

Compute C was rolled from its previous deployment to the same Rust, eBPF, and
Python hashes as Compute A. It then passed a real ACL policy/rule/binding
lifecycle and an actual old-version rollback followed by restoration to the
candidate. Aria did not restart or modify OVS or the Neutron OVS agent.

## Production-Agent RPC Regression

The RPC checks used the long-running agents with their deployed configuration:

```text
full_resync_enabled = true
rpc_events_enabled = true
incremental_rpc_enabled = false
event_merge_interval = 0.2
```

No temporary agent was started and no global managed-port rollback helper was
used. A real active port on Compute C with no ACL binding was selected as the
bounded lifecycle carrier.

### Fanout and foreign-host filtering

A `port.update` carrying the real Compute C binding was sent through the
deployed RabbitMQ path.

- Both available computes drained exactly one port update.
- Compute A treated the update as foreign: its 23 managed ports and generation
  stayed unchanged, and it did not run a full resync for the foreign port.
- Compute C treated the update as local and completed a full resync while its
  14 managed ports remained unchanged.
- OVS and OVS-agent process/container identities were unchanged on both nodes.

### Migration-source cleanup and recovery

The same unbound test port was announced as moving from Compute C to Compute A,
then immediately announced with its real Compute C binding again.

- Compute C logged `reason=migration_source_cleanup` and removed exactly the
  selected port, changing its managed count from 14 to 13.
- Compute A changed no managed port while processing the event.
- The restoring event re-added exactly the selected port on Compute C, changed
  the accepted generation from 3249 to 3251, and completed a full resync in
  about two seconds.
- Compute A again filtered the foreign event without a managed-port delta.
- OVS and OVS-agent identities remained unchanged during cleanup and recovery.

An earlier recovery observation was intentionally rejected as event-recovery
evidence because the 60-second periodic full resync restored the port before
the explicit restoring event arrived. The bounded rerun kept cleanup and
recovery in one interval and demonstrated the intended event-driven path.

## Remaining P5 Blocker

Compute B was not available for candidate rollout or validation. Its Aria ACL
agent and Neutron OVS agent were both reported dead by the control plane, and
the host did not provide a usable SSH session. No reboot was attempted.

P5 remains open until Compute B is healthy and the same candidate hashes pass:

1. rolling deployment and rollback;
2. readiness, UDS hardening, and traffic canary;
3. real ACL lifecycle and RPC fanout/foreign-host behavior;
4. lifecycle cleanup and final no-orphan checks.

This partial evidence must not be described as three-node acceptance.
