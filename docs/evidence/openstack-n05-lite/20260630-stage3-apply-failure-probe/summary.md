# Stage-Three N3 Apply-Failure Probe

Date: 2026-06-30
Target: compute-1.example.test

## Purpose

Validate a representative ACL apply failure without adding new product
features. The probe used the existing datapath fault-injection hook
`neutron.acl.after_policy_write` with `return_error`, then verified that the
fault did not falsely report the target ACL as ready, did not enforce a partial
target ACL, and could recover through a second full-resync plus rollback.

## Preconditions

- Hardened UDS config was active before the probe:
  - socket mode: `0660`
  - peercred enforcement: enabled
  - allowed uid/gid: `42435`
- Test VM reachability was healthy before the probe:
  - target IP: `192.0.2.28`
  - target port: `39adf570-1acb-4e81-9215-96744a6bf627`
  - target tap: `tap39adf570-1a`
- Datapath status before the probe:
  - generation: 115
  - managed_count: 0
  - pending_generation: null
  - wal_status: `replayed_with_errors`
  - wal_replay_failures: 219

The pre-existing `wal_replay_failures=219` is historical residue from earlier
restart/replay testing. This probe treated it as the per-run baseline and
required no increase.

## Fault Injection

The probe committed the current live datapath container into a temporary test
image and ran the existing Kolla smoke entrypoint with:

- `FAULT_POINTS=neutron.acl.after_policy_write`
- `FAULT_ACTION=return_error`
- `BUILD_DATAPATH_IMAGE=false`
- `REQUIRE_NO_ACTIVE_INSTANCES=false`

The first full-resync intentionally failed while submitting snapshot generation
117. The datapath status after the injected failure was:

- generation: 116
- accepted_generation: 117
- applied_generation: 116
- pending_generation: 117
- authority_state: `partial`
- wal_status: `commit_written`
- wal_replay_failures: 219

The target port reported:

- status: `error`
- reason: `acl_apply_failed:fault injection triggered at neutron.acl.after_policy_write`
- effective_action: null

Other host compute ports that had no ACL binding were present as
`not_requested` with `effective_action=bypass`. No port domain reported
`effective_action=enforce` during the fault state.

## Recovery

After the fault assertion:

- the target VM remained reachable while the ACL apply was partial;
- the second full-resync was allowed to start from the expected partial managed
  state;
- snapshot generation 119 applied successfully;
- the target port reached ACL `ready` with `effective_action=enforce`;
- ICMP from the probe host to the target VM was blocked while the ACL was ready;
- rollback deleted all five managed ports;
- post-rollback ping recovered.

Post-recovery datapath status:

- generation: 119
- accepted_generation: 119
- applied_generation: 119
- pending_generation: null
- authority_state: `ready`
- wal_status: `commit_written`
- managed_count: 0
- wal_replay_failures: 219

## Restore Check

After the smoke, the wrapper restored the datapath from a committed copy of the
pre-probe live container and the original Kolla config.

Final checked state:

- generation: 120
- authority_state: `ready`
- managed_count: 0
- pending_generation: null
- socket: `/run/aria/aria-agent.sock`
- socket mode/group: `srw-rw---- root:42435`
- peercred enforcement: enabled in config
- allowed peer access through the neutron agent container succeeded
- direct root curl to the UDS failed with an empty reply, as expected under
  peercred enforcement

## Smoke Script Fixes

The first run exposed two smoke-script assumptions that were too strict for a
real full-resync fault:

- Fault state can be `partial + commit_written`, not only
  `wal_intent_without_commit + intent_without_commit`.
- Non-target ports can be managed as `not_requested/bypass` before the target
  ACL apply fails.

The smoke contract was corrected to assert the safety properties instead:

- target port must not be left managed or enforced;
- target port must report `error` or `degraded`;
- no domain may report `effective_action=enforce` during the fault state;
- WAL replay failures must not increase from the per-run baseline;
- the recovery retry may explicitly allow the expected partial managed state.

## Disposition

`pass`.

The apply-failure path does not falsely report the target ACL as ready, does not
enforce a partial target ACL, preserves reachability while partial, recovers on
a retry, proves enforcement when ready, and rolls back to a clean datapath
state.
