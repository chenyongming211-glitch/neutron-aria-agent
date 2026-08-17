# Kolla eBPF Runtime Safe Upgrade And Rollback Design

## Status

Approved implementation baseline for the v0.9 Neutron integration. This
design extends the existing Kolla RC installer. It does not add a daemon,
change the datapath API, or introduce an alternative deployment controller.

## Problem

`install_aria_datapath_rc_image.sh` currently verifies the candidate image,
keeps the previous container as a rollback point, replaces `aria_datapath`,
and waits for readiness. That path is correct when the candidate can adopt the
existing pinned runtime.

When the candidate eBPF program hash or runtime schema differs, live TC links
and pinned maps belong to the old runtime. Starting the candidate against those
objects is intentionally rejected by the Rust runtime. Renaming the old
container back is also insufficient after a new runtime has created live
objects. Upgrade and rollback therefore need the same explicit quiesce and
detach boundary.

## Non-Negotiable Constraints

- Never restart, stop, reconfigure, or otherwise mutate OVS or the Neutron OVS
  agent.
- Stop the Python writer before any managed-port detach so full resync and RPC
  events cannot race the upgrade.
- Detach only ports reported by the authenticated Neutron UDS status API.
- Require `managed_ports=0` before replacing a runtime with a different hash.
- Reattach only from a fresh authoritative Neutron full resync.
- Preserve the previous container and exact image identity until final
  verification succeeds.
- A failed recovery must remain operator-visible and must not silently resume
  Python writes.
- Keep the implementation inside the current bounded RC installer and its
  tests. Do not add a long-running upgrade service.

## Selected Approach

Enhance `install_aria_datapath_rc_image.sh` with one hash-aware lifecycle.
The existing `install`, `check`, and `rollback` operator interface remains.

The installer compares the candidate eBPF file hash with the active container
file hash before mutation:

- Same hash: retain the current fast replacement path.
- Different hash and no managed ports: replace directly.
- Different hash and managed ports exist: run the safe migration path.
- Status, identity, or peer authentication cannot be established: fail before
  replacing the datapath.

A schema-only product change also changes the candidate binary hash. An
explicit force-migration switch may be used for recovery testing, but it is not
the normal operator path.

Always detaching on every image update was rejected because it creates
unnecessary ACL churn for packaging-only changes. A separate orchestrator was
rejected as overdevelopment for v0.9.

## Upgrade State Machine

```text
preflight
  -> quiesce_writer (only when migration is required)
  -> detach_old_runtime
  -> verify_zero_managed_ports
  -> preserve_old_container
  -> start_candidate
  -> resume_writer
  -> full_resync_converge
  -> verify_candidate
  -> committed
```

### Preflight

Before any mutation, record:

- active and candidate image IDs;
- active and candidate userspace/eBPF hashes;
- Python agent image, UID, GID, running identity, and start time;
- current managed port IDs and transaction status;
- `ovs-vswitchd` PID plus OVS-agent container ID and start time;
- state mount, UDS socket, and release state paths.

Candidate image identity and healthcheck validation stay ahead of mutation.
An existing pending release or incomplete upgrade state blocks a new install.

### Quiesce And Exact Detach

Stop only `neutron_aria_agent`. Use its active image in a short-lived container
with the same UID/GID and only the UDS socket mount required by `LocalClient`.
The helper performs a fresh capabilities/status handshake, deletes each exact
managed port through the supported UDS delete route, waits for every delete to
settle, and then requires an empty managed-port list.

This ordering removes the service-loop race while preserving UDS peercred.
The helper must not contact Neutron, OVS, or Docker from inside the container.

### Candidate Start And Reattach

After `managed_ports=0`, stop and rename the old datapath container, create the
candidate with the Kolla configuration, and start it. A hash-changing upgrade
does not let the candidate migrate the old release in place: after the old
datapath stops, the installer copies its quiesced state directory to a
candidate-specific sibling and renames the dormant Aria shared pin directory
to a release-specific backup. The candidate mounts the copied state and creates
fresh shared pins. Then start `neutron_aria_agent`. Its configured
startup/full-resync path is the only source of reattachment.

Final convergence requires:

- authenticated `/readyz` reports `overall_readiness=ready`;
- `pending_generation` is empty;
- `accepted_generation == applied_generation`;
- both Aria containers are Docker `healthy`;
- running image and file hashes equal the requested candidate identities;
- OVS and OVS-agent identities are unchanged.

The post-upgrade managed-port set is authoritative current Neutron state. It is
not required to equal the preflight set because ports may legitimately change
while the Python agent is stopped.

## Hash-Aware Rollback

Rollback uses the same safety boundary in reverse:

```text
stop Python writer
  -> detach candidate-managed ports
  -> verify zero managed ports
  -> stop candidate and quarantine candidate shared pins
  -> restore old shared-pin name (old state was never modified)
  -> remove candidate container
  -> restore previous container
  -> start Python writer
  -> fresh full resync
  -> verify readiness, generation, health, identities
```

Rollback must not merely rename the old container over live candidate pins.
The old container retains its original state mount, so it never needs to parse
or downgrade a future runtime schema. Candidate state and quarantined pins are
removed only after the old runtime is ready again. The previous release state
is retired only after all rollback checks pass.

## Failure Semantics

- Failure before datapath mutation: keep the old datapath running; restart the
  Python agent if it was stopped and no detach occurred.
- Failure after detach but before candidate readiness: attempt the hash-aware
  rollback automatically.
- Candidate verification failure: quiesce and detach candidate runtime before
  restoring the old runtime.
- Automatic rollback failure: retain the phase/state evidence, keep the Python
  writer stopped, and report exact manual recovery instructions. Never report
  success or resume uncontrolled writes.
- Any OVS or OVS-agent identity change fails verification. The installer has
  no command path that restarts either service.

## Durable State

Extend the root-owned mode-0600 release state with the lifecycle phase,
whether runtime migration was required, active/candidate hashes, Python agent
identity, preflight managed-port IDs, original/candidate state paths, old pin
backup path, candidate pin quarantine path, and rollback identity. State
updates use pending-file plus atomic rename. A host-local `flock` plus retained
pending state prevents overlapping lifecycle mutations.

No ACL rule payload is stored in release state. Neutron remains the authority
for reconstruction.

## Test Boundary

Add executable tests with fake `docker`, `curl`, `pgrep`, and UDS helper
responses. Required cases are:

1. Same hash skips writer stop and managed-port detach.
2. Hash mismatch performs stop, exact detach, zero-port barrier, switch,
   restart, convergence, and verification in that order.
3. A detach failure prevents candidate start.
4. A candidate start or readiness failure performs hash-aware rollback.
5. A rollback failure retains state and leaves the Python writer stopped.
6. Rollback itself detaches candidate-managed ports before restoring the old
   container.
7. Unknown status or identity fails closed before mutation.
8. No command invokes an OVS or OVS-agent restart/stop/reconfigure action.
9. Shell syntax, release-governance, bundle-content, and mode checks remain
   green.

Privileged field validation uses a temporary managed port on one test compute,
then a three-node rolling RC test. It records exact image and file hashes,
readiness/generation convergence, rollback, cleanup, and unchanged OVS
identities.
