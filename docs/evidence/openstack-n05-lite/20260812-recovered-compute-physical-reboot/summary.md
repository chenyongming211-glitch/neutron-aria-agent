# Recovered Compute Physical Reboot

Date: 2026-08-12

## Scope

This evidence validates automatic ACL recovery after a physical reboot of the
recovered compute. The test specifically targets the boot-order race where the
Neutron snapshot arrives before the VM tap has a usable ifindex.

No Aria recovery command, WAL cleanup, datapath restart, OVS restart, or
Neutron OVS agent restart was performed after the reboot was scheduled.

## Candidate Identity

- Source commit: `0d70dacc133e58cf0c74abbc3f4760082d8a554a`
- GitHub Actions validation run: `31566580372`
- GitHub Actions artifact run: `31567038301`
- `aria-agent` SHA-256:
  `924678564bc08cea1b7d5a8001042df414879c35c7cfbd62d78b427d867a22da`
- `libebpf_firewall.so` SHA-256:
  `6488da9614a7ce81d0d2ae6271ffd0108d084a2115c2d37da02f6dcda13ab50f`
- Datapath image: `aria-datapath:rc-0d70dac`

The running container image ID and all three deployed file hashes matched the
candidate manifest before and after reboot.

## Observed Recovery

The reboot reproduced the intended ordering:

1. Aria containers started while the managed VM tap was absent.
2. Two full-resync attempts observed the committed port without a ready
   ifindex.
3. Each attempt wrote an `inventory_unavailable` intent with empty affected
   port and domain sets.
4. Recovery returned to the last committed baseline and requested another full
   resync; it did not request operator action.
5. The tap returned with its expected identity and ifindex.
6. The next full resync updated the committed port with zero detaches and
   completed at generation 5841.

The final runtime state was:

```text
transaction_state=classified
overall_readiness=ready
required_action=none
authority_state=ready
wal_status=commit_written
```

No `neutron_acl_purge_failed`, partial detach, operator-required state, or
generation false advance occurred in the reboot window.

## Datapath And Control-Plane Checks

- `/run/aria` returned as `0770` and the UDS as `0660` with the configured peer
  group.
- The Neutron Aria agent heartbeat returned to alive.
- The effective port projection returned `ready/enforce` and was not stale.
- Both TC ingress and TC egress filters were attached to the restored tap.
- Five denied ICMP probes received no reply after terminal readiness.
- The datapath, Python agent, and Neutron OVS agent containers each reported a
  zero restart count in the new boot.

## Infrastructure Observation

The host management network took approximately eight minutes from scheduling
the reboot to becoming reachable from the operator workstation. During part of
that interval the host did not answer ARP from the other computes. This delayed
host recovery is outside Aria and should be tracked as a compute boot/network
issue. Aria recovered automatically once the host, containers, and VM tap were
available.

The compute service remained administratively disabled/down after the reboot,
matching its pre-existing recovery state. This did not prevent the retained
test VM and its ACL datapath from recovering, but compute-service admission is
a separate open infrastructure action.

## Result

Result: **PASS** for the Aria physical-reboot ACL recovery gate.

The previous Aria failure mode is resolved for the reproduced condition:
temporary boot-time ifindex absence no longer becomes detach/purge or permanent
operator recovery. The separate slow host-network recovery remains open and is
not claimed as fixed by this change.
