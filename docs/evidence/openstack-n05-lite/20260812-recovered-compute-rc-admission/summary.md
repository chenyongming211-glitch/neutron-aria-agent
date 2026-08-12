# Recovered Compute RC Admission

Date: 2026-08-12

## Scope

This evidence admits the recovered compute into the current release-candidate
baseline. It covers the two reboot-specific failures found before admission:

- `/run/aria` ownership and mode were lost after host reboot.
- A committed managed port whose tap was absent during datapath startup was
  classified as requiring operator intervention instead of automatic resync.

The test did not restart or modify OVS or the Neutron OVS agent.

## Candidate Identity

- Source commit: `b9bf03adb0050d41b34af4c58db8a171abc1e95e`
- GitHub Actions validation run: `31563212779`
- GitHub Actions artifact run: `31563536962`
- `aria-agent` SHA-256:
  `a40f0dd4c0a60f89353cb9ff2794dbf1f59bf338460d1041ba82b2e6ba338826`
- `libebpf_firewall.so` SHA-256:
  `6488da9614a7ce81d0d2ae6271ffd0108d084a2115c2d37da02f6dcda13ab50f`
- Datapath image: `aria-datapath:rc-b9bf03a`

Both CI runs completed successfully. The deployed binary hashes match the
manifest from the artifact run.

## Persistent UDS Profile

The recovered compute now has a persistent tmpfiles rule for `/run/aria`:

```text
d /run/aria 0770 root aria-neutron -
```

The runtime directory is `0770` and the UDS is `0660`, both owned by the
configured Aria peer group. An authorized service identity can read status and
readiness. A host-root request outside the allow-list is rejected, confirming
that peer credential enforcement remains active.

## Delayed Tap Recovery

The test retained the Neutron binding while reproducing compute reboot
ordering:

1. Confirm the test port is `ready/enforce` and blocks ICMP.
2. Pause Nova lifecycle event consumption for the recovered compute.
3. Stop only the test guest domain and wait for its tap to disappear.
4. Restart only the Aria datapath.
5. Confirm `degraded/full_resync` with `runtime_rebuild_required`.
6. Start the guest domain and allow the tap to return.
7. Wait for automatic full resync without operator recovery commands.
8. Restore Nova lifecycle event consumption and verify final state.

Observed state transitions:

```text
classified/degraded/full_resync
classified/ready/none
```

The port automatically converged in 14.4 seconds. Its generation advanced once,
both TC ingress and TC egress programs were attached to the new ifindex, and the
runtime and Neutron status returned to `ready/enforce`.

## Forwarding Semantics

Recovery remains fail-open while status is explicitly
`degraded/full_resync`. This preserves the product rule that an Aria failure
must not interrupt original OVS forwarding. Eighteen ICMP replies were observed
inside this declared bypass window. After `ready/enforce`, no additional reply
was observed, and an independent five-packet verification remained fully
blocked.

This is not reported as continuous ACL enforcement during recovery. The product
contract is:

- recovery window: visible degraded/bypass state; OVS forwarding preserved;
- terminal state: ready/enforce; ACL traffic decision active;
- never report ready before TC attachment and policy activation complete.

## Independent Final Verification

The final read-only verification passed all of the following:

- runtime status is `ready/none`;
- ACL domain is `ready/enforce`;
- `/readyz` reports `overall_readiness=ready`;
- UDS peer credentials and filesystem modes are enforced;
- deployed binary hashes match the CI artifact manifest;
- TC ingress and egress attachments are present;
- the test VM remains active and its denied ICMP remains blocked;
- OVS and the Neutron OVS agent retained their pre-test identities and restart
  counts.

## Admission Decision

Result: **PASS**.

The recovered compute is eligible to enter its own 24-hour low-disturbance soak.
The existing soak on the other computes remains separate; their elapsed time is
not reset or combined with this admission evidence.
