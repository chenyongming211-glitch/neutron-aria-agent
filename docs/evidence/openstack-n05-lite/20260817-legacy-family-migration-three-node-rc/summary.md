# Legacy ACL Migration And Three-Compute RC Acceptance

Date: 2026-08-17

## Scope

This evidence closes the target-kernel verification for:

- `REVIEW-ACL-116`: legacy family-zero migration authority;
- `REVIEW-TXN-039`: durable family migration before runtime schema publication;
- `REVIEW-OPS-039`: operational pinned-map faults must not become empty success;
- the offline Python dependency packaging defect found while producing the
  field Kolla image.

The rollout changed only `aria_datapath` and `neutron_aria_agent`. It did not
restart or modify OVS, the Neutron OVS agent, Nova, or a physical compute.

## Candidate Identity

- Source commit: `f8ef09a83fc85bbc6fc34257a2ac61410588ecf7`
- GitHub Actions run: `31995871565`
- Stage-two bundle SHA-256:
  `4c9fe240ec64b1fa2c96aaa9fa6724bb379570a2694543797a2c36fbc7b623ec`
- `aria-agent` SHA-256:
  `b0770d542edf9cdf7f201fdbfcac57eeb8feb09d3f1d7172902212d166b508b3`
- `libebpf_firewall.so` SHA-256:
  `ad3bea07f63a6038db486727f4da1d4919032885b74e00af5ca2da79edd28882`
- Offline `netaddr-0.7.19` wheel SHA-256:
  `56b3558bd71f3f6999e4c52e349f38660e54a7a8a9943335f73dfc96883e08ca`
- Maximum reported TC ingress/egress stack path: 480 bytes.

The bundle manifest names the exact source commit. Its egg and nested wheel
paths pass the bundle-root checksum file. All three computes contain the same
Rust, eBPF, and Python dependency hashes.

## Isolated Target-Kernel Gates

The first compute used private veth, network namespace, bpffs, state, and
socket paths before the field rollout:

1. Both TC ingress and TC egress loaded on the target 4.18 kernel.
2. A managed legacy family-zero record migrated to IPv4 only.
3. A standalone legacy family-zero record expanded to IPv4 and IPv6.
4. A deliberately invalid durable migration left the old state and runtime
   schema intact and blocked UDS admission.
5. A wrong pinned-map object produced an operational HTTP 500 error.
6. A genuinely absent optional pin produced the documented empty result.

Cleanup removed the private links, pins, namespace, state, and socket.

## Controlled Status V2 To V3 Rollout

Each compute was processed independently:

1. Save the Kolla Python agent configuration and OVS identities.
2. Disable full resync and RPC event consumption temporarily.
3. Perform the UDS capability handshake.
4. Delete every managed port through the supported UDS route and require the
   managed-port set to reach zero.
5. Install the exact candidate datapath.
6. Restore the original configuration and install the candidate Python agent.
7. Run a full resync and require Status V3 to converge.
8. Run both RC installer checks and compare OVS identities.

The three computes quiesced and restored 23, 2, and 14 managed ports. One
compute had an existing enforced ACL. Its policy and binding identities were
unchanged across the migration and returned to `ready/enforce` at the next
generation.

Final state on all three computes:

- Status schema is 3 and overall readiness is `ready`;
- accepted and applied generations are equal, with no pending generation;
- WAL status is `commit_written` with zero replay failures;
- Neutron heartbeat is alive, ready, non-degraded, and has generation lag 0;
- sync mode is `rpc_full_resync`;
- `incremental_rpc_enabled` remains false.

## ACL And Forwarding Regression

Every compute ran a real temporary Neutron ACL flow on a local VM port:

1. Verify baseline ICMP connectivity.
2. Create a policy, drop rule, and port binding.
3. Submit the full snapshot.
4. Require matching policy and binding identity in port status.
5. Require `ready/enforce` and observe real ICMP blocking.
6. Delete the temporary objects and submit rollback.
7. Require policy removal and connectivity recovery.

All three flows passed. No temporary policy, rule, or binding remained. The
independent OVS canaries had zero packet loss during the controlled image
rollouts, and the OVS process plus Neutron OVS agent identities remained
unchanged.

## Packaging Finding

The first exact-source Python image correctly failed its startup gate because
the field base image contained `netaddr 0.7.18` while the package requires at
least 0.7.19 and the target has no Python 2 package installer or Internet
dependency path. Commit `f8ef09a` fixes delivery rather than weakening the
dependency:

- the bundle carries the pinned universal wheel;
- the wheel hash is checked before image build;
- Python 3 pip installs it offline into the Python 2 site-packages path;
- image build and RC install both execute the real agent entry point;
- nested manifest and checksum paths are valid from the bundle root.

## Result

Result: **PASS**.

`REVIEW-ACL-116`, `REVIEW-TXN-039`, and `REVIEW-OPS-039` now have target-kernel
field evidence tied to an exact CI candidate. The three-compute RC is eligible
for the next release-governance gate. Production delivery should distribute one
prebuilt image or immutable registry digest; the field-local image layers have
different Docker IDs because the legacy build records installation time, even
though all embedded product artifacts are identical.
