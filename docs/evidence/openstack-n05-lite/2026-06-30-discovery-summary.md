# 2026-06-30 N0.5 Discovery Summary

Status: read-only target-environment discovery evidence; G4 discovery accepted.
Three-node reversible UDS hardening evidence is tracked separately in
`docs/evidence/openstack-n05-lite/2026-06-30-uds-hardening-summary.md`.

Evidence directories:

| Host | Evidence Path | Result |
| --- | --- | --- |
| `ostack2.bj159.net` | `docs/evidence/openstack-n05-lite/20260630114142-ostack2.bj159.net/` | 18 pass, 3 unsupported, 0 fail |
| `ostack3.bj159.net` | `docs/evidence/openstack-n05-lite/20260630114142-ostack3.bj159.net/` | 16 pass, 3 unsupported, 2 not_applicable, 0 fail |
| `ostack4.bj159.net` | `docs/evidence/openstack-n05-lite/20260630114142-ostack4.bj159.net/` | 16 pass, 3 unsupported, 2 not_applicable, 0 fail |

G4 acceptance command:

```bash
python ci/check_n05_discovery_evidence.py
```

Result:

```text
G4 N0.5 discovery evidence accepted
hosts=3
hosts_with_compute_iface_id=ostack2.bj159.net
unsupported=9
not_applicable=4
```

## Confirmed Facts

| Area | Result |
| --- | --- |
| OS/kernel | All three hosts run Rocky Linux 8.6 with kernel `4.18.0-553.5.1.el8_10.x86_64`. |
| OpenStack client | `openstack 1.7.1` is present in the target environment. |
| OVS | All three hosts report Open vSwitch `3.3.5` and have `br-int`. |
| ML2 | `ostack2` and `ostack3` neutron-server config reports `type_drivers=vxlan,vlan,flat`, `tenant_network_types=vxlan,vlan,flat`, `mechanism_drivers=openvswitch,linuxbridge,l2population,sriovnicswitch`. `ostack4` is compute/agent-side only; its OVS-agent container config was captured. |
| Tap topology | No `qvo/qvb` hybrid-plug links were found. `ostack2` has local VM tap/OVS interface evidence; `ostack3` and `ostack4` have no local Neutron compute ports at the time of collection, so VM tap `iface-id`/XDP checks are `not_applicable`. |
| Neutron port source | `ostack2`: 8 host ports, 5 compute ports. `ostack3`: 3 host ports, 0 compute ports. `ostack4`: 0 host ports, 0 compute ports. |
| Port class disposition | `ostack2`: 8 normal local vnic ports. `ostack3`: 3 normal local vnic ports. `ostack4`: 0 local ports. No local `direct`, `direct-physical`, `macvtap`, `baremetal`, or `virtio-forwarder` ports were found. |
| BTF/bpffs | `/sys/kernel/btf/vmlinux` is readable and bpffs is mounted on all three hosts. |
| QoS extension | Neutron QoS extension is not visible in the current extension list; disposition is `unsupported` for this stage. |
| Trunk extension | Neutron trunk extension is not visible in the current extension list; disposition is `unsupported` for this stage. |
| `tc` | `tc` command is not available on the hosts; QoS shaping remains `unsupported` or must use an explicitly documented degraded path. |
| `/run/aria` | `/run/aria` exists as `root:UNKNOWN 0770`; `/run/aria/aria-agent.sock` exists as `root:root 0666` during the smoke environment. This is functional for smoke but not the target hardened permission model. |
| UDS | UDS capabilities/status were readable through `neutron_aria_agent` on all three hosts. |
| `aria_acl` API | `aria_acl` extension is visible, API read path works, and `aria_acl_port_statuses` exposes `last_reported_at`, `stale`, and `runtime_status` fields. |
| Agent package consistency | `ostack4` initially had an older agent egg missing `build_aria_acl_client_from_env`; installing the same stage-two agent egg and restarting `neutron_aria_agent` fixed the read-path evidence. |

## Remaining Full-N0.5 Gaps

These are not feature-development tasks, but they still block declaring full
N0.5 complete:

- Hook direction has accepted active traffic evidence for external/host -> VM
  and VM -> external/host. The VM-originated direction uses the temporary CirrOS
  evidence in
  `docs/evidence/openstack-n05-lite/20260630145200-ostack2.bj159.net-cirros-vm-egress-final/`.
  The earlier host-initiated `ACL_DIRECTION=egress` probe remains rejected as an
  invalid proof shape.
- External/host -> VM rollback connectivity is covered by
  `docs/evidence/openstack-n05-lite/2026-06-30-g7-rollback-summary.md`;
  `aria-datapath` stop/restart is also covered there.
- DHCP/metadata/IPv6 disposition has bounded guest evidence in
  `docs/evidence/openstack-n05-lite/20260630155334-ostack2.bj159.net-guest-bypass-probe/`.
  DHCP initial request/lease passed with dnsmasq `DHCPOFFER`, `DHCPREQUEST`, and
  `DHCPACK`; explicit renew is `not_applicable` for the CirrOS image because it
  has no executable `udhcpc`.
- Metadata traffic reached the Neutron metadata namespace proxy from guest
  `10.58.159.40`, but the endpoint returned HTTP 500 because the proxy backend
  Unix socket was missing (`ENOENT`). This is target metadata service degraded,
  not an Aria ACL block.
- IPv6 ND is `not_applicable` for the current target networks: `neutron
  subnet-list` and guest route evidence show only IPv4 CIDRs and no IPv6 subnet.
  Re-test if an IPv6 network is added.
- Peer credential enforcement and UDS audit now have accepted three-node
  reversible hardening evidence. Persistent hardened rollout remains a release
  gate, not a product-feature expansion.
- Active behavior for real trunk, VLAN subport, SR-IOV/direct, and macvtap ports remains untested because the current target hosts did not expose those local port classes.
- The restored baseline `/run/aria` and socket permissions are smoke-functional;
  persistent deployment still needs to enable the hardened `root:neutron-aria
  0770` and `aria-datapath:neutron-aria 0660` model.

## Scope Boundary

This discovery did not enable QoS/Mirror, RabbitMQ event consumption, or new
datapath behavior. It only collected evidence and corrected package consistency
on `ostack4` so all three `neutron_aria_agent` containers run the same
stage-two Python package.
