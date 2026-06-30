# N0.5 Discovery Evidence

Host: `ostack4.bj159.net`

Generated at: `2026-06-30T03:28:01Z`

This is a read-only discovery record. It does not enable ACL, QoS,
Mirror, RPC event consumption, or datapath mutation.

| Fact | Expected | Command | Actual | Evidence | Disposition |
| --- | --- | --- | --- | --- | --- |
| OS and kernel | Record host OS and kernel | `collect_versions` | exit=0 | `os-kernel.txt` | pass |
| Neutron ML2 mechanism drivers | Record OVS/ML2 mechanism driver state | `collect_ml2_config` | exit=0 | `ml2-config.txt` | pass |
| Neutron agents | Record target Neutron agents and Aria agent heartbeat rows | `neutron_agent_list` | exit=0 | `neutron-agents.txt` | pass |
| Aria ACL agent heartbeat | At least one Aria ACL agent heartbeat is visible | `check_aria_agent_heartbeat` | exit=0 | `aria-agent-heartbeat.txt` | pass |
| Neutron extensions | Record Neutron extension set | `neutron_extension_list` | exit=0 | `neutron-extensions.txt` | pass |
| aria-acl extension | aria-acl extension is visible when production ACL gate is enabled | `check_aria_acl_extension` | exit=0 | `aria-acl-extension.txt` | pass |
| QoS extension | Record QoS support disposition; unsupported is acceptable for ACL MVP | `check_qos_extension` | exit=1 | `qos-extension.txt` | unsupported |
| OVS topology | OVS bridge and br-int ports are visible | `collect_ovs_topology` | exit=0 | `ovs-topology.txt` | pass |
| Tap and OVS interface inventory | Tap naming and OVS external_ids are recorded | `collect_tap_inventory` | exit=0 | `tap-inventory.txt` | pass |
| No qvo/qvb hybrid plug | Current MVP expects no qvo/qvb hybrid-plug path | `check_no_hybrid_plug` | exit=0 | `hybrid-plug.txt` | pass |
| OVS iface-id external_ids | OVS interfaces expose external_ids:iface-id | `check_ovs_iface_id` | exit=2 | `ovs-iface-id.txt` | not_applicable |
| BTF and bpffs | BTF and bpffs capability are known | `collect_bpf_capability` | exit=0 | `bpf.txt` | pass |
| tc capability | tc availability is known for QoS disposition | `collect_tc_capability` | exit=127 | `tc.txt` | unsupported |
| XDP tap status | Record current tap XDP status without attaching anything | `collect_xdp_status` | exit=2 | `xdp-status.txt` | not_applicable |
| /run/aria and socket permissions | Record UDS directory/socket owner and mode | `collect_run_aria_permissions` | exit=0 | `run-aria.txt` | pass |
| Container state and mounts | Record Kolla containers and relevant mounts | `collect_container_state` | exit=0 | `containers.txt` | pass |
| UDS capabilities/status | Record local datapath UDS capabilities/status | `collect_neutron_aria_agent_status` | exit=0 | `uds-status.txt` | pass |
| Neutron port source for host | Record host-bound Neutron ports and compute port count | `collect_neutron_port_source` | exit=0 | `neutron-port-source.txt` | pass |
| aria_acl API read counts | Record production ACL API read path counts and status fields | `collect_aria_acl_api` | exit=0 | `aria-acl-api.txt` | pass |

## Result

- pass: 15
- non-pass: 4
- fail: 0

Non-pass entries must be copied back into
`docs/openstack-target-env-discovery.md` with their disposition.
