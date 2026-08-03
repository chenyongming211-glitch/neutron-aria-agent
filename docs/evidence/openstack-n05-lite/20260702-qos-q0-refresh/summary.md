# 2026-07-02 QoS Q0 Refresh Summary

Status: Q0 evidence refreshed; QoS implementation remains deferred.

Scope: read-only discovery only. This pass did not enable Neutron QoS, did not
change `service_plugins`, did not restart OpenStack services, did not mutate
qdisc state, and did not enable QoS/Mirror datapath behavior.

## Evidence

| Host | Evidence Directory | Notes |
| --- | --- | --- |
| `compute-1.example.test` | `compute-1.example.test/` | Has local VM tap samples; container `tc` can read tap qdisc. |
| `compute-2.example.test` | `compute-2.example.test/` | No local VM tap at collection time; container `tc` can read global qdisc. |
| `compute-3.example.test` | `compute-3.example.test/` | No local VM tap at collection time; container `tc` can read global qdisc. |

Per-host files:

- `neutron-qos-extension.txt`
- `neutron-qos-config.txt`
- `tc-qdisc.txt`
- `container-tc-qdisc.txt`
- `qos-code-presence.txt`
- `host-baseline.txt`

## Refreshed Facts

| Area | Result | Disposition |
| --- | --- | --- |
| Neutron QoS extension | `neutron ext-list` and `openstack extension list --network` do not show `qos` on any collected host. | `unsupported/deferred` |
| Neutron server `service_plugins` | Active server nodes include `router,network_ip_availability,mirror` and the Aria ACL plugin, but not `qos`. | `unsupported/deferred` |
| OVS agent extension | OVS agent config still shows `extensions = mirror`; no standard OVS QoS agent extension is enabled. | `no_double_enforcement` |
| Neutron QoS code | The old Neutron image contains QoS extension/plugin/ML2/agent code paths. | `available_but_disabled` |
| Aria QoS translator code | `neutron_aria.agent.effective_qos` imports inside `neutron_aria_agent`. | `available_but_not_product_enabled` |
| Host `tc` binary | Host shell does not have `tc` on `compute-1/3/4`. | `host_tc_missing` |
| Container `tc` binary | `neutron_openvswitch_agent`, `neutron_aria_agent`, and `aria_datapath` containers have `/usr/sbin/tc`. | `candidate_runtime_tooling` |
| Container qdisc visibility | On `compute-1`, the containers can see VM tap links and `tc qdisc show dev tap86b83885-67` succeeds. On `compute-2/4`, no VM tap was present, but global qdisc is readable from containers. | `read_only_supported` |

## Decision

QoS remains deferred for product implementation after Q0.

The old conclusion "the target has no `tc`" is now too coarse. The more precise
Q0 conclusion is:

- the host shell lacks `tc`;
- the relevant Kolla containers include `tc`;
- those containers share enough network namespace visibility to read qdisc;
- no qdisc write, shaping, policing, or rollback behavior has been validated.

Therefore:

- tenant-facing Neutron QoS remains `unsupported/deferred` until native Neutron
  QoS API/extension/service-plugin enablement is explicitly tested;
- shaping is a candidate path through the container runtime, but not accepted
  until a bounded write/rollback smoke proves qdisc mutation on a test tap;
- eBPF policing remains an alternative product decision if we choose to avoid
  qdisc mutation;
- current QoS status semantics should report `unsupported` or
  `degraded/no_op`, without affecting ACL or OVS baseline forwarding.

## Next Step

Proceed to Q1/Q2 design only:

- define status-only QoS domain semantics for `not_requested`,
  `unsupported`, and `degraded/no_op`;
- verify `managed_domains=["qos"]` local-write blocking in unit/smoke tests;
- do not implement shaping until a separate Q4 datapath action decision accepts
  either container-`tc` shaping or eBPF policing.
