# ACL-013 Two-Compute Port Projection Acceptance

Date: 2026-08-12

Scope: close the target Neutron 9/Python 2 field-evidence gap for the legacy
Neutron port projection on every compute in the currently declared test
topology. The unavailable former compute is not part of this topology and no
three-compute availability claim is made.

## Result

| Check | Compute A | Compute B |
| --- | --- | --- |
| REST and legacy CLI read each other's policy/rule/address-set/binding objects | pass | shared control-plane baseline |
| `neutron port-show` exposes all nine Aria ACL projection fields | pass | pass |
| Enabled desired policy and binding identities match runtime status | pass | pass |
| Runtime `ready/enforce` projects as `applied` on the current host | pass | pass |
| Foreign-host ready row cannot displace the current-host row | pass | pass |
| Wrong/old binding identity projects conservatively as `pending` | pass | pass |
| Runtime `degraded/bypass` projects as `degraded` | pass | pass |
| Stale current-host evidence projects as `unknown/status_stale` | pass | not repeated; covered on Compute A |
| Python agent recovery restores fresh `applied` projection | pass | not repeated; agent was not restarted |
| Binding/policy cleanup restores `False/not_requested` | pass | pass |
| Continuous VM traffic and OVS non-interference | pass | pass |

Compute A used an explicit, reversible Python `neutron_aria_agent` stop/start
to age one status row past the 90-second stale threshold. The Rust datapath,
OVS, and `neutron-openvswitch-agent` were not restarted. Compute B ran the same
identity and negative-projection checks without any service restart.

The maintained smoke is:

```text
deploy/kolla/smoke/neutron_aria_acl_port_projection_smoke.sh
```

Its stale scenario is default-off and requires both `TEST_STALE=true` and
`ALLOW_AGENT_RESTART=true`. The script never restarts OVS or the Neutron OVS
agent.

## Cleanup

- Temporary policies, bindings, and synthetic foreign-host status rows were
  removed.
- Both tested ports returned to `aria_acl_enabled=False` and
  `aria_acl_runtime_status=not_requested`.
- Both Python agents and Rust datapaths were running after the test.
- VM connectivity passed after cleanup.

## Conclusion

`REVIEW-ACL-013` is field-verified for the current two-compute topology. A
future compute must run this smoke as part of node admission; its absence does
not invalidate evidence from the declared topology.
