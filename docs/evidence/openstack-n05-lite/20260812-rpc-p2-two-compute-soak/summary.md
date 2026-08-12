# RPC P2 Two-Compute Soak Evidence

Date: 2026-08-12

Scope: the declared active compute topology, `ostack2.bj159.net` and
`ostack4.bj159.net`. The unavailable former third compute is not part of this
acceptance claim.

## Result

`deploy/kolla/smoke/neutron_aria_rpc_p2_soak_smoke.sh` passed concurrently on
both active computes with a 300 second observation window and 10 second sample
interval.

| Host | Samples | Managed ports | Generation | Event batches | Result |
| --- | ---: | ---: | ---: | ---: | --- |
| `ostack2.bj159.net` | 30 | 23 | 3940 | 1 | pass |
| `ostack4.bj159.net` | 30 | 14 | 3298 | 2 | pass |

Every sample kept `pending_generation=none`, accepted generation equal to
applied generation, container restart count at zero, and the bad-log count at
zero. Periodic full resync occurred at the configured 60 second interval; the
single RPC trigger did not form a resync loop.

The smoke restored the exact pre-test configuration on exit. `aria_datapath`
was not restarted. The `ovs-vswitchd` PIDs remained `3272273` on ostack2 and
`22159` on ostack4. Neither OVS nor `neutron_openvswitch_agent` was modified or
restarted.

Remote evidence directories:

- `/var/tmp/rpc-p2-soak-current-ostack2`
- `/var/tmp/rpc-p2-soak-current-ostack4`

This short gate proves two-compute convergence and rollback. It does not
replace the separate 24-hour read-only resource-growth soak.
