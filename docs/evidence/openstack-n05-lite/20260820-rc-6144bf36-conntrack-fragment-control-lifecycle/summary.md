# RC 6144bf36 Conntrack, Fragment, Control-Plane, and Lifecycle Evidence

Date: 2026-08-20

## Candidate identity

- Source commit: `6144bf36`
- Hosted build: `32334693695`
- Agent SHA-256:
  `a6e069fcaa06c6fc80d0cdf8e03ce86780f53d5d5473801121784923e8d4347f`
- eBPF SHA-256:
  `b70f5f1e57f005c17aa262d3cde757764577df9a0c187aac0f5f682f7bee3e63`
- Target kernel: `4.18.0-553.5.1.el8_10.x86_64`
- Topology: three compute nodes, VLAN east-west only

The raw field archives are retained privately. This summary intentionally omits
internal addresses, hostnames, credentials, and tenant identifiers.

## Results

| Area | Result | Evidence summary |
| --- | --- | --- |
| Managed conntrack authority | PASS | Stateful reply tracking, stateless zero-CT behavior, deny zero-CT behavior, bank revision invalidation, TC ingress/egress authority, and XDP ACL/CT neutrality all passed. |
| IPv6 TCP revision invalidation | PASS | An established connection stopped passing after an allow-to-drop update; cleanup restored a fresh connection. |
| IPv6 UDP same-tuple invalidation | PASS | A fixed-source-port request/reply tuple stopped passing after an allow-to-drop update; cleanup restored the same tuple. |
| Deep fragment handling, system mode | PASS | IPv4/IPv6, both directions, ordered and reordered delivery, later-before-first behavior, VLAN isolation, epoch invalidation, restart scrub, pressure, and cleanup passed. |
| Deep fragment handling, tap mode | PASS | The system-mode matrix plus cross-tap isolation passed with complete temporary namespace, veth, mount, and pin cleanup. |
| Malformed packet injection on a real tap | PENDING, harness limitation | Direct host AF_PACKET injection failed before TC with `ENOBUFS`. It is neither a product PASS nor a product failure; malformed-chain field evidence still requires a guest or isolated-netns injector. |
| RPC-triggered full resync | PASS | Binding, rule, and policy changes converged through the event path in approximately 1.5-4.6 seconds and cleanup returned the port to `not_requested/bypass`. |
| Duplicate and reordered RPC events | PASS | Sixty forward/reverse revision events folded to one local port update per agent, without overflow or foreign-host mutation. |
| Polling fallback | PASS | With RPC events disabled on one compute, periodic full resync applied in about 30 seconds and cleanup converged in about 56 seconds; RPC mode was then restored. |
| UDS security and robustness | PASS | Three-node peer credentials and socket permissions passed; malformed JSON returned 400, oversized input returned 413, unauthorized UID was denied and audited, and 50 abrupt disconnects per node left status readable, FD count stable, health green, and restart count unchanged. |
| Active ACL during datapath pause | PASS | The old kernel ACL remained enforced while userspace was paused, the datapath healthcheck became unhealthy, the queued binding disable converged one second after unpause, and the independent OVS canary passed 265/265. |
| Python agent lifecycle | PASS | ACL enforcement remained active while the Python agent was stopped; health/status recovered in 17 seconds. |
| Rust datapath lifecycle | PASS | The committed kernel ACL remained active while userspace was stopped; health/status recovered in 47 seconds. The combined lifecycle OVS canary passed 719/719. |
| VM soft reboot / tap recreate | FAIL, intermittent P1 | Two runs admitted traffic after the tap changed ifindex while status remained `ready/enforce`; one measured admission window lasted at least 14.759 seconds. A third run reconciled before guest reachability and admitted no blocked-source probes in 120 samples. This race is registered as `REVIEW-ACL-124`. OVS canaries remained lossless, including 487/487 and 1539/1539. |

## Safety and cleanup

- No test restarted or modified OVS or the Neutron OVS agent.
- All temporary policies, rules, and bindings were removed.
- The exercised port returned to `not_requested/bypass`.
- All three datapath, Python agent, and OVS-agent containers ended healthy and
  unpaused with zero restart count.
- `full_resync_enabled=true`, `rpc_events_enabled=true`,
  `incremental_rpc_enabled=false`, and IPv6 ACL remained consistently configured
  across all three computes.

## Private archive checksums

- `aria-rc-6144bf36-ct-fragment-control-lifecycle-20260820-compute-a.tgz`:
  `d4b09f7107a8363e8a6ea81be628cff4bb23615bd826e0d83155c3fd3afff33c`
- `aria-rc-6144bf36-uds-control-20260820-compute-b.tgz`:
  `110ba4e5e81256264c1d3ef3375c0c65fdc407d2b05d5103c13972d9c338b79a`
- `aria-rc-6144bf36-uds-control-20260820-compute-c.tgz`:
  `07eebc528453844f1cf767fe2e33958a62ac0b7a31ba1c3008507e83d680b0bb`

## Release implication

Conntrack, fragment, RPC/UDS, and process lifecycle gates passed on the current
candidate. The candidate must not be declared lifecycle-complete until
`REVIEW-ACL-124` is fixed and the soft-reboot/tap-recreate field smoke proves
truthful degraded status and deterministic reattachment on the replacement
ifindex.
