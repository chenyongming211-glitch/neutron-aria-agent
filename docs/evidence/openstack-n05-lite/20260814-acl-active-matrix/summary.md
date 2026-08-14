# Three-Node ACL Active Matrix Acceptance

Date: `2026-08-14`

Candidate commit: `2a68e39`

Topology: three compute aliases (`node-a`, `node-b`, and `node-c`). Internal
addresses, credentials, endpoint URLs, and raw configuration are intentionally
excluded.

## Result

The authoritative detached run completed successfully:

| Gate | Result |
| --- | --- |
| systemd process exit | `0` |
| completion marker | present |
| active matrix | pass |
| case results | 444 pass, 0 fail |
| OVS canary | 9,325 samples, 0 failures |
| owned ACL resources remaining | 0 |
| matrix-prefixed policies remaining | 0 |

The transient systemd unit was inactive after completion because transient
units are unloaded after a successful run. Its recorded main-process exit
status was `0`.

## Coverage

The run completed 14 full cycles and 24 cases in cycle 15 before the fixed
deadline. All completed cases passed.

| Dimension | Cases |
| --- | ---: |
| ingress | 222 |
| egress | 222 |
| ICMP | 90 |
| TCP | 219 |
| UDP | 135 |
| stateful | 270 |
| stateless | 174 |

The matrix exercised single ports, port ranges, boundary ports, selector
updates, and policy/rule/binding disable and re-enable. TCP and UDP verdicts
used exact nonce responses rather than send success or `nc -uvz`.

## Convergence

The evidence contains 7,992 convergence observations. The aggregate latency
was median `1.108 s`, p95 `14.417 s`, p99 `19.547 s`, and maximum `19.587 s`.
This aggregate intentionally combines immediate allow checks, three
consecutive drop confirmations, and bounded convergence waits; it is not a
single RPC transport-latency metric.

Drop-confirmation phase medians ranged from approximately `8.3 s` to `10.3 s`.
Most allow and rollback checks had medians below `0.15 s`, while bounded retry
windows raised their p95 values to approximately `4.2 s`.

## Runtime Health

At morning collection, all three Aria agents reported:

- `alive=true`, `ready=true`, and `degraded=false`;
- `generation_lag=0` with accepted and applied generations equal;
- `sync_mode=rpc_full_resync` and heartbeat schema version 2;
- no reported runtime error.

The agent, datapath, OVS agent, and OVS process restart counters remained zero
during the run. The three datapath containers used identical executable and
eBPF payloads:

- `aria-agent`: `a4965d7e2db610d542b379e23628bb7bd69f847ca8640fce363639a58c4bfbb9`
- `libebpf_firewall.so`: `6488da9614a7ce81d0d2ae6271ffd0108d084a2115c2d37da02f6dcda13ab50f`

The gate did not restart or modify OVS, the Neutron OVS agent, or the Rust
datapath.

## Cleanup And Evidence

Owned bindings, rules, policies, dedicated VMs, ports, listeners, and runtime
targets were removed. One orphan policy created by an earlier, non-authoritative
harness attempt was separately proven to have no rules or bindings and then
removed. The final matrix-prefixed policy inventory was empty.

The raw archive is retained outside Git. Its SHA-256 is
`0ce4264d63f1c67347c103c50773fadffd286b24f74b8a9069f7044565315b57`.

Runtime stability, fixed-policy soak, and control-plane churn remain separate
gates and are not claimed by this active-matrix result.
