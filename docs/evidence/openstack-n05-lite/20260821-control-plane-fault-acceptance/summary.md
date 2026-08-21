# Control-Plane Fault Acceptance

## Scope

This gate exercised the three-compute Aria ACL control plane without restarting
or modifying OVS, the Neutron OVS agent, or the physical hosts. Field names and
addresses are intentionally replaced with `compute-1` through `compute-3`.
Raw evidence remains on the controlled field nodes under the versioned
`/var/tmp/aria-rc-ba9e7c90-control-plane-20260821/` and
`/var/tmp/aria-control-plane-00f03a59/` directories; it is not a public release
payload.

## Candidates

| Component | Candidate |
|---|---|
| Python adapter before HTTP-timeout repair | `neutron-aria-agent:rc-ba9e7c90` |
| Python adapter after repair | commit `00f03a59`, image `neutron-aria-agent:rc-00f03a59`, image ID `sha256:6c82acda0d7d64619b202ba46e5c0faa192d428cc9167310293866f56c65c6f9` |
| Rust datapath | unchanged throughout the Python rollout |

The fixed Python image was built against the target legacy Neutron/Python 2
base, validated through its real entry point, and installed serially. Each
compute retained an installer rollback state.

## Results

| Gate | Result | Evidence |
|---|---|---|
| UDS malformed JSON | pass | Authorized requests returned HTTP `400`; generation did not advance. |
| UDS oversized body | pass | A body one byte above the advertised 1 MiB limit returned HTTP `413`. |
| UDS abrupt disconnect | pass | Fifty partial disconnects per compute did not leak file descriptors or change container identity. |
| UDS peer credentials | pass | The authorized agent identity was accepted; an unlisted host-root peer received no HTTP response and was audited as denied. |
| UDS timeout with active ACL | pass | Pausing only datapath userspace preserved the old kernel ACL. After unpause, disable converged to bypass and traffic recovered; the independent OVS canary was `120/120`. |
| RabbitMQ duplicate and reversed events | pass | Sixty real fanout events, revisions `30..1` then `1..30`, folded into one batch. The owner chose full resync; foreign computes ignored the unknown foreign port. |
| RPC event loss | pass | With RPC intake disabled only on the owner, periodic polling enforced in `27.048s` and removed in `58.934s`; the independent OVS canary was `758/758`. |
| Neutron HTTP blackhole before repair | reproduced | A peer accepted TCP and never replied; the old client remained blocked until the external watchdog killed it after more than ten seconds. |
| Neutron HTTP blackhole after repair | pass | The deployed `api_timeout=10.0` caused the target legacy client to exit itself in `10.730s`, before the 18-second watchdog. |
| Neutron HTTP recovery | pass | The next real API read succeeded in `0.944s` and returned the local port set. |
| Real ACL after repair | pass | Policy, rule, and binding creation reached the current generation, traffic was blocked, delete rollback cleared the datapath, and traffic recovered. |
| Three-compute rollout | pass | All adapters used the same image ID, were healthy with zero restarts, advertised `ready=true`, `degraded=false`, `generation_lag=0`, and reported `neutron_api_timeout=10.0`. |
| RabbitMQ final state | pass | Three running nodes, no alarms, and no network partitions. |
| Cleanup | pass | The test port had no binding and reported `not_requested/bypass`, `stale=false`. No blackhole listener or temporary probe container remained. |

## Non-Interference

The serial Python rollout produced three independent `600/600` OVS canaries
with zero loss. The RPC-loss, UDS-timeout, and post-repair live-ACL runs added
`758/758`, `120/120`, and `400/400` zero-loss canaries. Datapath and Neutron OVS
agent container identities and start times matched their pre-test values on all
three computes.

## Harness Finding

The first post-repair live smoke applied the ACL successfully but its optional
port-status identity assertion exceeded Linux `ARG_MAX` because the complete
list response was placed in one environment variable. Cleanup succeeded and a
rerun without that optional assertion passed. This is tracked as
`REVIEW-OPS-044`; it does not change the product result above.

## Conclusion

RabbitMQ duplicate, reverse-order, and lost-event behavior converged through
the designed event merge or polling fallback. UDS malformed, oversized,
disconnect, peer-credential, and timeout paths preserved forwarding and
recovered. `REVIEW-OPS-043` removes the only reproduced unbounded Neutron HTTP
wait and is field-verified. Final source closure still requires the sanitized
exact-head hosted gate; no hosted result is inferred from field evidence.
