# Three-Compute RC Core Acceptance

Date: 2026-08-20

## Scope

This gate validates the exact Rust userspace candidate from source commit
`6144bf36` on all three admitted test computes. It covers persistent RC
installation, northbound ACL contracts, real IPv4 ingress and egress traffic,
and real IPv6 ingress traffic. It does not claim the later RPC, lifecycle,
scale, or soak gates listed below.

Aria did not restart or modify OVS or the Neutron OVS agent during this run.

## Candidate Identity

- GitHub Actions run: `32334693695`, result `success`.
- Datapath image ID on all three computes:
  `sha256:3c6f96376ffdfca8788b48ab5aa0e5fc8bf6b94e9d2b4e87f408481f4cf69a1a`.
- `aria-agent` SHA-256:
  `a6e069fcaa06c6fc80d0cdf8e03ce86780f53d5d5473801121784923e8d4347f`.
- eBPF ingress/egress object SHA-256:
  `b70f5f1e57f005c17aa262d3cde757764577df9a0c187aac0f5f682f7bee3e63`.
- Image archive SHA-256:
  `8c9d413003548596595784bd067629aa14dc75d7e6d80f92cb7990830f5a1cc4`.

Each compute retained its immediately previous datapath container as the
rollback point. The candidate used a dedicated root-only release ledger
because an older historical ledger no longer described the active pre-test
container. The older ledger was preserved read-only and was never used for
rollback.

## Deployment Result

All three computes passed the manifest-pinned installer `install` and `check`
commands. The eBPF hash was unchanged, so the installer used the fast
userspace-container replacement path. On every compute:

- `aria_datapath` and `neutron_aria_agent` were healthy with zero restart
  count after convergence;
- the exact image and all three runtime file hashes matched;
- the UDS socket remained mode `0660` with the authorized group;
- the OVS process identity was unchanged;
- the Neutron OVS agent container identity and start time were unchanged.

## API And DB Result

The production Neutron plugin passed direct SQLAlchemy CRUD and local REST
CRUD with cleanup. Live REST rejection checks returned:

- HTTP 400 for unsupported default deny;
- HTTP 400 for source-port matching;
- HTTP 400 for a reversed destination-port range;
- HTTP 400 for an unsupported protocol;
- HTTP 400 for an address-family mismatch;
- HTTP 400 for a mixed-family address set;
- HTTP 409 for a duplicate same-family priority.

The legacy CLI `policy-show --with-rules` also returned `rule_count` and the
created rule identity. No rejected request left a policy, rule, binding, or
address-set row.

## IPv4 Real-Traffic Result

Six real-VM cases passed across the three computes:

| Direction | Protocol | Policy mode | Selector |
| --- | --- | --- | --- |
| ingress | ICMP | stateful | protocol-only, then TCP selector update |
| ingress | TCP | stateful | single destination port |
| ingress | UDP | stateless | destination-port range |
| egress | TCP | stateful | single destination port |
| egress | UDP | stateful | destination-port range |
| egress | ICMP | stateless | protocol-only, then TCP selector update |

Every case verified baseline allow, matching drop, non-matching allow, rule
update, rule disable/enable, binding disable/enable, policy disable/enable,
`ready/enforce`, `not_requested/bypass`, rollback connectivity, heartbeat
readiness, zero generation lag, and object cleanup.

The first egress UDP attempt was invalid test evidence: the guest UDP probe
failed before any ACL object was created. `REVIEW-TEST-001` records the
BusyBox `nc` EOF root cause and the corrected passing rerun. One ICMP control
attempt also used an unproven same-host high-port service; its corrected
cross-compute target rerun passed. Neither initial directory is counted as a
product failure.

## IPv6 Real-Traffic Result

The IPv6 gate was explicitly enabled on all three agents. Each compute used a
dedicated source and destination VM on the real IPv6 subnet. All three cases
passed:

1. baseline ICMPv6 echo succeeded;
2. an IPv6 `/128` source and destination rule reached `ready/enforce` with the
   exact policy, binding, port, and host identities;
3. three consecutive ICMPv6 probes were dropped;
4. deleting the binding, rule, and policy restored traffic;
5. status advanced to `not_requested/bypass` with empty effective identities;
6. no test binding remained.

An initial node-a script read status immediately after delete and observed the
previous generation. Traffic had already recovered and the next status sample
correctly advanced to bypass. The rerun added a bounded final-status wait and
passed on all three computes.

## Private Raw Evidence

Raw evidence is retained outside the public repository because it contains
environment-specific host and port identities:

- node-a archive: `cf02908ab7d42f8646d8737457d25914d0797eace25c3fba76ce19e51f376478`;
- node-b archive: `deed9e3570ef707f200aefabdda41aae39b10b4a52e5e6734a24ab186a070623`;
- node-c archive: `8078b33f96a64bf32fb1fa38e8a362aeafdb4f75bad84e9a1775ca80dcdff893`.

## Result And Remaining Gates

Result: **PASS** for exact-candidate installation, API/DB contracts, the
three-compute IPv4 core matrix, and three-compute ICMPv6 ingress enforcement.

The current-candidate IPv6 TCP/UDP and ND follow-up is recorded in
`../20260820-rc-6144bf36-ipv6-transport-nd/summary.md`. The following remain
required before the overall RC can close:

- IPv6 egress, extension-header, fragment, and same-port dual-stack cases;
- RPC loss/duplicate/out-of-order/fanout and polling fallback;
- UDS timeout, malformed request, peer-credential, and double-writer gates;
- agent/datapath restart, tap recreate, migration, rebuild, shelve, and Kolla
  rollback lifecycle gates;
- multi-port scale, sustained updates, resource trends, cleanup, and final
  stability soak.
