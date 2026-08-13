# Aria ACL Capacity Probe on CirrOS VM

Date: 2026-07-07

This probe validates Aria ACL behavior on a real CirrOS VM port and measures the
current control-plane convergence cost as ACL rule count increases.

## Test Target

- VM: `aria-cirros-test-20260707`
- Compute host: `compute-a.example.test`
- Neutron port: `ff0b04e9-c1b3-4779-ae63-7e6d2a966a50`
- Tap: `tapff0b04e9-c1`
- VIF type: `ovs`
- VNIC type: `normal`

The target port is a normal OVS tap port and is eligible for Aria ACL
enforcement.

## Functional ACL Result

The following live ACL paths passed:

| Test | Result | Evidence |
| --- | --- | --- |
| Downlink / ingress ACL | Pass | Temporary `aria_acl_policy`, rule, and binding were created through Neutron. Full-resync applied a datapath drop policy. Host-to-VM ICMP was blocked. Deleting the ACL and resyncing restored connectivity. |
| Guest egress ACL | Pass | CirrOS guest-originated ICMP to the host was blocked by an egress ACL. Deleting the ACL and resyncing restored guest-originated traffic. |
| Datapath cleanup | Pass | After rollback, `tapff0b04e9-c1` had `0` policies and `0` groups. |
| Status recovery | Pass | Port status returned to `not_requested` / `bypass` after cleanup. |

## Capacity Probe Results

Two modes were tested:

1. Manual `neutron-aria-agent --once --enable-full-resync` while the long-running
   `neutron_aria_agent` service was also running.
2. Product-like long-running service mode, where only Neutron ACL objects were
   created and the resident agent performed periodic full-resync.

### Manual Full-Resync Mode

| Rules on one port | Create rules time | Full-resync time | Datapath count | Traffic result | Result |
| ---: | ---: | ---: | ---: | --- | --- |
| 10 | 0.391 s | 3.020 s | 10 policies / 10 groups | ICMP blocked, rollback OK | Pass |
| 50 | 1.144 s | 6.825 s | 50 policies / 50 groups | ICMP blocked, rollback OK | Pass |
| 100 | 1.758 s | 11.683 s | 100 policies / 100 groups | ICMP blocked, rollback OK | Pass |
| 120 | 2.208 s | 16.678 s | Partial during concurrent generation churn | ICMP was not reliably blocked | Not acceptable |
| 200 | 3.700 s | Timed out | Timeout / convergence failure | Cleanup later recovered | Not acceptable |

Manual mode is not a production-grade capacity measurement when the resident
agent is also running. It can create competing generations and should not be used
as the final performance proof.

### Long-Running Service Mode

| Rules on one port | Create rules time | Service apply convergence | Datapath count | Traffic result | Cleanup |
| ---: | ---: | ---: | ---: | --- | --- |
| 120 | 2.137 s | 20.512 s | 120 policies / 120 groups | ICMP blocked | 57.491 s |
| 200 | 3.625 s | 218.602 s | 200 policies / 200 groups | ICMP blocked | 77.948 s |

Service mode proves that 200 rules can eventually apply on the current test
environment, but the convergence time is too high for a safe default product
limit.

## Technical Interpretation

Current eBPF map limits are much higher than the product-safe limit:

| Map | Current max entries | Meaning |
| --- | ---: | --- |
| `POLICY_TABLE` | 65,536 | Raw datapath policy entries |
| `RULE_STATS` | 65,536 | Per-policy stats entries |
| `SRC_IPV4_TRIE` | 10,000 | Source IPv4 CIDR group entries |
| `DST_IPV4_TRIE` | 10,000 | Destination IPv4 CIDR group entries |
| `SRC_IPV6_TRIE` / `DST_IPV6_TRIE` | 5,000 each | IPv6 CIDR group entries, not yet supported by the minimal Neutron ACL translator |
| `TAP_CONFIG_MAP` / `IFACE_CTX_MAP` | 1,024 | Managed tap/interface context entries |

The product limit must not be set to the raw eBPF map maximum. In the current
implementation, full-resync and rollback cost grows with the number of effective
rules. A single policy with hundreds of rules already causes visible control
plane convergence delay.

## Recommended Product Limits

Initial default limits:

| Scope | Recommended hard limit | Warning threshold |
| --- | ---: | ---: |
| Rules per ACL policy | 100 | 70 |
| Effective ACL rules per port | 100 | 70 |
| Address-set members per set | 256 | 180 |
| Total ACL rules per project | 1,000 | 700 |
| Total effective datapath policies per host | 5,000 | 3,500 |

Optional advanced limits after optimization and longer soak:

| Scope | Candidate raised limit |
| --- | ---: |
| Rules per ACL policy | 200 |
| Effective ACL rules per port | 200 |
| Address-set members per set | 512 |
| Total ACL rules per project | 2,000 |
| Total effective datapath policies per host | 10,000 |

The raised profile should only be enabled after optimizing apply convergence,
adding quota enforcement, and completing a 500 / 1,000 rule lab stress test.

## Required Follow-Up Work

- Add Neutron Server quota checks for policy/rule/address-set/binding CRUD.
- Add defensive effective-rule checks in `neutron-aria-agent` before UDS submit.
- Add datapath status checks that compare expected policy count with applied
  policy count before reporting `ready`.
- Avoid concurrent manual full-resync and resident periodic full-resync in smoke
  tests, or add a generation lease / leader guard.
- Optimize Rust UDS apply path so large ACL snapshots are not vulnerable to
  client timeout and partial apply observations.
- Add a repeatable capacity smoke script with stair-step sizes and rollback
  verification.
