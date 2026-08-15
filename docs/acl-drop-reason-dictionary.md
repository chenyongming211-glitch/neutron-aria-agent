# ACL Drop-Reason Dictionary

This dictionary is the operator-facing reference for the numeric drop reasons
reported by the ACL explainability counter pipeline (`aria-acl-port-status-show
--counters` and the `aria_acl_port_counters` table).

The numeric vocabulary is defined by the eBPF ABI:

- ACL/QoS family: `abi/src/lib.rs` (`DROP_ACL_DENY`, `DROP_ACL_PORT_DENY`,
  `DROP_ACL_DEFAULT_DENY`, `DROP_QOS_INGRESS`, `DROP_QOS_EGRESS`)
- Fragment family: `abi/src/fragment.rs` (`DROP_FRAGMENT_*`, `DROP_MALFORMED_IP`)

Name mappings live in `openstack/neutron_aria/neutron_aria/agent/drop_reasons.py`
and are mirrored for the CLI in
`openstack/neutronclient_aria/neutronclient_aria/v2_0/aria_acl.py`; keep both in
sync when the ABI changes.

## Counting Semantics (normative)

- The **policy view** (bucket rows) counts traffic that hit an ACL policy
  bucket: `packets/bytes` total, `dropped_packets/dropped_bytes` denied.
- The **drop view** (reason rows) is the authoritative per-port drop
  accounting, including drops that are not policy-attributed (fragment,
  parse, QoS).
- An ACL-denied packet appears in **both** views by design. The two views
  answer different questions and must never be summed into one "total".
- A packet counted as policy-allow may still be dropped by a later phase
  (e.g. QoS ingress on the CT fast path), so `policy_allow + drop_total` is
  not a valid derived metric.

## Reason Table

| Name | Numeric | Meaning | Typical trigger | Troubleshooting |
| --- | --- | --- | --- | --- |
| ACL_DENY | 1 | ACL rule deny without a port filter | A rule with action `deny` matched on src/dst/proto/direction | Check `aria_acl_rules` for the bucket's src/dst ids; verify the deny rule is intended |
| ACL_PORT_DENY | 2 | ACL port-match deny | A rule with a port bitmap denied the destination port | Inspect the rule's port range against the traffic destination port |
| ACL_DEFAULT_DENY | 3 | ACL default deny (port not matched) | `default_action=deny` semantics on an unmatched port | Confirm the policy default action and missing port rules |
| QOS_INGRESS | 4 | QoS ingress rate-limit drop | Ingress traffic exceeds a bandwidth limit | Expected zero until QoS is product-enabled; check QoS config otherwise |
| QOS_EGRESS | 5 | QoS egress rate-limit drop | Egress traffic exceeds a bandwidth limit | Expected zero until QoS is product-enabled; check QoS config otherwise |
| FRAGMENT_CONFIG_MISSING | 6 | Fragment tracking disabled/misconfigured for the tap | Fragmented traffic on a tap without fragment tracking | Verify fragment tracking configuration for the port |
| FRAGMENT_TRACKING_DISABLED | 7 | Fragment tracking explicitly disabled | Fragment arrives while tracking is off | Enable or bypass fragment tracking per the runbook |
| FRAGMENT_CONFIG_INVALID | 8 | Invalid fragment tracking configuration | Config failed validation | Review fragment config capacity/flags |
| FRAGMENT_EPOCH_MISSING | 9 | No fragment epoch for the flow | First fragment after epoch expiry | Usually transient; repeated counts suggest churn |
| FRAGMENT_CONTEXT_MISSING | 10 | No fragment context for reassembly | Non-first fragment without prior state | Check for asymmetric routing or context eviction |
| FRAGMENT_CONTEXT_INVALID | 11 | Fragment context failed validation | Corrupt/stale reassembly state | Investigate MTU mismatches or overlapping fragments |
| FRAGMENT_CONTEXT_EXPIRED | 12 | Fragment context expired | Reassembly window elapsed | Confirm legitimate traffic patterns; tune expiry if needed |
| FRAGMENT_CONTEXT_STALE | 13 | Fragment context marked stale | Bank switch or policy update during reassembly | Expected during ACL updates; watch for sustained counts |
| FRAGMENT_CONTEXT_OVERLAP | 14 | Overlapping fragment ranges | Overlapping fragments in one datagram | Indicates hostile or broken traffic; investigate sources |
| FRAGMENT_CONTEXT_UPDATE_FAILED | 15 | Fragment context update failed | Map insert failure under pressure | Check eBPF map occupancy |
| FRAGMENT_TAP_UNASSIGNED | 16 | Fragment on a tap without an assigned id | Attach/detach race | Re-sync the port; usually transient |
| FRAGMENT_EXPIRY_OVERFLOW | 17 | Fragment expiry timer overflow | Very long expiry configuration | Review expiry configuration |
| MALFORMED_IP | 18 | Malformed IP header | Truncated/invalid IP packets | Check MTU and offload settings on the tap path |
| FRAGMENT_INVALID_L4 | 19 | Invalid L4 header on a fragment | Broken L4 offset/length | Investigate packet sources or NIC offloads |

Reasons 4 and 5 are part of the vocabulary but are expected to read zero on
Neutron-managed ports until QoS becomes a product-enabled domain.

## Field Evidence Status

Counter reporting ships disabled (`counters_report_enabled=false`) until field
RED/GREEN evidence exists. No field evidence is claimed for this pipeline; any
evidence recorded in `docs/evidence` follows the deferred/pending rules in
AGENTS.md.
