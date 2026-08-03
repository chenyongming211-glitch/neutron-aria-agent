# Aria ACL 1000-Rule Gate Evidence

Date: 2026-07-08

Scope: validate that the optimized Aria ACL delivery path can handle 1000
effective rules on one normal OVS tap port, that add/delete-one rule operations
touch only the delta, and that active traffic does not observe a whole-port ACL
bypass during non-empty diff updates.

## Target

| Field | Value |
| --- | --- |
| Host | `compute-1.example.test` |
| VM | `aria-cirros-test-20260707` |
| VM IP | `192.0.2.68` |
| Neutron port | `ff0b04e9-c1b3-4779-ae63-7e6d2a966a50` |
| tap | `tapff0b04e9-c1` |
| VIF / VNIC | `ovs` / `normal` |

## Before Gate-Mode Fix

The first 1000-rule run proved that rule/group diff apply was fast enough, but
also exposed a short active-traffic bypass window.

| Check | Result |
| --- | ---: |
| Create 1000 rules through Neutron API | `33459 ms` |
| Initial 1000-rule full-resync wall time | `2925 ms` |
| Initial 1000-rule datapath apply | `total_ms=304` |
| Add one rule full-resync wall time | `2956 ms` |
| Add one rule datapath apply | `total_ms=371`, `group_add_count=2`, `policy_add_count=1` |
| Delete one rule full-resync wall time | `4163 ms` |
| Delete one rule datapath apply | `total_ms=835`, `group_delete_count=2`, `policy_delete_count=1` |
| Active traffic probe | failed, `marked_replies=152` |

Root cause: the Rust `reconcile_neutron_acl()` path still disabled the port ACL
gate before every reconcile. Even a delete-one-rule diff update temporarily
bypassed the existing drop policy.

## Fix

The datapath now uses an ACL gate update mode:

| Mode | When Used | Behavior |
| --- | --- | --- |
| `keep_current_until_enable` | desired ACL has one or more policies | Keep the current ACL gate active while diff apply runs. |
| `disable_before_replace` | desired ACL is empty | Disable ACL before cleanup/rollback, which intentionally returns the port to bypass. |

Every `neutron_acl_apply_profile` now logs `gate_update_mode` and `disable_ms`.

## After Gate-Mode Fix

| Check | Result |
| --- | ---: |
| Create 1000 rules through Neutron API | `32715 ms` |
| Initial 1000-rule full-resync wall time | `3211 ms` |
| Initial 1000-rule datapath apply | `total_ms=570`, `disable_ms=0` |
| Add one rule full-resync wall time | `3071 ms` |
| Add one rule datapath apply | `total_ms=238`, `group_add_count=2`, `policy_add_count=1`, `disable_ms=0` |
| Delete one rule full-resync wall time | `2863 ms` |
| Delete one rule datapath apply | `total_ms=296`, `group_delete_count=2`, `group_cidr_delete_count=2`, `policy_delete_count=1`, `disable_ms=0` |
| Active traffic probe | pass, `marked_replies=0` from 1600 high-rate ICMP probes |
| Cleanup | pass, no temporary `acl-1000-gate-*` policy/rule/binding objects remained |
| Post-cleanup traffic | pass, host-to-VM ICMP recovered |
| Datapath status | pass, `pending_generation=null`, `authority_state=ready` |

## Conclusion

The 1000-rule ACL gate is accepted for the tested OVS tap-port path:

- Initial 1000-rule datapath apply is comfortably below the current target.
- Add/delete-one rule operations are delta-based and complete within the
  product target of less than 5 seconds.
- Active traffic did not observe a whole-port ACL bypass during non-empty diff
  updates after the gate-mode fix.

Remaining work:

- Add a reusable packaged capacity smoke script instead of relying on an
  operator-created temporary script.
- Run the same gate on additional compute hosts and with more traffic types.
- Keep shadow generation on the roadmap for strict all-or-nothing visibility
  during complex policy updates.
