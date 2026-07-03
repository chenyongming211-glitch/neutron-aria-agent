# ACL live rerun summary

Date: 2026-07-03

Scope:

- Re-run real Neutron `aria_acl` API to `neutron-aria-agent` full-resync to datapath ACL tests.
- Cover downlink traffic on all three test hosts.
- Re-run guest-originated egress traffic on a temporary VM.
- Confirm rollback and final cleanup.

## Results

| Check | Host | Target | Result | Evidence |
| --- | --- | --- | --- | --- |
| Agent precheck | ostack2/3/4 | Aria ACL agent heartbeat | PASS | All three agents `ready=true`, `degraded=false`, generation lag `0`. |
| Downlink ACL | ostack2.bj159.net | Existing VM `10.58.159.26`, port `86b83885-671f-474c-9556-8af98cf1cdc8` | PASS | Baseline ping passed, temporary ingress ICMP drop produced 100% loss, rollback restored ping. Apply generation `205`, rollback generation `206`. |
| Downlink ACL | ostack4.bj159.net | Existing VM `10.58.159.52`, port `dc70f24f-7637-4d04-ada4-b92aae7a53fc` | PASS | Baseline ping passed, temporary ingress ICMP drop produced 100% loss, rollback restored ping. Apply generation `12`, rollback generation `13`. |
| Downlink ACL | ostack3.bj159.net | Temporary CirrOS VM `10.58.159.57`, port `73fefcf5-55b6-410e-ad13-703d7243a761` | PASS | Baseline ping passed, temporary ingress ICMP drop produced 100% loss, rollback restored ping. Apply generation `27`, rollback generation `28`. |
| Guest egress ACL | ostack3.bj159.net | Temporary CirrOS VM `10.58.159.59`, port `4e5a70f8-b152-429e-b89e-66187fc0bfb5` | PASS | Guest ping to host passed, temporary egress ICMP drop produced 100% loss, rollback restored guest ping. Apply generation `36`, rollback generation `38`. |
| Port status detail | ostack2.bj159.net | Existing VM `10.58.159.26` | RESOLVED | Initial run reported `ready/enforce` but left `effective_policy_id` and `binding_id` as `null`; the follow-up agent fix and formal smoke runs below verified both fields are populated. |
| Cleanup | Neutron API | Temporary ACL objects | PASS | `aria_acl_policies=0`, `aria_acl_rules=0`, `aria_acl_bindings=0` after tests. |
| Cleanup | Nova/Glance | Temporary VM/image resources | PASS | Temporary images were removed. Remaining `acl-live-*` Nova rows are `DELETED` audit records, not active resources. |

## Final Agent State

| Host | Ready | Degraded | Generation | Managed ports | Snapshot ports |
| --- | --- | --- | --- | --- | --- |
| ostack2.bj159.net | true | false | 220 | 13 | 16 |
| ostack3.bj159.net | true | false | 47 | 0 | 3 |
| ostack4.bj159.net | true | false | 17 | 1 | 1 |

## Formal Smoke Follow-up

The status identity fix and heartbeat compaction were packaged into
`dist/kolla/neutron_aria-0.1.0-py2.7.egg`, installed into the
`neutron_aria_agent` container on ostack2/3/4, and loaded by restarting only the
`neutron_aria_agent` containers.

New smoke scripts:

- `deploy/kolla/smoke/neutron_aria_acl_live_downlink_smoke.sh`
- `deploy/kolla/smoke/neutron_aria_acl_live_egress_smoke.sh`

Formal smoke results:

| Script | Host | Result | Notes |
| --- | --- | --- | --- |
| `neutron_aria_acl_live_downlink_smoke.sh` | ostack2.bj159.net | PASS | Existing VM `10.58.159.26`; status row included `effective_policy_id` and `binding_id`. |
| `neutron_aria_acl_live_downlink_smoke.sh` | ostack4.bj159.net | PASS | Existing VM `10.58.159.52`; status row included `effective_policy_id` and `binding_id`. |
| `neutron_aria_acl_live_egress_smoke.sh` | ostack3.bj159.net | PASS | Temporary CirrOS VM `10.58.159.61`; guest-originated ICMP was blocked, then recovered after rollback; status row included `effective_policy_id` and `binding_id`. |

Final package checks:

- `python ci/check_payload_terms.py dist/kolla/neutron-aria-stage2-acl-kolla-bundle.tgz`: PASS.
- Bash syntax checks for live smoke scripts and stage2 gate: PASS.
- Python unit tests `test_event_loop` + `test_status_reporter`: PASS, 42 tests.
- Final ACL object counts: `aria_acl_policies=0`, `aria_acl_rules=0`, `aria_acl_bindings=0`.
- Temporary live-smoke images: none remaining.
- Temporary live-smoke servers: only `DELETED` Nova audit records remain.

## Notes

- The environment requires raw-format images for the target compute aggregate. The temporary CirrOS image was converted to raw before VM creation.
- ostack3 had no pre-existing VM, so the test created and removed temporary CirrOS VMs.
- `aria_acl_port_statuses` retains historical rows, including detached/deleted ports. The current cleanup policy still needs to be documented.
- Follow-up hotfix verification populated `effective_policy_id` and `binding_id` for the ready/enforce row on ostack2, generation `216`.
- The fix has now been included in the formal stage-two agent egg and verified with the new live smoke scripts.
