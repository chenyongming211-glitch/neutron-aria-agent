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
| Agent precheck | compute-1/3/4 | Aria ACL agent heartbeat | PASS | All three agents `ready=true`, `degraded=false`, generation lag `0`. |
| Downlink ACL | compute-1.example.test | Existing VM `192.0.2.26`, port `86b83885-671f-474c-9556-8af98cf1cdc8` | PASS | Baseline ping passed, temporary ingress ICMP drop produced 100% loss, rollback restored ping. Apply generation `205`, rollback generation `206`. |
| Downlink ACL | compute-3.example.test | Existing VM `192.0.2.52`, port `dc70f24f-7637-4d04-ada4-b92aae7a53fc` | PASS | Baseline ping passed, temporary ingress ICMP drop produced 100% loss, rollback restored ping. Apply generation `12`, rollback generation `13`. |
| Downlink ACL | compute-2.example.test | Temporary CirrOS VM `192.0.2.57`, port `73fefcf5-55b6-410e-ad13-703d7243a761` | PASS | Baseline ping passed, temporary ingress ICMP drop produced 100% loss, rollback restored ping. Apply generation `27`, rollback generation `28`. |
| Guest egress ACL | compute-2.example.test | Temporary CirrOS VM `192.0.2.59`, port `4e5a70f8-b152-429e-b89e-66187fc0bfb5` | PASS | Guest ping to host passed, temporary egress ICMP drop produced 100% loss, rollback restored guest ping. Apply generation `36`, rollback generation `38`. |
| Port status detail | compute-1.example.test | Existing VM `192.0.2.26` | RESOLVED | Initial run reported `ready/enforce` but left `effective_policy_id` and `binding_id` as `null`; the follow-up agent fix and formal smoke runs below verified both fields are populated. |
| Cleanup | Neutron API | Temporary ACL objects | PASS | `aria_acl_policies=0`, `aria_acl_rules=0`, `aria_acl_bindings=0` after tests. |
| Cleanup | Nova/Glance | Temporary VM/image resources | PASS | Temporary images were removed. Remaining `acl-live-*` Nova rows are `DELETED` audit records, not active resources. |

## Final Agent State

| Host | Ready | Degraded | Generation | Managed ports | Snapshot ports |
| --- | --- | --- | --- | --- | --- |
| compute-1.example.test | true | false | 220 | 13 | 16 |
| compute-2.example.test | true | false | 47 | 0 | 3 |
| compute-3.example.test | true | false | 17 | 1 | 1 |

## Formal Smoke Follow-up

The status identity fix and heartbeat compaction were packaged into
`dist/kolla/neutron_aria-0.1.0-py2.7.egg`, installed into the
`neutron_aria_agent` container on compute-1/3/4, and loaded by restarting only the
`neutron_aria_agent` containers.

New smoke scripts:

- `deploy/kolla/smoke/neutron_aria_acl_live_downlink_smoke.sh`
- `deploy/kolla/smoke/neutron_aria_acl_live_egress_smoke.sh`

Formal smoke results:

| Script | Host | Result | Notes |
| --- | --- | --- | --- |
| `neutron_aria_acl_live_downlink_smoke.sh` | compute-1.example.test | PASS | Existing VM `192.0.2.26`; status row included `effective_policy_id` and `binding_id`. |
| `neutron_aria_acl_live_downlink_smoke.sh` | compute-3.example.test | PASS | Existing VM `192.0.2.52`; status row included `effective_policy_id` and `binding_id`. |
| `neutron_aria_acl_live_egress_smoke.sh` | compute-2.example.test | PASS | Temporary CirrOS VM `192.0.2.61`; guest-originated ICMP was blocked, then recovered after rollback; status row included `effective_policy_id` and `binding_id`. |

Final package checks:

- `python ci/check_payload_terms.py dist/kolla/neutron-aria-stage2-acl-kolla-bundle.tgz`: PASS.
- Bash syntax checks for live smoke scripts and stage2 gate: PASS.
- Python unit tests `test_event_loop` + `test_status_reporter`: PASS, 42 tests.
- Final ACL object counts: `aria_acl_policies=0`, `aria_acl_rules=0`, `aria_acl_bindings=0`.
- Temporary live-smoke images: none remaining.
- Temporary live-smoke servers: only `DELETED` Nova audit records remain.

## Notes

- The environment requires raw-format images for the target compute aggregate. The temporary CirrOS image was converted to raw before VM creation.
- compute-2 had no pre-existing VM, so the test created and removed temporary CirrOS VMs.
- `aria_acl_port_statuses` retains historical rows, including detached/deleted ports. The current cleanup policy still needs to be documented.
- Follow-up hotfix verification populated `effective_policy_id` and `binding_id` for the ready/enforce row on compute-1, generation `216`.
- The fix has now been included in the formal stage-two agent egg and verified with the new live smoke scripts.
