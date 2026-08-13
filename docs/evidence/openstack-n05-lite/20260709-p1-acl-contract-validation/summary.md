# P1 ACL Contract Validation On 10.58.159

Date: 2026-07-09

Scope:

- Deploy the P1 ACL contract fixes to the 10.58.159 test environment.
- Validate default-action and unsupported rule-field rejection.
- Validate normal ACL create/read/bind/status CRUD still works.
- Validate a real VM port can still enforce existing ICMP/TCP/UDP drop rules.

Deployment:

- Uploaded `dist/kolla/neutron-aria-stage2-acl-kolla-bundle.tgz` to all three nodes.
- Extracted to `/tmp/aria-p1-fix`.
- Updated `neutron_server` plugin package on:
  - `compute-a.example.test`
  - `compute-b.example.test`
- Updated `neutron_aria_agent` egg on:
  - `compute-a.example.test`
  - `compute-b.example.test`
  - `compute-c.example.test`
- Updated legacy `neutron` CLI extension in `openstack_client` on:
  - `compute-a.example.test`
  - `compute-b.example.test`
  - `compute-c.example.test`

Restarts:

- Restarted `neutron_server` only on compute-a/compute-b.
- Restarted `neutron_aria_agent` on compute-a/compute-b/compute-c.
- Did not restart OVS, ovs-agent, or aria-datapath.

Negative validation:

- Legacy CLI rejected:
  - `aria-acl-policy-create --default-action deny`
  - `aria-acl-rule-create --src-port-min 1024`
  - `aria-acl-rule-create --ethertype IPv6`
  - `aria-acl-rule-create --protocol gre`
  - `aria-acl-rule-create --dst-port 0`
- API rejected:
  - `default_action=deny`
  - source-port matching
  - IPv6 ethertype
  - unsupported protocol `gre`
  - invalid destination port range

Note: API rejects currently surface as HTTP 500 in this old Neutron runtime. That is the already-recorded `REVIEW-ACL-006` error-mapping gap; the P1 result is that invalid objects are not created.

Positive validation:

- `neutron_aria_acl_db_crud_smoke.sh`: passed.
- `neutron_aria_acl_cli_consistency_smoke.sh`: passed.
- Existing test VM:
  - port: `ff0b04e9-c1b3-4779-ae63-7e6d2a966a50`
  - IP: `192.0.2.68`
  - policy: `496aa1ae-0119-4fcd-a7df-ec4574856371`
- Temporarily enabled the existing policy with ICMP, TCP/8080, UDP/1080, and TCP/18081 drop rules.
- Port status converged to `ready/enforce` in about 3 seconds.
- ICMP drop: passed.
- TCP/8080 drop: passed; listener events stayed `114 -> 114`.
- UDP/1080 drop: passed; listener events stayed `15 -> 15`.
- Restored policy to `enabled=False`; ping recovered.

Final state:

- compute-a:
  - `neutron_server`: healthy
  - `neutron_aria_agent`: running
  - `openstack_client`: healthy
- compute-b:
  - `neutron_server`: healthy
  - `neutron_aria_agent`: running
  - `openstack_client`: healthy
- compute-c:
  - no `neutron_server` container observed
  - `neutron_aria_agent`: running
  - `openstack_client`: healthy
- Test policy `496aa1ae-0119-4fcd-a7df-ec4574856371` restored to `enabled=False`.
- Test port `ff0b04e9-c1b3-4779-ae63-7e6d2a966a50` returned to `effective_action=bypass`, `status=degraded`, reason `policy_missing_or_disabled`.
