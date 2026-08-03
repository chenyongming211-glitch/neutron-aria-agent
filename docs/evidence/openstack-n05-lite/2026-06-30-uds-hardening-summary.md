# 2026-06-30 UDS Hardening Evidence Summary

Scope: stage-two ACL MVP UDS hardening evidence on the 10.58.159 target
environment. This evidence does not enable QoS, Mirror, RabbitMQ event
consumption, or new tenant features.

## Evidence

| Host | Evidence Path | Result |
| --- | --- | --- |
| `compute-1.example.test` | `docs/evidence/openstack-n05-lite/20260630131254-compute-1.example.test/` | hardened proof: 6 pass, 0 degraded, 0 not_applicable, 0 fail |
| `compute-2.example.test` | `docs/evidence/openstack-n05-lite/20260630133213-compute-2.example.test/` | hardened proof: 6 pass, 0 degraded, 0 not_applicable, 0 fail |
| `compute-3.example.test` | `docs/evidence/openstack-n05-lite/20260630133213-compute-3.example.test/` | hardened proof: 6 pass, 0 degraded, 0 not_applicable, 0 fail |
| `compute-1.example.test` | `docs/evidence/openstack-n05-lite/20260630131249-compute-1.example.test-uds-rollout/` | reversible rollout proof: passed and restored original container/config |
| `compute-2.example.test` | `docs/evidence/openstack-n05-lite/20260630133210-compute-2.example.test-uds-rollout/` | reversible rollout proof: passed and restored original container/config |
| `compute-3.example.test` | `docs/evidence/openstack-n05-lite/20260630133210-compute-3.example.test-uds-rollout/` | reversible rollout proof: passed and restored original container/config |
| `compute-1.example.test` | `docs/evidence/openstack-n05-lite/20260701132434-compute-1.example.test/` | persistent hardened proof: 6 pass, 0 fail |
| `compute-2.example.test` | `docs/evidence/openstack-n05-lite/20260701132436-compute-2.example.test/` | persistent hardened proof: 6 pass, 0 fail |
| `compute-3.example.test` | `docs/evidence/openstack-n05-lite/20260701132438-compute-3.example.test/` | persistent hardened proof: 6 pass, 0 fail |

Command:

```bash
EVIDENCE_ROOT=/var/tmp/neutron-aria-uds-hardening \
  REQUIRE_HARDENED=false \
  /tmp/neutron_aria_uds_hardening_smoke.sh
```

Validation:

```bash
python ci/check_uds_hardening_evidence.py
python ci/check_uds_hardening_evidence.py \
  --evidence-dir docs/evidence/openstack-n05-lite/20260630131254-compute-1.example.test \
  --evidence-dir docs/evidence/openstack-n05-lite/20260630133213-compute-2.example.test \
  --evidence-dir docs/evidence/openstack-n05-lite/20260630133213-compute-3.example.test \
  --min-hosts 3 \
  --require-hardened
python ci/check_uds_hardening_evidence.py --require-hardened
```

## Findings

- The peer identity evidence is now recorded for all three hosts.
- `neutron_aria_agent` runs as `neutron` with UID/GID `42435`; its groups are
  `42435 42400`.
- `aria_datapath` currently runs as `root` with UID/GID `0`.
- `/run/aria` is `root:42435 0770` from the host numeric view and appears as
  `root:neutron 0770` inside `neutron_aria_agent`.
- Reversible rollouts on `compute-1.example.test`, `compute-2.example.test`, and
  `compute-3.example.test` with `aria-datapath:peercred-test-202606301305` proved
  the hardened target: `/run/aria/aria-agent.sock` became `root:42435 0660`,
  a UDS probe from the `neutron_aria_agent` container as the `neutron` user
  returned HTTP 200, and the audit log recorded `result=allowed` with
  `reason=peercred_allow_list_match`.
- On 2026-07-01, the hardened settings were left enabled persistently across
  all three target hosts using the peercred-capable stage-three datapath image.
- The active sockets are now `root:42435 0660`; `neutron_peercred_enforce=true`
  and the `neutron_aria_agent` UID/GID allow-list are present in the active
  datapath config.
- `REQUIRE_HARDENED=true` smoke passed on all three hosts with 0 degraded,
  0 not_applicable, and 0 fail.
- The persistent rollout did not restart OVS, OVS agent, or
  `neutron_aria_agent`; only `aria_datapath` was rebuilt where needed.

## Disposition

Repository/config gate: accepted.

The repository now has a UDS hardening smoke, config-gated `SO_PEERCRED`
implementation hooks, and static checks in `ci/check_neutron_stage1.py`.

Site enforcement gate: accepted for three-node reversible proof on
`compute-1.example.test`, `compute-2.example.test`, and `compute-3.example.test`; additionally
accepted for persistent three-node rollout on the same target hosts.

The closure evidence is:

```bash
python ci/check_uds_hardening_evidence.py --require-hardened
```
