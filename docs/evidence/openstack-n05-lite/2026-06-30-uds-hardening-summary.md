# 2026-06-30 UDS Hardening Evidence Summary

Scope: stage-two ACL MVP UDS hardening evidence on the 10.58.159 target
environment. This evidence does not enable QoS, Mirror, RabbitMQ event
consumption, or new tenant features.

## Evidence

| Host | Evidence Path | Result |
| --- | --- | --- |
| `ostack2.bj159.net` | `docs/evidence/openstack-n05-lite/20260630131254-ostack2.bj159.net/` | hardened proof: 6 pass, 0 degraded, 0 not_applicable, 0 fail |
| `ostack3.bj159.net` | `docs/evidence/openstack-n05-lite/20260630133213-ostack3.bj159.net/` | hardened proof: 6 pass, 0 degraded, 0 not_applicable, 0 fail |
| `ostack4.bj159.net` | `docs/evidence/openstack-n05-lite/20260630133213-ostack4.bj159.net/` | hardened proof: 6 pass, 0 degraded, 0 not_applicable, 0 fail |
| `ostack2.bj159.net` | `docs/evidence/openstack-n05-lite/20260630131249-ostack2.bj159.net-uds-rollout/` | reversible rollout proof: passed and restored original container/config |
| `ostack3.bj159.net` | `docs/evidence/openstack-n05-lite/20260630133210-ostack3.bj159.net-uds-rollout/` | reversible rollout proof: passed and restored original container/config |
| `ostack4.bj159.net` | `docs/evidence/openstack-n05-lite/20260630133210-ostack4.bj159.net-uds-rollout/` | reversible rollout proof: passed and restored original container/config |

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
  --evidence-dir docs/evidence/openstack-n05-lite/20260630131254-ostack2.bj159.net \
  --evidence-dir docs/evidence/openstack-n05-lite/20260630133213-ostack3.bj159.net \
  --evidence-dir docs/evidence/openstack-n05-lite/20260630133213-ostack4.bj159.net \
  --min-hosts 3 \
  --require-hardened
```

## Findings

- The peer identity evidence is now recorded for all three hosts.
- `neutron_aria_agent` runs as `neutron` with UID/GID `42435`; its groups are
  `42435 42400`.
- `aria_datapath` currently runs as `root` with UID/GID `0`.
- `/run/aria` is `root:42435 0770` from the host numeric view and appears as
  `root:neutron 0770` inside `neutron_aria_agent`.
- The baseline deployed socket is still `root:root 0666` on all three hosts.
  This is smoke-functional but not the target hardened permission model.
- Reversible rollouts on `ostack2.bj159.net`, `ostack3.bj159.net`, and
  `ostack4.bj159.net` with `aria-datapath:peercred-test-202606301305` proved
  the hardened target: `/run/aria/aria-agent.sock` became `root:42435 0660`,
  a UDS probe from the `neutron_aria_agent` container as the `neutron` user
  returned HTTP 200, and the audit log recorded `result=allowed` with
  `reason=peercred_allow_list_match`.
- The rollout smoke restored the original `aria_datapath` container and config
  after collecting evidence; the active baseline container therefore remains on
  the prior `0666` configuration.

## Disposition

Repository/config gate: accepted.

The repository now has a UDS hardening smoke, config-gated `SO_PEERCRED`
implementation hooks, and static checks in `ci/check_neutron_stage1.py`.

Site enforcement gate: accepted for three-node reversible proof on
`ostack2.bj159.net`, `ostack3.bj159.net`, and `ostack4.bj159.net`; not yet
rolled out persistently across all three hosts.

To accept persistent site-level UDS hardening across the environment, deploy a
datapath build with the peercred hooks to every target datapath host, set
`neutron_peercred_enforce=true`, configure an allow-list for the recorded
`neutron_aria_agent` UID/GID, tighten the socket to non-world-writable
permissions, and rerun the smoke with:

```bash
REQUIRE_HARDENED=true /tmp/neutron_aria_uds_hardening_smoke.sh
```

The current `0666` socket on the restored baseline is no longer a proof blocker,
but it remains the work item for persistent hardened rollout.
