# 2026-07-01 Stage-Three UDS Persistent Rollout

Scope: close the stage-three `S3-2 uds-rollout` gate on the 10.58.159 target
environment without expanding QoS, Mirror, or event-driven delta apply.

Remote evidence root:

```text
/tmp/aria-stage3-uds-persistent-rollout-20260701132153
```

## Result

Disposition: `pass`.

The three target hosts now have persistent hardened UDS settings enabled for
the active `aria_datapath` service:

- `/run/aria` is non-world-writable.
- `/run/aria/aria-agent.sock` is `0660` and owned by the Neutron agent group.
- `neutron_peercred_enforce=true` is set in the datapath config.
- The peercred allow-list contains the runtime `neutron_aria_agent` UID/GID.
- The audit log records allowed peercred matches from the Python agent.
- `REQUIRE_HARDENED=true` smoke passed on all three hosts.

## Host Evidence

| Host | Evidence | Smoke Result | Live-State Note |
| --- | --- | --- | --- |
| `ostack2.bj159.net` | `docs/evidence/openstack-n05-lite/20260701132434-ostack2.bj159.net/` | 6 pass, 0 fail | Already running the peercred-capable datapath image; socket stayed `0660`; UDS status stayed `ready`, generation `148`, managed ports `0`. |
| `ostack3.bj159.net` | `docs/evidence/openstack-n05-lite/20260701132436-ostack3.bj159.net/` | 6 pass, 0 fail | Datapath container was rebuilt with the stage-three image and hardened config; post-rollout full-resync submitted generation `19`, status became `commit_written`, managed ports `0`. |
| `ostack4.bj159.net` | `docs/evidence/openstack-n05-lite/20260701132438-ostack4.bj159.net/` | 6 pass, 0 fail | Datapath container was rebuilt with the stage-three image and hardened config; UDS status stayed `ready`, generation `9`, managed ports `0`. |

Validation command:

```bash
python ci/check_uds_hardening_evidence.py --require-hardened
```

Accepted output:

```text
UDS hardening evidence accepted
hosts=3
require_hardened=true
degraded=0
not_applicable=0
```

## Rollout Notes

- The rollout did not restart OVS, OVS agent, or `neutron_aria_agent`.
- The rollout only rebuilt `aria_datapath` on hosts that were still using the
  older non-hardened socket config.
- Existing datapath state mounts were preserved; no state-directory migration
  was attempted as part of this UDS security gate.
- Stopped pre-rollout `aria_datapath` containers were left on `ostack3` and
  `ostack4` as immediate rollback handles.
- `ostack3` had stale smoke-state WAL residue after the image update. A
  one-shot full-resync through the existing agent path advanced the runtime to
  generation `19` and `wal_status=commit_written`; the historical
  `wal_replay_failures=7` counter remains recorded but no managed ports or
  pending generation remained.

## Boundary

This closes the UDS hardening rollout gate. It does not claim final packaging
normalization for the datapath state directory, nor does it enable additional
tenant features.
