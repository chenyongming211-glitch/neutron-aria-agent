# 2026-07-06 RPC P2 Canary On compute-a

Scope: single-host RPC P2 canary on `compute-a.example.test`.

This evidence validates the P2 contract only:

- `rpc_events_enabled=true`
- `incremental_rpc_enabled=false`
- `revisionless_incremental_mode=disabled`
- `sync_mode=rpc_full_resync`
- RPC event handling triggers full-resync/delete cleanup, not P3 port-scoped
  apply.

## Package Update

The current `neutron_aria-0.1.0-py2.7.egg` was installed into the existing
`neutron_aria_agent` container on `compute-a.example.test`.

The installer:

- backed up the previous container egg under
  `/var/tmp/neutron-aria-agent-package/`
- copied the new egg into `/usr/lib/python2.7/site-packages/`
- restarted only `neutron_aria_agent`
- passed the agent import and entrypoint smoke

OVS, OVS agent, Neutron server, and `aria_datapath` were not restarted for the
agent package update.

## Baseline P1

After the package update, the host remained in P1 polling mode:

```text
sync_mode=polling_full_resync
rpc_events_enabled=false
incremental_rpc_enabled=false
ready=true
degraded=false
managed_ports=14
```

Neutron reported the Aria ACL agent alive on `compute-a.example.test`.

## Package-Level RPC Smoke

Command:

```text
neutron_aria_rpc_event_smoke.sh
```

Result:

```text
rpc_event_package_smoke=pass
```

This validates config gates, `sync_mode` mapping, event merge behavior,
foreign-host filtering, and known-port delete cleanup without subscribing to
RabbitMQ or mutating tap datapath.

## Live Fanout A/B

Command:

```text
AGENT_TIMEOUT=40 STARTUP_WAIT=8 neutron_aria_rpc_fanout_smoke.sh
```

Result:

```text
rpc_fanout_agent_ab=pass
incremental_rpc_enabled=false
revisionless_incremental_mode=disabled
```

Observed behavior:

- disabled temporary agent: `sync_mode=polling_full_resync`; no event batch was
  processed
- enabled temporary agent: `sync_mode=rpc_full_resync`; one `port.update`
  reached `event_batch_drained`
- enabled event path triggered full-resync and kept `ready=true`

## Foreign-Host Filtering

Command:

```text
EVENT_BINDING_HOST=compute-b.example.test
EVENT_PORT_ID=3485b315-e152-42b8-aa55-75dff9d4266c
AGENT_TIMEOUT=55
STARTUP_WAIT=25
neutron_aria_rpc_foreign_host_smoke.sh
```

Result:

```text
rpc_foreign_host_filter=pass
```

Observed behavior:

- foreign `port.update` reached `event_batch_drained`
- only the initial full-resync was recorded
- no extra full-resync was triggered by the foreign-host event
- the foreign port did not appear in local `managed_ports`
- local managed-port count stayed at 14 before rollback

The first attempt with `STARTUP_WAIT=10` failed because the local full-resync
had not converged before the script sampled `initial_managed_ports`. The
successful run used `STARTUP_WAIT=25`.

## Source-Host Cleanup

Command:

```text
EVENT_BINDING_HOST=compute-b.example.test
AGENT_TIMEOUT=60
STARTUP_WAIT=25
neutron_aria_rpc_source_cleanup_smoke.sh
```

Result:

```text
rpc_source_cleanup=pass
```

Observed behavior:

- local projected port `05376f86-e8c0-4219-9983-bea090ae9e25` was selected
- one foreign binding update reached `event_batch_drained`
- local cleanup used `reason=migration_source_cleanup`
- managed-port count changed from 14 to 13 before final rollback
- no extra full-resync was triggered by the source cleanup event

## Persistent P2 Canary

The persistent host config was changed only on `compute-a.example.test`:

```text
rpc_events_enabled=true
incremental_rpc_enabled=false
revisionless_incremental_mode=disabled
```

Only `neutron_aria_agent` was restarted.

Result after convergence:

```text
sync_mode=rpc_full_resync
ready=true
degraded=false
managed_ports=14
```

A persistent live `port.update` was sent for local port
`05376f86-e8c0-4219-9983-bea090ae9e25`.

Observed long-running agent behavior:

```text
event_batch_drained port_updates=1
full_resync_complete generation=230 snapshot_ports=17 managed_ports=14
service_result action=event_batch ready=True degraded=False
```

This proves the long-running P2 agent can consume real RabbitMQ fanout and
recover through the full-resync path.

## Rollback

The P2 config was rolled back on `compute-a.example.test`:

```text
rpc_events_enabled=false
incremental_rpc_enabled=false
revisionless_incremental_mode=disabled
```

Only `neutron_aria_agent` was restarted.

Result:

```text
sync_mode=polling_full_resync
ready=true
degraded=false
managed_ports=14
```

OVS, OVS agent, Neutron server, and `aria_datapath` did not need to be
restarted for rollback.

## Transaction Finding

During the persistent P2 canary, the long-running agent initially reported:

```text
reason=local_api_degraded
pending snapshot hash mismatch: generation=223
```

The datapath UDS status showed a newer applied generation and no runtime
pending generation. The Python agent local state file still had a stale
`pending_generation=223`.

Recovery performed:

- backed up `snapshot-state.json`
- cleared only the stale pending fields
- restarted `neutron_aria_agent`
- full-resync converged to generation `230`
- heartbeat returned to `ready=true`, `degraded=false`

Follow-up:

- add a pre-canary gate that fails fast when Python agent local state contains
  stale pending snapshot metadata
- improve Python agent startup recovery so a stale pending record can be
  reconciled against UDS applied state when the datapath is already converged
- increase live smoke startup waits or wait explicitly for full-resync
  convergence before sampling `managed_ports`

## Follow-Up Retest After Hardening

A follow-up canary was run on `2026-07-06` after adding Python agent stale
pending recovery and RPC smoke convergence waits.

Package deployment:

- rebuilt `dist/kolla/neutron_aria-0.1.0-py2.7.egg`
- installed the egg into `neutron_aria_agent` on `compute-a.example.test`
- restarted only `neutron_aria_agent`
- kept the persistent host in safe P1 mode:

```text
sync_mode=polling_full_resync
rpc_events_enabled=false
incremental_rpc_enabled=false
ready=true
degraded=false
```

Stale pending recovery smoke:

```text
injected_pending_generation=230
remote_generation=231
pending_snapshot_stale_cleared
last_cleared_pending_reason=remote_generation_advanced
pending_generation=null
pending_desired_hash=null
initialize_full_resync ready=True managed_ports=15
```

This validates that an older Python local pending snapshot can be safely
cleared when UDS proves the datapath has already advanced to a newer committed
generation and has no runtime pending generation.

RPC smoke retest:

```text
neutron_aria_rpc_event_smoke.sh: rpc_event_package_smoke=pass
neutron_aria_rpc_fanout_smoke.sh: rpc_fanout_agent_ab=pass
neutron_aria_rpc_foreign_host_smoke.sh: rpc_foreign_host_filter=pass
neutron_aria_rpc_source_cleanup_smoke.sh: rpc_source_cleanup=pass
```

Observed hardening effects:

- fanout disabled case waited for initial full-resync convergence before
  sending a test event
- fanout enabled case waited for initial full-resync convergence, then consumed
  one `port.update` and triggered the P2 full-resync path
- foreign-host test used
  `EVENT_PORT_ID=3485b315-e152-42b8-aa55-75dff9d4266c` on
  `compute-b.example.test`; the event reached the merger but did not mutate
  compute-a managed ports
- source-cleanup test selected local port
  `05376f86-e8c0-4219-9983-bea090ae9e25`; the event deleted only that projected
  source port with `reason=migration_source_cleanup`
- rollback cleanup in the smoke scripts now treats DELETE timeout as
  recoverable: it polls UDS status and retries until the target port disappears
  or the bounded convergence window expires

The retest exposed one useful smoke bug before the rollback hardening:
pre-cleanup could fail on a 3-second UDS DELETE timeout even when the datapath
was able to converge. The smoke scripts were updated to use bounded
delete-convergence retries.

## Three-Node Package Rollout

After the compute-a retest passed, the same egg was rolled to the remaining
compute hosts without enabling persistent RPC mode.

Rollout results:

```text
compute-a.example.test: sync_mode=polling_full_resync, ready=True, managed_ports=15
compute-b.example.test: sync_mode=polling_full_resync, ready=True, managed_ports=0
compute-c.example.test: sync_mode=polling_full_resync, ready=True, managed_ports=3
```

Neutron reported all three Aria ACL agents alive:

```text
compute-a.example.test :-)
compute-b.example.test :-)
compute-c.example.test :-)
```

Only `neutron_aria_agent` containers were restarted during the rollout. OVS,
Neutron server, OVS agent, and `aria_datapath` were not restarted.

## Persistent P2 Short Observation Window

A smaller persistent P2 canary was then run only on `compute-a.example.test`.

Enablement:

```text
backup=/etc/kolla/neutron-aria-agent/neutron-aria-agent.ini.p2-canary-20260706110350.bak
rpc_events_enabled = true
incremental_rpc_enabled = false
revisionless_incremental_mode = disabled
```

Only `neutron_aria_agent` was restarted. The host entered P2 in 4 seconds:

```text
sync_mode=rpc_full_resync
ready=True
degraded=False
generation=245
managed_ports=15
```

Neutron heartbeat confirmed the same runtime mode:

```text
alive=True
configurations.sync_mode=rpc_full_resync
configurations.rpc_events_enabled=true
configurations.ready=true
configurations.degraded=false
configurations.last_managed_ports=15
```

A controlled local `port.update` was sent for:

```text
05376f86-e8c0-4219-9983-bea090ae9e25
```

Observed behavior:

```text
persistent_event_processed_after=2s
event_batch_drained port_updates=1
service_result action=event_batch ready=True degraded=False
full_resync_complete generation=245 snapshot_ports=18 managed_ports=15
```

Observation window:

```text
duration=3 minutes
sample_interval=30 seconds
managed_ports=15 throughout
pending_generation=None throughout
restart_count=0 throughout
bad_log_count=0
full_resync_count=3
heartbeat_ok_count=6
```

No `degraded=True`, `overflowed=True`, `Traceback`, `ERROR`,
`local_api_degraded`, or `pending_snapshot_hash_mismatch_blocked` lines were
seen during the observation window.

Rollback:

```text
restored_backup=/etc/kolla/neutron-aria-agent/neutron-aria-agent.ini.p2-canary-20260706110350.bak
rpc_events_enabled = false
sync_mode=polling_full_resync
ready=True
degraded=False
generation=245
managed_ports=15
pending_generation=None
```

Neutron heartbeat after rollback:

```text
alive=True
configurations.sync_mode=polling_full_resync
configurations.rpc_events_enabled=false
configurations.ready=true
configurations.degraded=false
configurations.last_managed_ports=15
```

## Second-Host Persistent P2 Short Observation Window

The same short persistent P2 canary was repeated on `compute-c.example.test`
because that host had 3 managed tap ports and therefore provided a useful
second-node validation target.

Baseline before enablement:

```text
sync_mode=polling_full_resync
rpc_events_enabled=false
ready=True
degraded=False
generation=18
managed_ports=3
pending_generation=None
```

Enablement:

```text
backup=/etc/kolla/neutron-aria-agent/neutron-aria-agent.ini.p2-canary-20260706112350.bak
rpc_events_enabled = true
incremental_rpc_enabled = false
revisionless_incremental_mode = disabled
```

Only the `neutron_aria_agent` container on `compute-c.example.test` was restarted.
The host entered P2 in 3 seconds:

```text
sync_mode=rpc_full_resync
ready=True
degraded=False
generation=18
managed_ports=3
pending_generation=None
```

Neutron heartbeat confirmed the same runtime mode:

```text
alive=True
configurations.sync_mode=rpc_full_resync
configurations.rpc_events_enabled=true
configurations.ready=true
configurations.degraded=false
configurations.last_managed_ports=3
```

A controlled local `port.update` was sent for:

```text
3af2a77d-9088-45c0-9530-68f8bddd4c4e
```

Observed behavior:

```text
persistent_event_processed_after=2s
event_batch_drained port_updates=1
service_result action=event_batch ready=True degraded=False
full_resync_complete generation=18 snapshot_ports=3 managed_ports=3
```

Observation window:

```text
duration=3 minutes
sample_interval=30 seconds
managed_ports=3 throughout
pending_generation=None throughout
restart_count=0 throughout
bad_log_count=0
full_resync_count=3
heartbeat_ok_count=6
```

No `degraded=True`, `overflowed=True`, `Traceback`, `ERROR`,
`local_api_degraded`, or `pending_snapshot_hash_mismatch_blocked` lines were
seen during the observation window.

Rollback:

```text
restored_backup=/etc/kolla/neutron-aria-agent/neutron-aria-agent.ini.p2-canary-20260706112350.bak
rpc_events_enabled = false
sync_mode=polling_full_resync
ready=True
degraded=False
generation=18
managed_ports=3
pending_generation=None
```

Neutron heartbeat after rollback:

```text
alive=True
configurations.sync_mode=polling_full_resync
configurations.rpc_events_enabled=false
configurations.ready=true
configurations.degraded=false
configurations.last_managed_ports=3
```

## Dual-Host Persistent P2 Parallel Canary

A parallel persistent P2 canary was then run with both `compute-a.example.test` and
`compute-c.example.test` enabled at the same time.

Baseline before enablement:

```text
compute-a.example.test: sync_mode=polling_full_resync, managed_ports=15, pending_generation=None
compute-c.example.test: sync_mode=polling_full_resync, managed_ports=3, pending_generation=None
```

Enablement:

```text
compute-a backup=/etc/kolla/neutron-aria-agent/neutron-aria-agent.ini.dual-p2-canary-20260706113322.bak
compute-c backup=/etc/kolla/neutron-aria-agent/neutron-aria-agent.ini.dual-p2-canary-20260706113326.bak
rpc_events_enabled=true
incremental_rpc_enabled=false
revisionless_incremental_mode=disabled
```

Both hosts entered P2 and reported healthy heartbeat:

```text
compute-a.example.test: sync_mode=rpc_full_resync, ready=True, degraded=False, managed_ports=15
compute-c.example.test: sync_mode=rpc_full_resync, ready=True, degraded=False, managed_ports=3
```

Two controlled `port.update` events were sent:

```text
compute-a.example.test port=05376f86-e8c0-4219-9983-bea090ae9e25
compute-c.example.test port=3af2a77d-9088-45c0-9530-68f8bddd4c4e
```

Observed behavior:

```text
compute-a: event_batch_drained port_updates=2
compute-a: service_result action=event_batch ready=True degraded=False managed_ports=15
compute-c: event_batch_drained port_updates=1
compute-c: event_batch_drained port_updates=1
compute-c: service_result action=event_batch ready=True degraded=False managed_ports=3
```

This confirms that with two agents subscribed to fanout simultaneously,
multiple host events may be observed in the same or adjacent event batches, but
the P2 path still converges through full-resync and keeps local managed-port
state stable.

Parallel observation window:

```text
duration=3 minutes
sample_interval=30 seconds
compute-a managed_ports=15 throughout
compute-c managed_ports=3 throughout
pending_generation=None throughout
restart_count=0 throughout
bad_log_count=0 on both hosts
full_resync_count=3 on both hosts
heartbeat_ok_count=6 on both hosts
```

No `degraded=True`, `overflowed=True`, `Traceback`, `ERROR`,
`local_api_degraded`, or `pending_snapshot_hash_mismatch_blocked` lines were
seen on either host during the parallel observation window.

Rollback:

```text
compute-a: restored dual-p2 backup, sync_mode=polling_full_resync, rpc_events_enabled=false, managed_ports=15
compute-c: restored dual-p2 backup, sync_mode=polling_full_resync, rpc_events_enabled=false, managed_ports=3
```

Neutron heartbeat after rollback confirmed both hosts were alive, ready, not
degraded, and back in `polling_full_resync`.

## Triple-Host Persistent P2 Full Fanout Canary

A full fanout canary was then run with all three compute hosts enabled at the
same time: `compute-a.example.test`, `compute-b.example.test`, and
`compute-c.example.test`.

Baseline before enablement:

```text
compute-a.example.test: sync_mode=polling_full_resync, managed_ports=15, pending_generation=None
compute-b.example.test: sync_mode=polling_full_resync, managed_ports=0, pending_generation=None
compute-c.example.test: sync_mode=polling_full_resync, managed_ports=3, pending_generation=None
```

`compute-b.example.test` had 3 Neutron ports bound to the host but 0 managed ports
in Aria, so it validated the boundary where an agent subscribes to fanout but
must not accidentally claim ineligible or unbound datapath ports.

Enablement:

```text
compute-a backup=/etc/kolla/neutron-aria-agent/neutron-aria-agent.ini.triple-p2-canary-20260706153852.bak
compute-b backup=/etc/kolla/neutron-aria-agent/neutron-aria-agent.ini.triple-p2-canary-20260706153852.bak
compute-c backup=/etc/kolla/neutron-aria-agent/neutron-aria-agent.ini.triple-p2-canary-20260706153852.bak
rpc_events_enabled=true
incremental_rpc_enabled=false
revisionless_incremental_mode=disabled
```

All three hosts entered P2 and reported healthy heartbeat:

```text
compute-a.example.test: sync_mode=rpc_full_resync, ready=True, degraded=False, managed_ports=15
compute-b.example.test: sync_mode=rpc_full_resync, ready=True, degraded=False, managed_ports=0
compute-c.example.test: sync_mode=rpc_full_resync, ready=True, degraded=False, managed_ports=3
```

Three controlled `port.update` events were sent:

```text
compute-a.example.test port=05376f86-e8c0-4219-9983-bea090ae9e25
compute-b.example.test port=3485b315-e152-42b8-aa55-75dff9d4266c
compute-c.example.test port=3af2a77d-9088-45c0-9530-68f8bddd4c4e
```

Observed behavior:

```text
compute-a: event_batch_drained port_updates=1
compute-a: event_batch_drained port_updates=2
compute-a: service_result action=event_batch ready=True degraded=False managed_ports=15

compute-b: event_batch_drained port_updates=1
compute-b: event_batch_drained port_updates=1
compute-b: event_batch_drained port_updates=1
compute-b: service_result action=event_batch ready=True degraded=False managed_ports=0

compute-c: event_batch_drained port_updates=1
compute-c: event_batch_drained port_updates=2
compute-c: service_result action=event_batch ready=True degraded=False managed_ports=3
```

This confirms that all three agents can subscribe to RPC fanout at the same
time. Events may be merged into a single batch or processed in adjacent
batches, but each host remains bounded by its local full-resync view:
`compute-a` stayed at 15 managed ports, `compute-b` stayed at 0, and `compute-c`
stayed at 3.

Parallel observation window:

```text
duration=3 minutes
sample_interval=30 seconds
compute-a managed_ports=15 throughout
compute-b managed_ports=0 throughout
compute-c managed_ports=3 throughout
pending_generation=None throughout
restart_count=0 throughout
bad_log_count=0 on all hosts
full_resync_count=3 on all hosts
heartbeat_ok_count=6 on all hosts
```

No `degraded=True`, `overflowed=True`, `Traceback`, `ERROR`,
`local_api_degraded`, or `pending_snapshot_hash_mismatch_blocked` lines were
seen on any host during the full fanout observation window.

Rollback:

```text
compute-a: restored triple-p2 backup, sync_mode=polling_full_resync, rpc_events_enabled=false, managed_ports=15
compute-b: restored triple-p2 backup, sync_mode=polling_full_resync, rpc_events_enabled=false, managed_ports=0
compute-c: restored triple-p2 backup, sync_mode=polling_full_resync, rpc_events_enabled=false, managed_ports=3
```

Neutron heartbeat after rollback confirmed all three hosts were alive, ready,
not degraded, and back in `polling_full_resync`.

## Triple-Host 30-Minute P2 Soak Gate

After the short triple-host canary, a formal P2 soak gate was added and run in
parallel on `compute-a.example.test`, `compute-b.example.test`, and
`compute-c.example.test`.

The soak gate uses `deploy/kolla/smoke/neutron_aria_rpc_p2_soak_smoke.sh` and
does the following on each host:

- backs up `/etc/kolla/neutron-aria-agent/neutron-aria-agent.ini`
- enables only P2:
  `rpc_events_enabled=true`, `incremental_rpc_enabled=false`,
  `revisionless_incremental_mode=disabled`
- restarts only `neutron_aria_agent`
- waits for `sync_mode=rpc_full_resync` and `full_resync_complete`
- sends one local `port.update` when a bound port is available
- samples UDS status every 30 seconds for 30 minutes
- restores the original config by default on success or failure

Before the passing run, the gate caught and fixed three automation assumptions:

- host Python was available as `python3`, not `python`
- persistent Kolla agent logs are in
  `/var/log/kolla/neutron/neutron-aria-agent.log`, not `docker logs`
- empty status fields must be parsed with stable delimiters so
  `pending_generation=None` is not confused with `accepted_generation`

Passing run:

```text
stamp=20260706160738
duration=30 minutes
sample_interval=30 seconds
samples_per_host=60
```

Startup and event convergence:

```text
compute-a.example.test:
  startup_converged=true waited=2 managed_ports=15 generation=245
  rpc_port_update_sent=05376f86-e8c0-4219-9983-bea090ae9e25
  event_converged=true waited=1 event_batches_before=0 event_batches_after=1

compute-b.example.test:
  startup_converged=true waited=2 managed_ports=0 generation=47
  rpc_port_update_sent=3485b315-e152-42b8-aa55-75dff9d4266c
  event_converged=true waited=1 event_batches_before=0 event_batches_after=2

compute-c.example.test:
  startup_converged=true waited=2 managed_ports=3 generation=18
  rpc_port_update_sent=3af2a77d-9088-45c0-9530-68f8bddd4c4e
  event_converged=true waited=1 event_batches_before=0 event_batches_after=2
```

Final sample before rollback:

```text
compute-a.example.test:
  sample=60 managed_ports=15 generation=245 pending_generation=none
  accepted_generation=245 applied_generation=245 restarts=0 bad_logs=0
  full_resync_count=31 event_batch_count=1

compute-b.example.test:
  sample=60 managed_ports=0 generation=47 pending_generation=none
  accepted_generation=47 applied_generation=47 restarts=0 bad_logs=0
  full_resync_count=31 event_batch_count=2

compute-c.example.test:
  sample=60 managed_ports=3 generation=18 pending_generation=none
  accepted_generation=18 applied_generation=18 restarts=0 bad_logs=0
  full_resync_count=31 event_batch_count=2
```

Result:

```text
compute-a.example.test: rpc_p2_soak=pass
compute-b.example.test: rpc_p2_soak=pass
compute-c.example.test: rpc_p2_soak=pass
```

Rollback verification:

```text
compute-a.example.test:
  config_rpc=false
  config_incremental=false
  config_revisionless=disabled
  last_start=sync_mode=polling_full_resync
  uds_managed_ports=15 generation=245 pending_generation=None
  accepted_generation=245 applied_generation=245

compute-b.example.test:
  config_rpc=false
  config_incremental=false
  config_revisionless omitted in file, default disabled
  last_start=sync_mode=polling_full_resync
  uds_managed_ports=0 generation=47 pending_generation=None
  accepted_generation=47 applied_generation=47

compute-c.example.test:
  config_rpc=false
  config_incremental=false
  config_revisionless omitted in file, default disabled
  last_start=sync_mode=polling_full_resync
  uds_managed_ports=3 generation=18 pending_generation=None
  accepted_generation=18 applied_generation=18
```

Conclusion from the soak:

- P2 can run for a 30-minute production-candidate window on all three compute
  hosts.
- Periodic full-resync remains active while RPC is enabled.
- Fanout subscription does not make `compute-b.example.test` claim ineligible ports.
- No managed-port drift, pending transaction, container restart, degraded log,
  overflow, traceback, local API degradation, or heartbeat failure was observed.
- The gate can be reused as the required acceptance step before making P2 a
  default production mode.

## Conclusion

RPC P2 canary passed on `compute-a.example.test` after clearing stale Python pending
state. The tested P2 path is safe to keep as a per-host canary process:

- package RPC contract passed
- live fanout A/B passed
- foreign-host filtering passed
- source-host cleanup passed
- persistent `rpc_full_resync` mode passed
- rollback to `polling_full_resync` passed
- triple-host 30-minute P2 soak passed and rolled back cleanly

P3 port-scoped apply was not enabled by this canary.
