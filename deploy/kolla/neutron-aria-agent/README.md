# neutron-aria-agent Kolla Packaging

This directory contains the product packaging shape for the compute-side
`neutron-aria-agent` container.

## Build

Use the same base image family as the onsite Neutron agents so the container
inherits Python 2.7, Neutron, oslo.messaging, OVS tools, and legacy
python-neutronclient.

```bash
docker build \
  --build-arg BASE_IMAGE=<registry>/neutron-openvswitch-agent:<tag> \
  -f deploy/kolla/neutron-aria-agent/Dockerfile \
  -t <registry>/neutron-aria-agent:<tag> \
  .
```

The stage-two ACL bundle also includes a wrapper that validates imports and can
save the image as a tar artifact:

```bash
sudo BASE_IMAGE=<registry>/neutron-openvswitch-agent:<tag> \
  IMAGE_TAG=<registry>/neutron-aria-agent:<tag> \
  SAVE_IMAGE=true \
  deploy/kolla/package/build_neutron_aria_agent_image.sh
```

## Release Candidate Image Rollout

Use the image installer when replacing an existing Kolla
`neutron_aria_agent` container. It preserves the current container as an
install-failure recovery point, records the previous image and configuration,
recreates only the Python agent container, and verifies that the Aria datapath
and Neutron OVS agent were not restarted.

```bash
sudo IMAGE_REF=neutron-aria-agent:<candidate-tag> \
  IMAGE_TAR=/path/to/neutron-aria-agent-image.tar.gz \
  EXPECTED_IMAGE_ID=sha256:<image-id> \
  CANDIDATE_CONFIG_SOURCE=/path/to/candidate-neutron-aria-agent.ini \
  ROLLBACK_CONFIG_SOURCE=/path/to/previous-neutron-aria-agent.ini \
  deploy/kolla/package/install_neutron_aria_agent_rc_image.sh install

sudo deploy/kolla/package/install_neutron_aria_agent_rc_image.sh check
sudo deploy/kolla/package/install_neutron_aria_agent_rc_image.sh rollback
```

The installer copies container environment values into a root-only state
directory and never prints them. Rollback creates a fresh container from the
recorded previous image rather than reusing the candidate writable layer.

For a host-local smoke using the currently deployed OVS agent image as the base:

```bash
sudo deploy/kolla/smoke/neutron_aria_container_smoke.sh
```

The smoke starts an independent `neutron_aria_agent` container in
heartbeat-only mode. It does not enable full resync, RPC events, snapshot
submission, or tap datapath writes.

To assert the product container boundary:

```bash
sudo deploy/kolla/smoke/neutron_aria_boundary_smoke.sh
```

The boundary smoke verifies that `neutron_aria_agent` is non-privileged, runs
as `neutron`, and does not mount OVSDB, BPF, or kernel module paths.

For a controlled full-resync gate smoke after local `aria-agent` UDS is ready:

```bash
sudo deploy/kolla/smoke/neutron_aria_full_resync_smoke.sh
```

The full-resync smoke checks `/run/aria`, UDS capabilities, legacy
neutronclient credentials, one candidate snapshot submission, and UDS rollback.
It refuses to continue if the local UDS already has managed ports.

To check whether every currently requested ACL has exact runtime enforcement
evidence, run the read-only enforcement-gap monitor:

```bash
sudo deploy/kolla/smoke/neutron_aria_acl_enforcement_gap_smoke.sh
```

Exit `0` is healthy, exit `2` reports one or more enabled ACL ports that are not
exactly `ready/enforce`, and exit `1` means the check itself failed. This command
does not mutate ACL state or restart any service.

## Stage-Two ACL Install Gate

After the `aria_acl` Neutron plugin is ready for the old onsite Neutron server,
use the stage-two gate instead of hand-copying files into containers:

```bash
sudo deploy/kolla/smoke/neutron_aria_acl_stage2_gate_smoke.sh install
```

The gate performs this fixed sequence:

```text
plugin install -> DB migration upgrade/check -> agent egg install ->
DB/REST CRUD smoke -> NeutronAclSource/full-resync smoke -> health check
```

For a repeat validation without reinstalling:

```bash
sudo deploy/kolla/smoke/neutron_aria_acl_stage2_gate_smoke.sh smoke
```

Rollback restores the backed-up agent egg and neutron-server config/package:

```bash
sudo deploy/kolla/smoke/neutron_aria_acl_stage2_gate_smoke.sh rollback
```

Rollback does not drop `aria_acl` DB tables by default. To explicitly drop the
stage-two ACL tables in a disposable test environment:

```bash
sudo ROLLBACK_DB_ON_ROLLBACK=true \
  deploy/kolla/smoke/neutron_aria_acl_stage2_gate_smoke.sh rollback
```

Local tap/OVS validation is performed by the privileged `aria-datapath`
container behind the UDS socket, not by this container.

## Kolla Config Files

The container expects a Kolla config directory mounted as
`/var/lib/kolla/config_files` with at least:

```text
config.json
neutron.conf
openvswitch_agent.ini
neutron-aria-agent.ini
```

`config.json` can be copied from this directory. `neutron.conf` and
`openvswitch_agent.ini` should be the same effective files used by
`neutron_openvswitch_agent` so the RPC and host conventions match.

## Required Mounts

Product mode needs Neutron config/log access and local Aria UDS access:

```text
/run/aria:/run/aria
/var/log/kolla/neutron:/var/log/kolla/neutron
```

`neutron-aria-agent` should not mount `/sys/fs/bpf`, `/lib/modules`, or
`/run/openvswitch` in the final product shape.

## Log Path

The container command uses `start-neutron-aria-agent`, which appends stdout and
stderr to:

```text
/var/log/kolla/neutron/neutron-aria-agent.log
```

This is the product log location. The mounted host path should therefore expose
the log as:

```text
/var/log/kolla/neutron/neutron-aria-agent.log
```

## Safe Startup

The default config is heartbeat-only:

```ini
[agent]
full_resync_enabled = false
heartbeat_detail_mode = summary_only

[neutron]
port_source = disabled
rpc_events_enabled = false
incremental_rpc_enabled = false
```

This should make `neutron agent-list` show:

```text
Aria ACL agent | <compute-fqdn> | :-) | True | neutron-aria-agent
```

It must not submit an empty snapshot and must not touch any tap datapath.

`summary_only` also keeps `neutron agent-show` independent of the number of
local ports. Per-port ACL runtime detail remains available through the
`aria-acl-port-status` API. Use `legacy_sample` only as a temporary rolling
upgrade compatibility setting; it adds at most three port/event sample rows to
the heartbeat.

## RPC Event Gate

Do not enable RPC event consumption until full resync is already safe. The
first wired event set intentionally matches the onsite legacy OVS agent shape:

```text
port.update
port.delete
network.update
```

When `[neutron] rpc_events_enabled = true`, the container command must keep
passing the same `neutron.conf` and `openvswitch_agent.ini` used by the OVS
agent so oslo.messaging and host naming match the existing deployment.

Before a real RabbitMQ fanout test, run the package-level event path smoke:

```bash
sudo deploy/kolla/smoke/neutron_aria_rpc_event_smoke.sh
```

This smoke does not subscribe to RabbitMQ and does not touch tap datapath. It
validates the installed package's P2 config gate, event merge behavior,
foreign-host filtering, and known-port delete cleanup.

P2 production enablement is per host:

1. Keep packaged defaults at `rpc_events_enabled = false`.
2. Confirm P1 full-resync and rollback are accepted on the host.
3. Confirm real fanout A/B, foreign-host filtering, and source-host cleanup
   evidence exists for the target environment.
4. Flip only `[neutron] rpc_events_enabled = true`.
5. Restart only `neutron_aria_agent` to load the setting.
6. Verify startup log and heartbeat report `sync_mode = rpc_full_resync`.
7. Verify `event_batch_drained`, full-resync recovery, and managed-port
   locality.

Rollback is also per host: set `rpc_events_enabled = false` and restart only
`neutron_aria_agent`. Verify startup log and heartbeat return to
`sync_mode = polling_full_resync`. Keep polling/full-resync enabled so ACL
recovery remains available. Do not restart OVS, OVS agent, neutron-server, or
`aria-datapath` for this switch.

Keep `incremental_rpc_enabled = false` for production P2. P3 port-scoped apply
is implemented behind explicit config gates, but it requires a later controlled
entry gate and must remain disabled in packaged defaults.

## Full Resync Gate

Do not enable full resync until all of these are true:

- `aria-agent` is deployed in `neutron_managed` mode.
- `/run/aria/aria-agent.sock` is mounted into this container.
- OS_* credentials are provided to the container for legacy neutronclient.
- `[neutron] port_source = neutronclient`.
- `[agent] full_resync_enabled = true`.
- `aria-datapath` can validate local OVS/tap state through its own privileged
  runtime.

If credentials or OVS are missing, `neutron-aria-agent` should remain alive but
degraded, and retry full resync with exponential backoff.

In the current target environment, `/run/openvswitch/db.sock` is owned by
`root:root` and is not readable by the image's `neutron` user. That is why
OVSDB access belongs to `aria-datapath`, not `neutron-aria-agent`.
