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

Heartbeat-only mode needs Neutron RPC access only. Full-resync mode additionally
needs OVS and local Aria access:

```text
/run/aria:/run/aria
/var/run/openvswitch:/var/run/openvswitch
/var/log/kolla/neutron:/var/log/kolla/neutron
```

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

[neutron]
port_source = disabled
rpc_events_enabled = false
```

This should make `neutron agent-list` show:

```text
Aria ACL agent | <compute-fqdn> | :-) | True | neutron-aria-agent
```

It must not submit an empty snapshot and must not touch any tap datapath.

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

## Full Resync Gate

Do not enable full resync until all of these are true:

- `aria-agent` is deployed in `neutron_managed` mode.
- `/run/aria/aria-agent.sock` is mounted into this container.
- `/var/run/openvswitch` is mounted and `ovs-vsctl list-ports br-int` works.
- OS_* credentials are provided to the container for legacy neutronclient.
- `[neutron] port_source = neutronclient`.
- `[agent] full_resync_enabled = true`.

If credentials or OVS are missing, `neutron-aria-agent` should remain alive but
degraded, and retry full resync with exponential backoff.
