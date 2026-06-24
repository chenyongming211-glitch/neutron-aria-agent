# aria-datapath Kolla Packaging

`aria-datapath` is the privileged local datapath service. It owns tap
discovery, OVS identity validation, eBPF load/attach, map updates, runtime
state, and the Neutron UDS endpoint at `/run/aria/aria-agent.sock`.

## Product Boundary

`aria-datapath` is intentionally separate from `neutron-aria-agent`:

- `aria-datapath` runs privileged, or with the minimum kernel/network
  capabilities supported by the target runtime.
- `aria-datapath` mounts `/sys/fs/bpf`, `/run/openvswitch`, `/run/aria`, and
  `/var/lib/aria-agent`.
- `neutron-aria-agent` stays non-privileged and communicates only through the
  UDS socket.

## Config

The OpenStack product config is:

```text
deploy/kolla/config/aria-agent-openstack.toml
```

Important defaults:

```toml
mode = "neutron_managed"
auto_attach = false
neutron_socket_path = "/run/aria/aria-agent.sock"
ovs_bridge = "br-int"
```

With `auto_attach=false`, existing `tap*` interfaces remain untouched until
`neutron-aria-agent` submits an explicit snapshot.

## Required Mounts

```text
/run/aria:/run/aria
/run/openvswitch:/run/openvswitch
/sys/fs/bpf:/sys/fs/bpf
/sys/kernel/btf/vmlinux:/sys/kernel/btf/vmlinux:ro
/var/lib/aria-agent:/var/lib/aria-agent
/var/log/kolla/aria-datapath:/var/log/kolla/aria-datapath
```

Initial smoke can use `--privileged --net=host`. A later hardening pass should
replace privileged mode with the smallest working capability set for the
target kernel and container runtime.

## Smoke

After downloading CI artifacts into `release/`, run:

```bash
sudo deploy/kolla/smoke/aria_datapath_container_smoke.sh
```

The smoke builds an `aria-datapath:smoke` image from the current Kolla base,
starts a privileged host-network container, verifies the required mounts and
UDS endpoint, checks Neutron UDS capabilities/status, and submits a fake
compute OVS port candidate. The expected result is `ovs_iface_id_not_found`,
which proves local OVS validation is happening inside `aria-datapath`.

The smoke is intentionally non-destructive. It does not create a test VM port
or add an interface to `br-int`; real eligible-port attach/cleanup should be
run as a separate live-environment gate with an explicit test VM port.
