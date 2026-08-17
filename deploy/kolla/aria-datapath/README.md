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

## Container Health

The image declares a strict Docker healthcheck. `healthy` means the datapath
TCP liveness endpoint is reachable and the Neutron UDS `/readyz` endpoint
returns HTTP 200 when called with the real `neutron` peer identity. Recovery,
`degraded`, `bypass`, blocked, and unknown states are `unhealthy`.

An unhealthy Aria container does not mean that OVS forwarding is down. The
probe is read-only: it does not restart the container and never restarts or
modifies OVS or the Neutron OVS agent. Docker retries every 30 seconds after a
60-second startup grace period, and a later strict-ready result automatically
returns the existing container to `healthy`.

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

## Product Image Build

Build the deployable datapath image from CI/release Rust artifacts:

```bash
sudo BASE_IMAGE=<registry>/neutron-openvswitch-agent:<tag> \
  IMAGE_TAG=<registry>/aria-datapath:<repo-version>-stage2-acl \
  ARTIFACT_DIR=release \
  SAVE_IMAGE=true \
  REPO_ROOT=$(pwd) \
  deploy/kolla/package/build_aria_datapath_image.sh
```

The artifact directory must contain:

```text
aria-agent
libebpf_firewall.so
libebpf_firewall_perf.so
```

This image carries the UDS peer credential enforcement/audit hooks. Before
turning on enforcement, record the current site identity and socket state:

```bash
sudo EVIDENCE_ROOT=/var/tmp/neutron-aria-uds-hardening \
  REQUIRE_HARDENED=false \
  REPO_ROOT=$(pwd) \
  deploy/kolla/smoke/neutron_aria_uds_hardening_smoke.sh
```

After deploying the peercred-enabled image, tightening the socket from `0666`,
and configuring `neutron_peercred_enforce=true` with the recorded uid/gid
allow-list, run:

```bash
sudo REQUIRE_HARDENED=true \
  REPO_ROOT=$(pwd) \
  deploy/kolla/smoke/neutron_aria_uds_hardening_smoke.sh
```

For deterministic datapath crash testing, the same smoke entrypoint can pass
fault-injection environment variables into the container:

```bash
sudo FAULT_INJECTION_ENABLED=1 \
  FAULT_POINT=neutron.acl.after_policy_write \
  FAULT_ACTION=sigkill \
  FAULT_ONCE_FILE=/run/aria/fault-after-policy.once \
  deploy/kolla/smoke/aria_datapath_container_smoke.sh
```

Fault injection is disabled by default and is intended only for CI or live
smoke validation. `FAULT_ONCE_FILE` should be used for crash actions so a
restarted `--restart unless-stopped` container can recover instead of
re-triggering the same fault point forever.

## Hash-Aware RC Upgrade

Use `deploy/kolla/package/install_aria_datapath_rc_image.sh` for RC install,
check, and rollback. When the active and candidate eBPF hashes match, it keeps
the normal fast container replacement. When they differ, it automatically:

1. stops only `neutron_aria_agent` to quiesce control-plane writes;
2. detaches the exact UDS-reported managed ports and requires zero remaining;
3. preserves the old state and dormant shared pins, then gives the candidate a
   state copy and fresh shared-pin namespace;
4. switches `aria_datapath` while preserving the old container;
5. restarts `neutron_aria_agent` for an authoritative full resync;
6. verifies readiness, generation convergence, image/file hashes, container
   health, and unchanged OVS identities.

Rollback crosses the same boundary in reverse. An unresolved candidate or
failed rollback leaves the Python writer stopped and retains
`/var/lib/aria-datapath-release/active.env.pending`. Correct the recorded
failure and rerun `rollback`; do not delete pinned runtime state manually.
Neither path restarts or modifies OVS or the Neutron OVS agent.
