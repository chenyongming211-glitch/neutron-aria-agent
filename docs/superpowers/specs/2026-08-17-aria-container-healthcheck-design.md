# Aria Kolla Container Healthcheck Design

## Status

Implemented RC baseline for the v0.9 Neutron integration.

The target maintenance-aware health contract is defined in
`2026-08-21-aria-planned-maintenance-upgrade-design.md`. The current strict
Docker-health behavior below remains a description of deployed RC behavior,
but it is superseded as the target design: Docker health will represent
liveness, `/readyz` will remain strict ACL readiness, and `/status` will expose
recognized maintenance bypass.

## Goal

Expose meaningful Docker `healthy` / `unhealthy` state for both
`aria_datapath` and `neutron_aria_agent` so operators can see whether the Aria
ACL path is strictly ready from `docker ps` and `docker inspect`.

## Health Semantics

Docker `healthy` means the local Aria ACL path is strictly ready. Any
`degraded`, `bypass`, `blocked`, `unknown`, or recovery state is unhealthy.

An unhealthy Aria container means that the Aria enhancement is not ready. It
does not mean that OVS forwarding is down. Health checks must never restart or
modify OVS, `ovs-vswitchd`, or the Neutron OVS agent.

## Datapath Probe

The `aria_datapath` image provides a dedicated healthcheck script that:

1. verifies the local TCP liveness endpoint `/api/v1/health` returns success;
2. verifies `/run/aria/aria-agent.sock` exists;
3. runs the UDS `/readyz` request as the `neutron` user so peercred enforcement
   uses the same identity as the real Python agent;
4. succeeds only when `/readyz` returns HTTP 200.

The script must not weaken the UDS UID/GID allow-list or add root to it.

## Python Agent Probe

The `neutron_aria_agent` image provides a dedicated healthcheck script that:

1. verifies the UDS socket exists;
2. calls UDS `/readyz` as the container's existing `neutron` user;
3. succeeds only when `/readyz` returns HTTP 200.

Docker already reports the container as exited when its PID 1 agent process
terminates. The v0.9 probe does not add a second watchdog process or poll the
Neutron API on every health interval.

## Docker Policy

Both images override inherited base-image health checks with:

- interval: 30 seconds;
- timeout: 5 seconds;
- start period: 60 seconds;
- retries: 3.

The start period permits startup WAL replay and normal full-resync convergence.
After startup, three consecutive failures mark the container unhealthy. A
later successful strict-ready probe returns it to healthy automatically.

## Packaging And Installation

The two healthcheck scripts are copied into their respective Kolla images with
mode `0755`. Image-level `HEALTHCHECK` declarations ensure both ordinary Kolla
container creation and the existing RC installers inherit the same contract.

RC installer `check` and post-install verification must require:

- the expected image and artifact identities;
- existing endpoint/readiness checks;
- Docker health status `healthy`.

Rollback continues to replace only the Aria container. It must not restart or
modify OVS or the Neutron OVS agent.

## Verification

CI and container smoke coverage must verify:

1. both Dockerfiles define the intended health check;
2. both scripts pass shell syntax checks;
3. a strict-ready runtime becomes healthy;
4. a degraded or bypass runtime becomes unhealthy after the configured
   threshold;
5. recovery to strict-ready returns the same container to healthy;
6. RC install, check, and rollback preserve OVS and OVS-agent identities.

## Non-Goals

- no automatic restart or remediation policy;
- no OVS or ovs-agent health ownership;
- no external monitoring backend;
- no periodic Neutron API authentication from Docker health checks;
- no new Python-agent watchdog or heartbeat timestamp file;
- no QoS or Mirror readiness expansion.
