# Heartbeat V2 Kolla Image Acceptance

## Candidate Identity

- Source commit: `c0b9e726e7e732a1ba38ed6601d61ec751687f70`
- Image tag: `neutron-aria-agent:v0.9.0-rc.1-heartbeat-v2-c0b9e72`
- Image ID: `sha256:8cc14273f02595d0383e01abf9318e55c476b56df88e97e7f59bc7b003a0a120`
- Image archive SHA-256: `6c037402505ea0576a5b3ffc4a07aa3c6af0dc0765fe19409c1d40b1bb944b48`
- Installed image egg SHA-256: `5f48e6391ec09864a1e54da998f7f60eff3431bb979dd7583945d3e145ee917a`

The image was built once on the target Kolla/Python 2 image family, exported,
and loaded on the other compute nodes. All three nodes therefore run the same
image ID rather than separate host-local builds.

## Container-Rebuild Acceptance

The rollout recreated only `neutron_aria_agent`. On every compute node:

- the running image ID matches the candidate;
- the image and running container report Heartbeat schema V2;
- `heartbeat_detail_mode=summary_only` is loaded from the Kolla host config;
- the Neutron agent remains alive;
- the heartbeat summary and P3 projection fields are present;
- legacy per-item heartbeat collections are absent;
- the dedicated ACL port-status API remains available;
- the serialized `agent-show` payload remains below 16 KiB.

The Aria datapath and Neutron OVS agent container identities and start times did
not change during build, install, check, rollback, or reinstallation.

## Image Rollback

Compute node 2 completed an image-level rollback and reinstallation:

1. The V2 candidate container was removed.
2. A fresh container was created from the recorded previous image ID.
3. The previous Kolla config was restored.
4. The runtime and Neutron API returned to the previous heartbeat contract.
5. The V2 image was reinstalled and the three-node V2 gate passed again.

This validates rollback to the previous image, not reuse of a modified
container writable layer.

## Immediate ACL Regression

After all three containers were rebuilt from the V2 image, a real three-node
ACL regression passed:

- ICMP, TCP/8080, and UDP/1080 enforcement;
- binding enable and disable;
- individual TCP rule enable and disable;
- policy enable and disable;
- policy, rule, and binding identity in port status;
- delete cleanup and normal-traffic rollback.

All temporary ACL objects were removed after the regression.

## Stability Test

A new 12-hour stability test started at approximately `2026-08-13T02:33Z`
and is expected to finish at approximately `2026-08-13T14:33Z`.

The test is currently `running`, not yet recorded as passed. It includes:

- per-node readiness, generation, RSS, FD, thread, WAL, and pin sampling;
- three-node ICMP drop with TCP/8080 and UDP/1080 allow traffic;
- final ACL cleanup and connectivity rollback.

The first runtime and ACL traffic samples passed on all three nodes.
