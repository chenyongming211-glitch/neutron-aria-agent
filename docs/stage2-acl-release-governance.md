# Stage-Two ACL Release Governance

This document freezes the release rules for the v0.9 stage-two ACL production
input path.

## Version Authority

The repository-root `VERSION` file is the only product release-version source.
For the current candidate it contains:

```text
0.9.0-rc.1
```

Release tags and Kolla image tags add a leading `v`. CI rejects a release tag
that does not exactly match `v` plus the manifest product version.

Rust workspace and Python package versions remain component compatibility
versions and are recorded separately in `release-manifest.json`. Changing the
product release label alone must not create an unvalidated datapath binary.

## Component Packages

The Python adapter package version is currently:

```text
neutron-aria==0.1.0
```

The stage-two ACL bundle filename is stable:

```text
neutron-aria-stage2-acl-kolla-bundle.tgz
```

Release tags should use the repository version tag, for example:

```text
v0.9.0-rc.1
```

## Default Release Attachments

Every GitHub tag release must include:

```text
firewall-binaries-x86_64.zip
neutron-aria-stage2-acl-kolla-bundle.tgz
release-manifest.json
SHA256SUMS
```

The binary archive and Kolla bundle include `VERSION`, the MIT `LICENSE`, the
changelog, and `release/support-matrix.json`. The deterministic manifest binds
the source commit, component versions, contract hashes, artifact hashes and,
when built in CI, immutable image identities.

The stage-two ACL Kolla bundle contains the old-Neutron plugin, agent package
builder, DB migration/check scripts, install gate, smoke gates, and operator
instructions.

## Image Tag Policy

The recommended image tag format is:

```text
<registry>/neutron-aria-agent:<repo-version>-stage2-acl
<registry>/aria-datapath:<repo-version>-stage2-acl
```

Example:

```text
registry.example.com/neutron-aria-agent:v0.9.0-rc.1-stage2-acl
registry.example.com/aria-datapath:v0.9.0-rc.1-stage2-acl
```

The `neutron-aria-agent` image must be built from the onsite Kolla Neutron
agent base image, for example:

```text
<onsite-registry>/neutron-openvswitch-agent:2.0.6sp2
```

Do not build the production image from a generic Python image. The old onsite
Neutron runtime depends on Python 2.7, legacy Neutron, oslo libraries, and
python-neutronclient from the Kolla image family.

The `aria-datapath` image must layer the CI/release Rust artifacts onto the
onsite Kolla image family:

```text
release/aria-agent
release/libebpf_firewall.so
release/libebpf_firewall_perf.so
```

This is the image that carries UDS peercred/audit hooks. Do not claim the
site-level UDS hardening gate is complete until this image is deployed, the
socket is tightened from `0666`, and `REQUIRE_HARDENED=true` smoke passes.

## Image Tar Release Policy

Image tar is optional. It should be attached to a release only when CI or the
release host has access to the exact onsite Kolla base image.

In GitHub Actions, set these repository variables to enable image tar
generation:

```text
KOLLA_NEUTRON_AGENT_BASE_IMAGE=<registry>/neutron-openvswitch-agent:<tag>
KOLLA_ARIA_DATAPATH_BASE_IMAGE=<registry>/neutron-openvswitch-agent:<tag>
```

When the variable is absent, CI still publishes the stage-two ACL Kolla bundle.
Operators can build the images from the bundle onsite:

```bash
sudo BASE_IMAGE=<registry>/neutron-openvswitch-agent:<tag> \
  IMAGE_TAG=<registry>/neutron-aria-agent:v0.9.0-rc.1-stage2-acl \
  SAVE_IMAGE=true \
  REPO_ROOT=$(pwd) \
  deploy/kolla/package/build_neutron_aria_agent_image.sh
```

```bash
sudo BASE_IMAGE=<registry>/neutron-openvswitch-agent:<tag> \
  IMAGE_TAG=<registry>/aria-datapath:v0.9.0-rc.1-stage2-acl \
  ARTIFACT_DIR=release \
  SAVE_IMAGE=true \
  REPO_ROOT=$(pwd) \
  deploy/kolla/package/build_aria_datapath_image.sh
```

## Datapath Image Lifecycle

Use the manifest-pinned installer instead of copying files into a running
container:

```bash
sudo IMAGE_REF=<registry-or-local-image>:<immutable-tag> \
  IMAGE_TAR=<optional-image-tar> \
  EXPECTED_IMAGE_ID=sha256:<image-id> \
  EXPECTED_ARIA_SHA256=<aria-agent-sha256> \
  EXPECTED_EBPF_SHA256=<ebpf-sha256> \
  EXPECTED_EBPF_PERF_SHA256=<ebpf-perf-sha256> \
  deploy/kolla/package/install_aria_datapath_rc_image.sh install
```

The installer validates all identities before mutation, discovers the current
datapath state mount, keeps the old container stopped, waits for authenticated
UDS readiness, and verifies that `ovs-vswitchd` and the Neutron OVS agent did
not change. It never restarts either OVS service.

```bash
sudo deploy/kolla/package/install_aria_datapath_rc_image.sh check
sudo deploy/kolla/package/install_aria_datapath_rc_image.sh rollback
```

When no registry is available, the image tar plus manifest and `SHA256SUMS` is
the accepted RC transport. This is not equivalent to production registry
promotion and does not close P6.

## Promotion Boundary

P6-1 may prepare and test RC assets while P5 is incomplete. P5 is evaluated
against the explicitly declared deployment topology, not a permanently fixed
node count. Every admitted compute must pass the same-candidate ACL lifecycle,
UDS peercred, API/DB consistency, rollback, and OVS non-interference gates.

An unavailable node may be removed from the declared topology instead of
blocking indefinitely. It must also be removed from API/DB rotation and must
not be counted in availability claims. If that node later returns, or a
replacement node is added, treat it as a new admission: discover host-local
UID/GID and runtime identities, run `apply` plus `check`, then repeat P5 before
allowing workloads or control-plane traffic on it.

## Release Validation

Before publishing a stage-two ACL release, these checks must pass:

```bash
python3 ci/check_neutron_stage2_acl.py
python3 ci/check_neutron_stage1.py
python3 ci/check_n05_discovery_evidence.py
python3 ci/check_uds_hardening_evidence.py \
  --evidence-dir docs/evidence/openstack-n05-lite/20260630131254-compute-1.example.test \
  --evidence-dir docs/evidence/openstack-n05-lite/20260630133213-compute-2.example.test \
  --evidence-dir docs/evidence/openstack-n05-lite/20260630133213-compute-3.example.test \
  --min-hosts 3 \
  --require-hardened
python3 ci/check_stage2_acceptance_evidence.py
python3 ci/check_stage3_readiness.py
bash deploy/kolla/package/build_stage2_acl_bundle.sh
python3 ci/check_payload_terms.py dist/kolla/neutron-aria-stage2-acl-kolla-bundle.tgz
```

GitHub branch and manual CI builds may compile Rust/eBPF to prove build health,
but they must not retain binary artifacts. Tag releases may upload binaries only
after `ci/check_payload_terms.py` accepts the generated payloads.

On the target Kolla environment, the release bundle gate must pass:

```bash
sudo REPO_ROOT=$(pwd) deploy/kolla/smoke/neutron_aria_acl_stage2_gate_smoke.sh smoke
```

For the UDS hardening gate, evidence-only mode should pass first:

```bash
python3 ci/check_uds_hardening_evidence.py
```

After deploying a peercred-enabled datapath image and tightening socket
permissions, the target environment must also pass:

```bash
sudo REQUIRE_HARDENED=true \
  REPO_ROOT=$(pwd) \
  deploy/kolla/smoke/neutron_aria_uds_hardening_smoke.sh
```

For a reversible per-node proof, prefer the rollout smoke on each target
datapath host. It rewrites the datapath config to `0660 + peercred`, replaces
`aria_datapath` with the supplied test image, probes the UDS from
`neutron_aria_agent` as the `neutron` user, runs the hardened smoke, and
restores the original container/config by default:

```bash
sudo TEST_IMAGE=<registry>/aria-datapath:<peercred-test-tag> \
  HARDENING_SMOKE_SCRIPT=$(pwd)/deploy/kolla/smoke/neutron_aria_uds_hardening_smoke.sh \
  deploy/kolla/smoke/neutron_aria_uds_hardened_rollout_smoke.sh
```

For any environment with multiple active `neutron_server` containers behind one
Neutron API endpoint, install and validate the same bundle on every
`neutron_server` node before declaring the release stable. Mixed old/new plugin
or policy state can return different API fields depending on request routing.

The 2026-06-29 MVP field evidence is recorded in:

```text
docs/evidence/openstack-n05-lite/2026-06-29-stage2-acl/summary.md
```
