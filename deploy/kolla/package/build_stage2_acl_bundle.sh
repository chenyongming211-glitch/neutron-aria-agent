#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
OUT_DIR="${OUT_DIR:-${REPO_ROOT}/dist/kolla}"
BUNDLE_NAME="${BUNDLE_NAME:-neutron-aria-stage2-acl-kolla-bundle.tgz}"
BUNDLE_PATH="${BUNDLE_PATH:-${OUT_DIR}/${BUNDLE_NAME}}"
STAGING_DIR="${STAGING_DIR:-${OUT_DIR}/stage2-acl-bundle}"
EGG_NAME="${EGG_NAME:-neutron_aria-0.1.0-py2.7.egg}"
PACKAGE_VERSION="${PACKAGE_VERSION:-0.1.0}"
RELEASE_VERSION="${RELEASE_VERSION:-${GITHUB_REF_NAME:-stage2-acl-dev}}"
RECOMMENDED_IMAGE_TAG="${RECOMMENDED_IMAGE_TAG:-neutron-aria-agent:${RELEASE_VERSION}-stage2-acl}"

log() {
    printf '[neutron-aria-stage2-bundle] %s\n' "$*"
}

require_path() {
    if [ ! -e "$1" ]; then
        echo "Missing required path: $1" >&2
        exit 1
    fi
}

for path in \
    "${REPO_ROOT}/openstack/neutron_aria" \
    "${REPO_ROOT}/openstack/neutronclient_aria" \
    "${REPO_ROOT}/deploy/kolla/package" \
    "${REPO_ROOT}/deploy/kolla/smoke" \
    "${REPO_ROOT}/deploy/kolla/config/neutron-aria-agent.ini" \
    "${REPO_ROOT}/deploy/kolla/neutron-aria-agent/README.md" \
    "${REPO_ROOT}/deploy/kolla/aria-datapath/README.md"
do
    require_path "${path}"
done

mkdir -p "${OUT_DIR}"
EGG_PATH="${OUT_DIR}/${EGG_NAME}" \
    OUT_DIR="${OUT_DIR}" \
    bash "${REPO_ROOT}/deploy/kolla/package/build_neutron_aria_egg.sh"

rm -rf "${STAGING_DIR}"
mkdir -p \
    "${STAGING_DIR}/openstack" \
    "${STAGING_DIR}/deploy/kolla" \
    "${STAGING_DIR}/dist/kolla"

cp -a "${REPO_ROOT}/openstack/neutron_aria" "${STAGING_DIR}/openstack/neutron_aria"
cp -a "${REPO_ROOT}/openstack/neutronclient_aria" "${STAGING_DIR}/openstack/neutronclient_aria"
cp -a "${REPO_ROOT}/deploy/kolla/package" "${STAGING_DIR}/deploy/kolla/package"
cp -a "${REPO_ROOT}/deploy/kolla/smoke" "${STAGING_DIR}/deploy/kolla/smoke"
cp -a "${REPO_ROOT}/deploy/kolla/config" "${STAGING_DIR}/deploy/kolla/config"
cp -a "${REPO_ROOT}/deploy/kolla/neutron-aria-agent" "${STAGING_DIR}/deploy/kolla/neutron-aria-agent"
cp -a "${REPO_ROOT}/deploy/kolla/aria-datapath" "${STAGING_DIR}/deploy/kolla/aria-datapath"
cp -a "${OUT_DIR}/${EGG_NAME}" "${STAGING_DIR}/dist/kolla/${EGG_NAME}"

find "${STAGING_DIR}" -type f -name '*.pyc' -delete
find "${STAGING_DIR}" -type d -name '__pycache__' -prune -exec rm -rf {} +

cat > "${STAGING_DIR}/README-stage2-acl-kolla.md" <<'EOF'
# Neutron Aria Stage-Two ACL Kolla Bundle

This bundle contains the productized stage-two ACL delivery gate for the legacy
onsite Neutron/Kolla runtime.

Package version:

```text
neutron-aria==0.1.0
neutronclient-aria==0.1.0
```

Recommended image tag:

```text
neutron-aria-agent:<release-version>-stage2-acl
```

Recommended install gate:

```bash
sudo REPO_ROOT=$(pwd) deploy/kolla/smoke/neutron_aria_acl_stage2_gate_smoke.sh install
```

The install gate also installs the legacy `neutron aria-acl-*` command
extension into the `openstack_client` container. To validate only that client
package:

```bash
sudo REPO_ROOT=$(pwd) deploy/kolla/package/install_neutronclient_aria_cli.sh smoke
```

Run the install gate on every active neutron-server node behind the Neutron API
endpoint before declaring the API stable. A mixed deployment can randomly return
old extension/policy fields depending on which neutron-server handles a request.
The install gate restarts neutron-server after plugin/policy updates and
restarts neutron-aria-agent after installing the egg so heartbeat payload changes
are loaded by the long-running process.

Read-only N0.5 discovery evidence:

```bash
sudo EVIDENCE_ROOT=/var/tmp/neutron-aria-n05-discovery \
  REPO_ROOT=$(pwd) \
  deploy/kolla/smoke/neutron_aria_n05_discovery_smoke.sh
```

Copy the generated evidence directory back to the repository under
`docs/evidence/openstack-n05-lite/` and update
`docs/openstack-target-env-discovery.md`. Unsupported or degraded facts should
stay visible; the discovery smoke does not enable new features.

Rollback connectivity evidence on a known reachable VM tap:

```bash
sudo EVIDENCE_ROOT=/var/tmp/neutron-aria-rollback-connectivity \
  REPO_ROOT=$(pwd) \
  VM_IP=<reachable-vm-ip> \
  EXPECTED_PORT_ID=<neutron-port-id> \
  EXPECTED_IFNAME=<tap-ifname> \
  CHECK_AGENT_STOP=true \
  CHECK_DATAPATH_STOP=true \
  deploy/kolla/smoke/neutron_aria_rollback_connectivity_smoke.sh
```

Optional image build using the onsite Neutron/Kolla base image:

```bash
sudo BASE_IMAGE=<registry>/neutron-openvswitch-agent:<tag> \
  IMAGE_TAG=<registry>/neutron-aria-agent:<tag> \
  SAVE_IMAGE=true \
  REPO_ROOT=$(pwd) \
  deploy/kolla/package/build_neutron_aria_agent_image.sh
```

Optional datapath image build using CI/release Rust artifacts:

```bash
sudo BASE_IMAGE=<registry>/neutron-openvswitch-agent:<tag> \
  IMAGE_TAG=<registry>/aria-datapath:<tag> \
  ARTIFACT_DIR=release \
  SAVE_IMAGE=true \
  REPO_ROOT=$(pwd) \
  deploy/kolla/package/build_aria_datapath_image.sh
```

For UDS hardening evidence, first record the current peer identity and socket
state without mutating the environment:

```bash
sudo EVIDENCE_ROOT=/var/tmp/neutron-aria-uds-hardening \
  REQUIRE_HARDENED=false \
  REPO_ROOT=$(pwd) \
  deploy/kolla/smoke/neutron_aria_uds_hardening_smoke.sh
```

Only after the peercred-enabled datapath build is deployed and socket
permissions are tightened, run the hardened gate:

```bash
sudo REQUIRE_HARDENED=true \
  REPO_ROOT=$(pwd) \
  deploy/kolla/smoke/neutron_aria_uds_hardening_smoke.sh
```

For a reversible per-node rollout proof, use the hardened rollout smoke with a
peercred-enabled datapath image on each target datapath host. By default it
restores the original container and config after collecting evidence:

```bash
sudo TEST_IMAGE=<registry>/aria-datapath:<peercred-test-tag> \
  HARDENING_SMOKE_SCRIPT=$(pwd)/deploy/kolla/smoke/neutron_aria_uds_hardening_smoke.sh \
  deploy/kolla/smoke/neutron_aria_uds_hardened_rollout_smoke.sh
```

Repeat validation without reinstalling:

```bash
sudo REPO_ROOT=$(pwd) deploy/kolla/smoke/neutron_aria_acl_stage2_gate_smoke.sh smoke
```

Optional live downlink ACL validation on a known reachable VM tap:

```bash
sudo REPO_ROOT=$(pwd) \
  VM_IP=<reachable-vm-ip> \
  EXPECTED_PORT_ID=<neutron-port-id> \
  EXPECTED_IFNAME=<tap-ifname> \
  RUN_LIVE_DOWNLINK_SMOKE=true \
  deploy/kolla/smoke/neutron_aria_acl_stage2_gate_smoke.sh smoke
```

Optional live guest-egress ACL validation on an existing SSH-reachable VM:

```bash
sudo REPO_ROOT=$(pwd) \
  VM_IP=<guest-ip> \
  EXPECTED_PORT_ID=<neutron-port-id> \
  EXPECTED_IFNAME=<tap-ifname> \
  EGRESS_TARGET_IP=<host-or-external-ip> \
  GUEST_SSH_USER=cirros \
  GUEST_SSH_PASSWORD=<guest-password> \
  RUN_LIVE_EGRESS_SMOKE=true \
  deploy/kolla/smoke/neutron_aria_acl_stage2_gate_smoke.sh smoke
```

If no suitable guest exists, the egress smoke can create a temporary CirrOS VM
and remove it after rollback:

```bash
sudo REPO_ROOT=$(pwd) \
  USE_TEMP_VM=true \
  CIRROS_IMAGE_FILE=/var/tmp/cirros.raw \
  CIRROS_IMAGE_DISK_FORMAT=raw \
  NETWORK_ID=<neutron-network-id> \
  BOOT_AZ=nova:$(hostname -f) \
  RUN_LIVE_EGRESS_SMOKE=true \
  deploy/kolla/smoke/neutron_aria_acl_stage2_gate_smoke.sh smoke
```

Rollback:

```bash
sudo REPO_ROOT=$(pwd) deploy/kolla/smoke/neutron_aria_acl_stage2_gate_smoke.sh rollback
```

DB downgrade is intentionally not part of normal rollback. To drop the stage-two
ACL DB tables in a disposable test environment:

```bash
sudo ROLLBACK_DB_ON_ROLLBACK=true REPO_ROOT=$(pwd) \
  deploy/kolla/smoke/neutron_aria_acl_stage2_gate_smoke.sh rollback
```
EOF

(
    cd "${STAGING_DIR}"
    {
        echo "bundle=${BUNDLE_NAME}"
        echo "created_utc=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
        echo "package_version=${PACKAGE_VERSION}"
        echo "release_version=${RELEASE_VERSION}"
        echo "recommended_image_tag=${RECOMMENDED_IMAGE_TAG}"
        echo "egg=dist/kolla/${EGG_NAME}"
        echo "gate=deploy/kolla/smoke/neutron_aria_acl_stage2_gate_smoke.sh"
        echo "db_migration=deploy/kolla/smoke/neutron_aria_acl_db_migration_smoke.sh"
        echo "agent_installer=deploy/kolla/package/install_neutron_aria_agent_egg.sh"
        echo "legacy_cli_installer=deploy/kolla/package/install_neutronclient_aria_cli.sh"
        echo "legacy_cli_package=openstack/neutronclient_aria"
        echo "agent_image_builder=deploy/kolla/package/build_neutron_aria_agent_image.sh"
        echo "datapath_image_builder=deploy/kolla/package/build_aria_datapath_image.sh"
        echo "uds_hardened_rollout=deploy/kolla/smoke/neutron_aria_uds_hardened_rollout_smoke.sh"
        echo "image_tar_policy=optional_requires_KOLLA_NEUTRON_AGENT_BASE_IMAGE"
        echo "datapath_image_tar_policy=optional_requires_KOLLA_ARIA_DATAPATH_BASE_IMAGE_or_onsite_BASE_IMAGE"
    } > MANIFEST.txt
)

rm -f "${BUNDLE_PATH}"
(
    cd "${STAGING_DIR}"
    tar -czf "${BUNDLE_PATH}" .
)

log "Built ${BUNDLE_PATH}"
