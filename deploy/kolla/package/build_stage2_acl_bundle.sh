#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="${REPO_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)}"
OUT_DIR="${OUT_DIR:-${REPO_ROOT}/dist/kolla}"
BUNDLE_NAME="${BUNDLE_NAME:-neutron-aria-stage2-acl-kolla-bundle.tgz}"
BUNDLE_PATH="${BUNDLE_PATH:-${OUT_DIR}/${BUNDLE_NAME}}"
STAGING_DIR="${STAGING_DIR:-${OUT_DIR}/stage2-acl-bundle}"
EGG_NAME="${EGG_NAME:-neutron_aria-0.1.0-py2.7.egg}"
NETADDR_WHEEL_NAME="${NETADDR_WHEEL_NAME:-netaddr-0.7.19-py2.py3-none-any.whl}"
NETADDR_WHEEL_SHA256="${NETADDR_WHEEL_SHA256:-56b3558bd71f3f6999e4c52e349f38660e54a7a8a9943335f73dfc96883e08ca}"
NETADDR_WHEEL_PATH="${NETADDR_WHEEL_PATH:-${REPO_ROOT}/dist/kolla/python2-wheels/${NETADDR_WHEEL_NAME}}"
PACKAGE_VERSION="${PACKAGE_VERSION:-0.1.0}"
SOURCE_TREEISH="${SOURCE_TREEISH:-HEAD}"
SOURCE_COMMIT="$(git -C "${REPO_ROOT}" rev-parse "${SOURCE_TREEISH}^{commit}")"
SOURCE_DATE_EPOCH="$(git -C "${REPO_ROOT}" show -s --format=%ct "${SOURCE_COMMIT}")"
PRODUCT_VERSION="$(git -C "${REPO_ROOT}" show "${SOURCE_COMMIT}:VERSION" | tr -d '[:space:]')"
RELEASE_VERSION="v${PRODUCT_VERSION}"
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
    "${REPO_ROOT}/VERSION" \
    "${REPO_ROOT}/LICENSE" \
    "${REPO_ROOT}/CHANGELOG.md" \
    "${REPO_ROOT}/Cargo.toml" \
    "${REPO_ROOT}/abi/src/lib.rs" \
    "${REPO_ROOT}/ebpf/src/maps.rs" \
    "${REPO_ROOT}/release/support-matrix.json" \
    "${REPO_ROOT}/release/runtime-compatibility.json" \
    "${REPO_ROOT}/ci/create_release_manifest.py" \
    "${REPO_ROOT}/docs/neutron-uds-contract.json" \
    "${REPO_ROOT}/deploy/kolla/package" \
    "${REPO_ROOT}/deploy/kolla/smoke" \
    "${REPO_ROOT}/deploy/kolla/config/neutron-aria-agent.ini" \
    "${REPO_ROOT}/deploy/kolla/neutron-aria-agent/README.md" \
    "${REPO_ROOT}/deploy/kolla/aria-datapath/README.md"
do
    require_path "${path}"
done

require_path "${NETADDR_WHEEL_PATH}"
actual_netaddr_sha256="$(sha256sum "${NETADDR_WHEEL_PATH}" | awk '{print $1}')"
if [ "${actual_netaddr_sha256}" != "${NETADDR_WHEEL_SHA256}" ]; then
    echo "netaddr wheel SHA-256 mismatch: ${actual_netaddr_sha256}" >&2
    exit 1
fi

rm -rf "${STAGING_DIR}"
mkdir -p "${OUT_DIR}" "${STAGING_DIR}"

# Release input is one exact Git commit, never arbitrary untracked, staged, or
# modified working-tree files. This prevents field evidence and local tools
# from leaking into a public bundle.
(
    cd "${REPO_ROOT}"
    git archive --format=tar "${SOURCE_TREEISH}" -- \
        Cargo.toml VERSION LICENSE CHANGELOG.md \
        abi/src/lib.rs \
        ebpf/src/maps.rs \
        release/support-matrix.json \
        release/runtime-compatibility.json \
        ci/create_release_manifest.py \
        docs/neutron-uds-contract.json \
        openstack/neutron_aria \
        openstack/neutronclient_aria \
        deploy/kolla/package \
        deploy/kolla/smoke \
        deploy/kolla/config \
        deploy/kolla/neutron-aria-agent \
        deploy/kolla/aria-datapath
) | tar -xf - -C "${STAGING_DIR}"

for path in \
    "${STAGING_DIR}/VERSION" \
    "${STAGING_DIR}/LICENSE" \
    "${STAGING_DIR}/CHANGELOG.md" \
    "${STAGING_DIR}/abi/src/lib.rs" \
    "${STAGING_DIR}/ebpf/src/maps.rs" \
    "${STAGING_DIR}/release/support-matrix.json" \
    "${STAGING_DIR}/release/runtime-compatibility.json" \
    "${STAGING_DIR}/ci/create_release_manifest.py" \
    "${STAGING_DIR}/deploy/kolla/package/aria_upgrade_control.py" \
    "${STAGING_DIR}/deploy/kolla/package/install_aria_datapath_rc_image.sh"
do
    require_path "${path}"
done

mkdir -p "${STAGING_DIR}/dist/kolla"
egg_path="${OUT_DIR}/${EGG_NAME}"
EGG_PATH="${egg_path}" \
    OUT_DIR="${OUT_DIR}" \
    REPO_ROOT="${STAGING_DIR}" \
    SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH}" \
    bash "${STAGING_DIR}/deploy/kolla/package/build_neutron_aria_egg.sh"
cp -a "${OUT_DIR}/${EGG_NAME}" "${STAGING_DIR}/dist/kolla/${EGG_NAME}"
mkdir -p "${STAGING_DIR}/dist/kolla/python2-wheels"
cp -a "${NETADDR_WHEEL_PATH}" \
    "${STAGING_DIR}/dist/kolla/python2-wheels/${NETADDR_WHEEL_NAME}"

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

Install or roll back that image without restarting the datapath or OVS:

```bash
sudo IMAGE_REF=<registry-or-local-image>:<immutable-tag> \
  IMAGE_TAR=<optional-image-tar-or-tar-gz> \
  EXPECTED_IMAGE_ID=sha256:<image-id> \
  CANDIDATE_CONFIG_SOURCE=/path/to/candidate-neutron-aria-agent.ini \
  ROLLBACK_CONFIG_SOURCE=/path/to/previous-neutron-aria-agent.ini \
  deploy/kolla/package/install_neutron_aria_agent_rc_image.sh install
sudo deploy/kolla/package/install_neutron_aria_agent_rc_image.sh check
sudo deploy/kolla/package/install_neutron_aria_agent_rc_image.sh rollback
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

Install a manifest-pinned datapath image while retaining the previous
container as a rollback point:

```bash
sudo IMAGE_REF=<registry-or-local-image>:<immutable-tag> \
  IMAGE_TAR=<optional-image-tar> \
  EXPECTED_IMAGE_ID=sha256:<image-id> \
  EXPECTED_ARIA_SHA256=<aria-agent-sha256> \
  EXPECTED_EBPF_SHA256=<ebpf-sha256> \
  EXPECTED_EBPF_PERF_SHA256=<ebpf-perf-sha256> \
  deploy/kolla/package/install_aria_datapath_rc_image.sh install
sudo deploy/kolla/package/install_aria_datapath_rc_image.sh check
```

Rollback changes only `aria_datapath`; it never restarts OVS or the Neutron
OVS agent:

```bash
sudo deploy/kolla/package/install_aria_datapath_rc_image.sh rollback
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

Persist the verified profile through the Kolla host configuration only after
the peercred-capable datapath image is installed. The installer discovers the
numeric Neutron identity from the running agent container, atomically updates
the mounted host config, tightens `/run/aria`, restarts only `aria_datapath`,
and verifies both an allowed and a denied peer:

```bash
sudo deploy/kolla/package/install_aria_uds_peercred_profile.sh apply
sudo deploy/kolla/package/install_aria_uds_peercred_profile.sh check
```

Rollback restores the latest config and runtime-directory preimage and
restarts only `aria_datapath`:

```bash
sudo deploy/kolla/package/install_aria_uds_peercred_profile.sh rollback
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

Read-only enforcement-gap alert check:

```bash
sudo REPO_ROOT=$(pwd) \
  deploy/kolla/smoke/neutron_aria_acl_enforcement_gap_smoke.sh
```

Exit `0` means every currently expected ACL port has exact non-stale
`ready/enforce` evidence. Exit `2` emits one `ALERT` line per enforcement gap;
exit `1` means the check itself failed. The check never changes ACL or OVS
state.

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
        echo "created_utc=$(date -u -d "@${SOURCE_DATE_EPOCH}" '+%Y-%m-%dT%H:%M:%SZ')"
        echo "package_version=${PACKAGE_VERSION}"
        echo "product_version=${PRODUCT_VERSION}"
        echo "release_version=${RELEASE_VERSION}"
        echo "source_commit=${SOURCE_COMMIT}"
        echo "recommended_image_tag=${RECOMMENDED_IMAGE_TAG}"
        echo "egg=dist/kolla/${EGG_NAME}"
        echo "python2_dependency=dist/kolla/python2-wheels/${NETADDR_WHEEL_NAME}"
        echo "python2_dependency_sha256=${NETADDR_WHEEL_SHA256}"
        echo "gate=deploy/kolla/smoke/neutron_aria_acl_stage2_gate_smoke.sh"
        echo "db_migration=deploy/kolla/smoke/neutron_aria_acl_db_migration_smoke.sh"
        echo "agent_installer=deploy/kolla/package/install_neutron_aria_agent_egg.sh"
        echo "legacy_cli_installer=deploy/kolla/package/install_neutronclient_aria_cli.sh"
        echo "legacy_cli_package=openstack/neutronclient_aria"
        echo "agent_image_builder=deploy/kolla/package/build_neutron_aria_agent_image.sh"
        echo "agent_rc_installer=deploy/kolla/package/install_neutron_aria_agent_rc_image.sh"
        echo "datapath_image_builder=deploy/kolla/package/build_aria_datapath_image.sh"
        echo "datapath_rc_installer=deploy/kolla/package/install_aria_datapath_rc_image.sh"
        echo "uds_peercred_profile_installer=deploy/kolla/package/install_aria_uds_peercred_profile.sh"
        echo "uds_hardened_rollout=deploy/kolla/smoke/neutron_aria_uds_hardened_rollout_smoke.sh"
        echo "acl_enforcement_gap_check=deploy/kolla/smoke/neutron_aria_acl_enforcement_gap_smoke.sh"
        echo "image_tar_policy=optional_requires_KOLLA_NEUTRON_AGENT_BASE_IMAGE"
        echo "datapath_image_tar_policy=optional_requires_KOLLA_ARIA_DATAPATH_BASE_IMAGE_or_onsite_BASE_IMAGE"
    } > MANIFEST.txt
)

python3 "${STAGING_DIR}/ci/create_release_manifest.py" \
    --repo-root "${STAGING_DIR}" \
    --source-commit "${SOURCE_COMMIT}" \
    --artifact "dist/kolla/${EGG_NAME}=${STAGING_DIR}/dist/kolla/${EGG_NAME}" \
    --artifact "dist/kolla/python2-wheels/${NETADDR_WHEEL_NAME}=${STAGING_DIR}/dist/kolla/python2-wheels/${NETADDR_WHEEL_NAME}" \
    --output "${STAGING_DIR}/release-manifest.json" \
    --checksums-output "${STAGING_DIR}/SHA256SUMS"

rm -f "${BUNDLE_PATH}"
find "${STAGING_DIR}" -type d -exec chmod 0755 {} +
find "${STAGING_DIR}" -type f -exec chmod 0644 {} +
find "${STAGING_DIR}" -type f -name '*.sh' -exec chmod 0755 {} +
find "${STAGING_DIR}" -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +
(
    cd "${STAGING_DIR}"
    tar --sort=name --mtime="@${SOURCE_DATE_EPOCH}" \
        --owner=0 --group=0 --numeric-owner --format=gnu -cf - . |
        gzip -n >"${BUNDLE_PATH}"
)

log "Built ${BUNDLE_PATH}"
