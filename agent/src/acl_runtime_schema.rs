use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

pub(crate) const ACL_RUNTIME_SCHEMA_VERSION: u32 = 3;
pub(crate) const ACL_POLICY_KEY_SCHEMA_VERSION: u32 = 2;

const ACL_RUNTIME_METADATA_FILE: &str = "acl-runtime-schema.json";
const ACL_RUNTIME_METADATA_TEMP_FILE: &str = "acl-runtime-schema.json.tmp";
const PERSISTED_LIVE_IFACES_SCHEMA_VERSION: u32 = 2;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AclRuntimeMetadata {
    pub(crate) runtime_schema: u32,
    pub(crate) acl_policy_key_schema: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum AclRuntimeSchemaDisposition {
    Adopt,
    RebuildDormant,
    RefuseLive { reason: String },
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct ManagedRuntimeActivity {
    pub(crate) link_pin_count: usize,
    pub(crate) persisted_iface_count: usize,
}

impl ManagedRuntimeActivity {
    fn may_be_live(self) -> bool {
        self.link_pin_count != 0 || self.persisted_iface_count != 0
    }
}

#[derive(Debug, Deserialize)]
struct PersistedLiveIfacesEvidence {
    schema_version: u32,
    ifaces: Vec<PersistedLiveIfaceEvidence>,
}

#[derive(Debug, Deserialize)]
struct PersistedLiveIfaceEvidence {
    iface: String,
    ifindex: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AclRuntimeSchemaPreparation {
    Adopted,
    RebuiltDormant,
}

pub(crate) fn current_acl_runtime_metadata() -> AclRuntimeMetadata {
    AclRuntimeMetadata {
        runtime_schema: ACL_RUNTIME_SCHEMA_VERSION,
        acl_policy_key_schema: ACL_POLICY_KEY_SCHEMA_VERSION,
    }
}

pub(crate) fn classify_acl_runtime_schema(
    metadata: Option<&AclRuntimeMetadata>,
    activity: ManagedRuntimeActivity,
) -> AclRuntimeSchemaDisposition {
    if metadata == Some(&current_acl_runtime_metadata()) {
        return AclRuntimeSchemaDisposition::Adopt;
    }
    if metadata.is_some_and(|metadata| {
        metadata.runtime_schema > ACL_RUNTIME_SCHEMA_VERSION
            || metadata.acl_policy_key_schema > ACL_POLICY_KEY_SCHEMA_VERSION
    }) {
        return AclRuntimeSchemaDisposition::RefuseLive {
            reason: "acl_runtime_schema_future".to_string(),
        };
    }
    if !activity.may_be_live() {
        AclRuntimeSchemaDisposition::RebuildDormant
    } else {
        AclRuntimeSchemaDisposition::RefuseLive {
            reason: "acl_runtime_schema_mismatch_live".to_string(),
        }
    }
}

fn persisted_live_ifaces_path(
    base_state_path: &Path,
    shared_pin_path: &Path,
) -> Result<PathBuf, String> {
    let namespace = shared_pin_path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            format!(
                "managed runtime pin path has no UTF-8 namespace: {}",
                shared_pin_path.display()
            )
        })?;
    Ok(base_state_path.join(format!(".{}.live-ifaces.json", namespace)))
}

fn count_persisted_live_ifaces(
    base_state_path: &Path,
    shared_pin_path: &Path,
) -> Result<usize, String> {
    let path = persisted_live_ifaces_path(base_state_path, shared_pin_path)?;
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => {
            return Err(format!(
                "read persisted live ifaces {}: {}",
                path.display(),
                error
            ));
        }
    };
    let evidence: PersistedLiveIfacesEvidence = serde_json::from_slice(&bytes)
        .map_err(|error| format!("parse persisted live ifaces {}: {}", path.display(), error))?;
    if evidence.schema_version != 1
        && evidence.schema_version != PERSISTED_LIVE_IFACES_SCHEMA_VERSION
    {
        return Err(format!(
            "persisted live ifaces schema {} is unsupported (expected 1 or {})",
            evidence.schema_version, PERSISTED_LIVE_IFACES_SCHEMA_VERSION
        ));
    }
    for entry in &evidence.ifaces {
        if entry.iface.trim().is_empty() || entry.ifindex == 0 {
            return Err(format!(
                "persisted live ifaces {} contains an invalid interface identity",
                path.display()
            ));
        }
    }
    Ok(evidence.ifaces.len())
}

pub(crate) fn inventory_managed_runtime_activity(
    base_state_path: &Path,
    shared_pin_path: &Path,
) -> Result<ManagedRuntimeActivity, String> {
    Ok(ManagedRuntimeActivity {
        link_pin_count: count_managed_link_pins(shared_pin_path)?,
        // Legacy clsact TC attachments do not have a pinnable link object. The
        // durable interface reservation is therefore live-safety evidence, not
        // merely bookkeeping. Unknown or malformed evidence is an error so the
        // caller cannot classify an uncertain runtime as dormant.
        persisted_iface_count: count_persisted_live_ifaces(base_state_path, shared_pin_path)?,
    })
}

fn metadata_path(base_state_path: &Path) -> PathBuf {
    base_state_path.join(ACL_RUNTIME_METADATA_FILE)
}

fn metadata_temp_path(base_state_path: &Path) -> PathBuf {
    base_state_path.join(ACL_RUNTIME_METADATA_TEMP_FILE)
}

pub(crate) fn load_acl_runtime_metadata(
    base_state_path: &Path,
) -> Result<Option<AclRuntimeMetadata>, String> {
    let path = metadata_path(base_state_path);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_file() => metadata,
        Ok(_) => {
            return Err(format!(
                "ACL runtime metadata path is not a regular file: {}",
                path.display()
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!(
                "inspect ACL runtime metadata {}: {}",
                path.display(),
                error
            ));
        }
    };
    if metadata.len() == 0 {
        return Err(format!("ACL runtime metadata is empty: {}", path.display()));
    }
    let bytes = fs::read(&path)
        .map_err(|error| format!("read ACL runtime metadata {}: {}", path.display(), error))?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| format!("parse ACL runtime metadata {}: {}", path.display(), error))
}

fn remove_stale_metadata_temp(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => fs::remove_file(path)
            .map_err(|error| format!("remove stale ACL runtime metadata {}: {}", path.display(), error)),
        Ok(_) => Err(format!(
            "stale ACL runtime metadata path is not a regular file: {}",
            path.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "inspect stale ACL runtime metadata {}: {}",
            path.display(),
            error
        )),
    }
}

pub(crate) fn publish_acl_runtime_metadata(
    base_state_path: &Path,
    metadata: &AclRuntimeMetadata,
) -> Result<(), String> {
    fs::create_dir_all(base_state_path).map_err(|error| {
        format!(
            "create ACL runtime metadata directory {}: {}",
            base_state_path.display(),
            error
        )
    })?;
    let path = metadata_path(base_state_path);
    let temp_path = metadata_temp_path(base_state_path);
    remove_stale_metadata_temp(&temp_path)?;

    let mut bytes = serde_json::to_vec(metadata)
        .map_err(|error| format!("serialize ACL runtime metadata: {}", error))?;
    bytes.push(b'\n');
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp_path)
        .map_err(|error| {
            format!(
                "create ACL runtime metadata {}: {}",
                temp_path.display(),
                error
            )
        })?;
    let mut writer = BufWriter::new(file);
    writer.write_all(&bytes).map_err(|error| {
        format!(
            "write ACL runtime metadata {}: {}",
            temp_path.display(),
            error
        )
    })?;
    writer.flush().map_err(|error| {
        format!(
            "flush ACL runtime metadata {}: {}",
            temp_path.display(),
            error
        )
    })?;
    writer.get_ref().sync_all().map_err(|error| {
        format!(
            "fsync ACL runtime metadata {}: {}",
            temp_path.display(),
            error
        )
    })?;
    drop(writer);

    fs::rename(&temp_path, &path).map_err(|error| {
        format!(
            "publish ACL runtime metadata {}: {}",
            path.display(),
            error
        )
    })?;
    File::open(base_state_path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            format!(
                "fsync ACL runtime metadata directory {}: {}",
                base_state_path.display(),
                error
            )
        })
}

pub(crate) fn count_managed_link_pins(shared_pin_path: &Path) -> Result<usize, String> {
    match fs::symlink_metadata(shared_pin_path) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => {
            return Err(format!(
                "managed runtime pin path is not a directory: {}",
                shared_pin_path.display()
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => {
            return Err(format!(
                "inspect managed runtime pin path {}: {}",
                shared_pin_path.display(),
                error
            ));
        }
    }
    let mut count = 0usize;
    for entry in fs::read_dir(shared_pin_path).map_err(|error| {
        format!(
            "read managed runtime pin path {}: {}",
            shared_pin_path.display(),
            error
        )
    })? {
        let entry = entry.map_err(|error| {
            format!(
                "read managed runtime pin entry {}: {}",
                shared_pin_path.display(),
                error
            )
        })?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if ["_xdp_link", "_tc_egress_link", "_tc_ingress_link"]
            .iter()
            .any(|suffix| name.ends_with(suffix))
        {
            count = count
                .checked_add(1)
                .ok_or_else(|| "managed runtime link pin count overflow".to_string())?;
        }
    }
    Ok(count)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AclRuntimeSchemaPreparationPhase {
    AfterDurableFamilyMigration,
}

fn managed_state_directories(base_state_path: &Path) -> Result<Vec<PathBuf>, String> {
    let mut directories = Vec::new();
    let entries = match fs::read_dir(base_state_path) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(directories),
        Err(error) => {
            return Err(format!(
                "read managed state root {}: {}",
                base_state_path.display(),
                error
            ));
        }
    };
    for entry in entries {
        let entry = entry.map_err(|error| {
            format!(
                "read managed state entry {}: {}",
                base_state_path.display(),
                error
            )
        })?;
        let file_type = entry.file_type().map_err(|error| {
            format!(
                "inspect managed state entry {}: {}",
                entry.path().display(),
                error
            )
        })?;
        if !file_type.is_dir() {
            continue;
        }

        let state_path = entry.path();
        if entry.file_name() == "system" {
            // The system-wide standalone state has its own authority and is
            // migrated by SystemManager/KernelDropManager, never by the
            // Neutron-managed runtime-schema transaction.
            continue;
        }
        let mut contains_state = false;
        for file_name in ["state.json", "state.wal"] {
            let file_path = state_path.join(file_name);
            match fs::symlink_metadata(&file_path) {
                Ok(metadata) if metadata.file_type().is_file() => contains_state = true,
                Ok(_) => {
                    return Err(format!(
                        "managed state path is not a regular file: {}",
                        file_path.display()
                    ));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!(
                        "inspect managed state path {}: {}",
                        file_path.display(),
                        error
                    ));
                }
            }
        }
        if contains_state {
            directories.push(state_path);
        }
    }
    directories.sort();
    Ok(directories)
}

fn durably_migrate_managed_acl_states(base_state_path: &Path) -> Result<(), String> {
    for state_path in managed_state_directories(base_state_path)? {
        let iface = state_path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                format!(
                    "managed ACL state path has no UTF-8 interface name: {}",
                    state_path.display()
                )
            })?;
        let state_path_str = state_path.to_str().ok_or_else(|| {
            format!(
                "managed ACL state path is not UTF-8: {}",
                state_path.display()
            )
        })?;
        aria_core::wal::load_with_wal_for_authority(
            state_path_str,
            aria_core::state::LegacyAclMigrationAuthority::ManagedLegacyIpv4,
        )
        .map_err(|error| format!("migrate managed ACL state {}: {}", iface, error))?;
    }
    Ok(())
}

pub(crate) fn prepare_acl_runtime_schema(
    base_state_path: &Path,
    shared_pin_path: &Path,
    activity: ManagedRuntimeActivity,
) -> Result<AclRuntimeSchemaPreparation, String> {
    prepare_acl_runtime_schema_with_hook(base_state_path, shared_pin_path, activity, |_| Ok(()))
}

fn prepare_acl_runtime_schema_with_hook<F>(
    base_state_path: &Path,
    shared_pin_path: &Path,
    activity: ManagedRuntimeActivity,
    mut hook: F,
) -> Result<AclRuntimeSchemaPreparation, String>
where
    F: FnMut(AclRuntimeSchemaPreparationPhase) -> Result<(), String>,
{
    let metadata = load_acl_runtime_metadata(base_state_path)?;
    let disposition = classify_acl_runtime_schema(metadata.as_ref(), activity);
    if matches!(
        &disposition,
        AclRuntimeSchemaDisposition::RefuseLive { reason }
            if reason == "acl_runtime_schema_future"
    ) {
        return Err("acl_runtime_schema_future".to_string());
    }

    // A known runtime schema may be rebuilt or adopted only after every
    // per-interface core snapshot and local WAL has reached durable family
    // form. Each checkpoint is idempotent, so a crash partway through this
    // loop resumes without publishing a premature runtime schema.
    durably_migrate_managed_acl_states(base_state_path)?;
    hook(AclRuntimeSchemaPreparationPhase::AfterDurableFamilyMigration)?;

    match disposition {
        AclRuntimeSchemaDisposition::Adopt => Ok(AclRuntimeSchemaPreparation::Adopted),
        AclRuntimeSchemaDisposition::RefuseLive { reason } => Err(reason),
        AclRuntimeSchemaDisposition::RebuildDormant => {
            match fs::symlink_metadata(shared_pin_path) {
                Ok(pin_metadata) if pin_metadata.file_type().is_dir() => {
                    fs::remove_dir_all(shared_pin_path).map_err(|error| {
                        format!(
                            "remove dormant managed runtime pin directory {}: {}",
                            shared_pin_path.display(),
                            error
                        )
                    })?;
                }
                Ok(_) => {
                    return Err(format!(
                        "dormant managed runtime pin path is not a directory: {}",
                        shared_pin_path.display()
                    ));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!(
                        "inspect dormant managed runtime pin path {}: {}",
                        shared_pin_path.display(),
                        error
                    ));
                }
            }
            publish_acl_runtime_metadata(base_state_path, &current_acl_runtime_metadata())?;
            Ok(AclRuntimeSchemaPreparation::RebuiltDormant)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aria_core::common::IP_FAMILY_V4;
    use aria_core::state::FirewallState;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_state_path(name: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should follow the Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "aria-acl-runtime-schema-{}-{}-{}",
            name,
            std::process::id(),
            nanos
        ))
    }

    fn old_runtime_metadata() -> AclRuntimeMetadata {
        AclRuntimeMetadata {
            runtime_schema: 2,
            acl_policy_key_schema: 1,
        }
    }

    fn write_legacy_managed_state(path: &Path) {
        std::fs::create_dir_all(path).unwrap();
        let mut state = FirewallState::default();
        state
            .apply_add_rule(0, 0, 6, 0, Some("443"), 0, IP_FAMILY_V4)
            .unwrap();
        state.rules[0].ip_family = 0;
        std::fs::write(
            path.join("state.json"),
            serde_json::to_vec_pretty(&state).unwrap(),
        )
        .unwrap();
        std::fs::write(path.join("state.wal"), b"").unwrap();
    }

    #[test]
    fn acl_runtime_schema_dormant_old_pins_require_rebuild() {
        let metadata = AclRuntimeMetadata {
            runtime_schema: 2,
            acl_policy_key_schema: 1,
        };

        assert_eq!(
            classify_acl_runtime_schema(
                Some(&metadata),
                ManagedRuntimeActivity::default(),
            ),
            AclRuntimeSchemaDisposition::RebuildDormant
        );
    }

    #[test]
    fn acl_runtime_schema_live_old_links_refuse_cleanup() {
        let metadata = AclRuntimeMetadata {
            runtime_schema: 2,
            acl_policy_key_schema: 1,
        };

        assert_eq!(
            classify_acl_runtime_schema(
                Some(&metadata),
                ManagedRuntimeActivity {
                    link_pin_count: 1,
                    persisted_iface_count: 0,
                },
            ),
            AclRuntimeSchemaDisposition::RefuseLive {
                reason: "acl_runtime_schema_mismatch_live".to_string(),
            }
        );
    }

    #[test]
    fn acl_runtime_schema_future_metadata_is_always_refused() {
        let future_versions = [
            AclRuntimeMetadata {
                runtime_schema: ACL_RUNTIME_SCHEMA_VERSION + 1,
                acl_policy_key_schema: ACL_POLICY_KEY_SCHEMA_VERSION,
            },
            AclRuntimeMetadata {
                runtime_schema: ACL_RUNTIME_SCHEMA_VERSION,
                acl_policy_key_schema: ACL_POLICY_KEY_SCHEMA_VERSION + 1,
            },
        ];
        let activities = [
            ManagedRuntimeActivity::default(),
            ManagedRuntimeActivity {
                link_pin_count: 1,
                persisted_iface_count: 1,
            },
        ];

        for metadata in future_versions {
            for activity in activities {
                assert_eq!(
                    classify_acl_runtime_schema(Some(&metadata), activity),
                    AclRuntimeSchemaDisposition::RefuseLive {
                        reason: "acl_runtime_schema_future".to_string(),
                    }
                );
            }
        }
    }

    #[test]
    fn acl_runtime_schema_legacy_tc_inventory_refuses_cleanup_without_link_pin() {
        let state_path = temp_state_path("legacy-tc-state");
        let pin_root = temp_state_path("legacy-tc-pins");
        let pin_path = pin_root.join("global-v2");
        std::fs::create_dir_all(&state_path).unwrap();
        std::fs::create_dir_all(&pin_path).unwrap();
        std::fs::write(
            state_path.join(".global-v2.live-ifaces.json"),
            br#"{"schema_version":2,"ifaces":[{"iface":"tap-legacy","ifindex":17,"active":true}]}"#,
        )
        .unwrap();
        let old = AclRuntimeMetadata {
            runtime_schema: 2,
            acl_policy_key_schema: 1,
        };
        publish_acl_runtime_metadata(&state_path, &old).unwrap();

        let activity = inventory_managed_runtime_activity(&state_path, &pin_path)
            .expect("legacy TC inventory must be readable without a link pin");
        assert_eq!(activity.link_pin_count, 0);
        assert_eq!(activity.persisted_iface_count, 1);
        assert_eq!(
            classify_acl_runtime_schema(Some(&old), activity),
            AclRuntimeSchemaDisposition::RefuseLive {
                reason: "acl_runtime_schema_mismatch_live".to_string(),
            }
        );
        assert_eq!(
            prepare_acl_runtime_schema(&state_path, &pin_path, activity).unwrap_err(),
            "acl_runtime_schema_mismatch_live"
        );
        assert!(pin_path.exists(), "live legacy TC pins must not be removed");
        assert_eq!(load_acl_runtime_metadata(&state_path).unwrap(), Some(old));

        std::fs::remove_dir_all(state_path).unwrap();
        std::fs::remove_dir_all(pin_root).unwrap();
    }

    #[test]
    fn acl_runtime_schema_malformed_legacy_inventory_blocks_cleanup() {
        let state_path = temp_state_path("malformed-legacy-tc-state");
        let pin_root = temp_state_path("malformed-legacy-tc-pins");
        let pin_path = pin_root.join("global-v2");
        std::fs::create_dir_all(&state_path).unwrap();
        std::fs::create_dir_all(&pin_path).unwrap();
        std::fs::write(
            state_path.join(".global-v2.live-ifaces.json"),
            b"not-json",
        )
        .unwrap();

        let error = inventory_managed_runtime_activity(&state_path, &pin_path).unwrap_err();

        assert!(error.contains("parse persisted live ifaces"));
        assert!(pin_path.exists(), "unknown legacy activity must fail safely");
        std::fs::remove_dir_all(state_path).unwrap();
        std::fs::remove_dir_all(pin_root).unwrap();
    }

    #[test]
    fn acl_runtime_schema_current_metadata_is_adopted() {
        let metadata = AclRuntimeMetadata {
            runtime_schema: ACL_RUNTIME_SCHEMA_VERSION,
            acl_policy_key_schema: ACL_POLICY_KEY_SCHEMA_VERSION,
        };

        assert_eq!(
            classify_acl_runtime_schema(
                Some(&metadata),
                ManagedRuntimeActivity {
                    link_pin_count: 3,
                    persisted_iface_count: 0,
                },
            ),
            AclRuntimeSchemaDisposition::Adopt
        );
    }

    #[test]
    fn acl_runtime_schema_metadata_publish_is_crash_restart_idempotent() {
        let state_path = temp_state_path("idempotent");
        let metadata = current_acl_runtime_metadata();

        publish_acl_runtime_metadata(&state_path, &metadata)
            .expect("first metadata publication should succeed");
        let first = std::fs::read(state_path.join("acl-runtime-schema.json"))
            .expect("first metadata bytes should exist");
        publish_acl_runtime_metadata(&state_path, &metadata)
            .expect("repeated metadata publication should succeed");
        let second = std::fs::read(state_path.join("acl-runtime-schema.json"))
            .expect("second metadata bytes should exist");

        assert_eq!(first, second);
        assert_eq!(
            load_acl_runtime_metadata(&state_path).unwrap(),
            Some(metadata.clone())
        );
        assert_eq!(
            classify_acl_runtime_schema(
                Some(&metadata),
                ManagedRuntimeActivity::default(),
            ),
            AclRuntimeSchemaDisposition::Adopt
        );

        std::fs::remove_dir_all(state_path).unwrap();
    }

    #[test]
    fn acl_runtime_schema_dormant_pin_directory_is_rebuilt_once() {
        let state_path = temp_state_path("dormant-rebuild-state");
        let pin_path = temp_state_path("dormant-rebuild-pins");
        std::fs::create_dir_all(&pin_path).unwrap();
        std::fs::write(pin_path.join("old-map"), b"legacy").unwrap();
        publish_acl_runtime_metadata(
            &state_path,
            &AclRuntimeMetadata {
                runtime_schema: 2,
                acl_policy_key_schema: 1,
            },
        )
        .unwrap();

        assert_eq!(
            prepare_acl_runtime_schema(
                &state_path,
                &pin_path,
                ManagedRuntimeActivity::default(),
            )
            .unwrap(),
            AclRuntimeSchemaPreparation::RebuiltDormant
        );
        assert!(!pin_path.exists());
        assert_eq!(
            load_acl_runtime_metadata(&state_path).unwrap(),
            Some(current_acl_runtime_metadata())
        );
        assert_eq!(
            prepare_acl_runtime_schema(
                &state_path,
                &pin_path,
                ManagedRuntimeActivity::default(),
            )
            .unwrap(),
            AclRuntimeSchemaPreparation::Adopted
        );

        std::fs::remove_dir_all(state_path).unwrap();
    }

    #[test]
    fn acl_runtime_schema_live_old_pins_are_preserved_on_refusal() {
        let state_path = temp_state_path("live-refusal-state");
        let pin_path = temp_state_path("live-refusal-pins");
        std::fs::create_dir_all(&pin_path).unwrap();
        std::fs::write(pin_path.join("tap0_tc_ingress_link"), b"legacy").unwrap();
        let old = AclRuntimeMetadata {
            runtime_schema: 2,
            acl_policy_key_schema: 1,
        };
        publish_acl_runtime_metadata(&state_path, &old).unwrap();

        let error = prepare_acl_runtime_schema(
            &state_path,
            &pin_path,
            ManagedRuntimeActivity {
                link_pin_count: 1,
                persisted_iface_count: 0,
            },
        )
        .unwrap_err();

        assert_eq!(error, "acl_runtime_schema_mismatch_live");
        assert!(pin_path.join("tap0_tc_ingress_link").exists());
        assert_eq!(load_acl_runtime_metadata(&state_path).unwrap(), Some(old));

        std::fs::remove_dir_all(state_path).unwrap();
        std::fs::remove_dir_all(pin_path).unwrap();
    }

    #[test]
    fn acl_runtime_schema_family_migration_failure_precedes_pin_cleanup_and_publication() {
        let state_path = temp_state_path("migration-failure-state");
        let pin_path = temp_state_path("migration-failure-pins");
        let iface_state_path = state_path.join("tap-migration-failure");
        write_legacy_managed_state(&iface_state_path);
        std::fs::write(iface_state_path.join("state.wal"), b"not-json\n").unwrap();
        std::fs::create_dir_all(&pin_path).unwrap();
        std::fs::write(pin_path.join("old-map"), b"legacy").unwrap();
        let old = old_runtime_metadata();
        publish_acl_runtime_metadata(&state_path, &old).unwrap();

        let error = prepare_acl_runtime_schema(
            &state_path,
            &pin_path,
            ManagedRuntimeActivity::default(),
        )
        .unwrap_err();

        assert!(error.contains("migrate managed ACL state tap-migration-failure"));
        assert!(pin_path.join("old-map").exists());
        assert_eq!(load_acl_runtime_metadata(&state_path).unwrap(), Some(old));

        std::fs::remove_dir_all(state_path).unwrap();
        std::fs::remove_dir_all(pin_path).unwrap();
    }

    #[test]
    fn acl_runtime_schema_crash_after_family_migration_retries_without_rewrite() {
        let state_path = temp_state_path("post-migration-crash-state");
        let pin_path = temp_state_path("post-migration-crash-pins");
        let iface_state_path = state_path.join("tap-post-migration-crash");
        write_legacy_managed_state(&iface_state_path);
        std::fs::create_dir_all(&pin_path).unwrap();
        std::fs::write(pin_path.join("old-map"), b"legacy").unwrap();
        let old = old_runtime_metadata();
        publish_acl_runtime_metadata(&state_path, &old).unwrap();

        let error = prepare_acl_runtime_schema_with_hook(
            &state_path,
            &pin_path,
            ManagedRuntimeActivity::default(),
            |phase| match phase {
                AclRuntimeSchemaPreparationPhase::AfterDurableFamilyMigration => {
                    Err("injected crash after durable family migration".to_string())
                }
            },
        )
        .unwrap_err();

        assert_eq!(error, "injected crash after durable family migration");
        assert!(pin_path.join("old-map").exists());
        assert_eq!(load_acl_runtime_metadata(&state_path).unwrap(), Some(old));
        let migrated_snapshot = std::fs::read(iface_state_path.join("state.json")).unwrap();
        let migrated_wal = std::fs::read(iface_state_path.join("state.wal")).unwrap();
        let migrated: FirewallState = serde_json::from_slice(&migrated_snapshot).unwrap();
        assert_eq!(migrated.rules.len(), 1);
        assert_eq!(migrated.rules[0].ip_family, IP_FAMILY_V4);

        assert_eq!(
            prepare_acl_runtime_schema(
                &state_path,
                &pin_path,
                ManagedRuntimeActivity::default(),
            )
            .unwrap(),
            AclRuntimeSchemaPreparation::RebuiltDormant
        );
        assert!(!pin_path.exists());
        assert_eq!(
            load_acl_runtime_metadata(&state_path).unwrap(),
            Some(current_acl_runtime_metadata())
        );
        assert_eq!(
            std::fs::read(iface_state_path.join("state.json")).unwrap(),
            migrated_snapshot
        );
        assert_eq!(
            std::fs::read(iface_state_path.join("state.wal")).unwrap(),
            migrated_wal
        );

        std::fs::remove_dir_all(state_path).unwrap();
    }

    #[test]
    fn acl_runtime_schema_future_metadata_refuses_before_family_migration() {
        let state_path = temp_state_path("future-before-migration-state");
        let pin_path = temp_state_path("future-before-migration-pins");
        let iface_state_path = state_path.join("tap-future-schema");
        write_legacy_managed_state(&iface_state_path);
        std::fs::create_dir_all(&pin_path).unwrap();
        std::fs::write(pin_path.join("future-map"), b"future").unwrap();
        let future = AclRuntimeMetadata {
            runtime_schema: ACL_RUNTIME_SCHEMA_VERSION + 1,
            acl_policy_key_schema: ACL_POLICY_KEY_SCHEMA_VERSION,
        };
        publish_acl_runtime_metadata(&state_path, &future).unwrap();
        let snapshot_before = std::fs::read(iface_state_path.join("state.json")).unwrap();
        let wal_before = std::fs::read(iface_state_path.join("state.wal")).unwrap();

        assert_eq!(
            prepare_acl_runtime_schema(
                &state_path,
                &pin_path,
                ManagedRuntimeActivity::default(),
            )
            .unwrap_err(),
            "acl_runtime_schema_future"
        );
        assert!(pin_path.join("future-map").exists());
        assert_eq!(load_acl_runtime_metadata(&state_path).unwrap(), Some(future));
        assert_eq!(
            std::fs::read(iface_state_path.join("state.json")).unwrap(),
            snapshot_before
        );
        assert_eq!(
            std::fs::read(iface_state_path.join("state.wal")).unwrap(),
            wal_before
        );

        std::fs::remove_dir_all(state_path).unwrap();
        std::fs::remove_dir_all(pin_path).unwrap();
    }
}
