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

pub(crate) fn prepare_acl_runtime_schema(
    base_state_path: &Path,
    shared_pin_path: &Path,
    activity: ManagedRuntimeActivity,
) -> Result<AclRuntimeSchemaPreparation, String> {
    let metadata = load_acl_runtime_metadata(base_state_path)?;
    match classify_acl_runtime_schema(metadata.as_ref(), activity) {
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
}
