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
            classify_acl_runtime_schema(Some(&metadata), 0),
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
            classify_acl_runtime_schema(Some(&metadata), 1),
            AclRuntimeSchemaDisposition::RefuseLive {
                reason: "acl_runtime_schema_mismatch_live".to_string(),
            }
        );
    }

    #[test]
    fn acl_runtime_schema_current_metadata_is_adopted() {
        let metadata = AclRuntimeMetadata {
            runtime_schema: ACL_RUNTIME_SCHEMA_VERSION,
            acl_policy_key_schema: ACL_POLICY_KEY_SCHEMA_VERSION,
        };

        assert_eq!(
            classify_acl_runtime_schema(Some(&metadata), 3),
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
            classify_acl_runtime_schema(Some(&metadata), 0),
            AclRuntimeSchemaDisposition::Adopt
        );

        std::fs::remove_dir_all(state_path).unwrap();
    }
}
