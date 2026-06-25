use aria_api::{ManagedNeutronPort, NeutronPortStatus};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

const WAL_FILE: &str = "neutron-snapshot.wal";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct NeutronWalReplay {
    pub(crate) state: NeutronWalState,
    pub(crate) status: String,
    pub(crate) replayed: u64,
    pub(crate) failures: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct NeutronWalState {
    #[serde(default)]
    pub(crate) accepted_generation: u64,
    #[serde(default)]
    pub(crate) applied_generation: u64,
    #[serde(default)]
    pub(crate) pending_generation: Option<u64>,
    #[serde(default)]
    pub(crate) desired_hash: Option<String>,
    #[serde(default)]
    pub(crate) applied_desired_hash: Option<String>,
    #[serde(default)]
    pub(crate) authority_state: String,
    #[serde(default)]
    pub(crate) ports: BTreeMap<String, ManagedNeutronPort>,
    #[serde(default)]
    pub(crate) port_statuses: BTreeMap<String, NeutronPortStatus>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
enum NeutronWalEntry {
    SnapshotIntent {
        generation: u64,
        desired_hash: Option<String>,
        port_ids: Vec<String>,
        #[serde(default)]
        affected_domains: Vec<String>,
    },
    SnapshotCommit {
        state: NeutronWalState,
    },
    DeleteIntent {
        port_id: String,
        generation: u64,
        #[serde(default)]
        affected_domains: Vec<String>,
    },
    DeleteCommit {
        state: NeutronWalState,
    },
}

#[derive(Clone, Debug)]
pub(crate) struct NeutronWal {
    path: PathBuf,
}

impl NeutronWal {
    pub(crate) fn new(base_state_path: impl AsRef<Path>) -> Self {
        Self {
            path: base_state_path.as_ref().join(WAL_FILE),
        }
    }

    pub(crate) fn replay(&self) -> NeutronWalReplay {
        let mut replay = NeutronWalReplay {
            state: NeutronWalState {
                authority_state: "idle".to_string(),
                ..NeutronWalState::default()
            },
            status: "empty".to_string(),
            replayed: 0,
            failures: 0,
        };

        let Ok(file) = File::open(&self.path) else {
            return replay;
        };

        let mut pending_intent: Option<(u64, Option<String>)> = None;
        for line in BufReader::new(file).lines() {
            let Ok(line) = line else {
                replay.failures += 1;
                break;
            };
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let entry = match serde_json::from_str::<NeutronWalEntry>(line) {
                Ok(entry) => entry,
                Err(_) => {
                    replay.failures += 1;
                    continue;
                }
            };
            replay.replayed += 1;
            match entry {
                NeutronWalEntry::SnapshotIntent {
                    generation,
                    desired_hash,
                    ..
                } => {
                    pending_intent = Some((generation, desired_hash));
                }
                NeutronWalEntry::DeleteIntent { generation, .. } => {
                    pending_intent = Some((generation, None));
                }
                NeutronWalEntry::SnapshotCommit { state }
                | NeutronWalEntry::DeleteCommit { state } => {
                    replay.state = state;
                    pending_intent = None;
                }
            }
        }

        if let Some((generation, desired_hash)) = pending_intent {
            replay.state.pending_generation = Some(generation);
            replay.state.desired_hash = desired_hash;
            replay.state.authority_state = "wal_intent_without_commit".to_string();
            replay.status = "intent_without_commit".to_string();
        } else if replay.failures > 0 {
            replay.status = "replayed_with_errors".to_string();
        } else if replay.replayed > 0 {
            replay.status = "replayed".to_string();
        }

        replay
    }

    pub(crate) fn append_snapshot_intent(
        &self,
        generation: u64,
        desired_hash: Option<String>,
        port_ids: Vec<String>,
        affected_domains: Vec<String>,
    ) -> Result<(), String> {
        self.append(&NeutronWalEntry::SnapshotIntent {
            generation,
            desired_hash,
            port_ids,
            affected_domains,
        })
    }

    pub(crate) fn append_snapshot_commit(&self, state: NeutronWalState) -> Result<(), String> {
        self.append(&NeutronWalEntry::SnapshotCommit { state })
    }

    pub(crate) fn append_delete_intent(
        &self,
        port_id: String,
        generation: u64,
        affected_domains: Vec<String>,
    ) -> Result<(), String> {
        self.append(&NeutronWalEntry::DeleteIntent {
            port_id,
            generation,
            affected_domains,
        })
    }

    pub(crate) fn append_delete_commit(&self, state: NeutronWalState) -> Result<(), String> {
        self.append(&NeutronWalEntry::DeleteCommit { state })
    }

    fn append(&self, entry: &NeutronWalEntry) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                format!("create Neutron WAL directory {}: {}", parent.display(), e)
            })?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| format!("open Neutron WAL {}: {}", self.path.display(), e))?;
        let mut writer = BufWriter::new(file);
        let line = serde_json::to_string(entry)
            .map_err(|e| format!("serialize Neutron WAL entry: {}", e))?;
        writer
            .write_all(line.as_bytes())
            .map_err(|e| format!("write Neutron WAL entry: {}", e))?;
        writer
            .write_all(b"\n")
            .map_err(|e| format!("write Neutron WAL newline: {}", e))?;
        writer
            .flush()
            .map_err(|e| format!("flush Neutron WAL: {}", e))?;
        writer
            .get_ref()
            .sync_all()
            .map_err(|e| format!("fsync Neutron WAL: {}", e))?;
        if let Some(parent) = self.path.parent() {
            sync_directory(parent)
                .map_err(|e| format!("fsync Neutron WAL directory {}: {}", parent.display(), e))?;
        }
        Ok(())
    }
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> std::io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_state_path() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("aria-neutron-wal-test-{}", nanos))
    }

    fn managed(port_id: &str, ifname: &str) -> ManagedNeutronPort {
        ManagedNeutronPort {
            port_id: port_id.to_string(),
            ifname: ifname.to_string(),
            ifindex: None,
            managed_domains: vec!["acl".to_string()],
        }
    }

    #[test]
    fn replay_restores_last_committed_state() {
        let root = temp_state_path();
        let wal = NeutronWal::new(&root);
        wal.append_snapshot_intent(
            7,
            Some("hash-7".to_string()),
            vec!["p1".to_string()],
            vec!["acl".to_string()],
        )
        .unwrap();
        let mut ports = BTreeMap::new();
        ports.insert("p1".to_string(), managed("p1", "tap-p1"));
        wal.append_snapshot_commit(NeutronWalState {
            accepted_generation: 7,
            applied_generation: 7,
            applied_desired_hash: Some("hash-7".to_string()),
            authority_state: "ready".to_string(),
            ports,
            ..NeutronWalState::default()
        })
        .unwrap();

        let replay = wal.replay();

        assert_eq!("replayed", replay.status);
        assert_eq!(7, replay.state.applied_generation);
        assert_eq!(Some("hash-7".to_string()), replay.state.applied_desired_hash);
        assert!(replay.state.ports.contains_key("p1"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn replay_reports_intent_without_commit() {
        let root = temp_state_path();
        let wal = NeutronWal::new(&root);
        wal.append_snapshot_intent(
            8,
            Some("hash-8".to_string()),
            vec!["p1".to_string()],
            vec!["acl".to_string(), "qos".to_string()],
        )
        .unwrap();

        let replay = wal.replay();

        assert_eq!("intent_without_commit", replay.status);
        assert_eq!(Some(8), replay.state.pending_generation);
        assert_eq!("wal_intent_without_commit", replay.state.authority_state);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn snapshot_intent_records_affected_domains() {
        let root = temp_state_path();
        let wal = NeutronWal::new(&root);
        wal.append_snapshot_intent(
            9,
            Some("hash-9".to_string()),
            vec!["p1".to_string()],
            vec!["acl".to_string(), "mirror".to_string(), "qos".to_string()],
        )
        .unwrap();

        let raw = fs::read_to_string(root.join(WAL_FILE)).unwrap();

        assert!(raw.contains(r#""affected_domains":["acl","mirror","qos"]"#));
        let _ = fs::remove_dir_all(root);
    }
}
