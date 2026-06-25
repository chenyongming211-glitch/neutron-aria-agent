use aria_api::{ManagedNeutronPort, NeutronPortStatus};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
    pub(crate) pending_intent: Option<PendingNeutronIntent>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct PendingNeutronIntent {
    pub(crate) kind: String,
    pub(crate) generation: u64,
    pub(crate) desired_hash: Option<String>,
    pub(crate) port_ids: Vec<String>,
    pub(crate) affected_domains: Vec<String>,
    pub(crate) affected_ports: Vec<ManagedNeutronPort>,
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
    #[serde(default)]
    pub(crate) status_hash: Option<String>,
}

#[derive(Serialize)]
struct NeutronWalStatusHashPayload<'a> {
    accepted_generation: u64,
    applied_generation: u64,
    pending_generation: Option<u64>,
    desired_hash: &'a Option<String>,
    applied_desired_hash: &'a Option<String>,
    authority_state: &'a str,
    ports: &'a BTreeMap<String, ManagedNeutronPort>,
    port_statuses: &'a BTreeMap<String, NeutronPortStatus>,
}

impl NeutronWalState {
    fn compute_status_hash(&self) -> Result<String, String> {
        let payload = NeutronWalStatusHashPayload {
            accepted_generation: self.accepted_generation,
            applied_generation: self.applied_generation,
            pending_generation: self.pending_generation,
            desired_hash: &self.desired_hash,
            applied_desired_hash: &self.applied_desired_hash,
            authority_state: &self.authority_state,
            ports: &self.ports,
            port_statuses: &self.port_statuses,
        };
        let bytes = serde_json::to_vec(&payload)
            .map_err(|e| format!("serialize Neutron WAL status hash payload: {}", e))?;
        let digest = Sha256::digest(bytes);
        Ok(digest
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<Vec<_>>()
            .join(""))
    }

    fn with_status_hash(mut self) -> Result<Self, String> {
        self.status_hash = Some(self.compute_status_hash()?);
        Ok(self)
    }

    fn status_hash_valid(&self) -> Result<bool, String> {
        let Some(expected) = self.status_hash.as_ref() else {
            return Ok(true);
        };
        Ok(expected == &self.compute_status_hash()?)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
enum NeutronWalEntry {
    SnapshotIntent {
        generation: u64,
        desired_hash: Option<String>,
        #[serde(default)]
        port_ids: Vec<String>,
        #[serde(default)]
        affected_domains: Vec<String>,
        #[serde(default)]
        affected_ports: Vec<ManagedNeutronPort>,
    },
    SnapshotCommit {
        state: NeutronWalState,
    },
    DeleteIntent {
        port_id: String,
        generation: u64,
        #[serde(default)]
        affected_domains: Vec<String>,
        #[serde(default)]
        port: Option<ManagedNeutronPort>,
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
            pending_intent: None,
        };

        let Ok(file) = File::open(&self.path) else {
            return replay;
        };

        let mut pending_intent: Option<PendingNeutronIntent> = None;
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
                    mut port_ids,
                    affected_domains,
                    affected_ports,
                } => {
                    if port_ids.is_empty() {
                        port_ids = affected_ports
                            .iter()
                            .map(|port| port.port_id.clone())
                            .collect();
                    }
                    pending_intent = Some(PendingNeutronIntent {
                        kind: "snapshot".to_string(),
                        generation,
                        desired_hash,
                        port_ids,
                        affected_domains,
                        affected_ports,
                    });
                }
                NeutronWalEntry::DeleteIntent {
                    port_id,
                    generation,
                    affected_domains,
                    port,
                } => {
                    let affected_ports = port.into_iter().collect();
                    pending_intent = Some(PendingNeutronIntent {
                        kind: "delete".to_string(),
                        generation,
                        desired_hash: None,
                        port_ids: vec![port_id],
                        affected_domains,
                        affected_ports,
                    });
                }
                NeutronWalEntry::SnapshotCommit { state }
                | NeutronWalEntry::DeleteCommit { state } => {
                    match state.status_hash_valid() {
                        Ok(true) => {}
                        Ok(false) => {
                            replay.failures += 1;
                            pending_intent = None;
                            continue;
                        }
                        Err(_) => {
                            replay.failures += 1;
                            pending_intent = None;
                            continue;
                        }
                    }
                    replay.state = state;
                    pending_intent = None;
                }
            }
        }

        if let Some(intent) = pending_intent {
            replay.state.pending_generation = Some(intent.generation);
            replay.state.desired_hash = intent.desired_hash.clone();
            replay.state.authority_state = "wal_intent_without_commit".to_string();
            replay.status = "intent_without_commit".to_string();
            replay.pending_intent = Some(intent);
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
        affected_ports: Vec<ManagedNeutronPort>,
    ) -> Result<(), String> {
        self.append(&NeutronWalEntry::SnapshotIntent {
            generation,
            desired_hash,
            port_ids,
            affected_domains,
            affected_ports,
        })
    }

    pub(crate) fn append_snapshot_commit(&self, state: NeutronWalState) -> Result<(), String> {
        self.append(&NeutronWalEntry::SnapshotCommit {
            state: state.with_status_hash()?,
        })
    }

    pub(crate) fn append_delete_intent(
        &self,
        port_id: String,
        generation: u64,
        affected_domains: Vec<String>,
        port: ManagedNeutronPort,
    ) -> Result<(), String> {
        self.append(&NeutronWalEntry::DeleteIntent {
            port_id,
            generation,
            affected_domains,
            port: Some(port),
        })
    }

    pub(crate) fn append_delete_commit(&self, state: NeutronWalState) -> Result<(), String> {
        self.append(&NeutronWalEntry::DeleteCommit {
            state: state.with_status_hash()?,
        })
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

    fn port_status(port_id: &str, ifname: &str, generation: u64) -> NeutronPortStatus {
        NeutronPortStatus {
            port_id: port_id.to_string(),
            ifname: ifname.to_string(),
            generation,
            desired_hash: Some(format!("hash-{}", generation)),
            status: "ready".to_string(),
            reason: None,
            managed_domains: vec!["acl".to_string()],
            domains: Vec::new(),
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
            vec![managed("p1", "tap-p1")],
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
        assert!(replay.state.status_hash.is_some());
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
            vec![managed("p1", "tap-p1")],
        )
        .unwrap();

        let replay = wal.replay();

        assert_eq!("intent_without_commit", replay.status);
        assert_eq!(Some(8), replay.state.pending_generation);
        assert_eq!("wal_intent_without_commit", replay.state.authority_state);
        let intent = replay.pending_intent.expect("pending intent should replay");
        assert_eq!("snapshot", intent.kind);
        assert_eq!(8, intent.generation);
        assert_eq!(vec!["p1".to_string()], intent.port_ids);
        assert_eq!(
            vec!["acl".to_string(), "qos".to_string()],
            intent.affected_domains
        );
        assert_eq!(vec![managed("p1", "tap-p1")], intent.affected_ports);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn replay_delete_intent_without_commit_preserves_committed_state() {
        let root = temp_state_path();
        let wal = NeutronWal::new(&root);
        let mut ports = BTreeMap::new();
        ports.insert("p1".to_string(), managed("p1", "tap-p1"));
        wal.append_snapshot_commit(NeutronWalState {
            accepted_generation: 11,
            applied_generation: 11,
            applied_desired_hash: Some("hash-11".to_string()),
            authority_state: "ready".to_string(),
            ports,
            ..NeutronWalState::default()
        })
        .unwrap();
        wal.append_delete_intent(
            "p1".to_string(),
            12,
            vec!["attach".to_string(), "acl".to_string()],
            managed("p1", "tap-p1"),
        )
        .unwrap();

        let replay = wal.replay();

        assert_eq!("intent_without_commit", replay.status);
        assert_eq!(11, replay.state.applied_generation);
        assert_eq!(Some(12), replay.state.pending_generation);
        assert!(replay.state.ports.contains_key("p1"));
        let intent = replay.pending_intent.expect("delete intent should replay");
        assert_eq!("delete", intent.kind);
        assert_eq!(12, intent.generation);
        assert_eq!(vec!["p1".to_string()], intent.port_ids);
        assert_eq!(vec![managed("p1", "tap-p1")], intent.affected_ports);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn replay_snapshot_intent_without_commit_preserves_previous_commit() {
        let root = temp_state_path();
        let wal = NeutronWal::new(&root);
        wal.append_snapshot_commit(NeutronWalState {
            accepted_generation: 20,
            applied_generation: 20,
            applied_desired_hash: Some("hash-20".to_string()),
            authority_state: "ready".to_string(),
            ..NeutronWalState::default()
        })
        .unwrap();
        wal.append_snapshot_intent(
            21,
            Some("hash-21".to_string()),
            vec!["p2".to_string()],
            vec!["attach".to_string(), "acl".to_string()],
            vec![managed("p2", "tap-p2")],
        )
        .unwrap();

        let replay = wal.replay();

        assert_eq!("intent_without_commit", replay.status);
        assert_eq!(20, replay.state.applied_generation);
        assert_eq!(Some(21), replay.state.pending_generation);
        assert_eq!(Some("hash-21".to_string()), replay.state.desired_hash);
        assert!(replay.state.ports.is_empty());
        let intent = replay.pending_intent.expect("snapshot intent should replay");
        assert_eq!("snapshot", intent.kind);
        assert_eq!(vec!["attach".to_string(), "acl".to_string()], intent.affected_domains);
        assert_eq!(vec![managed("p2", "tap-p2")], intent.affected_ports);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn replay_snapshot_intent_after_domain_half_apply_preserves_committed_runtime() {
        let root = temp_state_path();
        let wal = NeutronWal::new(&root);
        let mut ports = BTreeMap::new();
        ports.insert("p1".to_string(), managed("p1", "tap-p1"));
        let mut port_statuses = BTreeMap::new();
        port_statuses.insert("p1".to_string(), port_status("p1", "tap-p1", 40));
        wal.append_snapshot_commit(NeutronWalState {
            accepted_generation: 40,
            applied_generation: 40,
            applied_desired_hash: Some("hash-40".to_string()),
            authority_state: "ready".to_string(),
            ports,
            port_statuses,
            ..NeutronWalState::default()
        })
        .unwrap();
        wal.append_snapshot_intent(
            41,
            Some("hash-41".to_string()),
            vec!["p1".to_string()],
            vec![
                "acl".to_string(),
                "attach".to_string(),
                "mirror".to_string(),
                "qos".to_string(),
            ],
            vec![managed("p1", "tap-p1")],
        )
        .unwrap();

        let replay = wal.replay();

        assert_eq!("intent_without_commit", replay.status);
        assert_eq!(40, replay.state.applied_generation);
        assert_eq!(Some(41), replay.state.pending_generation);
        assert_eq!("wal_intent_without_commit", replay.state.authority_state);
        assert!(replay.state.ports.contains_key("p1"));
        assert_eq!(
            Some("ready"),
            replay
                .state
                .port_statuses
                .get("p1")
                .map(|status| status.status.as_str())
        );
        let intent = replay.pending_intent.expect("snapshot intent should replay");
        assert_eq!("snapshot", intent.kind);
        assert_eq!(
            vec![
                "acl".to_string(),
                "attach".to_string(),
                "mirror".to_string(),
                "qos".to_string(),
            ],
            intent.affected_domains
        );
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
            vec![managed("p1", "tap-p1")],
        )
        .unwrap();

        let raw = fs::read_to_string(root.join(WAL_FILE)).unwrap();

        assert!(raw.contains(r#""affected_domains":["acl","mirror","qos"]"#));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn commit_records_status_hash() {
        let root = temp_state_path();
        let wal = NeutronWal::new(&root);
        wal.append_snapshot_commit(NeutronWalState {
            accepted_generation: 30,
            applied_generation: 30,
            authority_state: "ready".to_string(),
            ..NeutronWalState::default()
        })
        .unwrap();

        let raw = fs::read_to_string(root.join(WAL_FILE)).unwrap();

        assert!(raw.contains(r#""status_hash":"#));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn delete_commit_records_status_hash() {
        let root = temp_state_path();
        let wal = NeutronWal::new(&root);
        wal.append_delete_commit(NeutronWalState {
            accepted_generation: 31,
            applied_generation: 31,
            authority_state: "ready".to_string(),
            ..NeutronWalState::default()
        })
        .unwrap();

        let raw = fs::read_to_string(root.join(WAL_FILE)).unwrap();

        assert!(raw.contains(r#""type":"delete_commit""#));
        assert!(raw.contains(r#""status_hash":"#));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn replay_rejects_commit_with_mismatched_status_hash() {
        let root = temp_state_path();
        let wal = NeutronWal::new(&root);
        wal.append_snapshot_commit(NeutronWalState {
            accepted_generation: 31,
            applied_generation: 31,
            authority_state: "ready".to_string(),
            ..NeutronWalState::default()
        })
        .unwrap();
        let path = root.join(WAL_FILE);
        let raw = fs::read_to_string(&path).unwrap();
        let tampered = raw.replace(r#""applied_generation":31"#, r#""applied_generation":32"#);
        assert_ne!(raw, tampered);
        fs::write(&path, tampered).unwrap();

        let replay = wal.replay();

        assert_eq!("replayed_with_errors", replay.status);
        assert_eq!(1, replay.failures);
        assert_eq!(0, replay.state.applied_generation);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn replay_skips_tampered_latest_commit_and_keeps_previous_good_commit() {
        let root = temp_state_path();
        let wal = NeutronWal::new(&root);
        wal.append_snapshot_commit(NeutronWalState {
            accepted_generation: 50,
            applied_generation: 50,
            applied_desired_hash: Some("hash-50".to_string()),
            authority_state: "ready".to_string(),
            ..NeutronWalState::default()
        })
        .unwrap();
        wal.append_snapshot_commit(NeutronWalState {
            accepted_generation: 51,
            applied_generation: 51,
            applied_desired_hash: Some("hash-51".to_string()),
            authority_state: "ready".to_string(),
            ..NeutronWalState::default()
        })
        .unwrap();
        let path = root.join(WAL_FILE);
        let raw = fs::read_to_string(&path).unwrap();
        let mut lines = raw.lines().map(ToOwned::to_owned).collect::<Vec<_>>();
        let last = lines.last_mut().expect("second commit should exist");
        *last = last.replace(r#""applied_generation":51"#, r#""applied_generation":52"#);
        fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();

        let replay = wal.replay();

        assert_eq!("replayed_with_errors", replay.status);
        assert_eq!(1, replay.failures);
        assert_eq!(50, replay.state.applied_generation);
        assert_eq!(Some("hash-50".to_string()), replay.state.applied_desired_hash);
        let _ = fs::remove_dir_all(root);
    }
}
