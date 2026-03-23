use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;
use tokio::sync::{mpsc, oneshot};
use tracing::{info, warn};

use crate::state::FirewallState;

/// Time-based compact interval (5 minutes)
const WAL_COMPACT_INTERVAL_SECS: u64 = 300;
const MAX_BATCH_SIZE: usize = 100;
const WAL_CHANNEL_CAPACITY: usize = 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WalEntry {
    AddGroup { name: String, cidr: String },
    DeleteGroup { name: String },
    AddRule { src_id: u32, dst_id: u32, proto: u8, action: u8, ports: Option<String>, direction: u8 },
    RemoveRule { src_id: u32, dst_id: u32, proto: u8, direction: u8 },
    AddQos { group_name: String, group_id: u32, direction: u8, rate_bps: u64, burst_bytes: u64, priority: u8, #[serde(default)] mode: u8 },
    DeleteQos { group_id: u32, direction: u8 },
    AddMirror { src_group_name: String, src_group_id: u32, dst_group_name: String, dst_group_id: u32, proto: u8, direction: u8, target_iface: String, target_ifindex: u32, is_global: bool },
    DeleteMirror { src_group_id: u32, dst_group_id: u32, proto: u8, direction: u8, is_global: bool },
    UpdateConfig { conntrack: Option<bool>, monitoring: Option<bool>, #[serde(default)] acl: Option<bool>, #[serde(default)] qos: Option<bool>, #[serde(default)] mirror: Option<bool>, #[serde(default)] tcprt: Option<bool>, #[serde(default)] ssl: Option<bool> },
    SetMaxPortPolicies { max: u32 },
    SetAttachedIface { iface: String },
    ClearAttachedIface,
}

pub struct WalWriter {
    file: BufWriter<File>,
    wal_path: PathBuf,
    entry_count: u64,
    last_compact_time: Instant,
}

impl WalWriter {
    pub fn open(state_path: &str) -> Result<Self, String> {
        let wal_path = PathBuf::from(format!("{}/state.wal", state_path));

        // Ensure directory exists
        if let Some(parent) = wal_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create WAL directory: {}", e))?;
        }

        // Count existing valid entries (skip corrupt lines)
        let entry_count = if wal_path.exists() {
            let f = File::open(&wal_path)
                .map_err(|e| format!("Failed to open WAL for counting: {}", e))?;
            BufReader::new(f).lines()
                .filter_map(|l| l.ok())
                .filter(|l| !l.trim().is_empty() && serde_json::from_str::<WalEntry>(l).is_ok())
                .count() as u64
        } else {
            0
        };

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&wal_path)
            .map_err(|e| format!("Failed to open WAL file: {}", e))?;

        Ok(Self {
            file: BufWriter::new(file),
            wal_path,
            entry_count,
            last_compact_time: Instant::now(),
        })
    }

    fn append_buffered(&mut self, entry: &WalEntry) -> Result<(), String> {
        let line = serde_json::to_string(entry)
            .map_err(|e| format!("Failed to serialize WAL entry: {}", e))?;
        self.file.write_all(line.as_bytes())
            .map_err(|e| format!("Failed to write WAL entry: {}", e))?;
        self.file.write_all(b"\n")
            .map_err(|e| format!("Failed to write WAL newline: {}", e))?;
        self.entry_count += 1;
        Ok(())
    }

    fn sync(&mut self) -> Result<(), String> {
        self.file.flush()
            .map_err(|e| format!("Failed to flush WAL: {}", e))?;
        self.file.get_ref().sync_all()
            .map_err(|e| format!("Failed to fsync WAL: {}", e))
    }

    pub fn append(&mut self, entry: &WalEntry) -> Result<(), String> {
        self.append_buffered(entry)?;
        self.sync()
    }

    pub fn entry_count(&self) -> u64 {
        self.entry_count
    }

    /// Check if compact is needed based on entry count threshold or time interval.
    pub fn needs_compact(&self, threshold: u64) -> bool {
        if self.entry_count == 0 {
            return false;
        }
        self.entry_count >= threshold
            || self.last_compact_time.elapsed().as_secs() >= WAL_COMPACT_INTERVAL_SECS
    }

    /// Write a full snapshot to state.json and truncate the WAL.
    /// Accepts pre-serialized JSON to avoid borrow conflicts when wal and state
    /// are fields of the same struct.
    pub fn compact(&mut self, state_json: &str) -> Result<(), String> {
        let state_dir = self.wal_path.parent()
            .ok_or_else(|| "WAL path has no parent directory".to_string())?;
        let state_file = state_dir.join("state.json");
        let tmp_file = state_dir.join("state.json.tmp");

        // Atomic write: tmp + fsync + rename
        let write_result = (|| -> Result<(), std::io::Error> {
            let mut f = File::create(&tmp_file)?;
            f.write_all(state_json.as_bytes())?;
            f.sync_all()?;
            fs::rename(&tmp_file, &state_file)?;
            Ok(())
        })();

        if let Err(e) = write_result {
            let _ = fs::remove_file(&tmp_file);
            return Err(format!("Failed to write snapshot: {}", e));
        }

        // Truncate WAL
        let file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&self.wal_path)
            .map_err(|e| format!("Failed to truncate WAL: {}", e))?;
        self.file = BufWriter::new(file);
        self.entry_count = 0;
        self.last_compact_time = Instant::now();

        Ok(())
    }
}

pub enum WalMessage {
    Append {
        entry: WalEntry,
        ack: oneshot::Sender<Result<(), String>>,
    },
    Compact {
        state_json: String,
        ack: oneshot::Sender<Result<(), String>>,
    },
    Shutdown {
        ack: oneshot::Sender<()>,
    },
}

#[derive(Clone)]
pub struct WalClient {
    sender: mpsc::Sender<WalMessage>,
    entry_count: Arc<AtomicU64>,
    last_compact_time: Arc<Mutex<Instant>>,
}

impl WalClient {
    pub fn open(state_path: &str) -> Result<Self, String> {
        let wal = WalWriter::open(state_path)?;
        let entry_count = Arc::new(AtomicU64::new(wal.entry_count()));
        let last_compact_time = Arc::new(Mutex::new(Instant::now()));
        let (sender, receiver) = mpsc::channel(WAL_CHANNEL_CAPACITY);

        let actor = WalActor {
            wal,
            receiver,
            entry_count: entry_count.clone(),
            last_compact_time: last_compact_time.clone(),
        };

        thread::Builder::new()
            .name("aria-wal-worker".to_string())
            .spawn(move || actor.run())
            .map_err(|e| format!("Failed to spawn WAL thread: {}", e))?;

        Ok(Self {
            sender,
            entry_count,
            last_compact_time,
        })
    }

    pub async fn append(&self, entry: WalEntry) -> Result<(), String> {
        let (ack_tx, ack_rx) = oneshot::channel();
        self.sender
            .send(WalMessage::Append { entry, ack: ack_tx })
            .await
            .map_err(|_| "WAL worker thread died".to_string())?;
        ack_rx
            .await
            .unwrap_or_else(|_| Err("WAL ack channel dropped".to_string()))
    }

    pub async fn compact(&self, state_json: String) -> Result<(), String> {
        let (ack_tx, ack_rx) = oneshot::channel();
        self.sender
            .send(WalMessage::Compact { state_json, ack: ack_tx })
            .await
            .map_err(|_| "WAL worker thread died".to_string())?;
        ack_rx
            .await
            .unwrap_or_else(|_| Err("WAL ack channel dropped".to_string()))
    }

    pub async fn shutdown(&self) {
        let (ack_tx, ack_rx) = oneshot::channel();
        if self.sender.send(WalMessage::Shutdown { ack: ack_tx }).await.is_ok() {
            let _ = ack_rx.await;
        }
    }

    pub fn entry_count(&self) -> u64 {
        self.entry_count.load(Ordering::Relaxed)
    }

    pub fn needs_compact(&self, threshold: u64) -> bool {
        let count = self.entry_count();
        if count == 0 {
            return false;
        }
        let elapsed = self
            .last_compact_time
            .lock()
            .map(|guard| guard.elapsed().as_secs())
            .unwrap_or(0);
        count >= threshold || elapsed >= WAL_COMPACT_INTERVAL_SECS
    }

    /// Approximate number of queued WAL messages waiting behind the actor.
    pub fn queue_depth(&self) -> usize {
        WAL_CHANNEL_CAPACITY.saturating_sub(self.sender.capacity())
    }
}

struct WalActor {
    wal: WalWriter,
    receiver: mpsc::Receiver<WalMessage>,
    entry_count: Arc<AtomicU64>,
    last_compact_time: Arc<Mutex<Instant>>,
}

impl WalActor {
    fn run(mut self) {
        let mut deferred: Option<WalMessage> = None;

        loop {
            let msg = match deferred.take() {
                Some(msg) => msg,
                None => match self.receiver.blocking_recv() {
                    Some(msg) => msg,
                    None => break,
                },
            };

            match msg {
                WalMessage::Append { entry, ack } => {
                    let mut acks = Vec::with_capacity(MAX_BATCH_SIZE);
                    let mut appended = 0u64;

                    match self.wal.append_buffered(&entry) {
                        Ok(()) => {
                            acks.push(ack);
                            appended += 1;
                        }
                        Err(e) => {
                            let _ = ack.send(Err(e));
                            continue;
                        }
                    }

                    while acks.len() < MAX_BATCH_SIZE {
                        match self.receiver.try_recv() {
                            Ok(WalMessage::Append { entry, ack }) => {
                                match self.wal.append_buffered(&entry) {
                                    Ok(()) => {
                                        acks.push(ack);
                                        appended += 1;
                                    }
                                    Err(e) => {
                                        let _ = ack.send(Err(e));
                                        break;
                                    }
                                }
                            }
                            Ok(other) => {
                                deferred = Some(other);
                                break;
                            }
                            Err(mpsc::error::TryRecvError::Empty) => break,
                            Err(mpsc::error::TryRecvError::Disconnected) => break,
                        }
                    }

                    let result = self.wal.sync();
                    if result.is_ok() {
                        self.entry_count.fetch_add(appended, Ordering::Relaxed);
                    }
                    for ack in acks {
                        let _ = ack.send(result.clone());
                    }
                }
                WalMessage::Compact { state_json, ack } => {
                    let result = self.wal.compact(&state_json);
                    if result.is_ok() {
                        self.entry_count.store(0, Ordering::Relaxed);
                        if let Ok(mut guard) = self.last_compact_time.lock() {
                            *guard = Instant::now();
                        }
                    }
                    let _ = ack.send(result);
                }
                WalMessage::Shutdown { ack } => {
                    if let Err(e) = self.wal.sync() {
                        warn!(error = %e, "final WAL sync on shutdown failed");
                    }
                    let _ = ack.send(());
                    break;
                }
            }
        }
    }
}

/// Apply a single WAL entry to an in-memory FirewallState.
/// Errors in individual entries are logged and skipped (best-effort replay).
pub fn apply_wal_entry(state: &mut FirewallState, entry: WalEntry) {
    match entry {
        WalEntry::AddGroup { name, cidr } => {
            if let Err(e) = state.add_group(&name, &cidr) {
                warn!(error = %e, group = %name, cidr = %cidr, "WAL replay AddGroup failed");
            }
        }
        WalEntry::DeleteGroup { name } => {
            state.groups.remove(&name);
        }
        WalEntry::AddRule { src_id, dst_id, proto, action, ports, direction } => {
            let ports_ref = ports.as_deref();
            if let Err(e) = state.apply_add_rule(src_id, dst_id, proto, action, ports_ref, direction) {
                warn!(error = %e, src_id, dst_id, proto, direction, "WAL replay AddRule failed");
            }
        }
        WalEntry::RemoveRule { src_id, dst_id, proto, direction } => {
            if let Err(e) = state.apply_remove_rule(src_id, dst_id, proto, direction) {
                warn!(error = %e, src_id, dst_id, proto, direction, "WAL replay RemoveRule failed");
            }
        }
        WalEntry::AddQos { group_name, group_id, direction, rate_bps, burst_bytes, priority, mode } => {
            use crate::state::QosRuleInfo;
            state.qos_rules.retain(|r| !(r.group_id == group_id && r.direction == direction));
            state.qos_rules.push(QosRuleInfo {
                group_name,
                group_id,
                direction,
                rate_bps,
                burst_bytes,
                priority,
                mode,
            });
        }
        WalEntry::DeleteQos { group_id, direction } => {
            state.qos_rules.retain(|r| !(r.group_id == group_id && r.direction == direction));
        }
        WalEntry::AddMirror { src_group_name, src_group_id, dst_group_name, dst_group_id, proto, direction, target_iface, target_ifindex, is_global } => {
            use crate::state::MirrorRuleInfo;
            if is_global {
                state.mirror_rules.retain(|r| !(r.is_global && r.direction == direction));
            } else {
                state.mirror_rules.retain(|r| !(r.src_group_id == src_group_id && r.dst_group_id == dst_group_id && r.proto == proto && r.direction == direction && !r.is_global));
            }
            state.mirror_rules.push(MirrorRuleInfo {
                src_group_name,
                src_group_id,
                dst_group_name,
                dst_group_id,
                proto,
                direction,
                target_iface,
                target_ifindex,
                is_global,
            });
        }
        WalEntry::DeleteMirror { src_group_id, dst_group_id, proto, direction, is_global } => {
            if is_global {
                state.mirror_rules.retain(|r| !(r.is_global && r.direction == direction));
            } else {
                state.mirror_rules.retain(|r| !(r.src_group_id == src_group_id && r.dst_group_id == dst_group_id && r.proto == proto && r.direction == direction && !r.is_global));
            }
        }
        WalEntry::UpdateConfig { conntrack, monitoring, acl, qos, mirror, tcprt, ssl } => {
            if let Some(ct) = conntrack {
                state.conntrack_enabled = ct;
            }
            if let Some(mon) = monitoring {
                state.monitoring_enabled = mon;
            }
            if let Some(a) = acl {
                state.acl_enabled = a;
            }
            if let Some(q) = qos {
                state.qos_enabled = q;
            }
            if let Some(m) = mirror {
                state.mirror_enabled = m;
            }
            if let Some(t) = tcprt {
                state.tcprt_enabled = t;
            }
            if let Some(s) = ssl {
                state.ssl_enabled = s;
            }
        }
        WalEntry::SetMaxPortPolicies { max } => {
            state.max_port_policies = max;
        }
        WalEntry::SetAttachedIface { iface } => {
            state.attached_iface = Some(iface);
        }
        WalEntry::ClearAttachedIface => {
            state.attached_iface = None;
        }
    }
}

/// Load state from snapshot + replay WAL entries.
pub fn load_with_wal(state_path: &str) -> FirewallState {
    // 1. Load base snapshot
    let state_file = format!("{}/state.json", state_path);
    let mut state = if let Ok(contents) = fs::read_to_string(&state_file) {
        if !contents.is_empty() {
            serde_json::from_str(&contents).unwrap_or_else(|e| {
                warn!(path = %state_file, error = %e, "failed to parse snapshot; using default state");
                FirewallState::default()
            })
        } else {
            FirewallState::default()
        }
    } else {
        FirewallState::default()
    };

    // 2. Replay WAL
    let wal_path = format!("{}/state.wal", state_path);
    if let Ok(file) = File::open(&wal_path) {
        let reader = BufReader::new(file);
        let mut replayed = 0u64;
        for (line_num, line_result) in reader.lines().enumerate() {
            match line_result {
                Ok(line) => {
                    if line.trim().is_empty() {
                        continue;
                    }
                    match serde_json::from_str::<WalEntry>(&line) {
                        Ok(entry) => {
                            apply_wal_entry(&mut state, entry);
                            replayed += 1;
                        }
                        Err(e) => {
                            warn!(path = %wal_path, line = line_num + 1, error = %e, "skipping corrupt WAL entry");
                        }
                    }
                }
                Err(e) => {
                    warn!(path = %wal_path, line = line_num + 1, error = %e, "read error while replaying WAL");
                    break;
                }
            }
        }
        if replayed > 0 {
            info!(path = %wal_path, replayed, "replayed WAL entries");
        }
    }

    state
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::FirewallState;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_state_path() -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = format!("/tmp/aria-wal-test-{}", nanos);
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn wal_append_and_load_roundtrip() {
        let state_path = temp_state_path();

        // Write initial snapshot
        let mut state = FirewallState::default();
        state.add_group("web", "10.0.0.0/24").unwrap();
        let snapshot = serde_json::to_string_pretty(&state).unwrap();
        fs::write(format!("{}/state.json", state_path), &snapshot).unwrap();

        // Append WAL entries
        {
            let mut wal = WalWriter::open(&state_path).unwrap();
            assert_eq!(wal.entry_count(), 0);

            wal.append(&WalEntry::AddGroup {
                name: "db".to_string(),
                cidr: "10.0.1.0/24".to_string(),
            }).unwrap();
            wal.append(&WalEntry::AddRule {
                src_id: 1,
                dst_id: 2,
                proto: 6,
                action: 0,
                ports: Some("80".to_string()),
                direction: 0,
            }).unwrap();
            assert_eq!(wal.entry_count(), 2);
        }

        // Load with WAL replay
        let loaded = load_with_wal(&state_path);
        assert!(loaded.groups.contains_key("web"), "snapshot group present");
        assert!(loaded.groups.contains_key("db"), "WAL group present");
        assert_eq!(loaded.rules.len(), 1, "WAL rule present");
        assert_eq!(loaded.rules[0].src_group_id, 1);

        // Cleanup
        let _ = fs::remove_dir_all(&state_path);
    }

    #[test]
    fn wal_compact_clears_wal() {
        let state_path = temp_state_path();

        let mut state = FirewallState::default();
        state.add_group("web", "10.0.0.0/24").unwrap();

        // Write initial snapshot
        let snapshot = serde_json::to_string_pretty(&state).unwrap();
        fs::write(format!("{}/state.json", state_path), &snapshot).unwrap();

        let mut wal = WalWriter::open(&state_path).unwrap();
        wal.append(&WalEntry::AddGroup {
            name: "db".to_string(),
            cidr: "10.0.1.0/24".to_string(),
        }).unwrap();
        wal.append(&WalEntry::AddGroup {
            name: "cache".to_string(),
            cidr: "10.0.2.0/24".to_string(),
        }).unwrap();
        assert_eq!(wal.entry_count(), 2);

        // Apply entries to state for compact
        state.add_group("db", "10.0.1.0/24").unwrap();
        state.add_group("cache", "10.0.2.0/24").unwrap();

        // Compact
        let json = serde_json::to_string_pretty(&state).unwrap();
        wal.compact(&json).unwrap();
        assert_eq!(wal.entry_count(), 0);

        // WAL file should be empty
        let wal_contents = fs::read_to_string(format!("{}/state.wal", state_path)).unwrap();
        assert!(wal_contents.is_empty(), "WAL should be empty after compact");

        // Snapshot should have all groups
        let loaded = load_with_wal(&state_path);
        assert!(loaded.groups.contains_key("web"));
        assert!(loaded.groups.contains_key("db"));
        assert!(loaded.groups.contains_key("cache"));

        let _ = fs::remove_dir_all(&state_path);
    }

    #[test]
    fn wal_skips_corrupt_lines() {
        let state_path = temp_state_path();

        // Write empty snapshot
        fs::write(format!("{}/state.json", state_path), "{}").unwrap();

        // Write WAL with a corrupt line in the middle
        let wal_file = format!("{}/state.wal", state_path);
        let mut f = File::create(&wal_file).unwrap();
        let entry1 = serde_json::to_string(&WalEntry::AddGroup {
            name: "g1".to_string(),
            cidr: "10.0.0.0/24".to_string(),
        }).unwrap();
        let entry2 = serde_json::to_string(&WalEntry::AddGroup {
            name: "g2".to_string(),
            cidr: "10.0.1.0/24".to_string(),
        }).unwrap();
        writeln!(f, "{}", entry1).unwrap();
        writeln!(f, "{{corrupt json line}}").unwrap();
        writeln!(f, "{}", entry2).unwrap();

        let loaded = load_with_wal(&state_path);
        assert!(loaded.groups.contains_key("g1"), "entry before corrupt line applied");
        assert!(loaded.groups.contains_key("g2"), "entry after corrupt line applied");

        let _ = fs::remove_dir_all(&state_path);
    }

    #[test]
    fn wal_empty_file_loads_default() {
        let state_path = temp_state_path();
        // No snapshot, no WAL
        let loaded = load_with_wal(&state_path);
        assert!(loaded.groups.is_empty());
        assert_eq!(loaded.next_group_id, 1);

        let _ = fs::remove_dir_all(&state_path);
    }

    #[test]
    fn apply_all_entry_types() {
        let mut state = FirewallState::default();

        // AddGroup
        apply_wal_entry(&mut state, WalEntry::AddGroup {
            name: "web".to_string(),
            cidr: "10.0.0.0/24".to_string(),
        });
        assert!(state.groups.contains_key("web"));

        // AddRule
        apply_wal_entry(&mut state, WalEntry::AddRule {
            src_id: 1, dst_id: 0, proto: 6, action: 0,
            ports: Some("80,443".to_string()), direction: 0,
        });
        assert_eq!(state.rules.len(), 1);

        // RemoveRule
        apply_wal_entry(&mut state, WalEntry::RemoveRule {
            src_id: 1, dst_id: 0, proto: 6, direction: 0,
        });
        assert_eq!(state.rules.len(), 0);

        // DeleteGroup
        apply_wal_entry(&mut state, WalEntry::DeleteGroup {
            name: "web".to_string(),
        });
        assert!(!state.groups.contains_key("web"));

        // AddQos
        apply_wal_entry(&mut state, WalEntry::AddQos {
            group_name: "default".to_string(),
            group_id: 0,
            direction: 0,
            rate_bps: 1_000_000,
            burst_bytes: 125_000,
            priority: 1,
            mode: 0,
        });
        assert_eq!(state.qos_rules.len(), 1);

        // DeleteQos
        apply_wal_entry(&mut state, WalEntry::DeleteQos {
            group_id: 0, direction: 0,
        });
        assert_eq!(state.qos_rules.len(), 0);

        // UpdateConfig
        apply_wal_entry(&mut state, WalEntry::UpdateConfig {
            conntrack: Some(false), monitoring: None, acl: None, qos: None, mirror: None, tcprt: None, ssl: None,
        });
        assert!(!state.conntrack_enabled);
        assert!(state.monitoring_enabled);

        // SetMaxPortPolicies
        apply_wal_entry(&mut state, WalEntry::SetMaxPortPolicies { max: 100 });
        assert_eq!(state.max_port_policies, 100);

        // SetAttachedIface
        apply_wal_entry(&mut state, WalEntry::SetAttachedIface {
            iface: "eth0".to_string(),
        });
        assert_eq!(state.attached_iface, Some("eth0".to_string()));

        // ClearAttachedIface
        apply_wal_entry(&mut state, WalEntry::ClearAttachedIface);
        assert_eq!(state.attached_iface, None);
    }

    #[test]
    fn wal_writer_resumes_count() {
        let state_path = temp_state_path();

        // Write 3 entries
        {
            let mut wal = WalWriter::open(&state_path).unwrap();
            wal.append(&WalEntry::AddGroup { name: "a".to_string(), cidr: "10.0.0.0/24".to_string() }).unwrap();
            wal.append(&WalEntry::AddGroup { name: "b".to_string(), cidr: "10.0.1.0/24".to_string() }).unwrap();
            wal.append(&WalEntry::AddGroup { name: "c".to_string(), cidr: "10.0.2.0/24".to_string() }).unwrap();
        }

        // Re-open and verify count resumes
        let wal = WalWriter::open(&state_path).unwrap();
        assert_eq!(wal.entry_count(), 3);

        let _ = fs::remove_dir_all(&state_path);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn wal_client_append_and_load_roundtrip() {
        let state_path = temp_state_path();

        let wal = WalClient::open(&state_path).unwrap();
        wal.append(WalEntry::AddGroup {
            name: "web".to_string(),
            cidr: "10.0.0.0/24".to_string(),
        }).await.unwrap();
        wal.append(WalEntry::AddGroup {
            name: "db".to_string(),
            cidr: "10.0.1.0/24".to_string(),
        }).await.unwrap();
        wal.shutdown().await;

        let loaded = load_with_wal(&state_path);
        assert!(loaded.groups.contains_key("web"));
        assert!(loaded.groups.contains_key("db"));

        let _ = fs::remove_dir_all(&state_path);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn wal_client_compact_clears_wal_and_persists_snapshot() {
        let state_path = temp_state_path();

        let wal = WalClient::open(&state_path).unwrap();
        wal.append(WalEntry::AddGroup {
            name: "web".to_string(),
            cidr: "10.0.0.0/24".to_string(),
        }).await.unwrap();

        let mut state = FirewallState::default();
        state.add_group("web", "10.0.0.0/24").unwrap();
        wal.compact(serde_json::to_string_pretty(&state).unwrap()).await.unwrap();
        wal.shutdown().await;

        let wal_contents = fs::read_to_string(format!("{}/state.wal", state_path)).unwrap();
        assert!(wal_contents.is_empty(), "WAL should be empty after compact");

        let loaded = load_with_wal(&state_path);
        assert!(loaded.groups.contains_key("web"));

        let _ = fs::remove_dir_all(&state_path);
    }
}
