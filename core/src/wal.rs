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

use crate::common::{IP_FAMILY_V4, IP_FAMILY_V6};
use crate::state::{
    migrate_legacy_rule_families, migrate_state_rule_families,
    persist_state_file_atomically_classified, AtomicStatePersistError, FirewallState, RuleInfo,
    WalReplayCursor, WAL_REPLAY_CURSOR_VERSION,
};

/// Time-based compact interval (5 minutes)
const WAL_COMPACT_INTERVAL_SECS: u64 = 300;
const MAX_BATCH_SIZE: usize = 100;
const WAL_CHANNEL_CAPACITY: usize = 1024;
static LAST_WAL_REPLAY_FAILURES: AtomicU64 = AtomicU64::new(0);

fn acl_ip_family_is_valid(ip_family: u8) -> bool {
    ip_family == IP_FAMILY_V4 || ip_family == IP_FAMILY_V6
}

pub fn last_wal_replay_failures() -> u64 {
    LAST_WAL_REPLAY_FAILURES.load(Ordering::Relaxed)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalLoadError {
    LegacyAclFamilyMigration { reason: String },
    LegacyAclFamilyCheckpoint { reason: String },
    LegacyAclFamilyCheckpointBlockedByWalFailure {
        failure_count: u64,
        reason: String,
    },
}

impl WalLoadError {
    fn family_migration(reason: String) -> Self {
        Self::LegacyAclFamilyMigration { reason }
    }

    fn family_checkpoint_blocked(failure_count: u64) -> Self {
        Self::LegacyAclFamilyCheckpointBlockedByWalFailure {
            failure_count,
            reason: format!(
                "legacy_acl_family_checkpoint_blocked_by_wal_failure: failure_count={}",
                failure_count
            ),
        }
    }

    pub fn reason(&self) -> &str {
        match self {
            Self::LegacyAclFamilyMigration { reason }
            | Self::LegacyAclFamilyCheckpoint { reason }
            | Self::LegacyAclFamilyCheckpointBlockedByWalFailure { reason, .. } => reason,
        }
    }
}

impl std::fmt::Display for WalLoadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LegacyAclFamilyMigration { reason } => formatter.write_str(reason),
            Self::LegacyAclFamilyCheckpoint { reason } => {
                write!(formatter, "legacy ACL family checkpoint failed: {}", reason)
            }
            Self::LegacyAclFamilyCheckpointBlockedByWalFailure { reason, .. } => {
                formatter.write_str(reason)
            }
        }
    }
}

impl std::error::Error for WalLoadError {}

#[derive(Debug, Clone, Copy)]
struct WalApplyOutcome {
    applied: bool,
    family_migrated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FamilyMigrationCheckpointPhase {
    BeforeCheckpointMarker,
    AfterCheckpointMarkerBeforeSnapshotPublication,
    AfterSnapshotPublication,
}

#[derive(Debug)]
struct WalCompactCommit {
    checkpoint_id: u64,
    cleanup_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WalEntry {
    AddGroup {
        name: String,
        cidr: String,
    },
    DeleteGroup {
        name: String,
    },
    AddRule {
        src_id: u32,
        dst_id: u32,
        proto: u8,
        action: u8,
        ports: Option<String>,
        direction: u8,
        #[serde(default)]
        ip_family: u8,
    },
    RemoveRule {
        src_id: u32,
        dst_id: u32,
        proto: u8,
        direction: u8,
        #[serde(default)]
        ip_family: u8,
    },
    AddQos {
        group_name: String,
        group_id: u32,
        direction: u8,
        rate_bps: u64,
        burst_bytes: u64,
        priority: u8,
        #[serde(default)]
        mode: u8,
    },
    DeleteQos {
        group_id: u32,
        direction: u8,
    },
    AddMirror {
        src_group_name: String,
        src_group_id: u32,
        dst_group_name: String,
        dst_group_id: u32,
        proto: u8,
        direction: u8,
        target_iface: String,
        target_ifindex: u32,
        is_global: bool,
    },
    DeleteMirror {
        src_group_id: u32,
        dst_group_id: u32,
        proto: u8,
        direction: u8,
        is_global: bool,
    },
    UpdateConfig {
        conntrack: Option<bool>,
        monitoring: Option<bool>,
        #[serde(default)]
        acl: Option<bool>,
        #[serde(default)]
        qos: Option<bool>,
        #[serde(default)]
        mirror: Option<bool>,
        #[serde(default)]
        tcprt: Option<bool>,
        #[serde(default)]
        ssl: Option<bool>,
    },
    SetMaxPortPolicies {
        max: u32,
    },
    SetAttachedIface {
        iface: String,
    },
    ClearAttachedIface,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WalCheckpointRecord {
    version: u8,
    checkpoint_id: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum PersistedWalRecord {
    Checkpoint {
        wal_checkpoint: WalCheckpointRecord,
    },
    Mutation(WalEntry),
}

#[derive(Default)]
struct WalInventory {
    mutation_count: u64,
    max_checkpoint_id: u64,
    has_matching_checkpoint: bool,
    has_nonempty_line: bool,
}

fn parse_persisted_wal_record(line: &str) -> Result<PersistedWalRecord, String> {
    serde_json::from_str(line).map_err(|error| format!("invalid WAL record: {}", error))
}

fn serialize_checkpoint_record(checkpoint_id: u64) -> Result<String, String> {
    if checkpoint_id == 0 {
        return Err("checkpoint ID must be nonzero".to_string());
    }
    serde_json::to_string(&PersistedWalRecord::Checkpoint {
        wal_checkpoint: WalCheckpointRecord {
            version: WAL_REPLAY_CURSOR_VERSION,
            checkpoint_id,
        },
    })
    .map_err(|error| format!("Failed to serialize WAL checkpoint: {}", error))
}

fn snapshot_cursor(state_path: &str) -> Result<WalReplayCursor, String> {
    let state_file = PathBuf::from(state_path).join("state.json");
    let contents = match fs::read_to_string(&state_file) {
        Ok(contents) if !contents.trim().is_empty() => contents,
        Ok(_) => return Ok(WalReplayCursor::default()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(WalReplayCursor::default());
        }
        Err(error) => {
            return Err(format!(
                "Failed to read snapshot cursor from {}: {}",
                state_file.display(),
                error
            ));
        }
    };
    // Snapshot recovery retains its existing best-effort fallback for malformed
    // JSON. Cursor validation only adds a hard gate when the metadata itself is
    // present and parseable, so opening the WAL does not broaden startup policy.
    let value: serde_json::Value = match serde_json::from_str(&contents) {
        Ok(value) => value,
        Err(_) => return Ok(WalReplayCursor::default()),
    };
    match value.get("wal_replay_cursor") {
        Some(cursor) => serde_json::from_value(cursor.clone()).map_err(|error| {
            format!(
                "Failed to parse WAL replay cursor from {}: {}",
                state_file.display(),
                error
            )
        }),
        None => Ok(WalReplayCursor::default()),
    }
}

fn inventory_wal(
    wal_path: &PathBuf,
    snapshot_checkpoint_id: Option<u64>,
) -> Result<WalInventory, String> {
    if !wal_path.exists() {
        return Ok(WalInventory::default());
    }
    let file = File::open(wal_path)
        .map_err(|error| format!("Failed to open WAL for inventory: {}", error))?;
    inventory_wal_reader(BufReader::new(file), snapshot_checkpoint_id)
}

fn inventory_wal_reader<R: BufRead>(
    reader: R,
    snapshot_checkpoint_id: Option<u64>,
) -> Result<WalInventory, String> {
    let mut inventory = WalInventory::default();
    let mut lines = reader.lines();
    loop {
        match lines.next() {
            None => break,
            Some(Ok(line)) => {
                if line.trim().is_empty() {
                    continue;
                }
                inventory.has_nonempty_line = true;
                match parse_persisted_wal_record(&line) {
                    Ok(PersistedWalRecord::Mutation(_)) => inventory.mutation_count += 1,
                    Ok(PersistedWalRecord::Checkpoint { wal_checkpoint }) => {
                        inventory.max_checkpoint_id = inventory
                            .max_checkpoint_id
                            .max(wal_checkpoint.checkpoint_id);
                        if wal_checkpoint.version == WAL_REPLAY_CURSOR_VERSION
                            && Some(wal_checkpoint.checkpoint_id) == snapshot_checkpoint_id
                        {
                            inventory.has_matching_checkpoint = true;
                        }
                    }
                    Err(_) => {}
                }
            }
            Some(Err(error)) => {
                // Non-UTF-8 records are tolerated exactly like the replay
                // path (REVIEW-OPS-027); genuine read I/O errors fail the
                // inventory so startup never builds a truncated view.
                if error.kind() == std::io::ErrorKind::InvalidData {
                    continue;
                }
                return Err(format!("Failed to read WAL for inventory: {}", error));
            }
        }
    }
    Ok(inventory)
}

pub struct WalWriter {
    file: BufWriter<File>,
    wal_path: PathBuf,
    entry_count: u64,
    last_compact_time: Instant,
    next_checkpoint_id: Option<u64>,
    current_checkpoint_id: Option<u64>,
    header_required: bool,
}

impl WalWriter {
    pub fn open(state_path: &str) -> Result<Self, String> {
        let wal_path = PathBuf::from(format!("{}/state.wal", state_path));

        // Ensure directory exists
        if let Some(parent) = wal_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create WAL directory: {}", e))?;
        }

        let cursor = snapshot_cursor(state_path)?;
        let snapshot_checkpoint_id = cursor.supported_checkpoint_id()?;
        let inventory = inventory_wal(&wal_path, snapshot_checkpoint_id)?;
        let max_checkpoint_id = snapshot_checkpoint_id
            .unwrap_or(0)
            .max(inventory.max_checkpoint_id);
        let next_checkpoint_id = max_checkpoint_id.checked_add(1);
        let header_required = snapshot_checkpoint_id.is_some()
            && !inventory.has_nonempty_line
            && !inventory.has_matching_checkpoint;

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&wal_path)
            .map_err(|e| format!("Failed to open WAL file: {}", e))?;

        Ok(Self {
            file: BufWriter::new(file),
            wal_path,
            entry_count: inventory.mutation_count,
            last_compact_time: Instant::now(),
            next_checkpoint_id,
            current_checkpoint_id: snapshot_checkpoint_id,
            header_required,
        })
    }

    fn append_checkpoint_buffered(&mut self, checkpoint_id: u64) -> Result<(), String> {
        let line = serialize_checkpoint_record(checkpoint_id)?;
        self.file
            .write_all(line.as_bytes())
            .map_err(|error| format!("Failed to write WAL checkpoint: {}", error))?;
        self.file
            .write_all(b"\n")
            .map_err(|error| format!("Failed to write WAL checkpoint newline: {}", error))
    }

    fn ensure_checkpoint_header(&mut self) -> Result<(), String> {
        if !self.header_required {
            return Ok(());
        }
        let checkpoint_id = self.current_checkpoint_id.ok_or_else(|| {
            "checkpoint header required without a current checkpoint ID".to_string()
        })?;
        let result = (|| {
            self.append_checkpoint_buffered(checkpoint_id)?;
            self.sync()
        })();
        if let Err(error) = &result {
            warn!(
                checkpoint_id,
                checkpoint_version = WAL_REPLAY_CURSOR_VERSION,
                header_required = true,
                error = %error,
                "failed to publish required WAL checkpoint header"
            );
        }
        result?;
        self.header_required = false;
        Ok(())
    }

    fn append_buffered(&mut self, entry: &WalEntry) -> Result<(), String> {
        match entry {
            WalEntry::AddRule { ip_family, .. } | WalEntry::RemoveRule { ip_family, .. }
                if !acl_ip_family_is_valid(*ip_family) =>
            {
                return Err(format!("invalid ACL IP family {}", ip_family));
            }
            _ => {}
        }
        self.ensure_checkpoint_header()?;
        let line = serde_json::to_string(entry)
            .map_err(|e| format!("Failed to serialize WAL entry: {}", e))?;
        self.file
            .write_all(line.as_bytes())
            .map_err(|e| format!("Failed to write WAL entry: {}", e))?;
        self.file
            .write_all(b"\n")
            .map_err(|e| format!("Failed to write WAL newline: {}", e))?;
        self.entry_count += 1;
        Ok(())
    }

    fn sync(&mut self) -> Result<(), String> {
        self.file
            .flush()
            .map_err(|e| format!("Failed to flush WAL: {}", e))?;
        self.file
            .get_ref()
            .sync_all()
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

    /// Publish a full checkpointed snapshot, then replace the covered WAL prefix.
    /// Accepts pre-serialized JSON to avoid borrow conflicts when wal and state
    /// are fields of the same struct.
    fn compact_with_commit_outcome<F>(
        &mut self,
        state_json: &str,
        mut hook: F,
    ) -> Result<WalCompactCommit, String>
    where
        F: FnMut(FamilyMigrationCheckpointPhase) -> Result<(), String>,
    {
        let covered_mutations = self.entry_count;
        let checkpoint_id = self.next_checkpoint_id.ok_or_else(|| {
            "WAL checkpoint ID space exhausted; refusing to truncate WAL".to_string()
        })?;
        let mut state: FirewallState = serde_json::from_str(state_json)
            .map_err(|error| format!("Failed to parse compact snapshot: {}", error))?;
        state.wal_replay_cursor = WalReplayCursor {
            version: WAL_REPLAY_CURSOR_VERSION,
            checkpoint_id,
        };
        let checkpointed_state = serde_json::to_vec_pretty(&state)
            .map_err(|error| format!("Failed to serialize compact snapshot: {}", error))?;

        hook(FamilyMigrationCheckpointPhase::BeforeCheckpointMarker)?;
        self.append_checkpoint_buffered(checkpoint_id)?;
        self.sync()?;
        self.next_checkpoint_id = checkpoint_id.checked_add(1);
        hook(FamilyMigrationCheckpointPhase::AfterCheckpointMarkerBeforeSnapshotPublication)?;

        let state_dir = self
            .wal_path
            .parent()
            .ok_or_else(|| "WAL path has no parent directory".to_string())?;
        let state_file = state_dir.join("state.json");
        match persist_state_file_atomically_classified(&state_file, &checkpointed_state) {
            Ok(()) => {}
            Err(AtomicStatePersistError::BeforePublication(error)) => {
                return Err(format!("Failed to write snapshot: {}", error));
            }
            Err(AtomicStatePersistError::AfterPublication(error)) => {
                self.current_checkpoint_id = Some(checkpoint_id);
                return Ok(WalCompactCommit {
                    checkpoint_id,
                    cleanup_error: Some(format!("Failed to write snapshot: {}", error)),
                });
            }
        }

        self.current_checkpoint_id = Some(checkpoint_id);
        if let Err(error) = hook(FamilyMigrationCheckpointPhase::AfterSnapshotPublication) {
            return Ok(WalCompactCommit {
                checkpoint_id,
                cleanup_error: Some(error),
            });
        }
        let cleanup_result = (|| {
            let file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&self.wal_path)
                .map_err(|e| format!("Failed to truncate WAL: {}", e))?;
            self.file = BufWriter::new(file);
            self.header_required = true;
            self.file
                .get_ref()
                .sync_all()
                .map_err(|e| format!("Failed to sync truncated WAL: {}", e))?;
            self.ensure_checkpoint_header()
        })();
        if let Err(error) = cleanup_result {
            return Ok(WalCompactCommit {
                checkpoint_id,
                cleanup_error: Some(error),
            });
        }
        self.entry_count = 0;
        self.last_compact_time = Instant::now();
        info!(
            checkpoint_id,
            checkpoint_version = WAL_REPLAY_CURSOR_VERSION,
            covered_mutations,
            header_required = self.header_required,
            "compacted standalone state with WAL checkpoint"
        );

        Ok(WalCompactCommit {
            checkpoint_id,
            cleanup_error: None,
        })
    }

    fn compact_strict_with_hook<F>(&mut self, state_json: &str, hook: F) -> Result<(), String>
    where
        F: FnMut(FamilyMigrationCheckpointPhase) -> Result<(), String>,
    {
        let outcome = self.compact_with_commit_outcome(state_json, hook)?;
        match outcome.cleanup_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Publish a full checkpointed snapshot, then replace the covered WAL prefix.
    /// General callers retain the strict contract that any cleanup failure is an error.
    pub fn compact(&mut self, state_json: &str) -> Result<(), String> {
        self.compact_strict_with_hook(state_json, |_| Ok(()))
    }

    pub(crate) fn compact_family_migration(
        &mut self,
        state_json: &str,
    ) -> Result<u64, String> {
        self.compact_family_migration_with_hook(state_json, |_| Ok(()))
    }

    fn compact_family_migration_with_hook<F>(
        &mut self,
        state_json: &str,
        hook: F,
    ) -> Result<u64, String>
    where
        F: FnMut(FamilyMigrationCheckpointPhase) -> Result<(), String>,
    {
        let outcome = self.compact_with_commit_outcome(state_json, hook)?;
        if let Some(error) = outcome.cleanup_error {
            warn!(
                checkpoint_id = outcome.checkpoint_id,
                checkpoint_version = WAL_REPLAY_CURSOR_VERSION,
                error = %error,
                "ACL family checkpoint committed; deferred WAL cleanup will recover on restart"
            );
        }
        Ok(outcome.checkpoint_id)
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
            .send(WalMessage::Compact {
                state_json,
                ack: ack_tx,
            })
            .await
            .map_err(|_| "WAL worker thread died".to_string())?;
        ack_rx
            .await
            .unwrap_or_else(|_| Err("WAL ack channel dropped".to_string()))
    }

    pub async fn shutdown(&self) {
        let (ack_tx, ack_rx) = oneshot::channel();
        if self
            .sender
            .send(WalMessage::Shutdown { ack: ack_tx })
            .await
            .is_ok()
        {
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

fn apply_wal_entry_for_load(
    state: &mut FirewallState,
    entry: WalEntry,
) -> Result<WalApplyOutcome, WalLoadError> {
    let mut family_migrated = false;
    match entry {
        WalEntry::AddGroup { name, cidr } => {
            if let Err(e) = state.add_group(&name, &cidr) {
                warn!(error = %e, group = %name, cidr = %cidr, "WAL replay AddGroup failed");
                return Ok(WalApplyOutcome {
                    applied: false,
                    family_migrated,
                });
            }
        }
        WalEntry::DeleteGroup { name } => {
            state.groups.remove(&name);
        }
        WalEntry::AddRule {
            src_id,
            dst_id,
            proto,
            action,
            ports,
            direction,
            ip_family,
        } => {
            let ports_ref = ports.as_deref();
            let persisted = RuleInfo {
                name: None,
                src_group_id: src_id,
                dst_group_id: dst_id,
                proto,
                action,
                ports: ports.clone(),
                bitmap_idx: None,
                direction,
                ip_family,
            };
            let normalized = migrate_legacy_rule_families(&persisted, &state.groups)
                .map_err(WalLoadError::family_migration)?;
            family_migrated = ip_family == 0;
            let mut staged = state.clone();
            for rule in normalized {
                if let Err(e) = staged.apply_add_rule(
                    src_id,
                    dst_id,
                    proto,
                    action,
                    ports_ref,
                    direction,
                    rule.ip_family,
                ) {
                    warn!(error = %e, src_id, dst_id, proto, direction, ip_family = rule.ip_family, "WAL replay AddRule failed");
                    return Ok(WalApplyOutcome {
                        applied: false,
                        family_migrated,
                    });
                }
            }
            *state = staged;
        }
        WalEntry::RemoveRule {
            src_id,
            dst_id,
            proto,
            direction,
            ip_family,
        } => {
            let persisted = RuleInfo {
                name: None,
                src_group_id: src_id,
                dst_group_id: dst_id,
                proto,
                action: 0,
                ports: None,
                bitmap_idx: None,
                direction,
                ip_family,
            };
            let normalized = migrate_legacy_rule_families(&persisted, &state.groups)
                .map_err(WalLoadError::family_migration)?;
            family_migrated = ip_family == 0;
            let mut staged = state.clone();
            for rule in normalized {
                if let Err(e) =
                    staged.apply_remove_rule(src_id, dst_id, proto, direction, rule.ip_family)
                {
                    warn!(error = %e, src_id, dst_id, proto, direction, ip_family = rule.ip_family, "WAL replay RemoveRule failed");
                    return Ok(WalApplyOutcome {
                        applied: false,
                        family_migrated,
                    });
                }
            }
            *state = staged;
        }
        WalEntry::AddQos {
            group_name,
            group_id,
            direction,
            rate_bps,
            burst_bytes,
            priority,
            mode,
        } => {
            use crate::state::QosRuleInfo;
            state
                .qos_rules
                .retain(|r| !(r.group_id == group_id && r.direction == direction));
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
        WalEntry::DeleteQos {
            group_id,
            direction,
        } => {
            state
                .qos_rules
                .retain(|r| !(r.group_id == group_id && r.direction == direction));
        }
        WalEntry::AddMirror {
            src_group_name,
            src_group_id,
            dst_group_name,
            dst_group_id,
            proto,
            direction,
            target_iface,
            target_ifindex,
            is_global,
        } => {
            use crate::state::MirrorRuleInfo;
            if is_global {
                state
                    .mirror_rules
                    .retain(|r| !(r.is_global && r.direction == direction));
            } else {
                state.mirror_rules.retain(|r| {
                    !(r.src_group_id == src_group_id
                        && r.dst_group_id == dst_group_id
                        && r.proto == proto
                        && r.direction == direction
                        && !r.is_global)
                });
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
        WalEntry::DeleteMirror {
            src_group_id,
            dst_group_id,
            proto,
            direction,
            is_global,
        } => {
            if is_global {
                state
                    .mirror_rules
                    .retain(|r| !(r.is_global && r.direction == direction));
            } else {
                state.mirror_rules.retain(|r| {
                    !(r.src_group_id == src_group_id
                        && r.dst_group_id == dst_group_id
                        && r.proto == proto
                        && r.direction == direction
                        && !r.is_global)
                });
            }
        }
        WalEntry::UpdateConfig {
            conntrack,
            monitoring,
            acl,
            qos,
            mirror,
            tcprt,
            ssl,
        } => {
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
    Ok(WalApplyOutcome {
        applied: true,
        family_migrated,
    })
}

/// Apply a single WAL entry to an in-memory FirewallState.
/// Errors in individual entries are logged and skipped (best-effort replay).
pub fn apply_wal_entry(state: &mut FirewallState, entry: WalEntry) -> bool {
    match apply_wal_entry_for_load(state, entry) {
        Ok(outcome) => outcome.applied,
        Err(error) => {
            warn!(error = %error, "WAL replay ACL family migration failed");
            false
        }
    }
}

fn checkpoint_family_migrated_state_with_hook<F>(
    state_path: &str,
    state: &mut FirewallState,
    hook: F,
) -> Result<(), WalLoadError>
where
    F: FnMut(FamilyMigrationCheckpointPhase) -> Result<(), String>,
{
    let state_json = serde_json::to_string(state).map_err(|error| {
        WalLoadError::LegacyAclFamilyCheckpoint {
            reason: format!("serialize migrated ACL state: {}", error),
        }
    })?;
    let mut wal = WalWriter::open(state_path)
        .map_err(|reason| WalLoadError::LegacyAclFamilyCheckpoint { reason })?;
    let checkpoint_id = wal
        .compact_family_migration_with_hook(&state_json, hook)
        .map_err(|reason| WalLoadError::LegacyAclFamilyCheckpoint { reason })?;
    state.wal_replay_cursor = WalReplayCursor {
        version: WAL_REPLAY_CURSOR_VERSION,
        checkpoint_id,
    };
    Ok(())
}

/// Load state from snapshot + replay WAL entries.
pub fn load_with_wal(state_path: &str) -> Result<FirewallState, WalLoadError> {
    load_with_wal_with_compact_hook(state_path, |_| Ok(()))
}

fn load_with_wal_with_compact_hook<F>(
    state_path: &str,
    mut compact_hook: F,
) -> Result<FirewallState, WalLoadError>
where
    F: FnMut(FamilyMigrationCheckpointPhase) -> Result<(), String>,
{
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

    let snapshot_family_migrated =
        migrate_state_rule_families(&mut state).map_err(WalLoadError::family_migration)?;
    let checkpoint_state = state.clone();
    let cursor_result = state.wal_replay_cursor.supported_checkpoint_id();
    let cursor_failed = cursor_result.is_err();
    let snapshot_checkpoint_id = match cursor_result {
        Ok(checkpoint_id) => checkpoint_id,
        Err(error) => {
            warn!(path = %state_file, error = %error, "unsupported WAL replay cursor");
            None
        }
    };

    // 2. Replay WAL
    let wal_path = format!("{}/state.wal", state_path);
    if let Ok(file) = File::open(&wal_path) {
        let reader = BufReader::new(file);
        let mut replayed = 0u64;
        let mut failed = u64::from(cursor_failed);
        let mut prefix_discarded = false;
        let mut family_migrated = snapshot_family_migrated;
        for (line_num, line_result) in reader.lines().enumerate() {
            match line_result {
                Ok(line) => {
                    if line.trim().is_empty() {
                        continue;
                    }
                    match parse_persisted_wal_record(&line) {
                        Ok(PersistedWalRecord::Mutation(entry)) => {
                            let outcome = apply_wal_entry_for_load(&mut state, entry)?;
                            family_migrated |= outcome.family_migrated;
                            if outcome.applied {
                                replayed += 1;
                            } else {
                                failed += 1;
                            }
                        }
                        Ok(PersistedWalRecord::Checkpoint { wal_checkpoint }) => {
                            if wal_checkpoint.version != WAL_REPLAY_CURSOR_VERSION
                                || wal_checkpoint.checkpoint_id == 0
                            {
                                warn!(
                                    path = %wal_path,
                                    line = line_num + 1,
                                    version = wal_checkpoint.version,
                                    checkpoint_id = wal_checkpoint.checkpoint_id,
                                    "unsupported WAL checkpoint record"
                                );
                                failed += 1;
                            } else if Some(wal_checkpoint.checkpoint_id)
                                == snapshot_checkpoint_id
                            {
                                state = checkpoint_state.clone();
                                replayed = 0;
                                failed = 0;
                                prefix_discarded = true;
                                family_migrated = snapshot_family_migrated;
                            }
                        }
                        Err(e) => {
                            warn!(path = %wal_path, line = line_num + 1, error = %e, "skipping corrupt WAL entry");
                            failed += 1;
                        }
                    }
                }
                Err(e) => {
                    warn!(path = %wal_path, line = line_num + 1, error = %e, "read error while replaying WAL");
                    failed += 1;
                    break;
                }
            }
        }
        LAST_WAL_REPLAY_FAILURES.store(failed, Ordering::Relaxed);
        if replayed > 0 || prefix_discarded {
            info!(
                path = %wal_path,
                checkpoint_id = snapshot_checkpoint_id.unwrap_or(0),
                checkpoint_version = state.wal_replay_cursor.version,
                tail_replayed = replayed,
                prefix_discarded,
                "replayed standalone WAL tail"
            );
        }
        if failed > 0 {
            warn!(path = %wal_path, failed, "WAL replay completed with failures");
        }
        if family_migrated {
            if failed > 0 {
                return Err(WalLoadError::family_checkpoint_blocked(failed));
            }
            checkpoint_family_migrated_state_with_hook(
                state_path,
                &mut state,
                &mut compact_hook,
            )?;
            info!(path = %state_path, rules = state.rules.len(), "checkpointed snapshot and WAL after ACL family migration");
        }
    } else {
        LAST_WAL_REPLAY_FAILURES.store(u64::from(cursor_failed), Ordering::Relaxed);
        if snapshot_family_migrated {
            if cursor_failed {
                return Err(WalLoadError::family_checkpoint_blocked(1));
            }
            checkpoint_family_migrated_state_with_hook(
                state_path,
                &mut state,
                &mut compact_hook,
            )?;
            info!(path = %state_path, rules = state.rules.len(), "checkpointed snapshot after ACL family migration");
        }
    }

    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::FirewallState;
    use std::time::{SystemTime, UNIX_EPOCH};

    static WAL_CHECKPOINT_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn temp_state_path() -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = format!("/tmp/aria-wal-test-{}", nanos);
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn wal_checkpoint_record(checkpoint_id: u64, version: u8) -> String {
        serde_json::json!({
            "wal_checkpoint": {
                "version": version,
                "checkpoint_id": checkpoint_id,
            }
        })
        .to_string()
    }

    fn wal_checkpoint_state_json(state: &FirewallState, checkpoint_id: u64) -> String {
        wal_checkpoint_state_json_with_version(state, checkpoint_id, 1)
    }

    fn wal_checkpoint_state_json_with_version(
        state: &FirewallState,
        checkpoint_id: u64,
        version: u8,
    ) -> String {
        let mut value = serde_json::to_value(state).unwrap();
        value["wal_replay_cursor"] = serde_json::json!({
            "version": version,
            "checkpoint_id": checkpoint_id,
        });
        serde_json::to_string_pretty(&value).unwrap()
    }

    fn wal_checkpoint_rule_update_chain() -> (Vec<WalEntry>, FirewallState) {
        let entries = vec![
            WalEntry::AddRule {
                src_id: 1,
                dst_id: 2,
                proto: 6,
                action: 0,
                ports: Some("80".to_string()),
                direction: 0,
                ip_family: IP_FAMILY_V4,
            },
            WalEntry::AddRule {
                src_id: 1,
                dst_id: 2,
                proto: 6,
                action: 0,
                ports: Some("443".to_string()),
                direction: 0,
                ip_family: IP_FAMILY_V4,
            },
            WalEntry::AddRule {
                src_id: 1,
                dst_id: 2,
                proto: 6,
                action: 0,
                ports: Some("8443".to_string()),
                direction: 0,
                ip_family: IP_FAMILY_V4,
            },
        ];
        let mut checkpoint = FirewallState::default();
        checkpoint.max_port_policies = 8;
        for entry in entries.iter().cloned() {
            assert!(apply_wal_entry(&mut checkpoint, entry));
        }
        checkpoint
            .quarantine_bitmap_cleanup(3, "53:0".to_string())
            .unwrap();
        (entries, checkpoint)
    }

    fn wal_checkpoint_write_lines(state_path: &str, lines: &[String]) {
        let mut contents = lines.join("\n");
        if !contents.is_empty() {
            contents.push('\n');
        }
        fs::write(format!("{}/state.wal", state_path), contents).unwrap();
    }

    fn wal_checkpoint_entry_lines(entries: &[WalEntry]) -> Vec<String> {
        entries
            .iter()
            .map(|entry| serde_json::to_string(entry).unwrap())
            .collect()
    }

    fn legacy_any_rule_snapshot(state_path: &str) {
        let mut state = FirewallState::default();
        state.max_port_policies = 8;
        state
            .apply_add_rule(0, 0, 6, 0, Some("80"), 0, IP_FAMILY_V4)
            .unwrap();
        state.rules[0].ip_family = 0;
        fs::write(
            format!("{}/state.json", state_path),
            serde_json::to_vec_pretty(&state).unwrap(),
        )
        .unwrap();
    }

    fn assert_any_rule_projection(
        state: &FirewallState,
        expected_action: u8,
        expected_ports: &str,
    ) {
        let mut identities = state
            .rules
            .iter()
            .map(|rule| {
                (
                    rule.src_group_id,
                    rule.dst_group_id,
                    rule.proto,
                    rule.direction,
                    rule.ip_family,
                    rule.action,
                    rule.ports.as_deref(),
                    rule.bitmap_idx,
                )
            })
            .collect::<Vec<_>>();
        identities.sort();
        assert_eq!(identities.len(), 2);
        assert_eq!(
            (
                identities[0].0,
                identities[0].1,
                identities[0].2,
                identities[0].3,
            ),
            (0, 0, 6, 0)
        );
        assert_eq!(
            (
                identities[1].0,
                identities[1].1,
                identities[1].2,
                identities[1].3,
            ),
            (0, 0, 6, 0)
        );
        assert_eq!([identities[0].4, identities[1].4], [4, 6]);
        assert!(identities
            .iter()
            .all(|rule| rule.5 == expected_action && rule.6 == Some(expected_ports)));
        let bitmap_idx = identities[0].7.expect("updated rule must own a bitmap");
        assert_eq!(identities[1].7, Some(bitmap_idx));
        assert_eq!(state.port_sets.len(), 1);
        let port_set = state.port_sets.values().next().unwrap();
        assert_eq!(port_set.bitmap_idx, bitmap_idx);
        assert_eq!(port_set.ref_count, 2);
    }

    fn wal_checkpoint_assert_allocator_parity(
        expected: &FirewallState,
        actual: &FirewallState,
    ) {
        let rule_view = |state: &FirewallState| {
            let mut rules = state
                .rules
                .iter()
                .map(|rule| {
                    (
                        rule.src_group_id,
                        rule.dst_group_id,
                        rule.proto,
                        rule.action,
                        rule.ports.clone(),
                        rule.bitmap_idx,
                        rule.direction,
                    )
                })
                .collect::<Vec<_>>();
            rules.sort();
            rules
        };
        let port_set_view = |state: &FirewallState| {
            state
                .port_sets
                .iter()
                .map(|(key, port_set)| {
                    (
                        key.clone(),
                        (
                            port_set.bitmap_idx,
                            port_set.ports_normalized.clone(),
                            port_set.ref_count,
                        ),
                    )
                })
                .collect::<std::collections::BTreeMap<_, _>>()
        };

        assert_eq!(rule_view(expected), rule_view(actual), "rule allocator view");
        assert_eq!(
            port_set_view(expected),
            port_set_view(actual),
            "port-set allocator view"
        );
        assert_eq!(
            expected.free_bitmap_indices, actual.free_bitmap_indices,
            "free bitmap stack"
        );
        assert_eq!(
            expected.next_bitmap_idx, actual.next_bitmap_idx,
            "next bitmap index"
        );
        assert_eq!(
            expected.max_port_policies, actual.max_port_policies,
            "allocator limit"
        );
        assert_eq!(
            expected.pending_bitmap_cleanups, actual.pending_bitmap_cleanups,
            "pending cleanup quarantine"
        );
        assert_eq!(
            expected.pending_bitmap_cleanup_count(),
            actual.pending_bitmap_cleanup_count(),
            "quarantine-visible count"
        );
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
            })
            .unwrap();
            wal.append(&WalEntry::AddRule {
                src_id: 1,
                dst_id: 2,
                proto: 6,
                action: 0,
                ports: Some("80".to_string()),
                direction: 0,
                ip_family: IP_FAMILY_V4,
            })
            .unwrap();
            assert_eq!(wal.entry_count(), 2);
        }

        // Load with WAL replay
        let loaded = load_with_wal(&state_path).unwrap();
        assert!(loaded.groups.contains_key("web"), "snapshot group present");
        assert!(loaded.groups.contains_key("db"), "WAL group present");
        assert_eq!(loaded.rules.len(), 1, "WAL rule present");
        assert_eq!(loaded.rules[0].src_group_id, 1);

        // Cleanup
        let _ = fs::remove_dir_all(&state_path);
    }

    #[test]
    fn legacy_snapshot_then_wal_any_add_updates_both_families_and_is_idempotent() {
        let state_path = temp_state_path();
        legacy_any_rule_snapshot(&state_path);
        wal_checkpoint_write_lines(
            &state_path,
            &[serde_json::json!({
                "AddRule": {
                    "src_id": 0,
                    "dst_id": 0,
                    "proto": 6,
                    "action": 1,
                    "ports": "443",
                    "direction": 0
                }
            })
            .to_string()],
        );

        let first = load_with_wal(&state_path).expect("family migration must succeed");
        assert_any_rule_projection(&first, 1, "443");
        let checkpointed_snapshot = fs::read(format!("{}/state.json", state_path)).unwrap();
        let checkpointed_wal = fs::read(format!("{}/state.wal", state_path)).unwrap();

        let restarted = load_with_wal(&state_path).expect("restart must remain usable");
        assert_any_rule_projection(&restarted, 1, "443");
        assert_eq!(
            fs::read(format!("{}/state.json", state_path)).unwrap(),
            checkpointed_snapshot,
            "idempotent restart must not rewrite the migrated snapshot"
        );
        assert_eq!(
            fs::read(format!("{}/state.wal", state_path)).unwrap(),
            checkpointed_wal,
            "idempotent restart must not rewrite the checkpointed WAL"
        );

        let _ = fs::remove_dir_all(&state_path);
    }

    #[test]
    fn managed_legacy_snapshot_and_wal_any_stay_ipv4_and_checkpoint_is_idempotent() {
        let state_path = temp_state_path();
        legacy_any_rule_snapshot(&state_path);
        wal_checkpoint_write_lines(
            &state_path,
            &[serde_json::json!({
                "AddRule": {
                    "src_id": 0,
                    "dst_id": 0,
                    "proto": 6,
                    "action": 1,
                    "ports": "443",
                    "direction": 0
                }
            })
            .to_string()],
        );

        let first = load_with_wal(
            &state_path,
            crate::state::LegacyAclMigrationAuthority::ManagedLegacyIpv4,
        )
        .expect("managed family migration must succeed");
        assert_eq!(first.rules.len(), 2);
        assert!(first
            .rules
            .iter()
            .all(|rule| rule.ip_family == IP_FAMILY_V4));
        let checkpointed_snapshot = fs::read(format!("{}/state.json", state_path)).unwrap();
        let checkpointed_wal = fs::read(format!("{}/state.wal", state_path)).unwrap();

        let restarted = load_with_wal(
            &state_path,
            crate::state::LegacyAclMigrationAuthority::ManagedLegacyIpv4,
        )
        .expect("managed restart must remain usable");
        assert_eq!(restarted.rules.len(), 2);
        assert!(restarted
            .rules
            .iter()
            .all(|rule| rule.ip_family == IP_FAMILY_V4));
        assert_eq!(
            fs::read(format!("{}/state.json", state_path)).unwrap(),
            checkpointed_snapshot
        );
        assert_eq!(
            fs::read(format!("{}/state.wal", state_path)).unwrap(),
            checkpointed_wal
        );

        let _ = fs::remove_dir_all(&state_path);
    }

    #[test]
    fn legacy_snapshot_then_wal_any_remove_removes_both_family_owners() {
        let state_path = temp_state_path();
        legacy_any_rule_snapshot(&state_path);
        wal_checkpoint_write_lines(
            &state_path,
            &[serde_json::json!({
                "RemoveRule": {
                    "src_id": 0,
                    "dst_id": 0,
                    "proto": 6,
                    "direction": 0
                }
            })
            .to_string()],
        );

        let loaded = load_with_wal(&state_path).expect("family migration must succeed");
        assert!(loaded.rules.is_empty());
        assert!(loaded.port_sets.is_empty());
        assert_eq!(loaded.free_bitmap_indices, vec![0]);

        let restarted = load_with_wal(&state_path).expect("restart must remain usable");
        assert!(restarted.rules.is_empty());
        assert!(restarted.port_sets.is_empty());
        assert_eq!(restarted.free_bitmap_indices, vec![0]);

        let _ = fs::remove_dir_all(&state_path);
    }

    #[test]
    fn mixed_legacy_snapshot_is_typed_fatal_and_preserves_durable_files() {
        let state_path = temp_state_path();
        let mut state = FirewallState::default();
        let src_id = state.add_group("src", "10.0.0.0/24").unwrap();
        let dst_id = state.add_group("dst", "2001:db8::/64").unwrap();
        let snapshot_path = format!("{}/state.json", state_path);
        let wal_path = format!("{}/state.wal", state_path);
        fs::write(&snapshot_path, serde_json::to_vec_pretty(&state).unwrap()).unwrap();
        fs::write(
            &wal_path,
            format!(
                "{}\n",
                serde_json::json!({
                    "AddRule": {
                        "src_id": src_id,
                        "dst_id": dst_id,
                        "proto": 6,
                        "action": 1,
                        "ports": null,
                        "direction": 0
                    }
                })
            ),
        )
        .unwrap();
        let snapshot_before = fs::read(&snapshot_path).unwrap();
        let wal_before = fs::read(&wal_path).unwrap();

        let error = load_with_wal(&state_path).expect_err("mixed families must abort loading");
        assert!(matches!(
            &error,
            WalLoadError::LegacyAclFamilyMigration { reason }
                if reason == "legacy_acl_rule_mixed_family"
        ));
        assert_eq!(error.reason(), "legacy_acl_rule_mixed_family");
        assert_eq!(fs::read(&snapshot_path).unwrap(), snapshot_before);
        assert_eq!(fs::read(&wal_path).unwrap(), wal_before);

        let _ = fs::remove_dir_all(&state_path);
    }

    #[test]
    fn wal_checkpoint_legacy_family_pre_publication_failure_is_fatal_and_preserves_files() {
        let _guard = WAL_CHECKPOINT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let state_path = temp_state_path();
        legacy_any_rule_snapshot(&state_path);
        let snapshot_path = format!("{}/state.json", state_path);
        let wal_path = format!("{}/state.wal", state_path);
        fs::write(&wal_path, b"").unwrap();
        let snapshot_before = fs::read(&snapshot_path).unwrap();
        let wal_before = fs::read(&wal_path).unwrap();

        let error = load_with_wal_with_compact_hook(&state_path, |phase| match phase {
            FamilyMigrationCheckpointPhase::BeforeCheckpointMarker => {
                Err("injected pre-publication failure".to_string())
            }
            FamilyMigrationCheckpointPhase::AfterCheckpointMarkerBeforeSnapshotPublication => {
                Ok(())
            }
            FamilyMigrationCheckpointPhase::AfterSnapshotPublication => Ok(()),
        })
        .expect_err("pre-publication checkpoint failure must remain fatal");

        assert!(matches!(
            &error,
            WalLoadError::LegacyAclFamilyCheckpoint { reason }
                if reason.contains("injected pre-publication failure")
        ));
        assert_eq!(fs::read(&snapshot_path).unwrap(), snapshot_before);
        assert_eq!(fs::read(&wal_path).unwrap(), wal_before);
        let _ = fs::remove_dir_all(&state_path);
    }

    #[test]
    fn wal_checkpoint_legacy_family_orphan_marker_is_ignored_and_retry_converges() {
        let _guard = WAL_CHECKPOINT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let state_path = temp_state_path();
        legacy_any_rule_snapshot(&state_path);
        let snapshot_path = format!("{}/state.json", state_path);
        let wal_path = format!("{}/state.wal", state_path);
        wal_checkpoint_write_lines(
            &state_path,
            &[serde_json::json!({
                "AddRule": {
                    "src_id": 0,
                    "dst_id": 0,
                    "proto": 6,
                    "action": 1,
                    "ports": "443",
                    "direction": 0
                }
            })
            .to_string()],
        );
        let snapshot_before = fs::read(&snapshot_path).unwrap();
        let wal_before = fs::read(&wal_path).unwrap();
        let old_snapshot: FirewallState = serde_json::from_slice(&snapshot_before).unwrap();

        let error = load_with_wal_with_compact_hook(&state_path, |phase| match phase {
            FamilyMigrationCheckpointPhase::BeforeCheckpointMarker => Ok(()),
            FamilyMigrationCheckpointPhase::AfterCheckpointMarkerBeforeSnapshotPublication => {
                Err("injected failure after durable checkpoint marker".to_string())
            }
            FamilyMigrationCheckpointPhase::AfterSnapshotPublication => Ok(()),
        })
        .expect_err("state publication failure window must remain fatal");

        assert!(matches!(
            &error,
            WalLoadError::LegacyAclFamilyCheckpoint { reason }
                if reason.contains("injected failure after durable checkpoint marker")
        ));
        assert_eq!(fs::read(&snapshot_path).unwrap(), snapshot_before);
        let unchanged_snapshot: FirewallState =
            serde_json::from_slice(&fs::read(&snapshot_path).unwrap()).unwrap();
        assert_eq!(
            unchanged_snapshot.wal_replay_cursor,
            old_snapshot.wal_replay_cursor,
            "the old snapshot cursor remains authoritative"
        );

        let wal_after_failure = fs::read(&wal_path).unwrap();
        assert!(wal_after_failure.starts_with(&wal_before));
        let appended = std::str::from_utf8(&wal_after_failure[wal_before.len()..]).unwrap();
        let appended_lines = appended.lines().collect::<Vec<_>>();
        assert_eq!(appended_lines.len(), 1, "only one orphan marker may append");
        let orphan_checkpoint_id = match parse_persisted_wal_record(appended_lines[0]).unwrap() {
            PersistedWalRecord::Checkpoint { wal_checkpoint } => wal_checkpoint.checkpoint_id,
            PersistedWalRecord::Mutation(_) => panic!("expected orphan checkpoint marker"),
        };
        assert_ne!(
            Some(orphan_checkpoint_id),
            old_snapshot
                .wal_replay_cursor
                .supported_checkpoint_id()
                .unwrap(),
            "the appended marker must not match the old authoritative cursor"
        );

        let restarted = load_with_wal(&state_path)
            .expect("restart must ignore the orphan marker and retry migration");
        assert_any_rule_projection(&restarted, 1, "443");
        assert!(restarted.rules.iter().all(|rule| rule.ip_family != 0));
        assert!(restarted.wal_replay_cursor.checkpoint_id > orphan_checkpoint_id);
        let converged_wal = fs::read_to_string(&wal_path).unwrap();
        assert_eq!(converged_wal.lines().count(), 1);
        assert!(converged_wal.contains(&format!(
            "\"checkpoint_id\":{}",
            restarted.wal_replay_cursor.checkpoint_id
        )));
        let _ = fs::remove_dir_all(&state_path);
    }

    #[test]
    fn wal_checkpoint_legacy_family_post_publication_failure_returns_committed_state() {
        let _guard = WAL_CHECKPOINT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let state_path = temp_state_path();
        legacy_any_rule_snapshot(&state_path);
        let wal_path = format!("{}/state.wal", state_path);
        fs::write(
            &wal_path,
            format!(
                "{}\n",
                serde_json::to_string(&WalEntry::AddGroup {
                    name: "retained-prefix".to_string(),
                    cidr: "192.0.2.0/24".to_string(),
                })
                .unwrap()
            ),
        )
        .unwrap();

        let committed = load_with_wal_with_compact_hook(&state_path, |phase| match phase {
            FamilyMigrationCheckpointPhase::BeforeCheckpointMarker => Ok(()),
            FamilyMigrationCheckpointPhase::AfterCheckpointMarkerBeforeSnapshotPublication => {
                Ok(())
            }
            FamilyMigrationCheckpointPhase::AfterSnapshotPublication => {
                Err("injected post-publication cleanup failure".to_string())
            }
        })
        .expect("published family checkpoint must remain usable");

        assert_any_rule_projection(&committed, 0, "80");
        assert!(committed.wal_replay_cursor.checkpoint_id > 0);
        let checkpointed_snapshot = fs::read(format!("{}/state.json", state_path)).unwrap();
        let retained_wal = fs::read(&wal_path).unwrap();
        let restarted = load_with_wal(&state_path).expect("cursor recovery must converge");
        assert_any_rule_projection(&restarted, 0, "80");
        assert_eq!(restarted.wal_replay_cursor, committed.wal_replay_cursor);
        assert_eq!(
            fs::read(format!("{}/state.json", state_path)).unwrap(),
            checkpointed_snapshot
        );
        assert_eq!(fs::read(&wal_path).unwrap(), retained_wal);
        let _ = fs::remove_dir_all(&state_path);
    }

    #[test]
    fn wal_checkpoint_legacy_family_with_malformed_wal_is_typed_fatal_and_preserves_files() {
        let _guard = WAL_CHECKPOINT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let state_path = temp_state_path();
        legacy_any_rule_snapshot(&state_path);
        let snapshot_path = format!("{}/state.json", state_path);
        let wal_path = format!("{}/state.wal", state_path);
        fs::write(&wal_path, b"{unrelated malformed record}\n").unwrap();
        let snapshot_before = fs::read(&snapshot_path).unwrap();
        let wal_before = fs::read(&wal_path).unwrap();

        let error = load_with_wal(&state_path)
            .expect_err("WAL failure must block publishing normalized family state");

        assert!(matches!(
            &error,
            WalLoadError::LegacyAclFamilyCheckpointBlockedByWalFailure {
                failure_count: 1,
                reason,
            } if reason == "legacy_acl_family_checkpoint_blocked_by_wal_failure: failure_count=1"
        ));
        assert_eq!(
            error.reason(),
            "legacy_acl_family_checkpoint_blocked_by_wal_failure: failure_count=1"
        );
        assert_eq!(fs::read(&snapshot_path).unwrap(), snapshot_before);
        assert_eq!(fs::read(&wal_path).unwrap(), wal_before);
        let _ = fs::remove_dir_all(&state_path);
    }

    #[test]
    fn wal_checkpoint_concrete_family_with_malformed_wal_remains_best_effort_usable() {
        let _guard = WAL_CHECKPOINT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let state_path = temp_state_path();
        let mut state = FirewallState::default();
        state
            .apply_add_rule(0, 0, 6, 0, Some("80"), 0, IP_FAMILY_V4)
            .unwrap();
        let snapshot_path = format!("{}/state.json", state_path);
        let wal_path = format!("{}/state.wal", state_path);
        fs::write(&snapshot_path, serde_json::to_vec_pretty(&state).unwrap()).unwrap();
        fs::write(&wal_path, b"{unrelated malformed record}\n").unwrap();
        let snapshot_before = fs::read(&snapshot_path).unwrap();
        let wal_before = fs::read(&wal_path).unwrap();

        let loaded = load_with_wal(&state_path)
            .expect("malformed WAL remains best-effort without family migration");

        assert_eq!(loaded.rules.len(), 1);
        assert_eq!(loaded.rules[0].ip_family, IP_FAMILY_V4);
        assert_eq!(fs::read(&snapshot_path).unwrap(), snapshot_before);
        assert_eq!(fs::read(&wal_path).unwrap(), wal_before);
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
        })
        .unwrap();
        wal.append(&WalEntry::AddGroup {
            name: "cache".to_string(),
            cidr: "10.0.2.0/24".to_string(),
        })
        .unwrap();
        assert_eq!(wal.entry_count(), 2);

        // Apply entries to state for compact
        state.add_group("db", "10.0.1.0/24").unwrap();
        state.add_group("cache", "10.0.2.0/24").unwrap();

        // Compact
        let json = serde_json::to_string_pretty(&state).unwrap();
        wal.compact(&json).unwrap();
        assert_eq!(wal.entry_count(), 0);

        // WAL retains only the checkpoint header; it is not a mutation.
        let wal_contents = fs::read_to_string(format!("{}/state.wal", state_path)).unwrap();
        assert_eq!(wal_contents.lines().count(), 1);
        assert!(wal_contents.contains("wal_checkpoint"));

        // Snapshot should have all groups
        let loaded = load_with_wal(&state_path).unwrap();
        assert!(loaded.groups.contains_key("web"));
        assert!(loaded.groups.contains_key("db"));
        assert!(loaded.groups.contains_key("cache"));

        let _ = fs::remove_dir_all(&state_path);
    }

    #[test]
    fn wal_checkpoint_general_compact_post_publication_failure_remains_strict_error() {
        let _guard = WAL_CHECKPOINT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let state_path = temp_state_path();
        let state = FirewallState::default();
        let mut wal = WalWriter::open(&state_path).unwrap();

        let error = wal
            .compact_strict_with_hook(
                &serde_json::to_string_pretty(&state).unwrap(),
                |phase| match phase {
                    FamilyMigrationCheckpointPhase::BeforeCheckpointMarker => Ok(()),
                    FamilyMigrationCheckpointPhase::AfterCheckpointMarkerBeforeSnapshotPublication => {
                        Ok(())
                    }
                    FamilyMigrationCheckpointPhase::AfterSnapshotPublication => {
                        Err("injected strict post-publication failure".to_string())
                    }
                },
            )
            .expect_err("general compact callers must retain strict error behavior");

        assert_eq!(error, "injected strict post-publication failure");
        let published: FirewallState = serde_json::from_slice(
            &fs::read(format!("{}/state.json", state_path)).unwrap(),
        )
        .unwrap();
        assert!(published.wal_replay_cursor.checkpoint_id > 0);
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
        })
        .unwrap();
        let entry2 = serde_json::to_string(&WalEntry::AddGroup {
            name: "g2".to_string(),
            cidr: "10.0.1.0/24".to_string(),
        })
        .unwrap();
        writeln!(f, "{}", entry1).unwrap();
        writeln!(f, "{{corrupt json line}}").unwrap();
        writeln!(f, "{}", entry2).unwrap();

        let loaded = load_with_wal(&state_path).unwrap();
        assert!(
            loaded.groups.contains_key("g1"),
            "entry before corrupt line applied"
        );
        assert!(
            loaded.groups.contains_key("g2"),
            "entry after corrupt line applied"
        );

        let _ = fs::remove_dir_all(&state_path);
    }

    #[test]
    fn wal_empty_file_loads_default() {
        let state_path = temp_state_path();
        // No snapshot, no WAL
        let loaded = load_with_wal(&state_path).unwrap();
        assert!(loaded.groups.is_empty());
        assert_eq!(loaded.next_group_id, 1);

        let _ = fs::remove_dir_all(&state_path);
    }

    #[test]
    fn apply_all_entry_types() {
        let mut state = FirewallState::default();

        // AddGroup
        apply_wal_entry(
            &mut state,
            WalEntry::AddGroup {
                name: "web".to_string(),
                cidr: "10.0.0.0/24".to_string(),
            },
        );
        assert!(state.groups.contains_key("web"));

        // AddRule
        apply_wal_entry(
            &mut state,
            WalEntry::AddRule {
                src_id: 1,
                dst_id: 0,
                proto: 6,
                action: 0,
                ports: Some("80,443".to_string()),
                direction: 0,
                ip_family: IP_FAMILY_V4,
            },
        );
        assert_eq!(state.rules.len(), 1);

        // RemoveRule
        apply_wal_entry(
            &mut state,
            WalEntry::RemoveRule {
                src_id: 1,
                dst_id: 0,
                proto: 6,
                direction: 0,
                ip_family: IP_FAMILY_V4,
            },
        );
        assert_eq!(state.rules.len(), 0);

        // DeleteGroup
        apply_wal_entry(
            &mut state,
            WalEntry::DeleteGroup {
                name: "web".to_string(),
            },
        );
        assert!(!state.groups.contains_key("web"));

        // AddQos
        apply_wal_entry(
            &mut state,
            WalEntry::AddQos {
                group_name: "default".to_string(),
                group_id: 0,
                direction: 0,
                rate_bps: 1_000_000,
                burst_bytes: 125_000,
                priority: 1,
                mode: 0,
            },
        );
        assert_eq!(state.qos_rules.len(), 1);

        // DeleteQos
        apply_wal_entry(
            &mut state,
            WalEntry::DeleteQos {
                group_id: 0,
                direction: 0,
            },
        );
        assert_eq!(state.qos_rules.len(), 0);

        // UpdateConfig
        apply_wal_entry(
            &mut state,
            WalEntry::UpdateConfig {
                conntrack: Some(false),
                monitoring: None,
                acl: None,
                qos: None,
                mirror: None,
                tcprt: None,
                ssl: None,
            },
        );
        assert!(!state.conntrack_enabled);
        assert!(state.monitoring_enabled);

        // SetMaxPortPolicies
        apply_wal_entry(&mut state, WalEntry::SetMaxPortPolicies { max: 100 });
        assert_eq!(state.max_port_policies, 100);

        // SetAttachedIface
        apply_wal_entry(
            &mut state,
            WalEntry::SetAttachedIface {
                iface: "eth0".to_string(),
            },
        );
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
            wal.append(&WalEntry::AddGroup {
                name: "a".to_string(),
                cidr: "10.0.0.0/24".to_string(),
            })
            .unwrap();
            wal.append(&WalEntry::AddGroup {
                name: "b".to_string(),
                cidr: "10.0.1.0/24".to_string(),
            })
            .unwrap();
            wal.append(&WalEntry::AddGroup {
                name: "c".to_string(),
                cidr: "10.0.2.0/24".to_string(),
            })
            .unwrap();
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
        })
        .await
        .unwrap();
        wal.append(WalEntry::AddGroup {
            name: "db".to_string(),
            cidr: "10.0.1.0/24".to_string(),
        })
        .await
        .unwrap();
        wal.shutdown().await;

        let loaded = load_with_wal(&state_path).unwrap();
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
        })
        .await
        .unwrap();

        let mut state = FirewallState::default();
        state.add_group("web", "10.0.0.0/24").unwrap();
        wal.compact(serde_json::to_string_pretty(&state).unwrap())
            .await
            .unwrap();
        wal.shutdown().await;

        let wal_contents = fs::read_to_string(format!("{}/state.wal", state_path)).unwrap();
        assert_eq!(wal_contents.lines().count(), 1);
        assert!(wal_contents.contains("wal_checkpoint"));

        let loaded = load_with_wal(&state_path).unwrap();
        assert!(loaded.groups.contains_key("web"));

        let _ = fs::remove_dir_all(&state_path);
    }

    #[test]
    fn wal_checkpoint_retained_prefix_preserves_complete_allocator_parity() {
        let _guard = WAL_CHECKPOINT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let state_path = temp_state_path();
        let (entries, checkpoint) = wal_checkpoint_rule_update_chain();
        fs::write(
            format!("{}/state.json", state_path),
            wal_checkpoint_state_json(&checkpoint, 7),
        )
        .unwrap();
        let mut lines = wal_checkpoint_entry_lines(&entries);
        lines.push(wal_checkpoint_record(7, 1));
        wal_checkpoint_write_lines(&state_path, &lines);

        let recovered = load_with_wal(&state_path).unwrap();

        wal_checkpoint_assert_allocator_parity(&checkpoint, &recovered);
        let _ = fs::remove_dir_all(&state_path);
    }

    #[test]
    fn wal_checkpoint_matching_marker_applies_tail_once() {
        let _guard = WAL_CHECKPOINT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let state_path = temp_state_path();
        let (entries, checkpoint) = wal_checkpoint_rule_update_chain();
        let tail = WalEntry::AddRule {
            src_id: 1,
            dst_id: 2,
            proto: 6,
            action: 0,
            ports: Some("9443".to_string()),
            direction: 0,
            ip_family: IP_FAMILY_V4,
        };
        let mut expected = checkpoint.clone();
        assert!(apply_wal_entry(&mut expected, tail.clone()));
        fs::write(
            format!("{}/state.json", state_path),
            wal_checkpoint_state_json(&checkpoint, 7),
        )
        .unwrap();
        let mut lines = wal_checkpoint_entry_lines(&entries);
        lines.push(wal_checkpoint_record(7, 1));
        lines.push(serde_json::to_string(&tail).unwrap());
        wal_checkpoint_write_lines(&state_path, &lines);

        let recovered = load_with_wal(&state_path).unwrap();

        wal_checkpoint_assert_allocator_parity(&expected, &recovered);
        let _ = fs::remove_dir_all(&state_path);
    }

    #[test]
    fn wal_checkpoint_unmatched_marker_preserves_legacy_full_replay() {
        let _guard = WAL_CHECKPOINT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let state_path = temp_state_path();
        let (entries, _) = wal_checkpoint_rule_update_chain();
        let mut expected = FirewallState::default();
        for entry in entries.iter().cloned() {
            assert!(apply_wal_entry(&mut expected, entry));
        }
        fs::write(
            format!("{}/state.json", state_path),
            serde_json::to_string_pretty(&FirewallState::default()).unwrap(),
        )
        .unwrap();
        let mut lines = wal_checkpoint_entry_lines(&entries);
        lines.push(wal_checkpoint_record(8, 1));
        wal_checkpoint_write_lines(&state_path, &lines);

        let recovered = load_with_wal(&state_path).unwrap();

        wal_checkpoint_assert_allocator_parity(&expected, &recovered);
        let _ = fs::remove_dir_all(&state_path);
    }

    #[test]
    fn wal_checkpoint_discards_covered_prefix_failures_but_keeps_tail_failures() {
        let _guard = WAL_CHECKPOINT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let state_path = temp_state_path();
        let (_, checkpoint) = wal_checkpoint_rule_update_chain();
        fs::write(
            format!("{}/state.json", state_path),
            wal_checkpoint_state_json(&checkpoint, 7),
        )
        .unwrap();
        wal_checkpoint_write_lines(
            &state_path,
            &[
                "{covered-corruption}".to_string(),
                wal_checkpoint_record(7, 1),
                "{tail-corruption}".to_string(),
            ],
        );

        let _ = load_with_wal(&state_path).unwrap();

        assert_eq!(last_wal_replay_failures(), 1);
        let _ = fs::remove_dir_all(&state_path);
    }

    #[test]
    fn wal_checkpoint_unsupported_version_is_observable_and_never_matches() {
        let _guard = WAL_CHECKPOINT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let state_path = temp_state_path();
        let (_, checkpoint) = wal_checkpoint_rule_update_chain();
        fs::write(
            format!("{}/state.json", state_path),
            wal_checkpoint_state_json_with_version(&checkpoint, 7, 2),
        )
        .unwrap();
        wal_checkpoint_write_lines(&state_path, &[wal_checkpoint_record(7, 2)]);

        let _ = load_with_wal(&state_path).unwrap();

        assert!(last_wal_replay_failures() > 0);
        assert!(WalWriter::open(&state_path).is_err());
        let _ = fs::remove_dir_all(&state_path);
    }

    #[test]
    fn wal_checkpoint_legacy_snapshot_and_mutations_remain_compatible() {
        let _guard = WAL_CHECKPOINT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let state_path = temp_state_path();
        let (entries, _) = wal_checkpoint_rule_update_chain();
        let mut expected = FirewallState::default();
        for entry in entries.iter().cloned() {
            assert!(apply_wal_entry(&mut expected, entry));
        }
        fs::write(
            format!("{}/state.json", state_path),
            serde_json::to_string_pretty(&FirewallState::default()).unwrap(),
        )
        .unwrap();
        wal_checkpoint_write_lines(&state_path, &wal_checkpoint_entry_lines(&entries));

        let recovered = load_with_wal(&state_path).unwrap();

        wal_checkpoint_assert_allocator_parity(&expected, &recovered);
        let _ = fs::remove_dir_all(&state_path);
    }

    #[test]
    fn wal_checkpoint_successful_compact_installs_header_without_mutation_count() {
        let _guard = WAL_CHECKPOINT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let state_path = temp_state_path();
        let (_, checkpoint) = wal_checkpoint_rule_update_chain();
        let mut wal = WalWriter::open(&state_path).unwrap();

        wal.compact(&serde_json::to_string_pretty(&checkpoint).unwrap())
            .unwrap();

        assert_eq!(wal.entry_count(), 0);
        let lines = fs::read_to_string(format!("{}/state.wal", state_path)).unwrap();
        let lines = lines.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 1);
        let marker: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(marker["wal_checkpoint"]["version"], 1);
        assert!(marker["wal_checkpoint"]["checkpoint_id"].as_u64().unwrap() > 0);
        let _ = fs::remove_dir_all(&state_path);
    }

    #[test]
    fn wal_checkpoint_empty_post_truncate_wal_repairs_header_before_append() {
        let _guard = WAL_CHECKPOINT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let state_path = temp_state_path();
        let state = FirewallState::default();
        fs::write(
            format!("{}/state.json", state_path),
            wal_checkpoint_state_json(&state, 9),
        )
        .unwrap();
        fs::write(format!("{}/state.wal", state_path), b"").unwrap();
        let mut wal = WalWriter::open(&state_path).unwrap();

        wal.append(&WalEntry::AddGroup {
            name: "tail".to_string(),
            cidr: "192.0.2.0/24".to_string(),
        })
        .unwrap();

        let lines = fs::read_to_string(format!("{}/state.wal", state_path)).unwrap();
        let lines = lines.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 2);
        let marker: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(marker["wal_checkpoint"]["checkpoint_id"], 9);
        let _ = fs::remove_dir_all(&state_path);
    }

    #[test]
    fn wal_checkpoint_id_advances_past_failed_attempt_markers() {
        let _guard = WAL_CHECKPOINT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let state_path = temp_state_path();
        let state = FirewallState::default();
        fs::write(
            format!("{}/state.json", state_path),
            wal_checkpoint_state_json(&state, 9),
        )
        .unwrap();
        wal_checkpoint_write_lines(&state_path, &[wal_checkpoint_record(10, 1)]);
        let mut wal = WalWriter::open(&state_path).unwrap();

        wal.compact(&serde_json::to_string_pretty(&state).unwrap())
            .unwrap();

        let contents = fs::read_to_string(format!("{}/state.wal", state_path)).unwrap();
        let marker: serde_json::Value =
            serde_json::from_str(contents.lines().next().unwrap()).unwrap();
        assert!(marker["wal_checkpoint"]["checkpoint_id"]
            .as_u64()
            .unwrap()
            > 10);
        let _ = fs::remove_dir_all(&state_path);
    }

    #[test]
    fn wal_checkpoint_id_overflow_never_truncates_or_wraps() {
        let _guard = WAL_CHECKPOINT_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let state_path = temp_state_path();
        let state = FirewallState::default();
        fs::write(
            format!("{}/state.json", state_path),
            wal_checkpoint_state_json(&state, u64::MAX),
        )
        .unwrap();
        let original = format!("{}\n", wal_checkpoint_record(u64::MAX, 1));
        fs::write(format!("{}/state.wal", state_path), &original).unwrap();
        let mut wal = WalWriter::open(&state_path).unwrap();

        let error = wal
            .compact(&serde_json::to_string_pretty(&state).unwrap())
            .expect_err("checkpoint IDs must not wrap");

        assert!(error.contains("checkpoint"));
        assert_eq!(
            fs::read_to_string(format!("{}/state.wal", state_path)).unwrap(),
            original
        );
        let _ = fs::remove_dir_all(&state_path);
    }

    struct ScriptedReader {
        chunks: std::collections::VecDeque<std::io::Result<Vec<u8>>>,
        current: Vec<u8>,
        pos: usize,
    }

    impl ScriptedReader {
        fn new(chunks: Vec<std::io::Result<Vec<u8>>>) -> Self {
            Self {
                chunks: chunks.into(),
                current: Vec::new(),
                pos: 0,
            }
        }
    }

    impl std::io::BufRead for ScriptedReader {
        fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
            if self.pos < self.current.len() {
                return Ok(&self.current[self.pos..]);
            }
            match self.chunks.pop_front() {
                None => Ok(&[]),
                Some(Err(error)) => Err(error),
                Some(Ok(bytes)) => {
                    self.current = bytes;
                    self.pos = 0;
                    Ok(&self.current)
                }
            }
        }

        fn consume(&mut self, amount: usize) {
            self.pos += amount;
        }
    }

    impl std::io::Read for ScriptedReader {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let filled = self.fill_buf()?;
            let count = filled.len().min(buffer.len());
            buffer[..count].copy_from_slice(&filled[..count]);
            self.consume(count);
            Ok(count)
        }
    }

    fn scripted_line(line: String) -> Vec<u8> {
        format!("{}\n", line).into_bytes()
    }

    #[test]
    fn wal_inventory_propagates_read_errors() {
        let reader = ScriptedReader::new(vec![
            Ok(scripted_line(wal_checkpoint_record(3, 1))),
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "injected read failure",
            )),
            Ok(scripted_line(wal_checkpoint_record(4, 1))),
        ]);
        let result = inventory_wal_reader(reader, None);

        match result {
            Err(error) => assert!(error.contains("injected read failure")),
            Ok(_) => panic!("expected the read error to propagate"),
        }
    }

    #[test]
    fn wal_inventory_skips_non_utf8_records() {
        let reader = ScriptedReader::new(vec![
            Ok(scripted_line(wal_checkpoint_record(3, 1))),
            Ok(vec![0xff, 0xfe, b'\n']),
            Ok(scripted_line(wal_checkpoint_record(5, 1))),
        ]);
        let inventory = inventory_wal_reader(reader, None).unwrap();

        assert_eq!(5, inventory.max_checkpoint_id);
        assert!(inventory.has_nonempty_line);
    }
}
