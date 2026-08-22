use aria_api::{ManagedNeutronPort, NeutronPortStatus};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use tracing::warn;

use crate::neutron_maintenance::{
    decode_maintenance_record, replay_maintenance_records, MaintenanceReplay,
    MaintenanceWalRecord,
};

const WAL_FILE: &str = "neutron-snapshot.wal";
const NEUTRON_WAL_SOFT_BYTES: u64 = 16 * 1024 * 1024;
const NEUTRON_WAL_HARD_BYTES: u64 = 64 * 1024 * 1024;
const INVENTORY_UNAVAILABLE_RECOVERY_CAUSE: &str = "inventory_unavailable";

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct NeutronWalReplay {
    pub(crate) state: NeutronWalState,
    pub(crate) status: String,
    pub(crate) replayed: u64,
    pub(crate) failures: u64,
    pub(crate) maintenance_failures: u64,
    pub(crate) pending_intent: Option<PendingNeutronIntent>,
    pub(crate) maintenance: MaintenanceReplay,
}

#[derive(Clone, Debug)]
struct NeutronWalScan {
    last_committed_state: Option<NeutronWalState>,
    pending_intent: Option<PendingNeutronIntent>,
    replayed: u64,
    failures: u64,
    maintenance_failures: u64,
    maintenance_records: Vec<MaintenanceWalRecord>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct PendingNeutronIntent {
    pub(crate) kind: String,
    pub(crate) generation: u64,
    pub(crate) desired_hash: Option<String>,
    pub(crate) port_ids: Vec<String>,
    pub(crate) affected_domains: Vec<String>,
    pub(crate) affected_ports: Vec<ManagedNeutronPort>,
    pub(crate) recovery_cause: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) applied_baseline_ports: Option<BTreeMap<String, ManagedNeutronPort>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) applied_baseline_port_statuses: Option<BTreeMap<String, NeutronPortStatus>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) recovery_cause: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    applied_baseline_ports: Option<&'a BTreeMap<String, ManagedNeutronPort>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    applied_baseline_port_statuses: Option<&'a BTreeMap<String, NeutronPortStatus>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recovery_cause: Option<&'a str>,
}

#[derive(Serialize)]
struct NeutronWalSnapshotIntentHashPayload<'a> {
    generation: u64,
    desired_hash: &'a Option<String>,
    port_ids: &'a [String],
    affected_domains: &'a [String],
    affected_ports: &'a [ManagedNeutronPort],
    recovery_cause: &'a str,
}

fn compute_snapshot_intent_hash(
    generation: u64,
    desired_hash: &Option<String>,
    port_ids: &[String],
    affected_domains: &[String],
    affected_ports: &[ManagedNeutronPort],
    recovery_cause: &str,
) -> Result<String, String> {
    let payload = NeutronWalSnapshotIntentHashPayload {
        generation,
        desired_hash,
        port_ids,
        affected_domains,
        affected_ports,
        recovery_cause,
    };
    let bytes = serde_json::to_vec(&payload)
        .map_err(|e| format!("serialize Neutron WAL snapshot intent hash payload: {}", e))?;
    let digest = Sha256::digest(bytes);
    Ok(digest
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<Vec<_>>()
        .join(""))
}

fn snapshot_intent_integrity_valid(
    generation: u64,
    desired_hash: &Option<String>,
    port_ids: &[String],
    affected_domains: &[String],
    affected_ports: &[ManagedNeutronPort],
    recovery_cause: Option<&str>,
    intent_hash: Option<&str>,
) -> Result<bool, String> {
    match (recovery_cause, intent_hash) {
        (None, None) => Ok(true),
        (Some(cause), Some(expected_hash))
            if cause == INVENTORY_UNAVAILABLE_RECOVERY_CAUSE
                && port_ids.is_empty()
                && affected_ports.is_empty() =>
        {
            let actual_hash = compute_snapshot_intent_hash(
                generation,
                desired_hash,
                port_ids,
                affected_domains,
                affected_ports,
                cause,
            )?;
            Ok(expected_hash == actual_hash.as_str())
        }
        _ => Ok(false),
    }
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
            applied_baseline_ports: self.applied_baseline_ports.as_ref(),
            applied_baseline_port_statuses: self.applied_baseline_port_statuses.as_ref(),
            recovery_cause: self.recovery_cause.as_deref(),
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
            return Ok(self.recovery_cause.is_none());
        };
        Ok(expected == &self.compute_status_hash()?)
    }
}

fn is_protected_inventory_intent(intent: &PendingNeutronIntent) -> bool {
    intent.kind == "snapshot"
        && intent.recovery_cause.as_deref() == Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE)
}

fn protected_inventory_snapshot_commit_valid(
    state: &NeutronWalState,
    intent: &PendingNeutronIntent,
    baseline: &NeutronWalState,
) -> Result<bool, String> {
    Ok(state.status_hash.is_some()
        && state.status_hash_valid()?
        && state.recovery_cause.as_deref() == Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE)
        && state.accepted_generation == intent.generation
        && state.pending_generation == Some(intent.generation)
        && state.desired_hash == intent.desired_hash
        && state.authority_state == "blocked_recovery_required"
        && state.applied_generation == baseline.applied_generation
        && state.applied_desired_hash == baseline.applied_desired_hash
        && state.ports == baseline.ports
        && state.port_statuses == baseline.port_statuses)
}

fn blocked_delete_snapshot_commit_valid(
    state: &NeutronWalState,
    intent: &PendingNeutronIntent,
    baseline: &NeutronWalState,
) -> Result<bool, String> {
    Ok(intent.kind == "delete"
        && state.status_hash.is_some()
        && state.status_hash_valid()?
        && state.pending_generation == Some(intent.generation)
        && state.desired_hash.is_none()
        && state.authority_state == "blocked_recovery_required"
        && state.accepted_generation == baseline.accepted_generation
        && state.applied_generation == baseline.applied_generation
        && state.applied_desired_hash == baseline.applied_desired_hash
        && intent.port_ids.iter().all(|port_id| {
            state.ports.contains_key(port_id) && state.port_statuses.contains_key(port_id)
        }))
}

fn matching_delete_commit_valid(
    state: &NeutronWalState,
    intent: &PendingNeutronIntent,
    baseline: &NeutronWalState,
) -> Result<bool, String> {
    Ok(intent.kind == "delete"
        && state.status_hash_valid()?
        && state.accepted_generation == intent.generation
        && state.accepted_generation == baseline.accepted_generation
        && state.applied_generation == baseline.applied_generation
        && state.applied_desired_hash == baseline.applied_desired_hash
        && state.pending_generation.is_none()
        && state.desired_hash == state.applied_desired_hash
        && intent.port_ids.iter().all(|port_id| {
            !state.ports.contains_key(port_id) && !state.port_statuses.contains_key(port_id)
        }))
}

fn empty_neutron_wal_state() -> NeutronWalState {
    NeutronWalState {
        authority_state: "idle".to_string(),
        ..NeutronWalState::default()
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
        #[serde(default, skip_serializing_if = "Option::is_none")]
        recovery_cause: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        intent_hash: Option<String>,
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
    Maintenance {
        record: MaintenanceWalRecord,
    },
}

fn looks_like_maintenance_entry(raw: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(raw)
        .ok()
        .and_then(|value| value.get("type").cloned())
        .and_then(|value| value.as_str().map(str::to_owned))
        .as_deref()
        == Some("maintenance")
        || raw
            .windows(b"\"type\":\"maintenance\"".len())
            .any(|window| window == b"\"type\":\"maintenance\"")
}

#[derive(Clone, Copy, Debug)]
struct NeutronWalLimits {
    soft_bytes: u64,
    hard_bytes: u64,
}

impl Default for NeutronWalLimits {
    fn default() -> Self {
        Self {
            soft_bytes: NEUTRON_WAL_SOFT_BYTES,
            hard_bytes: NEUTRON_WAL_HARD_BYTES,
        }
    }
}

#[derive(Debug)]
enum CheckpointInstallError {
    BeforeRename(String),
    AfterRename(String),
}

#[derive(Clone, Debug)]
pub(crate) struct NeutronWal {
    path: PathBuf,
    limits: NeutronWalLimits,
}

impl NeutronWal {
    pub(crate) fn new(base_state_path: impl AsRef<Path>) -> Self {
        Self {
            path: base_state_path.as_ref().join(WAL_FILE),
            limits: NeutronWalLimits::default(),
        }
    }

    #[cfg(test)]
    fn with_limits(
        base_state_path: impl AsRef<Path>,
        limits: NeutronWalLimits,
    ) -> Self {
        assert!(
            limits.soft_bytes <= limits.hard_bytes,
            "Neutron WAL soft limit must not exceed hard limit"
        );
        Self {
            path: base_state_path.as_ref().join(WAL_FILE),
            limits,
        }
    }

    fn scan(&self) -> NeutronWalScan {
        let mut scan = NeutronWalScan {
            last_committed_state: None,
            pending_intent: None,
            replayed: 0,
            failures: 0,
            maintenance_failures: 0,
            maintenance_records: Vec::new(),
        };

        let file = match File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return scan,
            Err(_) => {
                scan.failures = 1;
                return scan;
            }
        };

        let mut reader = BufReader::new(file);
        let mut record = Vec::new();
        loop {
            record.clear();
            match reader.read_until(b'\n', &mut record) {
                Ok(0) => break,
                Ok(_) => {}
                Err(_) => {
                    scan.failures += 1;
                    break;
                }
            }
            if record.iter().all(|byte| byte.is_ascii_whitespace()) {
                continue;
            }
            let entry = match serde_json::from_slice::<NeutronWalEntry>(&record) {
                Ok(entry) => entry,
                Err(_) => {
                    scan.failures += 1;
                    if looks_like_maintenance_entry(&record) {
                        scan.maintenance_failures += 1;
                    }
                    continue;
                }
            };
            scan.replayed += 1;
            match entry {
                NeutronWalEntry::Maintenance { record } => {
                    let encoded = match serde_json::to_vec(&record) {
                        Ok(encoded) => encoded,
                        Err(_) => {
                            scan.failures += 1;
                            scan.maintenance_failures += 1;
                            continue;
                        }
                    };
                    match decode_maintenance_record(&encoded) {
                        Ok(record) => scan.maintenance_records.push(record),
                        Err(_) => {
                            scan.failures += 1;
                            scan.maintenance_failures += 1;
                        }
                    }
                }
                NeutronWalEntry::SnapshotIntent {
                    generation,
                    desired_hash,
                    mut port_ids,
                    affected_domains,
                    affected_ports,
                    recovery_cause,
                    intent_hash,
                } => {
                    match snapshot_intent_integrity_valid(
                        generation,
                        &desired_hash,
                        &port_ids,
                        &affected_domains,
                        &affected_ports,
                        recovery_cause.as_deref(),
                        intent_hash.as_deref(),
                    ) {
                        Ok(true) => {}
                        Ok(false) | Err(_) => {
                            scan.failures += 1;
                            continue;
                        }
                    }
                    if port_ids.is_empty() {
                        port_ids = affected_ports
                            .iter()
                            .map(|port| port.port_id.clone())
                            .collect();
                    }
                    scan.pending_intent = Some(PendingNeutronIntent {
                        kind: "snapshot".to_string(),
                        generation,
                        desired_hash,
                        port_ids,
                        affected_domains,
                        affected_ports,
                        recovery_cause,
                    });
                }
                NeutronWalEntry::DeleteIntent {
                    port_id,
                    generation,
                    affected_domains,
                    port,
                } => {
                    let affected_ports = port.into_iter().collect();
                    scan.pending_intent = Some(PendingNeutronIntent {
                        kind: "delete".to_string(),
                        generation,
                        desired_hash: None,
                        port_ids: vec![port_id],
                        affected_domains,
                        affected_ports,
                        recovery_cause: None,
                    });
                }
                NeutronWalEntry::SnapshotCommit { state }
                    if scan
                        .pending_intent
                        .as_ref()
                        .map_or(false, is_protected_inventory_intent) =>
                {
                    let intent = scan
                        .pending_intent
                        .as_ref()
                        .expect("protected inventory intent guard requires a pending intent");
                    let baseline = scan
                        .last_committed_state
                        .as_ref()
                        .cloned()
                        .unwrap_or_else(empty_neutron_wal_state);
                    match protected_inventory_snapshot_commit_valid(&state, intent, &baseline) {
                        Ok(true) => {
                            scan.last_committed_state = Some(state);
                            scan.pending_intent = None;
                        }
                        Ok(false) | Err(_) => {
                            scan.failures += 1;
                        }
                    }
                }
                NeutronWalEntry::DeleteCommit { .. }
                    if scan
                        .pending_intent
                        .as_ref()
                        .map_or(false, is_protected_inventory_intent) =>
                {
                    scan.failures += 1;
                }
                NeutronWalEntry::SnapshotCommit { state }
                    if scan
                        .pending_intent
                        .as_ref()
                        .is_some_and(|intent| intent.kind == "delete") =>
                {
                    let intent = scan
                        .pending_intent
                        .as_ref()
                        .expect("delete intent guard requires a pending intent");
                    let baseline = scan
                        .last_committed_state
                        .as_ref()
                        .cloned()
                        .unwrap_or_else(empty_neutron_wal_state);
                    match blocked_delete_snapshot_commit_valid(&state, intent, &baseline) {
                        Ok(true) => {
                            scan.last_committed_state = Some(state);
                        }
                        Ok(false) | Err(_) => {
                            scan.failures += 1;
                        }
                    }
                }
                NeutronWalEntry::DeleteCommit { state }
                    if scan
                        .pending_intent
                        .as_ref()
                        .is_some_and(|intent| intent.kind == "delete") =>
                {
                    let intent = scan
                        .pending_intent
                        .as_ref()
                        .expect("delete intent guard requires a pending intent");
                    let baseline = scan
                        .last_committed_state
                        .as_ref()
                        .cloned()
                        .unwrap_or_else(empty_neutron_wal_state);
                    match matching_delete_commit_valid(&state, intent, &baseline) {
                        Ok(true) => {
                            scan.last_committed_state = Some(state);
                            scan.pending_intent = None;
                        }
                        Ok(false) | Err(_) => {
                            scan.failures += 1;
                        }
                    }
                }
                NeutronWalEntry::DeleteCommit { .. } if scan.pending_intent.is_some() => {
                    scan.failures += 1;
                }
                NeutronWalEntry::SnapshotCommit { state }
                | NeutronWalEntry::DeleteCommit { state } => {
                    if !matches!(state.status_hash_valid(), Ok(true)) {
                        scan.failures += 1;
                        continue;
                    }
                    scan.last_committed_state = Some(state);
                    scan.pending_intent = None;
                }
            }
        }
        scan
    }

    fn replay_from_scan(scan: NeutronWalScan) -> NeutronWalReplay {
        let mut replay = NeutronWalReplay {
            state: scan
                .last_committed_state
                .unwrap_or_else(empty_neutron_wal_state),
            status: "empty".to_string(),
            replayed: scan.replayed,
            failures: scan.failures,
            maintenance_failures: scan.maintenance_failures,
            pending_intent: None,
            maintenance: MaintenanceReplay::default(),
        };

        for end in 1..=scan.maintenance_records.len() {
            match replay_maintenance_records(&scan.maintenance_records[..end]) {
                Ok(maintenance) => replay.maintenance = maintenance,
                Err(_) => {
                    replay.failures += 1;
                    replay.maintenance_failures += 1;
                    break;
                }
            }
        }

        if let Some(intent) = scan.pending_intent {
            replay.state.pending_generation = Some(intent.generation);
            replay.state.desired_hash = intent.desired_hash.clone();
            replay.state.authority_state = "wal_intent_without_commit".to_string();
            replay.status = "intent_without_commit".to_string();
            replay.pending_intent = Some(intent);
        } else if replay.failures > 0 {
            replay.status = "replayed_with_errors".to_string();
        } else if let Some(cause) = replay.state.recovery_cause.as_ref() {
            replay.status = cause.clone();
        } else if replay.replayed > 0 {
            replay.status = "replayed".to_string();
        }

        replay
    }

    pub(crate) fn replay(&self) -> NeutronWalReplay {
        Self::replay_from_scan(self.scan())
    }

    fn entry_for_pending_intent(
        intent: &PendingNeutronIntent,
    ) -> Result<NeutronWalEntry, String> {
        match intent.kind.as_str() {
            "snapshot" => {
                let intent_hash = match intent.recovery_cause.as_deref() {
                    None => None,
                    Some(cause)
                        if cause == INVENTORY_UNAVAILABLE_RECOVERY_CAUSE
                            && intent.port_ids.is_empty()
                            && intent.affected_ports.is_empty() =>
                    {
                        Some(compute_snapshot_intent_hash(
                            intent.generation,
                            &intent.desired_hash,
                            &intent.port_ids,
                            &intent.affected_domains,
                            &intent.affected_ports,
                            cause,
                        )?)
                    }
                    Some(cause) => {
                        return Err(format!(
                            "cannot checkpoint Neutron snapshot intent with recovery cause {}",
                            cause
                        ));
                    }
                };
                Ok(NeutronWalEntry::SnapshotIntent {
                    generation: intent.generation,
                    desired_hash: intent.desired_hash.clone(),
                    port_ids: intent.port_ids.clone(),
                    affected_domains: intent.affected_domains.clone(),
                    affected_ports: intent.affected_ports.clone(),
                    recovery_cause: intent.recovery_cause.clone(),
                    intent_hash,
                })
            }
            "delete" => {
                if intent.recovery_cause.is_some() || intent.desired_hash.is_some() {
                    return Err(
                        "cannot checkpoint Neutron delete intent with snapshot-only fields"
                            .to_string(),
                    );
                }
                let [port_id] = intent.port_ids.as_slice() else {
                    return Err(format!(
                        "cannot checkpoint Neutron delete intent with {} port IDs",
                        intent.port_ids.len()
                    ));
                };
                if intent.affected_ports.len() > 1 {
                    return Err(format!(
                        "cannot checkpoint Neutron delete intent with {} affected ports",
                        intent.affected_ports.len()
                    ));
                }
                Ok(NeutronWalEntry::DeleteIntent {
                    port_id: port_id.clone(),
                    generation: intent.generation,
                    affected_domains: intent.affected_domains.clone(),
                    port: intent.affected_ports.first().cloned(),
                })
            }
            kind => Err(format!(
                "cannot checkpoint unknown Neutron WAL intent kind {}",
                kind
            )),
        }
    }

    fn canonical_checkpoint_bytes(&self) -> Result<Vec<u8>, String> {
        let scan = self.scan();
        if scan.failures != 0 {
            return Err(format!(
                "cannot compact Neutron WAL with {} replay failures",
                scan.failures
            ));
        }
        replay_maintenance_records(&scan.maintenance_records).map_err(|error| {
            format!(
                "cannot compact Neutron WAL with maintenance replay failure: {}",
                error
            )
        })?;

        let mut entries = Vec::new();
        if let Some(state) = scan.last_committed_state {
            entries.push(NeutronWalEntry::SnapshotCommit { state });
        }
        if let Some(intent) = scan.pending_intent.as_ref() {
            entries.push(Self::entry_for_pending_intent(intent)?);
        }
        entries.extend(
            scan.maintenance_records
                .into_iter()
                .map(|record| NeutronWalEntry::Maintenance { record }),
        );

        let mut bytes = Vec::new();
        for entry in entries {
            bytes.extend_from_slice(
                &serde_json::to_vec(&entry)
                    .map_err(|error| format!("serialize Neutron WAL checkpoint: {}", error))?,
            );
            bytes.push(b'\n');
        }
        Ok(bytes)
    }

    pub(crate) fn append_snapshot_intent(
        &self,
        generation: u64,
        desired_hash: Option<String>,
        port_ids: Vec<String>,
        affected_domains: Vec<String>,
        affected_ports: Vec<ManagedNeutronPort>,
        recovery_cause: Option<String>,
    ) -> Result<(), String> {
        let intent_hash = match recovery_cause.as_deref() {
            None => None,
            Some(cause)
                if cause == INVENTORY_UNAVAILABLE_RECOVERY_CAUSE
                    && port_ids.is_empty()
                    && affected_ports.is_empty() =>
            {
                Some(compute_snapshot_intent_hash(
                    generation,
                    &desired_hash,
                    &port_ids,
                    &affected_domains,
                    &affected_ports,
                    cause,
                )?)
            }
            Some(cause) => {
                return Err(format!(
                    "invalid Neutron snapshot intent recovery cause or scope: {}",
                    cause
                ));
            }
        };
        self.append(&NeutronWalEntry::SnapshotIntent {
            generation,
            desired_hash,
            port_ids,
            affected_domains,
            affected_ports,
            recovery_cause,
            intent_hash,
        })
    }

    pub(crate) fn append_snapshot_commit(&self, state: NeutronWalState) -> Result<(), String> {
        self.append(&NeutronWalEntry::SnapshotCommit {
            state: state.with_status_hash()?,
        })
    }

    pub(crate) fn append_verified_protected_inventory_commit(
        &self,
        expected_intent: &PendingNeutronIntent,
        state: NeutronWalState,
    ) -> Result<NeutronWalReplay, String> {
        let before = self.replay();
        if before.failures != 0 {
            return Err(format!(
                "cannot resolve protected inventory intent with {} WAL replay failures",
                before.failures
            ));
        }
        if !is_protected_inventory_intent(expected_intent) {
            return Err("expected intent is not a protected inventory intent".to_string());
        }
        let Some(actual_intent) = before.pending_intent.as_ref() else {
            return Err("protected inventory intent is no longer pending".to_string());
        };
        if actual_intent != expected_intent {
            return Err("protected inventory intent changed before commit".to_string());
        }

        let state = state.with_status_hash()?;
        if !protected_inventory_snapshot_commit_valid(&state, actual_intent, &before.state)? {
            return Err(
                "live blocked state does not match the protected inventory intent and baseline"
                    .to_string(),
            );
        }
        self.append(&NeutronWalEntry::SnapshotCommit {
            state: state.clone(),
        })?;

        let after = self.replay();
        if after.failures != 0 {
            return Err(format!(
                "protected inventory commit replayed with {} failures",
                after.failures
            ));
        }
        if after.pending_intent.is_some() {
            return Err("protected inventory intent remained pending after commit".to_string());
        }
        if after.status != INVENTORY_UNAVAILABLE_RECOVERY_CAUSE {
            return Err(format!(
                "protected inventory commit replayed with unexpected status {}",
                after.status
            ));
        }
        if after.state != state {
            return Err("protected inventory commit replayed a different state".to_string());
        }
        Ok(after)
    }

    pub(crate) fn append_snapshot_commit_after_verified_inventory_barrier(
        &self,
        blocked_state: NeutronWalState,
        next_state: NeutronWalState,
    ) -> Result<(), String> {
        let blocked_state = blocked_state.with_status_hash()?;
        let replay = self.replay();
        if replay.failures != 0 {
            return Err(format!(
                "cannot continue inventory recovery with {} WAL replay failures",
                replay.failures
            ));
        }
        if replay.pending_intent.is_some() {
            return Err("inventory recovery barrier still has a pending intent".to_string());
        }
        if replay.status != INVENTORY_UNAVAILABLE_RECOVERY_CAUSE {
            return Err(format!(
                "inventory recovery barrier replayed with unexpected status {}",
                replay.status
            ));
        }
        if replay.state != blocked_state {
            return Err("inventory recovery barrier does not match live blocked state".to_string());
        }
        self.append(&NeutronWalEntry::SnapshotCommit {
            state: next_state.with_status_hash()?,
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

    pub(crate) fn append_maintenance_record(
        &self,
        record: MaintenanceWalRecord,
    ) -> Result<(), String> {
        let encoded = serde_json::to_vec(&record)
            .map_err(|error| format!("serialize maintenance WAL record: {}", error))?;
        decode_maintenance_record(&encoded)?;
        self.append(&NeutronWalEntry::Maintenance { record })
    }

    fn checkpoint_temp_path(&self) -> PathBuf {
        let mut path = self.path.as_os_str().to_os_string();
        path.push(".compact.tmp");
        PathBuf::from(path)
    }

    #[cfg(test)]
    fn checkpoint_temp_path_for_test(&self) -> PathBuf {
        self.checkpoint_temp_path()
    }

    fn install_checkpoint(
        &self,
        checkpoint: &[u8],
    ) -> Result<(), CheckpointInstallError> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                CheckpointInstallError::BeforeRename(format!(
                    "create Neutron WAL directory {}: {}",
                    parent.display(),
                    error
                ))
            })?;
        }

        let temp_path = self.checkpoint_temp_path();
        match fs::symlink_metadata(&temp_path) {
            Ok(metadata) if metadata.file_type().is_file() => {
                fs::remove_file(&temp_path).map_err(|error| {
                    CheckpointInstallError::BeforeRename(format!(
                        "remove stale Neutron WAL checkpoint {}: {}",
                        temp_path.display(),
                        error
                    ))
                })?;
            }
            Ok(_) => {
                return Err(CheckpointInstallError::BeforeRename(format!(
                    "stale Neutron WAL checkpoint path is not a regular file: {}",
                    temp_path.display()
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(CheckpointInstallError::BeforeRename(format!(
                    "inspect Neutron WAL checkpoint {}: {}",
                    temp_path.display(),
                    error
                )));
            }
        }

        let file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp_path)
            .map_err(|error| {
                CheckpointInstallError::BeforeRename(format!(
                    "create Neutron WAL checkpoint {}: {}",
                    temp_path.display(),
                    error
                ))
            })?;
        let mut writer = BufWriter::new(file);
        writer
            .write_all(checkpoint)
            .map_err(|error| {
                CheckpointInstallError::BeforeRename(format!(
                    "write Neutron WAL checkpoint {}: {}",
                    temp_path.display(),
                    error
                ))
            })?;
        writer
            .flush()
            .map_err(|error| {
                CheckpointInstallError::BeforeRename(format!(
                    "flush Neutron WAL checkpoint {}: {}",
                    temp_path.display(),
                    error
                ))
            })?;
        writer
            .get_ref()
            .sync_all()
            .map_err(|error| {
                CheckpointInstallError::BeforeRename(format!(
                    "fsync Neutron WAL checkpoint {}: {}",
                    temp_path.display(),
                    error
                ))
            })?;
        drop(writer);

        fs::rename(&temp_path, &self.path).map_err(|error| {
            CheckpointInstallError::BeforeRename(format!(
                "replace Neutron WAL {} from checkpoint {}: {}",
                self.path.display(),
                temp_path.display(),
                error
            ))
        })?;

        if let Some(parent) = self.path.parent() {
            sync_directory(parent).map_err(|error| {
                CheckpointInstallError::AfterRename(format!(
                    "fsync Neutron WAL directory {} after checkpoint: {}",
                    parent.display(),
                    error
                ))
            })?;
        }
        Ok(())
    }

    #[cfg(test)]
    fn compact_now_for_test(&self) -> Result<(), String> {
        let checkpoint = self.canonical_checkpoint_bytes()?;
        let checkpoint_len = u64::try_from(checkpoint.len())
            .map_err(|_| "Neutron WAL checkpoint length does not fit u64".to_string())?;
        if checkpoint_len > self.limits.hard_bytes {
            return Err(self.hard_capacity_error(0, 0, Some(checkpoint_len), None));
        }
        self.install_checkpoint(&checkpoint)
            .map_err(|error| match error {
                CheckpointInstallError::BeforeRename(details) => details,
                CheckpointInstallError::AfterRename(details) => details,
            })
    }

    fn wal_length(&self) -> Result<u64, String> {
        match fs::metadata(&self.path) {
            Ok(metadata) => Ok(metadata.len()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(error) => Err(format!(
                "inspect Neutron WAL {}: {}",
                self.path.display(),
                error
            )),
        }
    }

    fn hard_capacity_error(
        &self,
        current_bytes: u64,
        entry_bytes: u64,
        checkpoint_bytes: Option<u64>,
        checkpoint_error: Option<&str>,
    ) -> String {
        format!(
            "neutron WAL hard capacity exceeded: current_bytes={} entry_bytes={} checkpoint_bytes={} hard_bytes={} checkpoint_error={}",
            current_bytes,
            entry_bytes,
            checkpoint_bytes
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unavailable".to_string()),
            self.limits.hard_bytes,
            checkpoint_error.unwrap_or("none")
        )
    }

    fn append(&self, entry: &NeutronWalEntry) -> Result<(), String> {
        let mut bytes = serde_json::to_vec(entry)
            .map_err(|error| format!("serialize Neutron WAL entry: {}", error))?;
        bytes.push(b'\n');
        let entry_bytes = u64::try_from(bytes.len())
            .map_err(|_| "Neutron WAL entry length does not fit u64".to_string())?;
        let current_bytes = self.wal_length()?;
        let projected_bytes = current_bytes
            .checked_add(entry_bytes)
            .ok_or_else(|| "Neutron WAL projected length overflow".to_string())?;

        if projected_bytes <= self.limits.soft_bytes {
            return self.append_serialized(&bytes);
        }

        let checkpoint = match self.canonical_checkpoint_bytes() {
            Ok(checkpoint) => checkpoint,
            Err(error) if projected_bytes <= self.limits.hard_bytes => {
                warn!(
                    current_bytes,
                    entry_bytes,
                    soft_bytes = self.limits.soft_bytes,
                    hard_bytes = self.limits.hard_bytes,
                    error = %error,
                    "neutron_wal_compaction_deferred"
                );
                return self.append_serialized(&bytes);
            }
            Err(error) => {
                return Err(self.hard_capacity_error(
                    current_bytes,
                    entry_bytes,
                    None,
                    Some(&error),
                ));
            }
        };

        let checkpoint_bytes = u64::try_from(checkpoint.len())
            .map_err(|_| "Neutron WAL checkpoint length does not fit u64".to_string())?;
        let compacted_projected_bytes = checkpoint_bytes
            .checked_add(entry_bytes)
            .ok_or_else(|| "Neutron WAL compacted length overflow".to_string())?;
        if compacted_projected_bytes > self.limits.hard_bytes {
            return Err(self.hard_capacity_error(
                current_bytes,
                entry_bytes,
                Some(checkpoint_bytes),
                None,
            ));
        }

        match self.install_checkpoint(&checkpoint) {
            Ok(()) => self.append_serialized(&bytes),
            Err(CheckpointInstallError::BeforeRename(error))
                if projected_bytes <= self.limits.hard_bytes =>
            {
                warn!(
                    current_bytes,
                    entry_bytes,
                    soft_bytes = self.limits.soft_bytes,
                    hard_bytes = self.limits.hard_bytes,
                    error = %error,
                    "neutron_wal_compaction_deferred"
                );
                self.append_serialized(&bytes)
            }
            Err(CheckpointInstallError::BeforeRename(error)) => Err(self.hard_capacity_error(
                current_bytes,
                entry_bytes,
                Some(checkpoint_bytes),
                Some(&error),
            )),
            Err(CheckpointInstallError::AfterRename(error)) => Err(format!(
                "Neutron WAL checkpoint durability failed after rename: {}",
                error
            )),
        }
    }

    fn append_serialized(&self, bytes: &[u8]) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("create Neutron WAL directory {}: {}", parent.display(), e))?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| format!("open Neutron WAL {}: {}", self.path.display(), e))?;
        let mut writer = BufWriter::new(file);
        writer
            .write_all(bytes)
            .map_err(|e| format!("write Neutron WAL entry: {}", e))?;
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
    use aria_api::{MaintenancePhase, MaintenanceState, MAINTENANCE_SCHEMA_VERSION};
    use crate::neutron_maintenance::MAINTENANCE_WAL_RECORD_MAX_BYTES;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Serialize)]
    struct TestSnapshotIntentHashPayload<'a> {
        generation: u64,
        desired_hash: &'a Option<String>,
        port_ids: &'a [String],
        affected_domains: &'a [String],
        affected_ports: &'a [ManagedNeutronPort],
        recovery_cause: &'a str,
    }

    fn temp_state_path() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("aria-neutron-wal-test-{}", nanos))
    }

    fn lifecycle_wal(root: &Path, soft_bytes: u64, hard_bytes: u64) -> NeutronWal {
        NeutronWal::with_limits(
            root,
            NeutronWalLimits {
                soft_bytes,
                hard_bytes,
            },
        )
    }

    fn wal_bytes(root: &Path) -> Vec<u8> {
        fs::read(root.join(WAL_FILE)).expect("WAL bytes should be readable")
    }

    fn managed(port_id: &str, ifname: &str) -> ManagedNeutronPort {
        ManagedNeutronPort {
            port_id: port_id.to_string(),
            ifname: ifname.to_string(),
            ifindex: None,
            managed_domains: vec!["acl".to_string()],
            domain_desired_hashes: BTreeMap::new(),
        }
    }

    fn maintenance_state(operation_id: &str) -> MaintenanceState {
        MaintenanceState {
            schema_version: MAINTENANCE_SCHEMA_VERSION,
            operation_id: Some(operation_id.to_string()),
            phase: MaintenancePhase::BypassPreparing,
            active_domains: vec!["acl".to_string()],
            expected_generation: 9,
            expected_desired_hash: Some("sha256:g9".to_string()),
            applied_generation: 9,
            applied_desired_hash: Some("sha256:g9".to_string()),
            bypass_started_at_ms: Some(100),
            last_progress_at_ms: 100,
            last_error: None,
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

    fn test_snapshot_intent_hash(
        generation: u64,
        desired_hash: &Option<String>,
        port_ids: &[String],
        affected_domains: &[String],
        affected_ports: &[ManagedNeutronPort],
        recovery_cause: &str,
    ) -> String {
        let payload = TestSnapshotIntentHashPayload {
            generation,
            desired_hash,
            port_ids,
            affected_domains,
            affected_ports,
            recovery_cause,
        };
        let bytes = serde_json::to_vec(&payload).expect("intent hash payload should serialize");
        Sha256::digest(bytes)
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<Vec<_>>()
            .join("")
    }

    fn hashed_snapshot_intent(
        generation: u64,
        desired_hash: Option<String>,
        port_ids: Vec<String>,
        affected_domains: Vec<String>,
        affected_ports: Vec<ManagedNeutronPort>,
        recovery_cause: &str,
    ) -> serde_json::Value {
        let intent_hash = test_snapshot_intent_hash(
            generation,
            &desired_hash,
            &port_ids,
            &affected_domains,
            &affected_ports,
            recovery_cause,
        );
        serde_json::json!({
            "type": "snapshot_intent",
            "generation": generation,
            "desired_hash": desired_hash,
            "port_ids": port_ids,
            "affected_domains": affected_domains,
            "affected_ports": affected_ports,
            "recovery_cause": recovery_cause,
            "intent_hash": intent_hash,
        })
    }

    fn write_wal_value(root: &Path, value: &serde_json::Value) {
        fs::create_dir_all(root).expect("WAL root should be creatable");
        let raw = format!(
            "{}\n",
            serde_json::to_string(value).expect("WAL value should serialize")
        );
        fs::write(root.join(WAL_FILE), raw).expect("WAL fixture should be writable");
    }

    fn hashless_snapshot_commit(generation: u64) -> serde_json::Value {
        serde_json::json!({
            "type": "snapshot_commit",
            "state": {
                "accepted_generation": generation,
                "applied_generation": generation,
                "authority_state": "ready",
                "ports": {},
                "port_statuses": {}
            }
        })
    }

    fn neutron_wal_baseline_state(generation: u64) -> NeutronWalState {
        let mut ports = BTreeMap::new();
        ports.insert("p1".to_string(), managed("p1", "tap-p1"));
        let mut port_statuses = BTreeMap::new();
        port_statuses.insert("p1".to_string(), port_status("p1", "tap-p1", generation));
        NeutronWalState {
            accepted_generation: generation,
            applied_generation: generation,
            desired_hash: Some(format!("hash-{}", generation)),
            applied_desired_hash: Some(format!("hash-{}", generation)),
            authority_state: "ready".to_string(),
            ports,
            port_statuses,
            ..NeutronWalState::default()
        }
    }

    fn encoded_snapshot_commit(generation: u64) -> Vec<u8> {
        let state = neutron_wal_baseline_state(generation)
            .with_status_hash()
            .expect("snapshot commit status hash should be computable");
        serde_json::to_vec(&NeutronWalEntry::SnapshotCommit { state })
            .expect("snapshot commit should serialize")
    }

    fn append_ready_commit(wal: &NeutronWal, generation: u64) {
        wal.append_snapshot_commit(neutron_wal_baseline_state(generation))
            .expect("ready commit should be durable");
    }

    fn protected_inventory_resolver_state(
        baseline: &NeutronWalState,
        generation: u64,
    ) -> NeutronWalState {
        let mut state = baseline.clone();
        state.accepted_generation = generation;
        state.pending_generation = Some(generation);
        state.desired_hash = Some(format!("hash-{}", generation));
        state.authority_state = "blocked_recovery_required".to_string();
        state.recovery_cause = Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE.to_string());
        state.status_hash = None;
        state
    }

    fn append_wal_value(root: &Path, value: &serde_json::Value) {
        let path = root.join(WAL_FILE);
        let mut raw = fs::read_to_string(&path).unwrap_or_default();
        raw.push_str(&serde_json::to_string(value).expect("WAL value should serialize"));
        raw.push('\n');
        fs::write(path, raw).expect("WAL fixture should be appendable");
    }

    fn hashless_snapshot_commit_for_state(state: NeutronWalState) -> serde_json::Value {
        let mut value = serde_json::to_value(NeutronWalEntry::SnapshotCommit { state }).unwrap();
        value["state"]
            .as_object_mut()
            .expect("snapshot commit state should be an object")
            .remove("status_hash");
        value
    }

    fn hashless_delete_commit_for_state(state: NeutronWalState) -> serde_json::Value {
        let mut value = serde_json::to_value(NeutronWalEntry::DeleteCommit { state }).unwrap();
        value["state"]
            .as_object_mut()
            .expect("delete commit state should be an object")
            .remove("status_hash");
        value
    }

    fn append_protected_inventory_intent(wal: &NeutronWal, generation: u64) {
        wal.append_snapshot_intent(
            generation,
            Some(format!("hash-{}", generation)),
            Vec::new(),
            vec!["acl".to_string()],
            Vec::new(),
            Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE.to_string()),
        )
        .expect("protected inventory intent should be durable");
    }

    fn assert_protected_inventory_intent_survives(
        replay: &NeutronWalReplay,
        baseline: &NeutronWalState,
        generation: u64,
        case: &str,
    ) {
        assert_eq!("intent_without_commit", replay.status, "{}", case);
        assert_eq!(1, replay.failures, "{}", case);
        assert_eq!(
            baseline.accepted_generation, replay.state.accepted_generation,
            "{}",
            case
        );
        assert_eq!(
            baseline.applied_generation, replay.state.applied_generation,
            "{}",
            case
        );
        assert_eq!(
            baseline.applied_desired_hash, replay.state.applied_desired_hash,
            "{}",
            case
        );
        assert_eq!(baseline.ports, replay.state.ports, "{}", case);
        assert_eq!(
            baseline.port_statuses, replay.state.port_statuses,
            "{}",
            case
        );
        assert_eq!(
            baseline.recovery_cause, replay.state.recovery_cause,
            "{}",
            case
        );
        assert_eq!(
            Some(generation),
            replay.state.pending_generation,
            "{}",
            case
        );
        assert_eq!(
            Some(format!("hash-{}", generation)),
            replay.state.desired_hash,
            "{}",
            case
        );
        assert_eq!(
            "wal_intent_without_commit", replay.state.authority_state,
            "{}",
            case
        );
        let pending = replay
            .pending_intent
            .as_ref()
            .unwrap_or_else(|| panic!("verified protected intent must remain pending: {}", case));
        assert_eq!(generation, pending.generation, "{}", case);
        assert!(pending.port_ids.is_empty(), "{}", case);
        assert!(pending.affected_ports.is_empty(), "{}", case);
        assert_eq!(
            Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE),
            pending.recovery_cause.as_deref(),
            "{}",
            case
        );
    }

    #[test]
    fn neutron_wal_ordinary_snapshot_intent_resolves_with_status_hashed_cause_free_commit() {
        let root = temp_state_path();
        let wal = NeutronWal::new(&root);
        wal.append_snapshot_intent(
            7,
            Some("hash-7".to_string()),
            vec!["p1".to_string()],
            vec!["acl".to_string()],
            vec![managed("p1", "tap-p1")],
            None,
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
        assert_eq!(
            Some("hash-7".to_string()),
            replay.state.applied_desired_hash
        );
        assert!(replay.state.status_hash.is_some());
        assert!(replay.state.ports.contains_key("p1"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn neutron_wal_ordinary_snapshot_intent_resolves_with_hashless_cause_free_commit() {
        let root = temp_state_path();
        let wal = NeutronWal::new(&root);
        wal.append_snapshot_intent(
            92,
            Some("hash-92".to_string()),
            vec!["p1".to_string()],
            vec!["acl".to_string()],
            vec![managed("p1", "tap-p1")],
            None,
        )
        .unwrap();
        let committed = neutron_wal_baseline_state(92);
        let legacy_commit = hashless_snapshot_commit_for_state(committed.clone());
        assert!(legacy_commit["state"].get("recovery_cause").is_none());
        assert!(legacy_commit["state"].get("status_hash").is_none());
        append_wal_value(&root, &legacy_commit);

        let replay = wal.replay();

        assert_eq!("replayed", replay.status);
        assert_eq!(0, replay.failures);
        assert!(replay.pending_intent.is_none());
        assert_eq!(
            committed.accepted_generation,
            replay.state.accepted_generation
        );
        assert_eq!(
            committed.applied_generation,
            replay.state.applied_generation
        );
        assert_eq!(
            committed.applied_desired_hash,
            replay.state.applied_desired_hash
        );
        assert_eq!(committed.ports, replay.state.ports);
        assert_eq!(committed.port_statuses, replay.state.port_statuses);
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
            None,
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
    fn legacy_hashless_snapshot_intent_without_recovery_cause_replays() {
        let root = temp_state_path();
        let legacy = serde_json::json!({
            "type": "snapshot_intent",
            "generation": 9,
            "desired_hash": "hash-9",
            "port_ids": ["p1"],
            "affected_domains": ["acl"],
            "affected_ports": [managed("p1", "tap-p1")],
        });
        let legacy_raw = serde_json::to_string(&legacy).unwrap();
        assert!(!legacy_raw.contains(r#""recovery_cause""#));
        assert!(!legacy_raw.contains(r#""intent_hash""#));
        write_wal_value(&root, &legacy);

        let replay = NeutronWal::new(&root).replay();

        assert_eq!("intent_without_commit", replay.status);
        assert_eq!(0, replay.failures);
        let intent = replay
            .pending_intent
            .expect("legacy snapshot intent should remain replayable");
        assert_eq!(9, intent.generation);
        assert_eq!(vec!["p1".to_string()], intent.port_ids);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn normal_snapshot_intent_omits_recovery_fields_and_replays() {
        let root = temp_state_path();
        let wal = NeutronWal::new(&root);
        wal.append_snapshot_intent(
            10,
            Some("hash-10".to_string()),
            vec!["p1".to_string()],
            vec!["acl".to_string()],
            vec![managed("p1", "tap-p1")],
            None,
        )
        .unwrap();

        let raw = fs::read_to_string(root.join(WAL_FILE)).unwrap();
        let written: serde_json::Value = serde_json::from_str(raw.trim()).unwrap();
        assert!(written.get("recovery_cause").is_none());
        assert!(written.get("intent_hash").is_none());

        let replay = wal.replay();
        assert_eq!("intent_without_commit", replay.status);
        assert_eq!(0, replay.failures);
        assert_eq!(
            Some(10),
            replay
                .pending_intent
                .as_ref()
                .map(|intent| intent.generation)
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn replay_rejects_hashed_inventory_intent_with_tampered_recovery_cause() {
        let valid = hashed_snapshot_intent(
            70,
            Some("hash-70".to_string()),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            "inventory_unavailable",
        );
        let valid_root = temp_state_path();
        write_wal_value(&valid_root, &valid);
        let valid_replay = NeutronWal::new(&valid_root).replay();
        assert_eq!("intent_without_commit", valid_replay.status);
        assert_eq!(0, valid_replay.failures);
        let _ = fs::remove_dir_all(valid_root);

        let mut tampered = valid;
        tampered["recovery_cause"] = serde_json::Value::String("inventory_timeout".to_string());
        let root = temp_state_path();
        write_wal_value(&root, &tampered);

        let replay = NeutronWal::new(&root).replay();

        assert_eq!("replayed_with_errors", replay.status);
        assert_eq!(1, replay.failures);
        assert!(replay.pending_intent.is_none());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn replay_rejects_hashed_inventory_intent_when_authority_field_changes() {
        let valid = hashed_snapshot_intent(
            71,
            Some("hash-71".to_string()),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            "inventory_unavailable",
        );
        let valid_root = temp_state_path();
        write_wal_value(&valid_root, &valid);
        let valid_replay = NeutronWal::new(&valid_root).replay();
        assert_eq!("intent_without_commit", valid_replay.status);
        assert_eq!(0, valid_replay.failures);
        let _ = fs::remove_dir_all(valid_root);

        let mut changed_generation = valid.clone();
        changed_generation["generation"] = serde_json::json!(72);
        let mut changed_desired_hash = valid.clone();
        changed_desired_hash["desired_hash"] = serde_json::json!("hash-tampered");
        let mut changed_port_ids = valid.clone();
        changed_port_ids["port_ids"] = serde_json::json!(["p1"]);
        let mut changed_domains = valid.clone();
        changed_domains["affected_domains"] = serde_json::json!(["acl", "qos"]);
        let mut changed_ports = valid;
        changed_ports["affected_ports"] = serde_json::json!([managed("p1", "tap-p1")]);

        for (case, tampered) in [
            ("generation", changed_generation),
            ("desired_hash", changed_desired_hash),
            ("port_ids", changed_port_ids),
            ("affected_domains", changed_domains),
            ("affected_ports", changed_ports),
        ] {
            let root = temp_state_path();
            write_wal_value(&root, &tampered);
            let replay = NeutronWal::new(&root).replay();

            assert_eq!("replayed_with_errors", replay.status, "{}", case);
            assert_eq!(1, replay.failures, "{}", case);
            assert!(replay.pending_intent.is_none(), "{}", case);
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn replay_rejects_recovery_cause_injected_into_legacy_snapshot_intent() {
        let root = temp_state_path();
        let mut legacy = serde_json::json!({
            "type": "snapshot_intent",
            "generation": 73,
            "desired_hash": "hash-73",
            "port_ids": [],
            "affected_domains": ["acl"],
            "affected_ports": [],
        });
        write_wal_value(&root, &legacy);
        let legacy_replay = NeutronWal::new(&root).replay();
        assert_eq!("intent_without_commit", legacy_replay.status);
        assert_eq!(0, legacy_replay.failures);

        legacy["recovery_cause"] = serde_json::Value::String("inventory_unavailable".to_string());
        assert!(legacy.get("intent_hash").is_none());
        write_wal_value(&root, &legacy);

        let replay = NeutronWal::new(&root).replay();

        assert_eq!("replayed_with_errors", replay.status);
        assert_eq!(1, replay.failures);
        assert!(replay.pending_intent.is_none());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn replay_rejects_self_consistent_unknown_snapshot_intent_cause() {
        let root = temp_state_path();
        let unknown = hashed_snapshot_intent(
            74,
            Some("hash-74".to_string()),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            "operator_override",
        );
        let hash = unknown
            .get("intent_hash")
            .and_then(serde_json::Value::as_str)
            .expect("unknown cause fixture should still carry a computed hash");
        assert!(!hash.is_empty());
        write_wal_value(&root, &unknown);

        let replay = NeutronWal::new(&root).replay();

        assert_eq!("replayed_with_errors", replay.status);
        assert_eq!(1, replay.failures);
        assert!(replay.pending_intent.is_none());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn replay_rejects_intent_hash_without_recovery_cause() {
        let root = temp_state_path();
        let hash_only = serde_json::json!({
            "type": "snapshot_intent",
            "generation": 75,
            "desired_hash": "hash-75",
            "port_ids": [],
            "affected_domains": ["acl"],
            "affected_ports": [],
            "intent_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        });
        assert!(hash_only.get("recovery_cause").is_none());
        write_wal_value(&root, &hash_only);

        let replay = NeutronWal::new(&root).replay();

        assert_eq!("replayed_with_errors", replay.status);
        assert_eq!(1, replay.failures);
        assert!(replay.pending_intent.is_none());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn replay_rejects_hashed_inventory_intent_with_nonempty_recovery_scope() {
        let nonempty_port_ids = hashed_snapshot_intent(
            76,
            Some("hash-76".to_string()),
            vec!["p1".to_string()],
            Vec::new(),
            Vec::new(),
            "inventory_unavailable",
        );
        let nonempty_affected_ports = hashed_snapshot_intent(
            77,
            Some("hash-77".to_string()),
            Vec::new(),
            Vec::new(),
            vec![managed("p1", "tap-p1")],
            "inventory_unavailable",
        );

        for (case, invalid) in [
            ("port_ids", nonempty_port_ids),
            ("affected_ports", nonempty_affected_ports),
        ] {
            let root = temp_state_path();
            write_wal_value(&root, &invalid);
            let replay = NeutronWal::new(&root).replay();

            assert_eq!("replayed_with_errors", replay.status, "{}", case);
            assert_eq!(1, replay.failures, "{}", case);
            assert!(replay.pending_intent.is_none(), "{}", case);
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn neutron_wal_protected_inventory_intent_survives_invalid_status_hash_commit() {
        let root = temp_state_path();
        let wal = NeutronWal::new(&root);
        let baseline = neutron_wal_baseline_state(80);
        wal.append_snapshot_commit(baseline.clone()).unwrap();
        append_protected_inventory_intent(&wal, 81);

        let mut invalid = protected_inventory_resolver_state(&baseline, 81);
        invalid.status_hash = Some("0".repeat(64));
        let invalid_commit =
            serde_json::to_value(NeutronWalEntry::SnapshotCommit { state: invalid }).unwrap();
        append_wal_value(&root, &invalid_commit);

        let replay = wal.replay();

        assert_protected_inventory_intent_survives(&replay, &baseline, 81, "invalid_status_hash");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn neutron_wal_protected_inventory_intent_rejects_hashless_cause_free_commit() {
        let root = temp_state_path();
        let wal = NeutronWal::new(&root);
        let baseline = neutron_wal_baseline_state(82);
        wal.append_snapshot_commit(baseline.clone()).unwrap();
        append_protected_inventory_intent(&wal, 83);

        let mut cause_free = protected_inventory_resolver_state(&baseline, 83);
        cause_free.recovery_cause = None;
        let mut legacy_commit =
            serde_json::to_value(NeutronWalEntry::SnapshotCommit { state: cause_free }).unwrap();
        legacy_commit["state"]
            .as_object_mut()
            .expect("legacy commit state should be an object")
            .remove("status_hash");
        assert!(legacy_commit["state"].get("recovery_cause").is_none());
        assert!(legacy_commit["state"].get("status_hash").is_none());
        append_wal_value(&root, &legacy_commit);

        let replay = wal.replay();

        assert_protected_inventory_intent_survives(&replay, &baseline, 83, "hashless_cause_free");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn neutron_wal_protected_inventory_intent_rejects_status_hashed_cause_free_commit() {
        let root = temp_state_path();
        let wal = NeutronWal::new(&root);
        let baseline = neutron_wal_baseline_state(84);
        wal.append_snapshot_commit(baseline.clone()).unwrap();
        append_protected_inventory_intent(&wal, 85);

        let mut cause_free = protected_inventory_resolver_state(&baseline, 85);
        cause_free.recovery_cause = None;
        wal.append_snapshot_commit(cause_free).unwrap();

        let replay = wal.replay();

        assert_protected_inventory_intent_survives(
            &replay,
            &baseline,
            85,
            "status_hashed_cause_free",
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn neutron_wal_protected_inventory_intent_rejects_closure_invariant_mutations() {
        let baseline = neutron_wal_baseline_state(86);
        let expected = protected_inventory_resolver_state(&baseline, 87);

        let mut recovery_cause = expected.clone();
        recovery_cause.recovery_cause = Some("operator_override".to_string());
        let mut accepted_generation = expected.clone();
        accepted_generation.accepted_generation = 88;
        let mut pending_generation = expected.clone();
        pending_generation.pending_generation = Some(88);
        let mut desired_hash = expected.clone();
        desired_hash.desired_hash = Some("hash-tampered".to_string());
        let mut authority_state = expected.clone();
        authority_state.authority_state = "ready".to_string();
        let mut applied_generation = expected.clone();
        applied_generation.applied_generation = baseline.applied_generation + 1;
        let mut applied_desired_hash = expected.clone();
        applied_desired_hash.applied_desired_hash = Some("hash-tampered-applied".to_string());
        let mut ports = expected.clone();
        ports
            .ports
            .get_mut("p1")
            .expect("baseline port should exist")
            .ifindex = Some(99);
        let mut port_statuses = expected;
        port_statuses
            .port_statuses
            .get_mut("p1")
            .expect("baseline port status should exist")
            .reason = Some("tampered_status".to_string());

        for (case, changed) in [
            ("recovery_cause", recovery_cause),
            ("accepted_generation", accepted_generation),
            ("pending_generation", pending_generation),
            ("desired_hash", desired_hash),
            ("authority_state", authority_state),
            ("applied_generation", applied_generation),
            ("applied_desired_hash", applied_desired_hash),
            ("ports", ports),
            ("port_statuses", port_statuses),
        ] {
            let root = temp_state_path();
            let wal = NeutronWal::new(&root);
            wal.append_snapshot_commit(baseline.clone()).unwrap();
            append_protected_inventory_intent(&wal, 87);
            wal.append_snapshot_commit(changed).unwrap();

            let raw = fs::read_to_string(root.join(WAL_FILE)).unwrap();
            let resolver: serde_json::Value = serde_json::from_str(
                raw.lines()
                    .last()
                    .expect("mutated resolver commit should be present"),
            )
            .unwrap();
            let resolver_state: NeutronWalState =
                serde_json::from_value(resolver["state"].clone()).unwrap();
            assert!(resolver_state.status_hash_valid().unwrap(), "{}", case);

            let replay = wal.replay();

            assert_protected_inventory_intent_survives(&replay, &baseline, 87, case);
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn neutron_wal_matching_protected_inventory_commit_resolves_intent() {
        let root = temp_state_path();
        let wal = NeutronWal::new(&root);
        let baseline = neutron_wal_baseline_state(88);
        wal.append_snapshot_commit(baseline.clone()).unwrap();
        append_protected_inventory_intent(&wal, 89);
        wal.append_snapshot_commit(protected_inventory_resolver_state(&baseline, 89))
            .unwrap();

        let replay = wal.replay();

        assert_eq!(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE, replay.status);
        assert_eq!(0, replay.failures);
        assert!(replay.pending_intent.is_none());
        assert_eq!(89, replay.state.accepted_generation);
        assert_eq!(baseline.applied_generation, replay.state.applied_generation);
        assert_eq!(
            baseline.applied_desired_hash,
            replay.state.applied_desired_hash
        );
        assert_eq!(baseline.ports, replay.state.ports);
        assert_eq!(baseline.port_statuses, replay.state.port_statuses);
        assert_eq!(Some(89), replay.state.pending_generation);
        assert_eq!(Some("hash-89"), replay.state.desired_hash.as_deref());
        assert_eq!(
            Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE),
            replay.state.recovery_cause.as_deref()
        );
        assert!(replay.state.status_hash.is_some());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn neutron_wal_standalone_cause_free_commits_remain_replayable() {
        let legacy_root = temp_state_path();
        write_wal_value(&legacy_root, &hashless_snapshot_commit(90));
        let legacy_replay = NeutronWal::new(&legacy_root).replay();
        assert_eq!("replayed", legacy_replay.status);
        assert_eq!(0, legacy_replay.failures);
        assert_eq!(90, legacy_replay.state.applied_generation);

        let hashed_root = temp_state_path();
        let hashed_wal = NeutronWal::new(&hashed_root);
        let hashed = neutron_wal_baseline_state(91);
        hashed_wal.append_snapshot_commit(hashed.clone()).unwrap();
        let hashed_replay = hashed_wal.replay();
        assert_eq!("replayed", hashed_replay.status);
        assert_eq!(0, hashed_replay.failures);
        assert_eq!(
            hashed.applied_generation,
            hashed_replay.state.applied_generation
        );
        assert_eq!(hashed.ports, hashed_replay.state.ports);
        assert_eq!(hashed.port_statuses, hashed_replay.state.port_statuses);

        let _ = fs::remove_dir_all(legacy_root);
        let _ = fs::remove_dir_all(hashed_root);
    }

    #[test]
    fn neutron_wal_delete_intent_resolves_with_hashless_cause_free_delete_commit() {
        let root = temp_state_path();
        let wal = NeutronWal::new(&root);
        let baseline = neutron_wal_baseline_state(93);
        wal.append_snapshot_commit(baseline.clone()).unwrap();
        wal.append_delete_intent(
            "p1".to_string(),
            baseline.accepted_generation,
            vec!["attach".to_string(), "acl".to_string()],
            managed("p1", "tap-p1"),
        )
        .unwrap();

        let mut committed = baseline.clone();
        committed.ports.remove("p1");
        committed.port_statuses.remove("p1");
        committed.status_hash = None;
        let legacy_commit = hashless_delete_commit_for_state(committed.clone());
        assert!(legacy_commit["state"].get("recovery_cause").is_none());
        assert!(legacy_commit["state"].get("status_hash").is_none());
        append_wal_value(&root, &legacy_commit);

        let replay = wal.replay();

        assert_eq!("replayed", replay.status);
        assert_eq!(0, replay.failures);
        assert!(replay.pending_intent.is_none());
        assert_eq!(
            committed.accepted_generation,
            replay.state.accepted_generation
        );
        assert_eq!(
            committed.applied_generation,
            replay.state.applied_generation
        );
        assert_eq!(
            committed.applied_desired_hash,
            replay.state.applied_desired_hash
        );
        assert!(replay.state.ports.is_empty());
        assert!(replay.state.port_statuses.is_empty());
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
        assert_eq!(
            vec!["attach".to_string(), "acl".to_string()],
            intent.affected_domains
        );
        assert_eq!(vec![managed("p1", "tap-p1")], intent.affected_ports);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn replay_blocked_snapshot_checkpoint_preserves_delete_intent() {
        let root = temp_state_path();
        let wal = NeutronWal::new(&root);
        let baseline = neutron_wal_baseline_state(12);
        wal.append_snapshot_commit(baseline.clone()).unwrap();
        wal.append_delete_intent(
            "p1".to_string(),
            12,
            vec!["attach".to_string(), "acl".to_string()],
            managed("p1", "tap-p1"),
        )
        .unwrap();

        let mut blocked = baseline.clone();
        blocked.pending_generation = Some(12);
        blocked.desired_hash = None;
        blocked.authority_state = "blocked_recovery_required".to_string();
        blocked.port_statuses.get_mut("p1").unwrap().status = "blocked".to_string();
        blocked.port_statuses.get_mut("p1").unwrap().reason =
            Some("delete_detach_failed".to_string());
        wal.append_snapshot_commit(blocked).unwrap();

        let replay = wal.replay();

        assert_eq!(0, replay.failures);
        assert_eq!(Some(12), replay.state.pending_generation);
        assert_eq!(
            Some("blocked"),
            replay
                .state
                .port_statuses
                .get("p1")
                .map(|status| status.status.as_str())
        );
        let intent = replay
            .pending_intent
            .expect("blocked status checkpoint must not resolve delete intent");
        assert_eq!("delete", intent.kind);
        assert_eq!(12, intent.generation);
        assert_eq!(vec!["p1".to_string()], intent.port_ids);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn replay_mismatched_delete_commit_preserves_delete_intent() {
        let root = temp_state_path();
        let wal = NeutronWal::new(&root);
        let baseline = neutron_wal_baseline_state(13);
        wal.append_snapshot_commit(baseline.clone()).unwrap();
        wal.append_delete_intent(
            "p1".to_string(),
            13,
            vec!["attach".to_string(), "acl".to_string()],
            managed("p1", "tap-p1"),
        )
        .unwrap();

        let mut mismatched = baseline.clone();
        mismatched.accepted_generation = 14;
        mismatched.ports.remove("p1");
        mismatched.port_statuses.remove("p1");
        mismatched.pending_generation = None;
        mismatched.desired_hash = mismatched.applied_desired_hash.clone();
        wal.append_delete_commit(mismatched).unwrap();

        let replay = wal.replay();

        assert_eq!(1, replay.failures);
        assert!(replay.state.ports.contains_key("p1"));
        assert_eq!(
            Some("delete"),
            replay
                .pending_intent
                .as_ref()
                .map(|intent| intent.kind.as_str())
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn replay_invalid_commit_hash_preserves_delete_intent() {
        let root = temp_state_path();
        let wal = NeutronWal::new(&root);
        let baseline = neutron_wal_baseline_state(14);
        wal.append_snapshot_commit(baseline.clone()).unwrap();
        wal.append_delete_intent(
            "p1".to_string(),
            14,
            vec!["attach".to_string(), "acl".to_string()],
            managed("p1", "tap-p1"),
        )
        .unwrap();

        let mut invalid = baseline.clone();
        invalid.status_hash = Some("0".repeat(64));
        let invalid_commit =
            serde_json::to_value(NeutronWalEntry::SnapshotCommit { state: invalid }).unwrap();
        append_wal_value(&root, &invalid_commit);

        let replay = wal.replay();

        assert_eq!(1, replay.failures);
        assert!(replay.state.ports.contains_key("p1"));
        assert_eq!(
            Some("delete"),
            replay
                .pending_intent
                .as_ref()
                .map(|intent| intent.kind.as_str())
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn replay_matching_delete_commit_closes_exact_intent() {
        let root = temp_state_path();
        let wal = NeutronWal::new(&root);
        let baseline = neutron_wal_baseline_state(15);
        wal.append_snapshot_commit(baseline.clone()).unwrap();
        wal.append_delete_intent(
            "p1".to_string(),
            15,
            vec!["attach".to_string(), "acl".to_string()],
            managed("p1", "tap-p1"),
        )
        .unwrap();

        let mut committed = baseline;
        committed.ports.remove("p1");
        committed.port_statuses.remove("p1");
        committed.pending_generation = None;
        committed.desired_hash = committed.applied_desired_hash.clone();
        wal.append_delete_commit(committed).unwrap();

        let replay = wal.replay();

        assert_eq!(0, replay.failures);
        assert!(replay.pending_intent.is_none());
        assert!(!replay.state.ports.contains_key("p1"));
        assert!(!replay.state.port_statuses.contains_key("p1"));
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
            None,
        )
        .unwrap();

        let replay = wal.replay();

        assert_eq!("intent_without_commit", replay.status);
        assert_eq!(20, replay.state.applied_generation);
        assert_eq!(Some(21), replay.state.pending_generation);
        assert_eq!(Some("hash-21".to_string()), replay.state.desired_hash);
        assert!(replay.state.ports.is_empty());
        let intent = replay
            .pending_intent
            .expect("snapshot intent should replay");
        assert_eq!("snapshot", intent.kind);
        assert_eq!(
            vec!["attach".to_string(), "acl".to_string()],
            intent.affected_domains
        );
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
            None,
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
        let intent = replay
            .pending_intent
            .expect("snapshot intent should replay");
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
            None,
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
        assert_eq!(
            Some("hash-50".to_string()),
            replay.state.applied_desired_hash
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn neutron_wal_replay_continues_after_non_utf8_record() {
        let root = temp_state_path();
        fs::create_dir_all(&root).unwrap();
        let mut raw = encoded_snapshot_commit(52);
        raw.push(b'\n');
        raw.extend_from_slice(&[0xff, b'\n']);
        raw.extend_from_slice(&encoded_snapshot_commit(53));
        raw.push(b'\n');
        fs::write(root.join(WAL_FILE), raw).unwrap();

        let replay = NeutronWal::new(&root).replay();

        assert_eq!("replayed_with_errors", replay.status);
        assert_eq!(1, replay.failures);
        assert_eq!(2, replay.replayed);
        assert_eq!(53, replay.state.applied_generation);
        assert_eq!(Some("hash-53"), replay.state.applied_desired_hash.as_deref());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn neutron_wal_replay_preserves_last_commit_before_truncated_record() {
        let root = temp_state_path();
        fs::create_dir_all(&root).unwrap();
        let mut raw = encoded_snapshot_commit(54);
        raw.push(b'\n');
        raw.extend_from_slice(br#"{"type":"snapshot_commit","state":{"accepted_generation":55"#);
        fs::write(root.join(WAL_FILE), raw).unwrap();

        let replay = NeutronWal::new(&root).replay();

        assert_eq!("replayed_with_errors", replay.status);
        assert_eq!(1, replay.failures);
        assert_eq!(1, replay.replayed);
        assert_eq!(54, replay.state.applied_generation);
        assert_eq!(Some("hash-54"), replay.state.applied_desired_hash.as_deref());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn replay_rejects_tampered_inventory_recovery_cause_without_new_status_hash() {
        let root = temp_state_path();
        let wal = NeutronWal::new(&root);
        wal.append_snapshot_commit(NeutronWalState {
            accepted_generation: 60,
            applied_generation: 60,
            authority_state: "ready".to_string(),
            ..NeutronWalState::default()
        })
        .unwrap();
        let path = root.join(WAL_FILE);
        let raw = fs::read_to_string(&path).unwrap();
        let tampered = raw.replacen(
            r#""authority_state":"ready""#,
            r#""authority_state":"ready","recovery_cause":"inventory_unavailable""#,
            1,
        );
        assert_ne!(raw, tampered);
        fs::write(&path, tampered).unwrap();

        let replay = wal.replay();

        assert_eq!("replayed_with_errors", replay.status);
        assert_eq!(1, replay.failures);
        assert_eq!(0, replay.state.applied_generation);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn hashless_legacy_commit_without_recovery_cause_replays() {
        let root = temp_state_path();
        let wal = NeutronWal::new(&root);
        fs::create_dir_all(&root).unwrap();
        let path = root.join(WAL_FILE);
        let legacy = hashless_snapshot_commit(62);
        let legacy_raw = format!("{}\n", serde_json::to_string(&legacy).unwrap());
        assert!(!legacy_raw.contains(r#""recovery_cause""#));
        assert!(!legacy_raw.contains(r#""status_hash""#));
        fs::write(&path, legacy_raw).unwrap();

        let legacy_replay = wal.replay();
        assert_eq!("replayed", legacy_replay.status);
        assert_eq!(0, legacy_replay.failures);
        assert_eq!(62, legacy_replay.state.applied_generation);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn hashless_commit_with_injected_inventory_recovery_cause_is_rejected() {
        let root = temp_state_path();
        let wal = NeutronWal::new(&root);
        fs::create_dir_all(&root).unwrap();
        let path = root.join(WAL_FILE);
        let mut injected = hashless_snapshot_commit(63);
        injected["state"]["recovery_cause"] =
            serde_json::Value::String("inventory_unavailable".to_string());
        let injected_raw = format!("{}\n", serde_json::to_string(&injected).unwrap());
        assert!(injected_raw.contains(r#""recovery_cause":"inventory_unavailable""#));
        assert!(!injected_raw.contains(r#""status_hash""#));
        fs::write(&path, injected_raw).unwrap();

        let injected_replay = wal.replay();
        assert_eq!("replayed_with_errors", injected_replay.status);
        assert_eq!(1, injected_replay.failures);
        assert_eq!(0, injected_replay.state.applied_generation);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn legacy_snapshot_commit_without_recovery_cause_omits_field_and_replays() {
        #[derive(serde::Serialize)]
        struct LegacyStatusHashPayload<'a> {
            accepted_generation: u64,
            applied_generation: u64,
            pending_generation: Option<u64>,
            desired_hash: &'a Option<String>,
            applied_desired_hash: &'a Option<String>,
            authority_state: &'a str,
            ports: &'a BTreeMap<String, ManagedNeutronPort>,
            port_statuses: &'a BTreeMap<String, NeutronPortStatus>,
        }

        let root = temp_state_path();
        let wal = NeutronWal::new(&root);
        let mut ports = BTreeMap::new();
        ports.insert("p1".to_string(), managed("p1", "tap-p1"));
        let mut port_statuses = BTreeMap::new();
        port_statuses.insert("p1".to_string(), port_status("p1", "tap-p1", 61));
        let state = NeutronWalState {
            accepted_generation: 61,
            applied_generation: 61,
            desired_hash: Some("hash-61".to_string()),
            applied_desired_hash: Some("hash-61".to_string()),
            authority_state: "ready".to_string(),
            ports,
            port_statuses,
            ..NeutronWalState::default()
        };
        let legacy_payload = LegacyStatusHashPayload {
            accepted_generation: state.accepted_generation,
            applied_generation: state.applied_generation,
            pending_generation: state.pending_generation,
            desired_hash: &state.desired_hash,
            applied_desired_hash: &state.applied_desired_hash,
            authority_state: &state.authority_state,
            ports: &state.ports,
            port_statuses: &state.port_statuses,
        };
        let bytes = serde_json::to_vec(&legacy_payload).unwrap();
        let digest = <sha2::Sha256 as sha2::Digest>::digest(bytes);
        let legacy_hash = digest
            .iter()
            .map(|byte| format!("{:02x}", byte))
            .collect::<Vec<_>>()
            .join("");
        wal.append_snapshot_commit(state).unwrap();

        let raw = fs::read_to_string(root.join(WAL_FILE)).unwrap();
        assert!(!raw.contains(r#""recovery_cause""#));
        let entry: serde_json::Value = serde_json::from_str(raw.trim()).unwrap();
        assert_eq!(
            entry["state"]["status_hash"].as_str(),
            Some(legacy_hash.as_str())
        );
        let replay = wal.replay();
        assert_eq!("replayed", replay.status);
        assert_eq!(0, replay.failures);
        assert_eq!(61, replay.state.applied_generation);
        assert_eq!(
            Some("hash-61"),
            replay.state.applied_desired_hash.as_deref()
        );
        assert_eq!(1, replay.state.ports.len());
        assert_eq!(1, replay.state.port_statuses.len());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn neutron_wal_compaction_bounds_repeated_commits_and_replays_latest_state() {
        let root = temp_state_path();
        let wal = lifecycle_wal(&root, 1, 16 * 1024);

        for generation in 1..=40 {
            append_ready_commit(&wal, generation);
        }

        let raw = wal_bytes(&root);
        let replay = wal.replay();
        assert!(raw.len() <= 16 * 1024);
        assert_eq!(40, replay.state.applied_generation);
        assert_eq!(
            Some("hash-40".to_string()),
            replay.state.applied_desired_hash
        );
        assert_eq!(0, replay.failures);
        assert!(replay.pending_intent.is_none());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn neutron_wal_compaction_preserves_snapshot_pending_baseline() {
        let root = temp_state_path();
        let wal = lifecycle_wal(&root, 1, 16 * 1024);
        append_ready_commit(&wal, 10);
        wal.append_snapshot_intent(
            11,
            Some("hash-11".to_string()),
            vec!["p2".to_string()],
            vec!["attach".to_string(), "acl".to_string()],
            vec![managed("p2", "tap-p2")],
            None,
        )
        .unwrap();
        wal.compact_now_for_test().unwrap();

        let replay = wal.replay();
        assert_eq!(10, replay.state.applied_generation);
        assert_eq!(
            Some("hash-10".to_string()),
            replay.state.applied_desired_hash
        );
        assert_eq!(Some(11), replay.state.pending_generation);
        assert_eq!("wal_intent_without_commit", replay.state.authority_state);
        assert_eq!("snapshot", replay.pending_intent.unwrap().kind);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn neutron_wal_compaction_preserves_legacy_delete_intent_without_port() {
        let root = temp_state_path();
        let wal = lifecycle_wal(&root, 1, 16 * 1024);
        append_ready_commit(&wal, 20);
        append_wal_value(
            &root,
            &serde_json::json!({
                "type": "delete_intent",
                "port_id": "p1",
                "generation": 21,
                "affected_domains": ["attach", "acl"]
            }),
        );
        wal.compact_now_for_test().unwrap();

        let replay = wal.replay();
        let intent = replay.pending_intent.unwrap();
        assert_eq!("delete", intent.kind);
        assert_eq!(21, intent.generation);
        assert_eq!(vec!["p1".to_string()], intent.port_ids);
        assert!(intent.affected_ports.is_empty());
        assert_eq!(20, replay.state.applied_generation);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn neutron_wal_compaction_preserves_protected_inventory_intent_and_closure() {
        let root = temp_state_path();
        let wal = lifecycle_wal(&root, 1, 16 * 1024);
        let baseline = neutron_wal_baseline_state(30);
        wal.append_snapshot_commit(baseline.clone()).unwrap();
        append_protected_inventory_intent(&wal, 31);
        wal.compact_now_for_test().unwrap();

        let replay = wal.replay();
        assert_eq!(0, replay.failures);
        assert_eq!("intent_without_commit", replay.status);
        let intent = replay.pending_intent.clone().unwrap();
        assert_eq!(
            Some(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE),
            intent.recovery_cause.as_deref()
        );
        let blocked = protected_inventory_resolver_state(&baseline, 31);
        let resolved = wal
            .append_verified_protected_inventory_commit(&intent, blocked)
            .unwrap();
        assert_eq!(INVENTORY_UNAVAILABLE_RECOVERY_CAUSE, resolved.status);
        assert!(resolved.pending_intent.is_none());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn neutron_wal_compaction_refuses_uncertain_replay_and_preserves_prefix() {
        let root = temp_state_path();
        let wal = lifecycle_wal(&root, 1, 64 * 1024);
        append_ready_commit(&wal, 40);
        let path = root.join(WAL_FILE);
        let mut raw = wal_bytes(&root);
        raw.extend_from_slice(b"{not-json}\n");
        fs::write(&path, &raw).unwrap();

        append_ready_commit(&wal, 41);

        let after = wal_bytes(&root);
        assert!(after.starts_with(&raw));
        assert_eq!(1, wal.replay().failures);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn neutron_wal_hard_capacity_rejection_preserves_live_bytes() {
        let root = temp_state_path();
        let seed = NeutronWal::new(&root);
        append_ready_commit(&seed, 50);
        let before = wal_bytes(&root);
        let wal = lifecycle_wal(&root, 1, 1);

        let error = wal
            .append_snapshot_commit(neutron_wal_baseline_state(51))
            .unwrap_err();

        assert!(error.starts_with("neutron WAL hard capacity exceeded"));
        assert_eq!(before, wal_bytes(&root));
        assert_eq!(50, wal.replay().state.applied_generation);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn neutron_wal_ignores_and_replaces_stale_checkpoint_temp_file() {
        let root = temp_state_path();
        let wal = lifecycle_wal(&root, 1, 16 * 1024);
        append_ready_commit(&wal, 60);
        fs::write(
            wal.checkpoint_temp_path_for_test(),
            b"{\"type\":\"snapshot_commit\",\"state\":",
        )
        .unwrap();

        append_ready_commit(&wal, 61);

        assert_eq!(61, wal.replay().state.applied_generation);
        assert!(!wal.checkpoint_temp_path_for_test().exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn neutron_wal_pre_rename_compaction_failure_falls_back_below_hard_limit() {
        let root = temp_state_path();
        let wal = lifecycle_wal(&root, 1, 64 * 1024);
        append_ready_commit(&wal, 70);
        let before = wal_bytes(&root);
        fs::create_dir_all(wal.checkpoint_temp_path_for_test()).unwrap();

        append_ready_commit(&wal, 71);

        let after = wal_bytes(&root);
        assert!(after.starts_with(&before));
        assert_eq!(71, wal.replay().state.applied_generation);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn neutron_wal_oversized_legacy_history_compacts_and_accepts_new_commit() {
        let root = temp_state_path();
        let seed = NeutronWal::new(&root);
        for generation in 80..=100 {
            append_ready_commit(&seed, generation);
        }
        let legacy_len = wal_bytes(&root).len();
        let wal = lifecycle_wal(&root, 1, legacy_len as u64);

        append_ready_commit(&wal, 101);

        assert!(wal_bytes(&root).len() < legacy_len);
        assert_eq!(101, wal.replay().state.applied_generation);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn neutron_maintenance_wal_dangling_intent_replays_active_from_real_wal() {
        let root = temp_state_path();
        let wal = NeutronWal::new(&root);
        wal.append_maintenance_record(MaintenanceWalRecord::enter_intent_state(
            maintenance_state("op-real-wal"),
        ))
        .unwrap();

        let replay = wal.replay();
        assert_eq!(0, replay.failures);
        assert!(replay.maintenance.requires_bypass);
        assert_eq!(
            replay.maintenance.state.operation_id.as_deref(),
            Some("op-real-wal")
        );
        assert_eq!(
            replay.maintenance.state.phase,
            MaintenancePhase::MaintenanceBypass
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn neutron_maintenance_wal_duplicate_keeps_last_good_active_prefix() {
        let root = temp_state_path();
        let wal = NeutronWal::new(&root);
        let intent = MaintenanceWalRecord::enter_intent_state(maintenance_state("op-duplicate"));
        wal.append_maintenance_record(intent.clone()).unwrap();
        wal.append_maintenance_record(intent).unwrap();

        let replay = wal.replay();
        assert_eq!(1, replay.failures);
        assert_eq!(1, replay.maintenance_failures);
        assert!(replay.maintenance.requires_bypass);
        assert_eq!(
            replay.maintenance.state.operation_id.as_deref(),
            Some("op-duplicate")
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn neutron_maintenance_wal_unknown_malformed_and_oversized_records_fail_conservatively() {
        for (case, invalid) in [
            (
                "unknown",
                b"{\"type\":\"maintenance\",\"record\":{\"kind\":\"unknown\"}}\n".to_vec(),
            ),
            ("malformed", b"{\"type\":\"maintenance\",\"record\":\n".to_vec()),
            (
                "oversized",
                format!(
                    "{{\"type\":\"maintenance\",\"record\":{{\"kind\":\"enter_intent\",\"schema_version\":1,\"state\":{{\"schema_version\":1,\"operation_id\":\"op-large\",\"phase\":\"bypass_preparing\",\"active_domains\":[\"acl\"],\"expected_generation\":9,\"expected_desired_hash\":\"sha256:g9\",\"applied_generation\":9,\"applied_desired_hash\":\"sha256:g9\",\"bypass_started_at_ms\":100,\"last_progress_at_ms\":100,\"last_error\":\"{}\"}}}}}}\n",
                    "x".repeat(MAINTENANCE_WAL_RECORD_MAX_BYTES + 1)
                )
                .into_bytes(),
            ),
        ] {
            let root = temp_state_path().join(case);
            let wal = NeutronWal::new(&root);
            wal.append_maintenance_record(MaintenanceWalRecord::enter_intent_state(
                maintenance_state(&format!("op-prefix-{}", case)),
            ))
            .unwrap();
            let mut bytes = wal_bytes(&root);
            bytes.extend_from_slice(&invalid);
            fs::write(root.join(WAL_FILE), bytes).unwrap();

            let replay = wal.replay();
            let expected_operation_id = format!("op-prefix-{}", case);
            assert_eq!(1, replay.failures, "case={case}");
            assert_eq!(1, replay.maintenance_failures, "case={case}");
            assert!(replay.maintenance.requires_bypass, "case={case}");
            assert_eq!(
                replay.maintenance.state.operation_id.as_deref(),
                Some(expected_operation_id.as_str()),
                "case={case}"
            );
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn neutron_maintenance_wal_compaction_retains_only_canonical_state_and_pending_transition() {
        let root = temp_state_path();
        let wal = NeutronWal::new(&root);
        let preparing = maintenance_state("op-compact");
        let mut active = preparing.clone();
        active.phase = MaintenancePhase::MaintenanceBypass;
        wal.append_maintenance_record(MaintenanceWalRecord::enter_intent_state(preparing))
            .unwrap();
        wal.append_maintenance_record(MaintenanceWalRecord::enter_commit_state(active.clone()))
            .unwrap();
        for progress in 1..=128 {
            let mut next = active.clone();
            next.last_progress_at_ms += progress;
            wal.append_maintenance_record(MaintenanceWalRecord::progress_commit_state(next))
                .unwrap();
        }

        wal.compact_now_for_test().unwrap();

        let scan = wal.scan();
        assert!(scan.maintenance_failures == 0);
        assert!(
            scan.maintenance_records.len() <= 2,
            "checkpoint must retain one canonical state plus at most one pending transition"
        );
        let replay = wal.replay();
        assert!(replay.maintenance.requires_bypass);
        assert_eq!(
            replay.maintenance.state.operation_id.as_deref(),
            Some("op-compact")
        );
        let _ = fs::remove_dir_all(root);
    }
}
