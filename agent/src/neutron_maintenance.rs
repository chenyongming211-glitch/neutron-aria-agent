use aria_api::{
    MaintenanceAbortRequest, MaintenanceEnterRequest, MaintenanceExitRequest, MaintenancePhase,
    MaintenanceState, MAINTENANCE_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

use crate::control_plane::ControlPlane;
use crate::neutron_wal::NeutronWal;

pub(crate) const ADMIN_SOCKET_PATH: &str = "/run/aria/aria-admin.sock";
pub(crate) const MAINTENANCE_WAL_RECORD_MAX_BYTES: usize = 64 * 1024;
const MAX_OPERATION_ID_BYTES: usize = 128;
const MAX_REASON_BYTES: usize = 256;
const MAX_HASH_BYTES: usize = 256;
const MAX_ERROR_BYTES: usize = 512;
const MAX_DOMAINS: usize = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MaintenanceError {
    pub(crate) http_status: u16,
    pub(crate) code: &'static str,
    pub(crate) details: String,
}

impl MaintenanceError {
    fn conflict(code: &'static str, details: impl Into<String>) -> Self {
        Self {
            http_status: 409,
            code,
            details: details.into(),
        }
    }

    fn invalid(code: &'static str, details: impl Into<String>) -> Self {
        Self {
            http_status: 400,
            code,
            details: details.into(),
        }
    }

    fn internal(code: &'static str, details: impl Into<String>) -> Self {
        Self {
            http_status: 500,
            code,
            details: details.into(),
        }
    }
}

fn bounded_text(
    value: &str,
    field: &'static str,
    maximum: usize,
) -> Result<(), MaintenanceError> {
    if value.is_empty() || value.len() > maximum {
        return Err(MaintenanceError::invalid(
            "maintenance_invalid_request",
            format!("{} must contain 1..={} bytes", field, maximum),
        ));
    }
    Ok(())
}

fn bounded_optional_text(
    value: Option<&str>,
    field: &'static str,
    maximum: usize,
) -> Result<(), MaintenanceError> {
    if let Some(value) = value {
        bounded_text(value, field, maximum)?;
    }
    Ok(())
}

fn bounded_error(value: impl AsRef<str>) -> String {
    let value = value.as_ref();
    if value.len() <= MAX_ERROR_BYTES {
        return value.to_string();
    }
    let mut end = MAX_ERROR_BYTES;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}

fn validate_state(state: &MaintenanceState) -> Result<(), String> {
    if state.schema_version != MAINTENANCE_SCHEMA_VERSION {
        return Err(format!(
            "unsupported maintenance schema version {}",
            state.schema_version
        ));
    }
    if state.active_domains.len() > MAX_DOMAINS {
        return Err("maintenance state has too many active domains".to_string());
    }
    if let Some(operation_id) = state.operation_id.as_deref() {
        bounded_text(operation_id, "operation_id", MAX_OPERATION_ID_BYTES)
            .map_err(|error| error.details)?;
    }
    bounded_optional_text(
        state.expected_desired_hash.as_deref(),
        "expected_desired_hash",
        MAX_HASH_BYTES,
    )
    .map_err(|error| error.details)?;
    bounded_optional_text(
        state.applied_desired_hash.as_deref(),
        "applied_desired_hash",
        MAX_HASH_BYTES,
    )
    .map_err(|error| error.details)?;
    bounded_optional_text(state.last_error.as_deref(), "last_error", MAX_ERROR_BYTES)
        .map_err(|error| error.details)?;
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MaintenanceConvergence {
    pub(crate) applied_generation: u64,
    pub(crate) applied_desired_hash: Option<String>,
    pub(crate) pending_generation: Option<u64>,
    pub(crate) managed_port_count: usize,
    pub(crate) ready_enforce_port_count: usize,
}

impl MaintenanceConvergence {
    pub(crate) fn is_complete(&self) -> bool {
        self.pending_generation.is_none()
            && self.managed_port_count == self.ready_enforce_port_count
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MaintenanceDisposition {
    Mutate,
    Idempotent,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MaintenancePlan {
    pub(crate) disposition: MaintenanceDisposition,
    pub(crate) next_state: Option<MaintenanceState>,
}

#[derive(Clone, Debug)]
pub(crate) struct MaintenanceStateMachine {
    state: MaintenanceState,
}

impl Default for MaintenanceStateMachine {
    fn default() -> Self {
        Self {
            state: MaintenanceState::inactive(),
        }
    }
}

impl MaintenanceStateMachine {
    pub(crate) fn with_state(state: MaintenanceState) -> Self {
        Self { state }
    }

    pub(crate) fn state(&self) -> &MaintenanceState {
        &self.state
    }

    pub(crate) fn plan_enter(
        &self,
        request: &MaintenanceEnterRequest,
        convergence: &MaintenanceConvergence,
        now_ms: u64,
    ) -> Result<MaintenancePlan, MaintenanceError> {
        bounded_text(&request.operation_id, "operation_id", MAX_OPERATION_ID_BYTES)?;
        bounded_text(&request.reason, "reason", MAX_REASON_BYTES)?;
        bounded_optional_text(
            request.expected_desired_hash.as_deref(),
            "expected_desired_hash",
            MAX_HASH_BYTES,
        )?;
        if request.domains.len() != 1 || request.domains[0] != "acl" {
            return Err(MaintenanceError::invalid(
                "maintenance_invalid_domains",
                "v0.9 maintenance domains must be exactly [acl]",
            ));
        }

        if self.state.is_active() {
            let exact = self.state.operation_id.as_deref() == Some(&request.operation_id)
                && self.state.active_domains == request.domains
                && self.state.expected_generation == request.expected_applied_generation
                && self.state.expected_desired_hash == request.expected_desired_hash;
            return if exact
                && self.state.phase == MaintenancePhase::MaintenanceBypass
                && self.state.last_error.is_none()
            {
                Ok(MaintenancePlan {
                    disposition: MaintenanceDisposition::Idempotent,
                    next_state: None,
                })
            } else {
                Err(MaintenanceError::conflict(
                    if exact {
                        "maintenance_recovery_blocked"
                    } else {
                        "maintenance_operation_conflict"
                    },
                    if exact {
                        "the matching maintenance operation is active but has unresolved recovery"
                    } else {
                        "another maintenance identity or compare-and-swap value is active"
                    },
                ))
            };
        }
        if self.state.phase == MaintenancePhase::Committed
            && self.state.operation_id.as_deref() == Some(&request.operation_id)
        {
            return Err(MaintenanceError::conflict(
                "maintenance_phase_conflict",
                "the terminal operation identity cannot be re-entered",
            ));
        }
        if convergence.pending_generation.is_some() {
            return Err(MaintenanceError::conflict(
                "maintenance_pending_generation",
                "cannot enter maintenance while a generation is pending",
            ));
        }
        if convergence.applied_generation != request.expected_applied_generation {
            return Err(MaintenanceError::conflict(
                "maintenance_generation_mismatch",
                "expected applied generation does not match durable runtime",
            ));
        }
        if convergence.applied_desired_hash != request.expected_desired_hash {
            return Err(MaintenanceError::conflict(
                "maintenance_desired_hash_mismatch",
                "expected desired hash does not match durable runtime",
            ));
        }
        Ok(MaintenancePlan {
            disposition: MaintenanceDisposition::Mutate,
            next_state: Some(MaintenanceState {
                schema_version: MAINTENANCE_SCHEMA_VERSION,
                operation_id: Some(request.operation_id.clone()),
                phase: MaintenancePhase::BypassPreparing,
                active_domains: request.domains.clone(),
                expected_generation: request.expected_applied_generation,
                expected_desired_hash: request.expected_desired_hash.clone(),
                applied_generation: convergence.applied_generation,
                applied_desired_hash: convergence.applied_desired_hash.clone(),
                bypass_started_at_ms: Some(now_ms),
                last_progress_at_ms: now_ms,
                last_error: None,
            }),
        })
    }

    pub(crate) fn commit_enter(&mut self, mut state: MaintenanceState) {
        state.phase = MaintenancePhase::MaintenanceBypass;
        state.last_error = None;
        self.state = state;
    }

    pub(crate) fn record_enter_failure(
        &mut self,
        mut state: MaintenanceState,
        error: impl AsRef<str>,
        now_ms: u64,
    ) {
        state.phase = MaintenancePhase::MaintenanceBypass;
        state.last_progress_at_ms = now_ms;
        state.last_error = Some(bounded_error(error));
        self.state = state;
    }

    pub(crate) fn plan_exit(
        &self,
        request: &MaintenanceExitRequest,
        convergence: &MaintenanceConvergence,
        now_ms: u64,
    ) -> Result<MaintenancePlan, MaintenanceError> {
        bounded_text(&request.operation_id, "operation_id", MAX_OPERATION_ID_BYTES)?;
        bounded_optional_text(
            request.expected_applied_desired_hash.as_deref(),
            "expected_applied_desired_hash",
            MAX_HASH_BYTES,
        )?;
        if self.state.phase == MaintenancePhase::Committed
            && self.state.operation_id.as_deref() == Some(&request.operation_id)
            && self.state.applied_generation == request.expected_applied_generation
            && self.state.applied_desired_hash == request.expected_applied_desired_hash
        {
            return Ok(MaintenancePlan {
                disposition: MaintenanceDisposition::Idempotent,
                next_state: None,
            });
        }
        if self.state.phase != MaintenancePhase::MaintenanceBypass {
            return Err(MaintenanceError::conflict(
                "maintenance_phase_conflict",
                "exit requires maintenance_bypass phase",
            ));
        }
        if self.state.operation_id.as_deref() != Some(&request.operation_id) {
            return Err(MaintenanceError::conflict(
                "maintenance_operation_mismatch",
                "exit operation identity does not match",
            ));
        }
        if request.expected_applied_generation != convergence.applied_generation
            || request.expected_applied_generation != self.state.applied_generation
        {
            return Err(MaintenanceError::conflict(
                "maintenance_generation_mismatch",
                "exit applied generation compare-and-swap failed",
            ));
        }
        if request.expected_applied_desired_hash != convergence.applied_desired_hash
            || request.expected_applied_desired_hash != self.state.applied_desired_hash
        {
            return Err(MaintenanceError::conflict(
                "maintenance_desired_hash_mismatch",
                "exit desired hash compare-and-swap failed",
            ));
        }
        if !convergence.is_complete() {
            return Err(MaintenanceError::conflict(
                "maintenance_convergence_incomplete",
                "pending generation or incomplete ready/enforce managed port set",
            ));
        }
        let mut next = self.state.clone();
        next.phase = MaintenancePhase::Verifying;
        next.last_progress_at_ms = now_ms;
        next.last_error = None;
        Ok(MaintenancePlan {
            disposition: MaintenanceDisposition::Mutate,
            next_state: Some(next),
        })
    }

    pub(crate) fn commit_exit(&mut self, mut state: MaintenanceState) {
        state.phase = MaintenancePhase::Committed;
        state.active_domains.clear();
        state.last_error = None;
        self.state = state;
    }

    pub(crate) fn plan_abort(
        &self,
        request: &MaintenanceAbortRequest,
        convergence: &MaintenanceConvergence,
        now_ms: u64,
    ) -> Result<MaintenancePlan, MaintenanceError> {
        bounded_text(&request.operation_id, "operation_id", MAX_OPERATION_ID_BYTES)?;
        bounded_optional_text(request.error.as_deref(), "error", MAX_ERROR_BYTES)?;
        if self.state.operation_id.as_deref() != Some(&request.operation_id) {
            return Err(MaintenanceError::conflict(
                "maintenance_operation_mismatch",
                "abort operation identity does not match",
            ));
        }
        if self.state.phase != request.expected_phase || !self.state.is_active() {
            return Err(MaintenanceError::conflict(
                "maintenance_phase_conflict",
                "abort phase compare-and-swap failed",
            ));
        }
        let mut next = self.state.clone();
        next.last_progress_at_ms = now_ms;
        next.last_error = Some(bounded_error(
            request.error.as_deref().unwrap_or("maintenance_aborted"),
        ));
        if convergence.is_complete()
            && convergence.applied_generation == self.state.applied_generation
            && convergence.applied_desired_hash == self.state.applied_desired_hash
        {
            next.phase = MaintenancePhase::Verifying;
        } else {
            next.phase = MaintenancePhase::MaintenanceBypass;
        }
        Ok(MaintenancePlan {
            disposition: MaintenanceDisposition::Mutate,
            next_state: Some(next),
        })
    }

    pub(crate) fn commit_abort(&mut self, state: MaintenanceState) {
        self.state = state;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MaintenanceWriter {
    FullHostSnapshot,
    PortSnapshot,
    Delete,
    Periodic,
    Background,
    Direct,
}

pub(crate) fn admit_maintenance_writer(
    state: &MaintenanceState,
    writer: MaintenanceWriter,
    operation_id: Option<&str>,
) -> Result<(), MaintenanceError> {
    if !state.is_active() {
        return Ok(());
    }
    if writer != MaintenanceWriter::FullHostSnapshot {
        return Err(MaintenanceError::conflict(
            "maintenance_requires_full_host",
            "maintenance permits only a matching full-host snapshot",
        ));
    }
    if state.operation_id.as_deref() != operation_id {
        return Err(MaintenanceError::conflict(
            "maintenance_operation_mismatch",
            "snapshot maintenance operation identity does not match",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum MaintenanceWalRecord {
    EnterIntent {
        schema_version: u32,
        state: MaintenanceState,
    },
    EnterCommit {
        schema_version: u32,
        state: MaintenanceState,
    },
    ExitIntent {
        schema_version: u32,
        state: MaintenanceState,
    },
    ExitCommit {
        schema_version: u32,
        state: MaintenanceState,
    },
    AbortIntent {
        schema_version: u32,
        state: MaintenanceState,
    },
    AbortCommit {
        schema_version: u32,
        state: MaintenanceState,
    },
    ProgressCommit {
        schema_version: u32,
        state: MaintenanceState,
    },
}

impl MaintenanceWalRecord {
    fn version_and_state(&self) -> (u32, &MaintenanceState) {
        match self {
            Self::EnterIntent {
                schema_version,
                state,
            }
            | Self::EnterCommit {
                schema_version,
                state,
            }
            | Self::ExitIntent {
                schema_version,
                state,
            }
            | Self::ExitCommit {
                schema_version,
                state,
            }
            | Self::AbortIntent {
                schema_version,
                state,
            }
            | Self::AbortCommit {
                schema_version,
                state,
            }
            | Self::ProgressCommit {
                schema_version,
                state,
            } => (*schema_version, state),
        }
    }

    pub(crate) fn enter_intent_state(state: MaintenanceState) -> Self {
        Self::EnterIntent {
            schema_version: MAINTENANCE_SCHEMA_VERSION,
            state,
        }
    }

    pub(crate) fn enter_commit_state(state: MaintenanceState) -> Self {
        Self::EnterCommit {
            schema_version: MAINTENANCE_SCHEMA_VERSION,
            state,
        }
    }

    pub(crate) fn exit_intent_state(state: MaintenanceState) -> Self {
        Self::ExitIntent {
            schema_version: MAINTENANCE_SCHEMA_VERSION,
            state,
        }
    }

    pub(crate) fn exit_commit_state(state: MaintenanceState) -> Self {
        Self::ExitCommit {
            schema_version: MAINTENANCE_SCHEMA_VERSION,
            state,
        }
    }

    pub(crate) fn abort_intent_state(state: MaintenanceState) -> Self {
        Self::AbortIntent {
            schema_version: MAINTENANCE_SCHEMA_VERSION,
            state,
        }
    }

    pub(crate) fn abort_commit_state(state: MaintenanceState) -> Self {
        Self::AbortCommit {
            schema_version: MAINTENANCE_SCHEMA_VERSION,
            state,
        }
    }

    pub(crate) fn progress_commit_state(state: MaintenanceState) -> Self {
        Self::ProgressCommit {
            schema_version: MAINTENANCE_SCHEMA_VERSION,
            state,
        }
    }

    #[cfg(test)]
    fn enter_intent(
        request: MaintenanceEnterRequest,
        convergence: MaintenanceConvergence,
        now_ms: u64,
    ) -> Result<Self, MaintenanceError> {
        let state = MaintenanceStateMachine::default()
            .plan_enter(&request, &convergence, now_ms)?
            .next_state
            .expect("mutating enter plan carries state");
        Ok(Self::EnterIntent {
            schema_version: MAINTENANCE_SCHEMA_VERSION,
            state,
        })
    }

    #[cfg(test)]
    fn abort_commit(state: MaintenanceState) -> Self {
        Self::AbortCommit {
            schema_version: MAINTENANCE_SCHEMA_VERSION,
            state,
        }
    }
}

pub(crate) fn decode_maintenance_record(raw: &[u8]) -> Result<MaintenanceWalRecord, String> {
    if raw.len() > MAINTENANCE_WAL_RECORD_MAX_BYTES {
        return Err(format!(
            "oversized maintenance WAL record: {} bytes",
            raw.len()
        ));
    }
    let record: MaintenanceWalRecord = serde_json::from_slice(raw)
        .map_err(|error| format!("unknown or malformed maintenance WAL record: {}", error))?;
    let (version, state) = record.version_and_state();
    if version != MAINTENANCE_SCHEMA_VERSION {
        return Err(format!(
            "unsupported maintenance WAL schema version {}",
            version
        ));
    }
    validate_state(state)?;
    Ok(record)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MaintenanceReplay {
    pub(crate) state: MaintenanceState,
    pub(crate) requires_bypass: bool,
}

impl Default for MaintenanceReplay {
    fn default() -> Self {
        Self {
            state: MaintenanceState::inactive(),
            requires_bypass: false,
        }
    }
}

pub(crate) fn replay_maintenance_records(
    records: &[MaintenanceWalRecord],
) -> Result<MaintenanceReplay, String> {
    let mut seen = BTreeSet::new();
    let mut state = MaintenanceState::inactive();
    let mut pending: Option<&'static str> = None;
    for record in records {
        let encoded = serde_json::to_string(record)
            .map_err(|error| format!("serialize maintenance replay key: {}", error))?;
        if !seen.insert(encoded) {
            return Err("duplicate maintenance WAL record".to_string());
        }
        let (version, next) = record.version_and_state();
        if version != MAINTENANCE_SCHEMA_VERSION {
            return Err(format!("unsupported maintenance WAL version {}", version));
        }
        validate_state(next)?;
        match record {
            MaintenanceWalRecord::EnterIntent { .. } => {
                if pending.is_some() || state.is_active() {
                    return Err("conflicting maintenance enter intent".to_string());
                }
                if next.phase != MaintenancePhase::BypassPreparing
                    || next.operation_id.is_none()
                    || next.active_domains.len() != 1
                    || next.active_domains[0] != "acl"
                {
                    return Err("invalid maintenance enter intent state".to_string());
                }
                state = next.clone();
                state.phase = MaintenancePhase::MaintenanceBypass;
                state.last_error = Some("recovered_dangling_enter_intent".to_string());
                pending = Some("enter");
            }
            MaintenanceWalRecord::EnterCommit { .. } => {
                if pending != Some("enter") {
                    return Err("maintenance enter commit without intent".to_string());
                }
                if state.operation_id != next.operation_id
                    || next.phase != MaintenancePhase::MaintenanceBypass
                    || next.active_domains.len() != 1
                    || next.active_domains[0] != "acl"
                {
                    return Err("maintenance enter commit identity changed".to_string());
                }
                state = next.clone();
                state.phase = MaintenancePhase::MaintenanceBypass;
                pending = None;
            }
            MaintenanceWalRecord::ExitIntent { .. } => {
                if !state.is_active() || pending.is_some() {
                    return Err("maintenance exit intent without active operation".to_string());
                }
                if state.operation_id != next.operation_id
                    || next.phase != MaintenancePhase::Verifying
                {
                    return Err("maintenance exit intent identity changed".to_string());
                }
                state = next.clone();
                state.phase = MaintenancePhase::MaintenanceBypass;
                state.last_error = Some("recovered_dangling_exit_intent".to_string());
                pending = Some("exit");
            }
            MaintenanceWalRecord::ExitCommit { .. } => {
                if pending != Some("exit") {
                    return Err("maintenance exit commit without intent".to_string());
                }
                if state.operation_id != next.operation_id
                    || next.phase != MaintenancePhase::Committed
                    || !next.active_domains.is_empty()
                {
                    return Err("maintenance exit commit identity changed".to_string());
                }
                state = next.clone();
                pending = None;
            }
            MaintenanceWalRecord::AbortIntent { .. } => {
                if !state.is_active() || pending.is_some() {
                    return Err("maintenance abort intent without active operation".to_string());
                }
                if state.operation_id != next.operation_id
                    || !matches!(
                        next.phase,
                        MaintenancePhase::Verifying | MaintenancePhase::MaintenanceBypass
                    )
                {
                    return Err("maintenance abort intent identity changed".to_string());
                }
                state = next.clone();
                state.phase = MaintenancePhase::MaintenanceBypass;
                pending = Some("abort");
            }
            MaintenanceWalRecord::AbortCommit { .. } => {
                if pending != Some("abort") || state.operation_id != next.operation_id {
                    return Err("maintenance abort commit without matching intent".to_string());
                }
                state = next.clone();
                if !matches!(
                    state.phase,
                    MaintenancePhase::Committed | MaintenancePhase::MaintenanceBypass
                ) {
                    return Err("invalid maintenance abort commit phase".to_string());
                }
                if state.phase != MaintenancePhase::Committed {
                    state.phase = MaintenancePhase::MaintenanceBypass;
                }
                pending = None;
            }
            MaintenanceWalRecord::ProgressCommit { .. } => {
                if !state.is_active() || pending.is_some() {
                    return Err("maintenance progress commit without active operation".to_string());
                }
                if state.operation_id != next.operation_id {
                    return Err("maintenance progress operation identity changed".to_string());
                }
                state = next.clone();
                state.phase = MaintenancePhase::MaintenanceBypass;
            }
        }
    }
    Ok(MaintenanceReplay {
        requires_bypass: state.is_active(),
        state,
    })
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

#[derive(Clone)]
pub(crate) struct MaintenanceCoordinator {
    wal: Arc<NeutronWal>,
    control_plane: Arc<ControlPlane>,
    state: Arc<RwLock<MaintenanceState>>,
    blocked: Arc<AtomicBool>,
}

impl MaintenanceCoordinator {
    pub(crate) fn new(wal: Arc<NeutronWal>, control_plane: Arc<ControlPlane>) -> Self {
        let replay = wal.replay();
        Self {
            wal,
            control_plane,
            state: Arc::new(RwLock::new(replay.maintenance.state)),
            blocked: Arc::new(AtomicBool::new(replay.maintenance_failures != 0)),
        }
    }

    pub(crate) async fn status(&self) -> MaintenanceState {
        self.state.read().await.clone()
    }

    pub(crate) async fn is_active(&self) -> bool {
        self.blocked.load(Ordering::Acquire) || self.state.read().await.is_active()
    }

    pub(crate) fn is_blocked(&self) -> bool {
        self.blocked.load(Ordering::Acquire)
    }

    pub(crate) async fn recover_before_reconciliation(&self) -> Result<(), String> {
        let replay = self.wal.replay();
        let mut recovered = replay.maintenance.state;
        if replay.maintenance.requires_bypass || replay.maintenance_failures != 0 {
            let authority = self
                .control_plane
                .mint_managed_maintenance_authority()
                .await
                .map_err(|error| format!("maintenance startup authority: {}", error))?;
            if let Err(error) = self
                .control_plane
                .set_acl_maintenance_bypass(&authority, true)
                .await
            {
                recovered.phase = MaintenancePhase::MaintenanceBypass;
                recovered.last_progress_at_ms = now_ms();
                recovered.last_error = Some(bounded_error(format!(
                    "maintenance_startup_gate_failed:{}",
                    error
                )));
                *self.state.write().await = recovered;
                self.blocked.store(true, Ordering::Release);
                return Err(format!("force maintenance bypass before reconciliation: {}", error));
            }
        }
        if replay.maintenance_failures != 0 {
            recovered.last_error = Some(bounded_error(format!(
                "maintenance_wal_replay_failures:{}",
                replay.maintenance_failures
            )));
            *self.state.write().await = recovered;
            self.blocked.store(true, Ordering::Release);
            return Err(format!(
                "maintenance WAL replay reported {} failure(s)",
                replay.maintenance_failures
            ));
        }
        *self.state.write().await = recovered;
        self.blocked.store(false, Ordering::Release);
        Ok(())
    }

    pub(crate) async fn admit_writer(
        &self,
        writer: MaintenanceWriter,
        operation_id: Option<&str>,
    ) -> Result<(), MaintenanceError> {
        if self.blocked.load(Ordering::Acquire) {
            return Err(MaintenanceError::conflict(
                "maintenance_recovery_blocked",
                "maintenance WAL or gate recovery is unresolved",
            ));
        }
        let state = self.state.read().await;
        admit_maintenance_writer(&*state, writer, operation_id)
    }

    pub(crate) async fn enter(
        &self,
        request: MaintenanceEnterRequest,
        convergence: MaintenanceConvergence,
    ) -> Result<(MaintenanceDisposition, MaintenanceState), MaintenanceError> {
        if self.blocked.load(Ordering::Acquire) {
            return Err(MaintenanceError::conflict(
                "maintenance_recovery_blocked",
                "maintenance recovery must be resolved before enter",
            ));
        }
        let current = self.state.read().await.clone();
        let mut machine = MaintenanceStateMachine::with_state(current);
        let plan = machine.plan_enter(&request, &convergence, now_ms())?;
        if plan.disposition == MaintenanceDisposition::Idempotent {
            return Ok((plan.disposition, machine.state().clone()));
        }
        let preparing = plan
            .next_state
            .expect("mutating maintenance enter plan carries state");

        let authority = self
            .control_plane
            .mint_managed_maintenance_authority()
            .await
            .map_err(|error| {
                MaintenanceError::conflict("maintenance_authority_unavailable", error)
            })?;
        self.wal
            .append_maintenance_record(MaintenanceWalRecord::enter_intent_state(
                preparing.clone(),
            ))
            .map_err(|error| MaintenanceError::internal("maintenance_wal_intent_failed", error))?;
        *self.state.write().await = preparing.clone();

        if let Err(error) = self
            .control_plane
            .set_acl_maintenance_bypass(&authority, true)
            .await
        {
            machine.record_enter_failure(
                preparing,
                format!("gate_readback_failed:{}", error),
                now_ms(),
            );
            *self.state.write().await = machine.state().clone();
            return Err(MaintenanceError::internal(
                "maintenance_gate_enable_failed",
                error,
            ));
        }

        machine.commit_enter(preparing);
        let mut active = machine.state().clone();
        active.last_progress_at_ms = now_ms();
        if let Err(error) = self
            .wal
            .append_maintenance_record(MaintenanceWalRecord::enter_commit_state(active.clone()))
        {
            active.last_error = Some(bounded_error(format!("wal_commit_failed:{}", error)));
            *self.state.write().await = active;
            return Err(MaintenanceError::internal(
                "maintenance_wal_commit_failed",
                error,
            ));
        }
        *self.state.write().await = active.clone();
        Ok((MaintenanceDisposition::Mutate, active))
    }

    pub(crate) async fn record_applied_snapshot(
        &self,
        operation_id: Option<&str>,
        generation: u64,
        desired_hash: Option<String>,
    ) -> Result<(), String> {
        let mut state = self.state.read().await.clone();
        if !state.is_active() {
            return Ok(());
        }
        if state.operation_id.as_deref() != operation_id {
            return Err("maintenance snapshot completion operation identity changed".to_string());
        }
        state.applied_generation = generation;
        state.applied_desired_hash = desired_hash;
        state.last_progress_at_ms = now_ms();
        state.last_error = None;
        self.wal.append_maintenance_record(
            MaintenanceWalRecord::progress_commit_state(state.clone()),
        )?;
        *self.state.write().await = state;
        Ok(())
    }

    pub(crate) async fn exit(
        &self,
        request: MaintenanceExitRequest,
        convergence: MaintenanceConvergence,
    ) -> Result<(MaintenanceDisposition, MaintenanceState), MaintenanceError> {
        if self.blocked.load(Ordering::Acquire) {
            return Err(MaintenanceError::conflict(
                "maintenance_recovery_blocked",
                "maintenance recovery must be resolved before exit",
            ));
        }
        let current = self.state.read().await.clone();
        let mut machine = MaintenanceStateMachine::with_state(current.clone());
        let plan = machine.plan_exit(&request, &convergence, now_ms())?;
        if plan.disposition == MaintenanceDisposition::Idempotent {
            return Ok((plan.disposition, current));
        }
        let verifying = plan
            .next_state
            .expect("mutating maintenance exit plan carries state");
        let authority = self
            .control_plane
            .mint_managed_maintenance_authority()
            .await
            .map_err(|error| {
                MaintenanceError::conflict("maintenance_authority_unavailable", error)
            })?;
        self.wal
            .append_maintenance_record(MaintenanceWalRecord::exit_intent_state(
                verifying.clone(),
            ))
            .map_err(|error| MaintenanceError::internal("maintenance_wal_intent_failed", error))?;
        *self.state.write().await = verifying.clone();
        if let Err(error) = self
            .control_plane
            .set_acl_maintenance_bypass(&authority, false)
            .await
        {
            let mut failed = current;
            failed.phase = MaintenancePhase::MaintenanceBypass;
            failed.last_progress_at_ms = now_ms();
            failed.last_error = Some(bounded_error(format!("exit_gate_failed:{}", error)));
            *self.state.write().await = failed;
            return Err(MaintenanceError::internal(
                "maintenance_gate_disable_failed",
                error,
            ));
        }

        machine.commit_exit(verifying);
        let mut committed = machine.state().clone();
        committed.last_progress_at_ms = now_ms();
        if let Err(error) = self.wal.append_maintenance_record(
            MaintenanceWalRecord::exit_commit_state(committed.clone()),
        ) {
            let restore = self
                .control_plane
                .set_acl_maintenance_bypass(&authority, true)
                .await;
            let mut failed = current;
            failed.phase = MaintenancePhase::MaintenanceBypass;
            failed.last_progress_at_ms = now_ms();
            failed.last_error = Some(bounded_error(format!(
                "exit_commit_failed:{};bypass_restore:{:?}",
                error, restore
            )));
            *self.state.write().await = failed;
            return Err(MaintenanceError::internal(
                "maintenance_wal_commit_failed",
                error,
            ));
        }
        *self.state.write().await = committed.clone();
        Ok((MaintenanceDisposition::Mutate, committed))
    }

    pub(crate) async fn abort(
        &self,
        request: MaintenanceAbortRequest,
        convergence: MaintenanceConvergence,
    ) -> Result<(MaintenanceDisposition, MaintenanceState), MaintenanceError> {
        if self.blocked.load(Ordering::Acquire) {
            return Err(MaintenanceError::conflict(
                "maintenance_recovery_blocked",
                "maintenance recovery must be resolved before abort",
            ));
        }
        let current = self.state.read().await.clone();
        let mut machine = MaintenanceStateMachine::with_state(current.clone());
        let plan = machine.plan_abort(&request, &convergence, now_ms())?;
        let mut next = plan
            .next_state
            .expect("mutating maintenance abort plan carries state");
        self.wal
            .append_maintenance_record(MaintenanceWalRecord::abort_intent_state(next.clone()))
            .map_err(|error| MaintenanceError::internal("maintenance_wal_intent_failed", error))?;
        *self.state.write().await = next.clone();

        if next.phase == MaintenancePhase::Verifying {
            let authority = self
                .control_plane
                .mint_managed_maintenance_authority()
                .await
                .map_err(|error| {
                    MaintenanceError::conflict("maintenance_authority_unavailable", error)
                })?;
            if let Err(error) = self
                .control_plane
                .set_acl_maintenance_bypass(&authority, false)
                .await
            {
                next = current;
                next.phase = MaintenancePhase::MaintenanceBypass;
                next.last_error = Some(bounded_error(format!("abort_gate_failed:{}", error)));
                *self.state.write().await = next;
                return Err(MaintenanceError::internal(
                    "maintenance_gate_disable_failed",
                    error,
                ));
            }
            next.phase = MaintenancePhase::Committed;
            next.active_domains.clear();
        } else {
            next.phase = MaintenancePhase::MaintenanceBypass;
        }
        if let Err(error) = self
            .wal
            .append_maintenance_record(MaintenanceWalRecord::abort_commit_state(next.clone()))
        {
            let restore = if next.phase == MaintenancePhase::Committed {
                match self.control_plane.mint_managed_maintenance_authority().await {
                    Ok(authority) => self
                        .control_plane
                        .set_acl_maintenance_bypass(&authority, true)
                        .await,
                    Err(authority_error) => Err(authority_error),
                }
            } else {
                Ok(())
            };
            let mut failed = current;
            failed.phase = MaintenancePhase::MaintenanceBypass;
            failed.last_progress_at_ms = now_ms();
            failed.last_error = Some(bounded_error(format!(
                "abort_commit_failed:{};bypass_restore:{:?}",
                error, restore
            )));
            *self.state.write().await = failed;
            return Err(MaintenanceError::internal(
                "maintenance_wal_commit_failed",
                error,
            ));
        }
        machine.commit_abort(next.clone());
        *self.state.write().await = machine.state().clone();
        Ok((MaintenanceDisposition::Mutate, next))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AdminSocketFacts {
    pub(crate) parent_is_directory: bool,
    pub(crate) parent_is_symlink: bool,
    pub(crate) parent_uid: u32,
    pub(crate) socket_is_socket: bool,
    pub(crate) socket_is_symlink: bool,
    pub(crate) socket_uid: u32,
    pub(crate) socket_gid: u32,
    pub(crate) socket_mode: u32,
}

pub(crate) fn validate_admin_socket_facts(facts: &AdminSocketFacts) -> Result<(), String> {
    if !facts.parent_is_directory
        || facts.parent_is_symlink
        || facts.parent_uid != 0
    {
        return Err("admin socket parent must be a root-owned non-symlink directory".to_string());
    }
    if !facts.socket_is_socket
        || facts.socket_is_symlink
        || facts.socket_uid != 0
        || facts.socket_gid != 0
        || facts.socket_mode != 0o600
    {
        return Err("admin socket must be a root-owned 0600 non-symlink socket".to_string());
    }
    Ok(())
}

const ADMIN_ROUTES: &[(&str, &str)] = &[
    ("POST", "/api/v1/admin/maintenance/enter"),
    ("GET", "/api/v1/admin/maintenance"),
    ("POST", "/api/v1/admin/maintenance/exit"),
    ("POST", "/api/v1/admin/maintenance/abort"),
];

pub(crate) fn admin_route_specs() -> &'static [(&'static str, &'static str)] {
    ADMIN_ROUTES
}

#[cfg(test)]
pub(crate) fn neutron_route_specs() -> &'static [(&'static str, &'static str)] {
    &[
        ("GET", "/readyz"),
        ("GET", "/api/v1/neutron/capabilities"),
        ("GET", "/api/v1/neutron/status"),
        ("POST", "/api/v1/neutron/snapshot/recover-pending"),
        ("PUT", "/api/v1/neutron/snapshot"),
        ("PUT", "/api/v1/neutron/ports/{port_id}/snapshot"),
        ("DELETE", "/api/v1/neutron/ports/{port_id}"),
    ]
}

#[cfg(test)]
pub(crate) fn tcp_route_specs() -> &'static [(&'static str, &'static str)] {
    &[]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn active_state(operation_id: &str, generation: u64, desired_hash: &str) -> MaintenanceState {
        MaintenanceState {
            schema_version: MAINTENANCE_SCHEMA_VERSION,
            operation_id: Some(operation_id.to_string()),
            phase: MaintenancePhase::MaintenanceBypass,
            active_domains: vec!["acl".to_string()],
            expected_generation: generation,
            expected_desired_hash: Some(desired_hash.to_string()),
            applied_generation: generation,
            applied_desired_hash: Some(desired_hash.to_string()),
            bypass_started_at_ms: Some(1),
            last_progress_at_ms: 1,
            last_error: None,
        }
    }

    fn enter_request(operation_id: &str) -> MaintenanceEnterRequest {
        MaintenanceEnterRequest {
            operation_id: operation_id.to_string(),
            domains: vec!["acl".to_string()],
            reason: "planned_upgrade".to_string(),
            expected_applied_generation: 41,
            expected_desired_hash: Some("sha256:host-41".to_string()),
        }
    }

    fn convergence() -> MaintenanceConvergence {
        MaintenanceConvergence {
            applied_generation: 41,
            applied_desired_hash: Some("sha256:host-41".to_string()),
            pending_generation: None,
            managed_port_count: 2,
            ready_enforce_port_count: 2,
        }
    }

    #[test]
    fn neutron_maintenance_same_enter_is_idempotent_and_conflict_is_side_effect_free() {
        let mut machine = MaintenanceStateMachine::default();
        let request = enter_request("op-a");
        let first = machine.plan_enter(&request, &convergence(), 1_000).unwrap();
        assert_eq!(first.disposition, MaintenanceDisposition::Mutate);
        machine.commit_enter(first.next_state.unwrap());
        let baseline = machine.state().clone();

        let repeated = machine.plan_enter(&request, &convergence(), 2_000).unwrap();
        assert_eq!(repeated.disposition, MaintenanceDisposition::Idempotent);
        let mut conflicting = enter_request("op-b");
        conflicting.expected_applied_generation = 99;
        let error = machine
            .plan_enter(&conflicting, &convergence(), 3_000)
            .unwrap_err();
        assert_eq!(error.http_status, 409);
        assert_eq!(machine.state(), &baseline);
    }

    #[test]
    fn neutron_maintenance_generation_hash_and_phase_cas_mismatch_do_not_mutate_state() {
        let machine = MaintenanceStateMachine::default();
        let baseline = machine.state().clone();
        let mut wrong_generation = enter_request("op-a");
        wrong_generation.expected_applied_generation = 40;
        assert_eq!(
            machine
                .plan_enter(&wrong_generation, &convergence(), 1_000)
                .unwrap_err()
                .code,
            "maintenance_generation_mismatch"
        );
        let mut wrong_hash = enter_request("op-a");
        wrong_hash.expected_desired_hash = Some("sha256:wrong".to_string());
        assert_eq!(
            machine
                .plan_enter(&wrong_hash, &convergence(), 1_000)
                .unwrap_err()
                .code,
            "maintenance_desired_hash_mismatch"
        );
        assert_eq!(machine.state(), &baseline);
    }

    #[test]
    fn neutron_maintenance_dangling_enter_intent_replays_as_active_bypass() {
        let intent = MaintenanceWalRecord::enter_intent(
            enter_request("op-restart"),
            convergence(),
            1_000,
        )
        .unwrap();
        let replay = replay_maintenance_records(&[intent]).unwrap();

        assert!(replay.requires_bypass);
        assert_eq!(replay.state.operation_id.as_deref(), Some("op-restart"));
        assert_eq!(replay.state.phase, MaintenancePhase::MaintenanceBypass);
        assert!(replay.state.last_error.as_deref().unwrap().contains("intent"));
    }

    #[test]
    fn neutron_maintenance_gate_or_commit_failure_never_reports_active_success_or_clears_gate() {
        let mut machine = MaintenanceStateMachine::default();
        let plan = machine
            .plan_enter(&enter_request("op-a"), &convergence(), 1_000)
            .unwrap();
        let preparing = plan.next_state.unwrap();
        machine.record_enter_failure(preparing.clone(), "gate_readback_failed", 1_100);
        assert!(machine.state().is_active());
        assert_ne!(machine.state().phase, MaintenancePhase::Committed);
        assert!(machine.state().last_error.as_deref().unwrap().contains("gate"));

        machine.record_enter_failure(preparing, "wal_commit_failed", 1_200);
        assert!(machine.state().is_active());
        assert!(machine.state().last_error.as_deref().unwrap().contains("wal"));
    }

    #[test]
    fn neutron_maintenance_writer_fence_allows_only_matching_full_host_snapshot() {
        let state = active_state("op-a", 41, "sha256:host-41");
        assert!(admit_maintenance_writer(
            &state,
            MaintenanceWriter::FullHostSnapshot,
            Some("op-a")
        )
        .is_ok());
        assert_eq!(
            admit_maintenance_writer(&state, MaintenanceWriter::FullHostSnapshot, None)
                .unwrap_err()
                .code,
            "maintenance_operation_mismatch"
        );
        assert_eq!(
            admit_maintenance_writer(
                &state,
                MaintenanceWriter::FullHostSnapshot,
                Some("op-b")
            )
            .unwrap_err()
            .code,
            "maintenance_operation_mismatch"
        );
        for writer in [
            MaintenanceWriter::PortSnapshot,
            MaintenanceWriter::Delete,
            MaintenanceWriter::Periodic,
            MaintenanceWriter::Background,
            MaintenanceWriter::Direct,
        ] {
            assert_eq!(
                admit_maintenance_writer(&state, writer, Some("op-a"))
                    .unwrap_err()
                    .code,
                "maintenance_requires_full_host"
            );
        }
    }

    #[test]
    fn neutron_maintenance_exit_requires_exact_complete_convergence_and_is_idempotent() {
        let mut machine = MaintenanceStateMachine::with_state(
            active_state("op-a", 41, "sha256:host-41"),
        );
        let request = MaintenanceExitRequest {
            operation_id: "op-a".to_string(),
            expected_applied_generation: 41,
            expected_applied_desired_hash: Some("sha256:host-41".to_string()),
        };
        let mut incomplete = convergence();
        incomplete.ready_enforce_port_count = 1;
        assert_eq!(
            machine.plan_exit(&request, &incomplete, 2_000).unwrap_err().code,
            "maintenance_convergence_incomplete"
        );
        let plan = machine.plan_exit(&request, &convergence(), 2_000).unwrap();
        machine.commit_exit(plan.next_state.unwrap());
        assert_eq!(machine.state().phase, MaintenancePhase::Committed);
        assert_eq!(
            machine
                .plan_exit(&request, &convergence(), 3_000)
                .unwrap()
                .disposition,
            MaintenanceDisposition::Idempotent
        );
    }

    #[test]
    fn neutron_maintenance_abort_and_restart_remain_bypassed_without_convergence() {
        let mut machine = MaintenanceStateMachine::with_state(
            active_state("op-a", 41, "sha256:host-41"),
        );
        let request = MaintenanceAbortRequest {
            operation_id: "op-a".to_string(),
            expected_phase: MaintenancePhase::MaintenanceBypass,
            error: Some("candidate_failed".to_string()),
        };
        let mut incomplete = convergence();
        incomplete.pending_generation = Some(42);
        let next = machine.plan_abort(&request, &incomplete, 2_000).unwrap();
        machine.commit_abort(next.next_state.unwrap());
        assert!(machine.state().is_active());
        let active = active_state("op-a", 41, "sha256:host-41");
        let mut preparing = active.clone();
        preparing.phase = MaintenancePhase::BypassPreparing;
        let replay = replay_maintenance_records(&[
            MaintenanceWalRecord::enter_intent_state(preparing),
            MaintenanceWalRecord::enter_commit_state(active),
            MaintenanceWalRecord::abort_intent_state(machine.state().clone()),
            MaintenanceWalRecord::abort_commit(machine.state().clone()),
        ])
        .unwrap();
        assert!(replay.requires_bypass);
    }

    #[test]
    fn neutron_maintenance_records_are_bounded_typed_and_reject_duplicate_unknown_or_oversized() {
        let request = enter_request("op-a");
        let intent = MaintenanceWalRecord::enter_intent(request, convergence(), 1_000).unwrap();
        assert!(replay_maintenance_records(&[intent.clone(), intent])
            .unwrap_err()
            .contains("duplicate"));
        assert!(decode_maintenance_record(br#"{"schema_version":1,"kind":"unknown"}"#)
            .unwrap_err()
            .contains("unknown"));
        assert!(decode_maintenance_record(&vec![b'x'; MAINTENANCE_WAL_RECORD_MAX_BYTES + 1])
            .unwrap_err()
            .contains("oversized"));
        let nested = br#"{"schema_version":1,"kind":"enter_intent","state":{"operation_id":{"secret":"leak"}}}"#;
        assert!(decode_maintenance_record(nested).is_err());
    }

    #[test]
    fn neutron_maintenance_status_is_bounded_and_contains_no_policy_or_secret_fields() {
        let state = active_state("op-a", 41, "sha256:host-41");
        let encoded = serde_json::to_value(&state).unwrap();
        assert!(encoded.get("policy").is_none());
        assert!(encoded.get("token").is_none());
        assert!(encoded.get("secret").is_none());
        assert!(encoded["active_domains"].as_array().unwrap().len() <= 4);
    }

    #[test]
    fn neutron_maintenance_admin_socket_policy_is_exact_and_rejects_symlinks_or_non_sockets() {
        assert_eq!(ADMIN_SOCKET_PATH, "/run/aria/aria-admin.sock");
        let valid = AdminSocketFacts {
            parent_is_directory: true,
            parent_is_symlink: false,
            parent_uid: 0,
            socket_is_socket: true,
            socket_is_symlink: false,
            socket_uid: 0,
            socket_gid: 0,
            socket_mode: 0o600,
        };
        validate_admin_socket_facts(&valid).unwrap();

        let mut symlink = valid;
        symlink.socket_is_symlink = true;
        assert!(validate_admin_socket_facts(&symlink).is_err());
        let mut non_socket = valid;
        non_socket.socket_is_socket = false;
        assert!(validate_admin_socket_facts(&non_socket).is_err());
        let mut public = valid;
        public.socket_mode = 0o660;
        assert!(validate_admin_socket_facts(&public).is_err());
        let mut non_root = valid;
        non_root.socket_uid = 1000;
        assert!(validate_admin_socket_facts(&non_root).is_err());
    }

    #[test]
    fn neutron_maintenance_admin_route_inventory_is_separate_and_complete() {
        assert_eq!(
            admin_route_specs(),
            &[
                ("POST", "/api/v1/admin/maintenance/enter"),
                ("GET", "/api/v1/admin/maintenance"),
                ("POST", "/api/v1/admin/maintenance/exit"),
                ("POST", "/api/v1/admin/maintenance/abort"),
            ]
        );
        for (_, path) in admin_route_specs() {
            assert!(!neutron_route_specs().iter().any(|(_, route)| route == path));
            assert!(!tcp_route_specs().iter().any(|(_, route)| route == path));
        }
    }
}
