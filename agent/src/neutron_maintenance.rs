use aria_api::{
    MaintenanceAbortRequest, MaintenanceEnterRequest, MaintenanceExitRequest, MaintenancePhase,
    MaintenanceState, MAINTENANCE_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock};

use crate::control_plane::ControlPlane;
use crate::neutron_wal::NeutronWal;

pub(crate) const ADMIN_SOCKET_PATH: &str = "/run/aria/aria-admin.sock";
pub(crate) const MAINTENANCE_WAL_RECORD_MAX_BYTES: usize = 64 * 1024;
const MAX_OPERATION_ID_BYTES: usize = 128;
const MAX_REASON_BYTES: usize = 256;
const MAX_HASH_BYTES: usize = 256;
const MAX_ERROR_BYTES: usize = 512;
const MAX_DOMAINS: usize = 4;
const MAX_MAINTENANCE_REPLAY_RECORDS: usize = 4_096;

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

fn same_transaction_identity(left: &MaintenanceState, right: &MaintenanceState) -> bool {
    left.schema_version == right.schema_version
        && left.operation_id == right.operation_id
        && left.expected_generation == right.expected_generation
        && left.expected_desired_hash == right.expected_desired_hash
        && left.applied_generation == right.applied_generation
        && left.applied_desired_hash == right.applied_desired_hash
        && left.bypass_started_at_ms == right.bypass_started_at_ms
        && left.active_domains == right.active_domains
}

fn same_operation_identity(left: &MaintenanceState, right: &MaintenanceState) -> bool {
    left.schema_version == right.schema_version
        && left.operation_id == right.operation_id
        && left.active_domains == right.active_domains
        && left.expected_generation == right.expected_generation
        && left.expected_desired_hash == right.expected_desired_hash
        && left.bypass_started_at_ms == right.bypass_started_at_ms
}

fn same_terminal_transaction_identity(
    left: &MaintenanceState,
    right: &MaintenanceState,
) -> bool {
    let mut terminal = right.clone();
    terminal.active_domains = left.active_domains.clone();
    same_transaction_identity(left, &terminal) && right.active_domains.is_empty()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MaintenanceConvergence {
    pub(crate) accepted_generation: u64,
    pub(crate) accepted_desired_hash: Option<String>,
    pub(crate) applied_generation: u64,
    pub(crate) applied_desired_hash: Option<String>,
    pub(crate) pending_generation: Option<u64>,
    pub(crate) managed_ports: BTreeSet<String>,
    pub(crate) ready_enforce_ports: BTreeSet<String>,
    pub(crate) wal_healthy: bool,
    pub(crate) recovery_healthy: bool,
}

impl MaintenanceConvergence {
    pub(crate) fn is_complete(&self) -> bool {
        self.accepted_generation == self.applied_generation
            && self.accepted_desired_hash == self.applied_desired_hash
            && self.pending_generation.is_none()
            && self.managed_ports == self.ready_enforce_ports
            && self.wal_healthy
            && self.recovery_healthy
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MaintenancePendingTransition {
    Enter,
    Exit,
    Abort,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MaintenanceTerminalAction {
    Exit,
    Abort,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MaintenanceGateState {
    Enforce,
    Bypass,
    Unknown,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MaintenanceAuditAction {
    Enter,
    Get,
    Exit,
    Abort,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MaintenanceAuditOutcome {
    Attempt,
    Success,
    Failure,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct MaintenanceAuditEvent {
    pub(crate) action: MaintenanceAuditAction,
    pub(crate) outcome: MaintenanceAuditOutcome,
    pub(crate) operation_id: Option<String>,
    pub(crate) phase: MaintenancePhase,
    pub(crate) reason: Option<String>,
    pub(crate) authorization: &'static str,
}

pub(crate) trait MaintenanceAuditSink: Send + Sync {
    fn emit(&self, event: MaintenanceAuditEvent);
}

#[derive(Default)]
struct TracingMaintenanceAudit;

impl MaintenanceAuditSink for TracingMaintenanceAudit {
    fn emit(&self, event: MaintenanceAuditEvent) {
        tracing::info!(
            action = ?event.action,
            outcome = ?event.outcome,
            operation_id = ?event.operation_id,
            phase = ?event.phase,
            reason = ?event.reason,
            authorization = event.authorization,
            "maintenance admin audit"
        );
    }
}

pub(crate) type MaintenanceIoFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;

pub(crate) trait MaintenanceGateRuntime: Send + Sync {
    fn verify_authority(&self) -> MaintenanceIoFuture<'_> {
        Box::pin(async { Ok(()) })
    }

    fn set_bypass_verified(&self, enabled: bool) -> MaintenanceIoFuture<'_>;
}

struct ControlPlaneMaintenanceGate {
    control_plane: Arc<ControlPlane>,
}

impl MaintenanceGateRuntime for ControlPlaneMaintenanceGate {
    fn verify_authority(&self) -> MaintenanceIoFuture<'_> {
        Box::pin(async move {
            self.control_plane
                .mint_managed_maintenance_authority()
                .await
                .map(drop)
        })
    }

    fn set_bypass_verified(&self, enabled: bool) -> MaintenanceIoFuture<'_> {
        Box::pin(async move {
            let authority = self
                .control_plane
                .mint_managed_maintenance_authority()
                .await?;
            self.control_plane
                .set_acl_maintenance_bypass(&authority, enabled)
                .await
        })
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
    Checkpoint {
        schema_version: u32,
        state: MaintenanceState,
        pending_transition: Option<MaintenancePendingTransition>,
        terminal_action: Option<MaintenanceTerminalAction>,
        #[serde(default)]
        gate_state: Option<MaintenanceGateState>,
        #[serde(default)]
        block_cause: Option<String>,
    },
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
    RecoveryCommit {
        schema_version: u32,
        state: MaintenanceState,
        gate_state: MaintenanceGateState,
        block_cause: String,
    },
}

impl MaintenanceWalRecord {
    fn version_and_state(&self) -> (u32, &MaintenanceState) {
        match self {
            Self::Checkpoint {
                schema_version,
                state,
                ..
            }
            | Self::EnterIntent {
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
            }
            | Self::RecoveryCommit {
                schema_version,
                state,
                ..
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

    pub(crate) fn checkpoint(
        state: MaintenanceState,
        pending_transition: Option<MaintenancePendingTransition>,
        terminal_action: Option<MaintenanceTerminalAction>,
        gate_state: MaintenanceGateState,
        block_cause: Option<String>,
    ) -> Self {
        Self::Checkpoint {
            schema_version: MAINTENANCE_SCHEMA_VERSION,
            state,
            pending_transition,
            terminal_action,
            gate_state: Some(gate_state),
            block_cause,
        }
    }

    pub(crate) fn recovery_commit_state(
        state: MaintenanceState,
        gate_state: MaintenanceGateState,
        block_cause: impl AsRef<str>,
    ) -> Self {
        Self::RecoveryCommit {
            schema_version: MAINTENANCE_SCHEMA_VERSION,
            state,
            gate_state,
            block_cause: bounded_error(block_cause),
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
    pub(crate) pending_transition: Option<MaintenancePendingTransition>,
    pub(crate) terminal_action: Option<MaintenanceTerminalAction>,
    pub(crate) gate_state: MaintenanceGateState,
    pub(crate) block_cause: Option<String>,
}

impl Default for MaintenanceReplay {
    fn default() -> Self {
        Self {
            state: MaintenanceState::inactive(),
            requires_bypass: false,
            pending_transition: None,
            terminal_action: None,
            gate_state: MaintenanceGateState::Enforce,
            block_cause: None,
        }
    }
}

pub(crate) fn replay_maintenance_records(
    records: &[MaintenanceWalRecord],
) -> Result<MaintenanceReplay, String> {
    if records.len() > MAX_MAINTENANCE_REPLAY_RECORDS {
        return Err(format!(
            "maintenance WAL replay exceeds {} records",
            MAX_MAINTENANCE_REPLAY_RECORDS
        ));
    }
    let mut seen = BTreeSet::new();
    let mut state = MaintenanceState::inactive();
    let mut pending: Option<MaintenancePendingTransition> = None;
    let mut terminal_action = None;
    let mut gate_state = MaintenanceGateState::Enforce;
    let mut block_cause = None;
    for record in records {
        let encoded = serde_json::to_string(record)
            .map_err(|error| format!("serialize maintenance replay key: {}", error))?;
        if !seen.insert(encoded) {
            let exact_retry = matches!(
                (record, pending),
                (MaintenanceWalRecord::ExitIntent { .. }, Some(MaintenancePendingTransition::Exit))
                    | (MaintenanceWalRecord::AbortIntent { .. }, Some(MaintenancePendingTransition::Abort))
            );
            if exact_retry {
                continue;
            }
            return Err("duplicate maintenance WAL record".to_string());
        }
        let (version, next) = record.version_and_state();
        if version != MAINTENANCE_SCHEMA_VERSION {
            return Err(format!("unsupported maintenance WAL version {}", version));
        }
        validate_state(next)?;
        match record {
            MaintenanceWalRecord::Checkpoint {
                pending_transition,
                terminal_action: checkpoint_terminal,
                gate_state: checkpoint_gate,
                block_cause: checkpoint_cause,
                ..
            } => {
                if state != MaintenanceState::inactive() || pending.is_some() {
                    return Err("maintenance checkpoint must be the first record".to_string());
                }
                state = next.clone();
                pending = *pending_transition;
                terminal_action = *checkpoint_terminal;
                gate_state = checkpoint_gate.unwrap_or(if state.is_active() {
                    MaintenanceGateState::Bypass
                } else {
                    MaintenanceGateState::Enforce
                });
                block_cause = checkpoint_cause.clone();
                if pending.is_some() && !state.is_active() {
                    return Err("maintenance checkpoint pending transition is inactive".to_string());
                }
                let terminal_state_valid = match terminal_action {
                    None => true,
                    Some(MaintenanceTerminalAction::Exit) => {
                        pending.is_none() && state.phase == MaintenancePhase::Committed
                    }
                    Some(MaintenanceTerminalAction::Abort) => {
                        pending.is_none()
                            && matches!(
                                state.phase,
                                MaintenancePhase::Committed | MaintenancePhase::MaintenanceBypass
                            )
                    }
                };
                if !terminal_state_valid {
                    return Err("maintenance checkpoint terminal identity is inconsistent".to_string());
                }
            }
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
                pending = Some(MaintenancePendingTransition::Enter);
                terminal_action = None;
                gate_state = MaintenanceGateState::Bypass;
                block_cause = None;
            }
            MaintenanceWalRecord::EnterCommit { .. } => {
                if pending != Some(MaintenancePendingTransition::Enter) {
                    return Err("maintenance enter commit without intent".to_string());
                }
                if !same_transaction_identity(&state, next)
                    || next.phase != MaintenancePhase::MaintenanceBypass
                    || next.active_domains.len() != 1
                    || next.active_domains[0] != "acl"
                {
                    return Err("maintenance enter commit identity changed".to_string());
                }
                state = next.clone();
                state.phase = MaintenancePhase::MaintenanceBypass;
                pending = None;
                gate_state = MaintenanceGateState::Bypass;
            }
            MaintenanceWalRecord::ExitIntent { .. } => {
                if !state.is_active() || pending.is_some() {
                    return Err("maintenance exit intent without active operation".to_string());
                }
                if !same_transaction_identity(&state, next)
                    || next.phase != MaintenancePhase::Verifying
                {
                    return Err("maintenance exit intent identity changed".to_string());
                }
                state = next.clone();
                state.phase = MaintenancePhase::MaintenanceBypass;
                state.last_error = Some("recovered_dangling_exit_intent".to_string());
                pending = Some(MaintenancePendingTransition::Exit);
            }
            MaintenanceWalRecord::ExitCommit { .. } => {
                if pending != Some(MaintenancePendingTransition::Exit) {
                    return Err("maintenance exit commit without intent".to_string());
                }
                if !same_terminal_transaction_identity(&state, next)
                    || next.phase != MaintenancePhase::Committed
                    || !next.active_domains.is_empty()
                {
                    return Err("maintenance exit commit identity changed".to_string());
                }
                state = next.clone();
                pending = None;
                terminal_action = Some(MaintenanceTerminalAction::Exit);
                gate_state = MaintenanceGateState::Enforce;
                block_cause = None;
            }
            MaintenanceWalRecord::AbortIntent { .. } => {
                if !state.is_active() || pending.is_some() {
                    return Err("maintenance abort intent without active operation".to_string());
                }
                if !same_transaction_identity(&state, next)
                    || !matches!(
                        next.phase,
                        MaintenancePhase::Verifying | MaintenancePhase::MaintenanceBypass
                    )
                {
                    return Err("maintenance abort intent identity changed".to_string());
                }
                state = next.clone();
                state.phase = MaintenancePhase::MaintenanceBypass;
                pending = Some(MaintenancePendingTransition::Abort);
            }
            MaintenanceWalRecord::AbortCommit { .. } => {
                if pending != Some(MaintenancePendingTransition::Abort)
                    || !(if next.phase == MaintenancePhase::Committed {
                        same_terminal_transaction_identity(&state, next)
                    } else {
                        same_transaction_identity(&state, next)
                    })
                {
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
                    terminal_action = Some(MaintenanceTerminalAction::Abort);
                    gate_state = MaintenanceGateState::Bypass;
                } else {
                    terminal_action = Some(MaintenanceTerminalAction::Abort);
                    gate_state = MaintenanceGateState::Enforce;
                }
                pending = None;
            }
            MaintenanceWalRecord::ProgressCommit { .. } => {
                if !state.is_active() || pending.is_some() {
                    return Err("maintenance progress commit without active operation".to_string());
                }
                if !same_operation_identity(&state, next)
                    || next.applied_generation < state.applied_generation
                {
                    return Err("maintenance progress operation identity changed".to_string());
                }
                state = next.clone();
                state.phase = MaintenancePhase::MaintenanceBypass;
            }
            MaintenanceWalRecord::RecoveryCommit {
                gate_state: next_gate,
                block_cause: next_cause,
                ..
            } => {
                if !state.is_active() || !same_transaction_identity(&state, next) {
                    return Err("maintenance recovery identity changed".to_string());
                }
                bounded_text(next_cause, "block_cause", MAX_ERROR_BYTES)
                    .map_err(|error| error.details)?;
                if *next_gate == MaintenanceGateState::Unknown
                    && next.phase != MaintenancePhase::GateUnknown
                {
                    return Err("gate-unknown recovery must use gate_unknown phase".to_string());
                }
                state = next.clone();
                gate_state = *next_gate;
                block_cause = (*next_gate == MaintenanceGateState::Unknown)
                    .then(|| next_cause.clone());
            }
        }
    }
    Ok(MaintenanceReplay {
        requires_bypass: state.is_active(),
        state,
        pending_transition: pending,
        terminal_action,
        gate_state,
        block_cause,
    })
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}

#[derive(Clone, Debug)]
pub(crate) struct MaintenanceStoreReplay {
    pub(crate) state: MaintenanceState,
    pub(crate) failures: u64,
    pub(crate) pending_transition: Option<MaintenancePendingTransition>,
    pub(crate) terminal_action: Option<MaintenanceTerminalAction>,
    pub(crate) gate_state: MaintenanceGateState,
    pub(crate) block_cause: Option<String>,
}

pub(crate) trait MaintenanceStore: Send + Sync {
    fn load(&self) -> MaintenanceStoreReplay;
    fn append(&self, record: MaintenanceWalRecord) -> Result<(), String>;
}

struct WalMaintenanceStore {
    wal: Arc<NeutronWal>,
}

impl MaintenanceStore for WalMaintenanceStore {
    fn load(&self) -> MaintenanceStoreReplay {
        let replay = self.wal.replay();
        MaintenanceStoreReplay {
            state: replay.maintenance.state,
            failures: replay.maintenance_failures,
            pending_transition: replay.maintenance.pending_transition,
            terminal_action: replay.maintenance.terminal_action,
            gate_state: replay.maintenance.gate_state,
            block_cause: replay.maintenance.block_cause,
        }
    }

    fn append(&self, record: MaintenanceWalRecord) -> Result<(), String> {
        self.wal.append_maintenance_record(record)
    }
}

#[derive(Debug)]
pub(crate) struct MaintenanceWriterLease {
    _guard: OwnedRwLockReadGuard<()>,
}

pub(crate) struct MaintenanceTransactionLease {
    _guard: OwnedRwLockWriteGuard<()>,
}

#[derive(Clone, Debug)]
pub(crate) struct MaintenanceCoordinatorSnapshot {
    pub(crate) state: MaintenanceState,
    pub(crate) gate_state: MaintenanceGateState,
    pub(crate) block_cause: Option<String>,
    pub(crate) fenced: bool,
    pub(crate) blocked: bool,
}

#[derive(Clone)]
pub(crate) struct MaintenanceCoordinator {
    store: Arc<dyn MaintenanceStore>,
    gate: Arc<dyn MaintenanceGateRuntime>,
    audit: Arc<dyn MaintenanceAuditSink>,
    state: Arc<RwLock<MaintenanceState>>,
    pending_transition: Arc<RwLock<Option<MaintenancePendingTransition>>>,
    terminal_action: Arc<RwLock<Option<MaintenanceTerminalAction>>>,
    gate_state: Arc<RwLock<MaintenanceGateState>>,
    block_cause: Arc<RwLock<Option<String>>>,
    replay_failures: u64,
    blocked: Arc<AtomicBool>,
    transaction_lock: Arc<RwLock<()>>,
}

impl MaintenanceCoordinator {
    pub(crate) fn new(wal: Arc<NeutronWal>, control_plane: Arc<ControlPlane>) -> Self {
        Self::new_with_dependencies(
            Arc::new(WalMaintenanceStore { wal }),
            Arc::new(ControlPlaneMaintenanceGate { control_plane }),
            Arc::new(TracingMaintenanceAudit),
        )
    }

    pub(crate) fn new_with_dependencies(
        store: Arc<dyn MaintenanceStore>,
        gate: Arc<dyn MaintenanceGateRuntime>,
        audit: Arc<dyn MaintenanceAuditSink>,
    ) -> Self {
        let replay = store.load();
        let initially_blocked = replay.failures != 0
            || replay.gate_state == MaintenanceGateState::Unknown;
        Self {
            store,
            gate,
            audit,
            state: Arc::new(RwLock::new(replay.state)),
            pending_transition: Arc::new(RwLock::new(replay.pending_transition)),
            terminal_action: Arc::new(RwLock::new(replay.terminal_action)),
            gate_state: Arc::new(RwLock::new(replay.gate_state)),
            block_cause: Arc::new(RwLock::new(replay.block_cause)),
            replay_failures: replay.failures,
            blocked: Arc::new(AtomicBool::new(initially_blocked)),
            transaction_lock: Arc::new(RwLock::new(())),
        }
    }

    fn emit_audit(
        &self,
        action: MaintenanceAuditAction,
        outcome: MaintenanceAuditOutcome,
        operation_id: Option<&str>,
        phase: MaintenancePhase,
        reason: Option<&str>,
    ) {
        self.audit.emit(MaintenanceAuditEvent {
            action,
            outcome,
            operation_id: operation_id.map(|value| bounded_error(value)),
            phase,
            reason: reason.map(|value| {
                let end = value.len().min(MAX_REASON_BYTES);
                let mut boundary = end;
                while !value.is_char_boundary(boundary) {
                    boundary -= 1;
                }
                value[..boundary].to_string()
            }),
            authorization: "root_only_uds",
        });
    }

    #[cfg(test)]
    pub(crate) async fn status(&self) -> MaintenanceState {
        self.state.read().await.clone()
    }

    pub(crate) async fn snapshot(&self) -> MaintenanceCoordinatorSnapshot {
        let _guard = self.transaction_lock.clone().read_owned().await;
        let state = self.state.read().await.clone();
        MaintenanceCoordinatorSnapshot {
            fenced: state.is_active() || self.blocked.load(Ordering::Acquire),
            state,
            gate_state: *self.gate_state.read().await,
            block_cause: self.block_cause.read().await.clone(),
            blocked: self.blocked.load(Ordering::Acquire),
        }
    }

    #[cfg(test)]
    pub(crate) async fn audited_status(&self) -> MaintenanceState {
        let snapshot = self.audited_snapshot().await;
        snapshot.state
    }

    pub(crate) async fn audited_snapshot(&self) -> MaintenanceCoordinatorSnapshot {
        let snapshot = self.snapshot().await;
        self.emit_audit(
            MaintenanceAuditAction::Get,
            MaintenanceAuditOutcome::Attempt,
            snapshot.state.operation_id.as_deref(),
            snapshot.state.phase.clone(),
            snapshot.state.last_error.as_deref(),
        );
        self.emit_audit(
            MaintenanceAuditAction::Get,
            MaintenanceAuditOutcome::Success,
            snapshot.state.operation_id.as_deref(),
            snapshot.state.phase.clone(),
            snapshot.state.last_error.as_deref(),
        );
        snapshot
    }

    pub(crate) async fn audit_failure(
        &self,
        action: MaintenanceAuditAction,
        operation_id: Option<&str>,
        reason: Option<&str>,
    ) {
        let phase = self.state.read().await.phase.clone();
        self.emit_audit(
            action,
            MaintenanceAuditOutcome::Failure,
            operation_id,
            phase,
            reason,
        );
    }

    pub(crate) async fn is_active(&self) -> bool {
        self.blocked.load(Ordering::Acquire) || self.state.read().await.is_active()
    }

    pub(crate) fn is_blocked(&self) -> bool {
        self.blocked.load(Ordering::Acquire)
    }

    pub(crate) async fn recover_before_reconciliation(&self) -> Result<(), String> {
        let _transaction = self.transaction_lock.clone().write_owned().await;
        let replay = self.store.load();
        let mut recovered = replay.state;
        if recovered.is_active() || replay.pending_transition.is_some() || replay.failures != 0 {
            recovered.phase = MaintenancePhase::MaintenanceBypass;
            *self.state.write().await = recovered.clone();
            *self.pending_transition.write().await = replay.pending_transition;
            *self.terminal_action.write().await = replay.terminal_action;
            self.blocked.store(true, Ordering::Release);
            *self.gate_state.write().await = if replay.failures != 0 {
                MaintenanceGateState::Unknown
            } else {
                replay.gate_state
            };
            *self.block_cause.write().await = replay.block_cause.clone();
            if let Err(error) = self.gate.set_bypass_verified(true).await {
                recovered.last_progress_at_ms = now_ms();
                recovered.last_error = Some(bounded_error(format!(
                    "maintenance_startup_gate_failed:{}",
                    error
                )));
                *self.state.write().await = recovered;
                *self.gate_state.write().await = MaintenanceGateState::Unknown;
                *self.block_cause.write().await =
                    Some("maintenance_authority_unavailable".to_string());
                return Err(format!("force maintenance bypass before reconciliation: {}", error));
            }
            *self.gate_state.write().await = MaintenanceGateState::Bypass;
        }
        if replay.failures != 0 {
            recovered.last_error = Some(bounded_error(format!(
                "maintenance_wal_replay_failures:{}",
                replay.failures
            )));
            *self.state.write().await = recovered;
            self.blocked.store(true, Ordering::Release);
            return Err(format!(
                "maintenance WAL replay reported {} failure(s)",
                replay.failures
            ));
        }
        if replay.pending_transition == Some(MaintenancePendingTransition::Enter) {
            recovered.phase = MaintenancePhase::MaintenanceBypass;
            recovered.last_progress_at_ms = now_ms();
            recovered.last_error = None;
            if let Err(error) = self
                .store
                .append(MaintenanceWalRecord::enter_commit_state(recovered.clone()))
            {
                recovered.last_error = Some(bounded_error(format!(
                    "maintenance_startup_commit_failed:{}",
                    error
                )));
                *self.state.write().await = recovered;
                self.blocked.store(true, Ordering::Release);
                return Err(format!("commit recovered maintenance enter: {}", error));
            }
            *self.pending_transition.write().await = None;
        }
        *self.state.write().await = recovered;
        self.blocked.store(false, Ordering::Release);
        *self.block_cause.write().await = None;
        Ok(())
    }

    pub(crate) async fn acquire_writer(
        &self,
        writer: MaintenanceWriter,
        operation_id: Option<&str>,
    ) -> Result<MaintenanceWriterLease, MaintenanceError> {
        let guard = self.transaction_lock.clone().read_owned().await;
        if self.blocked.load(Ordering::Acquire) {
            return Err(MaintenanceError::conflict(
                "maintenance_recovery_blocked",
                "maintenance WAL or gate recovery is unresolved",
            ));
        }
        if matches!(
            *self.pending_transition.read().await,
            Some(MaintenancePendingTransition::Exit | MaintenancePendingTransition::Abort)
        ) {
            return Err(MaintenanceError::conflict(
                "maintenance_terminal_transition_pending",
                "exit or abort transition fences all writers",
            ));
        }
        let state = self.state.read().await;
        admit_maintenance_writer(&*state, writer, operation_id)?;
        Ok(MaintenanceWriterLease { _guard: guard })
    }

    pub(crate) async fn admit_writer(
        &self,
        writer: MaintenanceWriter,
        operation_id: Option<&str>,
    ) -> Result<(), MaintenanceError> {
        self.acquire_writer(writer, operation_id).await.map(drop)
    }

    pub(crate) async fn begin_transaction(&self) -> MaintenanceTransactionLease {
        MaintenanceTransactionLease {
            _guard: self.transaction_lock.clone().write_owned().await,
        }
    }

    #[cfg(test)]
    pub(crate) async fn enter(
        &self,
        request: MaintenanceEnterRequest,
        convergence: MaintenanceConvergence,
    ) -> Result<(MaintenanceDisposition, MaintenanceState), MaintenanceError> {
        let transaction = self.begin_transaction().await;
        self.enter_with_transaction(transaction, request, convergence)
            .await
    }

    pub(crate) async fn enter_with_transaction(
        &self,
        _transaction: MaintenanceTransactionLease,
        request: MaintenanceEnterRequest,
        convergence: MaintenanceConvergence,
    ) -> Result<(MaintenanceDisposition, MaintenanceState), MaintenanceError> {
        let current = self.state.read().await.clone();
        self.emit_audit(
            MaintenanceAuditAction::Enter,
            MaintenanceAuditOutcome::Attempt,
            Some(&request.operation_id),
            current.phase.clone(),
            Some(&request.reason),
        );
        if matches!(
            *self.pending_transition.read().await,
            Some(MaintenancePendingTransition::Exit | MaintenancePendingTransition::Abort)
        ) {
            return Err(MaintenanceError::conflict(
                "maintenance_pending_transition_conflict",
                "resume the pending transition with its matching endpoint",
            ));
        }
        if self.blocked.load(Ordering::Acquire) {
            let same_identity = current.operation_id.as_deref() == Some(&request.operation_id)
                && current.active_domains == request.domains
                && current.expected_generation == request.expected_applied_generation
                && current.expected_desired_hash == request.expected_desired_hash;
            if !same_identity {
                return Err(MaintenanceError::conflict(
                    "maintenance_recovery_blocked",
                    "maintenance recovery must be resolved before enter",
                ));
            }
            if self.replay_failures != 0 {
                return Err(MaintenanceError::conflict(
                    "maintenance_operator_recovery_required",
                    "corrupt maintenance WAL requires operator recovery",
                ));
            }
            let pending = *self.pending_transition.read().await;
            if matches!(
                pending,
                Some(MaintenancePendingTransition::Exit | MaintenancePendingTransition::Abort)
            ) {
                return Err(MaintenanceError::conflict(
                    "maintenance_pending_transition_conflict",
                    "resume the pending transition with its matching endpoint",
                ));
            }
            if let Err(error) = self.gate.set_bypass_verified(true).await {
                let mut failed = current;
                failed.last_error = Some(bounded_error(&error));
                *self.state.write().await = failed;
                return Err(MaintenanceError::conflict(
                    "maintenance_authority_unavailable",
                    error,
                ));
            }
            let mut repaired = current;
            repaired.phase = MaintenancePhase::MaintenanceBypass;
            repaired.last_progress_at_ms = now_ms();
            repaired.last_error = None;
            let repair_record = if pending == Some(MaintenancePendingTransition::Enter) {
                MaintenanceWalRecord::enter_commit_state(repaired.clone())
            } else {
                MaintenanceWalRecord::recovery_commit_state(
                    repaired.clone(),
                    MaintenanceGateState::Bypass,
                    "maintenance_gate_reverified",
                )
            };
            self.store
                .append(repair_record)
                .map_err(|error| {
                    MaintenanceError::internal("maintenance_wal_commit_failed", error)
                })?;
            *self.state.write().await = repaired.clone();
            *self.pending_transition.write().await = None;
            self.blocked.store(false, Ordering::Release);
            *self.gate_state.write().await = MaintenanceGateState::Bypass;
            *self.block_cause.write().await = None;
            self.emit_audit(
                MaintenanceAuditAction::Enter,
                MaintenanceAuditOutcome::Success,
                repaired.operation_id.as_deref(),
                repaired.phase.clone(),
                Some(&request.reason),
            );
            return Ok((MaintenanceDisposition::Mutate, repaired));
        }
        let mut machine = MaintenanceStateMachine::with_state(current);
        let plan = machine.plan_enter(&request, &convergence, now_ms())?;
        if plan.disposition == MaintenanceDisposition::Idempotent {
            self.emit_audit(
                MaintenanceAuditAction::Enter,
                MaintenanceAuditOutcome::Success,
                machine.state().operation_id.as_deref(),
                machine.state().phase.clone(),
                Some(&request.reason),
            );
            return Ok((plan.disposition, machine.state().clone()));
        }
        let preparing = plan
            .next_state
            .expect("mutating maintenance enter plan carries state");

        self.gate.verify_authority().await.map_err(|error| {
            MaintenanceError::conflict("maintenance_authority_unavailable", error)
        })?;

        self.store
            .append(MaintenanceWalRecord::enter_intent_state(preparing.clone()))
            .map_err(|error| MaintenanceError::internal("maintenance_wal_intent_failed", error))?;
        *self.pending_transition.write().await = Some(MaintenancePendingTransition::Enter);
        *self.terminal_action.write().await = None;
        *self.state.write().await = preparing.clone();

        if let Err(error) = self.gate.set_bypass_verified(true).await {
            machine.record_enter_failure(
                preparing,
                format!("gate_readback_failed:{}", error),
                now_ms(),
            );
            *self.state.write().await = machine.state().clone();
            self.blocked.store(true, Ordering::Release);
            *self.gate_state.write().await = MaintenanceGateState::Unknown;
            *self.block_cause.write().await = Some("maintenance_gate_unknown".to_string());
            self.emit_audit(
                MaintenanceAuditAction::Enter,
                MaintenanceAuditOutcome::Failure,
                Some(&request.operation_id),
                machine.state().phase.clone(),
                Some(&error),
            );
            return Err(MaintenanceError::internal(
                "maintenance_gate_enable_failed",
                error,
            ));
        }

        machine.commit_enter(preparing);
        let mut active = machine.state().clone();
        active.last_progress_at_ms = now_ms();
        if let Err(error) = self
            .store
            .append(MaintenanceWalRecord::enter_commit_state(active.clone()))
        {
            active.last_error = Some(bounded_error(format!("wal_commit_failed:{}", error)));
            *self.state.write().await = active;
            self.blocked.store(true, Ordering::Release);
            return Err(MaintenanceError::internal(
                "maintenance_wal_commit_failed",
                error,
            ));
        }
        *self.state.write().await = active.clone();
        *self.pending_transition.write().await = None;
        *self.gate_state.write().await = MaintenanceGateState::Bypass;
        self.emit_audit(
            MaintenanceAuditAction::Enter,
            MaintenanceAuditOutcome::Success,
            active.operation_id.as_deref(),
            active.phase.clone(),
            Some(&request.reason),
        );
        Ok((MaintenanceDisposition::Mutate, active))
    }

    pub(crate) async fn prepare_applied_snapshot(
        &self,
        operation_id: Option<&str>,
        generation: u64,
        desired_hash: Option<String>,
    ) -> Result<Option<MaintenanceState>, String> {
        let mut state = self.state.read().await.clone();
        if !state.is_active() {
            return Ok(None);
        }
        if state.operation_id.as_deref() != operation_id {
            return Err("maintenance snapshot completion operation identity changed".to_string());
        }
        state.applied_generation = generation;
        state.applied_desired_hash = desired_hash;
        state.last_progress_at_ms = now_ms();
        state.last_error = None;
        Ok(Some(state))
    }

    pub(crate) async fn install_applied_snapshot(&self, state: MaintenanceState) {
        *self.state.write().await = state;
    }

    async fn repair_unknown_gate_for(
        &self,
        expected: MaintenancePendingTransition,
    ) -> Result<(), MaintenanceError> {
        if !self.blocked.load(Ordering::Acquire) {
            return Ok(());
        }
        if self.replay_failures != 0
            || *self.pending_transition.read().await != Some(expected)
            || *self.gate_state.read().await != MaintenanceGateState::Unknown
        {
            return Err(MaintenanceError::conflict(
                "maintenance_recovery_blocked",
                "resume requires the exact pending terminal transition and proven gate state",
            ));
        }
        self.gate.set_bypass_verified(true).await.map_err(|error| {
            MaintenanceError::conflict("maintenance_authority_unavailable", error)
        })?;
        let mut state = self.state.read().await.clone();
        state.phase = MaintenancePhase::MaintenanceBypass;
        state.last_progress_at_ms = now_ms();
        state.last_error = Some("maintenance_terminal_retry_required".to_string());
        self.store
            .append(MaintenanceWalRecord::recovery_commit_state(
                state.clone(),
                MaintenanceGateState::Bypass,
                "maintenance_terminal_retry_required",
            ))
            .map_err(|error| MaintenanceError::internal("maintenance_wal_commit_failed", error))?;
        *self.state.write().await = state;
        *self.gate_state.write().await = MaintenanceGateState::Bypass;
        *self.block_cause.write().await = None;
        self.blocked.store(false, Ordering::Release);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) async fn exit(
        &self,
        request: MaintenanceExitRequest,
        convergence: MaintenanceConvergence,
    ) -> Result<(MaintenanceDisposition, MaintenanceState), MaintenanceError> {
        let transaction = self.begin_transaction().await;
        self.exit_with_transaction(transaction, request, convergence)
            .await
    }

    pub(crate) async fn exit_with_transaction(
        &self,
        _transaction: MaintenanceTransactionLease,
        request: MaintenanceExitRequest,
        convergence: MaintenanceConvergence,
    ) -> Result<(MaintenanceDisposition, MaintenanceState), MaintenanceError> {
        let attempted = self.state.read().await.clone();
        self.emit_audit(
            MaintenanceAuditAction::Exit,
            MaintenanceAuditOutcome::Attempt,
            Some(&request.operation_id),
            attempted.phase,
            None,
        );
        self.repair_unknown_gate_for(MaintenancePendingTransition::Exit)
            .await?;
        let current = self.state.read().await.clone();
        let mut machine = MaintenanceStateMachine::with_state(current.clone());
        let plan = machine.plan_exit(&request, &convergence, now_ms())?;
        if plan.disposition == MaintenanceDisposition::Idempotent {
            self.emit_audit(
                MaintenanceAuditAction::Exit,
                MaintenanceAuditOutcome::Success,
                current.operation_id.as_deref(),
                current.phase.clone(),
                None,
            );
            return Ok((plan.disposition, current));
        }
        let verifying = plan
            .next_state
            .expect("mutating maintenance exit plan carries state");
        if *self.pending_transition.read().await != Some(MaintenancePendingTransition::Exit) {
            self.store
                .append(MaintenanceWalRecord::exit_intent_state(verifying.clone()))
                .map_err(|error| {
                    MaintenanceError::internal("maintenance_wal_intent_failed", error)
                })?;
            *self.pending_transition.write().await = Some(MaintenancePendingTransition::Exit);
        }
        *self.state.write().await = verifying.clone();
        if let Err(error) = self.gate.set_bypass_verified(false).await {
            let restore = self.gate.set_bypass_verified(true).await;
            let mut failed = current;
            failed.phase = MaintenancePhase::MaintenanceBypass;
            failed.last_progress_at_ms = now_ms();
            failed.last_error = Some(bounded_error(format!(
                "exit_gate_failed:{};bypass_restore:{:?}", error, restore
            )));
            *self.state.write().await = failed.clone();
            if restore.is_err() {
                self.blocked.store(true, Ordering::Release);
                failed.phase = MaintenancePhase::GateUnknown;
                failed.last_error = Some("maintenance_gate_unknown".to_string());
                *self.state.write().await = failed.clone();
                *self.gate_state.write().await = MaintenanceGateState::Unknown;
                *self.block_cause.write().await = Some("maintenance_gate_unknown".to_string());
                let _ = self.store.append(MaintenanceWalRecord::recovery_commit_state(
                    failed,
                    MaintenanceGateState::Unknown,
                    "maintenance_gate_unknown",
                ));
            } else {
                *self.gate_state.write().await = MaintenanceGateState::Bypass;
            }
            return Err(MaintenanceError::internal(
                "maintenance_gate_disable_failed",
                error,
            ));
        }

        machine.commit_exit(verifying);
        let mut committed = machine.state().clone();
        committed.last_progress_at_ms = now_ms();
        if let Err(error) = self
            .store
            .append(MaintenanceWalRecord::exit_commit_state(committed.clone()))
        {
            let restore = self.gate.set_bypass_verified(true).await;
            let mut failed = current;
            failed.phase = MaintenancePhase::MaintenanceBypass;
            failed.last_progress_at_ms = now_ms();
            failed.last_error = Some(bounded_error(format!(
                "exit_commit_failed:{};bypass_restore:{:?}",
                error, restore
            )));
            *self.state.write().await = failed.clone();
            if restore.is_err() {
                self.blocked.store(true, Ordering::Release);
                failed.phase = MaintenancePhase::GateUnknown;
                failed.last_error = Some("maintenance_gate_unknown".to_string());
                *self.state.write().await = failed.clone();
                *self.gate_state.write().await = MaintenanceGateState::Unknown;
                *self.block_cause.write().await = Some("maintenance_gate_unknown".to_string());
                let _ = self.store.append(MaintenanceWalRecord::recovery_commit_state(
                    failed,
                    MaintenanceGateState::Unknown,
                    "maintenance_gate_unknown",
                ));
            } else {
                *self.gate_state.write().await = MaintenanceGateState::Bypass;
            }
            return Err(MaintenanceError::internal(
                "maintenance_wal_commit_failed",
                error,
            ));
        }
        *self.state.write().await = committed.clone();
        *self.pending_transition.write().await = None;
        *self.terminal_action.write().await = Some(MaintenanceTerminalAction::Exit);
        *self.gate_state.write().await = MaintenanceGateState::Enforce;
        self.emit_audit(
            MaintenanceAuditAction::Exit,
            MaintenanceAuditOutcome::Success,
            committed.operation_id.as_deref(),
            committed.phase.clone(),
            None,
        );
        Ok((MaintenanceDisposition::Mutate, committed))
    }

    #[cfg(test)]
    pub(crate) async fn abort(
        &self,
        request: MaintenanceAbortRequest,
        convergence: MaintenanceConvergence,
    ) -> Result<(MaintenanceDisposition, MaintenanceState), MaintenanceError> {
        let transaction = self.begin_transaction().await;
        self.abort_with_transaction(transaction, request, convergence)
            .await
    }

    pub(crate) async fn abort_with_transaction(
        &self,
        _transaction: MaintenanceTransactionLease,
        request: MaintenanceAbortRequest,
        convergence: MaintenanceConvergence,
    ) -> Result<(MaintenanceDisposition, MaintenanceState), MaintenanceError> {
        let attempted = self.state.read().await.clone();
        self.emit_audit(
            MaintenanceAuditAction::Abort,
            MaintenanceAuditOutcome::Attempt,
            Some(&request.operation_id),
            attempted.phase,
            request.error.as_deref(),
        );
        self.repair_unknown_gate_for(MaintenancePendingTransition::Abort)
            .await?;
        let current = self.state.read().await.clone();
        let terminal_action = *self.terminal_action.read().await;
        let exact_terminal_phase = current.phase == request.expected_phase
            || (current.phase == MaintenancePhase::Committed
                && request.expected_phase == MaintenancePhase::MaintenanceBypass);
        if current.operation_id.as_deref() == Some(&request.operation_id)
            && exact_terminal_phase
            && terminal_action == Some(MaintenanceTerminalAction::Abort)
        {
            self.emit_audit(
                MaintenanceAuditAction::Abort,
                MaintenanceAuditOutcome::Success,
                current.operation_id.as_deref(),
                current.phase.clone(),
                request.error.as_deref(),
            );
            return Ok((MaintenanceDisposition::Idempotent, current));
        }
        let mut machine = MaintenanceStateMachine::with_state(current.clone());
        let plan = machine.plan_abort(&request, &convergence, now_ms())?;
        let mut next = plan
            .next_state
            .expect("mutating maintenance abort plan carries state");
        if *self.pending_transition.read().await != Some(MaintenancePendingTransition::Abort) {
            self.store
                .append(MaintenanceWalRecord::abort_intent_state(next.clone()))
                .map_err(|error| {
                    MaintenanceError::internal("maintenance_wal_intent_failed", error)
                })?;
            *self.pending_transition.write().await = Some(MaintenancePendingTransition::Abort);
        }
        *self.state.write().await = next.clone();

        if next.phase == MaintenancePhase::Verifying {
            if let Err(error) = self.gate.set_bypass_verified(false).await {
                let restore = self.gate.set_bypass_verified(true).await;
                next = current;
                next.phase = MaintenancePhase::MaintenanceBypass;
                next.last_error = Some(bounded_error(format!(
                    "abort_gate_failed:{};bypass_restore:{:?}", error, restore
                )));
                *self.state.write().await = next.clone();
                if restore.is_err() {
                    self.blocked.store(true, Ordering::Release);
                    next.phase = MaintenancePhase::GateUnknown;
                    next.last_error = Some("maintenance_gate_unknown".to_string());
                    *self.state.write().await = next.clone();
                    *self.gate_state.write().await = MaintenanceGateState::Unknown;
                    *self.block_cause.write().await = Some("maintenance_gate_unknown".to_string());
                    let _ = self.store.append(MaintenanceWalRecord::recovery_commit_state(
                        next,
                        MaintenanceGateState::Unknown,
                        "maintenance_gate_unknown",
                    ));
                } else {
                    *self.gate_state.write().await = MaintenanceGateState::Bypass;
                }
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
            .store
            .append(MaintenanceWalRecord::abort_commit_state(next.clone()))
        {
            let restore = if next.phase == MaintenancePhase::Committed {
                self.gate.set_bypass_verified(true).await
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
            *self.state.write().await = failed.clone();
            if restore.is_err() {
                self.blocked.store(true, Ordering::Release);
                failed.phase = MaintenancePhase::GateUnknown;
                failed.last_error = Some("maintenance_gate_unknown".to_string());
                *self.state.write().await = failed.clone();
                *self.gate_state.write().await = MaintenanceGateState::Unknown;
                *self.block_cause.write().await = Some("maintenance_gate_unknown".to_string());
                let _ = self.store.append(MaintenanceWalRecord::recovery_commit_state(
                    failed,
                    MaintenanceGateState::Unknown,
                    "maintenance_gate_unknown",
                ));
            } else {
                *self.gate_state.write().await = MaintenanceGateState::Bypass;
            }
            return Err(MaintenanceError::internal(
                "maintenance_wal_commit_failed",
                error,
            ));
        }
        machine.commit_abort(next.clone());
        *self.state.write().await = machine.state().clone();
        *self.pending_transition.write().await = None;
        *self.terminal_action.write().await = Some(MaintenanceTerminalAction::Abort);
        *self.gate_state.write().await = if next.phase == MaintenancePhase::Committed {
            MaintenanceGateState::Enforce
        } else {
            MaintenanceGateState::Bypass
        };
        self.emit_audit(
            MaintenanceAuditAction::Abort,
            MaintenanceAuditOutcome::Success,
            next.operation_id.as_deref(),
            next.phase.clone(),
            request.error.as_deref(),
        );
        Ok((MaintenanceDisposition::Mutate, next))
    }
}

#[cfg(test)]
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

#[cfg(test)]
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
    use std::collections::VecDeque;
    use std::sync::Mutex as StdMutex;

    #[derive(Clone)]
    struct FaultStore {
        records: Arc<StdMutex<Vec<MaintenanceWalRecord>>>,
        append_results: Arc<StdMutex<VecDeque<Result<(), String>>>>,
        replay_override: Arc<StdMutex<Option<MaintenanceStoreReplay>>>,
    }

    impl FaultStore {
        fn new(records: Vec<MaintenanceWalRecord>) -> Self {
            Self {
                records: Arc::new(StdMutex::new(records)),
                append_results: Arc::new(StdMutex::new(VecDeque::new())),
                replay_override: Arc::new(StdMutex::new(None)),
            }
        }

        fn with_replay(replay: MaintenanceStoreReplay) -> Self {
            let store = Self::new(Vec::new());
            *store.replay_override.lock().unwrap() = Some(replay);
            store
        }

        fn push_append_result(&self, result: Result<(), &str>) {
            self.append_results
                .lock()
                .unwrap()
                .push_back(result.map_err(str::to_string));
        }

        fn records(&self) -> Vec<MaintenanceWalRecord> {
            self.records.lock().unwrap().clone()
        }
    }

    impl MaintenanceStore for FaultStore {
        fn load(&self) -> MaintenanceStoreReplay {
            if let Some(replay) = self.replay_override.lock().unwrap().clone() {
                return replay;
            }
            match replay_maintenance_records(&self.records()) {
                Ok(replay) => MaintenanceStoreReplay {
                    state: replay.state,
                    failures: 0,
                    pending_transition: replay.pending_transition,
                    terminal_action: replay.terminal_action,
                    gate_state: replay.gate_state,
                    block_cause: replay.block_cause,
                },
                Err(_) => MaintenanceStoreReplay {
                    state: MaintenanceState::inactive(),
                    failures: 1,
                    pending_transition: None,
                    terminal_action: None,
                    gate_state: MaintenanceGateState::Unknown,
                    block_cause: Some("maintenance_wal_corrupt".to_string()),
                },
            }
        }

        fn append(&self, record: MaintenanceWalRecord) -> Result<(), String> {
            if let Some(result) = self.append_results.lock().unwrap().pop_front() {
                result?;
            }
            self.records.lock().unwrap().push(record);
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct FaultGate {
        results: Arc<StdMutex<VecDeque<Result<(), String>>>>,
        calls: Arc<StdMutex<Vec<bool>>>,
    }

    impl FaultGate {
        fn push_result(&self, result: Result<(), &str>) {
            self.results
                .lock()
                .unwrap()
                .push_back(result.map_err(str::to_string));
        }

        fn calls(&self) -> Vec<bool> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl MaintenanceGateRuntime for FaultGate {
        fn set_bypass_verified(&self, enabled: bool) -> MaintenanceIoFuture<'_> {
            Box::pin(async move {
                self.calls.lock().unwrap().push(enabled);
                self.results
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or(Ok(()))
            })
        }
    }

    #[derive(Clone, Default)]
    struct CapturingAudit {
        events: Arc<StdMutex<Vec<MaintenanceAuditEvent>>>,
    }

    impl MaintenanceAuditSink for CapturingAudit {
        fn emit(&self, event: MaintenanceAuditEvent) {
            self.events.lock().unwrap().push(event);
        }
    }

    fn active_records(operation_id: &str) -> Vec<MaintenanceWalRecord> {
        let active = active_state(operation_id, 41, "sha256:host-41");
        let mut preparing = active.clone();
        preparing.phase = MaintenancePhase::BypassPreparing;
        vec![
            MaintenanceWalRecord::enter_intent_state(preparing),
            MaintenanceWalRecord::enter_commit_state(active),
        ]
    }

    fn coordinator_with_faults(
        store: FaultStore,
        gate: FaultGate,
        audit: CapturingAudit,
    ) -> Arc<MaintenanceCoordinator> {
        Arc::new(MaintenanceCoordinator::new_with_dependencies(
            Arc::new(store),
            Arc::new(gate),
            Arc::new(audit),
        ))
    }

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
            accepted_generation: 41,
            accepted_desired_hash: Some("sha256:host-41".to_string()),
            applied_generation: 41,
            applied_desired_hash: Some("sha256:host-41".to_string()),
            pending_generation: None,
            managed_ports: BTreeSet::from(["port-a".to_string(), "port-b".to_string()]),
            ready_enforce_ports: BTreeSet::from([
                "port-a".to_string(),
                "port-b".to_string(),
            ]),
            wal_healthy: true,
            recovery_healthy: true,
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
        incomplete.ready_enforce_ports.remove("port-b");
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

    #[tokio::test]
    async fn neutron_maintenance_recovery_failure_blocks_restore_and_same_id_repairs_after_proof() {
        let mut preparing = active_state("op-repair", 41, "sha256:host-41");
        preparing.phase = MaintenancePhase::BypassPreparing;
        let store = FaultStore::new(vec![MaintenanceWalRecord::enter_intent_state(preparing)]);
        let gate = FaultGate::default();
        gate.push_result(Err("authority_identity_drift"));
        gate.push_result(Ok(()));
        let coordinator = coordinator_with_faults(
            store.clone(),
            gate.clone(),
            CapturingAudit::default(),
        );

        assert!(coordinator.recover_before_reconciliation().await.is_err());
        let failed = coordinator.status().await;
        assert!(failed.is_active());
        assert!(coordinator.is_blocked());
        assert!(failed
            .last_error
            .as_deref()
            .unwrap()
            .contains("authority_identity_drift"));
        assert!(coordinator
            .acquire_writer(MaintenanceWriter::Background, None)
            .await
            .is_err());

        let (disposition, repaired) = coordinator
            .enter(enter_request("op-repair"), convergence())
            .await
            .unwrap();
        assert_eq!(disposition, MaintenanceDisposition::Mutate);
        assert!(!coordinator.is_blocked());
        assert!(repaired.last_error.is_none());
        assert_eq!(gate.calls(), vec![true, true]);
        assert!(matches!(
            store.records().last(),
            Some(MaintenanceWalRecord::RecoveryCommit { .. })
        ));
    }

    #[tokio::test]
    async fn neutron_maintenance_atomic_writer_lease_serializes_enter_and_mutation() {
        let store = FaultStore::new(Vec::new());
        let gate = FaultGate::default();
        let coordinator = coordinator_with_faults(
            store,
            gate.clone(),
            CapturingAudit::default(),
        );
        let writer_lease = coordinator
            .acquire_writer(MaintenanceWriter::Direct, None)
            .await
            .unwrap();
        let mutation_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let enter_coordinator = coordinator.clone();
        let enter_task = tokio::spawn(async move {
            enter_coordinator
                .enter(enter_request("op-race"), convergence())
                .await
        });
        tokio::task::yield_now().await;
        assert!(gate.calls().is_empty(), "enter must wait behind writer lease");
        mutation_count.fetch_add(1, Ordering::SeqCst);
        drop(writer_lease);
        enter_task.await.unwrap().unwrap();

        assert_eq!(mutation_count.load(Ordering::SeqCst), 1);
        assert!(coordinator
            .acquire_writer(MaintenanceWriter::Direct, None)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn neutron_maintenance_exit_retry_resumes_pending_intent_without_duplicate_and_is_idempotent() {
        let store = FaultStore::new(active_records("op-exit"));
        let gate = FaultGate::default();
        let coordinator = coordinator_with_faults(
            store.clone(),
            gate.clone(),
            CapturingAudit::default(),
        );
        let request = MaintenanceExitRequest {
            operation_id: "op-exit".to_string(),
            expected_applied_generation: 41,
            expected_applied_desired_hash: Some("sha256:host-41".to_string()),
        };
        store.push_append_result(Ok(()));
        store.push_append_result(Err("terminal_commit_io"));

        assert!(coordinator
            .exit(request.clone(), convergence())
            .await
            .is_err());
        assert!(!coordinator.is_blocked(), "verified restore is retryable");
        assert!(coordinator.status().await.is_active());
        let (disposition, terminal) = coordinator
            .exit(request.clone(), convergence())
            .await
            .unwrap();
        assert_eq!(disposition, MaintenanceDisposition::Mutate);
        assert_eq!(terminal.phase, MaintenancePhase::Committed);
        assert_eq!(
            store
                .records()
                .iter()
                .filter(|record| matches!(record, MaintenanceWalRecord::ExitIntent { .. }))
                .count(),
            1
        );
        assert_eq!(
            coordinator.exit(request, convergence()).await.unwrap().0,
            MaintenanceDisposition::Idempotent
        );
        assert_eq!(gate.calls(), vec![false, true, false]);
    }

    #[tokio::test]
    async fn neutron_maintenance_uncertain_gate_clear_and_restore_failure_marks_blocked() {
        let store = FaultStore::new(active_records("op-uncertain"));
        let gate = FaultGate::default();
        gate.push_result(Err("clear_readback_unknown"));
        gate.push_result(Err("bypass_restore_unknown"));
        let coordinator = coordinator_with_faults(
            store,
            gate.clone(),
            CapturingAudit::default(),
        );
        let request = MaintenanceExitRequest {
            operation_id: "op-uncertain".to_string(),
            expected_applied_generation: 41,
            expected_applied_desired_hash: Some("sha256:host-41".to_string()),
        };

        assert!(coordinator.exit(request, convergence()).await.is_err());
        assert_eq!(gate.calls(), vec![false, true]);
        assert!(coordinator.is_blocked());
        assert!(coordinator.status().await.is_active());
    }

    #[tokio::test]
    async fn neutron_maintenance_abort_terminal_lost_response_retry_is_idempotent() {
        let store = FaultStore::new(active_records("op-abort"));
        let gate = FaultGate::default();
        let coordinator = coordinator_with_faults(
            store.clone(),
            gate.clone(),
            CapturingAudit::default(),
        );
        let request = MaintenanceAbortRequest {
            operation_id: "op-abort".to_string(),
            expected_phase: MaintenancePhase::MaintenanceBypass,
            error: Some("candidate_failed".to_string()),
        };

        let first = coordinator
            .abort(request.clone(), convergence())
            .await
            .unwrap();
        assert_eq!(first.0, MaintenanceDisposition::Mutate);
        assert_eq!(first.1.phase, MaintenancePhase::Committed);
        let before = store.records().len();
        assert_eq!(
            coordinator.abort(request, convergence()).await.unwrap().0,
            MaintenanceDisposition::Idempotent
        );
        assert_eq!(store.records().len(), before);
        assert_eq!(gate.calls(), vec![false]);
    }

    #[test]
    fn neutron_maintenance_replay_accepts_exact_pending_retry_and_rejects_identity_drift() {
        let records = active_records("op-pending");
        let active = active_state("op-pending", 41, "sha256:host-41");
        let mut verifying = active.clone();
        verifying.phase = MaintenancePhase::Verifying;
        let intent = MaintenanceWalRecord::exit_intent_state(verifying.clone());
        let mut exact_retry = records.clone();
        exact_retry.extend([intent.clone(), intent]);
        let replay = replay_maintenance_records(&exact_retry).unwrap();
        assert!(replay.requires_bypass);
        assert_eq!(
            replay.pending_transition,
            Some(MaintenancePendingTransition::Exit)
        );

        verifying.expected_generation += 1;
        let mut drift = records;
        drift.extend([
            MaintenanceWalRecord::exit_intent_state(active_state(
                "op-pending",
                41,
                "sha256:host-41",
            )),
            MaintenanceWalRecord::exit_intent_state(verifying),
        ]);
        assert!(replay_maintenance_records(&drift).is_err());
    }

    #[tokio::test]
    async fn neutron_maintenance_audit_events_are_bounded_structured_and_redacted() {
        let store = FaultStore::new(Vec::new());
        let gate = FaultGate::default();
        let audit = CapturingAudit::default();
        let coordinator = coordinator_with_faults(store, gate, audit.clone());
        let mut request = enter_request("op-audit");
        request.reason = "r".repeat(MAX_REASON_BYTES);

        coordinator
            .enter(request, convergence())
            .await
            .unwrap();
        coordinator.audited_status().await;
        let events = audit.events.lock().unwrap().clone();
        assert!(events.iter().any(|event| {
            event.action == MaintenanceAuditAction::Enter
                && event.outcome == MaintenanceAuditOutcome::Attempt
                && event.operation_id.as_deref() == Some("op-audit")
                && event.authorization == "root_only_uds"
        }));
        assert!(events.iter().any(|event| {
            event.action == MaintenanceAuditAction::Get
                && event.outcome == MaintenanceAuditOutcome::Success
        }));
        for event in events {
            let encoded = serde_json::to_value(event).unwrap();
            assert!(encoded.get("policy").is_none());
            assert!(encoded.get("token").is_none());
            assert!(encoded.get("secret").is_none());
            assert!(encoded["reason"].as_str().unwrap_or("").len() <= MAX_REASON_BYTES);
        }
    }

    #[tokio::test]
    async fn neutron_maintenance_corrupt_replay_and_pending_terminal_are_not_enter_repairable() {
        let corrupt = MaintenanceStoreReplay {
            state: active_state("op-corrupt", 41, "sha256:host-41"),
            failures: 1,
            pending_transition: None,
            terminal_action: None,
            gate_state: MaintenanceGateState::Unknown,
            block_cause: Some("maintenance_wal_corrupt".to_string()),
        };
        let corrupt_store = FaultStore::with_replay(corrupt);
        let corrupt_gate = FaultGate::default();
        let corrupt_coordinator = coordinator_with_faults(
            corrupt_store.clone(),
            corrupt_gate.clone(),
            CapturingAudit::default(),
        );
        let error = corrupt_coordinator
            .enter(enter_request("op-corrupt"), convergence())
            .await
            .unwrap_err();
        assert_eq!(error.code, "maintenance_operator_recovery_required");
        assert!(corrupt_store.records().is_empty());
        assert!(corrupt_gate.calls().is_empty());
        assert!(corrupt_coordinator.is_blocked());

        for pending in [
            MaintenancePendingTransition::Exit,
            MaintenancePendingTransition::Abort,
        ] {
            let replay = MaintenanceStoreReplay {
                state: active_state("op-pending-terminal", 41, "sha256:host-41"),
                failures: 0,
                pending_transition: Some(pending),
                terminal_action: None,
                gate_state: MaintenanceGateState::Bypass,
                block_cause: None,
            };
            let store = FaultStore::with_replay(replay);
            let gate = FaultGate::default();
            let coordinator = coordinator_with_faults(
                store.clone(),
                gate.clone(),
                CapturingAudit::default(),
            );
            let error = coordinator
                .enter(enter_request("op-pending-terminal"), convergence())
                .await
                .unwrap_err();
            assert_eq!(error.code, "maintenance_pending_transition_conflict");
            assert!(store.records().is_empty());
            assert!(gate.calls().is_empty());
        }
    }

    #[tokio::test]
    async fn neutron_maintenance_committed_active_repair_never_appends_orphan_enter_commit() {
        let store = FaultStore::new(active_records("op-active-repair"));
        let gate = FaultGate::default();
        gate.push_result(Err("startup_authority_unavailable"));
        gate.push_result(Ok(()));
        let coordinator = coordinator_with_faults(
            store.clone(),
            gate,
            CapturingAudit::default(),
        );
        assert!(coordinator.recover_before_reconciliation().await.is_err());
        coordinator
            .enter(enter_request("op-active-repair"), convergence())
            .await
            .unwrap();

        let replay = replay_maintenance_records(&store.records())
            .expect("active repair must remain a replayable canonical transaction");
        assert!(replay.requires_bypass);
        assert!(replay.pending_transition.is_none());
    }

    #[tokio::test]
    async fn neutron_maintenance_pending_exit_or_abort_fences_matching_snapshot_progress() {
        let store = FaultStore::new(active_records("op-terminal"));
        let gate = FaultGate::default();
        gate.push_result(Err("clear_response_lost"));
        gate.push_result(Ok(()));
        let coordinator = coordinator_with_faults(
            store.clone(),
            gate,
            CapturingAudit::default(),
        );
        let exit = MaintenanceExitRequest {
            operation_id: "op-terminal".to_string(),
            expected_applied_generation: 41,
            expected_applied_desired_hash: Some("sha256:host-41".to_string()),
        };
        assert!(coordinator.exit(exit, convergence()).await.is_err());

        let error = coordinator
            .acquire_writer(MaintenanceWriter::FullHostSnapshot, Some("op-terminal"))
            .await
            .unwrap_err();
        assert_eq!(error.code, "maintenance_terminal_transition_pending");
        assert!(!store
            .records()
            .iter()
            .any(|record| matches!(record, MaintenanceWalRecord::ProgressCommit { .. })));

        let abort_store = FaultStore::new(active_records("op-terminal-abort"));
        let abort_gate = FaultGate::default();
        abort_gate.push_result(Err("abort_clear_response_lost"));
        abort_gate.push_result(Ok(()));
        let abort_coordinator = coordinator_with_faults(
            abort_store.clone(),
            abort_gate,
            CapturingAudit::default(),
        );
        let abort = MaintenanceAbortRequest {
            operation_id: "op-terminal-abort".to_string(),
            expected_phase: MaintenancePhase::MaintenanceBypass,
            error: Some("candidate_failed".to_string()),
        };
        assert!(abort_coordinator.abort(abort, convergence()).await.is_err());
        let abort_error = abort_coordinator
            .acquire_writer(
                MaintenanceWriter::FullHostSnapshot,
                Some("op-terminal-abort"),
            )
            .await
            .unwrap_err();
        assert_eq!(abort_error.code, "maintenance_terminal_transition_pending");
        assert!(!abort_store
            .records()
            .iter()
            .any(|record| matches!(record, MaintenanceWalRecord::ProgressCommit { .. })));
    }

    #[tokio::test]
    async fn neutron_maintenance_double_gate_failure_is_unknown_not_bypass() {
        let store = FaultStore::new(active_records("op-gate-unknown"));
        let gate = FaultGate::default();
        gate.push_result(Err("clear_response_unknown"));
        gate.push_result(Err("restore_response_unknown"));
        let coordinator = coordinator_with_faults(store, gate, CapturingAudit::default());
        let request = MaintenanceExitRequest {
            operation_id: "op-gate-unknown".to_string(),
            expected_applied_generation: 41,
            expected_applied_desired_hash: Some("sha256:host-41".to_string()),
        };

        assert!(coordinator.exit(request, convergence()).await.is_err());
        let snapshot = coordinator.snapshot().await;
        assert!(snapshot.blocked);
        assert_eq!(snapshot.gate_state, MaintenanceGateState::Unknown);
        assert_eq!(snapshot.block_cause.as_deref(), Some("maintenance_gate_unknown"));
        assert_ne!(snapshot.state.phase, MaintenancePhase::MaintenanceBypass);
    }

    #[tokio::test]
    async fn neutron_maintenance_conservative_abort_retry_is_exactly_idempotent() {
        let store = FaultStore::new(active_records("op-abort-bypass"));
        let coordinator = coordinator_with_faults(
            store.clone(),
            FaultGate::default(),
            CapturingAudit::default(),
        );
        let request = MaintenanceAbortRequest {
            operation_id: "op-abort-bypass".to_string(),
            expected_phase: MaintenancePhase::MaintenanceBypass,
            error: Some("candidate_failed".to_string()),
        };
        let mut incomplete = convergence();
        incomplete.pending_generation = Some(42);
        let first = coordinator
            .abort(request.clone(), incomplete.clone())
            .await
            .unwrap();
        assert_eq!(first.0, MaintenanceDisposition::Mutate);
        assert!(first.1.is_active());
        let record_count = store.records().len();

        let retry = coordinator.abort(request, incomplete).await.unwrap();
        assert_eq!(retry.0, MaintenanceDisposition::Idempotent);
        assert_eq!(store.records().len(), record_count);
    }

    #[tokio::test]
    async fn neutron_maintenance_idempotent_results_emit_success_audit() {
        let store = FaultStore::new(Vec::new());
        let audit = CapturingAudit::default();
        let coordinator = coordinator_with_faults(
            store,
            FaultGate::default(),
            audit.clone(),
        );
        let request = enter_request("op-audit-idempotent");
        coordinator
            .enter(request.clone(), convergence())
            .await
            .unwrap();
        audit.events.lock().unwrap().clear();
        assert_eq!(
            coordinator.enter(request, convergence()).await.unwrap().0,
            MaintenanceDisposition::Idempotent
        );
        let events = audit.events.lock().unwrap().clone();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].outcome, MaintenanceAuditOutcome::Attempt);
        assert_eq!(events[1].outcome, MaintenanceAuditOutcome::Success);
    }
}
