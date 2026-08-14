use serde::{Deserialize, Serialize};
#[allow(unused_imports)]
use serde_json::json;
use std::collections::BTreeMap;
use std::fmt;
use utoipa::ToSchema;

// ── Error ──

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "code": 400,
    "error": "Validation error: Invalid protocol 'gre'"
}))]
pub struct ApiError {
    /// HTTP-style status or application error code.
    #[schema(example = 400)]
    pub code: u16,
    /// Human-readable error message safe to display to operators.
    #[schema(example = "Validation error: Invalid protocol 'gre'")]
    pub error: String,
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.error)
    }
}

// --- Neutron UDS Contract ---

pub const NEUTRON_UDS_API_VERSION: &str = "v1";
pub const NEUTRON_UDS_CONTRACT_VERSION: &str = "2026-06-v0.9";
pub const NEUTRON_UDS_SCHEMA_VERSION_MIN: u32 = 1;
pub const NEUTRON_UDS_SCHEMA_VERSION_MAX: u32 = 1;
pub const NEUTRON_UDS_BODY_MAX_BYTES: u64 = 1_048_576;
pub const NEUTRON_UDS_TIMEOUT_MS: u64 = 3_000;
pub const NEUTRON_UDS_ERROR_CODES_HASH: &str = "v0.9-neutron-errors-2";
pub const NEUTRON_UDS_PEER_AUTH_POLICY: &str = "filesystem_permissions_then_peercred";
pub const NEUTRON_UDS_CAPABILITY_HASH: &str = "v0.9-neutron-capabilities-3";
pub const NEUTRON_ATTACH_AUTHORITY: &str = "neutron_snapshot";
pub const NEUTRON_SUPPORTED_DOMAINS: &[&str] = &["attach", "acl"];
pub const NEUTRON_STATUS_SCHEMA_VERSION_MIN: u32 = 1;
pub const NEUTRON_STATUS_SCHEMA_VERSION_MAX: u32 = 1;
pub const NEUTRON_STATUS_CONTRACT_HASH: &str = "v0.9-neutron-status-1";

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[schema(example = json!({
    "generation": 101,
    "host": "compute-1.example.test",
    "ports": [
        {
            "port_id": "e607e86b-9e5f-4c63-a5df-3dc8986a1b0f",
            "ifname": "tape607e86b-9e",
            "ifindex": 27,
            "eligible": true,
            "disposition": "eligible_ovs_tap",
            "device_owner": "compute:nova",
            "vif_type": "ovs",
            "vnic_type": "normal",
            "network_backend": "openvswitch",
            "ovs_iface_id": "e607e86b-9e5f-4c63-a5df-3dc8986a1b0f",
            "managed_domains": ["acl"]
        }
    ]
}))]
pub struct NeutronSnapshotRequest {
    /// Optional schema version for future UDS contract changes.
    #[serde(default)]
    pub schema_version: Option<u32>,
    /// Monotonic generation assigned by neutron-aria-agent.
    #[serde(default)]
    #[schema(example = 101)]
    pub generation: u64,
    /// Stable hash of desired state excluding generation.
    #[serde(default)]
    #[schema(example = "sha256:...")]
    pub desired_hash: Option<String>,
    /// Neutron host that produced the snapshot.
    #[serde(default)]
    #[schema(example = "compute-1.example.test")]
    pub host: Option<String>,
    /// Desired local port runtime state for this host.
    #[serde(default)]
    pub ports: Vec<NeutronPortSnapshot>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[schema(example = json!({
    "port_id": "e607e86b-9e5f-4c63-a5df-3dc8986a1b0f",
    "ifname": "tape607e86b-9e",
    "ifindex": 27,
    "eligible": true,
    "disposition": "eligible_ovs_tap",
    "device_owner": "compute:nova",
    "vif_type": "ovs",
    "vnic_type": "normal",
    "network_backend": "openvswitch",
    "ovs_iface_id": "e607e86b-9e5f-4c63-a5df-3dc8986a1b0f",
    "managed_domains": ["acl"]
}))]
pub struct NeutronPortSnapshot {
    /// Neutron port UUID.
    #[schema(example = "e607e86b-9e5f-4c63-a5df-3dc8986a1b0f")]
    pub port_id: String,
    /// Local Linux interface name, usually the OVS tap name.
    #[serde(default)]
    #[schema(example = "tape607e86b-9e")]
    pub ifname: String,
    /// Current local ifindex observed by neutron-aria-agent.
    #[serde(default)]
    #[schema(example = 27)]
    pub ifindex: Option<u32>,
    /// Whether aria-agent is allowed to attach this port.
    #[serde(default)]
    #[schema(example = true)]
    pub eligible: bool,
    /// Classification reason such as eligible_ovs_tap, not_applicable, or unsupported.
    #[serde(default)]
    #[schema(example = "eligible_ovs_tap")]
    pub disposition: Option<String>,
    /// Neutron device_owner used for eligibility and diagnostics.
    #[serde(default)]
    #[schema(example = "compute:nova")]
    pub device_owner: Option<String>,
    /// Neutron binding:vif_type.
    #[serde(default)]
    #[schema(example = "ovs")]
    pub vif_type: Option<String>,
    /// Neutron binding:vnic_type.
    #[serde(default)]
    #[schema(example = "normal")]
    pub vnic_type: Option<String>,
    /// Local network backend classification.
    #[serde(default)]
    #[schema(example = "openvswitch")]
    pub network_backend: Option<String>,
    /// OVS external_ids:iface-id observed on the local interface.
    #[serde(default)]
    #[schema(example = "e607e86b-9e5f-4c63-a5df-3dc8986a1b0f")]
    pub ovs_iface_id: Option<String>,
    /// Per-feature domains owned by Neutron for this attached port.
    #[serde(default)]
    pub managed_domains: Vec<String>,
    /// Optional effective Aria ACL payload compiled by neutron-aria-agent.
    #[serde(default)]
    pub acl: Option<NeutronAclSnapshot>,
    /// Optional effective Aria QoS payload compiled by neutron-aria-agent.
    #[serde(default)]
    pub qos: Option<serde_json::Value>,
    /// Optional effective Aria mirror payload compiled by neutron-aria-agent.
    #[serde(default)]
    pub mirror: Option<serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[schema(example = json!({
    "enabled": true,
    "status": "ready",
    "reason": "ready",
    "effective_action": "enforce",
    "policy_id": "acl-policy-1",
    "policy_name": "allow-icmp",
    "binding_id": "acl-binding-1",
    "source": "port",
    "default_action": "allow",
    "stateful": true,
    "revision": 7,
    "rules": [
        {
            "id": "rule-1",
            "direction": "ingress",
            "priority": 100,
            "action": "drop",
            "ethertype": "IPv4",
            "protocol": "icmp",
            "src_cidrs": ["192.0.2.2/32"],
            "dst_cidrs": [],
            "src_port_min": null,
            "src_port_max": null,
            "dst_port_min": null,
            "dst_port_max": null
        }
    ]
}))]
pub struct NeutronAclSnapshot {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub effective_action: String,
    #[serde(default)]
    pub policy_id: Option<String>,
    #[serde(default)]
    pub policy_name: Option<String>,
    #[serde(default)]
    pub binding_id: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub default_action: String,
    #[serde(default)]
    pub stateful: bool,
    #[serde(default)]
    pub revision: u64,
    #[serde(default)]
    pub rules: Vec<NeutronAclRuleSnapshot>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct NeutronAclRuleSnapshot {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub direction: Option<String>,
    #[serde(default)]
    pub priority: i64,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub ethertype: Option<String>,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub src_cidrs: Vec<String>,
    #[serde(default)]
    pub dst_cidrs: Vec<String>,
    #[serde(default)]
    pub src_port_min: Option<u16>,
    #[serde(default)]
    pub src_port_max: Option<u16>,
    #[serde(default)]
    pub dst_port_min: Option<u16>,
    #[serde(default)]
    pub dst_port_max: Option<u16>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[schema(example = json!({
    "port_id": "e607e86b-9e5f-4c63-a5df-3dc8986a1b0f",
    "ifname": "tape607e86b-9e",
    "ifindex": 27,
    "managed_domains": ["acl"],
    "domain_desired_hashes": {
        "acl": "sha256:..."
    }
}))]
pub struct ManagedNeutronPort {
    /// Neutron port UUID.
    #[schema(example = "e607e86b-9e5f-4c63-a5df-3dc8986a1b0f")]
    pub port_id: String,
    /// Local Linux interface name currently attached by aria-agent.
    #[schema(example = "tape607e86b-9e")]
    pub ifname: String,
    /// Local ifindex from the accepted snapshot.
    #[serde(default)]
    #[schema(example = 27)]
    pub ifindex: Option<u32>,
    /// Per-feature domains owned by Neutron.
    #[serde(default)]
    pub managed_domains: Vec<String>,
    /// Per-domain desired-state hashes used to skip unchanged domain rewrites.
    #[serde(default)]
    pub domain_desired_hashes: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[schema(example = json!({
    "domain": "acl",
    "status": "ready",
    "reason": null,
    "effective_action": "enforce"
}))]
pub struct NeutronDomainStatus {
    pub domain: String,
    pub status: String,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub effective_action: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[schema(example = json!({
    "port_id": "e607e86b-9e5f-4c63-a5df-3dc8986a1b0f",
    "ifname": "tape607e86b-9e",
    "generation": 101,
    "desired_hash": "sha256:...",
    "status": "ready",
    "reason": null,
    "managed_domains": ["acl"],
    "domains": [{
        "domain": "acl",
        "status": "ready",
        "reason": null,
        "effective_action": "enforce"
    }]
}))]
pub struct NeutronPortStatus {
    pub port_id: String,
    pub ifname: String,
    pub generation: u64,
    #[serde(default)]
    pub desired_hash: Option<String>,
    pub status: String,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub managed_domains: Vec<String>,
    #[serde(default)]
    pub domains: Vec<NeutronDomainStatus>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NeutronStatusTransactionState {
    Idle,
    Pending,
    Classified,
    Blocked,
    Recovery,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NeutronStatusOverallReadiness {
    Ready,
    Degraded,
    Blocked,
    Unknown,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NeutronStatusRequiredAction {
    None,
    Poll,
    RecoverPending,
    FullResync,
    Operator,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NeutronStatusRecoveryCause {
    InventoryUnavailable,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NeutronStatusDomainState {
    Ready,
    NotRequested,
    Degraded,
    Blocked,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NeutronStatusEffectiveAction {
    Enforce,
    Bypass,
    Unchanged,
    Cleanup,
    NoOp,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NeutronStatusSupportDisposition {
    Supported,
    Unsupported,
    Unknown,
    NotApplicable,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct NeutronStatusDomainEvidence {
    pub domain: String,
    pub status: NeutronStatusDomainState,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub effective_action: Option<NeutronStatusEffectiveAction>,
    pub support_disposition: NeutronStatusSupportDisposition,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct NeutronStatusPortEvidence {
    pub port_id: String,
    pub ifname: String,
    pub generation: u64,
    #[serde(default)]
    pub desired_hash: Option<String>,
    pub status: String,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub managed_domains: Vec<String>,
    #[serde(default)]
    pub domains: Vec<NeutronStatusDomainEvidence>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[schema(example = json!({
    "api_version": "v1",
    "attach_authority": "neutron_snapshot",
    "supports_full_snapshot": true,
    "supports_port_scoped_snapshot": true,
    "supports_port_delete": true,
    "supported_domains": ["attach", "acl"]
}))]
pub struct NeutronCapabilitiesResponse {
    /// Local UDS API version.
    #[schema(example = "v1")]
    pub api_version: String,
    /// Version of the generated/recorded UDS contract.
    #[serde(default)]
    #[schema(example = "2026-06-v0.9")]
    pub contract_version: String,
    /// Minimum accepted snapshot schema version.
    #[serde(default)]
    #[schema(example = 1)]
    pub schema_version_min: u32,
    /// Maximum accepted snapshot schema version.
    #[serde(default)]
    #[schema(example = 1)]
    pub schema_version_max: u32,
    /// Minimum supported Status response schema version.
    #[serde(default)]
    #[schema(example = 1)]
    pub status_schema_version_min: u32,
    /// Maximum supported Status response schema version.
    #[serde(default)]
    #[schema(example = 1)]
    pub status_schema_version_max: u32,
    /// Stable hash/version for the independent Status response vocabulary.
    #[serde(default)]
    #[schema(example = "v0.9-neutron-status-1")]
    pub status_contract_hash: String,
    /// Authority model for attach/detach operations.
    #[schema(example = "neutron_snapshot")]
    pub attach_authority: String,
    /// Whether PUT snapshot is authoritative for the full host set.
    #[schema(example = true)]
    pub supports_full_snapshot: bool,
    /// Whether PUT /ports/{port_id}/snapshot is supported.
    #[serde(default)]
    #[schema(example = true)]
    pub supports_port_scoped_snapshot: bool,
    /// Whether DELETE /ports/{port_id} is supported.
    #[schema(example = true)]
    pub supports_port_delete: bool,
    /// Domains accepted in NeutronPortSnapshot.managed_domains.
    pub supported_domains: Vec<String>,
    /// Domains required by this local deployment profile.
    #[serde(default)]
    pub mandatory_domains: Vec<String>,
    /// Maximum request body accepted by the local UDS API.
    #[serde(default)]
    #[schema(example = 1048576)]
    pub body_max_bytes: u64,
    /// Recommended client timeout for mutating requests.
    #[serde(default)]
    #[schema(example = 3000)]
    pub timeout_ms: u64,
    /// Stable hash/version for UDS error code vocabulary.
    #[serde(default)]
    #[schema(example = "v0.9-neutron-errors-2")]
    pub error_codes_hash: String,
    /// Expected local Unix peer authentication policy.
    #[serde(default)]
    #[schema(example = "filesystem_permissions_then_peercred")]
    pub peer_auth_policy: String,
    /// Stable hash/version for capability drift detection.
    #[serde(default)]
    #[schema(example = "v0.9-neutron-capabilities-3")]
    pub capability_hash: String,
}

impl NeutronCapabilitiesResponse {
    pub fn current() -> Self {
        Self {
            api_version: NEUTRON_UDS_API_VERSION.to_string(),
            contract_version: NEUTRON_UDS_CONTRACT_VERSION.to_string(),
            schema_version_min: NEUTRON_UDS_SCHEMA_VERSION_MIN,
            schema_version_max: NEUTRON_UDS_SCHEMA_VERSION_MAX,
            status_schema_version_min: NEUTRON_STATUS_SCHEMA_VERSION_MIN,
            status_schema_version_max: NEUTRON_STATUS_SCHEMA_VERSION_MAX,
            status_contract_hash: NEUTRON_STATUS_CONTRACT_HASH.to_string(),
            attach_authority: NEUTRON_ATTACH_AUTHORITY.to_string(),
            supports_full_snapshot: true,
            supports_port_scoped_snapshot: true,
            supports_port_delete: true,
            supported_domains: NEUTRON_SUPPORTED_DOMAINS
                .iter()
                .map(|domain| (*domain).to_string())
                .collect(),
            mandatory_domains: Vec::new(),
            body_max_bytes: NEUTRON_UDS_BODY_MAX_BYTES,
            timeout_ms: NEUTRON_UDS_TIMEOUT_MS,
            error_codes_hash: NEUTRON_UDS_ERROR_CODES_HASH.to_string(),
            peer_auth_policy: NEUTRON_UDS_PEER_AUTH_POLICY.to_string(),
            capability_hash: NEUTRON_UDS_CAPABILITY_HASH.to_string(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[schema(example = json!({
    "generation": 101,
    "managed_ports": [
        {
            "port_id": "e607e86b-9e5f-4c63-a5df-3dc8986a1b0f",
            "ifname": "tape607e86b-9e",
            "ifindex": 27,
            "managed_domains": ["acl"]
        }
    ],
    "active_instances": ["tape607e86b-9e"]
}))]
pub struct NeutronStatusResponse {
    /// Latest generation accepted by the UDS runtime.
    #[schema(example = 101)]
    pub generation: u64,
    /// Latest generation accepted by the single-writer apply engine.
    #[serde(default)]
    pub accepted_generation: u64,
    /// Latest generation fully applied and reported as ready.
    #[serde(default)]
    pub applied_generation: u64,
    /// Generation currently being applied or left pending after a partial error.
    #[serde(default)]
    pub pending_generation: Option<u64>,
    /// Desired hash for the latest accepted generation.
    #[serde(default)]
    pub desired_hash: Option<String>,
    /// Desired hash for the latest fully applied generation.
    #[serde(default)]
    pub applied_desired_hash: Option<String>,
    /// Neutron snapshot WAL replay/apply state.
    #[serde(default)]
    pub wal_status: String,
    /// Number of Neutron WAL replay records that failed to parse or apply.
    #[serde(default)]
    pub wal_replay_failures: u64,
    /// Overall Neutron authority state.
    #[serde(default)]
    pub authority_state: String,
    /// Ports currently attached through the Neutron snapshot authority.
    pub managed_ports: Vec<ManagedNeutronPort>,
    /// Per-port transaction status.
    #[serde(default)]
    pub port_statuses: Vec<NeutronPortStatus>,
    /// All active aria-agent instances, including those outside Neutron authority.
    pub active_instances: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct NeutronStatusV1Response {
    pub status_schema_version: u32,
    pub status_contract_hash: String,
    pub transaction_state: NeutronStatusTransactionState,
    pub overall_readiness: NeutronStatusOverallReadiness,
    pub required_action: NeutronStatusRequiredAction,
    pub recovery_cause: Option<NeutronStatusRecoveryCause>,
    pub last_classified_generation: u64,
    pub generation: u64,
    #[serde(default)]
    pub accepted_generation: u64,
    #[serde(default)]
    pub applied_generation: u64,
    #[serde(default)]
    pub pending_generation: Option<u64>,
    #[serde(default)]
    pub desired_hash: Option<String>,
    #[serde(default)]
    pub applied_desired_hash: Option<String>,
    #[serde(default)]
    pub wal_status: String,
    #[serde(default)]
    pub wal_replay_failures: u64,
    #[serde(default)]
    pub authority_state: String,
    pub managed_ports: Vec<ManagedNeutronPort>,
    #[serde(default)]
    pub port_statuses: Vec<NeutronStatusPortEvidence>,
    pub active_instances: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[schema(example = json!({
    "generation": 101,
    "results": [
        {
            "port_id": "e607e86b-9e5f-4c63-a5df-3dc8986a1b0f",
            "ifname": "tape607e86b-9e",
            "action": "attach",
            "status": "ok",
            "reason": null
        }
    ],
    "active_instances": ["tape607e86b-9e"]
}))]
pub struct NeutronSnapshotResponse {
    /// Snapshot generation returned after apply.
    #[schema(example = 101)]
    pub generation: u64,
    /// Desired hash accepted for this snapshot, when supplied by neutron-aria-agent.
    #[serde(default)]
    pub desired_hash: Option<String>,
    /// Latest generation accepted by the local apply engine.
    #[serde(default)]
    pub accepted_generation: u64,
    /// Latest generation fully applied by the local apply engine.
    #[serde(default)]
    pub applied_generation: u64,
    /// Response status: accepted, pending, ok, noop, stale, or partial.
    #[serde(default)]
    pub status: String,
    /// Per-port apply results.
    pub results: Vec<NeutronPortApplyResult>,
    /// All active aria-agent instances after apply.
    pub active_instances: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[schema(example = json!({
    "port_id": "e607e86b-9e5f-4c63-a5df-3dc8986a1b0f",
    "ifname": "tape607e86b-9e",
    "action": "attach",
    "status": "ok",
    "reason": null
}))]
pub struct NeutronPortApplyResult {
    /// Neutron port UUID.
    #[schema(example = "e607e86b-9e5f-4c63-a5df-3dc8986a1b0f")]
    pub port_id: String,
    /// Local interface name used for the action.
    #[schema(example = "tape607e86b-9e")]
    pub ifname: String,
    /// Action taken: attach, update, detach, or ignore.
    #[schema(example = "attach")]
    pub action: String,
    /// Result status: ok, error, or ignored.
    #[schema(example = "ok")]
    pub status: String,
    /// Optional reason for ignored or failed actions.
    #[serde(default)]
    #[schema(example = "missing ifname")]
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[schema(example = json!({
    "port_id": "e607e86b-9e5f-4c63-a5df-3dc8986a1b0f",
    "ifname": "tape607e86b-9e",
    "detached": true,
    "status": "ok",
    "error": null
}))]
pub struct NeutronDeleteResponse {
    /// Neutron port UUID.
    #[schema(example = "e607e86b-9e5f-4c63-a5df-3dc8986a1b0f")]
    pub port_id: String,
    /// Local interface name that was detached, if known.
    #[serde(default)]
    #[schema(example = "tape607e86b-9e")]
    pub ifname: Option<String>,
    /// Whether a local runtime detach happened.
    #[schema(example = true)]
    pub detached: bool,
    /// Result status: ok, error, or not_found.
    #[schema(example = "ok")]
    pub status: String,
    /// Optional error string.
    #[serde(default)]
    pub error: Option<String>,
}

// ── Health ──

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "status": "ok",
    "version": "0.9.0",
    "instances": 2,
    "wal_replay_failures": 0,
    "kernel_drop_available": true,
    "kernel_drop_mode": "kfree_skb_reasonful",
    "kernel_drop_managed_ifaces": 1,
    "kernel_drop_last_error": null
}))]
pub struct HealthResponse {
    /// Overall agent status.
    #[schema(example = "ok")]
    pub status: String,
    /// Running agent version string.
    #[schema(example = "0.9.0")]
    pub version: String,
    /// Number of managed firewall instances currently active.
    #[schema(example = 2)]
    pub instances: usize,
    /// Number of WAL lines that failed to parse or apply during the last replay.
    #[schema(example = 0)]
    #[serde(default)]
    pub wal_replay_failures: u64,
    /// Whether kernel-attributed drop observability is currently available.
    #[schema(example = true)]
    #[serde(default)]
    pub kernel_drop_available: bool,
    /// Active kernel drop collection mode when the feature is enabled.
    #[schema(example = "kfree_skb_reasonful")]
    #[serde(default)]
    pub kernel_drop_mode: Option<String>,
    /// Number of managed interfaces participating in kernel drop collection.
    #[schema(example = 1)]
    #[serde(default)]
    pub kernel_drop_managed_ifaces: usize,
    /// Last kernel drop initialization error, if any.
    #[schema(example = "failed to attach kprobe to kfree_skb_reason")]
    #[serde(default)]
    pub kernel_drop_last_error: Option<String>,
}

// ── Instances ──

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "name": "eth0",
    "active": true,
    "acl_ready": true,
    "xdp_ready": false,
    "readiness_reason": "xdp_ddos_hook_unavailable",
    "cleanup_pending_count": 0,
    "maintenance_reason": null
}))]
pub struct InstanceInfo {
    /// Managed instance or tap name.
    #[schema(example = "eth0")]
    pub name: String,
    /// Whether the instance remains registered, independently of link health.
    #[schema(example = true)]
    pub active: bool,
    /// Whether desired ACL/CT enforcement has a complete dual-TC runtime and published gate.
    #[serde(default)]
    #[schema(example = true)]
    pub acl_ready: bool,
    /// Whether the independent XDP link is currently present.
    #[serde(default)]
    #[schema(example = false)]
    pub xdp_ready: bool,
    /// Stable runtime readiness reason when either independent health dimension is degraded.
    #[serde(default)]
    pub readiness_reason: Option<String>,
    /// Number of retired bitmap indices still awaiting confirmed kernel cleanup.
    #[serde(default)]
    pub cleanup_pending_count: usize,
    /// Maintenance state that does not lower datapath ACL readiness.
    #[serde(default)]
    pub maintenance_reason: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "instances": [
        {"name": "eth0", "active": true},
        {"name": "tapkd01", "active": false}
    ]
}))]
pub struct InstancesResponse {
    /// All managed instances known to the agent.
    pub instances: Vec<InstanceInfo>,
}

// ── System ──

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "iface": "eth0",
    "max_port_policies": 16384
}))]
pub struct SystemStartRequest {
    /// Physical or virtual interface to manage as the standalone firewall instance.
    #[schema(example = "eth0")]
    pub iface: String,
    /// Maximum number of port bitmap-backed policies to allocate for the instance.
    #[schema(example = 16384)]
    #[serde(default = "default_max_port_policies")]
    pub max_port_policies: u32,
}

fn default_max_port_policies() -> u32 {
    16384
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "message": "Added policy: web -> db (ingress)"
}))]
pub struct MessageResponse {
    /// Short operator-facing status message describing the completed action.
    #[schema(example = "Added policy: web -> db (ingress)")]
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
pub struct BitmapCleanupPendingResponse {
    pub bitmap_idx: u32,
    pub ports_normalized: String,
    pub error: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct PolicyMutationResponse {
    pub message: String,
    pub committed: bool,
    #[serde(default)]
    pub cleanup_pending: Vec<BitmapCleanupPendingResponse>,
}

// ── Groups ──

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "id": 1,
    "name": "web",
    "cidrs": ["10.0.1.0/24", "10.0.2.0/24"]
}))]
pub struct GroupEntry {
    /// Stable numeric identifier allocated to the group.
    #[schema(example = 1)]
    pub id: u32,
    /// Human-readable group name referenced by ACL, QoS, and mirror rules.
    #[schema(example = "web")]
    pub name: String,
    /// CIDR members contained in the group.
    pub cidrs: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "groups": [
        {"id": 1, "name": "web", "cidrs": ["10.0.1.0/24"]},
        {"id": 2, "name": "db", "cidrs": ["10.0.10.0/24"]}
    ]
}))]
pub struct GroupsResponse {
    /// Configured address groups for the instance.
    pub groups: Vec<GroupEntry>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "name": "web",
    "cidr": "10.0.1.0/24"
}))]
pub struct AddGroupRequest {
    /// Group name to create or extend.
    #[schema(example = "web")]
    pub name: String,
    /// CIDR to add to the group.
    #[schema(example = "10.0.1.0/24")]
    pub cidr: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "id": 1,
    "name": "web"
}))]
pub struct AddGroupResponse {
    /// Stable numeric identifier assigned to the group.
    #[schema(example = 1)]
    pub id: u32,
    /// Name of the created or extended group.
    #[schema(example = "web")]
    pub name: String,
}

// ── Groups with Stats (Aggregation) ──

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "id": 1,
    "name": "web",
    "cidrs": ["10.0.1.0/24"],
    "ingress_packets": 128,
    "ingress_bytes": 8192,
    "egress_packets": 256,
    "egress_bytes": 16384
}))]
pub struct GroupWithStatsEntry {
    /// Stable numeric identifier allocated to the group.
    #[schema(example = 1)]
    pub id: u32,
    /// Human-readable group name.
    #[schema(example = "web")]
    pub name: String,
    /// CIDR members contained in the group.
    pub cidrs: Vec<String>,
    /// Total ingress packets matched to the group.
    #[schema(example = 128)]
    #[serde(default)]
    pub ingress_packets: u64,
    /// Total ingress bytes matched to the group.
    #[schema(example = 8192)]
    #[serde(default)]
    pub ingress_bytes: u64,
    /// Total egress packets matched to the group.
    #[schema(example = 256)]
    #[serde(default)]
    pub egress_packets: u64,
    /// Total egress bytes matched to the group.
    #[schema(example = 16384)]
    #[serde(default)]
    pub egress_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "groups": [
        {
            "id": 1,
            "name": "web",
            "cidrs": ["10.0.1.0/24"],
            "ingress_packets": 128,
            "ingress_bytes": 8192,
            "egress_packets": 256,
            "egress_bytes": 16384
        }
    ]
}))]
pub struct GroupsWithStatsResponse {
    /// Groups enriched with aggregated per-direction traffic counters.
    pub groups: Vec<GroupWithStatsEntry>,
}

// ── Policies ──

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "src_group": "web",
    "src_group_id": 1,
    "dst_group": "db",
    "dst_group_id": 2,
    "proto": "tcp",
    "action": "allow",
    "direction": "ingress",
    "ports": "5432",
    "bitmap_idx": 7
}))]
pub struct PolicyEntry {
    /// Source group name or `any`.
    #[schema(example = "web")]
    pub src_group: String,
    /// Numeric identifier of the source group.
    #[schema(example = 1)]
    pub src_group_id: u32,
    /// Destination group name or `any`.
    #[schema(example = "db")]
    pub dst_group: String,
    /// Numeric identifier of the destination group.
    #[schema(example = 2)]
    pub dst_group_id: u32,
    /// Matched L4 protocol name or protocol number.
    #[schema(example = "tcp")]
    pub proto: String,
    /// Rule action, typically `allow` or `drop`.
    #[schema(example = "allow")]
    pub action: String,
    /// Traffic direction: `ingress` or `egress`.
    #[schema(example = "ingress")]
    pub direction: String,
    /// Optional port filter expression.
    #[schema(example = "5432")]
    pub ports: Option<String>,
    /// Optional bitmap index used for expanded port matching.
    #[schema(example = 7)]
    pub bitmap_idx: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "policies": [
        {
            "src_group": "web",
            "src_group_id": 1,
            "dst_group": "db",
            "dst_group_id": 2,
            "proto": "tcp",
            "action": "allow",
            "direction": "ingress",
            "ports": "5432",
            "bitmap_idx": 7
        }
    ]
}))]
pub struct PoliciesResponse {
    /// Configured policies for the instance.
    pub policies: Vec<PolicyEntry>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "src_group": "web",
    "dst_group": "db",
    "proto": "tcp",
    "action": "allow",
    "direction": "ingress",
    "ports": "5432"
}))]
pub struct AddPolicyRequest {
    /// Source group name or `any`.
    #[schema(example = "web")]
    pub src_group: String,
    /// Destination group name or `any`.
    #[schema(example = "db")]
    pub dst_group: String,
    /// Protocol name (`tcp`, `udp`, `icmp`, `any`) or protocol number.
    #[schema(example = "tcp")]
    pub proto: String,
    /// Action to apply when the rule matches.
    #[schema(example = "allow")]
    pub action: String,
    /// Traffic direction: `ingress`, `egress`, or `both`.
    #[schema(example = "ingress")]
    #[serde(default = "default_direction")]
    pub direction: String,
    /// Optional port filter expression such as `80,443`, `1000-2000`, or `all`.
    #[schema(example = "5432")]
    pub ports: Option<String>,
}

fn default_direction() -> String {
    "ingress".to_string()
}

fn default_mode_string() -> String {
    "policing".to_string()
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "src_group": "web",
    "dst_group": "db",
    "proto": "tcp",
    "direction": "ingress"
}))]
pub struct DeletePolicyRequest {
    /// Source group name or `any`.
    #[schema(example = "web")]
    pub src_group: String,
    /// Destination group name or `any`.
    #[schema(example = "db")]
    pub dst_group: String,
    /// Protocol name (`tcp`, `udp`, `icmp`, `any`) or protocol number.
    #[schema(example = "tcp")]
    pub proto: String,
    /// Traffic direction: `ingress`, `egress`, or `both`.
    #[schema(example = "ingress")]
    #[serde(default = "default_direction")]
    pub direction: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "policies": [
        {
            "src_group": "web",
            "dst_group": "db",
            "proto": "tcp",
            "action": "allow",
            "direction": "ingress",
            "ports": "5432"
        },
        {
            "src_group": "web",
            "dst_group": "any",
            "proto": "udp",
            "action": "drop",
            "direction": "egress",
            "ports": "53"
        }
    ]
}))]
pub struct BatchAddPoliciesRequest {
    /// Policies to create in order.
    pub policies: Vec<AddPolicyRequest>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "added": 2,
    "errors": [],
    "committed": true,
    "cleanup_pending": []
}))]
pub struct BatchPoliciesResponse {
    /// Number of policies successfully added.
    #[schema(example = 2)]
    pub added: usize,
    /// Validation or apply errors for entries that could not be created.
    pub errors: Vec<String>,
    /// True once every accepted item has been atomically published.
    #[serde(default)]
    pub committed: bool,
    /// Post-commit cleanup debt, separate from per-item validation errors.
    #[serde(default)]
    pub cleanup_pending: Vec<BitmapCleanupPendingResponse>,
}

// ── Policies with Stats (Aggregation) ──

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "src_group": "web",
    "src_group_id": 1,
    "dst_group": "db",
    "dst_group_id": 2,
    "proto": "tcp",
    "action": "allow",
    "direction": "ingress",
    "ports": "5432",
    "bitmap_idx": 7,
    "packets": 1024,
    "bytes": 65536,
    "dropped_packets": 0,
    "dropped_bytes": 0
}))]
pub struct PolicyWithStatsEntry {
    /// Source group name or `any`.
    #[schema(example = "web")]
    pub src_group: String,
    /// Numeric identifier of the source group.
    #[schema(example = 1)]
    pub src_group_id: u32,
    /// Destination group name or `any`.
    #[schema(example = "db")]
    pub dst_group: String,
    /// Numeric identifier of the destination group.
    #[schema(example = 2)]
    pub dst_group_id: u32,
    /// Matched L4 protocol name or protocol number.
    #[schema(example = "tcp")]
    pub proto: String,
    /// Rule action, typically `allow` or `drop`.
    #[schema(example = "allow")]
    pub action: String,
    /// Traffic direction: `ingress` or `egress`.
    #[schema(example = "ingress")]
    pub direction: String,
    /// Optional port filter expression.
    #[schema(example = "5432")]
    pub ports: Option<String>,
    /// Optional bitmap index used for expanded port matching.
    #[schema(example = 7)]
    pub bitmap_idx: Option<u32>,
    /// Total packets matched by the rule.
    #[schema(example = 1024)]
    #[serde(default)]
    pub packets: u64,
    /// Total bytes matched by the rule.
    #[schema(example = 65536)]
    #[serde(default)]
    pub bytes: u64,
    /// Total packets dropped by the rule.
    #[schema(example = 0)]
    #[serde(default)]
    pub dropped_packets: u64,
    /// Total bytes dropped by the rule.
    #[schema(example = 0)]
    #[serde(default)]
    pub dropped_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "policies": [
        {
            "src_group": "web",
            "src_group_id": 1,
            "dst_group": "db",
            "dst_group_id": 2,
            "proto": "tcp",
            "action": "allow",
            "direction": "ingress",
            "ports": "5432",
            "bitmap_idx": 7,
            "packets": 1024,
            "bytes": 65536,
            "dropped_packets": 0,
            "dropped_bytes": 0
        }
    ]
}))]
pub struct PoliciesWithStatsResponse {
    /// Policies enriched with aggregated hit and drop counters.
    pub policies: Vec<PolicyWithStatsEntry>,
}

// ── QoS ──

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "group": "web",
    "group_id": 1,
    "direction": "egress",
    "rate_bps": 100000000,
    "burst_bytes": 1048576,
    "priority": 3,
    "mode": "policing"
}))]
pub struct QosEntry {
    /// Group name the QoS rule applies to.
    #[schema(example = "web")]
    pub group: String,
    /// Numeric identifier of the matched group.
    #[schema(example = 1)]
    pub group_id: u32,
    /// Traffic direction: `ingress` or `egress`.
    #[schema(example = "egress")]
    pub direction: String,
    /// Rate limit in bits per second after unit parsing.
    #[schema(example = 100000000)]
    pub rate_bps: u64,
    /// Burst budget in bytes.
    #[schema(example = 1048576)]
    pub burst_bytes: u64,
    /// Scheduling priority applied to matched packets.
    #[schema(example = 3)]
    pub priority: u8,
    /// Enforcement mode, typically `policing` or `shaping`.
    #[schema(example = "policing")]
    #[serde(default = "default_mode_string")]
    pub mode: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "rules": [
        {
            "group": "web",
            "group_id": 1,
            "direction": "egress",
            "rate_bps": 100000000,
            "burst_bytes": 1048576,
            "priority": 3,
            "mode": "policing"
        }
    ]
}))]
pub struct QosListResponse {
    /// Configured QoS rules for the instance.
    pub rules: Vec<QosEntry>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "group": "web",
    "direction": "egress",
    "rate": "100mbit",
    "burst": "1mb",
    "priority": 3,
    "mode": "policing"
}))]
pub struct AddQosRequest {
    /// Group name the QoS rule applies to.
    #[schema(example = "web")]
    pub group: String,
    /// Traffic direction: `ingress` or `egress`.
    #[schema(example = "egress")]
    pub direction: String,
    /// Human-readable rate value such as `100mbit` or `10gbit`.
    #[schema(example = "100mbit")]
    pub rate: String,
    /// Optional burst size such as `1mb`; empty string keeps the default.
    #[schema(example = "1mb")]
    #[serde(default)]
    pub burst: String,
    /// Scheduling priority applied to matched packets.
    #[schema(example = 3)]
    #[serde(default)]
    pub priority: u8,
    /// Enforcement mode, typically `policing` or `shaping`.
    #[schema(example = "policing")]
    #[serde(default = "default_mode_string")]
    pub mode: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "group": "web",
    "direction": "egress"
}))]
pub struct DeleteQosRequest {
    /// Group name the QoS rule applies to.
    #[schema(example = "web")]
    pub group: String,
    /// Traffic direction: `ingress` or `egress`.
    #[schema(example = "egress")]
    pub direction: String,
}

// ── Conntrack ──

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ConntrackEntry {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: String,
    pub state: String,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ConntrackResponse {
    pub connections: Vec<ConntrackEntry>,
    pub total: usize,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ConntrackFlushResponse {
    pub flushed: u64,
}

// ── Config ──

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "conntrack": true,
    "monitoring": true,
    "acl": true,
    "qos": true,
    "mirror": false,
    "tcprt": true,
    "ssl": false,
    "num_cpus": 8
}))]
pub struct ConfigResponse {
    /// Whether conntrack collection is enabled for the instance.
    #[schema(example = true)]
    pub conntrack: bool,
    /// Whether base monitoring counters are enabled.
    #[schema(example = true)]
    pub monitoring: bool,
    /// Whether ACL enforcement is enabled.
    #[schema(example = true)]
    pub acl: bool,
    /// Whether QoS enforcement is enabled.
    #[schema(example = true)]
    pub qos: bool,
    /// Whether mirror rule evaluation is enabled.
    #[schema(example = false)]
    pub mirror: bool,
    /// Whether TCP-RT observability is enabled.
    #[schema(example = true)]
    pub tcprt: bool,
    /// Whether SSL observability is enabled for the instance.
    #[schema(example = false)]
    pub ssl: bool,
    /// Number of CPUs provisioned for per-CPU maps.
    #[schema(example = 8)]
    pub num_cpus: u16,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "qos": true,
    "mirror": true,
    "ssl": false
}))]
pub struct UpdateConfigRequest {
    /// Toggle conntrack collection.
    pub conntrack: Option<bool>,
    /// Toggle base monitoring counters.
    pub monitoring: Option<bool>,
    /// Toggle ACL enforcement.
    pub acl: Option<bool>,
    /// Toggle QoS enforcement.
    pub qos: Option<bool>,
    /// Toggle mirror rule evaluation.
    pub mirror: Option<bool>,
    /// Toggle TCP-RT observability.
    pub tcprt: Option<bool>,
    /// Toggle SSL observability for the instance.
    pub ssl: Option<bool>,
}

// ── Stats ──

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "groups": 4,
    "policies": 12,
    "qos_rules": 2,
    "mirror_rules": 1,
    "conntrack_v4": 38,
    "conntrack_v6": 0
}))]
pub struct StatsOverview {
    /// Number of configured groups.
    #[schema(example = 4)]
    pub groups: usize,
    /// Number of configured ACL policies.
    #[schema(example = 12)]
    pub policies: usize,
    /// Number of configured QoS rules.
    #[schema(example = 2)]
    pub qos_rules: usize,
    /// Number of configured mirror rules.
    #[schema(example = 1)]
    pub mirror_rules: usize,
    /// Active IPv4 conntrack entries.
    #[schema(example = 38)]
    pub conntrack_v4: u64,
    /// Active IPv6 conntrack entries.
    #[schema(example = 0)]
    pub conntrack_v6: u64,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct RuleStatsEntry {
    pub src_group: String,
    pub src_id: u32,
    pub dst_group: String,
    pub dst_id: u32,
    pub proto: String,
    pub direction: String,
    pub packets: u64,
    pub bytes: u64,
    #[serde(default)]
    pub dropped_packets: u64,
    #[serde(default)]
    pub dropped_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct RuleStatsResponse {
    pub rules: Vec<RuleStatsEntry>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct FlowEntry {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: String,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct FlowStatsResponse {
    pub flows: Vec<FlowEntry>,
}

// --- QoS Statistics ---

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct QosStatsEntry {
    pub group: String,
    pub group_id: u32,
    pub direction: String,
    pub passed_packets: u64,
    pub passed_bytes: u64,
    pub dropped_packets: u64,
    pub dropped_bytes: u64,
    pub shaped_packets: u64,
    pub shaped_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct QosStatsResponse {
    pub rules: Vec<QosStatsEntry>,
}

// ── QoS with Stats (Aggregation) ──

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct QosWithStatsEntry {
    // QoS configuration
    pub group: String,
    pub group_id: u32,
    pub direction: String,
    pub rate_bps: u64,
    pub burst_bytes: u64,
    pub priority: u8,
    pub mode: String,
    // Statistics
    #[serde(default)]
    pub passed_packets: u64,
    #[serde(default)]
    pub passed_bytes: u64,
    #[serde(default)]
    pub dropped_packets: u64,
    #[serde(default)]
    pub dropped_bytes: u64,
    #[serde(default)]
    pub shaped_packets: u64,
    #[serde(default)]
    pub shaped_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct QosWithStatsResponse {
    pub rules: Vec<QosWithStatsEntry>,
}

// --- Per-Group Statistics ---

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct GroupStatsEntry {
    pub group: String,
    pub group_id: u32,
    pub direction: String,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct GroupStatsResponse {
    pub groups: Vec<GroupStatsEntry>,
}

// ── Mirror ──

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "src_group": "any",
    "src_group_id": 0,
    "dst_group": "db",
    "dst_group_id": 2,
    "proto": "tcp",
    "direction": "egress",
    "target_iface": "eth1",
    "target_ifindex": 3,
    "is_global": false
}))]
pub struct MirrorEntry {
    /// Source group name or `any`.
    #[schema(example = "any")]
    pub src_group: String,
    /// Numeric identifier of the source group.
    #[schema(example = 0)]
    pub src_group_id: u32,
    /// Destination group name or `any`.
    #[schema(example = "db")]
    pub dst_group: String,
    /// Numeric identifier of the destination group.
    #[schema(example = 2)]
    pub dst_group_id: u32,
    /// Matched L4 protocol name or protocol number.
    #[schema(example = "tcp")]
    pub proto: String,
    /// Traffic direction: `ingress` or `egress`.
    #[schema(example = "egress")]
    pub direction: String,
    /// Interface name that receives mirrored packets.
    #[schema(example = "eth1")]
    pub target_iface: String,
    /// Interface index resolved from the target interface name.
    #[schema(example = 3)]
    pub target_ifindex: u32,
    /// Whether the rule applies globally across all groups.
    #[schema(example = false)]
    pub is_global: bool,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "rules": [
        {
            "src_group": "any",
            "src_group_id": 0,
            "dst_group": "db",
            "dst_group_id": 2,
            "proto": "tcp",
            "direction": "egress",
            "target_iface": "eth1",
            "target_ifindex": 3,
            "is_global": false
        }
    ]
}))]
pub struct MirrorListResponse {
    /// Configured mirror rules for the instance.
    pub rules: Vec<MirrorEntry>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "src_group": "any",
    "dst_group": "db",
    "proto": "tcp",
    "direction": "egress",
    "target": "eth1"
}))]
pub struct AddMirrorRequest {
    /// Source group name or `any`.
    #[schema(example = "any")]
    #[serde(default = "default_any")]
    pub src_group: String,
    /// Destination group name or `any`.
    #[schema(example = "db")]
    #[serde(default = "default_any")]
    pub dst_group: String,
    /// Protocol name (`tcp`, `udp`, `icmp`, `any`) or protocol number.
    #[schema(example = "tcp")]
    #[serde(default = "default_any_proto")]
    pub proto: String,
    /// Traffic direction: `ingress` or `egress`.
    #[schema(example = "egress")]
    pub direction: String,
    /// Target interface name that should receive mirrored packets.
    #[schema(example = "eth1")]
    pub target: String,
}

fn default_any() -> String {
    "any".to_string()
}

fn default_any_proto() -> String {
    "any".to_string()
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "src_group": "any",
    "dst_group": "db",
    "proto": "tcp",
    "direction": "egress"
}))]
pub struct DeleteMirrorRequest {
    /// Source group name or `any`.
    #[schema(example = "any")]
    #[serde(default = "default_any")]
    pub src_group: String,
    /// Destination group name or `any`.
    #[schema(example = "db")]
    #[serde(default = "default_any")]
    pub dst_group: String,
    /// Protocol name (`tcp`, `udp`, `icmp`, `any`) or protocol number.
    #[schema(example = "tcp")]
    #[serde(default = "default_any_proto")]
    pub proto: String,
    /// Traffic direction: `ingress` or `egress`.
    #[schema(example = "egress")]
    pub direction: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct MirrorStatsEntry {
    pub src_group: String,
    pub src_id: u32,
    pub dst_group: String,
    pub dst_id: u32,
    pub proto: String,
    pub direction: String,
    pub mirrored_packets: u64,
    pub mirrored_bytes: u64,
    pub errors: u64,
    pub is_global: bool,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct MirrorStatsResponse {
    pub rules: Vec<MirrorStatsEntry>,
}

// ── Mirror with Stats (Aggregation) ──

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MirrorWithStatsEntry {
    // Mirror configuration
    pub src_group: String,
    pub src_group_id: u32,
    pub dst_group: String,
    pub dst_group_id: u32,
    pub proto: String,
    pub direction: String,
    pub target_iface: String,
    pub target_ifindex: u32,
    pub is_global: bool,
    // Statistics
    #[serde(default)]
    pub mirrored_packets: u64,
    #[serde(default)]
    pub mirrored_bytes: u64,
    #[serde(default)]
    pub errors: u64,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct MirrorWithStatsResponse {
    pub rules: Vec<MirrorWithStatsEntry>,
}

// ── TCP-RT ──

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TcpRtEntry {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub handshake_us: f64,
    pub rtt_client_us: f64,
    pub rtt_server_us: f64,
    pub art_us: f64,
    pub retrans_req: u32,
    pub retrans_resp: u32,
    pub request_count: u32,
    pub state: String,
    #[serde(default)]
    pub forward_platform_us: f64,
    #[serde(default)]
    pub server_network_us: f64,
    #[serde(default)]
    pub reverse_platform_us: f64,
    #[serde(default)]
    pub fin_us: f64,
    #[serde(default)]
    pub rst_us: f64,
    #[serde(default)]
    pub close_us: f64,
    #[serde(default)]
    pub nqa_score: u8,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TcpRtResponse {
    pub flows: Vec<TcpRtEntry>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TcpRtFlushResponse {
    pub flushed: u64,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "src_ip": "10.0.1.10",
    "dst_ip": "10.0.10.20",
    "src_port": 52344,
    "dst_port": 443
}))]
pub struct TcpRtQueryTuple {
    /// Client or source IP address.
    #[schema(example = "10.0.1.10")]
    pub src_ip: String,
    /// Server or destination IP address.
    #[schema(example = "10.0.10.20")]
    pub dst_ip: String,
    /// Client or source port.
    #[schema(example = 52344)]
    pub src_port: u16,
    /// Server or destination port.
    #[schema(example = 443)]
    pub dst_port: u16,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "tuples": [
        {
            "src_ip": "10.0.1.10",
            "dst_ip": "10.0.10.20",
            "src_port": 52344,
            "dst_port": 443
        },
        {
            "src_ip": "10.0.1.11",
            "dst_ip": "10.0.10.20",
            "src_port": 52345,
            "dst_port": 443
        }
    ]
}))]
pub struct TcpRtBatchQueryRequest {
    /// Tuples to query across all managed instances.
    pub tuples: Vec<TcpRtQueryTuple>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TcpRtInstanceEntry {
    pub instance: String,
    pub entry: TcpRtEntry,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TcpRtBatchQueryResponse {
    pub results: Vec<TcpRtInstanceEntry>,
}

// ── TCP-RT Filter (by service address) ──

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "dst_ip": "10.0.10.20",
    "dst_port": 443
}))]
pub struct TcpRtFilterRequest {
    /// Service IP address to aggregate by.
    #[schema(example = "10.0.10.20")]
    pub dst_ip: String,
    /// Service port to aggregate by.
    #[schema(example = 443)]
    pub dst_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TcpRtAggregatedEntry {
    pub instance: String,
    pub flow_count: u32,
    pub avg_rtt_client_us: f64,
    pub avg_rtt_server_us: f64,
    pub avg_art_us: f64,
    pub avg_handshake_us: f64,
    pub total_retrans_req: u32,
    pub total_retrans_resp: u32,
    #[serde(default)]
    pub avg_forward_platform_us: f64,
    #[serde(default)]
    pub avg_server_network_us: f64,
    #[serde(default)]
    pub avg_reverse_platform_us: f64,
    #[serde(default)]
    pub avg_nqa_score: f64,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TcpRtFilterResponse {
    pub dst_ip: String,
    pub dst_port: u16,
    pub instances: Vec<TcpRtAggregatedEntry>,
}

// ── TCP-RT Histogram ──

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TcpRtHistogramBucket {
    pub le_us: f64,
    pub count: u64,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TcpRtHistogramResponse {
    pub buckets: Vec<TcpRtHistogramBucket>,
    pub total: u64,
    pub sum_us: f64,
    pub p50_us: f64,
    pub p95_us: f64,
    pub p99_us: f64,
}

// ── TCP-RT States ──

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TcpRtStateCount {
    pub state: String,
    pub count: u64,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TcpRtStatesResponse {
    pub states: Vec<TcpRtStateCount>,
    pub total_flows: u64,
    pub anomalies: Vec<String>,
}

// ── Service Chain ──

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "tap": "tapfw0",
    "role": "in"
}))]
pub struct TapBindingEntry {
    /// Tap interface name bound to the hop.
    #[schema(example = "tapfw0")]
    pub tap: String,
    /// Logical role of the tap within the hop.
    #[schema(example = "in")]
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ServiceHopEntry {
    /// Friendly hop name.
    #[schema(example = "fw-west")]
    pub name: String,
    /// Hop type such as `bridge` or `proxy`.
    #[schema(example = "bridge")]
    pub hop_type: String,
    /// Tap bindings associated with the hop.
    pub taps: Vec<TapBindingEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "name": "frontend-to-db",
    "description": "Traffic chain from frontend to database",
    "hops": [
        {
            "name": "fw-west",
            "hop_type": "bridge",
            "taps": [{"tap": "tapfw0", "role": "in"}]
        }
    ]
}))]
pub struct ServiceChainEntry {
    /// Stable service chain name.
    #[schema(example = "frontend-to-db")]
    pub name: String,
    /// Optional operator-facing description.
    #[schema(example = "Traffic chain from frontend to database")]
    #[serde(default)]
    pub description: String,
    /// Ordered list of hops in the chain.
    pub hops: Vec<ServiceHopEntry>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ServiceChainListResponse {
    pub chains: Vec<ServiceChainEntry>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "name": "frontend-to-db",
    "description": "Traffic chain from frontend to database",
    "hops": [
        {
            "name": "fw-west",
            "hop_type": "bridge",
            "taps": [{"tap": "tapfw0", "role": "in"}]
        },
        {
            "name": "db-service",
            "hop_type": "proxy",
            "taps": [{"tap": "tapdb0", "role": "out"}]
        }
    ]
}))]
pub struct CreateServiceChainRequest {
    /// Stable service chain name.
    #[schema(example = "frontend-to-db")]
    pub name: String,
    /// Optional operator-facing description.
    #[schema(example = "Traffic chain from frontend to database")]
    #[serde(default)]
    pub description: String,
    /// Ordered list of hops in the chain.
    pub hops: Vec<ServiceHopEntry>,
}

// ── Drop Reason Profiler ──

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct DropStatsEntry {
    pub reason: String,
    pub direction: String,
    pub proto: String,
    pub src_group: String,
    pub src_id: u32,
    pub dst_group: String,
    pub dst_id: u32,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct DropStatsResponse {
    pub drops: Vec<DropStatsEntry>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct DropFlushResponse {
    pub flushed: u64,
}

// ── Kernel Drop Observability ──

#[derive(Debug, Clone, Serialize, Deserialize, Default, ToSchema)]
#[schema(example = json!({
    "instance": "eth0",
    "iface": "eth0",
    "ifindex": 2,
    "reason": 38,
    "top": 20,
    "include_unattributed": false
}))]
pub struct KernelDropQuery {
    /// Optional managed instance name filter.
    #[schema(example = "eth0")]
    pub instance: Option<String>,
    /// Optional interface name filter.
    #[schema(example = "eth0")]
    pub iface: Option<String>,
    /// Optional interface index filter.
    #[schema(example = 2)]
    pub ifindex: Option<u32>,
    /// Optional numeric kernel drop reason code filter.
    #[schema(example = 38)]
    pub reason: Option<u16>,
    /// Maximum number of aggregated results to return.
    #[schema(example = 20)]
    pub top: Option<usize>,
    /// Include drop entries that could not be mapped back to a managed instance.
    #[schema(example = false)]
    #[serde(default)]
    pub include_unattributed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct KernelDropStatsEntry {
    pub instance: Option<String>,
    pub iface: Option<String>,
    pub ifindex: u32,
    pub reason_code: Option<u16>,
    pub reason: String,
    pub proto: String,
    pub packets: u64,
    pub bytes: u64,
    pub last_seen_ns: u64,
    pub last_location: Option<u64>,
    pub location: Option<String>,
    pub location_hint: Option<String>,
    pub source: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct KernelDropStatsResponse {
    pub drops: Vec<KernelDropStatsEntry>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct KernelDropFlushResponse {
    pub flushed: u64,
}

// ── Packet Trace ──

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "src_ip": "10.0.1.10",
    "dst_ip": "10.0.10.20",
    "src_port": 52344,
    "dst_port": 443,
    "proto": "tcp"
}))]
pub struct TraceStartRequest {
    /// Source IP filter; empty string matches any source.
    #[schema(example = "10.0.1.10")]
    #[serde(default)]
    pub src_ip: String,
    /// Destination IP filter; empty string matches any destination.
    #[schema(example = "10.0.10.20")]
    #[serde(default)]
    pub dst_ip: String,
    /// Source port filter; `0` matches any source port.
    #[schema(example = 52344)]
    #[serde(default)]
    pub src_port: u16,
    /// Destination port filter; `0` matches any destination port.
    #[schema(example = 443)]
    #[serde(default)]
    pub dst_port: u16,
    /// Protocol filter such as `tcp`, `udp`, or empty string for any protocol.
    #[schema(example = "tcp")]
    #[serde(default)]
    pub proto: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TraceEventEntry {
    pub seq: u64,
    pub timestamp: u64,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: String,
    pub hook: String,
    pub result: String,
    pub direction: String,
    pub src_group: String,
    pub src_id: u32,
    pub dst_group: String,
    pub dst_id: u32,
    pub pkt_len: u32,
    pub ct_state: String,
    pub drop_reason: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TraceResponse {
    pub events: Vec<TraceEventEntry>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct TraceFlushResponse {
    pub flushed: u64,
}

// ── Helpers ──

// ── SSL Observability ──

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct SslConnEntry {
    pub seq: u64,
    pub pid: u32,
    pub tid: u32,
    pub handshake_us: f64,
    pub timestamp: u64,
    pub sni: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct SslListResponse {
    pub connections: Vec<SslConnEntry>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct SslFlushResponse {
    pub flushed: u64,
}

// ── SSL HTTP Observability ──

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SslHttpEntry {
    pub seq: u64,
    pub pid: u32,
    pub tid: u32,
    pub method: String,
    pub path: String,
    pub host: String,
    pub status_code: u16,
    pub latency_us: f64,
    pub request_ts: u64,
    pub response_ts: u64,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct SslHttpListResponse {
    pub events: Vec<SslHttpEntry>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct SslHttpFlushResponse {
    pub flushed: u64,
}

// ── Global SSL Observability Config ──
// SSL uprobe is process-level, not tied to any network interface

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "enabled": true
}))]
pub struct SslGlobalConfigResponse {
    /// Whether process-level SSL observability is enabled.
    #[schema(example = true)]
    pub enabled: bool,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "enabled": true
}))]
pub struct UpdateSslGlobalConfigRequest {
    /// Desired global SSL observability state.
    #[schema(example = true)]
    pub enabled: bool,
}

// ── SSL Error Events ──

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct SslErrorEntry {
    pub seq: u64,
    pub pid: u32,
    pub tid: u32,
    pub timestamp: u64,
    pub syscall: String,
    pub ret_code: i32,
    pub error_hint: String,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct SslErrorListResponse {
    pub errors: Vec<SslErrorEntry>,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct SslErrorFlushResponse {
    pub flushed: u64,
}

// ── Helpers (functions) ──

pub fn proto_to_string(proto: u8) -> String {
    match proto {
        0 => "any".to_string(),
        1 => "icmp".to_string(),
        6 => "tcp".to_string(),
        17 => "udp".to_string(),
        _ => format!("{}", proto),
    }
}

pub fn proto_from_string(proto: &str) -> Result<u8, String> {
    match proto.to_lowercase().as_str() {
        "tcp" => Ok(6),
        "udp" => Ok(17),
        "icmp" => Ok(1),
        "any" => Ok(0),
        _ => proto
            .parse::<u8>()
            .map_err(|_| format!("Invalid protocol '{}'", proto)),
    }
}

pub fn action_to_string(action: u8) -> String {
    match action {
        0 => "allow".to_string(),
        1 => "drop".to_string(),
        _ => format!("{}", action),
    }
}

pub fn action_from_string(action: &str) -> Result<u8, String> {
    match action.to_lowercase().as_str() {
        "accept" | "pass" | "allow" => Ok(0),
        "drop" | "deny" => Ok(1),
        _ => Err(format!("Invalid action '{}'", action)),
    }
}

pub fn direction_to_string(direction: u8) -> String {
    match direction {
        0 => "ingress".to_string(),
        1 => "egress".to_string(),
        _ => format!("{}", direction),
    }
}

pub fn direction_from_string(direction: &str) -> Result<u8, String> {
    match direction.to_lowercase().as_str() {
        "ingress" | "in" => Ok(0),
        "egress" | "out" => Ok(1),
        "both" | "all" => Ok(2),
        _ => Err(format!(
            "Invalid direction '{}': must be 'ingress', 'egress', or 'both'",
            direction
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::collections::BTreeSet;
    use std::sync::OnceLock;

    const STATUS_V1_SCENARIOS_JSON: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../docs/neutron-status-contract-v1-scenarios.json"
    ));

    static STATUS_V1_SCENARIOS: OnceLock<Value> = OnceLock::new();

    fn rust_status_v1_scenario_ids() -> &'static [&'static str] {
        &[
            "full-classified-ready",
            "scoped-classified-ready",
            "classified-degraded-terminal",
            "classified-degraded-full-resync",
            "pending-poll",
            "blocked-recoverable-inventory",
            "blocked-operator",
            "recovery-full-resync",
            "generation-zero-inventory-recovery",
            "restart-classified-routing",
        ]
    }

    fn shared_status_v1_scenarios() -> &'static Value {
        STATUS_V1_SCENARIOS.get_or_init(|| {
            let fixture: Value = serde_json::from_str(STATUS_V1_SCENARIOS_JSON)
                .expect("shared Status V1 scenarios must be valid JSON");
            assert_eq!(
                fixture
                    .get("fixture_schema_version")
                    .and_then(Value::as_u64),
                Some(1),
                "shared Status V1 fixture schema must be version 1"
            );

            let scenarios = fixture
                .get("scenarios")
                .and_then(Value::as_array)
                .expect("shared Status V1 scenarios must be an array");
            let mut fixture_ids = BTreeSet::new();
            for scenario in scenarios {
                let id = scenario
                    .get("id")
                    .and_then(Value::as_str)
                    .expect("every shared Status V1 scenario must have a string id");
                assert!(
                    fixture_ids.insert(id),
                    "shared Status V1 scenario id must be unique: {id}"
                );
            }

            let producer_ids = rust_status_v1_scenario_ids();
            assert_eq!(
                producer_ids.len(),
                10,
                "Rust Status V1 producer selection must contain exactly ten ids"
            );
            assert_eq!(
                producer_ids.iter().copied().collect::<BTreeSet<_>>().len(),
                producer_ids.len(),
                "Rust Status V1 producer ids must be unique"
            );
            for id in producer_ids {
                assert!(
                    fixture_ids.contains(id),
                    "Rust Status V1 producer scenario must exist: {id}"
                );
            }
            drop(fixture_ids);

            fixture
        })
    }

    fn shared_status_v1_scenario(id: &str) -> &'static Value {
        let matches = shared_status_v1_scenarios()
            .get("scenarios")
            .and_then(Value::as_array)
            .expect("shared Status V1 scenarios must be an array")
            .iter()
            .filter(|scenario| scenario.get("id").and_then(Value::as_str) == Some(id))
            .collect::<Vec<_>>();
        assert_eq!(
            matches.len(),
            1,
            "shared Status V1 scenario id must match exactly once: {id}"
        );
        matches[0]
    }

    fn assert_json_matches_fixture(
        scenario_id: &str,
        expected: &Value,
        actual: &Value,
    ) -> Result<(), String> {
        if actual == expected {
            Ok(())
        } else {
            Err(format!(
                "{scenario_id}: expected exact shared Status V1 payload\nexpected: {expected}\n  actual: {actual}"
            ))
        }
    }

    fn normalize_pre_v1_managed_port_defaults(expected: &Value, actual: &mut Value) {
        // The shared fixture omits these legacy Serde defaults; remove only their
        // null/empty encodings so the exact comparison isolates Status V1 drift.
        let Some(expected_ports) = expected.get("managed_ports").and_then(Value::as_array) else {
            return;
        };
        let Some(actual_ports) = actual
            .get_mut("managed_ports")
            .and_then(Value::as_array_mut)
        else {
            return;
        };

        for actual_port in actual_ports {
            let Some(actual_object) = actual_port.as_object_mut() else {
                continue;
            };
            let Some(port_id) = actual_object
                .get("port_id")
                .and_then(Value::as_str)
                .map(str::to_string)
            else {
                continue;
            };
            let Some(expected_object) = expected_ports
                .iter()
                .find(|port| port.get("port_id").and_then(Value::as_str) == Some(port_id.as_str()))
                .and_then(Value::as_object)
            else {
                continue;
            };

            if !expected_object.contains_key("ifindex")
                && actual_object.get("ifindex").is_some_and(Value::is_null)
            {
                actual_object.remove("ifindex");
            }
            if !expected_object.contains_key("domain_desired_hashes")
                && actual_object
                    .get("domain_desired_hashes")
                    .and_then(Value::as_object)
                    .is_some_and(serde_json::Map::is_empty)
            {
                actual_object.remove("domain_desired_hashes");
            }
        }
    }

    #[test]
    fn instance_info_reports_acl_and_xdp_health_independently() {
        let value = serde_json::to_value(InstanceInfo {
            name: "tap0".to_string(),
            active: true,
            acl_ready: true,
            xdp_ready: false,
            readiness_reason: Some("xdp_ddos_hook_unavailable".to_string()),
            cleanup_pending_count: 0,
            maintenance_reason: None,
        })
        .unwrap();
        assert_eq!(value["acl_ready"], true);
        assert_eq!(value["xdp_ready"], false);

        let legacy: InstanceInfo =
            serde_json::from_value(serde_json::json!({"name": "tap0", "active": true}))
                .unwrap();
        assert!(!legacy.acl_ready);
        assert!(!legacy.xdp_ready);
        assert_eq!(legacy.readiness_reason, None);
    }

    #[test]
    fn instance_info_reports_bitmap_cleanup_debt_without_lowering_acl_readiness() {
        let value = serde_json::json!({
            "name": "system",
            "active": true,
            "acl_ready": true,
            "xdp_ready": true,
            "readiness_reason": null,
            "cleanup_pending_count": 1,
            "maintenance_reason": "bitmap_cleanup_pending"
        });

        let info: InstanceInfo = serde_json::from_value(value).unwrap();

        assert!(info.acl_ready);
        assert_eq!(info.cleanup_pending_count, 1);
        assert_eq!(
            info.maintenance_reason.as_deref(),
            Some("bitmap_cleanup_pending")
        );
    }

    #[test]
    fn neutron_contract_capabilities_are_stable() {
        let capabilities = NeutronCapabilitiesResponse::current();
        let expected_domains: Vec<String> = NEUTRON_SUPPORTED_DOMAINS
            .iter()
            .map(|domain| (*domain).to_string())
            .collect();

        assert_eq!(capabilities.api_version, NEUTRON_UDS_API_VERSION);
        assert_eq!(capabilities.contract_version, NEUTRON_UDS_CONTRACT_VERSION);
        assert_eq!(
            capabilities.schema_version_min,
            NEUTRON_UDS_SCHEMA_VERSION_MIN
        );
        assert_eq!(
            capabilities.schema_version_max,
            NEUTRON_UDS_SCHEMA_VERSION_MAX
        );
        assert_eq!(capabilities.attach_authority, NEUTRON_ATTACH_AUTHORITY);
        assert!(capabilities.supports_full_snapshot);
        assert!(capabilities.supports_port_scoped_snapshot);
        assert!(capabilities.supports_port_delete);
        assert_eq!(capabilities.supported_domains, expected_domains);
        assert!(capabilities.mandatory_domains.is_empty());
        assert_eq!(capabilities.body_max_bytes, NEUTRON_UDS_BODY_MAX_BYTES);
        assert_eq!(capabilities.timeout_ms, NEUTRON_UDS_TIMEOUT_MS);
        assert_eq!(capabilities.error_codes_hash, NEUTRON_UDS_ERROR_CODES_HASH);
        assert_eq!(capabilities.peer_auth_policy, NEUTRON_UDS_PEER_AUTH_POLICY);
        assert_eq!(capabilities.capability_hash, NEUTRON_UDS_CAPABILITY_HASH);
    }

    #[test]
    fn snapshot_generation_retry_contract_v2_capabilities_are_exact() {
        let capabilities = serde_json::to_value(NeutronCapabilitiesResponse::current())
            .expect("current Neutron capabilities must serialize");

        assert_eq!(capabilities["status_schema_version_min"], 2);
        assert_eq!(capabilities["status_schema_version_max"], 2);
        assert_eq!(
            capabilities["status_contract_hash"],
            "v0.9-neutron-status-2"
        );
        assert_eq!(
            capabilities["error_codes_hash"],
            "v0.9-neutron-errors-3"
        );
        assert_eq!(
            capabilities["capability_hash"],
            "v0.9-neutron-capabilities-4"
        );
    }

    #[test]
    fn neutron_contract_status_v1_capabilities_serialize_shared_metadata() {
        let fixture = shared_status_v1_scenarios();
        let declared_contract = fixture
            .get("status_contract")
            .and_then(Value::as_object)
            .expect("shared Status V1 contract declaration must be an object");
        let fixture_capabilities = shared_status_v1_scenario("full-classified-ready")
            .get("capabilities")
            .and_then(Value::as_object)
            .expect("full classified-ready capabilities must be an object");

        assert_eq!(
            fixture_capabilities.get("status_schema_version_min"),
            declared_contract.get("version"),
            "Status V1 capability minimum must match the shared contract version"
        );
        assert_eq!(
            fixture_capabilities.get("status_schema_version_max"),
            declared_contract.get("version"),
            "Status V1 capability maximum must match the shared contract version"
        );
        assert_eq!(
            fixture_capabilities.get("status_contract_hash"),
            declared_contract.get("hash"),
            "Status V1 capability hash must match the shared contract hash"
        );

        let actual = serde_json::to_value(NeutronCapabilitiesResponse::current())
            .expect("current Neutron capabilities must serialize");
        assert_eq!(
            actual.get("contract_version"),
            fixture_capabilities.get("contract_version"),
            "additive Status V1 metadata must not change the global contract version"
        );
        assert_eq!(
            actual.get("contract_version").and_then(Value::as_str),
            Some(NEUTRON_UDS_CONTRACT_VERSION)
        );
        assert_eq!(
            actual.get("capability_hash").and_then(Value::as_str),
            Some(NEUTRON_UDS_CAPABILITY_HASH),
            "additive Status V1 metadata must not change the global capability hash"
        );
        assert_eq!(
            NEUTRON_UDS_CAPABILITY_HASH, "v0.9-neutron-capabilities-3",
            "the additive Status V1 rollout must retain the pre-V1 capability hash"
        );

        let mut mismatches = Vec::new();
        for field in [
            "status_schema_version_min",
            "status_schema_version_max",
            "status_contract_hash",
        ] {
            if actual.get(field) != fixture_capabilities.get(field) {
                mismatches.push(format!(
                    "{field}: expected {:?}, got {:?}",
                    fixture_capabilities.get(field),
                    actual.get(field)
                ));
            }
        }
        let mut legacy_payload = actual.clone();
        let legacy_object = legacy_payload
            .as_object_mut()
            .expect("serialized Neutron capabilities must be an object");
        for field in [
            "status_schema_version_min",
            "status_schema_version_max",
            "status_contract_hash",
        ] {
            legacy_object.remove(field);
        }
        let legacy_decoded: NeutronCapabilitiesResponse = serde_json::from_value(legacy_payload)
            .expect("capabilities without Status V1 metadata must remain decodable");
        assert_eq!(legacy_decoded.status_schema_version_min, 0);
        assert_eq!(legacy_decoded.status_schema_version_max, 0);
        assert!(legacy_decoded.status_contract_hash.is_empty());
        assert!(
            mismatches.is_empty(),
            "current capabilities do not advertise the shared Status V1 metadata:\n{}",
            mismatches.join("\n")
        );
    }

    #[test]
    fn neutron_contract_status_v1_response_serialization_matches_shared_scenarios() {
        let mut mismatches = Vec::new();
        let legacy_expected = shared_status_v1_scenario("legacy-v0-ready")
            .get("status")
            .expect("legacy V0 scenario must include a status response");
        let legacy_decoded: NeutronStatusResponse = serde_json::from_value(legacy_expected.clone())
            .expect("legacy V0 status must remain decodable through the legacy response type");
        let legacy_row: &NeutronPortStatus = legacy_decoded
            .port_statuses
            .first()
            .expect("legacy V0 status must retain its legacy nested row type");
        assert_eq!(legacy_row.port_id, "legacy-port");

        for id in rust_status_v1_scenario_ids() {
            let expected = shared_status_v1_scenario(id)
                .get("status")
                .filter(|status| status.is_object())
                .unwrap_or_else(|| {
                    panic!("Rust Status V1 producer scenario must have status: {id}")
                });
            for field in [
                "status_schema_version",
                "status_contract_hash",
                "transaction_state",
                "overall_readiness",
                "required_action",
                "recovery_cause",
                "last_classified_generation",
            ] {
                assert!(
                    expected.get(field).is_some(),
                    "Rust Status V1 producer scenario {id} must declare {field}"
                );
            }
            assert_eq!(
                expected.get("generation"),
                expected.get("applied_generation"),
                "Status V1 generation must remain an applied_generation alias: {id}"
            );
            for port_status in expected
                .get("port_statuses")
                .and_then(Value::as_array)
                .unwrap_or_else(|| panic!("Status V1 port_statuses must be an array: {id}"))
            {
                for domain in port_status
                    .get("domains")
                    .and_then(Value::as_array)
                    .unwrap_or_else(|| panic!("Status V1 domains must be an array: {id}"))
                {
                    assert!(
                        domain.get("support_disposition").is_some(),
                        "Status V1 domain evidence must include support_disposition: {id}"
                    );
                }
            }

            let decoded: NeutronStatusV1Response = serde_json::from_value(expected.clone())
                .unwrap_or_else(|error| {
                    panic!("shared Status V1 response must deserialize for {id}: {error}")
                });
            let mut actual = serde_json::to_value(decoded).unwrap_or_else(|error| {
                panic!("shared Status V1 response must reserialize for {id}: {error}")
            });
            normalize_pre_v1_managed_port_defaults(expected, &mut actual);
            if let Err(mismatch) = assert_json_matches_fixture(id, expected, &actual) {
                mismatches.push(mismatch);
            }
        }

        assert!(
            mismatches.is_empty(),
            "Neutron Status V1 response serialization drifted from the shared scenarios:\n{}",
            mismatches.join("\n\n")
        );
    }

    #[test]
    fn neutron_contract_snapshot_roundtrip_preserves_managed_domains() {
        let snapshot = NeutronSnapshotRequest {
            schema_version: Some(1),
            generation: 42,
            desired_hash: Some("hash-42".to_string()),
            host: Some("compute-1.example.test".to_string()),
            ports: vec![NeutronPortSnapshot {
                port_id: "e607e86b-9e5f-4c63-a5df-3dc8986a1b0f".to_string(),
                ifname: "tape607e86b-9e".to_string(),
                ifindex: Some(27),
                eligible: true,
                disposition: Some("eligible_ovs_tap".to_string()),
                device_owner: Some("compute:nova".to_string()),
                vif_type: Some("ovs".to_string()),
                vnic_type: Some("normal".to_string()),
                network_backend: Some("openvswitch".to_string()),
                ovs_iface_id: Some("e607e86b-9e5f-4c63-a5df-3dc8986a1b0f".to_string()),
                managed_domains: vec!["acl".to_string(), "mirror".to_string()],
                acl: Some(NeutronAclSnapshot {
                    enabled: true,
                    status: "ready".to_string(),
                    reason: "ready".to_string(),
                    effective_action: "enforce".to_string(),
                    policy_id: Some("acl-policy-1".to_string()),
                    policy_name: Some("smoke".to_string()),
                    binding_id: Some("acl-binding-1".to_string()),
                    source: Some("port".to_string()),
                    default_action: "allow".to_string(),
                    stateful: true,
                    revision: 7,
                    rules: vec![NeutronAclRuleSnapshot {
                        id: Some("rule-1".to_string()),
                        direction: Some("ingress".to_string()),
                        priority: 100,
                        action: Some("drop".to_string()),
                        ethertype: Some("IPv4".to_string()),
                        protocol: Some("icmp".to_string()),
                        src_cidrs: vec!["192.0.2.2/32".to_string()],
                        dst_cidrs: Vec::new(),
                        src_port_min: None,
                        src_port_max: None,
                        dst_port_min: None,
                        dst_port_max: None,
                    }],
                }),
                qos: None,
                mirror: Some(serde_json::json!({
                    "enabled": true,
                    "mode": "global_l2"
                })),
            }],
        };

        let encoded = serde_json::to_string(&snapshot).expect("snapshot should serialize");
        let decoded: NeutronSnapshotRequest =
            serde_json::from_str(&encoded).expect("snapshot should deserialize");

        assert_eq!(decoded, snapshot);
        assert_eq!(decoded.desired_hash.as_deref(), Some("hash-42"));
        assert_eq!(decoded.ports[0].managed_domains, vec!["acl", "mirror"]);
    }

    #[test]
    fn neutron_contract_defaults_are_backward_compatible() {
        let decoded: NeutronSnapshotRequest =
            serde_json::from_str(r#"{"ports":[{"port_id":"port-1"}]}"#)
                .expect("minimal snapshot should deserialize");

        assert_eq!(decoded.generation, 0);
        assert_eq!(decoded.schema_version, None);
        assert_eq!(decoded.desired_hash, None);
        assert_eq!(decoded.host, None);
        assert_eq!(decoded.ports.len(), 1);

        let port = &decoded.ports[0];
        assert_eq!(port.port_id, "port-1");
        assert_eq!(port.ifname, "");
        assert_eq!(port.ifindex, None);
        assert!(!port.eligible);
        assert_eq!(port.disposition, None);
        assert_eq!(port.device_owner, None);
        assert_eq!(port.vif_type, None);
        assert_eq!(port.vnic_type, None);
        assert_eq!(port.network_backend, None);
        assert_eq!(port.ovs_iface_id, None);
        assert!(port.managed_domains.is_empty());
        assert_eq!(port.acl, None);
        assert_eq!(port.qos, None);
        assert_eq!(port.mirror, None);
    }
}
