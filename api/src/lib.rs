use serde::{Deserialize, Serialize};
use std::fmt;

// ── Error ──

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiError {
    pub code: u16,
    pub error: String,
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.error)
    }
}

// ── Health ──

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub instances: usize,
}

// ── Instances ──

#[derive(Debug, Serialize, Deserialize)]
pub struct InstanceInfo {
    pub name: String,
    pub active: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InstancesResponse {
    pub instances: Vec<InstanceInfo>,
}

// ── System ──

#[derive(Debug, Serialize, Deserialize)]
pub struct SystemStartRequest {
    pub iface: String,
    #[serde(default = "default_max_port_policies")]
    pub max_port_policies: u32,
}

fn default_max_port_policies() -> u32 {
    16384
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MessageResponse {
    pub message: String,
}

// ── Groups ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupEntry {
    pub id: u32,
    pub name: String,
    pub cidrs: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GroupsResponse {
    pub groups: Vec<GroupEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddGroupRequest {
    pub name: String,
    pub cidr: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddGroupResponse {
    pub id: u32,
    pub name: String,
}

// ── Policies ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEntry {
    pub src_group: String,
    pub src_group_id: u32,
    pub dst_group: String,
    pub dst_group_id: u32,
    pub proto: String,
    pub action: String,
    pub direction: String,
    pub ports: Option<String>,
    pub bitmap_idx: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PoliciesResponse {
    pub policies: Vec<PolicyEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddPolicyRequest {
    pub src_group: String,
    pub dst_group: String,
    pub proto: String,
    pub action: String,
    #[serde(default = "default_direction")]
    pub direction: String,
    pub ports: Option<String>,
}

fn default_direction() -> String {
    "ingress".to_string()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeletePolicyRequest {
    pub src_group: String,
    pub dst_group: String,
    pub proto: String,
    #[serde(default = "default_direction")]
    pub direction: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchAddPoliciesRequest {
    pub policies: Vec<AddPolicyRequest>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchPoliciesResponse {
    pub added: usize,
    pub errors: Vec<String>,
}

// ── QoS ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QosEntry {
    pub group: String,
    pub group_id: u32,
    pub direction: String,
    pub rate_bps: u64,
    pub burst_bytes: u64,
    pub priority: u8,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QosListResponse {
    pub rules: Vec<QosEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddQosRequest {
    pub group: String,
    #[serde(default = "default_direction")]
    pub direction: String,
    pub rate: String,
    #[serde(default)]
    pub burst: String,
    #[serde(default)]
    pub priority: u8,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteQosRequest {
    pub group: String,
    #[serde(default = "default_direction")]
    pub direction: String,
}

// ── Conntrack ──

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
pub struct ConntrackResponse {
    pub connections: Vec<ConntrackEntry>,
    pub total: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConntrackFlushResponse {
    pub flushed: u64,
}

// ── Config ──

#[derive(Debug, Serialize, Deserialize)]
pub struct ConfigResponse {
    pub conntrack: bool,
    pub monitoring: bool,
    pub qos: bool,
    pub num_cpus: u16,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateConfigRequest {
    pub conntrack: Option<bool>,
    pub monitoring: Option<bool>,
}

// ── Stats ──

#[derive(Debug, Serialize, Deserialize)]
pub struct StatsOverview {
    pub groups: usize,
    pub policies: usize,
    pub qos_rules: usize,
    pub conntrack_v4: u64,
    pub conntrack_v6: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RuleStatsEntry {
    pub src_id: u32,
    pub dst_id: u32,
    pub proto: String,
    pub direction: String,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RuleStatsResponse {
    pub rules: Vec<RuleStatsEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FlowEntry {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: String,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FlowStatsResponse {
    pub flows: Vec<FlowEntry>,
}

// ── Helpers ──

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
        _ => Err(format!("Invalid protocol '{}'", proto)),
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
        _ => Err(format!("Invalid direction '{}': must be 'ingress' or 'egress'", direction)),
    }
}
