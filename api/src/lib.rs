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

fn default_mode_string() -> String {
    "policing".to_string()
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
    #[serde(default = "default_mode_string")]
    pub mode: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct QosListResponse {
    pub rules: Vec<QosEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddQosRequest {
    pub group: String,
    pub direction: String,
    pub rate: String,
    #[serde(default)]
    pub burst: String,
    #[serde(default)]
    pub priority: u8,
    #[serde(default = "default_mode_string")]
    pub mode: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteQosRequest {
    pub group: String,
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
    pub acl: bool,
    pub qos: bool,
    pub mirror: bool,
    pub tcprt: bool,
    pub num_cpus: u16,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateConfigRequest {
    pub conntrack: Option<bool>,
    pub monitoring: Option<bool>,
    pub acl: Option<bool>,
    pub qos: Option<bool>,
    pub mirror: Option<bool>,
    pub tcprt: Option<bool>,
}

// ── Stats ──

#[derive(Debug, Serialize, Deserialize)]
pub struct StatsOverview {
    pub groups: usize,
    pub policies: usize,
    pub qos_rules: usize,
    pub mirror_rules: usize,
    pub conntrack_v4: u64,
    pub conntrack_v6: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RuleStatsEntry {
    pub src_group: String,
    pub src_id: u32,
    pub dst_group: String,
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

// --- QoS Statistics ---

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
pub struct QosStatsResponse {
    pub rules: Vec<QosStatsEntry>,
}

// --- Per-Group Statistics ---

#[derive(Debug, Serialize, Deserialize)]
pub struct GroupStatsEntry {
    pub group: String,
    pub group_id: u32,
    pub direction: String,
    pub packets: u64,
    pub bytes: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GroupStatsResponse {
    pub groups: Vec<GroupStatsEntry>,
}

// ── Mirror ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirrorEntry {
    pub src_group: String,
    pub src_group_id: u32,
    pub dst_group: String,
    pub dst_group_id: u32,
    pub proto: String,
    pub direction: String,
    pub target_iface: String,
    pub target_ifindex: u32,
    pub is_global: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MirrorListResponse {
    pub rules: Vec<MirrorEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AddMirrorRequest {
    #[serde(default = "default_any")]
    pub src_group: String,
    #[serde(default = "default_any")]
    pub dst_group: String,
    #[serde(default = "default_any_proto")]
    pub proto: String,
    pub direction: String,
    pub target: String,
}

fn default_any() -> String {
    "any".to_string()
}

fn default_any_proto() -> String {
    "any".to_string()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteMirrorRequest {
    #[serde(default = "default_any")]
    pub src_group: String,
    #[serde(default = "default_any")]
    pub dst_group: String,
    #[serde(default = "default_any_proto")]
    pub proto: String,
    pub direction: String,
}

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
pub struct MirrorStatsResponse {
    pub rules: Vec<MirrorStatsEntry>,
}

// ── TCP-RT ──

#[derive(Debug, Serialize, Deserialize)]
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
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TcpRtResponse {
    pub flows: Vec<TcpRtEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TcpRtFlushResponse {
    pub flushed: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TcpRtQueryTuple {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TcpRtBatchQueryRequest {
    pub tuples: Vec<TcpRtQueryTuple>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TcpRtInstanceEntry {
    pub instance: String,
    pub entry: TcpRtEntry,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TcpRtBatchQueryResponse {
    pub results: Vec<TcpRtInstanceEntry>,
}

// ── TCP-RT Filter (by service address) ──

#[derive(Debug, Serialize, Deserialize)]
pub struct TcpRtFilterRequest {
    pub dst_ip: String,
    pub dst_port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpRtAggregatedEntry {
    pub instance: String,
    pub flow_count: u32,
    pub avg_rtt_client_us: f64,
    pub avg_rtt_server_us: f64,
    pub avg_art_us: f64,
    pub avg_handshake_us: f64,
    pub total_retrans_req: u32,
    pub total_retrans_resp: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TcpRtFilterResponse {
    pub dst_ip: String,
    pub dst_port: u16,
    pub instances: Vec<TcpRtAggregatedEntry>,
}

// ── Service Chain ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TapBindingEntry {
    pub tap: String,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceHopEntry {
    pub name: String,
    pub hop_type: String,
    pub taps: Vec<TapBindingEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceChainEntry {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub hops: Vec<ServiceHopEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ServiceChainListResponse {
    pub chains: Vec<ServiceChainEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateServiceChainRequest {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub hops: Vec<ServiceHopEntry>,
}

// ── Drop Reason Profiler ──

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
pub struct DropStatsResponse {
    pub drops: Vec<DropStatsEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DropFlushResponse {
    pub flushed: u64,
}

// ── Packet Trace ──

#[derive(Debug, Serialize, Deserialize)]
pub struct TraceStartRequest {
    #[serde(default)]
    pub src_ip: String,
    #[serde(default)]
    pub dst_ip: String,
    #[serde(default)]
    pub src_port: u16,
    #[serde(default)]
    pub dst_port: u16,
    #[serde(default)]
    pub proto: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
pub struct TraceResponse {
    pub events: Vec<TraceEventEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TraceFlushResponse {
    pub flushed: u64,
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
        _ => proto.parse::<u8>().map_err(|_| format!("Invalid protocol '{}'", proto)),
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
        _ => Err(format!("Invalid direction '{}': must be 'ingress', 'egress', or 'both'", direction)),
    }
}
