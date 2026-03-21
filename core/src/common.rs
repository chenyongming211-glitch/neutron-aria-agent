use aya::Pod;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct PolicyKey {
    pub src_id: u32,
    pub dst_id: u32,
    pub proto: u8,
    pub direction: u8,     // 0=ingress, 1=egress
    pub pad: [u8; 2],
}
unsafe impl Pod for PolicyKey {}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct PolicyValue {
    pub action: u8,
    pub has_port_filter: u8,
    pub pad1: [u8; 2],
    pub bitmap_idx: u32,
}
unsafe impl Pod for PolicyValue {}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct PortKey {
    pub idx: u32,
    pub port: u16,
    pub pad: u16,
}
unsafe impl Pod for PortKey {}

// --- Connection tracking ---

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct CtKey4 {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub pad: [u8; 3],
}
unsafe impl Pod for CtKey4 {}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct CtKey6 {
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub pad: [u8; 3],
}
unsafe impl Pod for CtKey6 {}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct CtValue {
    pub state: u8,
    pub flags: u8,
    pub direction: u8,
    pub matched_proto: u8,
    pub matched_src_id: u32,
    pub matched_dst_id: u32,
    pub last_seen: u64,
    pub pkt_count: u64,
    pub byte_count: u64,
}
unsafe impl Pod for CtValue {}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct CtConfig {
    pub tcp_established_ns: u64,
    pub tcp_new_ns: u64,
    pub udp_ns: u64,
    pub icmp_ns: u64,
}
unsafe impl Pod for CtConfig {}

// --- Traffic statistics ---

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct RuleStatsValue {
    pub packets: u64,
    pub bytes: u64,
    pub dropped_packets: u64,
    pub dropped_bytes: u64,
}
unsafe impl Pod for RuleStatsValue {}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct FlowStatsValue {
    pub packets: u64,
    pub bytes: u64,
    pub last_seen: u64,
}
unsafe impl Pod for FlowStatsValue {}

// --- QoS ---

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct QosKey {
    pub group_id: u32,
    pub direction: u8,
    pub pad: [u8; 3],
}
unsafe impl Pod for QosKey {}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct QosConfig {
    pub rate_bps: u64,
    pub burst_bytes: u64,
    pub priority: u8,
    pub mode: u8,            // 0=policing, 1=shaping
    pub pad: [u8; 6],
}
unsafe impl Pod for QosConfig {}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct TokenBucket {
    pub tokens: u64,
    pub last_refill_ns: u64,
    pub last_edt: u64,
}
unsafe impl Pod for TokenBucket {}

// --- QoS statistics ---

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct QosStatsValue {
    pub passed_packets: u64,
    pub passed_bytes: u64,
    pub dropped_packets: u64,
    pub dropped_bytes: u64,
    pub shaped_packets: u64,
    pub shaped_bytes: u64,
}
unsafe impl Pod for QosStatsValue {}

// --- Per-group statistics ---

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct GroupStatsKey {
    pub group_id: u32,
    pub direction: u8,
    pub pad: [u8; 3],
}
unsafe impl Pod for GroupStatsKey {}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct GroupStatsValue {
    pub packets: u64,
    pub bytes: u64,
}
unsafe impl Pod for GroupStatsValue {}

// --- Mirror (Port SPAN) ---

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct MirrorKey {
    pub src_id: u32,
    pub dst_id: u32,
    pub proto: u8,
    pub direction: u8,
    pub pad: [u8; 2],
}
unsafe impl Pod for MirrorKey {}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct GlobalMirrorKey {
    pub direction: u8,
    pub pad: [u8; 3],
}
unsafe impl Pod for GlobalMirrorKey {}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct MirrorConfig {
    pub target_ifindex: u32,
}
unsafe impl Pod for MirrorConfig {}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct MirrorStatsValue {
    pub mirrored_packets: u64,
    pub mirrored_bytes: u64,
    pub errors: u64,
}
unsafe impl Pod for MirrorStatsValue {}

// --- TCP-RT (TCP Response Time) ---

/// TCP-RT per-flow tracking state (mirrors ebpf/src/common.rs TcpRtValue)
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct TcpRtValue {
    pub syn_ts: u64,
    pub synack_ts: u64,
    pub ack_ts: u64,
    pub last_request_ts: u64,
    pub first_response_ts: u64,
    pub handshake_ns: u64,
    pub rtt_client_ns: u64,
    pub rtt_server_ns: u64,
    pub art_ns: u64,
    pub syn_ingress_ts: u64,
    pub synack_ingress_ts: u64,
    pub retrans_req: u32,
    pub retrans_resp: u32,
    pub request_count: u32,
    pub state: u8,
    pub flags: u8,
    pub pad: [u8; 2],
    pub last_seq: u32,
    pub last_payload_len: u16,
    pub prev_seq: u32,
    pub prev_payload_len: u16,
    pub last_resp_seq: u32,
    pub last_resp_payload_len: u16,
    pub prev_resp_seq: u32,
    pub prev_resp_payload_len: u16,
    pub _pad2: [u8; 6],
    pub fin_ts: u64,
    pub rst_ts: u64,
    pub close_ts: u64,
}
unsafe impl Pod for TcpRtValue {}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct FirewallConfig {
    pub conntrack_enabled: u8,
    pub monitoring_enabled: u8,
    pub num_cpus: u16,
    pub qos_enabled: u8,
    pub acl_enabled: u8,
    pub mirror_enabled: u8,
    pub tcprt_enabled: u8,
    pub ssl_enabled: u8,
}
unsafe impl Pod for FirewallConfig {}

// --- SSL Observability ---

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct SslScratch {
    pub ssl_ptr: u64,
    pub start_ts: u64,
}
unsafe impl Pod for SslScratch {}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct SslConnValue {
    pub pid: u32,
    pub tid: u32,
    pub handshake_ns: u64,
    pub timestamp: u64,
    pub sni: [u8; 64],
}
unsafe impl Pod for SslConnValue {}

// --- SSL HTTP Observability ---

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct SslHttpValue {
    pub pid: u32,
    pub tid: u32,
    pub request_ts: u64,
    pub response_ts: u64,
    pub latency_ns: u64,
    pub status_code: u16,
    pub _pad: [u8; 6],
    pub req_data: [u8; 256],  // raw HTTP request header (was 128)
}
unsafe impl Pod for SslHttpValue {}

// --- Drop Reason Profiler ---

pub const DROP_ACL_DENY: u8 = 1;
pub const DROP_ACL_PORT_DENY: u8 = 2;
pub const DROP_ACL_DEFAULT_DENY: u8 = 3;
pub const DROP_QOS_INGRESS: u8 = 4;
pub const DROP_QOS_EGRESS: u8 = 5;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct DropKey {
    pub reason: u8,
    pub direction: u8,
    pub proto: u8,
    pub pad: u8,
    pub src_id: u32,
    pub dst_id: u32,
}
unsafe impl Pod for DropKey {}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct DropValue {
    pub packets: u64,
    pub bytes: u64,
    pub last_seen: u64,
}
unsafe impl Pod for DropValue {}

// --- Packet Trace ---

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct TraceFilter {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_ip_v6: [u8; 16],
    pub dst_ip_v6: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub enabled: u8,
    pub is_ipv6: u8,        // 0=IPv4, 1=IPv6, 2=both
    pub pad: [u8; 1],
}
unsafe impl Pod for TraceFilter {}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct TraceEvent {
    pub timestamp: u64,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub hook: u8,
    pub result: u8,
    pub direction: u8,
    pub src_id: u32,
    pub dst_id: u32,
    pub pkt_len: u32,
    pub ct_state: u8,
    pub drop_reason: u8,
    pub pad: [u8; 2],
}
unsafe impl Pod for TraceEvent {}

pub const CT_NEW: u8 = 1;
pub const CT_ESTABLISHED: u8 = 2;
pub const DIR_INGRESS: u8 = 0;
pub const DIR_EGRESS: u8 = 1;
