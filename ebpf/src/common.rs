#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct PolicyKey {
    pub src_id: u32,
    pub dst_id: u32,
    pub proto: u8,
    pub direction: u8,     // 0=ingress, 1=egress
    pub pad: [u8; 2],
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct PolicyValue {
    pub action: u8,
    pub has_port_filter: u8,
    pub pad1: [u8; 2],
    pub bitmap_idx: u32,
}

pub const XDP_PASS: u32 = 2;
pub const XDP_DROP: u32 = 1;

pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;
pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_ICMPV6: u8 = 58;

pub const DIR_INGRESS: u8 = 0;
pub const DIR_EGRESS: u8 = 1;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct PortKey {
    pub idx: u32,
    pub port: u16,
    pub pad: u16,
}

// --- Connection tracking ---

#[repr(C)]
#[derive(Copy, Clone)]
pub struct CtKey4 {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub pad: [u8; 3],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct CtKey6 {
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub pad: [u8; 3],
}

pub const CT_NEW: u8 = 1;
pub const CT_ESTABLISHED: u8 = 2;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct CtValue {
    pub state: u8,
    pub flags: u8,          // bit 0: seen_reply
    pub direction: u8,      // direction of the matched policy rule
    pub matched_proto: u8,  // proto of the matched policy rule (0 = wildcard)
    pub matched_src_id: u32,
    pub matched_dst_id: u32,
    pub last_seen: u64,
    pub pkt_count: u64,
    pub byte_count: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct CtConfig {
    pub tcp_established_ns: u64,
    pub tcp_new_ns: u64,
    pub udp_ns: u64,
    pub icmp_ns: u64,
}

// --- Traffic statistics ---

#[repr(C)]
#[derive(Copy, Clone)]
pub struct RuleStatsValue {
    pub packets: u64,
    pub bytes: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FlowStatsValue {
    pub packets: u64,
    pub bytes: u64,
    pub last_seen: u64,
}

// --- QoS ---

#[repr(C)]
#[derive(Copy, Clone)]
pub struct QosKey {
    pub group_id: u32,
    pub direction: u8,
    pub pad: [u8; 3],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct QosConfig {
    pub rate_bps: u64,
    pub burst_bytes: u64,
    pub priority: u8,
    pub mode: u8,            // 0=policing, 1=shaping
    pub pad: [u8; 6],
}

/// Token bucket for QoS rate limiting (shared across CPUs, lock-free).
/// Layout: tokens(8) + last_refill_ns(8) + last_edt(8) = 24 bytes.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct TokenBucket {
    pub tokens: u64,
    pub last_refill_ns: u64,
    pub last_edt: u64,
}

// --- QoS statistics ---

#[repr(C)]
#[derive(Copy, Clone)]
pub struct QosStatsValue {
    pub passed_packets: u64,
    pub passed_bytes: u64,
    pub dropped_packets: u64,
    pub dropped_bytes: u64,
    pub shaped_packets: u64,
    pub shaped_bytes: u64,
}

// --- Per-group statistics ---

#[repr(C)]
#[derive(Copy, Clone)]
pub struct GroupStatsKey {
    pub group_id: u32,
    pub direction: u8,
    pub pad: [u8; 3],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct GroupStatsValue {
    pub packets: u64,
    pub bytes: u64,
}

// --- Mirror (Port SPAN) ---

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MirrorKey {
    pub src_id: u32,
    pub dst_id: u32,
    pub proto: u8,
    pub direction: u8,
    pub pad: [u8; 2],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct GlobalMirrorKey {
    pub direction: u8,
    pub pad: [u8; 3],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MirrorConfig {
    pub target_ifindex: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MirrorStatsValue {
    pub mirrored_packets: u64,
    pub mirrored_bytes: u64,
    pub errors: u64,
}

// --- TCP-RT (TCP Response Time) ---

pub const TCP_FLAG_FIN: u8 = 0x01;
pub const TCP_FLAG_SYN: u8 = 0x02;
pub const TCP_FLAG_RST: u8 = 0x04;
pub const TCP_FLAG_ACK: u8 = 0x10;

/// TCP-RT per-flow tracking state (stored in TCPRT_TABLE_V4/V6)
#[repr(C)]
#[derive(Copy, Clone)]
pub struct TcpRtValue {
    pub syn_ts: u64,            // SYN timestamp
    pub synack_ts: u64,         // SYN-ACK timestamp
    pub ack_ts: u64,            // Handshake completion ACK timestamp
    pub last_request_ts: u64,   // Last request data packet timestamp
    pub first_response_ts: u64, // First response packet timestamp
    pub handshake_ns: u64,      // Handshake total time (ack_ts - syn_ts)
    pub rtt_ns: u64,            // RTT estimate (ack_ts - synack_ts)
    pub art_ns: u64,            // Application response time (first_response_ts - last_request_ts)
    pub retransmissions: u32,   // Retransmission count
    pub request_count: u32,     // Completed request-response cycles
    pub state: u8,              // 0=handshake, 1=established, 2=closing
    pub flags: u8,              // bit 0: syn_seen, bit 1: synack_seen, bit 2: established
    pub pad: [u8; 2],
    pub last_seq: u32,          // Last seq number (for retransmission detection)
    pub last_payload_len: u16,  // Last payload length
    pub pad2: [u8; 2],
}

pub const TCPRT_STATE_HANDSHAKE: u8 = 0;
pub const TCPRT_STATE_ESTABLISHED: u8 = 1;
pub const TCPRT_STATE_CLOSING: u8 = 2;

pub const TCPRT_FLAG_SYN_SEEN: u8 = 1;
pub const TCPRT_FLAG_SYNACK_SEEN: u8 = 2;
pub const TCPRT_FLAG_ESTABLISHED: u8 = 4;

// --- Global firewall config (feature switches) ---

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FirewallConfig {
    pub conntrack_enabled: u8,
    pub monitoring_enabled: u8,
    pub num_cpus: u16,
    pub qos_enabled: u8,
    pub acl_enabled: u8,
    pub mirror_enabled: u8,
    pub tcprt_enabled: u8,
}
