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
    pub dropped_packets: u64,
    pub dropped_bytes: u64,
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
    pub rtt_client_ns: u64,     // Client-side RTT (ack_ts - synack_ts)
    pub rtt_server_ns: u64,     // Server-side RTT (synack_ts - syn_ts)
    pub art_ns: u64,            // Application response time (first_response_ts - last_request_ts)
    pub syn_ingress_ts: u64,    // SYN first observation (ingress) for dual-observation
    pub synack_ingress_ts: u64, // SYN-ACK first observation (ingress) for dual-observation
    pub retrans_req: u32,       // Request direction retransmissions (client → server)
    pub retrans_resp: u32,      // Response direction retransmissions (server → client)
    pub request_count: u32,     // Completed request-response cycles
    pub state: u8,              // 0=syn_sent, 1=established, 2=fin_wait, 3=close_wait, 4=time_wait, 5=rst, 6=closed
    pub flags: u8,              // bit 0: syn_seen, bit 1: synack_seen, bit 2: established, bit 3: fin_fwd, bit 4: fin_rev
    pub pad: [u8; 2],
    pub last_seq: u32,          // Last forward seq (for retransmission detection)
    pub last_payload_len: u16,  // Last forward payload length
    pub prev_seq: u32,          // Previous forward seq (catch retransmits after new data)
    pub prev_payload_len: u16,  // Previous forward payload length
    pub last_resp_seq: u32,     // Last reverse seq (for retransmission detection)
    pub last_resp_payload_len: u16, // Last reverse payload length
    pub prev_resp_seq: u32,     // Previous reverse seq
    pub prev_resp_payload_len: u16, // Previous reverse payload length
    pub _pad2: [u8; 6],        // Align to u64 boundary
    pub fin_ts: u64,            // FIN timestamp
    pub rst_ts: u64,            // RST timestamp
    pub close_ts: u64,          // Connection fully closed timestamp
}

pub const TCPRT_STATE_SYN_SENT: u8 = 0;
pub const TCPRT_STATE_ESTABLISHED: u8 = 1;
pub const TCPRT_STATE_FIN_WAIT: u8 = 2;
pub const TCPRT_STATE_CLOSE_WAIT: u8 = 3;
pub const TCPRT_STATE_TIME_WAIT: u8 = 4;
pub const TCPRT_STATE_RST: u8 = 5;
pub const TCPRT_STATE_CLOSED: u8 = 6;

pub const TCPRT_FLAG_SYN_SEEN: u8 = 1;
pub const TCPRT_FLAG_SYNACK_SEEN: u8 = 2;
pub const TCPRT_FLAG_ESTABLISHED: u8 = 4;
pub const TCPRT_FLAG_FIN_FWD: u8 = 1 << 3;
pub const TCPRT_FLAG_FIN_REV: u8 = 1 << 4;

// --- Drop Reason Profiler ---

pub const DROP_ACL_DENY: u8 = 1;          // ACL rule deny (no port filter)
pub const DROP_ACL_PORT_DENY: u8 = 2;     // ACL port match deny
pub const DROP_ACL_DEFAULT_DENY: u8 = 3;  // ACL default deny (port not matched)
pub const DROP_QOS_INGRESS: u8 = 4;       // QoS ingress rate limit drop
pub const DROP_QOS_EGRESS: u8 = 5;        // QoS egress rate limit drop

#[repr(C)]
#[derive(Copy, Clone)]
pub struct DropKey {
    pub reason: u8,
    pub direction: u8,
    pub proto: u8,
    pub pad: u8,
    pub src_id: u32,
    pub dst_id: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct DropValue {
    pub packets: u64,
    pub bytes: u64,
    pub last_seen: u64,
}

// --- Packet Trace ---

pub const TRACE_XDP_INGRESS: u8 = 1;
pub const TRACE_XDP_DROP: u8 = 2;
pub const TRACE_TC_EGRESS: u8 = 3;
pub const TRACE_TC_DROP: u8 = 4;
pub const TRACE_TC_INGRESS: u8 = 5;

pub const TRACE_RESULT_PASS: u8 = 0;
#[allow(dead_code)]
pub const TRACE_RESULT_DROP_ACL: u8 = 1;
#[allow(dead_code)]
pub const TRACE_RESULT_DROP_ACL_PORT: u8 = 2;
#[allow(dead_code)]
pub const TRACE_RESULT_DROP_ACL_DEFAULT: u8 = 3;
pub const TRACE_RESULT_DROP_QOS: u8 = 4;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct TraceFilter {
    pub src_ip: u32,        // 0 = any (IPv4)
    pub dst_ip: u32,        // 0 = any (IPv4)
    pub src_ip_v6: [u8; 16], // all-zero = any (IPv6)
    pub dst_ip_v6: [u8; 16], // all-zero = any (IPv6)
    pub src_port: u16,      // 0 = any
    pub dst_port: u16,      // 0 = any
    pub proto: u8,          // 0 = any
    pub enabled: u8,        // 1 = tracing active
    pub is_ipv6: u8,        // 0 = match IPv4, 1 = match IPv6, 2 = match both
    pub pad: [u8; 1],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct TraceEvent {
    pub timestamp: u64,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub hook: u8,           // TRACE_XDP_INGRESS / TRACE_TC_EGRESS / etc.
    pub result: u8,         // TRACE_RESULT_PASS / TRACE_RESULT_DROP_*
    pub direction: u8,
    pub src_id: u32,
    pub dst_id: u32,
    pub pkt_len: u32,
    pub ct_state: u8,       // 0=none, 1=new, 2=established
    pub drop_reason: u8,    // DROP_* code if dropped, 0 if passed
    pub pad: [u8; 2],
}

// --- Pipeline scratch context (per-CPU, inter-phase communication) ---

/// Feature flag bits for PipelineCtx.flags
pub const FLAG_QOS_ON: u16 = 1 << 0;
pub const FLAG_TCPRT_ON: u16 = 1 << 1;
pub const FLAG_TRACING: u16 = 1 << 2;
pub const FLAG_ACL_ON: u16 = 1 << 3;
pub const FLAG_MIRROR_ON: u16 = 1 << 4;
pub const FLAG_CT_HIT: u16 = 1 << 5;
pub const FLAG_IS_FORWARD: u16 = 1 << 6;
#[allow(dead_code)]
pub const FLAG_NEED_IDS: u16 = 1 << 7;

/// Per-CPU scratch buffer for passing state between pipeline phases.
/// Lives in PIPE_SCRATCH PerCpuArray — zero stack overhead.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct PipelineCtx {
    // ID lookup results
    pub src_id: u32,
    pub dst_id: u32,

    // Common parameters
    pub pkt_len: u32,
    pub now: u64,
    pub proto: u8,
    pub direction: u8,
    pub flags: u16,

    // CT / policy results
    pub ct_state: u8,       // 0=not_found, 1=new, 2=established
    pub drop_reason: u8,
    pub _pad: [u8; 2],
    pub action: u32,

    // Matched policy (from CT fast-path or evaluate_policy)
    pub matched_src_id: u32,
    pub matched_dst_id: u32,
    pub matched_proto: u8,
    pub matched_direction: u8,
    pub _pad2: [u8; 2],
}

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
    pub ssl_enabled: u8,
}

// --- SSL Observability ---

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SslScratch {
    pub ssl_ptr: u64,
    pub start_ts: u64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct SslConnValue {
    pub pid: u32,
    pub tid: u32,
    pub handshake_ns: u64,
    pub timestamp: u64,
    pub sni: [u8; 64],
}
