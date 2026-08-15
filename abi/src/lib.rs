#![no_std]

mod fragment;
pub use fragment::*;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct PolicyKey {
    pub tap_id: u32,
    pub src_id: u32,
    pub dst_id: u32,
    pub proto: u8,
    pub direction: u8, // 0=ingress, 1=egress
    pub bank: u8,
    pub pad: [u8; 1],
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

pub const ACL_BANK_PRIMARY: u8 = 0;
pub const ACL_BANK_SHADOW: u8 = 1;
pub const ACL_INGRESS_HOOK_XDP: u8 = 0;
pub const ACL_INGRESS_HOOK_TC: u8 = 1;

#[inline(always)]
pub fn normalize_acl_ingress_hook(_value: u8) -> u8 {
    ACL_INGRESS_HOOK_TC
}

#[inline(always)]
pub fn normalize_acl_bank(bank: u8) -> u8 {
    bank & 1
}

#[inline(always)]
pub fn acl_next_bank(bank: u8) -> u8 {
    normalize_acl_bank(bank ^ ACL_BANK_SHADOW)
}

#[inline(always)]
pub fn acl_banked_tap_id(tap_id: u32, bank: u8) -> u32 {
    tap_id.saturating_mul(2) | normalize_acl_bank(bank) as u32
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct PortKey {
    pub tap_id: u32,
    pub idx: u32,
    pub port: u16,
    pub pad: u16,
}

// --- Connection tracking ---

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct CtKey4 {
    pub tap_id: u32,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub pad: [u8; 3],
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct CtKey6 {
    pub tap_id: u32,
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub pad: [u8; 3],
}

pub const CT_NEW: u8 = 1;
pub const CT_ESTABLISHED: u8 = 2;
pub const CT_FLAG_SEEN_REPLY: u8 = 1;
pub const CT_FLAG_POLICY_HIT: u8 = 1 << 1;
pub const CT_FLAG_ACL_EVALUATED: u8 = 1 << 2;

#[inline(always)]
pub fn ct_acl_bank_is_current(
    matched_bank: u8,
    validate_acl_bank: u8,
    expected_acl_bank: u8,
) -> bool {
    validate_acl_bank == 0 || matched_bank == normalize_acl_bank(expected_acl_bank)
}

#[inline(always)]
pub fn ct_acl_cache_is_current(
    flags: u8,
    matched_bank: u8,
    validate_acl_bank: u8,
    expected_acl_bank: u8,
) -> bool {
    validate_acl_bank == 0
        || ((flags & CT_FLAG_ACL_EVALUATED) != 0
            && ct_acl_bank_is_current(matched_bank, validate_acl_bank, expected_acl_bank))
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct CtValue {
    pub state: u8,
    pub flags: u8,         // bit 0: seen_reply; bit 1: policy_hit; bit 2: ACL evaluated
    pub direction: u8,     // direction of the matched policy rule
    pub matched_proto: u8, // proto of the matched policy rule (0 = wildcard)
    pub matched_src_id: u32,
    pub matched_dst_id: u32,
    // Keep the 8-byte alignment before last_seen explicit so older verifiers
    // do not see an uninitialized padding hole during map_update_elem.
    pub matched_bank: u8,
    pub _pad: [u8; 3],
    pub last_seen: u64,
    pub pkt_count: u64,
    pub byte_count: u64,
}

/// Accept a conntrack value only when two same-key observations agree in full.
///
/// Preallocated LRU hash elements can be deleted and reused while another CPU
/// still holds the value pointer returned by a lookup. Comparing two complete
/// copies turns a concurrent delete/reuse into a cache miss instead of using a
/// mixed or aliased policy decision.
#[inline(always)]
pub fn ct_snapshot_is_stable(first: &CtValue, second: Option<&CtValue>) -> bool {
    let Some(second) = second else {
        return false;
    };
    first.state == second.state
        && first.flags == second.flags
        && first.direction == second.direction
        && first.matched_proto == second.matched_proto
        && first.matched_src_id == second.matched_src_id
        && first.matched_dst_id == second.matched_dst_id
        && first.matched_bank == second.matched_bank
        && first._pad == second._pad
        && first.last_seen == second.last_seen
        && first.pkt_count == second.pkt_count
        && first.byte_count == second.byte_count
}

/// Apply the existing conntrack hit transition to a confirmed private copy.
#[inline(always)]
pub fn ct_apply_confirmed_hit(
    entry: &mut CtValue,
    now: u64,
    pkt_len: u32,
    is_forward: bool,
) {
    entry.last_seen = now;
    entry.pkt_count = entry.pkt_count.wrapping_add(1);
    entry.byte_count = entry.byte_count.wrapping_add(pkt_len as u64);
    if is_forward {
        if entry.state == CT_NEW && (entry.flags & CT_FLAG_SEEN_REPLY) != 0 {
            entry.state = CT_ESTABLISHED;
        }
    } else {
        entry.flags |= CT_FLAG_SEEN_REPLY;
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct CtConfig {
    pub tcp_established_ns: u64,
    pub tcp_new_ns: u64,
    pub udp_ns: u64,
    pub icmp_ns: u64,
}

// --- Conntrack contract telemetry ---

pub const CT_CONTRACT_HOOK_TC_INGRESS: u8 = 1;
pub const CT_CONTRACT_HOOK_TC_EGRESS: u8 = 2;

pub const CT_CONTRACT_FAMILY_IPV4: u8 = 4;
pub const CT_CONTRACT_FAMILY_IPV6: u8 = 6;

pub const CT_CONTRACT_REASON_CT_HIT: u8 = 0;
pub const CT_CONTRACT_REASON_CT_MISS: u8 = 1;
pub const CT_CONTRACT_REASON_CT_DISABLED: u8 = 2;
pub const CT_CONTRACT_REASON_STALE_BANK: u8 = 3;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct CtContractKey {
    pub tap_id: u32,
    pub hook: u8,
    pub family: u8,
    pub reason: u8,
    pub pad: u8,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct CtContractValue {
    pub packets: u64,
    pub bytes: u64,
    pub last_seen: u64,
}

// --- Traffic statistics ---

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct RuleStatsValue {
    pub packets: u64,
    pub bytes: u64,
    pub dropped_packets: u64,
    pub dropped_bytes: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct FlowStatsValue {
    pub packets: u64,
    pub bytes: u64,
    pub last_seen: u64,
}

// --- QoS ---

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct QosKey {
    pub tap_id: u32,
    pub group_id: u32,
    pub direction: u8,
    pub pad: [u8; 3],
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct QosConfig {
    pub rate_bps: u64,
    pub burst_bytes: u64,
    pub priority: u8,
    pub mode: u8, // 0=policing, 1=shaping
    pub pad: [u8; 6],
}

/// Token bucket for QoS rate limiting (shared across CPUs, lock-free).
/// Layout: tokens(8) + last_refill_ns(8) + last_edt(8) = 24 bytes.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct TokenBucket {
    pub tokens: u64,
    pub last_refill_ns: u64,
    pub last_edt: u64,
}

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

// --- Per-group statistics ---

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct GroupStatsKey {
    pub tap_id: u32,
    pub group_id: u32,
    pub direction: u8,
    pub pad: [u8; 3],
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct GroupStatsValue {
    pub packets: u64,
    pub bytes: u64,
}

// --- Mirror (Port SPAN) ---

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct MirrorKey {
    pub tap_id: u32,
    pub src_id: u32,
    pub dst_id: u32,
    pub proto: u8,
    pub direction: u8,
    pub pad: [u8; 2],
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct GlobalMirrorKey {
    pub tap_id: u32,
    pub direction: u8,
    pub pad: [u8; 3],
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct MirrorConfig {
    pub target_ifindex: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
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
#[derive(Copy, Clone, Debug)]
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
    pub state: u8, // 0=syn_sent, 1=established, 2=fin_wait, 3=close_wait, 4=time_wait, 5=rst, 6=closed
    pub flags: u8, // bit 0: syn_seen, bit 1: synack_seen, bit 2: established, bit 3: fin_fwd, bit 4: fin_rev
    pub pad: [u8; 2],
    pub last_seq: u32,         // Last forward seq (for retransmission detection)
    pub last_payload_len: u16, // Last forward payload length
    pub _pad_last_payload_len: [u8; 2],
    pub prev_seq: u32, // Previous forward seq (catch retransmits after new data)
    pub prev_payload_len: u16, // Previous forward payload length
    pub _pad_prev_payload_len: [u8; 2],
    pub last_resp_seq: u32, // Last reverse seq (for retransmission detection)
    pub last_resp_payload_len: u16, // Last reverse payload length
    pub _pad_last_resp_payload_len: [u8; 2],
    pub prev_resp_seq: u32,         // Previous reverse seq
    pub prev_resp_payload_len: u16, // Previous reverse payload length
    pub _pad2: [u8; 6],             // Align to u64 boundary
    pub _pad3: [u8; 4],
    pub fin_ts: u64,   // FIN timestamp
    pub rst_ts: u64,   // RST timestamp
    pub close_ts: u64, // Connection fully closed timestamp
}

pub const TCPRT_STATE_SYN_SENT: u8 = 0;
pub const TCPRT_STATE_ESTABLISHED: u8 = 1;
pub const TCPRT_STATE_FIN_WAIT: u8 = 2;
pub const TCPRT_STATE_CLOSE_WAIT: u8 = 3;
pub const TCPRT_STATE_TIME_WAIT: u8 = 4;
pub const TCPRT_STATE_RST: u8 = 5;

pub const TCPRT_FLAG_SYN_SEEN: u8 = 1;
pub const TCPRT_FLAG_SYNACK_SEEN: u8 = 2;
pub const TCPRT_FLAG_ESTABLISHED: u8 = 4;
pub const TCPRT_FLAG_FIN_FWD: u8 = 1 << 3;
pub const TCPRT_FLAG_FIN_REV: u8 = 1 << 4;

// --- Drop Reason Profiler ---

pub const DROP_ACL_DENY: u8 = 1; // ACL rule deny (no port filter)
pub const DROP_ACL_PORT_DENY: u8 = 2; // ACL port match deny
pub const DROP_ACL_DEFAULT_DENY: u8 = 3; // ACL default deny (port not matched)
pub const DROP_QOS_INGRESS: u8 = 4; // QoS ingress rate limit drop
pub const DROP_QOS_EGRESS: u8 = 5; // QoS egress rate limit drop

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct DropKey {
    pub tap_id: u32,
    pub reason: u8,
    pub direction: u8,
    pub proto: u8,
    pub pad: u8,
    pub src_id: u32,
    pub dst_id: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct DropValue {
    pub packets: u64,
    pub bytes: u64,
    pub last_seen: u64,
}

// --- Kernel Drop Observability ---

pub const KERNEL_DROP_FLAG_HAS_PROTOCOL: u32 = 1 << 0;
pub const KERNEL_DROP_FLAG_HAS_LOCATION: u32 = 1 << 1;
pub const KERNEL_DROP_FLAG_HAS_REASON: u32 = 1 << 2;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct KernelDropFilterValue {
    pub tap_id: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct KernelDropConfig {
    pub flags: u32,
    pub trace_skbaddr_offset: u32,
    pub trace_location_offset: u32,
    pub trace_protocol_offset: u32,
    pub trace_reason_offset: u32,
    pub skb_dev_offset: u32,
    pub skb_len_offset: u32,
    pub net_device_ifindex_offset: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct KernelDropKey {
    pub tap_id: u32,
    pub ifindex: u32,
    pub reason_code: u16,
    pub proto: u16,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct KernelDropValue {
    pub packets: u64,
    pub bytes: u64,
    pub last_seen_ns: u64,
    pub last_location: u64,
}

// --- Packet Trace ---

pub const TRACE_XDP_INGRESS: u8 = 1;
pub const TRACE_XDP_DROP: u8 = 2;
pub const TRACE_TC_EGRESS: u8 = 3;
pub const TRACE_TC_DROP: u8 = 4;
pub const TRACE_TC_INGRESS: u8 = 5;

pub const TRACE_RESULT_PASS: u8 = 0;
pub const TRACE_RESULT_DROP_ACL: u8 = 1;
pub const TRACE_RESULT_DROP_ACL_PORT: u8 = 2;
pub const TRACE_RESULT_DROP_ACL_DEFAULT: u8 = 3;
pub const TRACE_RESULT_DROP_QOS: u8 = 4;
pub const TRACE_RESULT_DROP_FRAGMENT: u8 = 5;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct TraceFilter {
    pub src_ip: u32,         // 0 = any (IPv4)
    pub dst_ip: u32,         // 0 = any (IPv4)
    pub src_ip_v6: [u8; 16], // all-zero = any (IPv6)
    pub dst_ip_v6: [u8; 16], // all-zero = any (IPv6)
    pub src_port: u16,       // 0 = any
    pub dst_port: u16,       // 0 = any
    pub proto: u8,           // 0 = any
    pub enabled: u8,         // 1 = tracing active
    pub is_ipv6: u8,         // 0 = match IPv4, 1 = match IPv6, 2 = match both
    pub pad: [u8; 1],
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct TraceEventKey {
    pub tap_id: u32,
    pub cpu_id: u32,
    pub seq: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct TraceEvent {
    pub timestamp: u64,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub hook: u8,   // TRACE_XDP_INGRESS / TRACE_TC_EGRESS / etc.
    pub result: u8, // TRACE_RESULT_PASS / TRACE_RESULT_DROP_*
    pub direction: u8,
    pub src_id: u32,
    pub dst_id: u32,
    pub pkt_len: u32,
    pub ct_state: u8,    // 0=none, 1=new, 2=established
    pub drop_reason: u8, // DROP_* code if dropped, 0 if passed
    pub pad: [u8; 2],
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct TraceEventV6 {
    pub timestamp: u64,
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub hook: u8,   // TRACE_XDP_INGRESS / TRACE_TC_EGRESS / etc.
    pub result: u8, // TRACE_RESULT_PASS / TRACE_RESULT_DROP_*
    pub direction: u8,
    pub src_id: u32,
    pub dst_id: u32,
    pub pkt_len: u32,
    pub ct_state: u8,    // 0=none, 1=new, 2=established
    pub drop_reason: u8, // DROP_* code if dropped, 0 if passed
    pub pad: [u8; 2],
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct TraceStreamEvent {
    pub tap_id: u32,
    pub cpu_id: u32,
    pub seq: u64,
    pub timestamp: u64,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_ip_v6: [u8; 16],
    pub dst_ip_v6: [u8; 16],
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
    pub is_ipv6: u8,
    pub pad: [u8; 1],
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
pub const FLAG_POLICY_HIT: u16 = 1 << 8;
pub const FLAG_CT_STALE_BANK: u16 = 1 << 9;

/// Per-CPU scratch buffer for passing state between pipeline phases.
/// Lives in PIPE_SCRATCH PerCpuArray — zero stack overhead.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct PipelineCtx {
    pub tap_id: u32,

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
    pub ct_state: u8, // 0=not_found, 1=new, 2=established
    pub drop_reason: u8,
    pub _pad: [u8; 2],
    pub action: u32,

    // Matched policy (from CT fast-path or evaluate_policy)
    pub matched_src_id: u32,
    pub matched_dst_id: u32,
    pub matched_proto: u8,
    pub matched_direction: u8,
    pub matched_bank: u8,
    pub _pad2: [u8; 1],

    // One-packet authority snapshot, sampled after tap resolution.
    pub fragment_epoch_snapshot: u64,
    pub acl_bank_snapshot: u8,
    pub fragment_epoch_present: u8,
    pub _pad3: [u8; 6],
}

impl PipelineCtx {
    #[inline(always)]
    pub fn reset_for_tc_packet(&mut self, pkt_len: u32, direction: u8) {
        self.tap_id = TAP_ID_UNASSIGNED;
        self.src_id = 0;
        self.dst_id = 0;
        self.pkt_len = pkt_len;
        self.now = 0;
        self.proto = 0;
        self.direction = direction;
        self.flags = 0;
        self.ct_state = 0;
        self.drop_reason = 0;
        self._pad = [0; 2];
        self.action = 0;
        self.matched_src_id = 0;
        self.matched_dst_id = 0;
        self.matched_proto = 0;
        self.matched_direction = 0;
        self.matched_bank = 0;
        self._pad2 = [0; 1];
        self.fragment_epoch_snapshot = 0;
        self.acl_bank_snapshot = 0;
        self.fragment_epoch_present = 0;
        self._pad3 = [0; 6];
    }
}

#[inline(always)]
pub fn set_fragment_resolve_drop_ids(
    pipeline: &mut PipelineCtx,
    src_id: Option<u32>,
    dst_id: Option<u32>,
) {
    pipeline.src_id = src_id.unwrap_or(0);
    pipeline.dst_id = dst_id.unwrap_or(0);
}

// --- Global firewall config (feature switches) ---

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
    /// Standalone/global ACL bank. This reuses the former padding byte, so the
    /// pinned-map ABI remains 10 bytes and existing zeroed values select bank 0.
    pub acl_active_bank: u8,
}

pub const TAP_ID_UNASSIGNED: u32 = 0;
pub const FIRST_MANAGED_TAP_ID: u32 = 1;

/// Runtime lookup result for a managed interface in the future shared data plane.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct IfaceCtx {
    pub tap_id: u32,
    pub flags: u32,
}

/// Per-tap feature toggles for the future shared data plane.
/// This intentionally excludes process-global SSL configuration.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct TapConfig {
    pub conntrack_enabled: u8,
    pub monitoring_enabled: u8,
    pub acl_enabled: u8,
    pub qos_enabled: u8,
    pub mirror_enabled: u8,
    pub tcprt_enabled: u8,
    pub acl_active_bank: u8,
    pub acl_ingress_hook: u8,
}

impl From<FirewallConfig> for TapConfig {
    fn from(value: FirewallConfig) -> Self {
        Self {
            conntrack_enabled: value.conntrack_enabled,
            monitoring_enabled: value.monitoring_enabled,
            acl_enabled: value.acl_enabled,
            qos_enabled: value.qos_enabled,
            mirror_enabled: value.mirror_enabled,
            tcprt_enabled: value.tcprt_enabled,
            acl_active_bank: ACL_BANK_PRIMARY,
            acl_ingress_hook: ACL_INGRESS_HOOK_TC,
        }
    }
}

// --- SSL Observability ---

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct SslScratch {
    pub ssl_ptr: u64,
    pub start_ts: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct SslConnValue {
    pub pid: u32,
    pub tid: u32,
    pub handshake_ns: u64,
    pub timestamp: u64,
    pub sni: [u8; 64],
}

// --- SSL HTTP Observability ---

/// Per-CPU scratch buffer for reading SSL user buffers (avoids stack overflow)
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct SslParseBuf {
    pub data: [u8; 256],
}

/// SSL_write → SSL_read correlation scratch (key=pid_tgid)
/// Accumulates raw request header bytes across multiple SSL_write* calls.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct SslHttpScratch {
    pub first_write_ts: u64,
    pub data_len: u16,
    pub flags: u8,
    pub _pad: [u8; 5],
    pub req_data: [u8; 256], // raw HTTP request first 256 bytes
}

/// SSL_read entry saves buf pointer for return probe
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct SslReadScratch {
    pub ssl_ptr: u64,
    pub buf_ptr: u64,
    pub out_len_ptr: u64,
    pub mode: u8, // 0=SSL_read, 1=SSL_read_ex
    pub _pad: [u8; 7],
}

/// Completed HTTP request/response event
/// req_data contains raw request header; method/path/host parsed in userspace
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
    pub req_data: [u8; 256], // raw HTTP request header (was 128)
}

// --- SSL Error Observability ---

/// SSL error event (read/write failures)
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct SslErrorEvent {
    pub pid: u32,
    pub tid: u32,
    pub timestamp: u64,
    pub ssl_ptr: u64,
    pub ret_code: i32,  // SSL_read/write return value
    pub syscall: u8,    // 0=read, 1=write
    pub error_hint: u8, // 0=none, 1=zero_return, 2=want_retry, 3=syscall_err
    pub _pad: [u8; 2],
}

/// SSL_write scratch for storing ssl_ptr in entry probe
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct SslWriteScratch {
    pub ssl_ptr: u64,
    pub write_ts: u64,
}

#[cfg(all(feature = "aya-pod", not(target_arch = "bpf")))]
mod userspace_pod {
    use super::*;

    macro_rules! impl_aya_pod {
        ($($type:ty),+ $(,)?) => {
            $(unsafe impl aya::Pod for $type {})+
        };
    }

    impl_aya_pod!(
        PolicyKey,
        PolicyValue,
        PortKey,
        CtKey4,
        CtKey6,
        CtValue,
        CtConfig,
        CtContractKey,
        CtContractValue,
        RuleStatsValue,
        FlowStatsValue,
        QosKey,
        QosConfig,
        TokenBucket,
        QosStatsValue,
        GroupStatsKey,
        GroupStatsValue,
        MirrorKey,
        GlobalMirrorKey,
        MirrorConfig,
        MirrorStatsValue,
        TcpRtValue,
        FirewallConfig,
        IfaceCtx,
        TapConfig,
        SslScratch,
        SslConnValue,
        SslHttpValue,
        SslErrorEvent,
        SslWriteScratch,
        DropKey,
        DropValue,
        KernelDropFilterValue,
        KernelDropConfig,
        KernelDropKey,
        KernelDropValue,
        TraceFilter,
        TraceEventKey,
        TraceEvent,
        TraceEventV6,
        TraceStreamEvent,
    );
}

/// Stable userspace ABI surface consumed by `aria-core`.
///
/// Datapath-only scratch types stay at the crate root for the eBPF program and
/// are intentionally not re-exported through this module.
pub mod userspace {
    pub use super::{
        acl_banked_tap_id, acl_next_bank, fragment_metric_index, normalize_acl_bank,
        normalize_acl_ingress_hook, CtConfig, CtContractKey, CtContractValue, CtKey4, CtKey6,
        CtValue, DropKey, DropValue, FirewallConfig, FlowStatsValue, FragmentConfig,
        FragmentContextKey4, FragmentContextKey6, FragmentContextValue, FragmentEpochValue,
        FragmentKind, GlobalMirrorKey, GroupStatsKey, GroupStatsValue, IfaceCtx, KernelDropConfig,
        KernelDropFilterValue, KernelDropKey, KernelDropValue, MirrorConfig, MirrorKey,
        MirrorStatsValue, PolicyKey, PolicyValue, PortKey, QosConfig, QosKey, QosStatsValue,
        RuleStatsValue, SslConnValue, SslErrorEvent, SslHttpValue, SslScratch, SslWriteScratch,
        TapConfig, TcpRtValue, TokenBucket, TraceEvent, TraceEventKey, TraceEventV6, TraceFilter,
        TraceStreamEvent, ACL_BANK_PRIMARY, ACL_BANK_SHADOW, ACL_INGRESS_HOOK_TC,
        ACL_INGRESS_HOOK_XDP, CT_CONTRACT_FAMILY_IPV4, CT_CONTRACT_FAMILY_IPV6,
        CT_CONTRACT_HOOK_TC_EGRESS, CT_CONTRACT_HOOK_TC_INGRESS, CT_CONTRACT_REASON_CT_DISABLED,
        CT_CONTRACT_REASON_CT_HIT, CT_CONTRACT_REASON_CT_MISS, CT_CONTRACT_REASON_STALE_BANK,
        CT_ESTABLISHED, CT_FLAG_ACL_EVALUATED, CT_FLAG_POLICY_HIT, CT_FLAG_SEEN_REPLY, CT_NEW,
        DIR_EGRESS, DIR_INGRESS, DROP_ACL_DEFAULT_DENY, DROP_ACL_DENY, DROP_ACL_PORT_DENY,
        DROP_FRAGMENT_CONFIG_INVALID, DROP_FRAGMENT_CONFIG_MISSING, DROP_FRAGMENT_CONTEXT_EXPIRED,
        DROP_FRAGMENT_CONTEXT_INVALID, DROP_FRAGMENT_CONTEXT_MISSING,
        DROP_FRAGMENT_CONTEXT_OVERLAP, DROP_FRAGMENT_CONTEXT_STALE,
        DROP_FRAGMENT_CONTEXT_UPDATE_FAILED, DROP_FRAGMENT_EPOCH_MISSING,
        DROP_FRAGMENT_EXPIRY_OVERFLOW, DROP_FRAGMENT_INVALID_L4, DROP_FRAGMENT_TAP_UNASSIGNED,
        DROP_FRAGMENT_TRACKING_DISABLED, DROP_MALFORMED_IP, DROP_QOS_EGRESS, DROP_QOS_INGRESS,
        FIRST_MANAGED_TAP_ID, FRAGMENT_CONFIG_DISABLED, FRAGMENT_CONFIG_ENABLED,
        FRAGMENT_CONFIG_MAX_TIMEOUT_NS, FRAGMENT_CONFIG_MIN_TIMEOUT_NS, FRAGMENT_CONFIG_VERSION,
        FRAGMENT_CONTEXT_FLAG_TCP, FRAGMENT_CONTEXT_FLAG_UDP, FRAGMENT_CONTEXT_VERSION,
        FRAGMENT_FAMILY_IPV4, FRAGMENT_FAMILY_IPV6, FRAGMENT_METRIC_CONFIG_INVALID,
        FRAGMENT_METRIC_CONFIG_MISSING, FRAGMENT_METRIC_CONTEXT_EXPIRED,
        FRAGMENT_METRIC_CONTEXT_HIT, FRAGMENT_METRIC_CONTEXT_INSERTED,
        FRAGMENT_METRIC_CONTEXT_INVALID, FRAGMENT_METRIC_CONTEXT_MISSING,
        FRAGMENT_METRIC_CONTEXT_OVERLAP, FRAGMENT_METRIC_CONTEXT_STALE,
        FRAGMENT_METRIC_CONTEXT_UPDATE_FAILED, FRAGMENT_METRIC_EPOCH_MISSING,
        FRAGMENT_METRIC_EXPIRY_OVERFLOW, FRAGMENT_METRIC_FIRST, FRAGMENT_METRIC_INVALID_L4,
        FRAGMENT_METRIC_MAX, FRAGMENT_METRIC_NON_INITIAL, FRAGMENT_METRIC_TAP_UNASSIGNED,
        FRAGMENT_METRIC_TRACKING_DISABLED, FRAGMENT_RUNTIME_MODE_MANAGED,
        FRAGMENT_RUNTIME_MODE_STANDALONE, KERNEL_DROP_FLAG_HAS_LOCATION,
        KERNEL_DROP_FLAG_HAS_PROTOCOL, KERNEL_DROP_FLAG_HAS_REASON, TAP_ID_UNASSIGNED,
        TRACE_RESULT_DROP_FRAGMENT,
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn critical_map_layouts_remain_stable() {
        assert_eq!(core::mem::size_of::<PolicyKey>(), 16);
        assert_eq!(core::mem::size_of::<TapConfig>(), 8);
        assert_eq!(core::mem::size_of::<CtValue>(), 40);
        assert_eq!(core::mem::size_of::<FragmentContextKey4>(), 20);
        assert_eq!(
            core::mem::size_of::<FragmentContextValue>(),
            3 * core::mem::size_of::<u16>()
                + 4 * core::mem::size_of::<u8>()
                + core::mem::size_of::<[u8; 6]>()
                + 2 * core::mem::size_of::<u64>()
        );
        assert_eq!(core::mem::size_of::<SslErrorEvent>(), 32);
        assert_eq!(core::mem::size_of::<FirewallConfig>(), 10);
        assert_eq!(core::mem::size_of::<TcpRtValue>(), 168);
        assert_eq!(core::mem::offset_of!(FirewallConfig, acl_active_bank), 9);
        assert_eq!(core::mem::offset_of!(TcpRtValue, prev_seq), 112);
        assert_eq!(core::mem::offset_of!(TcpRtValue, last_resp_seq), 120);
        assert_eq!(core::mem::offset_of!(TcpRtValue, prev_resp_seq), 128);
        assert_eq!(core::mem::offset_of!(TcpRtValue, _pad3), 140);
        assert_eq!(core::mem::offset_of!(TcpRtValue, fin_ts), 144);
    }

    #[test]
    fn fragment_map_layouts_are_stable() {
        assert_eq!(core::mem::size_of::<FragmentKind>(), 1);

        assert_eq!(core::mem::size_of::<FragmentContextKey4>(), 20);
        assert_eq!(core::mem::offset_of!(FragmentContextKey4, tap_id), 0);
        assert_eq!(core::mem::offset_of!(FragmentContextKey4, src_ip), 4);
        assert_eq!(core::mem::offset_of!(FragmentContextKey4, dst_ip), 8);
        assert_eq!(core::mem::offset_of!(FragmentContextKey4, fragment_id), 12);
        assert_eq!(core::mem::offset_of!(FragmentContextKey4, vlan_id), 14);
        assert_eq!(core::mem::offset_of!(FragmentContextKey4, proto), 16);
        assert_eq!(core::mem::offset_of!(FragmentContextKey4, direction), 17);
        assert_eq!(core::mem::offset_of!(FragmentContextKey4, _pad), 18);

        assert_eq!(core::mem::size_of::<FragmentContextKey6>(), 44);
        assert_eq!(core::mem::offset_of!(FragmentContextKey6, tap_id), 0);
        assert_eq!(core::mem::offset_of!(FragmentContextKey6, src_ip), 4);
        assert_eq!(core::mem::offset_of!(FragmentContextKey6, dst_ip), 20);
        assert_eq!(core::mem::offset_of!(FragmentContextKey6, fragment_id), 36);
        assert_eq!(core::mem::offset_of!(FragmentContextKey6, vlan_id), 40);
        assert_eq!(core::mem::offset_of!(FragmentContextKey6, proto), 42);
        assert_eq!(core::mem::offset_of!(FragmentContextKey6, direction), 43);

        assert_eq!(core::mem::size_of::<FragmentContextValue>(), 32);
        assert_eq!(core::mem::offset_of!(FragmentContextValue, src_port), 0);
        assert_eq!(core::mem::offset_of!(FragmentContextValue, dst_port), 2);
        assert_eq!(
            core::mem::offset_of!(FragmentContextValue, first_payload_end),
            4
        );
        assert_eq!(core::mem::offset_of!(FragmentContextValue, acl_bank), 6);
        assert_eq!(core::mem::offset_of!(FragmentContextValue, flags), 7);
        assert_eq!(core::mem::offset_of!(FragmentContextValue, version), 8);
        assert_eq!(core::mem::offset_of!(FragmentContextValue, _pad), 9);
        assert_eq!(core::mem::offset_of!(FragmentContextValue, _reserved), 10);
        assert_eq!(core::mem::offset_of!(FragmentContextValue, epoch), 16);
        assert_eq!(
            core::mem::offset_of!(FragmentContextValue, expires_at_ns),
            24
        );
        assert_eq!(core::mem::size_of::<FragmentContextValue>(), 32);

        assert_eq!(core::mem::size_of::<FragmentConfig>(), 24);
        assert_eq!(core::mem::offset_of!(FragmentConfig, version), 0);
        assert_eq!(core::mem::offset_of!(FragmentConfig, enabled), 1);
        assert_eq!(core::mem::offset_of!(FragmentConfig, runtime_mode), 2);
        assert_eq!(core::mem::offset_of!(FragmentConfig, _pad), 3);
        assert_eq!(core::mem::offset_of!(FragmentConfig, ipv4_timeout_ns), 8);
        assert_eq!(core::mem::offset_of!(FragmentConfig, ipv6_timeout_ns), 16);

        assert_eq!(core::mem::size_of::<FragmentEpochValue>(), 8);
        assert_eq!(core::mem::offset_of!(FragmentEpochValue, epoch), 0);
    }

    #[test]
    fn acl_ingress_hook_is_abi_only_and_normalizes_to_tc() {
        assert_eq!(ACL_INGRESS_HOOK_XDP, 0);
        assert_eq!(ACL_INGRESS_HOOK_TC, 1);
        assert_eq!(normalize_acl_ingress_hook(0), ACL_INGRESS_HOOK_TC);
        assert_eq!(normalize_acl_ingress_hook(1), ACL_INGRESS_HOOK_TC);
        assert_eq!(normalize_acl_ingress_hook(u8::MAX), ACL_INGRESS_HOOK_TC);
    }

    #[test]
    fn acl_bank_helpers_encode_the_selected_bank() {
        assert_eq!(ACL_BANK_PRIMARY, 0);
        assert_eq!(ACL_BANK_SHADOW, 1);
        assert_eq!(acl_banked_tap_id(7, 0), 14);
        assert_eq!(acl_banked_tap_id(7, 1), 15);
        assert_eq!(acl_next_bank(0), 1);
        assert_eq!(acl_next_bank(1), 0);
        assert_eq!(acl_next_bank(42), 1);
    }

    #[test]
    fn tc_ct_bank_accepts_only_current_bank_when_acl_is_active() {
        assert!(ct_acl_bank_is_current(0, 1, 0));
        assert!(ct_acl_bank_is_current(1, 1, 1));
        assert!(!ct_acl_bank_is_current(1, 1, 0));
    }

    #[test]
    fn tc_ct_cache_requires_acl_evaluation_when_acl_turns_on() {
        assert!(ct_acl_cache_is_current(0, 0, 0, 0));
        assert!(!ct_acl_cache_is_current(0, 0, 1, 0));
        assert!(ct_acl_cache_is_current(CT_FLAG_ACL_EVALUATED, 0, 1, 0,));
        assert!(!ct_acl_cache_is_current(CT_FLAG_ACL_EVALUATED, 0, 1, 1,));
    }

    fn ct_concurrency_fixture() -> CtValue {
        CtValue {
            state: CT_NEW,
            flags: CT_FLAG_ACL_EVALUATED | CT_FLAG_POLICY_HIT,
            direction: DIR_INGRESS,
            matched_proto: 6,
            matched_src_id: 101,
            matched_dst_id: 202,
            matched_bank: ACL_BANK_SHADOW,
            _pad: [0; 3],
            last_seen: 1_000,
            pkt_count: 7,
            byte_count: 700,
        }
    }

    #[test]
    fn tc_ct_concurrency_accepts_only_identical_complete_snapshots() {
        let first = ct_concurrency_fixture();
        let same = first;
        assert!(ct_snapshot_is_stable(&first, Some(&same)));
        assert!(!ct_snapshot_is_stable(&first, None));

        let mutations = [
            CtValue {
                state: CT_ESTABLISHED,
                ..first
            },
            CtValue {
                flags: first.flags | CT_FLAG_SEEN_REPLY,
                ..first
            },
            CtValue {
                direction: DIR_EGRESS,
                ..first
            },
            CtValue {
                matched_proto: 17,
                ..first
            },
            CtValue {
                matched_src_id: 303,
                ..first
            },
            CtValue {
                matched_dst_id: 404,
                ..first
            },
            CtValue {
                matched_bank: ACL_BANK_PRIMARY,
                ..first
            },
            CtValue {
                _pad: [1, 0, 0],
                ..first
            },
            CtValue {
                last_seen: first.last_seen + 1,
                ..first
            },
            CtValue {
                pkt_count: first.pkt_count + 1,
                ..first
            },
            CtValue {
                byte_count: first.byte_count + 1,
                ..first
            },
        ];
        for reused in &mutations {
            assert!(!ct_snapshot_is_stable(&first, Some(reused)));
        }
    }

    #[test]
    fn tc_ct_concurrency_forward_hit_promotes_only_after_reply() {
        let mut without_reply = ct_concurrency_fixture();
        ct_apply_confirmed_hit(&mut without_reply, 2_000, 128, true);
        assert_eq!(without_reply.state, CT_NEW);
        assert_eq!(without_reply.last_seen, 2_000);
        assert_eq!(without_reply.pkt_count, 8);
        assert_eq!(without_reply.byte_count, 828);

        let mut after_reply = ct_concurrency_fixture();
        after_reply.flags |= CT_FLAG_SEEN_REPLY;
        ct_apply_confirmed_hit(&mut after_reply, 3_000, 64, true);
        assert_eq!(after_reply.state, CT_ESTABLISHED);
    }

    #[test]
    fn tc_ct_concurrency_reverse_hit_marks_reply_without_promotion() {
        let mut entry = ct_concurrency_fixture();
        ct_apply_confirmed_hit(&mut entry, 2_000, 128, false);
        assert_eq!(entry.state, CT_NEW);
        assert_ne!(entry.flags & CT_FLAG_SEEN_REPLY, 0);
        assert_eq!(entry.last_seen, 2_000);
        assert_eq!(entry.pkt_count, 8);
        assert_eq!(entry.byte_count, 828);
    }

    #[test]
    fn tc_ct_concurrency_hit_counters_wrap_without_layout_change() {
        let mut entry = ct_concurrency_fixture();
        entry.pkt_count = u64::MAX;
        entry.byte_count = u64::MAX - 7;
        ct_apply_confirmed_hit(&mut entry, 2_000, 16, true);
        assert_eq!(entry.pkt_count, 0);
        assert_eq!(entry.byte_count, 8);
        assert_eq!(core::mem::size_of::<CtValue>(), 40);
    }

    #[test]
    fn ct_policy_hit_uses_an_unused_flag_without_layout_change() {
        assert_eq!(CT_FLAG_POLICY_HIT, 2);
        assert_eq!(CT_FLAG_ACL_EVALUATED, 4);
        assert_eq!(core::mem::size_of::<CtValue>(), 40);
    }

    #[test]
    fn reserved_xdp_trace_hook_discriminators_remain_stable() {
        assert_eq!(TRACE_XDP_INGRESS, 1);
        assert_eq!(TRACE_XDP_DROP, 2);
    }
}
