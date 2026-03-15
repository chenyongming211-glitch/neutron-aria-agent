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

#[repr(C)]
#[derive(Copy, Clone)]
pub struct TokenBucket {
    pub tokens: u64,
    pub last_refill_ns: u64,
}

// --- Global firewall config (feature switches) ---

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FirewallConfig {
    pub conntrack_enabled: u8,
    pub monitoring_enabled: u8,
    pub num_cpus: u16,
    pub qos_enabled: u8,
    pub pad: [u8; 3],
}
