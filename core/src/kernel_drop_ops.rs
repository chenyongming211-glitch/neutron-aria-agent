#[derive(Debug, Clone)]
pub struct KernelDropStatsEntry {
    pub tap_id: u32,
    pub ifindex: u32,
    pub reason_code: Option<u16>,
    pub proto: u16,
    pub packets: u64,
    pub bytes: u64,
    pub last_seen_ns: u64,
    pub last_location: Option<u64>,
    pub source: String,
}

#[derive(Debug, Clone, Default)]
pub struct KernelDropQuery {
    pub tap_id: Option<u32>,
    pub ifindex: Option<u32>,
    pub reason_code: Option<u16>,
    pub top: Option<usize>,
    pub include_unattributed: bool,
}

pub fn kernel_drop_reason_name(code: Option<u16>) -> String {
    match code {
        Some(code) => format!("reason_{}", code),
        None => "unknown".to_string(),
    }
}

pub fn kernel_drop_proto_name(proto: u16) -> String {
    match proto {
        6 => "tcp".to_string(),
        17 => "udp".to_string(),
        1 => "icmp".to_string(),
        58 => "icmpv6".to_string(),
        0 => "unknown".to_string(),
        other => other.to_string(),
    }
}

pub fn get_kernel_drop_stats(_pin_path: &str, _query: &KernelDropQuery) -> Result<Vec<KernelDropStatsEntry>, String> {
    Ok(Vec::new())
}

pub fn flush_kernel_drop_stats(_pin_path: &str, _query: &KernelDropQuery) -> Result<u64, String> {
    Ok(0)
}
