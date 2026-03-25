use aya_ebpf::maps::{HashMap, LpmTrie, LruHashMap, PerCpuHashMap, LruPerCpuHashMap, PerCpuArray};
use aya_ebpf::macros::map;

pub use crate::common::{
    PolicyKey, PolicyValue, PortKey,
    CtKey4, CtKey6, CtValue, CtConfig, CtContractKey, CtContractValue,
    RuleStatsValue, FlowStatsValue,
    QosKey, QosConfig, TokenBucket, QosStatsValue,
    GroupStatsKey, GroupStatsValue,
    MirrorKey, GlobalMirrorKey, MirrorConfig, MirrorStatsValue,
    FirewallConfig,
    TapConfig,
    TcpRtValue,
    DropKey, DropValue,
    TraceFilter, TraceEvent, TraceEventKey, TraceEventV6,
    PipelineCtx,
    IfaceCtx,
    SslScratch, SslConnValue,
    SslParseBuf, SslHttpScratch, SslReadScratch, SslHttpValue,
    SslErrorEvent, SslWriteScratch,
};
use crate::parser::PacketInfo;

// --- Scratch buffer for PacketInfo (avoids stack allocation) ---

#[map(name = "PKT_SCRATCH")]
pub static PKT_SCRATCH: PerCpuArray<PacketInfo> = PerCpuArray::with_max_entries(1, 0);

// --- Pipeline scratch context (inter-phase communication) ---

#[map(name = "PIPE_SCRATCH")]
pub static PIPE_SCRATCH: PerCpuArray<PipelineCtx> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "IFACE_CTX_MAP")]
pub static IFACE_CTX_MAP: HashMap<u32, IfaceCtx> = HashMap::with_max_entries(1024, 0);

// --- Existing maps ---

#[map(name = "SRC_IPV4_TRIE")]
pub static SRC_IPV4_TRIE: LpmTrie<[u8; 8], u32> = LpmTrie::with_max_entries(10000, 0);

#[map(name = "DST_IPV4_TRIE")]
pub static DST_IPV4_TRIE: LpmTrie<[u8; 8], u32> = LpmTrie::with_max_entries(10000, 0);

#[map(name = "SRC_IPV6_TRIE")]
pub static SRC_IPV6_TRIE: LpmTrie<[u8; 20], u32> = LpmTrie::with_max_entries(5000, 0);

#[map(name = "DST_IPV6_TRIE")]
pub static DST_IPV6_TRIE: LpmTrie<[u8; 20], u32> = LpmTrie::with_max_entries(5000, 0);

#[map(name = "POLICY_TABLE")]
pub static POLICY_TABLE: HashMap<PolicyKey, PolicyValue> = HashMap::with_max_entries(65536, 0);

// 端口匹配 HashMap：key=(bitmap_idx, port) → value=action
// BPF_F_NO_PREALLOC (1) 只为实际条目分配内存
#[map(name = "PORT_BITMAP_POOL")]
pub static PORT_BITMAP_POOL: HashMap<PortKey, u8> = HashMap::with_max_entries(2_000_000, 1);

// --- Connection tracking maps ---

#[map(name = "CT_TABLE_V4")]
pub static CT_TABLE_V4: LruHashMap<CtKey4, CtValue> = LruHashMap::with_max_entries(262144, 0);

#[map(name = "CT_TABLE_V6")]
pub static CT_TABLE_V6: LruHashMap<CtKey6, CtValue> = LruHashMap::with_max_entries(65536, 0);

// CT_CONFIG: Array with 1 entry for timeout configuration
// Using HashMap with u32 key as a workaround (key=0 → config)
#[map(name = "CT_CONFIG")]
pub static CT_CONFIG: HashMap<u32, CtConfig> = HashMap::with_max_entries(1, 0);

#[map(name = "CT_CONTRACT_STATS")]
pub static CT_CONTRACT_STATS: PerCpuHashMap<CtContractKey, CtContractValue> =
    PerCpuHashMap::with_max_entries(4096, 0);

#[map(name = "CT_CONTRACT_VALUE_BUF")]
pub static CT_CONTRACT_VALUE_BUF: PerCpuArray<CtContractValue> = PerCpuArray::with_max_entries(1, 0);

// 全局配置：特性开关等（key=0）
#[map(name = "FIREWALL_CONFIG")]
pub static FIREWALL_CONFIG: HashMap<u32, FirewallConfig> = HashMap::with_max_entries(1, 0);

#[map(name = "TAP_CONFIG_MAP")]
pub static TAP_CONFIG_MAP: HashMap<u32, TapConfig> = HashMap::with_max_entries(1024, 0);

// --- Traffic statistics maps ---

#[map(name = "RULE_STATS")]
pub static RULE_STATS: PerCpuHashMap<PolicyKey, RuleStatsValue> = PerCpuHashMap::with_max_entries(65536, 0);

#[map(name = "RULE_STATS_BUF")]
pub static RULE_STATS_BUF: PerCpuArray<RuleStatsValue> = PerCpuArray::with_max_entries(1, 0);

// BPF_F_NO_PREALLOC (1) for LRU per-CPU maps
#[map(name = "FLOW_STATS_V4")]
pub static FLOW_STATS_V4: LruPerCpuHashMap<CtKey4, FlowStatsValue> = LruPerCpuHashMap::with_max_entries(16384, 0);

#[map(name = "FLOW_STATS_V6")]
pub static FLOW_STATS_V6: LruPerCpuHashMap<CtKey6, FlowStatsValue> = LruPerCpuHashMap::with_max_entries(4096, 0);

#[map(name = "FLOW_STATS_BUF")]
pub static FLOW_STATS_BUF: PerCpuArray<FlowStatsValue> = PerCpuArray::with_max_entries(1, 0);

// --- QoS maps ---

#[map(name = "QOS_CONFIG")]
pub static QOS_CONFIG: HashMap<QosKey, QosConfig> = HashMap::with_max_entries(16384, 0);

// Shared (non-per-CPU) token bucket: all CPUs race on the same bucket.
// The TOCTOU window is a few nanoseconds, bounding overshoot to
// (num_cpus - 1) × MTU per race — negligible for a policer.
#[map(name = "QOS_TOKEN_BUCKET")]
pub static QOS_TOKEN_BUCKET: HashMap<QosKey, TokenBucket> = HashMap::with_max_entries(16384, 0);

// --- QoS statistics ---

#[map(name = "QOS_STATS")]
pub static QOS_STATS: PerCpuHashMap<QosKey, QosStatsValue> = PerCpuHashMap::with_max_entries(16384, 0);

#[map(name = "QOS_STATS_BUF")]
pub static QOS_STATS_BUF: PerCpuArray<QosStatsValue> = PerCpuArray::with_max_entries(1, 0);

// --- Per-group statistics ---

#[map(name = "GROUP_STATS")]
pub static GROUP_STATS: PerCpuHashMap<GroupStatsKey, GroupStatsValue> = PerCpuHashMap::with_max_entries(8192, 0);

#[map(name = "GROUP_STATS_BUF")]
pub static GROUP_STATS_BUF: PerCpuArray<GroupStatsValue> = PerCpuArray::with_max_entries(1, 0);

// --- Mirror (Port SPAN) maps ---

// Shared managed runtime supports up to 1024 tap IDs. Global mirror rules are
// keyed by (tap_id, direction), so reserve two entries per tap.
const MIRROR_GLOBAL_MAX_ENTRIES: u32 = 2048;

#[map(name = "MIRROR_POLICY")]
pub static MIRROR_POLICY: HashMap<MirrorKey, MirrorConfig> = HashMap::with_max_entries(4096, 0);

#[map(name = "MIRROR_GLOBAL")]
pub static MIRROR_GLOBAL: HashMap<GlobalMirrorKey, MirrorConfig> =
    HashMap::with_max_entries(MIRROR_GLOBAL_MAX_ENTRIES, 0);

#[map(name = "MIRROR_STATS")]
pub static MIRROR_STATS: PerCpuHashMap<MirrorKey, MirrorStatsValue> = PerCpuHashMap::with_max_entries(4096, 0);

#[map(name = "MIRROR_GLOBAL_STATS")]
pub static MIRROR_GLOBAL_STATS: PerCpuHashMap<GlobalMirrorKey, MirrorStatsValue> =
    PerCpuHashMap::with_max_entries(MIRROR_GLOBAL_MAX_ENTRIES, 0);

#[map(name = "MIRROR_STATS_BUF")]
pub static MIRROR_STATS_BUF: PerCpuArray<MirrorStatsValue> = PerCpuArray::with_max_entries(1, 0);

// --- TCP-RT (TCP Response Time) maps ---

#[map(name = "TCPRT_TABLE_V4")]
pub static TCPRT_TABLE_V4: LruHashMap<CtKey4, TcpRtValue> = LruHashMap::with_max_entries(65536, 0);

#[map(name = "TCPRT_TABLE_V6")]
pub static TCPRT_TABLE_V6: LruHashMap<CtKey6, TcpRtValue> = LruHashMap::with_max_entries(16384, 0);

#[map(name = "TCPRT_VALUE_BUF")]
pub static TCPRT_VALUE_BUF: PerCpuArray<TcpRtValue> = PerCpuArray::with_max_entries(1, 0);

// --- Drop Reason Profiler ---

#[map(name = "DROP_REASON_STATS")]
pub static DROP_REASON_STATS: PerCpuHashMap<DropKey, DropValue> = PerCpuHashMap::with_max_entries(1024, 0);

#[map(name = "DROP_VALUE_BUF")]
pub static DROP_VALUE_BUF: PerCpuArray<DropValue> = PerCpuArray::with_max_entries(1, 0);

// --- Packet Trace ---

#[map(name = "TRACE_FILTER")]
pub static TRACE_FILTER: HashMap<u32, TraceFilter> = HashMap::with_max_entries(1024, 0);

#[map(name = "TRACE_LOG")]
pub static TRACE_LOG: LruHashMap<TraceEventKey, TraceEvent> = LruHashMap::with_max_entries(4096, 0);

#[map(name = "TRACE_LOG_V6")]
pub static TRACE_LOG_V6: LruHashMap<TraceEventKey, TraceEventV6> = LruHashMap::with_max_entries(4096, 0);

#[map(name = "TRACE_SEQ")]
pub static TRACE_SEQ: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "TRACE_EVENT_BUF")]
pub static TRACE_EVENT_BUF: PerCpuArray<TraceEvent> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "TRACE_EVENT_V6_BUF")]
pub static TRACE_EVENT_V6_BUF: PerCpuArray<TraceEventV6> = PerCpuArray::with_max_entries(1, 0);

// --- SSL Observability maps ---

#[map(name = "SSL_HANDSHAKE_SCRATCH")]
pub static SSL_HANDSHAKE_SCRATCH: HashMap<u64, SslScratch> = HashMap::with_max_entries(4096, 0);

#[map(name = "SSL_CONN_TABLE")]
pub static SSL_CONN_TABLE: LruHashMap<u64, SslConnValue> = LruHashMap::with_max_entries(16384, 0);

#[map(name = "SSL_SNI_TABLE")]
pub static SSL_SNI_TABLE: LruHashMap<u64, [u8; 64]> = LruHashMap::with_max_entries(4096, 0);

#[map(name = "SSL_SEQ")]
pub static SSL_SEQ: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

// --- SSL HTTP Observability maps ---

#[map(name = "SSL_HTTP_PARSE_BUF")]
pub static SSL_HTTP_PARSE_BUF: PerCpuArray<SslParseBuf> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "SSL_HTTP_SCRATCH")]
pub static SSL_HTTP_SCRATCH: HashMap<u64, SslHttpScratch> = HashMap::with_max_entries(4096, 0);

/// Per-CPU scratch for building SslHttpScratch without stack memset
#[map(name = "SSL_HTTP_SCRATCH_BUF")]
pub static SSL_HTTP_SCRATCH_BUF: PerCpuArray<SslHttpScratch> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "SSL_READ_SCRATCH")]
pub static SSL_READ_SCRATCH: HashMap<u64, SslReadScratch> = HashMap::with_max_entries(4096, 0);

#[map(name = "SSL_HTTP_TABLE")]
pub static SSL_HTTP_TABLE: LruHashMap<u64, SslHttpValue> = LruHashMap::with_max_entries(16384, 0);

#[map(name = "SSL_HTTP_SEQ")]
pub static SSL_HTTP_SEQ: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Per-CPU scratch for building SslHttpValue without stack overflow
#[map(name = "SSL_HTTP_VALUE_BUF")]
pub static SSL_HTTP_VALUE_BUF: PerCpuArray<SslHttpValue> = PerCpuArray::with_max_entries(1, 0);

/// Global SSL observability config (key=0)
/// SSL uprobe is process-level, not tied to any network interface
#[map(name = "SSL_GLOBAL_CONFIG")]
pub static SSL_GLOBAL_CONFIG: HashMap<u32, u8> = HashMap::with_max_entries(1, 0);

/// SSL error events table
#[map(name = "SSL_ERROR_TABLE")]
pub static SSL_ERROR_TABLE: LruHashMap<u64, SslErrorEvent> = LruHashMap::with_max_entries(4096, 0);

/// SSL error sequence counter (per-CPU)
#[map(name = "SSL_ERROR_SEQ")]
pub static SSL_ERROR_SEQ: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// SSL_write scratch: store ssl_ptr in entry, read in return
#[map(name = "SSL_WRITE_SCRATCH")]
pub static SSL_WRITE_SCRATCH: HashMap<u64, SslWriteScratch> = HashMap::with_max_entries(4096, 0);
