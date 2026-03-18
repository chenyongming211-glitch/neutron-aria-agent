use aya_ebpf::maps::{HashMap, LpmTrie, LruHashMap, PerCpuHashMap, LruPerCpuHashMap, PerCpuArray};
use aya_ebpf::macros::map;

pub use crate::common::{
    PolicyKey, PolicyValue, PortKey,
    CtKey4, CtKey6, CtValue, CtConfig,
    RuleStatsValue, FlowStatsValue,
    QosKey, QosConfig, TokenBucket, QosStatsValue,
    GroupStatsKey, GroupStatsValue,
    MirrorKey, GlobalMirrorKey, MirrorConfig, MirrorStatsValue,
    FirewallConfig,
    TcpRtValue,
    DropKey, DropValue,
    TraceFilter, TraceEvent,
    PipelineCtx,
};
use crate::parser::PacketInfo;

// --- Scratch buffer for PacketInfo (avoids stack allocation) ---

#[map(name = "PKT_SCRATCH")]
pub static PKT_SCRATCH: PerCpuArray<PacketInfo> = PerCpuArray::with_max_entries(1, 0);

// --- Pipeline scratch context (inter-phase communication) ---

#[map(name = "PIPE_SCRATCH")]
pub static PIPE_SCRATCH: PerCpuArray<PipelineCtx> = PerCpuArray::with_max_entries(1, 0);

// --- Existing maps ---

#[map(name = "SRC_IPV4_TRIE")]
pub static SRC_IPV4_TRIE: LpmTrie<[u8; 4], u32> = LpmTrie::with_max_entries(10000, 0);

#[map(name = "DST_IPV4_TRIE")]
pub static DST_IPV4_TRIE: LpmTrie<[u8; 4], u32> = LpmTrie::with_max_entries(10000, 0);

#[map(name = "SRC_IPV6_TRIE")]
pub static SRC_IPV6_TRIE: LpmTrie<[u8; 16], u32> = LpmTrie::with_max_entries(5000, 0);

#[map(name = "DST_IPV6_TRIE")]
pub static DST_IPV6_TRIE: LpmTrie<[u8; 16], u32> = LpmTrie::with_max_entries(5000, 0);

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

// 全局配置：特性开关等（key=0）
#[map(name = "FIREWALL_CONFIG")]
pub static FIREWALL_CONFIG: HashMap<u32, FirewallConfig> = HashMap::with_max_entries(1, 0);

// --- Traffic statistics maps ---

#[map(name = "RULE_STATS")]
pub static RULE_STATS: PerCpuHashMap<PolicyKey, RuleStatsValue> = PerCpuHashMap::with_max_entries(65536, 0);

// BPF_F_NO_PREALLOC (1) for LRU per-CPU maps
#[map(name = "FLOW_STATS_V4")]
pub static FLOW_STATS_V4: LruPerCpuHashMap<CtKey4, FlowStatsValue> = LruPerCpuHashMap::with_max_entries(16384, 0);

#[map(name = "FLOW_STATS_V6")]
pub static FLOW_STATS_V6: LruPerCpuHashMap<CtKey6, FlowStatsValue> = LruPerCpuHashMap::with_max_entries(4096, 0);

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

// --- Per-group statistics ---

#[map(name = "GROUP_STATS")]
pub static GROUP_STATS: PerCpuHashMap<GroupStatsKey, GroupStatsValue> = PerCpuHashMap::with_max_entries(8192, 0);

// --- Mirror (Port SPAN) maps ---

#[map(name = "MIRROR_POLICY")]
pub static MIRROR_POLICY: HashMap<MirrorKey, MirrorConfig> = HashMap::with_max_entries(4096, 0);

#[map(name = "MIRROR_GLOBAL")]
pub static MIRROR_GLOBAL: HashMap<GlobalMirrorKey, MirrorConfig> = HashMap::with_max_entries(2, 0);

#[map(name = "MIRROR_STATS")]
pub static MIRROR_STATS: PerCpuHashMap<MirrorKey, MirrorStatsValue> = PerCpuHashMap::with_max_entries(4096, 0);

#[map(name = "MIRROR_GLOBAL_STATS")]
pub static MIRROR_GLOBAL_STATS: PerCpuHashMap<GlobalMirrorKey, MirrorStatsValue> = PerCpuHashMap::with_max_entries(2, 0);

// --- TCP-RT (TCP Response Time) maps ---

#[map(name = "TCPRT_TABLE_V4")]
pub static TCPRT_TABLE_V4: LruHashMap<CtKey4, TcpRtValue> = LruHashMap::with_max_entries(65536, 0);

#[map(name = "TCPRT_TABLE_V6")]
pub static TCPRT_TABLE_V6: LruHashMap<CtKey6, TcpRtValue> = LruHashMap::with_max_entries(16384, 0);

// --- Drop Reason Profiler ---

#[map(name = "DROP_REASON_STATS")]
pub static DROP_REASON_STATS: PerCpuHashMap<DropKey, DropValue> = PerCpuHashMap::with_max_entries(1024, 0);

// --- Packet Trace ---

#[map(name = "TRACE_FILTER")]
pub static TRACE_FILTER: HashMap<u32, TraceFilter> = HashMap::with_max_entries(1, 0);

#[map(name = "TRACE_LOG")]
pub static TRACE_LOG: LruHashMap<u64, TraceEvent> = LruHashMap::with_max_entries(4096, 0);

#[map(name = "TRACE_SEQ")]
pub static TRACE_SEQ: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
