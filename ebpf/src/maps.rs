use aya_ebpf::maps::{HashMap, LpmTrie};
use aya_ebpf::macros::map;

pub use crate::common::{PolicyKey, PolicyValue, PortKey};

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