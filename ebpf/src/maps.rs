use aya_ebpf::maps::{Array, HashMap, LpmTrie};
use aya_ebpf::macros::map;

pub use crate::common::{PolicyKey, PolicyValue};

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

// 扁平位图池：64 个策略组 × 65536 端口 = 4MB
// 注意：aya-ebpf 0.1 不支持 ArrayOfMaps，使用 flat Array 方案
// 如果升级到支持 ArrayOfMaps 的版本，应改为嵌套结构以减少内存占用
#[map(name = "PORT_BITMAP_POOL")]
pub static PORT_BITMAP_POOL: Array<u8> = Array::with_max_entries(64 * 65536, 0);