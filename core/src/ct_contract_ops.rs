use aya::maps::{MapData, PerCpuHashMap, PerCpuValues};

use crate::common::{CtContractKey, CtContractValue, TapMapRuntime};

pub struct CtContractStatsEntry {
    pub hook: u8,
    pub family: u8,
    pub reason: u8,
    pub packets: u64,
    pub bytes: u64,
    pub last_seen: u64,
}

fn sum_per_cpu_contract(values: PerCpuValues<CtContractValue>) -> (u64, u64, u64) {
    let mut packets = 0u64;
    let mut bytes = 0u64;
    let mut last_seen = 0u64;
    for v in values.iter() {
        packets += v.packets;
        bytes += v.bytes;
        if v.last_seen > last_seen {
            last_seen = v.last_seen;
        }
    }
    (packets, bytes, last_seen)
}

pub fn get_ct_contract_stats(
    runtime: TapMapRuntime<'_>,
) -> Result<Vec<CtContractStatsEntry>, String> {
    let pin_path = runtime.pin_path;
    let map_path = format!("{}/CT_CONTRACT_STATS", pin_path);
    let map_data =
        MapData::from_pin(&map_path).map_err(|e| format!("open CT_CONTRACT_STATS: {:?}", e))?;
    let map = PerCpuHashMap::<_, CtContractKey, CtContractValue>::try_from(
        aya::maps::Map::PerCpuHashMap(map_data),
    )
    .map_err(|e| format!("convert CT_CONTRACT_STATS: {:?}", e))?;

    let mut entries = Vec::new();
    for item in map.iter() {
        if let Ok((key, values)) = item {
            if key.tap_id != runtime.tap_id {
                continue;
            }
            let (packets, bytes, last_seen) = sum_per_cpu_contract(values);
            if packets > 0 {
                entries.push(CtContractStatsEntry {
                    hook: key.hook,
                    family: key.family,
                    reason: key.reason,
                    packets,
                    bytes,
                    last_seen,
                });
            }
        }
    }

    entries.sort_by(|a, b| b.packets.cmp(&a.packets));
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::fold_ct_contract_entries;
    use crate::common::CtContractKey;

    fn key(tap_id: u32, hook: u8) -> CtContractKey {
        CtContractKey {
            tap_id,
            hook,
            family: 4,
            reason: 1,
            pad: 0,
        }
    }

    #[test]
    fn ct_contract_stats_iteration_propagates_errors() {
        let items = vec![
            Ok((key(3, 0), 10u64, 100u64, 1u64)),
            Err("injected".to_string()),
            Ok((key(3, 1), 20u64, 200u64, 2u64)),
        ];
        let result = fold_ct_contract_entries(items, 3);

        match result {
            Err(error) => assert!(error.contains("injected")),
            Ok(_) => panic!("expected the iteration error to propagate"),
        }
    }

    #[test]
    fn ct_contract_stats_iteration_filters_and_sorts_entries() {
        let items = vec![
            Ok((key(3, 0), 10u64, 100u64, 5u64)),
            Ok((key(4, 0), 99u64, 900u64, 9u64)),
            Ok((key(3, 1), 30u64, 300u64, 7u64)),
        ];
        let result = fold_ct_contract_entries(items, 3).unwrap();

        assert_eq!(2, result.len());
        assert_eq!(30, result[0].packets);
        assert_eq!(10, result[1].packets);
        assert_eq!(1, result[0].hook);
        assert_eq!(1, result[0].reason);
    }
}
