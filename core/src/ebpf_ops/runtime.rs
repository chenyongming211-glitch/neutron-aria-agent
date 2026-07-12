use super::*;

pub fn sync_iface_ctx(runtime: TapMapRuntime<'_>, ifindex: u32) -> Result<(), String> {
    let mut map = open_pinned_iface_ctx(runtime.pin_path)?;
    let ctx = IfaceCtx {
        tap_id: runtime.tap_id,
        flags: 0,
    };
    map.insert(&ifindex, &ctx, 0)
        .map_err(|e| format!("IFACE_CTX_MAP insert for ifindex {}: {:?}", ifindex, e))
}

pub fn read_iface_ctx(pin_path: &str, ifindex: u32) -> Result<IfaceCtx, String> {
    let map = open_pinned_iface_ctx(pin_path)?;
    map.get(&ifindex, 0)
        .map_err(|e| format!("read IFACE_CTX_MAP for ifindex {}: {:?}", ifindex, e))
}

pub fn clear_iface_ctx(pin_path: &str, ifindex: u32) -> Result<(), String> {
    let mut map = open_pinned_iface_ctx(pin_path)?;
    match map.remove(&ifindex) {
        Ok(()) => Ok(()),
        Err(e) => Err(format!(
            "IFACE_CTX_MAP remove for ifindex {}: {:?}",
            ifindex, e
        )),
    }
}

pub fn write_tap_config(runtime: TapMapRuntime<'_>, config: TapConfig) -> Result<(), String> {
    let mut map = open_pinned_tap_config(runtime.pin_path)?;
    map.insert(&runtime.tap_id, &config, 0).map_err(|e| {
        format!(
            "TAP_CONFIG_MAP insert for tap_id {}: {:?}",
            runtime.tap_id, e
        )
    })
}

pub fn delete_tap_config(runtime: TapMapRuntime<'_>) -> Result<(), String> {
    let mut map = open_pinned_tap_config(runtime.pin_path)?;
    match map.remove(&runtime.tap_id) {
        Ok(()) => Ok(()),
        Err(e) => Err(format!(
            "TAP_CONFIG_MAP remove for tap_id {}: {:?}",
            runtime.tap_id, e
        )),
    }
}

fn tap_config_with_acl_bank(current: Option<TapConfig>, bank: u8) -> TapConfig {
    let current = current.as_ref();
    TapConfig {
        conntrack_enabled: current.map(|c| c.conntrack_enabled).unwrap_or(1),
        monitoring_enabled: current.map(|c| c.monitoring_enabled).unwrap_or(1),
        acl_enabled: current.map(|c| c.acl_enabled).unwrap_or(1),
        qos_enabled: current.map(|c| c.qos_enabled).unwrap_or(0),
        mirror_enabled: current.map(|c| c.mirror_enabled).unwrap_or(0),
        tcprt_enabled: current.map(|c| c.tcprt_enabled).unwrap_or(0),
        acl_active_bank: normalize_acl_bank(bank),
        pad: [0; 1],
    }
}

pub fn set_acl_active_bank(runtime: TapMapRuntime<'_>, bank: u8) -> Result<(), String> {
    if runtime.tap_id == TAP_ID_UNASSIGNED {
        return Err("ACL active bank is only supported for per-tap runtime config".to_string());
    }

    let mut map = open_pinned_tap_config(runtime.pin_path)?;
    let current = map.get(&runtime.tap_id, 0).ok();
    let cfg = tap_config_with_acl_bank(current, bank);
    map.insert(&runtime.tap_id, &cfg, 0).map_err(|e| {
        format!(
            "TAP_CONFIG_MAP insert for tap_id {}: {:?}",
            runtime.tap_id, e
        )
    })
}

pub fn read_acl_active_bank(runtime: TapMapRuntime<'_>) -> Result<u8, String> {
    if runtime.tap_id == TAP_ID_UNASSIGNED {
        return Ok(ACL_BANK_PRIMARY);
    }

    let map = open_pinned_tap_config(runtime.pin_path)?;
    let cfg = map
        .get(&runtime.tap_id, 0)
        .map_err(|e| format!("read TAP_CONFIG_MAP for tap_id {}: {:?}", runtime.tap_id, e))?;
    Ok(normalize_acl_bank(cfg.acl_active_bank))
}

pub fn update_runtime_config(
    runtime: TapMapRuntime<'_>,
    conntrack_enabled: Option<bool>,
    monitoring_enabled: Option<bool>,
    acl_enabled: Option<bool>,
    qos_enabled: Option<bool>,
    mirror_enabled: Option<bool>,
    tcprt_enabled: Option<bool>,
    ssl_enabled: Option<bool>,
) -> Result<(), String> {
    if runtime.tap_id == TAP_ID_UNASSIGNED {
        return update_firewall_config(
            runtime,
            conntrack_enabled,
            monitoring_enabled,
            acl_enabled,
            qos_enabled,
            mirror_enabled,
            tcprt_enabled,
            ssl_enabled,
        );
    }

    let mut map = open_pinned_tap_config(runtime.pin_path)?;
    let current = map.get(&runtime.tap_id, 0).ok();
    let cfg = TapConfig {
        conntrack_enabled: conntrack_enabled
            .map(|b| if b { 1 } else { 0 })
            .unwrap_or_else(|| current.as_ref().map(|c| c.conntrack_enabled).unwrap_or(1)),
        monitoring_enabled: monitoring_enabled
            .map(|b| if b { 1 } else { 0 })
            .unwrap_or_else(|| current.as_ref().map(|c| c.monitoring_enabled).unwrap_or(1)),
        acl_enabled: acl_enabled
            .map(|b| if b { 1 } else { 0 })
            .unwrap_or_else(|| current.as_ref().map(|c| c.acl_enabled).unwrap_or(1)),
        qos_enabled: qos_enabled
            .map(|b| if b { 1 } else { 0 })
            .unwrap_or_else(|| current.as_ref().map(|c| c.qos_enabled).unwrap_or(0)),
        mirror_enabled: mirror_enabled
            .map(|b| if b { 1 } else { 0 })
            .unwrap_or_else(|| current.as_ref().map(|c| c.mirror_enabled).unwrap_or(0)),
        tcprt_enabled: tcprt_enabled
            .map(|b| if b { 1 } else { 0 })
            .unwrap_or_else(|| current.as_ref().map(|c| c.tcprt_enabled).unwrap_or(0)),
        acl_active_bank: current
            .as_ref()
            .map(|c| normalize_acl_bank(c.acl_active_bank))
            .unwrap_or(ACL_BANK_PRIMARY),
        pad: [0; 1],
    };
    map.insert(&runtime.tap_id, &cfg, 0).map_err(|e| {
        format!(
            "TAP_CONFIG_MAP insert for tap_id {}: {:?}",
            runtime.tap_id, e
        )
    })
}

/// Update FIREWALL_CONFIG map at runtime via pinned map.
/// Reads the current config, applies the changes, and writes back.
pub fn update_firewall_config(
    runtime: TapMapRuntime<'_>,
    conntrack_enabled: Option<bool>,
    monitoring_enabled: Option<bool>,
    acl_enabled: Option<bool>,
    qos_enabled: Option<bool>,
    mirror_enabled: Option<bool>,
    tcprt_enabled: Option<bool>,
    ssl_enabled: Option<bool>,
) -> Result<(), String> {
    let pin_path = runtime.pin_path;
    let map_path = format!("{}/FIREWALL_CONFIG", pin_path);
    let map_data =
        MapData::from_pin(&map_path).map_err(|e| format!("open FIREWALL_CONFIG: {:?}", e))?;
    let mut map =
        aya::maps::HashMap::<_, u32, FirewallConfig>::try_from(aya::maps::Map::HashMap(map_data))
            .map_err(|e| format!("convert FIREWALL_CONFIG: {:?}", e))?;

    let current = map.get(&0u32, 0).ok();
    let num_cpus_val = current.as_ref().map(|c| c.num_cpus).unwrap_or_else(|| {
        let raw = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
        if raw > 0 {
            raw as u16
        } else {
            1u16
        }
    });
    let ct = conntrack_enabled
        .map(|b| if b { 1u8 } else { 0 })
        .unwrap_or_else(|| current.as_ref().map(|c| c.conntrack_enabled).unwrap_or(1));
    let mon = monitoring_enabled
        .map(|b| if b { 1u8 } else { 0 })
        .unwrap_or_else(|| current.as_ref().map(|c| c.monitoring_enabled).unwrap_or(1));
    let acl = acl_enabled
        .map(|b| if b { 1u8 } else { 0 })
        .unwrap_or_else(|| current.as_ref().map(|c| c.acl_enabled).unwrap_or(1));
    let qos = qos_enabled
        .map(|b| if b { 1u8 } else { 0 })
        .unwrap_or_else(|| current.as_ref().map(|c| c.qos_enabled).unwrap_or(0));
    let mir = mirror_enabled
        .map(|b| if b { 1u8 } else { 0 })
        .unwrap_or_else(|| current.as_ref().map(|c| c.mirror_enabled).unwrap_or(0));
    let tcprt = tcprt_enabled
        .map(|b| if b { 1u8 } else { 0 })
        .unwrap_or_else(|| current.as_ref().map(|c| c.tcprt_enabled).unwrap_or(0));
    let ssl = ssl_enabled
        .map(|b| if b { 1u8 } else { 0 })
        .unwrap_or_else(|| current.as_ref().map(|c| c.ssl_enabled).unwrap_or(0));

    let cfg = FirewallConfig {
        conntrack_enabled: ct,
        monitoring_enabled: mon,
        num_cpus: num_cpus_val,
        qos_enabled: qos,
        acl_enabled: acl,
        mirror_enabled: mir,
        tcprt_enabled: tcprt,
        ssl_enabled: ssl,
    };
    map.insert(&0u32, &cfg, 0)
        .map_err(|e| format!("FIREWALL_CONFIG insert: {:?}", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{tap_config_with_acl_bank, tap_config_with_runtime_updates};
    use crate::common::{TapConfig, ACL_INGRESS_HOOK_TC};

    #[test]
    fn acl_ingress_hook_active_bank_update_preserves_tc_mode() {
        let current = TapConfig {
            conntrack_enabled: 1,
            monitoring_enabled: 0,
            acl_enabled: 1,
            qos_enabled: 1,
            mirror_enabled: 1,
            tcprt_enabled: 0,
            acl_active_bank: 0,
            acl_ingress_hook: ACL_INGRESS_HOOK_TC,
        };

        let next = tap_config_with_acl_bank(Some(current), 1);

        assert_eq!(next.conntrack_enabled, 1);
        assert_eq!(next.monitoring_enabled, 0);
        assert_eq!(next.acl_enabled, 1);
        assert_eq!(next.qos_enabled, 1);
        assert_eq!(next.mirror_enabled, 1);
        assert_eq!(next.tcprt_enabled, 0);
        assert_eq!(next.acl_active_bank, 1);
        assert_eq!(next.acl_ingress_hook, ACL_INGRESS_HOOK_TC);
    }

    #[test]
    fn acl_ingress_hook_partial_feature_update_preserves_tc_mode() {
        let current = TapConfig {
            conntrack_enabled: 1,
            monitoring_enabled: 0,
            acl_enabled: 1,
            qos_enabled: 1,
            mirror_enabled: 1,
            tcprt_enabled: 0,
            acl_active_bank: 1,
            acl_ingress_hook: ACL_INGRESS_HOOK_TC,
        };

        let next = tap_config_with_runtime_updates(
            Some(current),
            None,
            Some(true),
            None,
            None,
            None,
            None,
        );

        assert_eq!(next.conntrack_enabled, 1);
        assert_eq!(next.monitoring_enabled, 1);
        assert_eq!(next.acl_enabled, 1);
        assert_eq!(next.qos_enabled, 1);
        assert_eq!(next.mirror_enabled, 1);
        assert_eq!(next.tcprt_enabled, 0);
        assert_eq!(next.acl_active_bank, 1);
        assert_eq!(next.acl_ingress_hook, ACL_INGRESS_HOOK_TC);
    }
}

/// Read the current FIREWALL_CONFIG from pinned map.
pub fn read_firewall_config(runtime: TapMapRuntime<'_>) -> Result<FirewallConfig, String> {
    let pin_path = runtime.pin_path;
    let map_path = format!("{}/FIREWALL_CONFIG", pin_path);
    let map_data =
        MapData::from_pin(&map_path).map_err(|e| format!("open FIREWALL_CONFIG: {:?}", e))?;
    let map =
        aya::maps::HashMap::<_, u32, FirewallConfig>::try_from(aya::maps::Map::HashMap(map_data))
            .map_err(|e| format!("convert FIREWALL_CONFIG: {:?}", e))?;

    map.get(&0u32, 0)
        .map_err(|e| format!("read FIREWALL_CONFIG: {:?}", e))
}

pub fn read_runtime_config(runtime: TapMapRuntime<'_>) -> Result<FirewallConfig, String> {
    if runtime.tap_id == TAP_ID_UNASSIGNED {
        return read_firewall_config(runtime);
    }

    let global = read_firewall_config(runtime).unwrap_or_else(|_| {
        let raw = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
        FirewallConfig {
            conntrack_enabled: 1,
            monitoring_enabled: 1,
            num_cpus: if raw > 0 { raw as u16 } else { 1u16 },
            qos_enabled: 0,
            acl_enabled: 1,
            mirror_enabled: 0,
            tcprt_enabled: 1,
            ssl_enabled: 0,
        }
    });

    let map = open_pinned_tap_config(runtime.pin_path)?;
    let tap_cfg = map
        .get(&runtime.tap_id, 0)
        .map_err(|e| format!("read TAP_CONFIG_MAP for tap_id {}: {:?}", runtime.tap_id, e))?;

    Ok(FirewallConfig {
        conntrack_enabled: tap_cfg.conntrack_enabled,
        monitoring_enabled: tap_cfg.monitoring_enabled,
        num_cpus: global.num_cpus,
        qos_enabled: tap_cfg.qos_enabled,
        acl_enabled: tap_cfg.acl_enabled,
        mirror_enabled: tap_cfg.mirror_enabled,
        tcprt_enabled: tap_cfg.tcprt_enabled,
        ssl_enabled: global.ssl_enabled,
    })
}
