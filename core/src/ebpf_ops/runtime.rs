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

fn tap_config_with_acl_bank(current: TapConfig, bank: u8) -> TapConfig {
    TapConfig {
        acl_active_bank: normalize_acl_bank(bank),
        acl_ingress_hook: ACL_INGRESS_HOOK_TC,
        ..current
    }
}

fn tap_config_with_runtime_updates(
    current: TapConfig,
    conntrack_enabled: Option<bool>,
    monitoring_enabled: Option<bool>,
    acl_enabled: Option<bool>,
    qos_enabled: Option<bool>,
    mirror_enabled: Option<bool>,
    tcprt_enabled: Option<bool>,
) -> TapConfig {
    TapConfig {
        conntrack_enabled: conntrack_enabled
            .map(|b| if b { 1 } else { 0 })
            .unwrap_or(current.conntrack_enabled),
        monitoring_enabled: monitoring_enabled
            .map(|b| if b { 1 } else { 0 })
            .unwrap_or(current.monitoring_enabled),
        acl_enabled: acl_enabled
            .map(|b| if b { 1 } else { 0 })
            .unwrap_or(current.acl_enabled),
        qos_enabled: qos_enabled
            .map(|b| if b { 1 } else { 0 })
            .unwrap_or(current.qos_enabled),
        mirror_enabled: mirror_enabled
            .map(|b| if b { 1 } else { 0 })
            .unwrap_or(current.mirror_enabled),
        tcprt_enabled: tcprt_enabled
            .map(|b| if b { 1 } else { 0 })
            .unwrap_or(current.tcprt_enabled),
        acl_active_bank: current.acl_active_bank,
        acl_ingress_hook: ACL_INGRESS_HOOK_TC,
    }
}

fn tap_config_with_acl_runtime_gate(
    current: TapConfig,
    conntrack_enabled: bool,
    acl_enabled: bool,
    _acl_ingress_hook: u8,
) -> TapConfig {
    TapConfig {
        conntrack_enabled: if conntrack_enabled { 1 } else { 0 },
        monitoring_enabled: current.monitoring_enabled,
        acl_enabled: if acl_enabled { 1 } else { 0 },
        qos_enabled: current.qos_enabled,
        mirror_enabled: current.mirror_enabled,
        tcprt_enabled: current.tcprt_enabled,
        acl_active_bank: current.acl_active_bank,
        acl_ingress_hook: ACL_INGRESS_HOOK_TC,
    }
}

fn required_tap_config(
    lookup: Result<TapConfig, aya::maps::MapError>,
    tap_id: u32,
    operation: &str,
) -> Result<TapConfig, String> {
    match lookup {
        Ok(config) => Ok(config),
        Err(aya::maps::MapError::KeyNotFound) => Err(format!(
            "{} requires initialized TAP_CONFIG_MAP for tap_id {}",
            operation, tap_id
        )),
        Err(error) => Err(format!(
            "{} read TAP_CONFIG_MAP for tap_id {}: {}",
            operation, tap_id, error
        )),
    }
}

pub fn set_acl_active_bank(runtime: TapMapRuntime<'_>, bank: u8) -> Result<(), String> {
    if runtime.tap_id == TAP_ID_UNASSIGNED {
        return Err("ACL active bank is only supported for per-tap runtime config".to_string());
    }

    let mut map = open_pinned_tap_config(runtime.pin_path)?;
    let current = required_tap_config(
        map.get(&runtime.tap_id, 0),
        runtime.tap_id,
        "active bank update",
    )?;
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

pub fn update_acl_runtime_gate(
    runtime: TapMapRuntime<'_>,
    conntrack_enabled: bool,
    acl_enabled: bool,
    acl_ingress_hook: u8,
) -> Result<(), String> {
    if runtime.tap_id == TAP_ID_UNASSIGNED {
        return Err("ACL runtime gate is only supported for per-tap runtime config".to_string());
    }

    let mut map = open_pinned_tap_config(runtime.pin_path)?;
    let current = required_tap_config(
        map.get(&runtime.tap_id, 0),
        runtime.tap_id,
        "ACL runtime gate update",
    )?;
    let cfg = tap_config_with_acl_runtime_gate(
        current,
        conntrack_enabled,
        acl_enabled,
        acl_ingress_hook,
    );
    map.insert(&runtime.tap_id, &cfg, 0).map_err(|e| {
        format!(
            "TAP_CONFIG_MAP insert for tap_id {}: {:?}",
            runtime.tap_id, e
        )
    })
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
    let current = required_tap_config(
        map.get(&runtime.tap_id, 0),
        runtime.tap_id,
        "partial update",
    )?;
    let cfg = tap_config_with_runtime_updates(
        current,
        conntrack_enabled,
        monitoring_enabled,
        acl_enabled,
        qos_enabled,
        mirror_enabled,
        tcprt_enabled,
    );
    map.insert(&runtime.tap_id, &cfg, 0).map_err(|e| {
        format!(
            "TAP_CONFIG_MAP insert for tap_id {}: {:?}",
            runtime.tap_id, e
        )
    })
}

fn required_firewall_config(
    lookup: Result<FirewallConfig, aya::maps::MapError>,
    full_initialization: bool,
    operation: &str,
) -> Result<Option<FirewallConfig>, String> {
    match lookup {
        Ok(config) => Ok(Some(config)),
        Err(aya::maps::MapError::KeyNotFound) if full_initialization => Ok(None),
        Err(aya::maps::MapError::KeyNotFound) => Err(format!(
            "{} requires initialized FIREWALL_CONFIG key 0",
            operation
        )),
        Err(error) => Err(format!(
            "{} read FIREWALL_CONFIG key 0: {}",
            operation, error
        )),
    }
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

    let full_initialization = conntrack_enabled.is_some()
        && monitoring_enabled.is_some()
        && acl_enabled.is_some()
        && qos_enabled.is_some()
        && mirror_enabled.is_some()
        && tcprt_enabled.is_some()
        && ssl_enabled.is_some();
    let operation = if full_initialization {
        "full initialization"
    } else {
        "partial update"
    };
    let current = required_firewall_config(
        map.get(&0u32, 0),
        full_initialization,
        operation,
    )?;
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
        _pad: [0; 1],
    };
    map.insert(&0u32, &cfg, 0)
        .map_err(|e| format!("FIREWALL_CONFIG insert: {:?}", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        required_firewall_config, required_tap_config, tap_config_with_acl_bank,
        tap_config_with_acl_runtime_gate, tap_config_with_runtime_updates,
    };
    use crate::common::{
        FirewallConfig, TapConfig, ACL_INGRESS_HOOK_TC, ACL_INGRESS_HOOK_XDP,
    };
    use aya::maps::MapError;

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
            acl_ingress_hook: ACL_INGRESS_HOOK_XDP,
        };

        let next = tap_config_with_acl_bank(current, 1);

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
            current,
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

    #[test]
    fn acl_ingress_hook_gate_transformer_preserves_runtime_and_forces_tc() {
        let current = TapConfig {
            conntrack_enabled: 0,
            monitoring_enabled: 0,
            acl_enabled: 0,
            qos_enabled: 1,
            mirror_enabled: 1,
            tcprt_enabled: 1,
            acl_active_bank: 1,
            acl_ingress_hook: ACL_INGRESS_HOOK_XDP,
        };

        let next = tap_config_with_acl_runtime_gate(current, true, true, 255);

        assert_eq!(next.conntrack_enabled, 1);
        assert_eq!(next.monitoring_enabled, 0);
        assert_eq!(next.acl_enabled, 1);
        assert_eq!(next.qos_enabled, 1);
        assert_eq!(next.mirror_enabled, 1);
        assert_eq!(next.tcprt_enabled, 1);
        assert_eq!(next.acl_active_bank, 1);
        assert_eq!(next.acl_ingress_hook, ACL_INGRESS_HOOK_TC);
    }

    #[test]
    fn tap_runtime_config_rejects_missing_and_non_key_not_found_reads() {
        let missing = required_tap_config(Err(MapError::KeyNotFound), 42, "partial update")
            .unwrap_err();
        assert_eq!(
            missing,
            "partial update requires initialized TAP_CONFIG_MAP for tap_id 42"
        );

        let read_error = required_tap_config(
            Err(MapError::InvalidKeySize {
                size: 1,
                expected: 4,
            }),
            42,
            "active bank update",
        )
        .unwrap_err();
        assert_eq!(
            read_error,
            "active bank update read TAP_CONFIG_MAP for tap_id 42: invalid key size 1, expected 4"
        );
    }

    #[test]
    fn global_runtime_partial_update_requires_an_existing_config() {
        let missing = required_firewall_config(
            Err(MapError::KeyNotFound),
            false,
            "partial update",
        )
        .unwrap_err();
        assert_eq!(
            missing,
            "partial update requires initialized FIREWALL_CONFIG key 0"
        );

        let read_error = required_firewall_config(
            Err(MapError::InvalidValueSize {
                size: 1,
                expected: core::mem::size_of::<FirewallConfig>(),
            }),
            false,
            "partial update",
        )
        .unwrap_err();
        assert!(read_error.starts_with("partial update read FIREWALL_CONFIG key 0:"));
    }

    #[test]
    fn global_runtime_full_initialization_only_accepts_key_not_found() {
        assert!(required_firewall_config(
            Err(MapError::KeyNotFound),
            true,
            "full initialization",
        )
        .unwrap()
        .is_none());
        let existing = FirewallConfig {
            conntrack_enabled: 0,
            monitoring_enabled: 1,
            num_cpus: 8,
            qos_enabled: 0,
            acl_enabled: 0,
            mirror_enabled: 0,
            tcprt_enabled: 0,
            ssl_enabled: 0,
            _pad: [0; 1],
        };
        assert_eq!(
            required_firewall_config(Ok(existing), true, "full initialization")
                .unwrap()
                .unwrap()
                .num_cpus,
            8
        );
    }

    #[test]
    fn tap_runtime_config_partial_writes_force_tc_and_preserve_unrelated_fields() {
        let current = TapConfig {
            conntrack_enabled: 1,
            monitoring_enabled: 0,
            acl_enabled: 1,
            qos_enabled: 1,
            mirror_enabled: 1,
            tcprt_enabled: 0,
            acl_active_bank: 1,
            acl_ingress_hook: ACL_INGRESS_HOOK_XDP,
        };
        let next = tap_config_with_runtime_updates(
            current,
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

    let global = read_firewall_config(runtime)?;

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
        _pad: [0; 1],
    })
}
