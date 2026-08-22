use crate::common::{
    acl_ct_runtime_source, normalize_acl_bank, AclCtRuntimeSource, FirewallConfig,
    ACL_BANK_PRIMARY, TAP_ID_UNASSIGNED,
};
use crate::maps::{FIREWALL_CONFIG, TAP_CONFIG_MAP};

#[inline(always)]
fn read_global_config() -> Option<FirewallConfig> {
    let key: u32 = 0;
    unsafe { FIREWALL_CONFIG.get(&key).copied() }
}

#[inline(always)]
pub fn conntrack_enabled(tap_id: u32) -> bool {
    let global = read_global_config();
    match acl_ct_runtime_source(global.as_ref(), tap_id) {
        AclCtRuntimeSource::BypassAclAndConntrack => return false,
        AclCtRuntimeSource::PerTapThenGlobal => {
            if let Some(cfg) = unsafe { TAP_CONFIG_MAP.get(&tap_id) } {
                return cfg.conntrack_enabled != 0;
            }
        }
        AclCtRuntimeSource::GlobalOnly => {}
    }
    global
        .map(|cfg| cfg.conntrack_enabled != 0)
        .unwrap_or(true)
}

#[inline(always)]
pub fn monitoring_enabled(tap_id: u32) -> bool {
    if tap_id != TAP_ID_UNASSIGNED {
        if let Some(cfg) = unsafe { TAP_CONFIG_MAP.get(&tap_id) } {
            return cfg.monitoring_enabled != 0;
        }
    }
    read_global_config()
        .map(|cfg| cfg.monitoring_enabled != 0)
        .unwrap_or(true)
}

#[inline(always)]
pub fn acl_enabled(tap_id: u32) -> bool {
    let global = read_global_config();
    match acl_ct_runtime_source(global.as_ref(), tap_id) {
        AclCtRuntimeSource::BypassAclAndConntrack => return false,
        AclCtRuntimeSource::PerTapThenGlobal => {
            if let Some(cfg) = unsafe { TAP_CONFIG_MAP.get(&tap_id) } {
                return cfg.acl_enabled != 0;
            }
        }
        AclCtRuntimeSource::GlobalOnly => {}
    }
    global
        .map(|cfg| cfg.acl_enabled != 0)
        .unwrap_or(true)
}

#[inline(always)]
pub fn acl_active_bank(tap_id: u32) -> u8 {
    if tap_id != TAP_ID_UNASSIGNED {
        if let Some(cfg) = unsafe { TAP_CONFIG_MAP.get(&tap_id) } {
            return normalize_acl_bank(cfg.acl_active_bank);
        }
    }
    read_global_config()
        .map(|cfg| normalize_acl_bank(cfg.acl_active_bank))
        .unwrap_or(ACL_BANK_PRIMARY)
}

#[inline(always)]
pub fn qos_enabled(tap_id: u32) -> bool {
    if tap_id != TAP_ID_UNASSIGNED {
        if let Some(cfg) = unsafe { TAP_CONFIG_MAP.get(&tap_id) } {
            return cfg.qos_enabled != 0;
        }
    }
    read_global_config()
        .map(|cfg| cfg.qos_enabled != 0)
        .unwrap_or(false)
}

#[inline(always)]
pub fn mirror_enabled(tap_id: u32) -> bool {
    if tap_id != TAP_ID_UNASSIGNED {
        if let Some(cfg) = unsafe { TAP_CONFIG_MAP.get(&tap_id) } {
            return cfg.mirror_enabled != 0;
        }
    }
    read_global_config()
        .map(|cfg| cfg.mirror_enabled != 0)
        .unwrap_or(false)
}

#[inline(always)]
pub fn tcprt_enabled(tap_id: u32) -> bool {
    if tap_id != TAP_ID_UNASSIGNED {
        if let Some(cfg) = unsafe { TAP_CONFIG_MAP.get(&tap_id) } {
            return cfg.tcprt_enabled != 0;
        }
    }
    read_global_config()
        .map(|cfg| cfg.tcprt_enabled != 0)
        .unwrap_or(false)
}
