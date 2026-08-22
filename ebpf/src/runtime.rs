use crate::common::{
    acl_ct_packet_sample_flags, normalize_acl_bank, packet_acl_ct_phase_enabled, FirewallConfig,
    PipelineCtx, ACL_BANK_PRIMARY, FLAG_ACL_ON, FLAG_CT_ON, TAP_ID_UNASSIGNED,
};
use crate::maps::{FIREWALL_CONFIG, TAP_CONFIG_MAP};

#[inline(always)]
fn read_global_config() -> Option<FirewallConfig> {
    let key: u32 = 0;
    unsafe { FIREWALL_CONFIG.get(&key).copied() }
}

#[inline(always)]
pub fn sample_acl_ct_packet_state(p: &mut PipelineCtx) {
    let global = read_global_config();
    p.flags |= acl_ct_packet_sample_flags(global.as_ref());
    p.acl_bank_snapshot = global
        .map(|config| normalize_acl_bank(config.acl_active_bank))
        .unwrap_or(ACL_BANK_PRIMARY);
}

#[inline(always)]
pub fn apply_per_tap_acl_ct_state(p: &mut PipelineCtx) {
    if !packet_acl_ct_phase_enabled(p.flags) || p.tap_id == TAP_ID_UNASSIGNED {
        return;
    }
    if let Some(config) = unsafe { TAP_CONFIG_MAP.get(&p.tap_id) } {
        p.flags &= !(FLAG_ACL_ON | FLAG_CT_ON);
        if config.acl_enabled != 0 {
            p.flags |= FLAG_ACL_ON;
        }
        if config.conntrack_enabled != 0 {
            p.flags |= FLAG_CT_ON;
        }
        p.acl_bank_snapshot = normalize_acl_bank(config.acl_active_bank);
    }
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
