#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FragmentKind {
    Unfragmented = 0,
    First = 1,
    NonInitial = 2,
    Atomic = 3,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FragmentCtCreatePoint {
    AfterPolicyQos = 0,
    AfterContextInstall = 1,
}

pub const FRAGMENT_CONTEXT_VERSION: u8 = 1;
pub const FRAGMENT_CONFIG_VERSION: u8 = 2;
pub const FRAGMENT_CONFIG_DISABLED: u8 = 0;
pub const FRAGMENT_CONFIG_ENABLED: u8 = 1;
pub const FRAGMENT_RUNTIME_MODE_MANAGED: u8 = 1;
pub const FRAGMENT_RUNTIME_MODE_STANDALONE: u8 = 2;
pub const FRAGMENT_CONFIG_MIN_TIMEOUT_NS: u64 = 1_000_000_000;
pub const FRAGMENT_CONFIG_MAX_TIMEOUT_NS: u64 = 60_000_000_000;

pub const FRAGMENT_CONTEXT_FLAG_UDP: u8 = 0;
pub const FRAGMENT_CONTEXT_FLAG_TCP: u8 = 1;

pub const DROP_FRAGMENT_CONFIG_MISSING: u8 = 6;
pub const DROP_FRAGMENT_TRACKING_DISABLED: u8 = 7;
pub const DROP_FRAGMENT_CONFIG_INVALID: u8 = 8;
pub const DROP_FRAGMENT_EPOCH_MISSING: u8 = 9;
pub const DROP_FRAGMENT_CONTEXT_MISSING: u8 = 10;
pub const DROP_FRAGMENT_CONTEXT_INVALID: u8 = 11;
pub const DROP_FRAGMENT_CONTEXT_EXPIRED: u8 = 12;
pub const DROP_FRAGMENT_CONTEXT_STALE: u8 = 13;
pub const DROP_FRAGMENT_CONTEXT_OVERLAP: u8 = 14;
pub const DROP_FRAGMENT_CONTEXT_UPDATE_FAILED: u8 = 15;
pub const DROP_FRAGMENT_TAP_UNASSIGNED: u8 = 16;
pub const DROP_FRAGMENT_EXPIRY_OVERFLOW: u8 = 17;
pub const DROP_MALFORMED_IP: u8 = 18;
pub const DROP_FRAGMENT_INVALID_L4: u8 = 19;

pub const FRAGMENT_FAMILY_IPV4: u8 = 4;
pub const FRAGMENT_FAMILY_IPV6: u8 = 6;

pub const FRAGMENT_METRIC_FIRST: u8 = 1;
pub const FRAGMENT_METRIC_NON_INITIAL: u8 = 2;
pub const FRAGMENT_METRIC_CONTEXT_HIT: u8 = 3;
pub const FRAGMENT_METRIC_CONFIG_MISSING: u8 = 4;
pub const FRAGMENT_METRIC_TRACKING_DISABLED: u8 = 5;
pub const FRAGMENT_METRIC_CONFIG_INVALID: u8 = 6;
pub const FRAGMENT_METRIC_EPOCH_MISSING: u8 = 7;
pub const FRAGMENT_METRIC_CONTEXT_MISSING: u8 = 8;
pub const FRAGMENT_METRIC_CONTEXT_INVALID: u8 = 9;
pub const FRAGMENT_METRIC_CONTEXT_EXPIRED: u8 = 10;
pub const FRAGMENT_METRIC_CONTEXT_STALE: u8 = 11;
pub const FRAGMENT_METRIC_CONTEXT_OVERLAP: u8 = 12;
pub const FRAGMENT_METRIC_CONTEXT_INSERTED: u8 = 13;
pub const FRAGMENT_METRIC_CONTEXT_UPDATE_FAILED: u8 = 14;
pub const FRAGMENT_METRIC_TAP_UNASSIGNED: u8 = 15;
pub const FRAGMENT_METRIC_EXPIRY_OVERFLOW: u8 = 16;
pub const FRAGMENT_METRIC_INVALID_L4: u8 = 17;
pub const FRAGMENT_METRIC_MAX: u8 = FRAGMENT_METRIC_INVALID_L4;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_HOPOPTS: u8 = 0;
const IPPROTO_ROUTING: u8 = 43;
const IPPROTO_DSTOPTS: u8 = 60;

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct FragmentContextKey4 {
    pub tap_id: u32,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub fragment_id: u16,
    pub vlan_id: u16,
    pub proto: u8,
    pub direction: u8,
    pub _pad: [u8; 2],
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
pub struct FragmentContextKey6 {
    pub tap_id: u32,
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub fragment_id: u32,
    pub vlan_id: u16,
    pub proto: u8,
    pub direction: u8,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct FragmentContextValue {
    pub src_port: u16,
    pub dst_port: u16,
    pub first_payload_end: u16,
    pub acl_bank: u8,
    pub flags: u8,
    pub version: u8,
    pub _pad: u8,
    pub _reserved: [u8; 6],
    pub epoch: u64,
    pub expires_at_ns: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct FragmentConfig {
    pub version: u8,
    pub enabled: u8,
    pub runtime_mode: u8,
    pub _pad: [u8; 5],
    pub ipv4_timeout_ns: u64,
    pub ipv6_timeout_ns: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct FragmentEpochValue {
    pub epoch: u64,
}

#[cfg(all(feature = "aya-pod", not(target_arch = "bpf")))]
mod userspace_pod {
    use super::*;

    macro_rules! impl_aya_pod {
        ($($type:ty),+ $(,)?) => {
            $(unsafe impl aya::Pod for $type {})+
        };
    }

    impl_aya_pod!(
        FragmentContextKey4,
        FragmentContextKey6,
        FragmentContextValue,
        FragmentConfig,
        FragmentEpochValue,
    );
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FragmentContextDisposition {
    Hit = 0,
    InvalidVersion = 1,
    Expired = 2,
    Stale = 3,
    Overlap = 4,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FragmentResolveDecision {
    Hit = 0,
    DropConfigMissing = DROP_FRAGMENT_CONFIG_MISSING,
    DropTrackingDisabled = DROP_FRAGMENT_TRACKING_DISABLED,
    DropConfigInvalid = DROP_FRAGMENT_CONFIG_INVALID,
    DropEpochMissing = DROP_FRAGMENT_EPOCH_MISSING,
    DropContextMissing = DROP_FRAGMENT_CONTEXT_MISSING,
    DropContextInvalid = DROP_FRAGMENT_CONTEXT_INVALID,
    DropExpired = DROP_FRAGMENT_CONTEXT_EXPIRED,
    DropContextStale = DROP_FRAGMENT_CONTEXT_STALE,
    DropOverlap = DROP_FRAGMENT_CONTEXT_OVERLAP,
    DropTapUnassigned = DROP_FRAGMENT_TAP_UNASSIGNED,
}

impl FragmentResolveDecision {
    #[inline(always)]
    pub fn drop_reason(self) -> u8 {
        self as u8
    }

    #[inline(always)]
    pub fn metric(self) -> u8 {
        match self {
            Self::Hit => FRAGMENT_METRIC_CONTEXT_HIT,
            _ => fragment_metric_for_drop_reason(self.drop_reason()),
        }
    }

    #[inline(always)]
    pub fn delete_context(self) -> bool {
        false
    }
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FragmentInstallDecision {
    Pass = 0,
    DropKeepCt = 1,
}

impl FragmentInstallDecision {
    #[inline(always)]
    pub fn drop_reason(self) -> u8 {
        match self {
            Self::Pass => 0,
            Self::DropKeepCt => DROP_FRAGMENT_CONTEXT_UPDATE_FAILED,
        }
    }

    #[inline(always)]
    pub fn metric(self) -> u8 {
        match self {
            Self::Pass => FRAGMENT_METRIC_CONTEXT_INSERTED,
            Self::DropKeepCt => FRAGMENT_METRIC_CONTEXT_UPDATE_FAILED,
        }
    }

    #[inline(always)]
    pub fn remove_created_ct(self) -> bool {
        false
    }
}

#[inline(always)]
pub const fn fragment_ct_create_point(fragment_kind: u8) -> FragmentCtCreatePoint {
    if fragment_kind == FragmentKind::First as u8 {
        FragmentCtCreatePoint::AfterContextInstall
    } else {
        FragmentCtCreatePoint::AfterPolicyQos
    }
}

#[inline(always)]
pub fn fragment_tracking_required(fragment_kind: u8, fragment_proto: u8, is_ipv6: bool) -> bool {
    let real_fragment = fragment_kind == FragmentKind::First as u8
        || fragment_kind == FragmentKind::NonInitial as u8;
    real_fragment
        && (matches!(fragment_proto, IPPROTO_TCP | IPPROTO_UDP)
            || (is_ipv6
                && matches!(
                    fragment_proto,
                    IPPROTO_HOPOPTS | IPPROTO_ROUTING | IPPROTO_DSTOPTS
                )))
}

#[inline(always)]
pub const fn fragment_first_observation_metric(fragment_kind: u8, effective_proto: u8) -> u8 {
    if fragment_kind == FragmentKind::First as u8
        && (effective_proto == IPPROTO_TCP || effective_proto == IPPROTO_UDP)
    {
        FRAGMENT_METRIC_FIRST
    } else {
        0
    }
}

#[inline(always)]
pub fn fragment_context_flags_for_l4(proto: u8) -> Option<u8> {
    match proto {
        IPPROTO_UDP => Some(FRAGMENT_CONTEXT_FLAG_UDP),
        IPPROTO_TCP => Some(FRAGMENT_CONTEXT_FLAG_TCP),
        _ => None,
    }
}

#[inline(always)]
pub fn fragment_context_l4_proto(value: &FragmentContextValue) -> Option<u8> {
    match value.flags {
        FRAGMENT_CONTEXT_FLAG_UDP => Some(IPPROTO_UDP),
        FRAGMENT_CONTEXT_FLAG_TCP => Some(IPPROTO_TCP),
        _ => None,
    }
}

/// Recover the authoritative L4 fields from a fragment context value when the
/// stored L4 flags allow it. Returns (proto, src_port, dst_port). Resolve-stage
/// drops use this so drop statistics and trace events are attributed to the
/// real transport protocol instead of the on-wire fragment-header value.
#[inline(always)]
pub fn fragment_resolved_l4_fields(
    value: &FragmentContextValue,
) -> Option<(u8, u16, u16)> {
    fragment_context_l4_proto(value).map(|proto| (proto, value.src_port, value.dst_port))
}

#[inline(always)]
pub fn fragment_authority_drop_reason(
    tap_id: u32,
    _is_ipv6: bool,
    config: Option<&FragmentConfig>,
    epoch: Option<&FragmentEpochValue>,
) -> u8 {
    let config = match config {
        Some(config) => config,
        None => return DROP_FRAGMENT_CONFIG_MISSING,
    };
    if config.version != FRAGMENT_CONFIG_VERSION
        || (config.enabled != FRAGMENT_CONFIG_DISABLED && config.enabled != FRAGMENT_CONFIG_ENABLED)
        || (config.runtime_mode != FRAGMENT_RUNTIME_MODE_MANAGED
            && config.runtime_mode != FRAGMENT_RUNTIME_MODE_STANDALONE)
        || config._pad != [0; 5]
    {
        return DROP_FRAGMENT_CONFIG_INVALID;
    }
    if config.ipv4_timeout_ns < FRAGMENT_CONFIG_MIN_TIMEOUT_NS
        || config.ipv4_timeout_ns > FRAGMENT_CONFIG_MAX_TIMEOUT_NS
        || config.ipv6_timeout_ns < FRAGMENT_CONFIG_MIN_TIMEOUT_NS
        || config.ipv6_timeout_ns > FRAGMENT_CONFIG_MAX_TIMEOUT_NS
    {
        return DROP_FRAGMENT_CONFIG_INVALID;
    }
    if config.enabled == FRAGMENT_CONFIG_DISABLED {
        return DROP_FRAGMENT_TRACKING_DISABLED;
    }
    if (config.runtime_mode == FRAGMENT_RUNTIME_MODE_MANAGED && tap_id == 0)
        || (config.runtime_mode == FRAGMENT_RUNTIME_MODE_STANDALONE && tap_id != 0)
    {
        return DROP_FRAGMENT_TAP_UNASSIGNED;
    }
    if epoch.is_none() {
        return DROP_FRAGMENT_EPOCH_MISSING;
    }
    0
}

#[inline(always)]
pub fn fragment_metric_for_drop_reason(drop_reason: u8) -> u8 {
    match drop_reason {
        DROP_FRAGMENT_CONFIG_MISSING => FRAGMENT_METRIC_CONFIG_MISSING,
        DROP_FRAGMENT_TRACKING_DISABLED => FRAGMENT_METRIC_TRACKING_DISABLED,
        DROP_FRAGMENT_CONFIG_INVALID => FRAGMENT_METRIC_CONFIG_INVALID,
        DROP_FRAGMENT_EPOCH_MISSING => FRAGMENT_METRIC_EPOCH_MISSING,
        DROP_FRAGMENT_CONTEXT_MISSING => FRAGMENT_METRIC_CONTEXT_MISSING,
        DROP_FRAGMENT_CONTEXT_INVALID => FRAGMENT_METRIC_CONTEXT_INVALID,
        DROP_FRAGMENT_CONTEXT_EXPIRED => FRAGMENT_METRIC_CONTEXT_EXPIRED,
        DROP_FRAGMENT_CONTEXT_STALE => FRAGMENT_METRIC_CONTEXT_STALE,
        DROP_FRAGMENT_CONTEXT_OVERLAP => FRAGMENT_METRIC_CONTEXT_OVERLAP,
        DROP_FRAGMENT_CONTEXT_UPDATE_FAILED => FRAGMENT_METRIC_CONTEXT_UPDATE_FAILED,
        DROP_FRAGMENT_TAP_UNASSIGNED => FRAGMENT_METRIC_TAP_UNASSIGNED,
        DROP_FRAGMENT_EXPIRY_OVERFLOW => FRAGMENT_METRIC_EXPIRY_OVERFLOW,
        DROP_FRAGMENT_INVALID_L4 => FRAGMENT_METRIC_INVALID_L4,
        _ => 0,
    }
}

#[inline(always)]
pub const fn fragment_metric_index(metric: u8, family: u8) -> Option<u32> {
    if metric == 0 || metric > FRAGMENT_METRIC_MAX {
        return None;
    }
    match family {
        FRAGMENT_FAMILY_IPV4 => Some(metric as u32 * 2),
        FRAGMENT_FAMILY_IPV6 => Some(metric as u32 * 2 + 1),
        _ => None,
    }
}

#[inline(always)]
pub fn fragment_resolve_decision(
    tap_id: u32,
    is_ipv6: bool,
    config: Option<&FragmentConfig>,
    epoch: Option<&FragmentEpochValue>,
    value: Option<&FragmentContextValue>,
    active_bank: u8,
    now_ns: u64,
    fragment_offset: u16,
) -> FragmentResolveDecision {
    match fragment_authority_drop_reason(tap_id, is_ipv6, config, epoch) {
        0 => {}
        DROP_FRAGMENT_TAP_UNASSIGNED => return FragmentResolveDecision::DropTapUnassigned,
        DROP_FRAGMENT_CONFIG_MISSING => return FragmentResolveDecision::DropConfigMissing,
        DROP_FRAGMENT_TRACKING_DISABLED => {
            return FragmentResolveDecision::DropTrackingDisabled;
        }
        DROP_FRAGMENT_CONFIG_INVALID => return FragmentResolveDecision::DropConfigInvalid,
        DROP_FRAGMENT_EPOCH_MISSING => return FragmentResolveDecision::DropEpochMissing,
        _ => return FragmentResolveDecision::DropConfigInvalid,
    }

    let value = match value {
        Some(value) => value,
        None => return FragmentResolveDecision::DropContextMissing,
    };
    if fragment_context_l4_proto(value).is_none() {
        return FragmentResolveDecision::DropContextInvalid;
    }
    let active_epoch = match epoch {
        Some(epoch) => epoch.epoch,
        None => return FragmentResolveDecision::DropEpochMissing,
    };
    match fragment_context_disposition(value, active_bank, active_epoch, now_ns, fragment_offset) {
        FragmentContextDisposition::Hit => FragmentResolveDecision::Hit,
        FragmentContextDisposition::InvalidVersion => FragmentResolveDecision::DropContextInvalid,
        FragmentContextDisposition::Expired => FragmentResolveDecision::DropExpired,
        FragmentContextDisposition::Stale => FragmentResolveDecision::DropContextStale,
        FragmentContextDisposition::Overlap => FragmentResolveDecision::DropOverlap,
    }
}

#[inline(always)]
pub fn fragment_install_result(context_insert_succeeded: bool) -> FragmentInstallDecision {
    if context_insert_succeeded {
        FragmentInstallDecision::Pass
    } else {
        FragmentInstallDecision::DropKeepCt
    }
}

#[inline(always)]
pub fn fragment_context_disposition(
    value: &FragmentContextValue,
    active_bank: u8,
    active_epoch: u64,
    now_ns: u64,
    fragment_offset: u16,
) -> FragmentContextDisposition {
    if value.version != FRAGMENT_CONTEXT_VERSION {
        FragmentContextDisposition::InvalidVersion
    } else if now_ns >= value.expires_at_ns {
        FragmentContextDisposition::Expired
    } else if value.acl_bank != active_bank || value.epoch != active_epoch {
        FragmentContextDisposition::Stale
    } else if fragment_offset < value.first_payload_end {
        FragmentContextDisposition::Overlap
    } else {
        FragmentContextDisposition::Hit
    }
}
