#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FragmentKind {
    Unfragmented = 0,
    First = 1,
    NonInitial = 2,
    Atomic = 3,
}

pub const FRAGMENT_CONTEXT_VERSION: u8 = 1;
pub const FRAGMENT_CONFIG_VERSION: u8 = 1;
pub const FRAGMENT_CONFIG_DISABLED: u8 = 0;
pub const FRAGMENT_CONFIG_ENABLED: u8 = 1;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
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
#[derive(Copy, Clone, Debug)]
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
    pub epoch: u64,
    pub expires_at_ns: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct FragmentConfig {
    pub version: u8,
    pub enabled: u8,
    pub _pad: [u8; 6],
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
