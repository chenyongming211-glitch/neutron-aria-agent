#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct PolicyKey {
    pub src_id: u32,
    pub dst_id: u32,
    pub proto: u8,
    pub pad: [u8; 3],
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct PolicyValue {
    pub action: u8,
    pub has_port_filter: u8,
    pub pad1: [u8; 2],
    pub bitmap_idx: u32,
}

pub const XDP_PASS: u32 = 2;
pub const XDP_DROP: u32 = 1;

pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct PortKey {
    pub idx: u32,
    pub port: u16,
    pub pad: u16,
}