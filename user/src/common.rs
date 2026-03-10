use aya::Pod;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct PolicyKey {
    pub src_id: u32,
    pub dst_id: u32,
    pub proto: u8,
    pub pad: [u8; 3],
}
unsafe impl Pod for PolicyKey {}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct PolicyValue {
    pub action: u8,
    pub has_port_filter: u8,
    pub pad1: [u8; 2],
    pub bitmap_idx: u32,
}
unsafe impl Pod for PolicyValue {}