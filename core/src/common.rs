pub use aria_ebpf_abi::userspace::*;

#[derive(Copy, Clone, Debug)]
pub struct TapMapRuntime<'a> {
    pub pin_path: &'a str,
    pub tap_id: u32,
}

impl<'a> TapMapRuntime<'a> {
    pub fn new(pin_path: &'a str, tap_id: u32) -> Self {
        Self { pin_path, tap_id }
    }
}
