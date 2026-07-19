mod common {
    pub use aria_ebpf_abi::{IPPROTO_TCP, IPPROTO_UDP};
}

#[path = "../../ebpf/src/parser.rs"]
mod parser;

use aria_ebpf_abi::{FragmentKind, IPPROTO_UDP};
use core::mem::MaybeUninit;

fn ethernet(ethertype: u16) -> Vec<u8> {
    let mut frame = vec![0; 12];
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame
}

fn ipv4_fragment(
    proto: u8,
    fragment_id: u16,
    fragment_offset_units: u16,
    more_fragments: bool,
    payload: &[u8],
) -> Vec<u8> {
    let mut frame = ethernet(0x0800);
    let total_len = 20 + payload.len();
    assert!(total_len <= u16::MAX as usize);
    frame.extend_from_slice(&[
        0x45,
        0,
        (total_len >> 8) as u8,
        total_len as u8,
        (fragment_id >> 8) as u8,
        fragment_id as u8,
        ((fragment_offset_units >> 8) as u8) | if more_fragments { 0x20 } else { 0 },
        fragment_offset_units as u8,
        64,
        proto,
        0,
        0,
        192,
        0,
        2,
        10,
        198,
        51,
        100,
        53,
    ]);
    frame.extend_from_slice(payload);
    frame
}

fn ipv6_fragment(
    fragment_id: u32,
    fragment_offset_units: u16,
    more_fragments: bool,
    payload: &[u8],
) -> Vec<u8> {
    let mut frame = ethernet(0x86dd);
    let payload_len = 8 + payload.len();
    assert!(payload_len <= u16::MAX as usize);
    frame.extend_from_slice(&[
        0x60,
        0,
        0,
        0,
        (payload_len >> 8) as u8,
        payload_len as u8,
        44,
        64,
        0x20,
        0x01,
        0x0d,
        0xb8,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        1,
        0x20,
        0x01,
        0x0d,
        0xb8,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        53,
        IPPROTO_UDP,
        0,
        (fragment_offset_units >> 5) as u8,
        ((fragment_offset_units << 3) as u8) | u8::from(more_fragments),
        (fragment_id >> 24) as u8,
        (fragment_id >> 16) as u8,
        (fragment_id >> 8) as u8,
        fragment_id as u8,
    ]);
    frame.extend_from_slice(payload);
    frame
}

fn ipv6_extension_then_fragment(
    fragment_id: u32,
    fragment_offset_units: u16,
    more_fragments: bool,
    payload: &[u8],
) -> Vec<u8> {
    let mut frame = ipv6_fragment(fragment_id, fragment_offset_units, more_fragments, payload);
    let ipv6 = 14;
    frame[ipv6 + 6] = 0;
    frame[ipv6 + 4] = 0;
    frame[ipv6 + 5] = (16 + payload.len()) as u8;
    frame.splice(
        (ipv6 + 40)..(ipv6 + 40),
        [44, 0, 0, 0, 0, 0, 0, 0],
    );
    frame
}

unsafe fn parse_v4(frame: &[u8]) -> parser::PacketInfo {
    let mut out = MaybeUninit::<parser::PacketInfo>::zeroed();
    assert!(parser::parse_eth_ipv4(
        frame.as_ptr() as usize,
        frame.as_ptr() as usize + frame.len(),
        0,
        out.as_mut_ptr(),
    ));
    out.assume_init()
}

unsafe fn parse_v6(frame: &[u8]) -> parser::PacketInfo {
    let mut out = MaybeUninit::<parser::PacketInfo>::zeroed();
    assert!(parser::parse_eth_ipv6(
        frame.as_ptr() as usize,
        frame.as_ptr() as usize + frame.len(),
        0,
        out.as_mut_ptr(),
    ));
    out.assume_init()
}

#[test]
fn fragment_parser_ipv4_first_udp_keeps_ports_and_byte_offset() {
    let frame = ipv4_fragment(
        IPPROTO_UDP,
        0x1234,
        0,
        true,
        &[0x9c, 0x40, 0x00, 0x35, 0x00, 0x08, 0, 0],
    );
    let info = unsafe { parse_v4(&frame) };

    assert_eq!(info.fragment_kind, FragmentKind::First as u8);
    assert_eq!(info.fragment_id, 0x1234);
    assert_eq!(info.fragment_offset, 0);
    assert_eq!((info.src_port, info.dst_port), (40000, 53));
}

#[test]
fn fragment_parser_ipv4_non_initial_never_reads_payload_as_ports() {
    let frame = ipv4_fragment(
        IPPROTO_UDP,
        0x1234,
        1,
        false,
        &[0x00, 0x35, 0x13, 0x89],
    );
    let info = unsafe { parse_v4(&frame) };
    assert_eq!(info.fragment_kind, FragmentKind::NonInitial as u8);
    assert_eq!(info.fragment_id, 0x1234);
    assert_eq!(info.fragment_offset, 8);
    assert_eq!((info.src_port, info.dst_port), (0, 0));
    assert_eq!((info.tcp_flags, info.tcp_seq, info.payload_len), (0, 0, 0));
}

#[test]
fn fragment_parser_ipv4_first_udp_rejects_four_payload_bytes() {
    let frame = ipv4_fragment(IPPROTO_UDP, 0x1234, 0, true, &[0x9c, 0x40, 0x00, 0x35]);
    let mut out = MaybeUninit::<parser::PacketInfo>::zeroed();
    let accepted = unsafe {
        parser::parse_eth_ipv4(
            frame.as_ptr() as usize,
            frame.as_ptr() as usize + frame.len(),
            0,
            out.as_mut_ptr(),
        )
    };

    assert!(!accepted);
}

#[test]
fn fragment_parser_ipv6_first_udp_keeps_ports_and_identity() {
    let frame = ipv6_fragment(
        0x0102_0304,
        0,
        true,
        &[0x9c, 0x40, 0x00, 0x35, 0x00, 0x08, 0, 0],
    );
    let info = unsafe { parse_v6(&frame) };

    assert_eq!(info.fragment_kind, FragmentKind::First as u8);
    assert_eq!(info.fragment_id, 0x0102_0304);
    assert_eq!(info.fragment_offset, 0);
    assert_eq!((info.src_port, info.dst_port), (40000, 53));
}

#[test]
fn fragment_parser_ipv6_non_initial_never_reads_payload_as_ports() {
    let frame = ipv6_fragment(
        0x0102_0304,
        3,
        false,
        &[0x00, 0x35, 0x13, 0x89, 0, 0, 0, 0],
    );
    let info = unsafe { parse_v6(&frame) };

    assert_eq!(info.fragment_kind, FragmentKind::NonInitial as u8);
    assert_eq!(info.fragment_id, 0x0102_0304);
    assert_eq!(info.fragment_offset, 24);
    assert_eq!((info.src_port, info.dst_port), (0, 0));
    assert_eq!((info.tcp_flags, info.tcp_seq, info.payload_len), (0, 0, 0));
}

#[test]
fn fragment_parser_ipv6_atomic_preserves_l4_ports() {
    let frame = ipv6_fragment(
        0x0102_0304,
        0,
        false,
        &[0x9c, 0x40, 0x00, 0x35, 0x00, 0x08, 0, 0],
    );
    let info = unsafe { parse_v6(&frame) };

    assert_eq!(info.fragment_kind, FragmentKind::Atomic as u8);
    assert_eq!(info.fragment_offset, 0);
    assert_eq!((info.src_port, info.dst_port), (40000, 53));
}

#[test]
fn fragment_parser_ipv6_extension_chain_preserves_fragment_metadata() {
    let frame = ipv6_extension_then_fragment(
        0x0102_0304,
        0,
        true,
        &[0x9c, 0x40, 0x00, 0x35, 0x00, 0x08, 0, 0],
    );
    let info = unsafe { parse_v6(&frame) };

    assert_eq!(info.fragment_kind, FragmentKind::First as u8);
    assert_eq!(info.fragment_id, 0x0102_0304);
    assert_eq!(info.fragment_offset, 0);
    assert_eq!((info.src_port, info.dst_port), (40000, 53));
}
