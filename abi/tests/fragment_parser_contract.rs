mod common {
    pub use aria_ebpf_abi::{IPPROTO_TCP, IPPROTO_UDP};
}

#[path = "../../ebpf/src/parser.rs"]
mod parser;

use aria_ebpf_abi::{FragmentKind, IPPROTO_TCP, IPPROTO_UDP};
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
    frame.splice((ipv6 + 40)..(ipv6 + 40), [44, 0, 0, 0, 0, 0, 0, 0]);
    frame
}

fn ipv6_fragment_with_destination_options(
    fragment_id: u32,
    fragment_offset_units: u16,
    more_fragments: bool,
    payload: &[u8],
) -> Vec<u8> {
    let mut frame = ipv6_fragment(fragment_id, fragment_offset_units, more_fragments, payload);
    frame[14 + 40] = 60;
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

fn classified_ip_family(frame: &[u8]) -> u8 {
    unsafe {
        parser::ethernet_ip_family(
            frame.as_ptr() as usize,
            frame.as_ptr() as usize + frame.len(),
            0,
        )
    }
}

#[test]
fn fragment_parser_non_ip_ethernet_remains_an_unsupported_pass_candidate() {
    let mut frame = ethernet(0x0806);
    frame.extend_from_slice(&[0; 28]);

    assert_eq!(classified_ip_family(&frame), 0);
}

#[test]
fn fragment_parser_incomplete_supported_ipv4_is_a_malformed_drop_candidate() {
    let frame = ipv4_fragment(IPPROTO_UDP, 0x1234, 0, false, &[0; 4]);
    let mut out = MaybeUninit::<parser::PacketInfo>::zeroed();

    assert_eq!(classified_ip_family(&frame), 4);
    assert!(!unsafe {
        parser::parse_eth_ipv4(
            frame.as_ptr() as usize,
            frame.as_ptr() as usize + frame.len(),
            0,
            out.as_mut_ptr(),
        )
    });
    let info = unsafe { out.assume_init() };
    assert_eq!(parser::invalid_l4_failure(&info), None);
}

#[test]
fn fragment_parser_incomplete_vlan_ipv6_is_a_malformed_drop_candidate() {
    let mut frame = vec![0; 12];
    frame.extend_from_slice(&0x8100u16.to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes());
    frame.extend_from_slice(&0x86ddu16.to_be_bytes());
    frame.extend_from_slice(&[0x60, 0, 0, 0, 0, 8, IPPROTO_UDP, 64]);
    frame.extend_from_slice(&[0; 32]);
    frame.extend_from_slice(&[0; 4]);
    let mut out = MaybeUninit::<parser::PacketInfo>::zeroed();

    assert_eq!(classified_ip_family(&frame), 6);
    assert!(!unsafe {
        parser::parse_eth_ipv6(
            frame.as_ptr() as usize,
            frame.as_ptr() as usize + frame.len(),
            0,
            out.as_mut_ptr(),
        )
    });
    let info = unsafe { out.assume_init() };
    assert_eq!(parser::invalid_l4_failure(&info), None);
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
    let frame = ipv4_fragment(IPPROTO_UDP, 0x1234, 1, false, &[0x00, 0x35, 0x13, 0x89]);
    let info = unsafe { parse_v4(&frame) };
    assert_eq!(info.fragment_kind, FragmentKind::NonInitial as u8);
    assert_eq!(info.fragment_id, 0x1234);
    assert_eq!(info.fragment_offset, 8);
    assert_eq!((info.src_port, info.dst_port), (0, 0));
    assert_eq!((info.tcp_flags, info.tcp_seq, info.payload_len), (0, 0, 0));
}

#[test]
fn fragment_parser_ipv4_incomplete_udp_datagram_is_rejected() {
    let frame = ipv4_fragment(IPPROTO_UDP, 0x1234, 0, false, &[0x9c, 0x40, 0x00, 0x35]);
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
fn fragment_parser_ipv4_incomplete_udp_first_fragment_is_rejected() {
    let frame = ipv4_fragment(IPPROTO_UDP, 0x1234, 0, true, &[0x9c, 0x40, 0x00, 0x35]);
    let mut out = MaybeUninit::<parser::PacketInfo>::zeroed();
    unsafe {
        (*out.as_mut_ptr()).src_port = 65000;
        (*out.as_mut_ptr()).dst_port = 65001;
        (*out.as_mut_ptr()).fragment_id = u32::MAX;
    }
    let accepted = unsafe {
        parser::parse_eth_ipv4(
            frame.as_ptr() as usize,
            frame.as_ptr() as usize + frame.len(),
            0,
            out.as_mut_ptr(),
        )
    };

    assert!(!accepted);
    let info = unsafe { out.assume_init() };
    assert_eq!(parser::invalid_l4_failure(&info), Some((4, IPPROTO_UDP)));
    assert_eq!((info.src_port, info.dst_port), (0, 0));
    assert_eq!(info.fragment_id, 0);
}

#[test]
fn fragment_parser_ipv4_ethertype_with_ipv6_version_never_marks_invalid_l4() {
    let mut frame = ipv4_fragment(IPPROTO_UDP, 0x1234, 0, true, &[0; 4]);
    frame[14] = 0x65;
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
    let info = unsafe { out.assume_init() };
    assert_eq!(parser::invalid_l4_failure(&info), None);
}

#[test]
fn fragment_parser_ipv4_truncated_tcp_base_header_is_rejected() {
    let frame = ipv4_fragment(IPPROTO_TCP, 0x1234, 0, true, &[0; 19]);
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
fn fragment_parser_ipv6_incomplete_udp_first_fragment_is_rejected() {
    let frame = ipv6_fragment(0x1234_5678, 0, true, &[0x9c, 0x40, 0x00, 0x35]);
    let mut out = MaybeUninit::<parser::PacketInfo>::zeroed();
    let accepted = unsafe {
        parser::parse_eth_ipv6(
            frame.as_ptr() as usize,
            frame.as_ptr() as usize + frame.len(),
            0,
            out.as_mut_ptr(),
        )
    };

    assert!(!accepted);
}

#[test]
fn fragment_parser_ipv6_incomplete_tcp_first_fragment_is_rejected() {
    let mut frame = ipv6_fragment(0x1234_5678, 0, true, &[0; 19]);
    frame[14 + 40] = IPPROTO_TCP;
    let mut out = MaybeUninit::<parser::PacketInfo>::zeroed();
    unsafe {
        (*out.as_mut_ptr()).src_port = 65000;
        (*out.as_mut_ptr()).dst_port = 65001;
        (*out.as_mut_ptr()).fragment_id = u32::MAX;
    }
    let accepted = unsafe {
        parser::parse_eth_ipv6(
            frame.as_ptr() as usize,
            frame.as_ptr() as usize + frame.len(),
            0,
            out.as_mut_ptr(),
        )
    };

    assert!(!accepted);
    let info = unsafe { out.assume_init() };
    assert_eq!(parser::invalid_l4_failure(&info), Some((6, IPPROTO_TCP)));
    assert_eq!((info.src_port, info.dst_port), (0, 0));
    assert_eq!(info.fragment_id, 0);
}

#[test]
fn fragment_parser_ipv6_ethertype_with_ipv4_version_never_marks_invalid_l4() {
    let mut frame = ipv6_fragment(0x1234_5678, 0, true, &[0; 19]);
    frame[14] = 0x40;
    frame[14 + 40] = IPPROTO_TCP;
    let mut out = MaybeUninit::<parser::PacketInfo>::zeroed();
    let accepted = unsafe {
        parser::parse_eth_ipv6(
            frame.as_ptr() as usize,
            frame.as_ptr() as usize + frame.len(),
            0,
            out.as_mut_ptr(),
        )
    };

    assert!(!accepted);
    let info = unsafe { out.assume_init() };
    assert_eq!(parser::invalid_l4_failure(&info), None);
}

#[test]
fn fragment_parser_ipv4_tcp_data_offset_must_fit_first_fragment() {
    let mut tcp = [0; 20];
    tcp[12] = 6 << 4;
    let frame = ipv4_fragment(IPPROTO_TCP, 0x1234, 0, true, &tcp);
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
fn fragment_parser_ipv4_tcp_payload_length_uses_selected_header() {
    let mut tcp_and_payload = [0; 28];
    tcp_and_payload[0..2].copy_from_slice(&40000u16.to_be_bytes());
    tcp_and_payload[2..4].copy_from_slice(&443u16.to_be_bytes());
    tcp_and_payload[12] = 6 << 4;
    let frame = ipv4_fragment(IPPROTO_TCP, 0x1234, 0, true, &tcp_and_payload);
    let info = unsafe { parse_v4(&frame) };

    assert_eq!((info.src_port, info.dst_port), (40000, 443));
    assert_eq!(info.payload_len, 4);
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
    let frame = ipv6_fragment(0x0102_0304, 3, false, &[0x00, 0x35, 0x13, 0x89, 0, 0, 0, 0]);
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

#[test]
fn fragment_parser_ipv6_post_fragment_options_keep_stable_identity() {
    let first = ipv6_fragment_with_destination_options(
        0x0102_0304,
        0,
        true,
        &[
            IPPROTO_UDP,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0x9c,
            0x40,
            0x00,
            0x35,
            0x00,
            0x08,
            0,
            0,
        ],
    );
    let non_initial = ipv6_fragment_with_destination_options(
        0x0102_0304,
        1,
        false,
        &[0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0],
    );

    let first_info = unsafe { parse_v6(&first) };
    let non_initial_info = unsafe { parse_v6(&non_initial) };

    assert_eq!(first_info.fragment_proto, 60);
    assert_eq!(non_initial_info.fragment_proto, first_info.fragment_proto);
    assert_eq!(first_info.proto, IPPROTO_UDP);
    assert_eq!((first_info.src_port, first_info.dst_port), (40000, 53));
    assert_eq!(non_initial_info.proto, 60);
    assert_eq!(
        (non_initial_info.src_port, non_initial_info.dst_port),
        (0, 0)
    );
}
