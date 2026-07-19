use crate::common::{IPPROTO_TCP, IPPROTO_UDP};
use aria_ebpf_abi::FragmentKind;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct PacketInfo {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_ip_v6: [u8; 16],
    pub dst_ip_v6: [u8; 16],
    pub tcp_seq: u32,
    pub fragment_id: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload_len: u16,
    pub vlan_id: u16,
    pub fragment_offset: u16,
    pub l4_offset: u16,
    pub first_payload_end: u16,
    pub proto: u8,
    pub is_ipv6: bool,
    pub tcp_flags: u8,
    pub fragment_kind: u8,
    pub more_fragments: bool,
    pub _pad: [u8; 1],
}

const ETH_HLEN: usize = 14;

#[inline]
unsafe fn read8(data: usize, offset: usize) -> u8 {
    *(data as *const u8).add(offset)
}

#[inline]
unsafe fn read_be16(data: usize, offset: usize) -> u16 {
    let ptr = (data as *const u8).add(offset);
    u16::from_be_bytes([*ptr, *ptr.add(1)])
}

#[inline]
unsafe fn read_be32(data: usize, offset: usize) -> u32 {
    let ptr = (data as *const u8).add(offset);
    u32::from_be_bytes([*ptr, *ptr.add(1), *ptr.add(2), *ptr.add(3)])
}

#[inline(always)]
unsafe fn parse_transport(
    proto: u8,
    transport_offset: usize,
    packet_end: usize,
) -> Option<(u16, u16, u8, u32, u16)> {
    if proto == IPPROTO_TCP {
        if transport_offset + 20 > packet_end {
            return None;
        }

        let data_offset = (read8(transport_offset, 12) >> 4) as usize * 4;
        if data_offset < 20 || transport_offset + data_offset > packet_end {
            return None;
        }

        Some((
            read_be16(transport_offset, 0),
            read_be16(transport_offset, 2),
            read8(transport_offset, 13),
            read_be32(transport_offset, 4),
            (packet_end - transport_offset - data_offset) as u16,
        ))
    } else if proto == IPPROTO_UDP {
        if transport_offset + 8 > packet_end {
            return None;
        }

        Some((
            read_be16(transport_offset, 0),
            read_be16(transport_offset, 2),
            0,
            0,
            0,
        ))
    } else {
        Some((0, 0, 0, 0, 0))
    }
}

/// Parse IPv4 packet, writing result directly to `out` pointer (scratch map).
/// Returns true on success, false if not an IPv4 packet.
#[inline(never)]
pub unsafe fn parse_eth_ipv4(
    data: usize,
    data_end: usize,
    offset: usize,
    out: *mut PacketInfo,
) -> bool {
    if data + offset + ETH_HLEN + 20 > data_end {
        return false;
    }

    let eth_offset = data + offset;

    let mut eth_type = read_be16(eth_offset, 12);
    let mut vlan_id: u16 = 0;
    let mut ip_offset = eth_offset + ETH_HLEN;

    if eth_type == 0x8100 {
        // 802.1Q VLAN tagged frame
        if ip_offset + 4 + 20 > data_end {
            return false;
        }
        let tci = read_be16(eth_offset, 14);
        vlan_id = tci & 0x0FFF;
        eth_type = read_be16(eth_offset, 16);
        ip_offset += 4;
    }

    if eth_type != 0x0800 {
        return false;
    }
    let ihl = ((read8(ip_offset, 0) & 0x0F) as usize) * 4;
    if ihl < 20 {
        return false;
    }
    if ip_offset + ihl > data_end {
        return false;
    }

    let ip_total_len = read_be16(ip_offset, 2) as usize;
    if ip_total_len < ihl || ip_offset + ip_total_len > data_end {
        return false;
    }
    let packet_end = ip_offset + ip_total_len;
    let proto = read8(ip_offset, 9);

    let src_ip = read_be32(ip_offset, 12);
    let dst_ip = read_be32(ip_offset, 16);
    let fragment_id = read_be16(ip_offset, 4) as u32;
    let fragment_bits = read_be16(ip_offset, 6);
    let fragment_offset = (fragment_bits & 0x1fff) * 8;
    let more_fragments = fragment_bits & 0x2000 != 0;
    let fragment_kind = if fragment_offset != 0 {
        FragmentKind::NonInitial
    } else if more_fragments {
        FragmentKind::First
    } else {
        FragmentKind::Unfragmented
    };

    let transport_offset = ip_offset + ihl;
    let l4_offset = transport_offset - data;
    if l4_offset > u16::MAX as usize {
        return false;
    }
    let (src_port, dst_port, tcp_flags, tcp_seq, payload_len) =
        if fragment_kind == FragmentKind::NonInitial {
            (0, 0, 0, 0, 0)
        } else if let Some(parsed) = parse_transport(proto, transport_offset, packet_end) {
            parsed
        } else {
            return false;
        };

    (*out).src_ip = src_ip;
    (*out).dst_ip = dst_ip;
    (*out).src_ip_v6 = [0; 16];
    (*out).dst_ip_v6 = [0; 16];
    (*out).fragment_id = fragment_id;
    (*out).fragment_offset = fragment_offset;
    (*out).fragment_kind = fragment_kind as u8;
    (*out).more_fragments = more_fragments;
    (*out).l4_offset = l4_offset as u16;
    (*out).first_payload_end = if fragment_kind == FragmentKind::First {
        (ip_total_len - ihl) as u16
    } else {
        0
    };
    (*out).proto = proto;
    (*out).src_port = src_port;
    (*out).dst_port = dst_port;
    (*out).is_ipv6 = false;
    (*out).tcp_flags = tcp_flags;
    (*out).tcp_seq = tcp_seq;
    (*out).payload_len = payload_len;
    (*out).vlan_id = vlan_id;
    (*out)._pad = [0; 1];

    true
}

// IPv6 扩展头类型
const IPPROTO_HOPOPTS: u8 = 0; // Hop-by-Hop Options
const IPPROTO_ROUTING: u8 = 43; // Routing Header
const IPPROTO_DSTOPTS: u8 = 60; // Destination Options
const IPPROTO_FRAGMENT: u8 = 44; // Fragment Header

#[inline]
fn is_ipv6_extension_header(next_header: u8) -> bool {
    matches!(
        next_header,
        IPPROTO_HOPOPTS | IPPROTO_ROUTING | IPPROTO_DSTOPTS | IPPROTO_FRAGMENT
    )
}

/// Parse IPv6 packet, writing result directly to `out` pointer (scratch map).
/// Returns true on success, false if not an IPv6 packet.
#[inline(never)]
pub unsafe fn parse_eth_ipv6(
    data: usize,
    data_end: usize,
    offset: usize,
    out: *mut PacketInfo,
) -> bool {
    if data + offset + ETH_HLEN + 40 > data_end {
        return false;
    }

    let eth_offset = data + offset;

    let mut eth_type = read_be16(eth_offset, 12);
    let mut vlan_id: u16 = 0;
    let mut ip_offset = eth_offset + ETH_HLEN;

    if eth_type == 0x8100 {
        // 802.1Q VLAN tagged frame
        if ip_offset + 4 + 40 > data_end {
            return false;
        }
        let tci = read_be16(eth_offset, 14);
        vlan_id = tci & 0x0FFF;
        eth_type = read_be16(eth_offset, 16);
        ip_offset += 4;
    }

    if eth_type != 0x86DD {
        return false;
    }
    let ipv6_payload_len = read_be16(ip_offset, 4) as usize;
    if ip_offset + 40 + ipv6_payload_len > data_end {
        return false;
    }
    let packet_end = ip_offset + 40 + ipv6_payload_len;
    let mut next_header = read8(ip_offset, 6);

    // Write IPv6 addresses directly to output
    for i in 0..16 {
        (*out).src_ip_v6[i] = read8(ip_offset, 8 + i);
        (*out).dst_ip_v6[i] = read8(ip_offset, 24 + i);
    }

    // 跳过 IPv6 扩展头（最多跳过 4 层，防止 BPF 验证器拒绝无界循环）
    let mut transport_offset = ip_offset + 40;
    let mut fragment_kind = FragmentKind::Unfragmented;
    let mut fragment_id = 0;
    let mut fragment_offset = 0;
    let mut more_fragments = false;
    let mut fragment_payload_offset = 0;
    let mut i = 0u8;
    while i < 4 && is_ipv6_extension_header(next_header) {
        if transport_offset + 2 > packet_end {
            return false;
        }

        if next_header == IPPROTO_FRAGMENT {
            if transport_offset + 8 > packet_end {
                return false;
            }
            let frag_off_flags = read_be16(transport_offset, 2);
            fragment_offset = ((frag_off_flags & 0xfff8) >> 3) * 8;
            more_fragments = frag_off_flags & 1 != 0;
            fragment_id = read_be32(transport_offset, 4);
            fragment_kind = if fragment_offset != 0 {
                FragmentKind::NonInitial
            } else if more_fragments {
                FragmentKind::First
            } else {
                FragmentKind::Atomic
            };
            next_header = read8(transport_offset, 0);
            transport_offset += 8;
            fragment_payload_offset = transport_offset;
        } else {
            next_header = read8(transport_offset, 0);
            let ext_len = (read8(transport_offset, 1) as usize + 1) * 8;
            if transport_offset + ext_len > packet_end {
                return false;
            }
            transport_offset += ext_len;
        }

        i += 1;

        if fragment_kind == FragmentKind::NonInitial {
            break;
        }
    }

    if fragment_kind != FragmentKind::NonInitial && is_ipv6_extension_header(next_header) {
        return false;
    }

    let l4_offset = transport_offset - data;
    if l4_offset > u16::MAX as usize {
        return false;
    }

    let (src_port, dst_port, tcp_flags, tcp_seq, payload_len) =
        if fragment_kind == FragmentKind::NonInitial {
            (0, 0, 0, 0, 0)
        } else if let Some(parsed) = parse_transport(next_header, transport_offset, packet_end) {
            parsed
        } else {
            return false;
        };

    (*out).src_ip = 0;
    (*out).dst_ip = 0;
    (*out).fragment_id = fragment_id;
    (*out).fragment_offset = fragment_offset;
    (*out).fragment_kind = fragment_kind as u8;
    (*out).more_fragments = more_fragments;
    (*out).l4_offset = l4_offset as u16;
    (*out).first_payload_end = if fragment_kind == FragmentKind::First {
        (packet_end - fragment_payload_offset) as u16
    } else {
        0
    };
    (*out).proto = next_header;
    (*out).src_port = src_port;
    (*out).dst_port = dst_port;
    (*out).is_ipv6 = true;
    (*out).tcp_flags = tcp_flags;
    (*out).tcp_seq = tcp_seq;
    (*out).payload_len = payload_len;
    (*out).vlan_id = vlan_id;
    (*out)._pad = [0; 1];

    true
}
