use crate::common::{IPPROTO_TCP, IPPROTO_UDP};

#[derive(Debug, Copy, Clone)]
pub struct PacketInfo {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_ip_v6: [u8; 16],
    pub dst_ip_v6: [u8; 16],
    pub proto: u8,
    pub src_port: u16,
    pub dst_port: u16,
    pub is_ipv6: bool,
}

impl Default for PacketInfo {
    fn default() -> Self {
        Self {
            src_ip: 0,
            dst_ip: 0,
            src_ip_v6: [0; 16],
            dst_ip_v6: [0; 16],
            proto: 0,
            src_port: 0,
            dst_port: 0,
            is_ipv6: false,
        }
    }
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

#[inline]
pub fn parse_eth_ipv4(data: usize, data_end: usize, offset: usize) -> Option<PacketInfo> {
    if data + offset + ETH_HLEN + 20 > data_end {
        return None;
    }

    let eth_offset = data + offset;
    
    unsafe {
        let eth_type = read_be16(eth_offset, 12);
        if eth_type != 0x0800 {
            return None;
        }

        let ip_offset = eth_offset + ETH_HLEN;
        let ihl = ((read8(ip_offset, 0) & 0x0F) as usize) * 4;
        let proto = read8(ip_offset, 9);
        
        let src_ip = read_be32(ip_offset, 12);
        let dst_ip = read_be32(ip_offset, 16);

        let (src_port, dst_port) = if proto == IPPROTO_TCP || proto == IPPROTO_UDP {
            let transport_offset = ip_offset + ihl;
            if transport_offset + 4 <= data_end {
                (
                    read_be16(transport_offset, 0),
                    read_be16(transport_offset, 2),
                )
            } else {
                (0, 0)
            }
        } else {
            (0, 0)
        };

        Some(PacketInfo {
            src_ip,
            dst_ip,
            proto,
            src_port,
            dst_port,
            is_ipv6: false,
            ..Default::default()
        })
    }
}

#[inline]
pub fn parse_eth_ipv6(data: usize, data_end: usize, offset: usize) -> Option<PacketInfo> {
    // NOTE: This parser assumes transport layer (TCP/UDP) follows directly after IPv6 fixed header.
    // IPv6 extension headers (Hop-by-Hop, Routing, Fragment, etc.) are not handled.
    // For production use, extension header parsing should be added.
    if data + offset + ETH_HLEN + 40 > data_end {
        return None;
    }

    let eth_offset = data + offset;
    
    unsafe {
        let eth_type = read_be16(eth_offset, 12);
        if eth_type != 0x86DD {
            return None;
        }

        let ip_offset = eth_offset + ETH_HLEN;
        let next_header = read8(ip_offset, 6);

        let mut src_ip_v6 = [0u8; 16];
        let mut dst_ip_v6 = [0u8; 16];
        
        for i in 0..16 {
            src_ip_v6[i] = read8(ip_offset, 8 + i);
            dst_ip_v6[i] = read8(ip_offset, 24 + i);
        }

        let (src_port, dst_port) = if next_header == IPPROTO_TCP || next_header == IPPROTO_UDP {
            let transport_offset = ip_offset + 40;
            if transport_offset + 4 <= data_end {
                (
                    read_be16(transport_offset, 0),
                    read_be16(transport_offset, 2),
                )
            } else {
                (0, 0)
            }
        } else {
            (0, 0)
        };

        Some(PacketInfo {
            src_ip: 0,
            dst_ip: 0,
            src_ip_v6,
            dst_ip_v6,
            proto: next_header,
            src_port,
            dst_port,
            is_ipv6: true,
        })
    }
}
