use crate::common::{IPPROTO_TCP, IPPROTO_UDP};

#[derive(Debug, Copy, Clone)]
pub struct PacketInfo {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_ip_v6: [u8; 16],
    pub dst_ip_v6: [u8; 16],
    pub proto: u8,
    #[allow(dead_code)]
    pub src_port: u16,
    pub dst_port: u16,
    pub is_ipv6: bool,
    pub tcp_flags: u8,      // TCP flags byte (SYN, ACK, FIN, RST, etc.)
    pub tcp_seq: u32,        // TCP sequence number
    pub payload_len: u16,    // L4 payload length
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
            tcp_flags: 0,
            tcp_seq: 0,
            payload_len: 0,
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
        if ihl < 20 {
            return None; // 最小 IP 头长度为 20 字节
        }
        // 确保完整的 IP 头在包范围内
        if ip_offset + ihl > data_end {
            return None;
        }
        let proto = read8(ip_offset, 9);
        
        let src_ip = read_be32(ip_offset, 12);
        let dst_ip = read_be32(ip_offset, 16);

        let (src_port, dst_port, tcp_flags, tcp_seq, payload_len) = if proto == IPPROTO_TCP {
            let transport_offset = ip_offset + ihl;
            if transport_offset + 14 <= data_end {
                let sp = read_be16(transport_offset, 0);
                let dp = read_be16(transport_offset, 2);
                let seq = read_be32(transport_offset, 4);
                let flags = read8(transport_offset, 13);
                let data_off = (read8(transport_offset, 12) >> 4) as usize * 4;
                let ip_total_len = read_be16(ip_offset, 2) as usize;
                let pl = if data_off >= 20 && ip_total_len > ihl + data_off {
                    (ip_total_len - ihl - data_off) as u16
                } else {
                    0
                };
                (sp, dp, flags, seq, pl)
            } else if transport_offset + 4 <= data_end {
                (read_be16(transport_offset, 0), read_be16(transport_offset, 2), 0, 0, 0)
            } else {
                (0, 0, 0, 0, 0)
            }
        } else if proto == IPPROTO_UDP {
            let transport_offset = ip_offset + ihl;
            if transport_offset + 4 <= data_end {
                (read_be16(transport_offset, 0), read_be16(transport_offset, 2), 0, 0, 0)
            } else {
                (0, 0, 0, 0, 0)
            }
        } else {
            (0, 0, 0, 0, 0)
        };

        Some(PacketInfo {
            src_ip,
            dst_ip,
            proto,
            src_port,
            dst_port,
            is_ipv6: false,
            tcp_flags,
            tcp_seq,
            payload_len,
            ..Default::default()
        })
    }
}

// IPv6 扩展头类型
const IPPROTO_HOPOPTS: u8 = 0;   // Hop-by-Hop Options
const IPPROTO_ROUTING: u8 = 43;  // Routing Header
const IPPROTO_DSTOPTS: u8 = 60;  // Destination Options
const IPPROTO_FRAGMENT: u8 = 44; // Fragment Header

#[inline]
fn is_ipv6_extension_header(next_header: u8) -> bool {
    matches!(next_header, IPPROTO_HOPOPTS | IPPROTO_ROUTING | IPPROTO_DSTOPTS | IPPROTO_FRAGMENT)
}

#[inline]
pub fn parse_eth_ipv6(data: usize, data_end: usize, offset: usize) -> Option<PacketInfo> {
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
        let mut next_header = read8(ip_offset, 6);

        let mut src_ip_v6 = [0u8; 16];
        let mut dst_ip_v6 = [0u8; 16];

        for i in 0..16 {
            src_ip_v6[i] = read8(ip_offset, 8 + i);
            dst_ip_v6[i] = read8(ip_offset, 24 + i);
        }

        // 跳过 IPv6 扩展头（最多跳过 4 层，防止 BPF 验证器拒绝无界循环）
        let mut transport_offset = ip_offset + 40;
        let mut is_fragment = false; // 非首分片标记
        let mut i = 0u8;
        while i < 4 && is_ipv6_extension_header(next_header) {
            if transport_offset + 2 > data_end {
                return None;
            }

            if next_header == IPPROTO_FRAGMENT {
                // Fragment Header 格式（固定 8 字节）:
                //   [0] next_header
                //   [1] reserved
                //   [2..4] frag_offset(13bit) | res(2bit) | MF(1bit)
                //   [4..8] identification
                if transport_offset + 8 > data_end {
                    return None;
                }
                let frag_off_flags = read_be16(transport_offset, 2);
                let frag_offset = frag_off_flags >> 3;
                if frag_offset != 0 {
                    // 非首分片：传输层头不在此分片中，无法获取端口
                    is_fragment = true;
                }
                next_header = read8(transport_offset, 0);
                transport_offset += 8; // Fragment Header 固定 8 字节
            } else {
                // 其它扩展头: hdr_len 以 8 字节为单位（不含首 8 字节）
                next_header = read8(transport_offset, 0);
                let ext_len = (read8(transport_offset, 1) as usize + 1) * 8;
                transport_offset += ext_len;
            }

            if transport_offset > data_end {
                return None;
            }
            i += 1;
        }

        let (src_port, dst_port, tcp_flags, tcp_seq, payload_len) = if is_fragment {
            (0, 0, 0, 0, 0)
        } else if next_header == IPPROTO_TCP {
            if transport_offset + 14 <= data_end {
                let sp = read_be16(transport_offset, 0);
                let dp = read_be16(transport_offset, 2);
                let seq = read_be32(transport_offset, 4);
                let flags = read8(transport_offset, 13);
                let data_off = (read8(transport_offset, 12) >> 4) as usize * 4;
                // IPv6 payload_length = everything after the 40-byte fixed header
                let ipv6_payload_len = read_be16(ip_offset, 4) as usize;
                // transport payload offset relative to start of IPv6 payload
                let transport_rel = transport_offset - (ip_offset + 40);
                let pl = if data_off >= 20 && ipv6_payload_len > transport_rel + data_off {
                    (ipv6_payload_len - transport_rel - data_off) as u16
                } else {
                    0
                };
                (sp, dp, flags, seq, pl)
            } else if transport_offset + 4 <= data_end {
                (read_be16(transport_offset, 0), read_be16(transport_offset, 2), 0, 0, 0)
            } else {
                (0, 0, 0, 0, 0)
            }
        } else if next_header == IPPROTO_UDP {
            if transport_offset + 4 <= data_end {
                (read_be16(transport_offset, 0), read_be16(transport_offset, 2), 0, 0, 0)
            } else {
                (0, 0, 0, 0, 0)
            }
        } else {
            (0, 0, 0, 0, 0)
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
            tcp_flags,
            tcp_seq,
            payload_len,
        })
    }
}
