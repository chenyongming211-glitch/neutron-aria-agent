use crate::common::{
    CtKey4, CtKey6, TcpRtValue,
    TCP_FLAG_SYN, TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_RST,
    TCPRT_STATE_HANDSHAKE, TCPRT_STATE_ESTABLISHED, TCPRT_STATE_CLOSING,
    TCPRT_FLAG_SYN_SEEN, TCPRT_FLAG_SYNACK_SEEN, TCPRT_FLAG_ESTABLISHED,
};
use crate::maps::{TCPRT_TABLE_V4, TCPRT_TABLE_V6, FIREWALL_CONFIG};
use crate::parser::PacketInfo;

#[inline(always)]
pub fn tcprt_enabled() -> bool {
    let key: u32 = 0;
    if let Some(cfg) = unsafe { FIREWALL_CONFIG.get(&key) } {
        cfg.tcprt_enabled != 0
    } else {
        false
    }
}

/// Track TCP response time for an IPv4 flow.
/// `ct_key` must be the forward (original direction) key.
/// `is_forward` indicates whether this packet is in the original direction.
#[inline(never)]
pub unsafe fn track_tcp_rt_v4(ct_key: &CtKey4, info: &PacketInfo, now: u64, is_forward: bool) {
    let flags = info.tcp_flags;
    let is_syn = (flags & TCP_FLAG_SYN) != 0;
    let is_ack = (flags & TCP_FLAG_ACK) != 0;
    let is_fin = (flags & TCP_FLAG_FIN) != 0;
    let is_rst = (flags & TCP_FLAG_RST) != 0;

    // SYN (no ACK) — new connection, forward direction
    if is_syn && !is_ack && is_forward {
        let val = TcpRtValue {
            syn_ts: now,
            synack_ts: 0,
            ack_ts: 0,
            last_request_ts: 0,
            first_response_ts: 0,
            handshake_ns: 0,
            rtt_client_ns: 0,
            rtt_server_ns: 0,
            art_ns: 0,
            retrans_req: 0,
            retrans_resp: 0,
            request_count: 0,
            state: TCPRT_STATE_HANDSHAKE,
            flags: TCPRT_FLAG_SYN_SEEN,
            pad: [0; 2],
            last_seq: info.tcp_seq,
            last_payload_len: 0,
            last_resp_seq: 0,
            last_resp_payload_len: 0,
        };
        let _ = TCPRT_TABLE_V4.insert(ct_key, &val, 0);
        return;
    }

    // All other packets: lookup existing entry
    let entry = match TCPRT_TABLE_V4.get_ptr_mut(ct_key) {
        Some(e) => e,
        None => return,
    };

    // FIN or RST → closing
    if is_fin || is_rst {
        (*entry).state = TCPRT_STATE_CLOSING;
        return;
    }

    // SYN-ACK — reverse direction (server response)
    if is_syn && is_ack && !is_forward {
        (*entry).synack_ts = now;
        (*entry).rtt_server_ns = now.wrapping_sub((*entry).syn_ts);
        (*entry).flags |= TCPRT_FLAG_SYNACK_SEEN;
        return;
    }

    // Handshake completion ACK — forward direction, no payload, synack seen
    if is_ack && !is_syn && (*entry).state == TCPRT_STATE_HANDSHAKE
        && ((*entry).flags & TCPRT_FLAG_SYNACK_SEEN) != 0
        && info.payload_len == 0 && is_forward
    {
        (*entry).ack_ts = now;
        (*entry).handshake_ns = now.wrapping_sub((*entry).syn_ts);
        (*entry).rtt_client_ns = now.wrapping_sub((*entry).synack_ts);
        (*entry).state = TCPRT_STATE_ESTABLISHED;
        (*entry).flags |= TCPRT_FLAG_ESTABLISHED;
        return;
    }

    // Data packets in established state
    if (*entry).state != TCPRT_STATE_ESTABLISHED {
        return;
    }

    if is_forward {
        // Request direction (client → server)
        if info.payload_len > 0 {
            if (*entry).last_seq == info.tcp_seq && (*entry).last_payload_len > 0 {
                (*entry).retrans_req += 1;
            }

            if (*entry).first_response_ts > 0 {
                (*entry).request_count += 1;
                (*entry).first_response_ts = 0;
            }

            (*entry).last_request_ts = now;
            (*entry).last_seq = info.tcp_seq;
            (*entry).last_payload_len = info.payload_len;
        }
    } else {
        // Response direction (server → client)
        if info.payload_len > 0 {
            // Retransmission detection for response direction
            if (*entry).last_resp_seq == info.tcp_seq && (*entry).last_resp_payload_len > 0 {
                (*entry).retrans_resp += 1;
            }

            // ART: first response after last request
            if (*entry).first_response_ts == 0 && (*entry).last_request_ts > 0 {
                (*entry).first_response_ts = now;
                (*entry).art_ns = now.wrapping_sub((*entry).last_request_ts);
            }

            (*entry).last_resp_seq = info.tcp_seq;
            (*entry).last_resp_payload_len = info.payload_len;
        }
    }
}

/// Track TCP response time for an IPv6 flow.
/// Same logic as V4, different map.
#[inline(never)]
pub unsafe fn track_tcp_rt_v6(ct_key: &CtKey6, info: &PacketInfo, now: u64, is_forward: bool) {
    let flags = info.tcp_flags;
    let is_syn = (flags & TCP_FLAG_SYN) != 0;
    let is_ack = (flags & TCP_FLAG_ACK) != 0;
    let is_fin = (flags & TCP_FLAG_FIN) != 0;
    let is_rst = (flags & TCP_FLAG_RST) != 0;

    if is_syn && !is_ack && is_forward {
        let val = TcpRtValue {
            syn_ts: now,
            synack_ts: 0,
            ack_ts: 0,
            last_request_ts: 0,
            first_response_ts: 0,
            handshake_ns: 0,
            rtt_client_ns: 0,
            rtt_server_ns: 0,
            art_ns: 0,
            retrans_req: 0,
            retrans_resp: 0,
            request_count: 0,
            state: TCPRT_STATE_HANDSHAKE,
            flags: TCPRT_FLAG_SYN_SEEN,
            pad: [0; 2],
            last_seq: info.tcp_seq,
            last_payload_len: 0,
            last_resp_seq: 0,
            last_resp_payload_len: 0,
        };
        let _ = TCPRT_TABLE_V6.insert(ct_key, &val, 0);
        return;
    }

    let entry = match TCPRT_TABLE_V6.get_ptr_mut(ct_key) {
        Some(e) => e,
        None => return,
    };

    if is_fin || is_rst {
        (*entry).state = TCPRT_STATE_CLOSING;
        return;
    }

    if is_syn && is_ack && !is_forward {
        (*entry).synack_ts = now;
        (*entry).rtt_server_ns = now.wrapping_sub((*entry).syn_ts);
        (*entry).flags |= TCPRT_FLAG_SYNACK_SEEN;
        return;
    }

    if is_ack && !is_syn && (*entry).state == TCPRT_STATE_HANDSHAKE
        && ((*entry).flags & TCPRT_FLAG_SYNACK_SEEN) != 0
        && info.payload_len == 0 && is_forward
    {
        (*entry).ack_ts = now;
        (*entry).handshake_ns = now.wrapping_sub((*entry).syn_ts);
        (*entry).rtt_client_ns = now.wrapping_sub((*entry).synack_ts);
        (*entry).state = TCPRT_STATE_ESTABLISHED;
        (*entry).flags |= TCPRT_FLAG_ESTABLISHED;
        return;
    }

    if (*entry).state != TCPRT_STATE_ESTABLISHED {
        return;
    }

    if is_forward {
        if info.payload_len > 0 {
            if (*entry).last_seq == info.tcp_seq && (*entry).last_payload_len > 0 {
                (*entry).retrans_req += 1;
            }
            if (*entry).first_response_ts > 0 {
                (*entry).request_count += 1;
                (*entry).first_response_ts = 0;
            }
            (*entry).last_request_ts = now;
            (*entry).last_seq = info.tcp_seq;
            (*entry).last_payload_len = info.payload_len;
        }
    } else {
        if info.payload_len > 0 {
            if (*entry).last_resp_seq == info.tcp_seq && (*entry).last_resp_payload_len > 0 {
                (*entry).retrans_resp += 1;
            }
            if (*entry).first_response_ts == 0 && (*entry).last_request_ts > 0 {
                (*entry).first_response_ts = now;
                (*entry).art_ns = now.wrapping_sub((*entry).last_request_ts);
            }
            (*entry).last_resp_seq = info.tcp_seq;
            (*entry).last_resp_payload_len = info.payload_len;
        }
    }
}
