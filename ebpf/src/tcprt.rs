use crate::common::{
    CtKey4, CtKey6, TcpRtValue, TCPRT_FLAG_ESTABLISHED, TCPRT_FLAG_FIN_FWD, TCPRT_FLAG_FIN_REV,
    TCPRT_FLAG_SYNACK_SEEN, TCPRT_FLAG_SYN_SEEN, TCPRT_STATE_CLOSE_WAIT, TCPRT_STATE_ESTABLISHED,
    TCPRT_STATE_FIN_WAIT, TCPRT_STATE_RST, TCPRT_STATE_SYN_SENT, TCPRT_STATE_TIME_WAIT,
    TCP_FLAG_ACK, TCP_FLAG_FIN, TCP_FLAG_RST, TCP_FLAG_SYN,
};
use crate::maps::{
    CT_KEY4_SCRATCH, CT_KEY6_SCRATCH, CT_KEY_DERIVED_SLOT, TCPRT_TABLE_V4, TCPRT_TABLE_V6,
    TCPRT_VALUE_BUF,
};
use crate::parser::PacketInfo;

#[inline(always)]
pub fn tcprt_enabled(tap_id: u32) -> bool {
    crate::runtime::tcprt_enabled(tap_id)
}

#[inline(always)]
unsafe fn init_tcprt_value(val: *mut TcpRtValue, now: u64, tcp_seq: u32, from_ingress_hook: bool) {
    (*val).syn_ts = now;
    (*val).synack_ts = 0;
    (*val).ack_ts = 0;
    (*val).last_request_ts = 0;
    (*val).first_response_ts = 0;
    (*val).handshake_ns = 0;
    (*val).rtt_client_ns = 0;
    (*val).rtt_server_ns = 0;
    (*val).art_ns = 0;
    (*val).syn_ingress_ts = if from_ingress_hook { now } else { 0 };
    (*val).synack_ingress_ts = 0;
    (*val).retrans_req = 0;
    (*val).retrans_resp = 0;
    (*val).request_count = 0;
    (*val).state = TCPRT_STATE_SYN_SENT;
    (*val).flags = TCPRT_FLAG_SYN_SEEN;
    (*val).pad = [0; 2];
    (*val).last_seq = tcp_seq;
    (*val).last_payload_len = 0;
    (*val)._pad_last_payload_len = [0; 2];
    (*val).prev_seq = 0;
    (*val).prev_payload_len = 0;
    (*val)._pad_prev_payload_len = [0; 2];
    (*val).last_resp_seq = 0;
    (*val).last_resp_payload_len = 0;
    (*val)._pad_last_resp_payload_len = [0; 2];
    (*val).prev_resp_seq = 0;
    (*val).prev_resp_payload_len = 0;
    (*val)._pad2 = [0; 6];
    (*val)._pad3 = [0; 4];
    (*val).fin_ts = 0;
    (*val).rst_ts = 0;
    (*val).close_ts = 0;
}

/// Check if seq matches last_seq or prev_seq (catches retransmits arriving after new data).
#[inline(always)]
unsafe fn is_retrans_req(entry: *mut TcpRtValue, seq: u32) -> bool {
    ((*entry).last_seq == seq && (*entry).last_payload_len > 0)
        || ((*entry).prev_seq == seq && (*entry).prev_payload_len > 0)
}

#[inline(always)]
unsafe fn is_retrans_resp(entry: *mut TcpRtValue, seq: u32) -> bool {
    ((*entry).last_resp_seq == seq && (*entry).last_resp_payload_len > 0)
        || ((*entry).prev_resp_seq == seq && (*entry).prev_resp_payload_len > 0)
}

/// Track TCP response time for an IPv4 flow.
/// `ct_key` must be the forward (original direction) key.
/// `is_forward` indicates whether this packet is in the original direction.
#[inline(never)]
pub unsafe fn track_tcp_rt_v4(
    ct_key: &CtKey4,
    info: &PacketInfo,
    now: u64,
    is_forward: bool,
    from_ingress_hook: bool,
) {
    let flags = info.tcp_flags;
    let is_syn = (flags & TCP_FLAG_SYN) != 0;
    let is_ack = (flags & TCP_FLAG_ACK) != 0;
    let is_fin = (flags & TCP_FLAG_FIN) != 0;
    let is_rst = (flags & TCP_FLAG_RST) != 0;

    // SYN (no ACK) — new connection, forward direction
    if is_syn && !is_ack && is_forward {
        if let Some(entry) = TCPRT_TABLE_V4.get_ptr_mut(ct_key) {
            if (*entry).close_ts > 0 {
                init_tcprt_value(entry, now, info.tcp_seq, from_ingress_hook);
                return;
            }
            if !from_ingress_hook
                && (*entry).state == TCPRT_STATE_SYN_SENT
                && (*entry).syn_ingress_ts > 0
                && (*entry).syn_ingress_ts == (*entry).syn_ts
            {
                (*entry).syn_ts = now; // update to egress timestamp, preserve syn_ingress_ts
            }
            return;
        }
        let val = match TCPRT_VALUE_BUF.get_ptr_mut(0) {
            Some(v) => v,
            None => return,
        };
        init_tcprt_value(val, now, info.tcp_seq, from_ingress_hook);
        let _ = TCPRT_TABLE_V4.insert(ct_key, &*val, 0);
        return;
    }

    // All other packets: lookup existing entry
    let entry = match TCPRT_TABLE_V4.get_ptr_mut(ct_key) {
        Some(e) => e,
        None => return,
    };

    // Closed entries stay in the LRU map until eviction or explicit flush.
    // Do not let late packets mutate the old connection state; only a new SYN
    // is allowed to reinitialize the slot above.
    if (*entry).close_ts > 0 {
        return;
    }

    // FIN — fine-grained close tracking
    if is_fin {
        if (*entry).fin_ts == 0 {
            (*entry).fin_ts = now;
        }
        if is_forward {
            (*entry).flags |= TCPRT_FLAG_FIN_FWD;
            (*entry).state = if ((*entry).flags & TCPRT_FLAG_FIN_REV) != 0 {
                (*entry).close_ts = now;
                TCPRT_STATE_TIME_WAIT
            } else {
                TCPRT_STATE_FIN_WAIT
            };
        } else {
            (*entry).flags |= TCPRT_FLAG_FIN_REV;
            (*entry).state = if ((*entry).flags & TCPRT_FLAG_FIN_FWD) != 0 {
                (*entry).close_ts = now;
                TCPRT_STATE_TIME_WAIT
            } else {
                TCPRT_STATE_CLOSE_WAIT
            };
        }
        return;
    }
    // RST — immediate close
    if is_rst {
        (*entry).rst_ts = now;
        (*entry).close_ts = now;
        (*entry).state = TCPRT_STATE_RST;
        return;
    }

    // SYN-ACK — reverse direction (server response)
    if is_syn && is_ack && !is_forward {
        if from_ingress_hook {
            if (*entry).synack_ingress_ts == 0 {
                (*entry).synack_ingress_ts = now; // first observation (ingress)
                (*entry).synack_ts = now;
                (*entry).rtt_server_ns = now.wrapping_sub((*entry).syn_ts);
                (*entry).flags |= TCPRT_FLAG_SYNACK_SEEN;
            }
            return;
        }

        if (*entry).synack_ingress_ts > 0 && (*entry).synack_ingress_ts == (*entry).synack_ts {
            (*entry).synack_ts = now;
            (*entry).rtt_server_ns = now.wrapping_sub((*entry).syn_ts);
            (*entry).flags |= TCPRT_FLAG_SYNACK_SEEN;
            return;
        }

        if (*entry).synack_ts == 0 {
            // First observation happened on egress-only path.
            (*entry).synack_ts = now;
            (*entry).rtt_server_ns = now.wrapping_sub((*entry).syn_ts);
            (*entry).flags |= TCPRT_FLAG_SYNACK_SEEN;
        }
        return;
    }

    // Handshake completion ACK — forward direction, no payload, synack seen
    if is_ack
        && !is_syn
        && (*entry).state == TCPRT_STATE_SYN_SENT
        && ((*entry).flags & TCPRT_FLAG_SYNACK_SEEN) != 0
        && info.payload_len == 0
        && is_forward
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
            if is_retrans_req(entry, info.tcp_seq) {
                (*entry).retrans_req += 1;
            } else {
                // Start a new request/response cycle after the prior one completed.
                if (*entry).first_response_ts > 0 {
                    (*entry).first_response_ts = 0;
                }
            }

            (*entry).last_request_ts = now;
            // Rotate: last → prev, new → last
            (*entry).prev_seq = (*entry).last_seq;
            (*entry).prev_payload_len = (*entry).last_payload_len;
            (*entry).last_seq = info.tcp_seq;
            (*entry).last_payload_len = info.payload_len;
        }
    } else {
        // Response direction (server → client)
        if info.payload_len > 0 {
            if is_retrans_resp(entry, info.tcp_seq) {
                (*entry).retrans_resp += 1;
            }

            // ART and completed cycle count: first response after the latest request.
            if (*entry).first_response_ts == 0 && (*entry).last_request_ts > 0 {
                (*entry).first_response_ts = now;
                (*entry).art_ns = now.wrapping_sub((*entry).last_request_ts);
                (*entry).request_count += 1;
            }

            // Rotate: last → prev, new → last
            (*entry).prev_resp_seq = (*entry).last_resp_seq;
            (*entry).prev_resp_payload_len = (*entry).last_resp_payload_len;
            (*entry).last_resp_seq = info.tcp_seq;
            (*entry).last_resp_payload_len = info.payload_len;
        }
    }
}

/// Track TCP-RT for reverse direction IPv4 (constructs forward key internally).
#[inline(never)]
pub unsafe fn track_tcp_rt_v4_rev(
    tap_id: u32,
    info: &PacketInfo,
    now: u64,
    from_ingress_hook: bool,
) {
    let key_ptr = match CT_KEY4_SCRATCH.get_ptr_mut(CT_KEY_DERIVED_SLOT) {
        Some(ptr) => ptr,
        None => return,
    };
    (*key_ptr).tap_id = tap_id;
    (*key_ptr).src_ip = info.dst_ip;
    (*key_ptr).dst_ip = info.src_ip;
    (*key_ptr).src_port = info.dst_port;
    (*key_ptr).dst_port = info.src_port;
    (*key_ptr).proto = info.proto;
    (*key_ptr).pad = [0; 3];
    track_tcp_rt_v4(&*key_ptr, info, now, false, from_ingress_hook);
}

/// Track TCP-RT for either direction without relying on conntrack direction hints.
/// Used on degraded paths where we only have the packet tuple and current TCPRT table state.
#[inline(never)]
pub unsafe fn track_tcp_rt_v4_auto(
    tap_id: u32,
    info: &PacketInfo,
    now: u64,
    from_ingress_hook: bool,
) {
    let is_syn = (info.tcp_flags & TCP_FLAG_SYN) != 0;
    let is_ack = (info.tcp_flags & TCP_FLAG_ACK) != 0;
    let key_ptr = match CT_KEY4_SCRATCH.get_ptr_mut(CT_KEY_DERIVED_SLOT) {
        Some(ptr) => ptr,
        None => return,
    };
    (*key_ptr).tap_id = tap_id;
    (*key_ptr).src_ip = info.src_ip;
    (*key_ptr).dst_ip = info.dst_ip;
    (*key_ptr).src_port = info.src_port;
    (*key_ptr).dst_port = info.dst_port;
    (*key_ptr).proto = info.proto;
    (*key_ptr).pad = [0; 3];

    if is_syn && !is_ack {
        // Degraded auto-path cannot distinguish a true second-hook observation
        // from a client SYN retransmission. Keep the first SYN timestamp stable,
        // but allow a previously closed slot to be reinitialized for a new flow.
        if TCPRT_TABLE_V4
            .get(&*key_ptr)
            .map(|entry| entry.close_ts > 0)
            .unwrap_or(true)
        {
            track_tcp_rt_v4(&*key_ptr, info, now, true, from_ingress_hook);
        }
        return;
    }

    if TCPRT_TABLE_V4.get(&*key_ptr).is_some() {
        track_tcp_rt_v4(&*key_ptr, info, now, true, from_ingress_hook);
        return;
    }

    (*key_ptr).src_ip = info.dst_ip;
    (*key_ptr).dst_ip = info.src_ip;
    (*key_ptr).src_port = info.dst_port;
    (*key_ptr).dst_port = info.src_port;
    if TCPRT_TABLE_V4.get(&*key_ptr).is_some() {
        track_tcp_rt_v4(&*key_ptr, info, now, false, from_ingress_hook);
    }
}

/// Track TCP response time for an IPv6 flow.
/// Same logic as V4, different map.
#[inline(never)]
pub unsafe fn track_tcp_rt_v6(
    ct_key: &CtKey6,
    info: &PacketInfo,
    now: u64,
    is_forward: bool,
    from_ingress_hook: bool,
) {
    let flags = info.tcp_flags;
    let is_syn = (flags & TCP_FLAG_SYN) != 0;
    let is_ack = (flags & TCP_FLAG_ACK) != 0;
    let is_fin = (flags & TCP_FLAG_FIN) != 0;
    let is_rst = (flags & TCP_FLAG_RST) != 0;

    if is_syn && !is_ack && is_forward {
        if let Some(entry) = TCPRT_TABLE_V6.get_ptr_mut(ct_key) {
            if (*entry).close_ts > 0 {
                init_tcprt_value(entry, now, info.tcp_seq, from_ingress_hook);
                return;
            }
            if !from_ingress_hook
                && (*entry).state == TCPRT_STATE_SYN_SENT
                && (*entry).syn_ingress_ts > 0
                && (*entry).syn_ingress_ts == (*entry).syn_ts
            {
                (*entry).syn_ts = now;
            }
            return;
        }
        let val = match TCPRT_VALUE_BUF.get_ptr_mut(0) {
            Some(v) => v,
            None => return,
        };
        init_tcprt_value(val, now, info.tcp_seq, from_ingress_hook);
        let _ = TCPRT_TABLE_V6.insert(ct_key, &*val, 0);
        return;
    }

    let entry = match TCPRT_TABLE_V6.get_ptr_mut(ct_key) {
        Some(e) => e,
        None => return,
    };

    if (*entry).close_ts > 0 {
        return;
    }

    // FIN — fine-grained close tracking
    if is_fin {
        if (*entry).fin_ts == 0 {
            (*entry).fin_ts = now;
        }
        if is_forward {
            (*entry).flags |= TCPRT_FLAG_FIN_FWD;
            (*entry).state = if ((*entry).flags & TCPRT_FLAG_FIN_REV) != 0 {
                (*entry).close_ts = now;
                TCPRT_STATE_TIME_WAIT
            } else {
                TCPRT_STATE_FIN_WAIT
            };
        } else {
            (*entry).flags |= TCPRT_FLAG_FIN_REV;
            (*entry).state = if ((*entry).flags & TCPRT_FLAG_FIN_FWD) != 0 {
                (*entry).close_ts = now;
                TCPRT_STATE_TIME_WAIT
            } else {
                TCPRT_STATE_CLOSE_WAIT
            };
        }
        return;
    }
    // RST — immediate close
    if is_rst {
        (*entry).rst_ts = now;
        (*entry).close_ts = now;
        (*entry).state = TCPRT_STATE_RST;
        return;
    }

    if is_syn && is_ack && !is_forward {
        if from_ingress_hook {
            if (*entry).synack_ingress_ts == 0 {
                (*entry).synack_ingress_ts = now;
                (*entry).synack_ts = now;
                (*entry).rtt_server_ns = now.wrapping_sub((*entry).syn_ts);
                (*entry).flags |= TCPRT_FLAG_SYNACK_SEEN;
            }
            return;
        }

        if (*entry).synack_ingress_ts > 0 && (*entry).synack_ingress_ts == (*entry).synack_ts {
            (*entry).synack_ts = now;
            (*entry).rtt_server_ns = now.wrapping_sub((*entry).syn_ts);
            (*entry).flags |= TCPRT_FLAG_SYNACK_SEEN;
            return;
        }

        if (*entry).synack_ts == 0 {
            (*entry).synack_ts = now;
            (*entry).rtt_server_ns = now.wrapping_sub((*entry).syn_ts);
            (*entry).flags |= TCPRT_FLAG_SYNACK_SEEN;
        }
        return;
    }

    if is_ack
        && !is_syn
        && (*entry).state == TCPRT_STATE_SYN_SENT
        && ((*entry).flags & TCPRT_FLAG_SYNACK_SEEN) != 0
        && info.payload_len == 0
        && is_forward
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
            if is_retrans_req(entry, info.tcp_seq) {
                (*entry).retrans_req += 1;
            } else {
                if (*entry).first_response_ts > 0 {
                    (*entry).first_response_ts = 0;
                }
            }
            (*entry).last_request_ts = now;
            (*entry).prev_seq = (*entry).last_seq;
            (*entry).prev_payload_len = (*entry).last_payload_len;
            (*entry).last_seq = info.tcp_seq;
            (*entry).last_payload_len = info.payload_len;
        }
    } else {
        if info.payload_len > 0 {
            if is_retrans_resp(entry, info.tcp_seq) {
                (*entry).retrans_resp += 1;
            }
            if (*entry).first_response_ts == 0 && (*entry).last_request_ts > 0 {
                (*entry).first_response_ts = now;
                (*entry).art_ns = now.wrapping_sub((*entry).last_request_ts);
                (*entry).request_count += 1;
            }
            (*entry).prev_resp_seq = (*entry).last_resp_seq;
            (*entry).prev_resp_payload_len = (*entry).last_resp_payload_len;
            (*entry).last_resp_seq = info.tcp_seq;
            (*entry).last_resp_payload_len = info.payload_len;
        }
    }
}

/// Track TCP-RT for reverse direction IPv6 (constructs forward key internally).
#[inline(never)]
pub unsafe fn track_tcp_rt_v6_rev(
    tap_id: u32,
    info: &PacketInfo,
    now: u64,
    from_ingress_hook: bool,
) {
    let key_ptr = match CT_KEY6_SCRATCH.get_ptr_mut(CT_KEY_DERIVED_SLOT) {
        Some(ptr) => ptr,
        None => return,
    };
    (*key_ptr).tap_id = tap_id;
    (*key_ptr).src_ip = info.dst_ip_v6;
    (*key_ptr).dst_ip = info.src_ip_v6;
    (*key_ptr).src_port = info.dst_port;
    (*key_ptr).dst_port = info.src_port;
    (*key_ptr).proto = info.proto;
    (*key_ptr).pad = [0; 3];
    track_tcp_rt_v6(&*key_ptr, info, now, false, from_ingress_hook);
}

/// Track TCP-RT for either direction without relying on conntrack direction hints.
#[inline(never)]
pub unsafe fn track_tcp_rt_v6_auto(
    tap_id: u32,
    info: &PacketInfo,
    now: u64,
    from_ingress_hook: bool,
) {
    let is_syn = (info.tcp_flags & TCP_FLAG_SYN) != 0;
    let is_ack = (info.tcp_flags & TCP_FLAG_ACK) != 0;
    let key_ptr = match CT_KEY6_SCRATCH.get_ptr_mut(CT_KEY_DERIVED_SLOT) {
        Some(ptr) => ptr,
        None => return,
    };
    (*key_ptr).tap_id = tap_id;
    (*key_ptr).src_ip = info.src_ip_v6;
    (*key_ptr).dst_ip = info.dst_ip_v6;
    (*key_ptr).src_port = info.src_port;
    (*key_ptr).dst_port = info.dst_port;
    (*key_ptr).proto = info.proto;
    (*key_ptr).pad = [0; 3];

    if is_syn && !is_ack {
        if TCPRT_TABLE_V6
            .get(&*key_ptr)
            .map(|entry| entry.close_ts > 0)
            .unwrap_or(true)
        {
            track_tcp_rt_v6(&*key_ptr, info, now, true, from_ingress_hook);
        }
        return;
    }

    if TCPRT_TABLE_V6.get(&*key_ptr).is_some() {
        track_tcp_rt_v6(&*key_ptr, info, now, true, from_ingress_hook);
        return;
    }

    (*key_ptr).src_ip = info.dst_ip_v6;
    (*key_ptr).dst_ip = info.src_ip_v6;
    (*key_ptr).src_port = info.dst_port;
    (*key_ptr).dst_port = info.src_port;
    if TCPRT_TABLE_V6.get(&*key_ptr).is_some() {
        track_tcp_rt_v6(&*key_ptr, info, now, false, from_ingress_hook);
    }
}
