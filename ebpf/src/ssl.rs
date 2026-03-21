use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_user_str_bytes, bpf_probe_read_user_buf};
use aya_ebpf::programs::{ProbeContext, RetProbeContext};

use crate::maps::{
    FIREWALL_CONFIG, SSL_HANDSHAKE_SCRATCH, SSL_CONN_TABLE, SSL_SNI_TABLE, SSL_SEQ,
    SSL_HTTP_PARSE_BUF, SSL_HTTP_SCRATCH, SSL_READ_SCRATCH, SSL_HTTP_TABLE, SSL_HTTP_SEQ,
    SslScratch, SslConnValue, SslHttpScratch, SslReadScratch, SslHttpValue,
};

const SSL_CTRL_SET_TLSEXT_HOSTNAME: u64 = 55;

#[inline(always)]
unsafe fn ssl_enabled() -> bool {
    match FIREWALL_CONFIG.get(&0u32) {
        Some(cfg) => cfg.ssl_enabled != 0,
        None => false,
    }
}

pub unsafe fn ssl_handshake_entry_impl(ctx: &ProbeContext) -> u32 {
    if !ssl_enabled() {
        return 0;
    }
    let pid_tgid = bpf_get_current_pid_tgid();
    let ssl_ptr: u64 = match ctx.arg(0) {
        Some(v) => v,
        None => return 0,
    };
    let scratch = SslScratch {
        ssl_ptr,
        start_ts: bpf_ktime_get_ns(),
    };
    let _ = SSL_HANDSHAKE_SCRATCH.insert(&pid_tgid, &scratch, 0);
    0
}

pub unsafe fn ssl_handshake_return_impl(_ctx: &RetProbeContext) -> u32 {
    if !ssl_enabled() {
        return 0;
    }
    let pid_tgid = bpf_get_current_pid_tgid();
    let scratch = match SSL_HANDSHAKE_SCRATCH.get(&pid_tgid) {
        Some(s) => *s,
        None => return 0,
    };
    let _ = SSL_HANDSHAKE_SCRATCH.remove(&pid_tgid);

    let now = bpf_ktime_get_ns();
    let handshake_ns = now.saturating_sub(scratch.start_ts);

    // Read SNI if available
    let mut sni = [0u8; 64];
    if let Some(sni_val) = SSL_SNI_TABLE.get(&pid_tgid) {
        sni = *sni_val;
        let _ = SSL_SNI_TABLE.remove(&pid_tgid);
    }

    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    let conn = SslConnValue {
        pid,
        tid,
        handshake_ns,
        timestamp: now,
        sni,
    };

    // Get per-CPU seq
    let seq_ptr = match SSL_SEQ.get_ptr_mut(0) {
        Some(p) => p,
        None => return 0,
    };
    let seq = *seq_ptr;
    *seq_ptr = seq.wrapping_add(1);

    let _ = SSL_CONN_TABLE.insert(&seq, &conn, 0);
    0
}

pub unsafe fn ssl_set_sni_impl(ctx: &ProbeContext) -> u32 {
    if !ssl_enabled() {
        return 0;
    }
    // SSL_ctrl(ssl, cmd, larg, parg)
    // cmd is arg1, parg is arg3
    let cmd: u64 = match ctx.arg(1) {
        Some(v) => v,
        None => return 0,
    };
    if cmd != SSL_CTRL_SET_TLSEXT_HOSTNAME {
        return 0;
    }
    let hostname_ptr: *const u8 = match ctx.arg::<u64>(3) {
        Some(v) => v as *const u8,
        None => return 0,
    };
    if hostname_ptr.is_null() {
        return 0;
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let mut sni = [0u8; 64];

    match bpf_probe_read_user_str_bytes(hostname_ptr, &mut sni) {
        Ok(_) => {}
        Err(_) => return 0,
    }

    let _ = SSL_SNI_TABLE.insert(&pid_tgid, &sni, 0);
    0
}

// --- SSL HTTP (Phase 2) ---

/// Check if a byte slice starts with the given prefix (verifier-friendly)
#[inline(always)]
fn starts_with(data: &[u8], prefix: &[u8]) -> bool {
    if data.len() < prefix.len() {
        return false;
    }
    let mut i = 0;
    while i < prefix.len() {
        if data[i] != prefix[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// uprobe on SSL_write: parse HTTP request line and Host header
pub unsafe fn ssl_write_entry_impl(ctx: &ProbeContext) -> u32 {
    if !ssl_enabled() {
        return 0;
    }
    // SSL_write(ssl, buf, num) — buf is arg1, num is arg2
    let buf_ptr: u64 = match ctx.arg(1) {
        Some(v) => v,
        None => return 0,
    };
    let num: u64 = match ctx.arg(2) {
        Some(v) => v,
        None => return 0,
    };
    if buf_ptr == 0 || num == 0 {
        return 0;
    }

    let parse_buf = match SSL_HTTP_PARSE_BUF.get_ptr_mut(0) {
        Some(p) => &mut *p,
        None => return 0,
    };

    let read_len = if num < 256 { num as usize } else { 256 };
    let read_len = read_len & 0xFF; // verifier hint: max 255
    if read_len == 0 {
        return 0;
    }
    if bpf_probe_read_user_buf(buf_ptr as *const u8, &mut parse_buf.data[..read_len]).is_err() {
        return 0;
    }

    // Check for HTTP methods
    let data = &parse_buf.data[..read_len];
    let mut method_len: usize = 0;

    if starts_with(data, b"GET ") {
        method_len = 3;
    } else if starts_with(data, b"POST ") {
        method_len = 4;
    } else if starts_with(data, b"PUT ") {
        method_len = 3;
    } else if starts_with(data, b"DELETE ") {
        method_len = 6;
    } else if starts_with(data, b"HEAD ") {
        method_len = 4;
    } else if starts_with(data, b"PATCH ") {
        method_len = 5;
    } else {
        // Not an HTTP request, skip
        return 0;
    }

    let mut scratch = SslHttpScratch {
        write_ts: bpf_ktime_get_ns(),
        method: [0u8; 8],
        path: [0u8; 128],
        host: [0u8; 64],
    };

    // Copy method
    let m_copy = if method_len > 7 { 7 } else { method_len };
    for i in 0..m_copy {
        if i < 7 {
            scratch.method[i] = data[i];
        }
    }

    // Extract path: starts after "METHOD ", ends at next space or \r\n
    let path_start = method_len + 1; // skip the space after method
    let mut path_end = path_start;
    for i in path_start..read_len {
        if i >= read_len {
            break;
        }
        if data[i] == b' ' || data[i] == b'\r' || data[i] == b'\n' {
            path_end = i;
            break;
        }
        path_end = i + 1;
    }
    let path_len = path_end - path_start;
    let p_copy = if path_len > 127 { 127 } else { path_len };
    for i in 0..p_copy {
        let src_idx = path_start + i;
        if src_idx < read_len && i < 127 {
            scratch.path[i] = data[src_idx];
        }
    }

    // Extract Host header: search for "\r\nHost: "
    let host_prefix = b"\r\nHost: ";
    let hp_len = host_prefix.len(); // 8
    let mut host_start: usize = 0;
    let mut found_host = false;
    // Bounded loop for verifier
    for i in 0..248 {
        if i + hp_len > read_len {
            break;
        }
        if starts_with(&data[i..], host_prefix) {
            host_start = i + hp_len;
            found_host = true;
            break;
        }
    }
    if found_host {
        let mut host_end = host_start;
        for i in host_start..read_len {
            if i >= read_len {
                break;
            }
            if data[i] == b'\r' || data[i] == b'\n' {
                host_end = i;
                break;
            }
            host_end = i + 1;
        }
        let host_len = host_end - host_start;
        let h_copy = if host_len > 63 { 63 } else { host_len };
        for i in 0..h_copy {
            let src_idx = host_start + i;
            if src_idx < read_len && i < 63 {
                scratch.host[i] = data[src_idx];
            }
        }
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let _ = SSL_HTTP_SCRATCH.insert(&pid_tgid, &scratch, 0);
    0
}

/// uprobe on SSL_read: save buf pointer for return probe
pub unsafe fn ssl_read_entry_impl(ctx: &ProbeContext) -> u32 {
    if !ssl_enabled() {
        return 0;
    }
    // SSL_read(ssl, buf, num) — buf is arg1
    let buf_ptr: u64 = match ctx.arg(1) {
        Some(v) => v,
        None => return 0,
    };
    if buf_ptr == 0 {
        return 0;
    }

    let pid_tgid = bpf_get_current_pid_tgid();

    // Only track if we have a pending write (HTTP request)
    if SSL_HTTP_SCRATCH.get(&pid_tgid).is_none() {
        return 0;
    }

    let read_scratch = SslReadScratch { buf_ptr };
    let _ = SSL_READ_SCRATCH.insert(&pid_tgid, &read_scratch, 0);
    0
}

/// uretprobe on SSL_read: parse HTTP response status code and emit event
pub unsafe fn ssl_read_return_impl(ctx: &RetProbeContext) -> u32 {
    if !ssl_enabled() {
        return 0;
    }
    let ret: i32 = match ctx.ret() {
        Some(v) => v,
        None => return 0,
    };
    if ret <= 0 {
        return 0;
    }

    let pid_tgid = bpf_get_current_pid_tgid();

    // Get and remove read scratch
    let read_scratch = match SSL_READ_SCRATCH.get(&pid_tgid) {
        Some(s) => *s,
        None => return 0,
    };
    let _ = SSL_READ_SCRATCH.remove(&pid_tgid);

    // Get and remove HTTP scratch (pending request)
    let http_scratch = match SSL_HTTP_SCRATCH.get(&pid_tgid) {
        Some(s) => *s,
        None => return 0,
    };
    let _ = SSL_HTTP_SCRATCH.remove(&pid_tgid);

    // Read response data
    let parse_buf = match SSL_HTTP_PARSE_BUF.get_ptr_mut(0) {
        Some(p) => &mut *p,
        None => return 0,
    };

    let read_len = if (ret as usize) < 256 { ret as usize } else { 256 };
    let read_len = read_len & 0xFF; // verifier hint: max 255
    if read_len == 0 {
        return 0;
    }
    if bpf_probe_read_user_buf(read_scratch.buf_ptr as *const u8, &mut parse_buf.data[..read_len]).is_err() {
        return 0;
    }

    let data = &parse_buf.data[..read_len];

    // Parse "HTTP/1.x NNN": need at least 12 bytes
    if read_len < 12 {
        return 0;
    }
    if !starts_with(data, b"HTTP/1.") {
        return 0;
    }

    // Status code starts at offset 9 (after "HTTP/1.x ")
    let d0 = data[9];
    let d1 = data[10];
    let d2 = data[11];
    if d0 < b'0' || d0 > b'9' || d1 < b'0' || d1 > b'9' || d2 < b'0' || d2 > b'9' {
        return 0;
    }
    let status_code = ((d0 - b'0') as u16) * 100 + ((d1 - b'0') as u16) * 10 + ((d2 - b'0') as u16);

    let now = bpf_ktime_get_ns();
    let latency_ns = now.saturating_sub(http_scratch.write_ts);

    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    let event = SslHttpValue {
        pid,
        tid,
        request_ts: http_scratch.write_ts,
        response_ts: now,
        latency_ns,
        status_code,
        method: http_scratch.method,
        path: http_scratch.path,
        host: http_scratch.host,
        _pad: [0u8; 2],
    };

    // Get per-CPU seq
    let seq_ptr = match SSL_HTTP_SEQ.get_ptr_mut(0) {
        Some(p) => p,
        None => return 0,
    };
    let seq = *seq_ptr;
    *seq_ptr = seq.wrapping_add(1);

    let _ = SSL_HTTP_TABLE.insert(&seq, &event, 0);
    0
}
