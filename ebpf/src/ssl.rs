use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_user_str_bytes, bpf_probe_read_user_buf};
use aya_ebpf::programs::{ProbeContext, RetProbeContext};

use crate::maps::{
    FIREWALL_CONFIG, SSL_HANDSHAKE_SCRATCH, SSL_CONN_TABLE, SSL_SNI_TABLE, SSL_SEQ,
    SSL_HTTP_SCRATCH_BUF, SSL_HTTP_SCRATCH, SSL_READ_SCRATCH, SSL_HTTP_TABLE, SSL_HTTP_SEQ,
    SSL_HTTP_PARSE_BUF, SSL_HTTP_VALUE_BUF, SSL_GLOBAL_CONFIG,
    SslScratch, SslConnValue, SslReadScratch, SslHttpValue,
};

const SSL_CTRL_SET_TLSEXT_HOSTNAME: u64 = 55;

/// Check global SSL observability config (not per-interface)
/// SSL uprobe is process-level, shared across all network interfaces
#[inline(always)]
unsafe fn ssl_enabled() -> bool {
    match SSL_GLOBAL_CONFIG.get(&0u32) {
        Some(&v) => v != 0,
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

// --- SSL HTTP (Phase 2): zero-loop design for kernel 4.18+ compatibility ---

/// uprobe on SSL_write: detect HTTP request, store raw header for userspace parsing
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

    // Use per-CPU scratch to read request data directly (no loops)
    let scratch = match SSL_HTTP_SCRATCH_BUF.get_ptr_mut(0) {
        Some(p) => &mut *p,
        None => return 0,
    };

    let read_len = if num < 255 { num as usize } else { 255 };
    let read_len = read_len & 0xFF; // verifier hint: max 255
    if read_len < 4 {
        return 0;
    }

    // Read directly into scratch.req_data — zero copy, zero loops
    if bpf_probe_read_user_buf(buf_ptr as *const u8, &mut scratch.req_data[..read_len]).is_err() {
        return 0;
    }

    // Detect HTTP method — pure branch comparison, zero loops
    let d = &scratch.req_data;
    let is_http = (d[0] == b'G' && d[1] == b'E' && d[2] == b'T' && d[3] == b' ')
        || (read_len >= 5 && d[0] == b'P' && d[1] == b'O' && d[2] == b'S' && d[3] == b'T' && d[4] == b' ')
        || (d[0] == b'P' && d[1] == b'U' && d[2] == b'T' && d[3] == b' ')
        || (read_len >= 5 && d[0] == b'H' && d[1] == b'E' && d[2] == b'A' && d[3] == b'D' && d[4] == b' ')
        || (read_len >= 7 && d[0] == b'D' && d[1] == b'E' && d[2] == b'L' && d[3] == b'E' && d[4] == b'T' && d[5] == b'E' && d[6] == b' ')
        || (read_len >= 6 && d[0] == b'P' && d[1] == b'A' && d[2] == b'T' && d[3] == b'C' && d[4] == b'H' && d[5] == b' ');

    if !is_http {
        return 0;
    }

    scratch.write_ts = bpf_ktime_get_ns();

    // Null-terminate: always safe since read_len <= 255 < 256
    scratch.req_data[read_len] = 0;

    let pid_tgid = bpf_get_current_pid_tgid();
    let _ = SSL_HTTP_SCRATCH.insert(&pid_tgid, scratch, 0);
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

    // Check for pending HTTP request (avoid stack copy of 264-byte struct)
    let http_scratch = match SSL_HTTP_SCRATCH.get(&pid_tgid) {
        Some(s) => s,
        None => return 0,
    };

    // Clean up stale entries: request without response for > 30s
    const SCRATCH_TIMEOUT_NS: u64 = 30_000_000_000;
    let now = bpf_ktime_get_ns();
    if now.saturating_sub(http_scratch.write_ts) > SCRATCH_TIMEOUT_NS {
        let _ = SSL_HTTP_SCRATCH.remove(&pid_tgid);
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

    // Get and remove read scratch (small struct, ok to copy)
    let read_scratch = match SSL_READ_SCRATCH.get(&pid_tgid) {
        Some(s) => *s,
        None => return 0,
    };
    let _ = SSL_READ_SCRATCH.remove(&pid_tgid);

    // Get HTTP scratch pointer (avoid stack copy of 264-byte struct)
    let http_scratch = match SSL_HTTP_SCRATCH.get(&pid_tgid) {
        Some(s) => s,
        None => return 0,
    };

    // Read first 32 bytes of response to detect "HTTP/1.x NNN" (handle fragmentation)
    let parse_buf = match SSL_HTTP_PARSE_BUF.get_ptr_mut(0) {
        Some(p) => &mut *p,
        None => return 0,
    };

    // Only need 13 bytes ("HTTP/1.x NNN"), read 32 for fragmentation tolerance
    let read_len: usize = if (ret as usize) < 32 { ret as usize } else { 32 };
    if read_len < 13 {
        return 0;
    }
    if bpf_probe_read_user_buf(read_scratch.buf_ptr as *const u8, &mut parse_buf.data[..32]).is_err() {
        return 0;
    }

    let d = &parse_buf.data;

    // Check "HTTP/1." prefix — pure branch, zero loops
    if d[0] != b'H' || d[1] != b'T' || d[2] != b'T' || d[3] != b'P'
        || d[4] != b'/' || d[5] != b'1' || d[6] != b'.' {
        return 0;
    }

    // Status code at offset 9 (after "HTTP/1.x ")
    let d0 = d[9];
    let d1 = d[10];
    let d2 = d[11];
    if d0 < b'0' || d0 > b'9' || d1 < b'0' || d1 > b'9' || d2 < b'0' || d2 > b'9' {
        return 0;
    }
    let status_code = ((d0 - b'0') as u16) * 100 + ((d1 - b'0') as u16) * 10 + ((d2 - b'0') as u16);

    let now = bpf_ktime_get_ns();
    let latency_ns = now.saturating_sub(http_scratch.write_ts);

    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    // Use Per-CPU buffer for SslHttpValue to avoid stack overflow
    let event = match SSL_HTTP_VALUE_BUF.get_ptr_mut(0) {
        Some(p) => &mut *p,
        None => return 0,
    };

    event.pid = pid;
    event.tid = tid;
    event.request_ts = http_scratch.write_ts;
    event.response_ts = now;
    event.latency_ns = latency_ns;
    event.status_code = status_code;
    event._pad = [0u8; 6];
    event.req_data.copy_from_slice(&http_scratch.req_data);

    // Remove HTTP scratch after copying data
    let _ = SSL_HTTP_SCRATCH.remove(&pid_tgid);

    // Get per-CPU seq
    let seq_ptr = match SSL_HTTP_SEQ.get_ptr_mut(0) {
        Some(p) => p,
        None => return 0,
    };
    let seq = *seq_ptr;
    *seq_ptr = seq.wrapping_add(1);

    let _ = SSL_HTTP_TABLE.insert(&seq, event, 0);
    0
}
