use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_user_str_bytes, bpf_probe_read_user_buf};
use aya_ebpf::programs::{ProbeContext, RetProbeContext};

use crate::maps::{
    FIREWALL_CONFIG, SSL_HANDSHAKE_SCRATCH, SSL_CONN_TABLE, SSL_SNI_TABLE, SSL_SEQ,
    SSL_HTTP_SCRATCH_BUF, SSL_HTTP_SCRATCH, SSL_READ_SCRATCH, SSL_HTTP_TABLE, SSL_HTTP_SEQ,
    SSL_HTTP_PARSE_BUF, SSL_HTTP_VALUE_BUF, SSL_GLOBAL_CONFIG,
    SSL_ERROR_TABLE, SSL_ERROR_SEQ, SSL_WRITE_SCRATCH,
    SslScratch, SslConnValue, SslReadScratch, SslHttpValue, SslErrorEvent, SslWriteScratch,
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

/// Emit SSL error event to userspace
#[inline(always)]
unsafe fn emit_ssl_error_event(
    pid_tgid: u64,
    ssl_ptr: u64,
    syscall: u8,
    ret_code: i32,
    error_hint: u8,
) {
    let now = bpf_ktime_get_ns();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    let event = SslErrorEvent {
        pid,
        tid,
        timestamp: now,
        ssl_ptr,
        syscall,
        ret_code,
        error_hint,
        _pad: [0u8; 2],
    };

    // Get per-CPU seq
    let seq_ptr = match SSL_ERROR_SEQ.get_ptr_mut(0) {
        Some(p) => p,
        None => return,
    };
    let seq = *seq_ptr;
    *seq_ptr = seq.wrapping_add(1);

    let _ = SSL_ERROR_TABLE.insert(&seq, &event, 0);
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

const SCRATCH_TIMEOUT_NS: u64 = 30_000_000_000;
const SSL_READ_MODE_STANDARD: u8 = 0;
const SSL_READ_MODE_EX: u8 = 1;

#[inline(always)]
unsafe fn http_request_is_fresh(pid_tgid: u64) -> bool {
    let http_scratch = match SSL_HTTP_SCRATCH.get(&pid_tgid) {
        Some(s) => s,
        None => return false,
    };

    if bpf_ktime_get_ns().saturating_sub(http_scratch.write_ts) > SCRATCH_TIMEOUT_NS {
        let _ = SSL_HTTP_SCRATCH.remove(&pid_tgid);
        return false;
    }

    true
}

#[inline(always)]
unsafe fn store_ssl_read_scratch(
    pid_tgid: u64,
    ssl_ptr: u64,
    buf_ptr: u64,
    out_len_ptr: u64,
    mode: u8,
) {
    let read_scratch = SslReadScratch {
        ssl_ptr,
        buf_ptr,
        out_len_ptr,
        mode,
        _pad: [0u8; 7],
    };
    let _ = SSL_READ_SCRATCH.insert(&pid_tgid, &read_scratch, 0);
}

#[inline(always)]
unsafe fn resolve_ssl_read_len(read_scratch: &SslReadScratch, ret: i32) -> Option<usize> {
    let actual_len = if read_scratch.mode == SSL_READ_MODE_EX {
        if read_scratch.out_len_ptr == 0 {
            return None;
        }

        let mut len_bytes = [0u8; 8];
        if bpf_probe_read_user_buf(read_scratch.out_len_ptr as *const u8, &mut len_bytes).is_err() {
            return None;
        }

        u64::from_ne_bytes(len_bytes) as usize
    } else {
        ret as usize
    };

    let read_len = if actual_len < 32 { actual_len } else { 32 };
    if read_len < 13 {
        return None;
    }

    Some(read_len)
}

#[inline(always)]
unsafe fn handle_ssl_read_return(pid_tgid: u64, ret: i32) -> u32 {
    if ret <= 0 {
        let ssl_ptr = SSL_READ_SCRATCH
            .get(&pid_tgid)
            .map(|s| s.ssl_ptr)
            .unwrap_or(0);

        let error_hint = if ret == 0 { 1 } else { 3 };
        emit_ssl_error_event(pid_tgid, ssl_ptr, 0, ret, error_hint);

        let _ = SSL_READ_SCRATCH.remove(&pid_tgid);

        // SSL_read* may report retryable states as non-positive returns and
        // require userspace to inspect SSL_get_error(). Keep the pending HTTP
        // request so a later successful read can still correlate the response.
        // Stale requests are cleaned up by the scratch timeout path.
        return 0;
    }

    let read_scratch = match SSL_READ_SCRATCH.get(&pid_tgid) {
        Some(s) => *s,
        None => return 0,
    };
    let _ = SSL_READ_SCRATCH.remove(&pid_tgid);

    let http_scratch = match SSL_HTTP_SCRATCH.get(&pid_tgid) {
        Some(s) => s,
        None => return 0,
    };

    let read_len = match resolve_ssl_read_len(&read_scratch, ret) {
        Some(v) => v,
        None => return 0,
    };

    let parse_buf = match SSL_HTTP_PARSE_BUF.get_ptr_mut(0) {
        Some(p) => &mut *p,
        None => return 0,
    };

    if bpf_probe_read_user_buf(
        read_scratch.buf_ptr as *const u8,
        &mut parse_buf.data[..read_len],
    )
    .is_err()
    {
        return 0;
    }

    let d = &parse_buf.data;
    if d[0] != b'H' || d[1] != b'T' || d[2] != b'T' || d[3] != b'P'
        || d[4] != b'/' || d[5] != b'1' || d[6] != b'.'
    {
        return 0;
    }

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

    let _ = SSL_HTTP_SCRATCH.remove(&pid_tgid);

    let seq_ptr = match SSL_HTTP_SEQ.get_ptr_mut(0) {
        Some(p) => p,
        None => return 0,
    };
    let seq = *seq_ptr;
    *seq_ptr = seq.wrapping_add(1);

    let _ = SSL_HTTP_TABLE.insert(&seq, event, 0);
    0
}

/// uprobe on SSL_write: detect HTTP request, store raw header for userspace parsing
pub unsafe fn ssl_write_entry_impl(ctx: &ProbeContext) -> u32 {
    if !ssl_enabled() {
        return 0;
    }
    // SSL_write(ssl, buf, num) — ssl is arg0, buf is arg1, num is arg2
    let ssl_ptr: u64 = match ctx.arg(0) {
        Some(v) => v,
        None => return 0,
    };
    let buf_ptr: u64 = match ctx.arg(1) {
        Some(v) => v,
        None => return 0,
    };
    let num: u64 = match ctx.arg(2) {
        Some(v) => v,
        None => return 0,
    };
    if ssl_ptr == 0 || buf_ptr == 0 || num == 0 {
        return 0;
    }

    // Save ssl_ptr for return probe (to emit error if write fails)
    let pid_tgid = bpf_get_current_pid_tgid();
    let write_scratch = SslWriteScratch {
        ssl_ptr,
        write_ts: bpf_ktime_get_ns(),
    };
    let _ = SSL_WRITE_SCRATCH.insert(&pid_tgid, &write_scratch, 0);

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
    // SSL_read(ssl, buf, num)
    let ssl_ptr: u64 = match ctx.arg(0) {
        Some(v) => v,
        None => return 0,
    };
    let buf_ptr: u64 = match ctx.arg(1) {
        Some(v) => v,
        None => return 0,
    };
    if ssl_ptr == 0 || buf_ptr == 0 {
        return 0;
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    if !http_request_is_fresh(pid_tgid) {
        return 0;
    }

    store_ssl_read_scratch(pid_tgid, ssl_ptr, buf_ptr, 0, SSL_READ_MODE_STANDARD);
    0
}

/// uprobe on SSL_read_ex: save buf pointer and out-len pointer for return probe
pub unsafe fn ssl_read_ex_entry_impl(ctx: &ProbeContext) -> u32 {
    if !ssl_enabled() {
        return 0;
    }
    // SSL_read_ex(ssl, buf, num, readbytes)
    let ssl_ptr: u64 = match ctx.arg(0) {
        Some(v) => v,
        None => return 0,
    };
    let buf_ptr: u64 = match ctx.arg(1) {
        Some(v) => v,
        None => return 0,
    };
    let out_len_ptr: u64 = match ctx.arg(3) {
        Some(v) => v,
        None => return 0,
    };
    if ssl_ptr == 0 || buf_ptr == 0 || out_len_ptr == 0 {
        return 0;
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    if !http_request_is_fresh(pid_tgid) {
        return 0;
    }

    store_ssl_read_scratch(pid_tgid, ssl_ptr, buf_ptr, out_len_ptr, SSL_READ_MODE_EX);
    0
}

/// uretprobe on SSL_read: parse HTTP response status code and emit event
/// Also track errors when ret <= 0
pub unsafe fn ssl_read_return_impl(ctx: &RetProbeContext) -> u32 {
    if !ssl_enabled() {
        return 0;
    }
    let ret: i32 = match ctx.ret() {
        Some(v) => v,
        None => return 0,
    };

    let pid_tgid = bpf_get_current_pid_tgid();
    handle_ssl_read_return(pid_tgid, ret)
}

/// uretprobe on SSL_read_ex: parse HTTP response status code and emit event
pub unsafe fn ssl_read_ex_return_impl(ctx: &RetProbeContext) -> u32 {
    if !ssl_enabled() {
        return 0;
    }
    let ret: i32 = match ctx.ret() {
        Some(v) => v,
        None => return 0,
    };

    let pid_tgid = bpf_get_current_pid_tgid();
    handle_ssl_read_return(pid_tgid, ret)
}

/// uretprobe on SSL_write: track write errors
pub unsafe fn ssl_write_return_impl(ctx: &RetProbeContext) -> u32 {
    if !ssl_enabled() {
        return 0;
    }
    let ret: i32 = match ctx.ret() {
        Some(v) => v,
        None => return 0,
    };

    // Only track errors
    if ret <= 0 {
        let pid_tgid = bpf_get_current_pid_tgid();

        // Get ssl_ptr from write scratch
        let ssl_ptr = match SSL_WRITE_SCRATCH.get(&pid_tgid) {
            Some(s) => s.ssl_ptr,
            None => return 0,
        };

        let error_hint = if ret == 0 {
            1  // zero_return
        } else {
            3  // syscall_err
        };

        emit_ssl_error_event(pid_tgid, ssl_ptr, 1, ret, error_hint);
    }

    // Always clean up write scratch
    let pid_tgid = bpf_get_current_pid_tgid();
    let _ = SSL_WRITE_SCRATCH.remove(&pid_tgid);

    0
}
