use aya_ebpf::{check_bounds_signed, cty::c_void};
use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_user_str_bytes, bpf_probe_read_user_buf, gen};
use aya_ebpf::programs::{ProbeContext, RetProbeContext};

use crate::maps::{
    FIREWALL_CONFIG, SSL_HANDSHAKE_SCRATCH, SSL_CONN_TABLE, SSL_SNI_TABLE, SSL_SEQ,
    SSL_HTTP_SCRATCH_BUF, SSL_HTTP_SCRATCH, SSL_READ_SCRATCH, SSL_HTTP_TABLE, SSL_HTTP_SEQ,
    SSL_HTTP_PARSE_BUF, SSL_HTTP_VALUE_BUF, SSL_GLOBAL_CONFIG,
    SSL_ERROR_TABLE, SSL_ERROR_SEQ, SSL_WRITE_SCRATCH,
    SslScratch, SslConnValue, SslParseBuf, SslHttpScratch, SslReadScratch, SslHttpValue, SslErrorEvent, SslWriteScratch,
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
const SSL_HTTP_REQ_CAP: usize = 256;
const SSL_READ_MODE_STANDARD: u8 = 0;
const SSL_READ_MODE_EX: u8 = 1;
const SSL_HTTP_FLAG_MATCHED: u8 = 1;
const HTTP_PREFIX_REJECT: u8 = 0;
const HTTP_PREFIX_PENDING: u8 = 1;
const HTTP_PREFIX_MATCHED: u8 = 2;

macro_rules! append_fragment_byte {
    ($scratch:expr, $parse_buf:expr, $copy_len:expr, $idx:expr $(,)?) => {
        if $copy_len > $idx {
            let current_start = core::ptr::read_volatile(core::ptr::addr_of!(($scratch).data_len)) as usize;
            if current_start > (SSL_HTTP_REQ_CAP - 1 - $idx) {
                return false;
            }
            *((($scratch).req_data.as_mut_ptr()).add(current_start + $idx)) = ($parse_buf).data[$idx];
        }
    };
}

#[inline(always)]
fn http_method_state_4(data: &[u8; 256], len: usize, b0: u8, b1: u8, b2: u8, b3: u8) -> u8 {
    if len == 0 {
        return HTTP_PREFIX_PENDING;
    }
    if data[0] != b0 {
        return HTTP_PREFIX_REJECT;
    }
    if len == 1 {
        return HTTP_PREFIX_PENDING;
    }
    if data[1] != b1 {
        return HTTP_PREFIX_REJECT;
    }
    if len == 2 {
        return HTTP_PREFIX_PENDING;
    }
    if data[2] != b2 {
        return HTTP_PREFIX_REJECT;
    }
    if len == 3 {
        return HTTP_PREFIX_PENDING;
    }
    if data[3] != b3 {
        return HTTP_PREFIX_REJECT;
    }
    HTTP_PREFIX_MATCHED
}

#[inline(always)]
fn http_method_state_5(data: &[u8; 256], len: usize, b0: u8, b1: u8, b2: u8, b3: u8, b4: u8) -> u8 {
    let state = http_method_state_4(data, len, b0, b1, b2, b3);
    if state != HTTP_PREFIX_MATCHED {
        return state;
    }
    if len == 4 {
        return HTTP_PREFIX_PENDING;
    }
    if data[4] != b4 {
        return HTTP_PREFIX_REJECT;
    }
    HTTP_PREFIX_MATCHED
}

#[inline(always)]
fn http_method_state_6(
    data: &[u8; 256],
    len: usize,
    b0: u8,
    b1: u8,
    b2: u8,
    b3: u8,
    b4: u8,
    b5: u8,
) -> u8 {
    let state = http_method_state_5(data, len, b0, b1, b2, b3, b4);
    if state != HTTP_PREFIX_MATCHED {
        return state;
    }
    if len == 5 {
        return HTTP_PREFIX_PENDING;
    }
    if data[5] != b5 {
        return HTTP_PREFIX_REJECT;
    }
    HTTP_PREFIX_MATCHED
}

#[inline(always)]
fn http_method_state_7(
    data: &[u8; 256],
    len: usize,
    b0: u8,
    b1: u8,
    b2: u8,
    b3: u8,
    b4: u8,
    b5: u8,
    b6: u8,
) -> u8 {
    let state = http_method_state_6(data, len, b0, b1, b2, b3, b4, b5);
    if state != HTTP_PREFIX_MATCHED {
        return state;
    }
    if len == 6 {
        return HTTP_PREFIX_PENDING;
    }
    if data[6] != b6 {
        return HTTP_PREFIX_REJECT;
    }
    HTTP_PREFIX_MATCHED
}

#[inline(always)]
fn http_method_state_8(
    data: &[u8; 256],
    len: usize,
    b0: u8,
    b1: u8,
    b2: u8,
    b3: u8,
    b4: u8,
    b5: u8,
    b6: u8,
    b7: u8,
) -> u8 {
    let state = http_method_state_7(data, len, b0, b1, b2, b3, b4, b5, b6);
    if state != HTTP_PREFIX_MATCHED {
        return state;
    }
    if len == 7 {
        return HTTP_PREFIX_PENDING;
    }
    if data[7] != b7 {
        return HTTP_PREFIX_REJECT;
    }
    HTTP_PREFIX_MATCHED
}

#[inline(always)]
fn classify_http_method_prefix(data: &[u8; 256], len: usize) -> u8 {
    let get = http_method_state_4(data, len, b'G', b'E', b'T', b' ');
    if get == HTTP_PREFIX_MATCHED {
        return HTTP_PREFIX_MATCHED;
    }

    let post = http_method_state_5(data, len, b'P', b'O', b'S', b'T', b' ');
    if post == HTTP_PREFIX_MATCHED {
        return HTTP_PREFIX_MATCHED;
    }

    let put = http_method_state_4(data, len, b'P', b'U', b'T', b' ');
    if put == HTTP_PREFIX_MATCHED {
        return HTTP_PREFIX_MATCHED;
    }

    let head = http_method_state_5(data, len, b'H', b'E', b'A', b'D', b' ');
    if head == HTTP_PREFIX_MATCHED {
        return HTTP_PREFIX_MATCHED;
    }

    let delete = http_method_state_7(data, len, b'D', b'E', b'L', b'E', b'T', b'E', b' ');
    if delete == HTTP_PREFIX_MATCHED {
        return HTTP_PREFIX_MATCHED;
    }

    let patch = http_method_state_6(data, len, b'P', b'A', b'T', b'C', b'H', b' ');
    if patch == HTTP_PREFIX_MATCHED {
        return HTTP_PREFIX_MATCHED;
    }

    let options = http_method_state_8(data, len, b'O', b'P', b'T', b'I', b'O', b'N', b'S', b' ');
    if options == HTTP_PREFIX_MATCHED {
        return HTTP_PREFIX_MATCHED;
    }

    if get == HTTP_PREFIX_PENDING
        || post == HTTP_PREFIX_PENDING
        || put == HTTP_PREFIX_PENDING
        || head == HTTP_PREFIX_PENDING
        || delete == HTTP_PREFIX_PENDING
        || patch == HTTP_PREFIX_PENDING
        || options == HTTP_PREFIX_PENDING
    {
        HTTP_PREFIX_PENDING
    } else {
        HTTP_PREFIX_REJECT
    }
}

#[inline(always)]
unsafe fn is_http_scratch_stale(first_write_ts: u64) -> bool {
    first_write_ts == 0 || bpf_ktime_get_ns().saturating_sub(first_write_ts) > SCRATCH_TIMEOUT_NS
}

#[inline(always)]
unsafe fn copy_parse_buf_into_http_scratch(
    scratch: &mut SslHttpScratch,
    parse_buf: &SslParseBuf,
    copy_len: usize,
) -> bool {
    append_fragment_byte!(scratch, parse_buf, copy_len, 0,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 1,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 2,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 3,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 4,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 5,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 6,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 7,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 8,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 9,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 10,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 11,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 12,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 13,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 14,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 15,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 16,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 17,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 18,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 19,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 20,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 21,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 22,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 23,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 24,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 25,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 26,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 27,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 28,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 29,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 30,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 31,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 32,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 33,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 34,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 35,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 36,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 37,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 38,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 39,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 40,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 41,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 42,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 43,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 44,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 45,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 46,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 47,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 48,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 49,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 50,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 51,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 52,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 53,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 54,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 55,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 56,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 57,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 58,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 59,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 60,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 61,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 62,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 63,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 64,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 65,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 66,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 67,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 68,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 69,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 70,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 71,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 72,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 73,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 74,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 75,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 76,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 77,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 78,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 79,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 80,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 81,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 82,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 83,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 84,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 85,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 86,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 87,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 88,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 89,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 90,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 91,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 92,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 93,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 94,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 95,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 96,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 97,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 98,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 99,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 100,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 101,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 102,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 103,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 104,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 105,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 106,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 107,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 108,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 109,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 110,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 111,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 112,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 113,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 114,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 115,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 116,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 117,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 118,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 119,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 120,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 121,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 122,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 123,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 124,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 125,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 126,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 127,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 128,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 129,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 130,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 131,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 132,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 133,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 134,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 135,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 136,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 137,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 138,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 139,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 140,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 141,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 142,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 143,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 144,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 145,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 146,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 147,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 148,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 149,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 150,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 151,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 152,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 153,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 154,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 155,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 156,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 157,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 158,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 159,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 160,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 161,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 162,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 163,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 164,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 165,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 166,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 167,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 168,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 169,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 170,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 171,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 172,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 173,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 174,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 175,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 176,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 177,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 178,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 179,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 180,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 181,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 182,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 183,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 184,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 185,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 186,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 187,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 188,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 189,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 190,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 191,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 192,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 193,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 194,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 195,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 196,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 197,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 198,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 199,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 200,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 201,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 202,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 203,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 204,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 205,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 206,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 207,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 208,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 209,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 210,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 211,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 212,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 213,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 214,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 215,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 216,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 217,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 218,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 219,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 220,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 221,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 222,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 223,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 224,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 225,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 226,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 227,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 228,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 229,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 230,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 231,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 232,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 233,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 234,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 235,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 236,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 237,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 238,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 239,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 240,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 241,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 242,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 243,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 244,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 245,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 246,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 247,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 248,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 249,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 250,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 251,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 252,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 253,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 254,);
    append_fragment_byte!(scratch, parse_buf, copy_len, 255,);

    true
}

#[inline(always)]
unsafe fn http_request_is_ready(pid_tgid: u64) -> bool {
    let http_scratch = match SSL_HTTP_SCRATCH.get(&pid_tgid) {
        Some(s) => s,
        None => return false,
    };

    if is_http_scratch_stale(http_scratch.first_write_ts) {
        let _ = SSL_HTTP_SCRATCH.remove(&pid_tgid);
        return false;
    }

    (http_scratch.flags & SSL_HTTP_FLAG_MATCHED) != 0
}

#[inline(always)]
unsafe fn append_http_fragment(
    scratch: &mut SslHttpScratch,
    buf_ptr: *const u8,
    num: usize,
) -> bool {
    let start = scratch.data_len as i64;
    if !check_bounds_signed(start, 0, (SSL_HTTP_REQ_CAP - 1) as i64) {
        return false;
    }

    let capped_num = if num < SSL_HTTP_REQ_CAP {
        num as i64
    } else {
        SSL_HTTP_REQ_CAP as i64
    };
    if !check_bounds_signed(capped_num, 1, SSL_HTTP_REQ_CAP as i64) {
        return false;
    }

    let remaining = (SSL_HTTP_REQ_CAP as i64) - start;
    if !check_bounds_signed(remaining, 1, SSL_HTTP_REQ_CAP as i64) {
        return false;
    }

    // LLVM can spill and reload `start` before the helper call, so narrow the
    // final size scalar explicitly in a verifier-friendly signed form.
    let copy_len = if capped_num < remaining {
        capped_num
    } else {
        remaining
    };
    if !check_bounds_signed(copy_len, 1, SSL_HTTP_REQ_CAP as i64) {
        return false;
    }

    let end = start + copy_len;
    if !check_bounds_signed(end, 1, SSL_HTTP_REQ_CAP as i64) {
        return false;
    }

    let parse_buf = match SSL_HTTP_PARSE_BUF.get_ptr_mut(0) {
        Some(p) => &mut *p,
        None => return false,
    };

    let dst = parse_buf.data.as_mut_ptr() as *mut c_void;
    let src = buf_ptr as *const c_void;
    if gen::bpf_probe_read_user(dst, copy_len as u32, src) != 0 {
        return false;
    }

    if !copy_parse_buf_into_http_scratch(scratch, parse_buf, copy_len as usize) {
        return false;
    }

    scratch.data_len = end as u16;
    if end < SSL_HTTP_REQ_CAP as i64 {
        *scratch.req_data.as_mut_ptr().add(end as usize) = 0;
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
    let latency_ns = now.saturating_sub(http_scratch.first_write_ts);
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;

    let event = match SSL_HTTP_VALUE_BUF.get_ptr_mut(0) {
        Some(p) => &mut *p,
        None => return 0,
    };

    event.pid = pid;
    event.tid = tid;
    event.request_ts = http_scratch.first_write_ts;
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

    let now = bpf_ktime_get_ns();
    if let Some(existing) = SSL_HTTP_SCRATCH.get(&pid_tgid) {
        if is_http_scratch_stale(existing.first_write_ts) {
            let _ = SSL_HTTP_SCRATCH.remove(&pid_tgid);
        }
    }

    if let Some(scratch_ptr) = SSL_HTTP_SCRATCH.get_ptr_mut(&pid_tgid) {
        let mut remove_scratch = false;
        {
            let scratch = &mut *scratch_ptr;
            let _ = append_http_fragment(scratch, buf_ptr as *const u8, num as usize);

            if (scratch.flags & SSL_HTTP_FLAG_MATCHED) == 0 {
                match classify_http_method_prefix(&scratch.req_data, scratch.data_len as usize) {
                    HTTP_PREFIX_MATCHED => scratch.flags |= SSL_HTTP_FLAG_MATCHED,
                    HTTP_PREFIX_REJECT => remove_scratch = true,
                    _ => {
                        if scratch.data_len as usize >= SSL_HTTP_REQ_CAP {
                            remove_scratch = true;
                        }
                    }
                }
            }
        }

        if remove_scratch {
            let _ = SSL_HTTP_SCRATCH.remove(&pid_tgid);
        }

        return 0;
    }

    let scratch = match SSL_HTTP_SCRATCH_BUF.get_ptr_mut(0) {
        Some(p) => &mut *p,
        None => return 0,
    };
    scratch.first_write_ts = now;
    scratch.data_len = 0;
    scratch.flags = 0;
    scratch._pad = [0u8; 5];
    scratch.req_data[0] = 0;

    if !append_http_fragment(scratch, buf_ptr as *const u8, num as usize) {
        return 0;
    }

    match classify_http_method_prefix(&scratch.req_data, scratch.data_len as usize) {
        HTTP_PREFIX_MATCHED => scratch.flags |= SSL_HTTP_FLAG_MATCHED,
        HTTP_PREFIX_REJECT => return 0,
        _ => {}
    }

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
    if !http_request_is_ready(pid_tgid) {
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
    if !http_request_is_ready(pid_tgid) {
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
