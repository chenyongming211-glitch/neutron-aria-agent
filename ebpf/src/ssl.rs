use aya_ebpf::helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_user_str_bytes};
use aya_ebpf::programs::ProbeContext;

use crate::maps::{
    FIREWALL_CONFIG, SSL_HANDSHAKE_SCRATCH, SSL_CONN_TABLE, SSL_SNI_TABLE, SSL_SEQ,
    SslScratch, SslConnValue,
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

pub unsafe fn ssl_handshake_return_impl(_ctx: &ProbeContext) -> u32 {
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
