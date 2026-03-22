use std::path::Path;

pub struct SslUprobeSpec {
    pub program_name: &'static str,
    pub symbol_name: &'static str,
}

pub const SSL_MAP_NAMES: &[&str] = &[
    "SSL_HANDSHAKE_SCRATCH",
    "SSL_CONN_TABLE",
    "SSL_SNI_TABLE",
    "SSL_SEQ",
    "SSL_HTTP_PARSE_BUF",
    "SSL_HTTP_SCRATCH",
    "SSL_HTTP_SCRATCH_BUF",
    "SSL_READ_SCRATCH",
    "SSL_HTTP_TABLE",
    "SSL_HTTP_SEQ",
    "SSL_HTTP_VALUE_BUF",
    "SSL_GLOBAL_CONFIG",
    "SSL_ERROR_TABLE",
    "SSL_ERROR_SEQ",
    "SSL_WRITE_SCRATCH",
];

pub const SSL_PROGRAM_NAMES: &[&str] = &[
    "ssl_handshake_entry",
    "ssl_handshake_return",
    "ssl_set_sni",
    "ssl_write_entry",
    "ssl_write_return",
    "ssl_read_entry",
    "ssl_read_return",
];

pub const SSL_LINK_NAMES: &[&str] = &[
    "ssl_handshake_entry_link",
    "ssl_handshake_return_link",
    "ssl_set_sni_link",
    "ssl_write_entry_link",
    "ssl_write_return_link",
    "ssl_read_entry_link",
    "ssl_read_return_link",
];

pub const SSL_UPROBE_SPECS: &[SslUprobeSpec] = &[
    SslUprobeSpec {
        program_name: "ssl_handshake_entry",
        symbol_name: "SSL_do_handshake",
    },
    SslUprobeSpec {
        program_name: "ssl_handshake_return",
        symbol_name: "SSL_do_handshake",
    },
    SslUprobeSpec {
        program_name: "ssl_set_sni",
        symbol_name: "SSL_ctrl",
    },
    SslUprobeSpec {
        program_name: "ssl_write_entry",
        symbol_name: "SSL_write",
    },
    SslUprobeSpec {
        program_name: "ssl_write_return",
        symbol_name: "SSL_write",
    },
    SslUprobeSpec {
        program_name: "ssl_read_entry",
        symbol_name: "SSL_read",
    },
    SslUprobeSpec {
        program_name: "ssl_read_return",
        symbol_name: "SSL_read",
    },
];

fn uprobe_program<'a>(
    bpf: &'a mut aya::Ebpf,
    prog_name: &str,
) -> Result<&'a mut aya::programs::UProbe, String> {
    let program = bpf
        .program_mut(prog_name)
        .ok_or_else(|| format!("{} program not found in eBPF binary", prog_name))?;

    program
        .try_into()
        .map_err(|e: aya::programs::ProgramError| format!("{} try_into: {:?}", prog_name, e))
}

pub fn is_ssl_pin_name(name: &str) -> bool {
    name.starts_with("SSL_") || name.starts_with("ssl_")
}

pub fn link_pin_path(pin_path: &str, prog_name: &str) -> String {
    format!("{}/{}_link", pin_path, prog_name)
}

pub fn pin_map_if_needed(bpf: &mut aya::Ebpf, map_name: &str, pin_path: &str) -> Result<(), String> {
    let target = format!("{}/{}", pin_path, map_name);
    if Path::new(&target).exists() {
        return Ok(());
    }

    let map = bpf
        .map_mut(map_name)
        .ok_or_else(|| format!("{} map not found in eBPF binary", map_name))?;

    map.pin(&target)
        .map_err(|e| format!("{} pin: {}", map_name, e))
}

pub fn load_uprobe_program(bpf: &mut aya::Ebpf, prog_name: &str) -> Result<(), String> {
    let probe = uprobe_program(bpf, prog_name)?;
    match probe.load() {
        Ok(()) => Ok(()),
        Err(e) => {
            let err = format!("{:?}", e);
            if err.contains("already loaded") {
                Ok(())
            } else {
                Err(format!("{} load: {}", prog_name, err))
            }
        }
    }
}

pub fn pin_program_if_needed(bpf: &mut aya::Ebpf, prog_name: &str, pin_path: &str) -> Result<(), String> {
    let target = format!("{}/{}", pin_path, prog_name);
    if Path::new(&target).exists() {
        return Ok(());
    }

    let program = bpf
        .program_mut(prog_name)
        .ok_or_else(|| format!("{} program not found in eBPF binary", prog_name))?;

    program
        .pin(&target)
        .map_err(|e| format!("{} pin: {:?}", prog_name, e))
}

pub fn attach_uprobe_if_needed(
    bpf: &mut aya::Ebpf,
    prog_name: &str,
    target: &str,
    fn_name: &str,
    pin_path: &str,
) -> Result<(), String> {
    let link_pin = link_pin_path(pin_path, prog_name);
    if Path::new(&link_pin).exists() {
        return Ok(());
    }

    let probe = uprobe_program(bpf, prog_name)?;
    match probe.load() {
        Ok(()) => {}
        Err(e) => {
            let err = format!("{:?}", e);
            if !err.contains("already loaded") {
                return Err(format!("{} load: {}", prog_name, err));
            }
        }
    }

    let link_id = probe
        .attach(Some(fn_name), 0, target, None)
        .map_err(|e| format!("{} attach: {:?}", prog_name, e))?;

    let link = probe
        .take_link(link_id)
        .map_err(|e| format!("{} take_link: {:?}", prog_name, e))?;
    let fd_link: aya::programs::links::FdLink = link
        .try_into()
        .map_err(|e: aya::programs::links::LinkError| format!("{} FdLink: {:?}", prog_name, e))?;
    fd_link
        .pin(&link_pin)
        .map_err(|e| format!("{} pin link: {:?}", prog_name, e))?;

    Ok(())
}

pub fn find_libssl() -> Option<String> {
    let candidates = [
        "/usr/lib/x86_64-linux-gnu/libssl.so.3",
        "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
        "/usr/lib64/libssl.so.3",
        "/usr/lib64/libssl.so.1.1",
        "/usr/lib/libssl.so.3",
        "/usr/lib/libssl.so.1.1",
        "/usr/lib/aarch64-linux-gnu/libssl.so.3",
        "/usr/lib/aarch64-linux-gnu/libssl.so.1.1",
    ];

    for path in &candidates {
        if Path::new(path).exists() {
            return Some(path.to_string());
        }
    }

    if let Ok(output) = std::process::Command::new("ldconfig").arg("-p").output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains("libssl.so") && line.contains("=>") {
                if let Some(path) = line.split("=>").nth(1) {
                    let path = path.trim();
                    if Path::new(path).exists() {
                        return Some(path.to_string());
                    }
                }
            }
        }
    }

    None
}
