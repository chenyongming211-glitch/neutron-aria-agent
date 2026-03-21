use std::fs;
use std::sync::Arc;
use crate::control_plane::ControlPlane;

use aria_core::ebpf_ops::{
    detach_tc_egress, setup_fq_qdisc,
    replay_state, ALL_MAP_NAMES,
};

/// Start the system firewall (standalone mode, not tap-managed)
pub async fn system_start(
    iface: &str,
    ebpf_path: &str,
    pin_path: &str,
    state_path: &str,
    max_port_policies: u32,
    control_plane: Arc<ControlPlane>,
) -> Result<(), String> {
    fs::create_dir_all(pin_path)
        .map_err(|e| format!("Failed to create pin directory: {}", e))?;
    fs::create_dir_all(state_path)
        .map_err(|e| format!("Failed to create state directory: {}", e))?;

    // Set max_port_policies
    let sm = aria_core::state::StateManager::new(state_path);
    if let Err(e) = sm.set_max_port_policies(max_port_policies) {
        eprintln!("Warning: Failed to persist max_port_policies: {}", e);
    }

    println!("Loading eBPF from: {}", ebpf_path);
    let bpf_bytes = std::fs::read(ebpf_path).map_err(|e| format!("read ebpf: {}", e))?;
    let mut bpf = aya::EbpfLoader::new()
        .map_pin_path(pin_path)
        .load(&bpf_bytes)
        .map_err(|e| format!("load error: {:?}", e))?;

    // Attach XDP
    println!("Attaching XDP to {}...", iface);
    let xdp_program = bpf
        .program_mut("xdp_firewall")
        .ok_or("XDP program not found")?;

    let xdp: &mut aya::programs::Xdp = xdp_program
        .try_into()
        .map_err(|e: aya::programs::ProgramError| format!("try_into error: {:?}", e))?;

    xdp.load().map_err(|e| format!("xdp.load error: {:?}", e))?;

    let link_id = xdp
        .attach(iface, aya::programs::XdpFlags::default())
        .map_err(|e| format!("attach error: {:?}", e))?;

    println!("XDP attached successfully (link_id: {:?})", link_id);

    // Try to pin the XDP link (requires bpf_link, kernel 5.7+)
    let xdp_link_pin = format!("{}/xdp_link", pin_path);
    match (|| -> Result<(), String> {
        let xdp_link = xdp.take_link(link_id)
            .map_err(|e| format!("take_link: {:?}", e))?;
        let fd_link: aya::programs::links::FdLink = xdp_link.try_into()
            .map_err(|e: aya::programs::links::LinkError| format!("FdLink: {:?}", e))?;
        fd_link.pin(&xdp_link_pin)
            .map_err(|e| format!("pin: {:?}", e))?;
        Ok(())
    })() {
        Ok(()) => println!("XDP link pinned (crash-resilient)"),
        Err(e) => eprintln!("XDP link pin not supported ({}), XDP will detach on agent exit", e),
    }

    // Attach TC egress (with graceful link pin fallback)
    if let Err(e) = attach_tc_program(&mut bpf, "tc_egress", iface, aya::programs::tc::TcAttachType::Egress, pin_path) {
        eprintln!("Warning: TC egress attach failed: {}. Egress control disabled.", e);
    }

    // Attach TC ingress (mirror, with graceful link pin fallback)
    if let Err(e) = attach_tc_program(&mut bpf, "tc_ingress", iface, aya::programs::tc::TcAttachType::Ingress, pin_path) {
        eprintln!("Warning: TC ingress attach failed: {}. Ingress mirror disabled.", e);
    }

    // Setup FQ qdisc for QoS EDT
    if let Err(e) = setup_fq_qdisc(iface) {
        eprintln!("Warning: FQ qdisc setup failed: {}. QoS EDT disabled.", e);
    }

    // Pin all maps
    for name in ALL_MAP_NAMES {
        if let Some(map) = bpf.map_mut(name) {
            if let Err(e) = map.pin(format!("{}/{}", pin_path, name)) {
                eprintln!("Warning: failed to pin map {}: {}", name, e);
            }
        }
    }

    // Pin programs
    for (name, prog) in bpf.programs_mut() {
        prog.pin(format!("{}/{}", pin_path, name))
            .map_err(|e| format!("Failed to pin program {}: {:?}", name, e))?;
    }

    // Record attached iface
    let sm = aria_core::state::StateManager::new(state_path);
    if let Err(e) = sm.set_attached_iface(iface) {
        eprintln!("Warning: failed to record attached interface: {}", e);
    }

    // Replay state
    replay_state(&mut bpf, state_path);

    // Attach SSL uprobes (non-fatal: warn and continue if libssl not found)
    attach_ssl_uprobes(&mut bpf, pin_path);

    // Register with control plane
    control_plane.register_system_instance(pin_path, state_path).await;

    println!("eBPF system started successfully on {}", iface);
    Ok(())
}

/// Stop the system firewall
pub async fn system_stop(
    pin_path: &str,
    state_path: &str,
    control_plane: Arc<ControlPlane>,
) -> Result<(), String> {
    let sm = aria_core::state::StateManager::new(state_path);
    match sm.get_attached_iface() {
        Ok(Some(iface)) => {
            // Remove pinned XDP link (this detaches XDP from the interface)
            let xdp_link_pin = format!("{}/xdp_link", pin_path);
            if std::path::Path::new(&xdp_link_pin).exists() {
                if let Err(e) = fs::remove_file(&xdp_link_pin) {
                    eprintln!("Warning: failed to remove pinned XDP link: {}", e);
                } else {
                    println!("XDP link unpinned (detached from {})", iface);
                }
            } else {
                // Fallback: use ip command if pin file doesn't exist
                let output = std::process::Command::new("ip")
                    .args(["link", "set", "dev", &iface, "xdp", "off"])
                    .output();
                match output {
                    Ok(o) if o.status.success() => println!("Detached XDP from {}", iface),
                    Ok(o) => eprintln!("Warning: failed to detach XDP from {}: {}",
                        iface, String::from_utf8_lossy(&o.stderr)),
                    Err(e) => eprintln!("Warning: failed to run ip command: {}", e),
                }
            }

            // Remove pinned TC egress link
            let tc_link_pin = format!("{}/tc_egress_link", pin_path);
            if std::path::Path::new(&tc_link_pin).exists() {
                if let Err(e) = fs::remove_file(&tc_link_pin) {
                    eprintln!("Warning: failed to remove pinned TC egress link: {}", e);
                }
            }

            // Remove pinned TC ingress link
            let tc_ingress_link_pin = format!("{}/tc_ingress_link", pin_path);
            if std::path::Path::new(&tc_ingress_link_pin).exists() {
                if let Err(e) = fs::remove_file(&tc_ingress_link_pin) {
                    eprintln!("Warning: failed to remove pinned TC ingress link: {}", e);
                }
            }

            // Remove pinned SSL uprobe links
            for link_name in &["ssl_handshake_entry_link", "ssl_handshake_return_link", "ssl_set_sni_link",
                                "ssl_write_entry_link", "ssl_read_entry_link", "ssl_read_return_link"] {
                let link_pin = format!("{}/{}", pin_path, link_name);
                if std::path::Path::new(&link_pin).exists() {
                    if let Err(e) = fs::remove_file(&link_pin) {
                        eprintln!("Warning: failed to remove pinned {} link: {}", link_name, e);
                    }
                }
            }

            detach_tc_egress(&iface);

            if let Err(e) = sm.clear_attached_iface() {
                eprintln!("Warning: failed to clear attached interface record: {}", e);
            }
        }
        Ok(None) => {
            println!("No attached interface recorded, skipping XDP/TC detach");
        }
        Err(e) => {
            eprintln!("Warning: failed to read state: {}", e);
        }
    }

    if std::path::Path::new(pin_path).exists() {
        fs::remove_dir_all(pin_path)
            .map_err(|e| format!("Failed to remove pin directory: {}", e))?;
        println!("Removed pinned maps and programs from {}", pin_path);
    }

    // Unregister AFTER cleanup succeeds, so retry is possible on failure
    control_plane.unregister_instance("system").await;

    println!("eBPF system stopped");
    Ok(())
}

/// Attach a TC program with optional link pinning (graceful fallback for older kernels).
fn attach_tc_program(
    bpf: &mut aya::Ebpf,
    prog_name: &str,
    iface: &str,
    attach_type: aya::programs::tc::TcAttachType,
    pin_path: &str,
) -> Result<(), String> {
    if let Err(e) = aya::programs::tc::qdisc_add_clsact(iface) {
        let err_str = format!("{:?}", e);
        if !err_str.contains("File exists") {
            return Err(format!("qdisc_add_clsact: {}", err_str));
        }
    }

    let tc_program = bpf.program_mut(prog_name)
        .ok_or_else(|| format!("{} program not found", prog_name))?;

    let tc: &mut aya::programs::SchedClassifier = tc_program
        .try_into()
        .map_err(|e: aya::programs::ProgramError| format!("{} try_into: {:?}", prog_name, e))?;

    tc.load().map_err(|e| format!("{} load: {:?}", prog_name, e))?;

    let dir_str = match attach_type {
        aya::programs::tc::TcAttachType::Ingress => "ingress",
        aya::programs::tc::TcAttachType::Egress => "egress",
        _ => "unknown",
    };

    let link_id = tc.attach(iface, attach_type)
        .map_err(|e| format!("{} attach: {:?}", prog_name, e))?;

    // Try to pin TC link (graceful fallback)
    match (|| -> Result<(), String> {
        let tc_link = tc.take_link(link_id)
            .map_err(|e| format!("take_link: {:?}", e))?;
        let fd_link: aya::programs::links::FdLink = tc_link.try_into()
            .map_err(|e: aya::programs::links::LinkError| format!("FdLink: {:?}", e))?;
        let link_pin = format!("{}/{}_link", pin_path, prog_name);
        fd_link.pin(&link_pin)
            .map_err(|e| format!("pin: {:?}", e))?;
        Ok(())
    })() {
        Ok(()) => println!("TC {} attached to {} (link pinned)", dir_str, iface),
        Err(e) => println!("TC {} attached to {} (link pin skipped: {})", dir_str, iface, e),
    }

    Ok(())
}

/// Find libssl.so path on the system
fn find_libssl() -> Option<String> {
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
        if std::path::Path::new(path).exists() {
            return Some(path.to_string());
        }
    }

    // Fallback: try ldconfig -p
    if let Ok(output) = std::process::Command::new("ldconfig").arg("-p").output() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.contains("libssl.so") && line.contains("=>") {
                if let Some(path) = line.split("=>").nth(1) {
                    let path = path.trim();
                    if std::path::Path::new(path).exists() {
                        return Some(path.to_string());
                    }
                }
            }
        }
    }

    None
}

/// Attach SSL uprobes to libssl. Non-fatal: warns on failure.
fn attach_ssl_uprobes(bpf: &mut aya::Ebpf, pin_path: &str) {
    let libssl = match find_libssl() {
        Some(p) => p,
        None => {
            println!("libssl not found, SSL uprobes not attached");
            return;
        }
    };
    println!("Found libssl at: {}", libssl);

    if let Err(e) = attach_uprobe(bpf, "ssl_handshake_entry", &libssl, "SSL_do_handshake", pin_path) {
        eprintln!("Warning: failed to attach ssl_handshake_entry uprobe: {}", e);
        return;
    }

    if let Err(e) = attach_uprobe(bpf, "ssl_handshake_return", &libssl, "SSL_do_handshake", pin_path) {
        eprintln!("Warning: failed to attach ssl_handshake_return uretprobe: {}", e);
        return;
    }

    if let Err(e) = attach_uprobe(bpf, "ssl_set_sni", &libssl, "SSL_ctrl", pin_path) {
        eprintln!("Warning: failed to attach ssl_set_sni uprobe: {}", e);
        return;
    }

    // Phase 2: HTTP/1.1 observation
    if let Err(e) = attach_uprobe(bpf, "ssl_write_entry", &libssl, "SSL_write", pin_path) {
        eprintln!("Warning: failed to attach ssl_write_entry uprobe: {}", e);
        return;
    }

    if let Err(e) = attach_uprobe(bpf, "ssl_read_entry", &libssl, "SSL_read", pin_path) {
        eprintln!("Warning: failed to attach ssl_read_entry uprobe: {}", e);
        return;
    }

    if let Err(e) = attach_uprobe(bpf, "ssl_read_return", &libssl, "SSL_read", pin_path) {
        eprintln!("Warning: failed to attach ssl_read_return uretprobe: {}", e);
        return;
    }

    println!("SSL uprobes attached to {}", libssl);
}

/// Attach a single uprobe/uretprobe and pin its link.
fn attach_uprobe(
    bpf: &mut aya::Ebpf,
    prog_name: &str,
    target: &str,
    fn_name: &str,
    pin_path: &str,
) -> Result<(), String> {
    let program = bpf.program_mut(prog_name)
        .ok_or_else(|| format!("{} program not found in eBPF binary", prog_name))?;

    let probe: &mut aya::programs::UProbe = program
        .try_into()
        .map_err(|e: aya::programs::ProgramError| format!("{} try_into: {:?}", prog_name, e))?;

    probe.load().map_err(|e| format!("{} load: {:?}", prog_name, e))?;

    let link_id = probe.attach(Some(fn_name), 0, target, None)
        .map_err(|e| format!("{} attach: {:?}", prog_name, e))?;

    // Try to pin the link (graceful fallback)
    match (|| -> Result<(), String> {
        let link = probe.take_link(link_id)
            .map_err(|e| format!("take_link: {:?}", e))?;
        let fd_link: aya::programs::links::FdLink = link.try_into()
            .map_err(|e: aya::programs::links::LinkError| format!("FdLink: {:?}", e))?;
        let link_pin = format!("{}/{}_link", pin_path, prog_name);
        fd_link.pin(&link_pin)
            .map_err(|e| format!("pin: {:?}", e))?;
        Ok(())
    })() {
        Ok(()) => println!("  {} -> {}:{} (link pinned)", prog_name, target, fn_name),
        Err(e) => println!("  {} -> {}:{} (link pin skipped: {})", prog_name, target, fn_name, e),
    }

    Ok(())
}
