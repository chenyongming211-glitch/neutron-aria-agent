use std::fs;
use std::sync::Arc;
use crate::control_plane::ControlPlane;

use aria_core::ebpf_ops::{
    attach_tc_egress, detach_tc_egress, setup_fq_qdisc,
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

    // Pin the XDP link so it survives for the lifetime of the process
    let xdp_link = xdp.take_link(link_id)
        .map_err(|e| format!("take_link error: {:?}", e))?;
    let xdp_link_pin = format!("{}/xdp_link", pin_path);
    let fd_link: aya::programs::links::FdLink = xdp_link.try_into()
        .map_err(|e: aya::programs::links::LinkError| format!("convert to FdLink error: {:?}", e))?;
    let _pinned_link = fd_link.pin(&xdp_link_pin)
        .map_err(|e| format!("pin link error: {:?}", e))?;

    // Attach TC egress
    if let Err(e) = attach_tc_egress(&mut bpf, iface, pin_path) {
        eprintln!("Warning: TC egress attach failed: {}. Egress control disabled.", e);
    }

    // Attach TC ingress (mirror)
    if let Err(e) = aria_core::ebpf_ops::attach_tc_ingress(&mut bpf, iface, pin_path) {
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
