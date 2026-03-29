use crate::control_plane::ControlPlane;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{info, warn};

use aria_core::ebpf_ops::{
    cleanup_root_qdisc, critical_network_map_names, detach_tc_egress, ensure_fq_qdisc,
    replay_state, scrub_standalone_runtime_state, FqQdiscState, NETWORK_MAP_NAMES,
    TraceMapMode,
};

const FQ_QDISC_MARKER: &str = ".fq-root-qdisc-owned";

fn fq_qdisc_marker_path(state_path: &str) -> PathBuf {
    Path::new(state_path).join(FQ_QDISC_MARKER)
}

fn mark_owned_root_qdisc(state_path: &str) -> Result<(), String> {
    let marker_path = fq_qdisc_marker_path(state_path);
    fs::write(&marker_path, b"owned\n")
        .map_err(|e| format!("failed to persist FQ qdisc ownership marker: {}", e))
}

fn cleanup_owned_root_qdisc(iface: &str, state_path: &str) -> Result<(), String> {
    let marker_path = fq_qdisc_marker_path(state_path);
    if !marker_path.exists() {
        return Ok(());
    }

    cleanup_root_qdisc(iface)
        .map_err(|e| format!("failed to clean owned root qdisc on {}: {}", iface, e))?;
    fs::remove_file(&marker_path).map_err(|e| {
        format!(
            "failed to remove FQ qdisc ownership marker {}: {}",
            marker_path.display(),
            e
        )
    })?;
    Ok(())
}

fn cleanup_failed_start(iface: &str, pin_path: &str, state_path: &str) {
    let _ = std::process::Command::new("ip")
        .args(["link", "set", "dev", iface, "xdp", "off"])
        .output();
    detach_tc_egress(iface);
    if let Err(e) = cleanup_owned_root_qdisc(iface, state_path) {
        warn!(iface = %iface, error = %e, "failed to clean owned root qdisc during start rollback");
    }
    let _ = fs::remove_dir_all(pin_path);
}

fn pin_runtime_maps(
    bpf: &mut aya::Ebpf,
    pin_path: &str,
    trace_map_mode: TraceMapMode,
) -> Result<(), String> {
    let critical_map_names = critical_network_map_names(trace_map_mode);
    for name in NETWORK_MAP_NAMES {
        if let Some(map) = bpf.map_mut(name) {
            if let Err(e) = map.pin(format!("{}/{}", pin_path, name)) {
                if critical_map_names.contains(name) {
                    return Err(format!("failed to pin critical map {}: {}", name, e));
                }
                warn!(map = %name, error = %e, "failed to pin runtime map");
            }
        } else if critical_map_names.contains(name) {
            return Err(format!("critical map {} not found", name));
        }
    }
    Ok(())
}

fn pin_runtime_programs(bpf: &mut aya::Ebpf, pin_path: &str) -> Result<(), String> {
    for name in &["xdp_firewall", "tc_egress", "tc_ingress"] {
        let program = match bpf.program_mut(name) {
            Some(program) => program,
            None => return Err(format!("Program {} not found", name)),
        };
        if let Err(e) = program.pin(format!("{}/{}", pin_path, name)) {
            return Err(format!("Failed to pin program {}: {:?}", name, e));
        }
    }
    Ok(())
}

fn attach_xdp_program(bpf: &mut aya::Ebpf, iface: &str, pin_path: &str) -> Result<(), String> {
    info!(iface = %iface, "attaching XDP");
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

    info!(iface = %iface, link_id = ?link_id, "XDP attached successfully");

    let xdp_link_pin = format!("{}/xdp_link", pin_path);
    match (|| -> Result<(), String> {
        let xdp_link = xdp
            .take_link(link_id)
            .map_err(|e| format!("take_link: {:?}", e))?;
        let fd_link: aya::programs::links::FdLink = xdp_link
            .try_into()
            .map_err(|e: aya::programs::links::LinkError| format!("FdLink: {:?}", e))?;
        fd_link
            .pin(&xdp_link_pin)
            .map_err(|e| format!("pin: {:?}", e))?;
        Ok(())
    })() {
        Ok(()) => info!(iface = %iface, "XDP link pinned"),
        Err(e) => {
            warn!(iface = %iface, error = %e, "XDP link pin not supported; XDP will detach on agent exit")
        }
    }

    Ok(())
}

/// Start the system firewall (standalone mode, not tap-managed)
pub async fn system_start(
    iface: &str,
    ebpf_path: &str,
    pin_path: &str,
    state_path: &str,
    max_port_policies: u32,
    control_plane: Arc<ControlPlane>,
) -> Result<(), String> {
    fs::create_dir_all(pin_path).map_err(|e| format!("Failed to create pin directory: {}", e))?;
    fs::create_dir_all(state_path)
        .map_err(|e| format!("Failed to create state directory: {}", e))?;

    // Set max_port_policies
    let sm = aria_core::state::StateManager::new(state_path);
    if let Err(e) = sm.set_max_port_policies(max_port_policies) {
        warn!(iface = %iface, error = %e, "failed to persist max_port_policies");
    }

    info!(iface = %iface, ebpf_path = %ebpf_path, "loading eBPF for system instance");
    let bpf_bytes = std::fs::read(ebpf_path).map_err(|e| format!("read ebpf: {}", e))?;
    let mut bpf = aya::EbpfLoader::new()
        .map_pin_path(pin_path)
        .load(&bpf_bytes)
        .map_err(|e| format!("load error: {:?}", e))?;
    let trace_map_mode = control_plane.trace_map_mode();

    // Pin all maps before attaching any programs so replay can rebuild runtime state
    // before packets hit the dataplane.
    if let Err(e) = pin_runtime_maps(&mut bpf, pin_path, trace_map_mode) {
        cleanup_failed_start(iface, pin_path, state_path);
        return Err(e);
    }

    let sm = aria_core::state::StateManager::new(state_path);
    match sm.get_tap_id() {
        Ok(tap_id) if tap_id != aria_core::common::TAP_ID_UNASSIGNED => {
            sm.set_tap_id(aria_core::common::TAP_ID_UNASSIGNED)
                .map_err(|e| {
                    cleanup_failed_start(iface, pin_path, state_path);
                    format!("failed to reset system tap_id before replay: {}", e)
                })?;
            info!(iface = %iface, stale_tap_id = tap_id, "reset stale system tap_id before replay");
        }
        Ok(_) => {}
        Err(e) => {
            cleanup_failed_start(iface, pin_path, state_path);
            return Err(format!("failed to read system tap_id before replay: {}", e));
        }
    }

    if let Err(e) = scrub_standalone_runtime_state(pin_path) {
        cleanup_failed_start(iface, pin_path, state_path);
        return Err(format!("failed to scrub standalone runtime state before replay: {}", e));
    }

    // Replay state
    if let Err(e) = replay_state(&mut bpf, state_path) {
        cleanup_failed_start(iface, pin_path, state_path);
        return Err(format!("failed to replay state: {}", e));
    }

    match ensure_fq_qdisc(iface) {
        Ok(FqQdiscState::InstalledNow) => {
            if let Err(e) = mark_owned_root_qdisc(state_path) {
                if let Err(cleanup_err) = cleanup_root_qdisc(iface) {
                    warn!(iface = %iface, error = %cleanup_err, "failed to roll back root qdisc after marker write failure");
                }
                cleanup_failed_start(iface, pin_path, state_path);
                return Err(e);
            }
        }
        Ok(FqQdiscState::AlreadyPresent) => {}
        Err(e) => {
            warn!(iface = %iface, error = %e, "FQ qdisc setup failed; QoS EDT disabled");
        }
    }

    if let Err(e) = attach_xdp_program(&mut bpf, iface, pin_path) {
        cleanup_failed_start(iface, pin_path, state_path);
        return Err(e);
    }

    if let Err(e) = attach_tc_program(
        &mut bpf,
        "tc_egress",
        iface,
        aya::programs::tc::TcAttachType::Egress,
        pin_path,
    ) {
        warn!(iface = %iface, error = %e, "TC egress attach failed; egress control disabled");
    }

    if let Err(e) = attach_tc_program(
        &mut bpf,
        "tc_ingress",
        iface,
        aya::programs::tc::TcAttachType::Ingress,
        pin_path,
    ) {
        warn!(iface = %iface, error = %e, "TC ingress attach failed; ingress mirror disabled");
    }

    if let Err(e) = pin_runtime_programs(&mut bpf, pin_path) {
        cleanup_failed_start(iface, pin_path, state_path);
        return Err(e);
    }

    if let Err(e) = sm.set_attached_iface(iface) {
        warn!(iface = %iface, error = %e, "failed to record attached interface");
    }

    // Register with control plane
    if let Err(e) = control_plane
        .register_system_instance(pin_path, state_path)
        .await
    {
        if let Err(clear_err) = sm.clear_attached_iface() {
            warn!(iface = %iface, error = %clear_err, "failed to clear attached interface record after register failure");
        }
        cleanup_failed_start(iface, pin_path, state_path);
        return Err(format!("control-plane register failed: {}", e));
    }

    info!(iface = %iface, "system firewall started successfully");
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
                    warn!(iface = %iface, error = %e, "failed to remove pinned XDP link");
                } else {
                    info!(iface = %iface, "XDP link unpinned");
                }
            } else {
                // Fallback: use ip command if pin file doesn't exist
                let output = std::process::Command::new("ip")
                    .args(["link", "set", "dev", &iface, "xdp", "off"])
                    .output();
                match output {
                    Ok(o) if o.status.success() => {
                        info!(iface = %iface, "detached XDP via ip link")
                    }
                    Ok(o) => warn!(
                        iface = %iface,
                        stderr = %String::from_utf8_lossy(&o.stderr),
                        "failed to detach XDP"
                    ),
                    Err(e) => warn!(iface = %iface, error = %e, "failed to run ip command"),
                }
            }

            // Remove pinned TC egress link
            let tc_link_pin = format!("{}/tc_egress_link", pin_path);
            if std::path::Path::new(&tc_link_pin).exists() {
                if let Err(e) = fs::remove_file(&tc_link_pin) {
                    warn!(iface = %iface, error = %e, "failed to remove pinned TC egress link");
                }
            }

            // Remove pinned TC ingress link
            let tc_ingress_link_pin = format!("{}/tc_ingress_link", pin_path);
            if std::path::Path::new(&tc_ingress_link_pin).exists() {
                if let Err(e) = fs::remove_file(&tc_ingress_link_pin) {
                    warn!(iface = %iface, error = %e, "failed to remove pinned TC ingress link");
                }
            }

            detach_tc_egress(&iface);
            if let Err(e) = cleanup_owned_root_qdisc(&iface, state_path) {
                warn!(iface = %iface, error = %e, "failed to clean owned root qdisc");
            }

            if let Err(e) = sm.clear_attached_iface() {
                warn!(iface = %iface, error = %e, "failed to clear attached interface record");
            }
        }
        Ok(None) => {
            info!("no attached interface recorded; skipping XDP/TC detach");
        }
        Err(e) => {
            warn!(error = %e, "failed to read system state");
        }
    }

    if std::path::Path::new(pin_path).exists() {
        fs::remove_dir_all(pin_path)
            .map_err(|e| format!("Failed to remove pin directory: {}", e))?;
        info!(pin_path = %pin_path, "removed pinned maps and programs");
    }

    // Unregister AFTER cleanup succeeds, so retry is possible on failure
    control_plane.unregister_instance("system").await;

    info!("system firewall stopped");
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

    let tc_program = bpf
        .program_mut(prog_name)
        .ok_or_else(|| format!("{} program not found", prog_name))?;

    let tc: &mut aya::programs::SchedClassifier = tc_program
        .try_into()
        .map_err(|e: aya::programs::ProgramError| format!("{} try_into: {:?}", prog_name, e))?;

    tc.load()
        .map_err(|e| format!("{} load: {:?}", prog_name, e))?;

    let dir_str = match attach_type {
        aya::programs::tc::TcAttachType::Ingress => "ingress",
        aya::programs::tc::TcAttachType::Egress => "egress",
        _ => "unknown",
    };

    let link_id = tc
        .attach(iface, attach_type)
        .map_err(|e| format!("{} attach: {:?}", prog_name, e))?;

    // Try to pin TC link (graceful fallback)
    match (|| -> Result<(), String> {
        let tc_link = tc
            .take_link(link_id)
            .map_err(|e| format!("take_link: {:?}", e))?;
        let fd_link: aya::programs::links::FdLink = tc_link
            .try_into()
            .map_err(|e: aya::programs::links::LinkError| format!("FdLink: {:?}", e))?;
        let link_pin = format!("{}/{}_link", pin_path, prog_name);
        fd_link
            .pin(&link_pin)
            .map_err(|e| format!("pin: {:?}", e))?;
        Ok(())
    })() {
        Ok(()) => {
            info!(iface = %iface, direction = %dir_str, "TC program attached with pinned link")
        }
        Err(e) => {
            info!(iface = %iface, direction = %dir_str, error = %e, "TC program attached without link pin")
        }
    }

    Ok(())
}
