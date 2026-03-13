use std::fs;
use tokio::signal::unix::{signal, SignalKind};

// Re-export shared functions from aria-core for use by main.rs
pub use aria_core::ebpf_ops::{
    add_network, delete_network, add_policy, delete_policy,
    delete_port_set, show_stats, replay_state, ALL_MAP_NAMES,
    attach_tc_egress, detach_tc_egress, setup_fq_qdisc,
};

pub async fn system_start(iface: &str, ebpf_path: &str, pin_path: &str, _max_port_policies: u32, state_path: &str) -> Result<(), String> {
    fs::create_dir_all(pin_path)
        .map_err(|e| format!("Failed to create pin directory: {}", e))?;

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

    let _link = xdp.take_link(link_id)
        .map_err(|e| format!("take_link error: {:?}", e))?;

    // Attach TC egress
    if let Err(e) = attach_tc_egress(&mut bpf, iface) {
        eprintln!("Warning: TC egress attach failed: {}. Egress control disabled.", e);
    }

    // Setup FQ qdisc for QoS EDT
    if let Err(e) = setup_fq_qdisc(iface) {
        eprintln!("Warning: FQ qdisc setup failed: {}. QoS EDT disabled.", e);
    }

    // Pin all maps (including new CT, stats, QoS maps)
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

    println!("eBPF system started successfully");
    println!("Pin path: {}", pin_path);

    // 记录挂载的网卡名到状态文件
    let state_manager = aria_core::state::StateManager::new(state_path);
    if let Err(e) = state_manager.set_attached_iface(iface) {
        eprintln!("Warning: failed to record attached interface: {}", e);
    }

    // 从 state.json 重放状态到内核 maps
    replay_state(&mut bpf, state_path);

    println!("Firewall attached to {}. Waiting for stop signal...", iface);

    // 监听 SIGTERM 和 SIGINT 信号，实现优雅退出
    let mut term = signal(SignalKind::terminate())
        .map_err(|e| format!("failed to create signal handler: {}", e))?;
    let mut int = signal(SignalKind::interrupt())
        .map_err(|e| format!("failed to create signal handler: {}", e))?;

    tokio::select! {
        _ = term.recv() => println!("Received SIGTERM"),
        _ = int.recv() => println!("Received SIGINT"),
    }

    println!("Shutting down firewall, XDP detached automatically.");
    Ok(())
}

pub async fn system_stop(pin_path: &str, state_path: &str) -> Result<(), String> {
    let state_manager = aria_core::state::StateManager::new(state_path);
    match state_manager.get_attached_iface() {
        Ok(Some(iface)) => {
            // Detach XDP
            let output = std::process::Command::new("ip")
                .args(["link", "set", "dev", &iface, "xdp", "off"])
                .output();
            match output {
                Ok(o) if o.status.success() => println!("Detached XDP from {}", iface),
                Ok(o) => eprintln!("Warning: failed to detach XDP from {}: {}",
                    iface, String::from_utf8_lossy(&o.stderr)),
                Err(e) => eprintln!("Warning: failed to run ip command: {}", e),
            }

            // Detach TC egress
            detach_tc_egress(&iface);

            if let Err(e) = state_manager.clear_attached_iface() {
                eprintln!("Warning: failed to clear attached interface record: {}", e);
            }
        }
        Ok(None) => {
            println!("No attached interface recorded, skipping XDP/TC detach");
        }
        Err(e) => {
            eprintln!("Warning: failed to read state: {}", e);
            println!("Skipping XDP/TC detach (could not determine attached interface)");
        }
    }

    if std::path::Path::new(pin_path).exists() {
        fs::remove_dir_all(pin_path)
            .map_err(|e| format!("Failed to remove pin directory: {}", e))?;
        println!("Removed pinned maps and programs from {}", pin_path);
    }
    println!("eBPF system stopped");
    Ok(())
}
