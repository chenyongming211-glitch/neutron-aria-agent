use std::path::PathBuf;
use aria_core::ebpf_ops::ALL_MAP_NAMES;

/// Represents a single tap interface with its attached XDP firewall instance.
/// The XDP link is pinned to bpffs so it survives agent crashes.
pub struct FirewallInstance {
    pub iface: String,
    pub pin_path: PathBuf,
    pub state_path: PathBuf,
}

impl FirewallInstance {
    pub fn new(iface: &str, base_pin_path: &str, base_state_path: &str) -> Self {
        Self {
            iface: iface.to_string(),
            pin_path: PathBuf::from(format!("{}/{}", base_pin_path, iface)),
            state_path: PathBuf::from(format!("{}/{}", base_state_path, iface)),
        }
    }

    /// Attach XDP and TC egress to this interface: load eBPF, attach, pin maps + link.
    pub fn attach(&self, ebpf_path: &str) -> Result<(), String> {
        std::fs::create_dir_all(&self.pin_path)
            .map_err(|e| format!("Failed to create pin directory {:?}: {}", self.pin_path, e))?;
        std::fs::create_dir_all(&self.state_path)
            .map_err(|e| format!("Failed to create state directory {:?}: {}", self.state_path, e))?;

        let pin_path_str = self.pin_path.to_str().unwrap();
        let xdp_link_pin = format!("{}/xdp_link", pin_path_str);

        // Check if XDP link is already pinned (recovery from crash)
        if std::path::Path::new(&xdp_link_pin).exists() {
            println!("[{}] Found pinned XDP link, recovering...", self.iface);
            self.replay_state_to_pinned_maps(ebpf_path)?;
            println!("[{}] Recovery complete", self.iface);
            return Ok(());
        }

        println!("[{}] Loading eBPF from: {}", self.iface, ebpf_path);
        let bpf_bytes = std::fs::read(ebpf_path)
            .map_err(|e| format!("read ebpf: {}", e))?;
        let mut bpf = aya::EbpfLoader::new()
            .map_pin_path(pin_path_str)
            .load(&bpf_bytes)
            .map_err(|e| format!("[{}] load error: {:?}", self.iface, e))?;

        // Attach XDP
        let xdp_program = bpf
            .program_mut("xdp_firewall")
            .ok_or_else(|| format!("[{}] XDP program not found", self.iface))?;

        let xdp: &mut aya::programs::Xdp = xdp_program
            .try_into()
            .map_err(|e: aya::programs::ProgramError| format!("[{}] try_into error: {:?}", self.iface, e))?;

        xdp.load()
            .map_err(|e| format!("[{}] xdp.load error: {:?}", self.iface, e))?;

        let link_id = xdp
            .attach(&self.iface, aya::programs::XdpFlags::default())
            .map_err(|e| format!("[{}] attach error: {:?}", self.iface, e))?;

        println!("[{}] XDP attached (link_id: {:?})", self.iface, link_id);

        // Pin the XDP link so it survives agent crashes
        let xdp_link = xdp.take_link(link_id)
            .map_err(|e| format!("[{}] take_link error: {:?}", self.iface, e))?;
        let fd_link: aya::programs::links::FdLink = xdp_link.try_into()
            .map_err(|e: aya::programs::links::LinkError| format!("[{}] convert to FdLink error: {:?}", self.iface, e))?;
        let _pinned_link = fd_link.pin(&xdp_link_pin)
            .map_err(|e| format!("[{}] pin link error: {:?}", self.iface, e))?;

        // Attach TC egress
        if let Err(e) = aria_core::ebpf_ops::attach_tc_egress(&mut bpf, &self.iface, pin_path_str) {
            eprintln!("[{}] Warning: TC egress attach failed: {}. Egress control disabled.", self.iface, e);
        }

        // Attach TC ingress (mirror)
        if let Err(e) = aria_core::ebpf_ops::attach_tc_ingress(&mut bpf, &self.iface, pin_path_str) {
            eprintln!("[{}] Warning: TC ingress attach failed: {}. Ingress mirror disabled.", self.iface, e);
        }

        // Setup FQ qdisc for QoS EDT
        if let Err(e) = aria_core::ebpf_ops::setup_fq_qdisc(&self.iface) {
            eprintln!("[{}] Warning: FQ qdisc setup failed: {}. QoS EDT disabled.", self.iface, e);
        }

        // Pin all maps (including new CT, stats, QoS maps)
        for name in ALL_MAP_NAMES {
            if let Some(map) = bpf.map_mut(name) {
                if let Err(e) = map.pin(format!("{}/{}", pin_path_str, name)) {
                    eprintln!("[{}] Warning: failed to pin map {}: {}", self.iface, name, e);
                }
            }
        }

        // Pin programs
        for (name, prog) in bpf.programs_mut() {
            if let Err(e) = prog.pin(format!("{}/{}", pin_path_str, name)) {
                eprintln!("[{}] Warning: failed to pin program {}: {:?}", self.iface, name, e);
            }
        }

        // Replay state from state.json if exists
        let state_path_str = self.state_path.to_str().unwrap();
        aria_core::ebpf_ops::replay_state(&mut bpf, state_path_str);

        println!("[{}] Firewall instance active", self.iface);
        Ok(())
    }

    /// Replay state to already-pinned maps (used during crash recovery)
    fn replay_state_to_pinned_maps(&self, ebpf_path: &str) -> Result<(), String> {
        let pin_path_str = self.pin_path.to_str().unwrap();
        let state_path_str = self.state_path.to_str().unwrap();

        let mut bpf = aria_core::ebpf_ops::load_bpf_with_pin(pin_path_str, ebpf_path)?;
        aria_core::ebpf_ops::replay_state(&mut bpf, state_path_str);
        Ok(())
    }

    /// Detach XDP and TC: unpin link (causes XDP detach), clean up pin directory.
    pub fn detach(&self) -> Result<(), String> {
        let pin_path_str = self.pin_path.to_str().unwrap();
        let xdp_link_pin = format!("{}/xdp_link", pin_path_str);

        // Removing the pinned link file causes the kernel to detach XDP
        if std::path::Path::new(&xdp_link_pin).exists() {
            std::fs::remove_file(&xdp_link_pin)
                .map_err(|e| format!("[{}] Failed to remove pinned link: {}", self.iface, e))?;
            println!("[{}] XDP link unpinned (XDP detached)", self.iface);
        }

        // Detach TC egress
        aria_core::ebpf_ops::detach_tc_egress(&self.iface);

        // Note: TC ingress link is cleaned up when pin directory is removed

        // Clean up all pinned maps and programs
        if self.pin_path.exists() {
            std::fs::remove_dir_all(&self.pin_path)
                .map_err(|e| format!("[{}] Failed to remove pin directory: {}", self.iface, e))?;
            println!("[{}] Pin directory cleaned", self.iface);
        }

        println!("[{}] Firewall instance detached", self.iface);
        Ok(())
    }
}
