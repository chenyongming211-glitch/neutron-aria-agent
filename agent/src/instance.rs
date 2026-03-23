use std::path::PathBuf;
use aria_core::ebpf_ops::{CRITICAL_NETWORK_MAP_NAMES, NETWORK_MAP_NAMES};

/// Represents a single tap interface with its attached XDP firewall instance.
/// On kernel 5.7+, the XDP link is pinned to bpffs so it survives agent crashes.
/// On older kernels, XDP is attached via netlink and will detach when agent exits.
pub struct FirewallInstance {
    pub iface: String,
    pub pin_path: PathBuf,
    pub state_path: PathBuf,
    /// Whether FQ qdisc (EDT) was successfully configured.
    /// If false, QoS shaping is unavailable — only policing works.
    pub edt_available: bool,
}

impl FirewallInstance {
    fn pin_runtime_maps(&self, bpf: &mut aya::Ebpf, pin_path: &str) -> Result<(), String> {
        for name in NETWORK_MAP_NAMES {
            if let Some(map) = bpf.map_mut(name) {
                if let Err(e) = map.pin(format!("{}/{}", pin_path, name)) {
                    if CRITICAL_NETWORK_MAP_NAMES.contains(name) {
                        return Err(format!("failed to pin critical map {}: {}", name, e));
                    }
                    eprintln!("[{}] Warning: failed to pin map {}: {}", self.iface, name, e);
                }
            } else if CRITICAL_NETWORK_MAP_NAMES.contains(name) {
                return Err(format!("critical map {} not found", name));
            }
        }
        Ok(())
    }

    pub fn new(iface: &str, base_pin_path: &str, base_state_path: &str) -> Self {
        Self {
            iface: iface.to_string(),
            pin_path: PathBuf::from(format!("{}/{}", base_pin_path, iface)),
            state_path: PathBuf::from(format!("{}/{}", base_state_path, iface)),
            edt_available: false,
        }
    }

    /// Attach XDP and TC egress to this interface: load eBPF, attach, pin maps + link.
    pub fn attach(&mut self, ebpf_path: &str) -> Result<(), String> {
        std::fs::create_dir_all(&self.pin_path)
            .map_err(|e| format!("Failed to create pin directory {:?}: {}", self.pin_path, e))?;
        std::fs::create_dir_all(&self.state_path)
            .map_err(|e| format!("Failed to create state directory {:?}: {}", self.state_path, e))?;

        let pin_path_str = self.pin_path.to_str().unwrap();
        let xdp_link_pin = format!("{}/xdp_link", pin_path_str);

        // Check if XDP link is already pinned (recovery from crash, kernel 5.7+ only)
        if std::path::Path::new(&xdp_link_pin).exists() {
            println!("[{}] Found pinned XDP link, recovering...", self.iface);
            self.replay_state_to_pinned_maps(ebpf_path)?;
            let mut bpf = aria_core::ebpf_ops::load_bpf_with_pin(pin_path_str, ebpf_path)?;
            self.ensure_tc_runtime(&mut bpf, pin_path_str);
            self.ensure_fq_runtime();
            println!("[{}] Recovery complete (EDT: {})", self.iface, if self.edt_available { "available" } else { "unavailable" });
            return Ok(());
        }

        // Check if XDP program is pinned but link isn't (older kernel recovery)
        let xdp_prog_pin = format!("{}/xdp_firewall", pin_path_str);
        if std::path::Path::new(&xdp_prog_pin).exists() {
            println!("[{}] Found pinned XDP program (no link pin), recovering...", self.iface);
            let mut bpf = aria_core::ebpf_ops::load_bpf_with_pin(pin_path_str, ebpf_path)?;
            let state_path_str = self.state_path.to_str().unwrap();
            aria_core::ebpf_ops::replay_state(&mut bpf, state_path_str);
            self.reattach_xdp_from_loaded(&mut bpf, &xdp_link_pin)?;
            self.ensure_tc_runtime(&mut bpf, pin_path_str);
            self.ensure_fq_runtime();
            println!("[{}] Recovery complete (EDT: {})", self.iface, if self.edt_available { "available" } else { "unavailable" });
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

        // Try to pin the XDP link (requires bpf_link, kernel 5.7+)
        // If pinning fails, continue without — XDP will detach when agent exits
        match self.try_pin_xdp_link(xdp, link_id, &xdp_link_pin) {
            Ok(()) => println!("[{}] XDP link pinned (crash-resilient)", self.iface),
            Err(e) => eprintln!("[{}] XDP link pin not supported ({}), XDP will detach on agent exit", self.iface, e),
        }

        // Attach TC egress
        if let Err(e) = self.try_attach_tc(&mut bpf, "tc_egress", aya::programs::tc::TcAttachType::Egress, pin_path_str) {
            eprintln!("[{}] Warning: TC egress attach failed: {}. Egress control disabled.", self.iface, e);
        }

        // Attach TC ingress (mirror)
        if let Err(e) = self.try_attach_tc(&mut bpf, "tc_ingress", aya::programs::tc::TcAttachType::Ingress, pin_path_str) {
            eprintln!("[{}] Warning: TC ingress attach failed: {}. Ingress mirror disabled.", self.iface, e);
        }

        // Setup FQ qdisc for QoS EDT (kernel 5.0+)
        match aria_core::ebpf_ops::setup_fq_qdisc(&self.iface) {
            Ok(()) => self.edt_available = true,
            Err(e) => {
                eprintln!("[{}] FQ qdisc not available ({}), QoS shaping disabled (policing only)", self.iface, e);
                self.edt_available = false;
            }
        }

        self.pin_runtime_maps(&mut bpf, pin_path_str)?;

        // Pin runtime programs.
        for name in &["xdp_firewall", "tc_egress", "tc_ingress"] {
            if let Some(program) = bpf.program_mut(name) {
                if let Err(e) = program.pin(format!("{}/{}", pin_path_str, name)) {
                    eprintln!("[{}] Warning: failed to pin program {}: {:?}", self.iface, name, e);
                }
            }
        }

        // Replay state from snapshot + WAL if present.
        let state_path_str = self.state_path.to_str().unwrap();
        aria_core::ebpf_ops::replay_state(&mut bpf, state_path_str);

        println!("[{}] Firewall instance active", self.iface);
        Ok(())
    }

    /// Try to pin XDP link to bpffs. Returns Ok if pinned, Err if kernel doesn't support bpf_link.
    fn try_pin_xdp_link(
        &self,
        xdp: &mut aya::programs::Xdp,
        link_id: aya::programs::xdp::XdpLinkId,
        pin_path: &str,
    ) -> Result<(), String> {
        let xdp_link = xdp.take_link(link_id)
            .map_err(|e| format!("take_link: {:?}", e))?;
        let fd_link: aya::programs::links::FdLink = xdp_link.try_into()
            .map_err(|e: aya::programs::links::LinkError| format!("FdLink convert: {:?}", e))?;
        fd_link.pin(pin_path)
            .map_err(|e| format!("pin: {:?}", e))?;
        Ok(())
    }

    /// Attach a TC program with optional link pinning (graceful fallback for older kernels).
    fn try_attach_tc(
        &self,
        bpf: &mut aya::Ebpf,
        prog_name: &str,
        attach_type: aya::programs::tc::TcAttachType,
        pin_path: &str,
    ) -> Result<(), String> {
        // Add clsact qdisc (idempotent)
        if let Err(e) = aya::programs::tc::qdisc_add_clsact(&self.iface) {
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

        let link_id = tc.attach(&self.iface, attach_type)
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
            Ok(()) => println!("TC {} attached to {} (link pinned)", dir_str, self.iface),
            Err(e) => println!("TC {} attached to {} (link pin skipped: {})", dir_str, self.iface, e),
        }

        Ok(())
    }

    fn ensure_tc_runtime(&self, bpf: &mut aya::Ebpf, pin_path: &str) {
        let tc_programs = [
            ("tc_egress", aya::programs::tc::TcAttachType::Egress, "Egress control"),
            ("tc_ingress", aya::programs::tc::TcAttachType::Ingress, "Ingress mirror"),
        ];

        for (prog_name, attach_type, purpose) in tc_programs {
            let link_pin = format!("{}/{}_link", pin_path, prog_name);
            if std::path::Path::new(&link_pin).exists() {
                continue;
            }

            if let Err(e) = self.try_attach_tc(bpf, prog_name, attach_type, pin_path) {
                eprintln!("[{}] Warning: failed to recover {}: {}", self.iface, purpose, e);
            }
        }
    }

    fn ensure_fq_runtime(&mut self) {
        let state_path_str = self.state_path.to_str().unwrap();
        let state = aria_core::wal::load_with_wal(state_path_str);
        let requires_shaping = state.qos_rules.iter().any(|rule| rule.mode == 1);

        if requires_shaping {
            match aria_core::ebpf_ops::setup_fq_qdisc(&self.iface) {
                Ok(()) => self.edt_available = true,
                Err(e) => {
                    self.edt_available = aria_core::ebpf_ops::check_fq_qdisc(&self.iface);
                    if !self.edt_available {
                        eprintln!("[{}] Warning: failed to recover FQ qdisc: {}", self.iface, e);
                    }
                }
            }
        } else {
            self.edt_available = aria_core::ebpf_ops::check_fq_qdisc(&self.iface);
        }
    }

    /// Re-attach XDP after loading the pinned map set on kernels where the link itself was not pinned.
    fn reattach_xdp_from_loaded(&self, bpf: &mut aya::Ebpf, xdp_link_pin: &str) -> Result<(), String> {
        let xdp_program = bpf
            .program_mut("xdp_firewall")
            .ok_or_else(|| format!("[{}] XDP program not found during recovery", self.iface))?;

        let xdp: &mut aya::programs::Xdp = xdp_program
            .try_into()
            .map_err(|e: aya::programs::ProgramError| format!("[{}] xdp try_into during recovery: {:?}", self.iface, e))?;

        xdp.load()
            .map_err(|e| format!("[{}] xdp.load during recovery: {:?}", self.iface, e))?;

        let link_id = xdp
            .attach(&self.iface, aya::programs::XdpFlags::default())
            .map_err(|e| format!("[{}] xdp.attach during recovery: {:?}", self.iface, e))?;

        match self.try_pin_xdp_link(xdp, link_id, xdp_link_pin) {
            Ok(()) => println!("[{}] Recovered XDP link pin", self.iface),
            Err(e) => eprintln!("[{}] Warning: XDP link re-pin skipped during recovery: {}", self.iface, e),
        }
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

        // Method 1: Remove pinned link (kernel 5.7+ with bpf_link)
        if std::path::Path::new(&xdp_link_pin).exists() {
            std::fs::remove_file(&xdp_link_pin)
                .map_err(|e| format!("[{}] Failed to remove pinned link: {}", self.iface, e))?;
            println!("[{}] XDP link unpinned (XDP detached)", self.iface);
        } else {
            // Method 2: Use ip command to detach XDP (older kernels)
            let _ = std::process::Command::new("ip")
                .args(["link", "set", "dev", &self.iface, "xdp", "off"])
                .output();
            println!("[{}] XDP detached via netlink", self.iface);
        }

        // Detach TC egress
        aria_core::ebpf_ops::detach_tc_egress(&self.iface);

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
