use std::path::PathBuf;
use aria_core::ebpf_ops::{CRITICAL_NETWORK_MAP_NAMES, NETWORK_MAP_NAMES};
use tracing::{info, warn};

/// Represents a single tap interface with its attached XDP firewall instance.
/// On kernel 5.7+, the XDP link is pinned to bpffs so it survives agent crashes.
/// On older kernels, XDP is attached via netlink and will detach when agent exits.
pub struct FirewallInstance {
    pub iface: String,
    pub pin_path: PathBuf,
    pub state_path: PathBuf,
    pub shared_runtime: bool,
    /// Whether FQ qdisc (EDT) was successfully configured.
    /// If false, QoS shaping is unavailable — only policing works.
    pub edt_available: bool,
}

impl FirewallInstance {
    fn rollback_partial_attach(
        &self,
        stage: &str,
        err: String,
        remove_pin_path: bool,
    ) -> Result<(), String> {
        if let Err(cleanup_err) = self.detach_with_cleanup(remove_pin_path) {
            return Err(format!(
                "{} failed: {}; rollback also failed: {}",
                stage, err, cleanup_err
            ));
        }
        Err(format!("{} failed: {}", stage, err))
    }

    fn xdp_link_pin_path(&self) -> String {
        if self.shared_runtime {
            format!("{}/{}_xdp_link", self.pin_path.display(), self.iface)
        } else {
            format!("{}/xdp_link", self.pin_path.display())
        }
    }

    fn tc_link_pin_path(&self, prog_name: &str) -> String {
        if self.shared_runtime {
            format!("{}/{}_{}_link", self.pin_path.display(), self.iface, prog_name)
        } else {
            format!("{}/{}_link", self.pin_path.display(), prog_name)
        }
    }

    fn pin_runtime_maps(&self, bpf: &mut aya::Ebpf, pin_path: &str) -> Result<(), String> {
        for name in NETWORK_MAP_NAMES {
            if let Some(map) = bpf.map_mut(name) {
                let target = format!("{}/{}", pin_path, name);
                if std::path::Path::new(&target).exists() {
                    continue;
                }
                if let Err(e) = map.pin(target) {
                    if CRITICAL_NETWORK_MAP_NAMES.contains(name) {
                        return Err(format!("failed to pin critical map {}: {}", name, e));
                    }
                    warn!(instance = %self.iface, map = %name, error = %e, "failed to pin runtime map");
                }
            } else if CRITICAL_NETWORK_MAP_NAMES.contains(name) {
                return Err(format!("critical map {} not found", name));
            }
        }
        Ok(())
    }

    pub fn new(iface: &str, pin_path: PathBuf, state_path: PathBuf, shared_runtime: bool) -> Self {
        Self {
            iface: iface.to_string(),
            pin_path,
            state_path,
            shared_runtime,
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
        let xdp_link_pin = self.xdp_link_pin_path();

        // Check if XDP link is already pinned (recovery from crash, kernel 5.7+ only)
        if std::path::Path::new(&xdp_link_pin).exists() {
            info!(instance = %self.iface, "found pinned XDP link; recovering");
            self.ensure_tc_runtime();
            self.ensure_fq_runtime();
            info!(instance = %self.iface, edt_available = self.edt_available, "recovery complete from pinned XDP link");
            return Ok(());
        }

        // If the shared runtime is already pinned, only this interface link needs to be attached.
        let xdp_prog_pin = format!("{}/xdp_firewall", pin_path_str);
        if std::path::Path::new(&xdp_prog_pin).exists() {
            info!(instance = %self.iface, "found pinned XDP runtime; attaching interface link");
            self.reattach_xdp_from_pin(&xdp_prog_pin, &xdp_link_pin)?;
            self.ensure_tc_runtime();
            self.ensure_fq_runtime();
            info!(instance = %self.iface, edt_available = self.edt_available, "interface link attached from pinned runtime");
            return Ok(());
        }

        info!(instance = %self.iface, ebpf_path = %ebpf_path, "loading eBPF");
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

        info!(instance = %self.iface, link_id = ?link_id, "XDP attached");

        // Try to pin the XDP link (requires bpf_link, kernel 5.7+)
        // If pinning fails, continue without — XDP will detach when agent exits
        match self.try_pin_xdp_link(xdp, link_id, &xdp_link_pin) {
            Ok(()) => info!(instance = %self.iface, "XDP link pinned"),
            Err(e) => warn!(instance = %self.iface, error = %e, "XDP link pin not supported; XDP will detach on agent exit"),
        }

        // Attach TC egress
        if let Err(e) = self.try_attach_tc(&mut bpf, "tc_egress", aya::programs::tc::TcAttachType::Egress) {
            warn!(instance = %self.iface, error = %e, "TC egress attach failed; egress control disabled");
        }

        // Attach TC ingress (mirror)
        if let Err(e) = self.try_attach_tc(&mut bpf, "tc_ingress", aya::programs::tc::TcAttachType::Ingress) {
            warn!(instance = %self.iface, error = %e, "TC ingress attach failed; ingress mirror disabled");
        }

        // Setup FQ qdisc for QoS EDT (kernel 5.0+)
        match aria_core::ebpf_ops::setup_fq_qdisc(&self.iface) {
            Ok(()) => self.edt_available = true,
            Err(e) => {
                warn!(instance = %self.iface, error = %e, "FQ qdisc not available; QoS shaping disabled");
                self.edt_available = false;
            }
        }

        if let Err(e) = self.pin_runtime_maps(&mut bpf, pin_path_str) {
            return self.rollback_partial_attach("pin runtime maps", e, true);
        }

        // Pin runtime programs.
        for name in &["xdp_firewall", "tc_egress", "tc_ingress"] {
            if let Some(program) = bpf.program_mut(name) {
                let target = format!("{}/{}", pin_path_str, name);
                if std::path::Path::new(&target).exists() {
                    continue;
                }
                if let Err(e) = program.pin(target) {
                    warn!(instance = %self.iface, program = %name, error = ?e, "failed to pin runtime program");
                }
            }
        }

        info!(instance = %self.iface, "firewall instance active");
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
            let link_pin = self.tc_link_pin_path(prog_name);
            fd_link.pin(&link_pin)
                .map_err(|e| format!("pin: {:?}", e))?;
            Ok(())
        })() {
            Ok(()) => info!(instance = %self.iface, direction = %dir_str, "TC program attached with pinned link"),
            Err(e) => info!(instance = %self.iface, direction = %dir_str, error = %e, "TC program attached without link pin"),
        }

        Ok(())
    }

    fn tc_prog_pin_path(&self, prog_name: &str) -> String {
        format!("{}/{}", self.pin_path.display(), prog_name)
    }

    fn ensure_tc_runtime(&self) {
        let tc_programs = [
            ("tc_egress", aya::programs::tc::TcAttachType::Egress, "Egress control"),
            ("tc_ingress", aya::programs::tc::TcAttachType::Ingress, "Ingress mirror"),
        ];

        for (prog_name, attach_type, purpose) in tc_programs {
            let link_pin = self.tc_link_pin_path(prog_name);
            if std::path::Path::new(&link_pin).exists() {
                continue;
            }

            let prog_pin = self.tc_prog_pin_path(prog_name);
            if !std::path::Path::new(&prog_pin).exists() {
                warn!(
                    instance = %self.iface,
                    purpose = %purpose,
                    prog_pin = %prog_pin,
                    "pinned TC program missing during recovery"
                );
                continue;
            }

            if let Err(e) = self.try_attach_tc_from_pin(prog_name, &prog_pin, attach_type) {
                warn!(instance = %self.iface, purpose = %purpose, error = %e, "failed to recover TC runtime");
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
                        warn!(instance = %self.iface, error = %e, "failed to recover FQ qdisc");
                    }
                }
            }
        } else {
            self.edt_available = aria_core::ebpf_ops::check_fq_qdisc(&self.iface);
        }
    }

    /// Re-attach XDP from the already pinned shared runtime without loading a new eBPF object.
    fn reattach_xdp_from_pin(&self, prog_pin: &str, xdp_link_pin: &str) -> Result<(), String> {
        let mut xdp = aya::programs::Xdp::from_pin(
            prog_pin,
            aya_obj::programs::XdpAttachType::Interface,
        )
            .map_err(|e| format!("[{}] XDP from_pin during recovery: {:?}", self.iface, e))?;

        let link_id = xdp
            .attach(&self.iface, aya::programs::XdpFlags::default())
            .map_err(|e| format!("[{}] xdp.attach during recovery: {:?}", self.iface, e))?;

        match self.try_pin_xdp_link(&mut xdp, link_id, xdp_link_pin) {
            Ok(()) => info!(instance = %self.iface, "recovered XDP link pin"),
            Err(e) => warn!(instance = %self.iface, error = %e, "XDP link re-pin skipped during recovery"),
        }
        Ok(())
    }

    fn try_attach_tc_from_pin(
        &self,
        prog_name: &str,
        prog_pin: &str,
        attach_type: aya::programs::tc::TcAttachType,
    ) -> Result<(), String> {
        if let Err(e) = aya::programs::tc::qdisc_add_clsact(&self.iface) {
            let err_str = format!("{:?}", e);
            if !err_str.contains("File exists") {
                return Err(format!("qdisc_add_clsact: {}", err_str));
            }
        }

        let mut tc = aya::programs::SchedClassifier::from_pin(prog_pin)
            .map_err(|e| format!("{} from_pin: {:?}", prog_name, e))?;

        let dir_str = match attach_type {
            aya::programs::tc::TcAttachType::Ingress => "ingress",
            aya::programs::tc::TcAttachType::Egress => "egress",
            _ => "unknown",
        };

        let link_id = tc.attach(&self.iface, attach_type)
            .map_err(|e| format!("{} attach from pin: {:?}", prog_name, e))?;

        match (|| -> Result<(), String> {
            let tc_link = tc.take_link(link_id)
                .map_err(|e| format!("take_link: {:?}", e))?;
            let fd_link: aya::programs::links::FdLink = tc_link.try_into()
                .map_err(|e: aya::programs::links::LinkError| format!("FdLink: {:?}", e))?;
            let link_pin = self.tc_link_pin_path(prog_name);
            fd_link.pin(&link_pin)
                .map_err(|e| format!("pin: {:?}", e))?;
            Ok(())
        })() {
            Ok(()) => info!(instance = %self.iface, direction = %dir_str, "TC program reattached from pinned runtime"),
            Err(e) => info!(instance = %self.iface, direction = %dir_str, error = %e, "TC program reattached without link pin"),
        }

        Ok(())
    }

    /// Replay state to already-pinned maps.
    pub fn replay_state(&self, _ebpf_path: &str) -> Result<(), String> {
        let pin_path_str = self.pin_path.to_str().unwrap();
        let state_path_str = self.state_path.to_str().unwrap();

        aria_core::ebpf_ops::replay_state_to_pinned_maps(pin_path_str, state_path_str)
    }

    fn detach_with_cleanup(&self, remove_pin_path: bool) -> Result<(), String> {
        let xdp_link_pin = self.xdp_link_pin_path();

        // Method 1: Remove pinned link (kernel 5.7+ with bpf_link)
        if std::path::Path::new(&xdp_link_pin).exists() {
            std::fs::remove_file(&xdp_link_pin)
                .map_err(|e| format!("[{}] Failed to remove pinned link: {}", self.iface, e))?;
            info!(instance = %self.iface, "XDP link unpinned");
        } else {
            // Method 2: Use ip command to detach XDP (older kernels)
            let _ = std::process::Command::new("ip")
                .args(["link", "set", "dev", &self.iface, "xdp", "off"])
                .output();
            info!(instance = %self.iface, "XDP detached via netlink");
        }

        for prog_name in ["tc_egress", "tc_ingress"] {
            let link_pin = self.tc_link_pin_path(prog_name);
            if std::path::Path::new(&link_pin).exists() {
                std::fs::remove_file(&link_pin)
                    .map_err(|e| format!("[{}] Failed to remove pinned {} link: {}", self.iface, prog_name, e))?;
                info!(instance = %self.iface, program = %prog_name, "TC link unpinned");
            }
        }

        // Detach TC egress
        aria_core::ebpf_ops::detach_tc_egress(&self.iface);

        // Clean up pinned runtime dir only for non-shared runtimes or explicit rollback.
        if remove_pin_path && self.pin_path.exists() {
            std::fs::remove_dir_all(&self.pin_path)
                .map_err(|e| format!("[{}] Failed to remove pin directory: {}", self.iface, e))?;
            info!(instance = %self.iface, "pin directory cleaned");
        }

        info!(instance = %self.iface, "firewall instance detached");
        Ok(())
    }

    /// Detach XDP and TC. Shared managed runtimes keep the shared pin directory
    /// until the last tap is removed by TapRegistry.
    pub fn detach(&self) -> Result<(), String> {
        self.detach_with_cleanup(!self.shared_runtime)
    }
}
