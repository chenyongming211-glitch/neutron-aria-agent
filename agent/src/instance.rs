use std::path::{Path, PathBuf};
use aria_core::ebpf_ops::{CRITICAL_NETWORK_MAP_NAMES, NETWORK_MAP_NAMES};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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

const RUNTIME_METADATA_SCHEMA_VERSION: u32 = 2;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RuntimePinState {
    pub created_shared_runtime: bool,
    pub reused_existing_runtime: bool,
    pub preexisting_xdp_link: bool,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum LinkOwnership {
    Absent,
    ClaimedExisting,
    AttachedNow,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AttachedLinks {
    xdp: LinkOwnership,
    tc_egress: LinkOwnership,
    tc_ingress: LinkOwnership,
}

impl Default for AttachedLinks {
    fn default() -> Self {
        Self {
            xdp: LinkOwnership::Absent,
            tc_egress: LinkOwnership::Absent,
            tc_ingress: LinkOwnership::Absent,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RuntimeMetadata {
    schema_version: u32,
    ebpf_sha256: String,
    required_program_pins: Vec<String>,
    optional_program_pins: Vec<String>,
    present_program_pins: Vec<String>,
    critical_map_pins: Vec<String>,
}

#[derive(Debug, Clone)]
enum RuntimeInventoryStatus {
    Healthy,
    StaleOrIncomplete(String),
}

impl FirewallInstance {
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

    fn runtime_namespace(&self) -> String {
        self.pin_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("shared-runtime")
            .to_string()
    }

    fn runtime_metadata_path(&self) -> PathBuf {
        let state_root = self
            .state_path
            .parent()
            .unwrap_or(self.state_path.as_path());
        state_root.join(format!(".{}.runtime.meta.json", self.runtime_namespace()))
    }

    fn required_program_pins() -> Vec<String> {
        vec!["xdp_firewall".to_string()]
    }

    fn optional_program_pins() -> Vec<String> {
        vec!["tc_egress".to_string(), "tc_ingress".to_string()]
    }

    fn expected_critical_map_pins() -> Vec<String> {
        CRITICAL_NETWORK_MAP_NAMES
            .iter()
            .map(|name| (*name).to_string())
            .collect()
    }

    fn compute_ebpf_sha256(&self, ebpf_path: &str) -> Result<String, String> {
        let bytes = std::fs::read(ebpf_path)
            .map_err(|e| format!("read ebpf for hash: {}", e))?;
        let digest = Sha256::digest(bytes);
        Ok(digest
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(""))
    }

    fn expected_runtime_metadata(&self, ebpf_path: &str) -> Result<RuntimeMetadata, String> {
        Ok(RuntimeMetadata {
            schema_version: RUNTIME_METADATA_SCHEMA_VERSION,
            ebpf_sha256: self.compute_ebpf_sha256(ebpf_path)?,
            required_program_pins: Self::required_program_pins(),
            optional_program_pins: Self::optional_program_pins(),
            present_program_pins: Vec::new(),
            critical_map_pins: Self::expected_critical_map_pins(),
        })
    }

    fn load_runtime_metadata(&self) -> Result<RuntimeMetadata, String> {
        let path = self.runtime_metadata_path();
        let raw = std::fs::read_to_string(&path)
            .map_err(|e| format!("read runtime metadata {}: {}", path.display(), e))?;
        serde_json::from_str(&raw)
            .map_err(|e| format!("parse runtime metadata {}: {}", path.display(), e))
    }

    fn store_runtime_metadata_atomically(&self, metadata: &RuntimeMetadata) -> Result<(), String> {
        let path = self.runtime_metadata_path();
        let tmp_path = path.with_extension("tmp");
        let json = serde_json::to_string_pretty(metadata)
            .map_err(|e| format!("serialize runtime metadata: {}", e))?;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("create runtime metadata dir {}: {}", parent.display(), e))?;
        }

        std::fs::write(&tmp_path, json)
            .map_err(|e| format!("write runtime metadata tmp {}: {}", tmp_path.display(), e))?;
        std::fs::rename(&tmp_path, &path)
            .map_err(|e| format!("rename runtime metadata {}: {}", path.display(), e))?;
        Ok(())
    }

    fn clear_runtime_metadata(&self) {
        let metadata_path = self.runtime_metadata_path();
        if metadata_path.exists() {
            if let Err(e) = std::fs::remove_file(&metadata_path) {
                warn!(instance = %self.iface, path = %metadata_path.display(), error = %e, "failed to remove runtime metadata");
            }
        }
    }

    fn shared_runtime_has_pinned_live_links(&self) -> Result<bool, String> {
        if !self.pin_path.exists() {
            return Ok(false);
        }

        let entries = std::fs::read_dir(&self.pin_path)
            .map_err(|e| format!("read shared pin dir {}: {}", self.pin_path.display(), e))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("read shared pin entry: {}", e))?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name.ends_with("_xdp_link")
                || name.ends_with("_tc_egress_link")
                || name.ends_with("_tc_ingress_link")
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn validate_runtime_inventory(
        &self,
        expected: &RuntimeMetadata,
    ) -> RuntimeInventoryStatus {
        let metadata = match self.load_runtime_metadata() {
            Ok(metadata) => metadata,
            Err(e) => return RuntimeInventoryStatus::StaleOrIncomplete(e),
        };

        if metadata.schema_version != expected.schema_version {
            return RuntimeInventoryStatus::StaleOrIncomplete(format!(
                "runtime metadata schema {} != expected {}",
                metadata.schema_version, expected.schema_version
            ));
        }
        if metadata.ebpf_sha256 != expected.ebpf_sha256 {
            return RuntimeInventoryStatus::StaleOrIncomplete(format!(
                "runtime eBPF hash {} != expected {}",
                metadata.ebpf_sha256, expected.ebpf_sha256
            ));
        }
        if metadata.required_program_pins != expected.required_program_pins {
            return RuntimeInventoryStatus::StaleOrIncomplete(format!(
                "runtime required program inventory {:?} != expected {:?}",
                metadata.required_program_pins, expected.required_program_pins
            ));
        }
        if metadata.optional_program_pins != expected.optional_program_pins {
            return RuntimeInventoryStatus::StaleOrIncomplete(format!(
                "runtime optional program inventory {:?} != expected {:?}",
                metadata.optional_program_pins, expected.optional_program_pins
            ));
        }
        if metadata.critical_map_pins != expected.critical_map_pins {
            return RuntimeInventoryStatus::StaleOrIncomplete(format!(
                "runtime critical map inventory {:?} != expected {:?}",
                metadata.critical_map_pins, expected.critical_map_pins
            ));
        }

        for program in &metadata.required_program_pins {
            let path = self.pin_path.join(program);
            if !path.exists() {
                return RuntimeInventoryStatus::StaleOrIncomplete(format!(
                    "pinned program missing: {}",
                    path.display()
                ));
            }
        }

        for program in &metadata.present_program_pins {
            let is_known_program = metadata.required_program_pins.iter().any(|p| p == program)
                || metadata.optional_program_pins.iter().any(|p| p == program);
            if !is_known_program {
                return RuntimeInventoryStatus::StaleOrIncomplete(format!(
                    "runtime metadata references unknown pinned program: {}",
                    program
                ));
            }

            let path = self.pin_path.join(program);
            if !path.exists() {
                return RuntimeInventoryStatus::StaleOrIncomplete(format!(
                    "declared pinned program missing: {}",
                    path.display()
                ));
            }
        }

        for map_name in &metadata.critical_map_pins {
            let path = self.pin_path.join(map_name);
            if !path.exists() {
                return RuntimeInventoryStatus::StaleOrIncomplete(format!(
                    "critical pinned map missing: {}",
                    path.display()
                ));
            }
        }

        RuntimeInventoryStatus::Healthy
    }

    fn load_and_pin_runtime(&self, ebpf_path: &str, expected_metadata: &RuntimeMetadata) -> Result<(), String> {
        let pin_path_str = self.pin_path.to_str().unwrap();

        std::fs::create_dir_all(&self.pin_path)
            .map_err(|e| format!("Failed to create pin directory {:?}: {}", self.pin_path, e))?;
        std::fs::create_dir_all(&self.state_path)
            .map_err(|e| format!("Failed to create state directory {:?}: {}", self.state_path, e))?;

        info!(instance = %self.iface, ebpf_path = %ebpf_path, "loading eBPF");
        let bpf_bytes = std::fs::read(ebpf_path)
            .map_err(|e| format!("read ebpf: {}", e))?;
        let mut bpf = aya::EbpfLoader::new()
            .map_pin_path(pin_path_str)
            .load(&bpf_bytes)
            .map_err(|e| format!("[{}] load error: {:?}", self.iface, e))?;

        let loaded_optional_programs = self.load_runtime_programs(&mut bpf)?;
        self.pin_runtime_maps(&mut bpf, pin_path_str)
            .map_err(|e| format!("pin runtime maps failed: {}", e))?;
        let present_program_pins = self.pin_runtime_programs(&mut bpf, pin_path_str, &loaded_optional_programs)?;
        let mut metadata = expected_metadata.clone();
        metadata.present_program_pins = present_program_pins;
        self.store_runtime_metadata_atomically(&metadata)?;

        Ok(())
    }

    fn rebuild_shared_runtime(&self, ebpf_path: &str, metadata: &RuntimeMetadata) -> Result<(), String> {
        info!(instance = %self.iface, path = %self.pin_path.display(), "rebuilding dormant shared runtime");

        if self.pin_path.exists() {
            std::fs::remove_dir_all(&self.pin_path)
                .map_err(|e| format!("remove stale shared pin dir {}: {}", self.pin_path.display(), e))?;
        }
        self.clear_runtime_metadata();

        if let Err(e) = self.load_and_pin_runtime(ebpf_path, metadata) {
            if self.pin_path.exists() {
                let _ = std::fs::remove_dir_all(&self.pin_path);
            }
            self.clear_runtime_metadata();
            return Err(e);
        }

        Ok(())
    }

    /// Ensure the shared runtime objects are pinned before any interface link goes live.
    pub fn ensure_runtime_pinned(
        &self,
        ebpf_path: &str,
        known_live_runtime: bool,
    ) -> Result<RuntimePinState, String> {
        let pin_path_preexisted = self.pin_path.exists();
        let created_shared_runtime = self.shared_runtime && !pin_path_preexisted;
        let xdp_link_pin = self.xdp_link_pin_path();
        let preexisting_xdp_link = Path::new(&xdp_link_pin).exists();
        let expected_metadata = self.expected_runtime_metadata(ebpf_path)?;

        if !pin_path_preexisted {
            if let Err(e) = self.load_and_pin_runtime(ebpf_path, &expected_metadata) {
                if self.pin_path.exists() {
                    let _ = std::fs::remove_dir_all(&self.pin_path);
                }
                self.clear_runtime_metadata();
                return Err(e);
            }
            info!(instance = %self.iface, created_shared_runtime, "runtime pinned and ready for link attach");
            return Ok(RuntimePinState {
                created_shared_runtime,
                reused_existing_runtime: false,
                preexisting_xdp_link: false,
            });
        }

        let live_runtime = known_live_runtime || self.shared_runtime_has_pinned_live_links()?;
        match self.validate_runtime_inventory(&expected_metadata) {
            RuntimeInventoryStatus::Healthy => {
                info!(instance = %self.iface, preexisting_xdp_link, live_runtime, "reusing healthy shared runtime");
                Ok(RuntimePinState {
                    created_shared_runtime: false,
                    reused_existing_runtime: true,
                    preexisting_xdp_link,
                })
            }
            RuntimeInventoryStatus::StaleOrIncomplete(reason) => {
                if live_runtime {
                    return Err(format!(
                        "shared runtime is live but pinned eBPF/schema is stale or incomplete: {}; detach managed taps and reattach to rebuild safely",
                        reason
                    ));
                }

                self.rebuild_shared_runtime(ebpf_path, &expected_metadata)?;
                info!(instance = %self.iface, "rebuilt dormant shared runtime from current eBPF");
                Ok(RuntimePinState {
                    created_shared_runtime: false,
                    reused_existing_runtime: false,
                    preexisting_xdp_link: false,
                })
            }
        }
    }

    /// Attach or recover interface links from an already-pinned runtime.
    pub fn attach_links_from_pinned_runtime(
        &mut self,
        pin_state: &RuntimePinState,
    ) -> Result<AttachedLinks, String> {
        let mut attached = AttachedLinks::default();
        let xdp_link_pin = self.xdp_link_pin_path();

        if pin_state.preexisting_xdp_link {
            attached.xdp = LinkOwnership::ClaimedExisting;
            self.claim_existing_tc_links(&mut attached);
            self.edt_available = aria_core::ebpf_ops::check_fq_qdisc(&self.iface);
            info!(instance = %self.iface, edt_available = self.edt_available, "claimed preexisting live links without runtime mutation");
            return Ok(attached);
        }

        let pin_path_str = self.pin_path.to_str().unwrap();
        let xdp_prog_pin = format!("{}/xdp_firewall", pin_path_str);
        if !std::path::Path::new(&xdp_prog_pin).exists() {
            return Err(format!("[{}] pinned XDP program missing at {}", self.iface, xdp_prog_pin));
        }

        self.attach_xdp_from_pin(&xdp_prog_pin, &xdp_link_pin)?;
        attached.xdp = LinkOwnership::AttachedNow;

        self.ensure_tc_runtime(&mut attached);
        self.ensure_fq_runtime();

        info!(instance = %self.iface, edt_available = self.edt_available, "interface links attached from pinned runtime");
        Ok(attached)
    }

    pub fn rollback_attached_links(
        &self,
        attached: &AttachedLinks,
        remove_pin_path: bool,
    ) -> Result<(), String> {
        if attached.xdp == LinkOwnership::AttachedNow {
            let xdp_link_pin = self.xdp_link_pin_path();
            if std::path::Path::new(&xdp_link_pin).exists() {
                std::fs::remove_file(&xdp_link_pin)
                    .map_err(|e| format!("[{}] Failed to remove pinned XDP link: {}", self.iface, e))?;
            } else {
                let _ = std::process::Command::new("ip")
                    .args(["link", "set", "dev", &self.iface, "xdp", "off"])
                    .output();
            }
            info!(instance = %self.iface, "rolled back newly attached XDP link");
        }

        let tc_attached_now = attached.tc_egress == LinkOwnership::AttachedNow
            || attached.tc_ingress == LinkOwnership::AttachedNow;
        if tc_attached_now {
            for (prog_name, ownership) in [
                ("tc_egress", attached.tc_egress),
                ("tc_ingress", attached.tc_ingress),
            ] {
                if ownership != LinkOwnership::AttachedNow {
                    continue;
                }
                let link_pin = self.tc_link_pin_path(prog_name);
                if std::path::Path::new(&link_pin).exists() {
                    std::fs::remove_file(&link_pin)
                        .map_err(|e| format!("[{}] Failed to remove pinned {} link: {}", self.iface, prog_name, e))?;
                }
            }
            aria_core::ebpf_ops::detach_tc_egress(&self.iface);
            info!(instance = %self.iface, "rolled back newly attached TC links");
        }

        if remove_pin_path && self.pin_path.exists() {
            std::fs::remove_dir_all(&self.pin_path)
                .map_err(|e| format!("[{}] Failed to remove pin directory: {}", self.iface, e))?;
            info!(instance = %self.iface, "runtime pin directory cleaned after rollback");
        }

        Ok(())
    }

    fn load_runtime_programs(&self, bpf: &mut aya::Ebpf) -> Result<Vec<String>, String> {
        {
            let xdp_program = bpf
                .program_mut("xdp_firewall")
                .ok_or_else(|| format!("[{}] XDP program not found", self.iface))?;

            let xdp: &mut aya::programs::Xdp = xdp_program
                .try_into()
                .map_err(|e: aya::programs::ProgramError| format!("[{}] xdp try_into error: {:?}", self.iface, e))?;

            xdp.load()
                .map_err(|e| format!("[{}] xdp.load error: {:?}", self.iface, e))?;
        }

        let mut loaded_optional_programs = Vec::new();
        for prog_name in Self::optional_program_pins() {
            if let Err(e) = self.load_tc_program(bpf, &prog_name) {
                warn!(instance = %self.iface, program = %prog_name, error = %e, "TC program load failed; runtime will continue without it");
            } else {
                loaded_optional_programs.push(prog_name);
            }
        }

        Ok(loaded_optional_programs)
    }

    fn load_tc_program(&self, bpf: &mut aya::Ebpf, prog_name: &str) -> Result<(), String> {
        let tc_program = bpf.program_mut(prog_name)
            .ok_or_else(|| format!("{} program not found", prog_name))?;

        let tc: &mut aya::programs::SchedClassifier = tc_program
            .try_into()
            .map_err(|e: aya::programs::ProgramError| format!("{} try_into: {:?}", prog_name, e))?;

        tc.load().map_err(|e| format!("{} load: {:?}", prog_name, e))
    }

    fn pin_runtime_programs(
        &self,
        bpf: &mut aya::Ebpf,
        pin_path: &str,
        loaded_optional_programs: &[String],
    ) -> Result<Vec<String>, String> {
        let mut present_program_pins = Vec::new();

        let required_program = "xdp_firewall";
        let required_target = format!("{}/{}", pin_path, required_program);
        let required_program_ref = bpf
            .program_mut(required_program)
            .ok_or_else(|| format!("required runtime program {} not found", required_program))?;
        if !Path::new(&required_target).exists() {
            required_program_ref
                .pin(required_target)
                .map_err(|e| format!("failed to pin required runtime program {}: {:?}", required_program, e))?;
        }
        present_program_pins.push(required_program.to_string());

        for name in loaded_optional_programs {
            let Some(program) = bpf.program_mut(name.as_str()) else {
                continue;
            };
            let target = format!("{}/{}", pin_path, name);
            if Path::new(&target).exists() {
                present_program_pins.push(name.clone());
                continue;
            }
            if let Err(e) = program.pin(target) {
                warn!(instance = %self.iface, program = %name, error = ?e, "failed to pin optional runtime program");
            } else {
                present_program_pins.push(name.clone());
            }
        }

        Ok(present_program_pins)
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

    fn tc_prog_pin_path(&self, prog_name: &str) -> String {
        format!("{}/{}", self.pin_path.display(), prog_name)
    }

    fn ensure_tc_runtime(&self, attached: &mut AttachedLinks) {
        let tc_programs = [
            ("tc_egress", aya::programs::tc::TcAttachType::Egress, "Egress control"),
            ("tc_ingress", aya::programs::tc::TcAttachType::Ingress, "Ingress mirror"),
        ];

        for (prog_name, attach_type, purpose) in tc_programs {
            let link_pin = self.tc_link_pin_path(prog_name);
            if std::path::Path::new(&link_pin).exists() {
                Self::set_tc_link_ownership(attached, prog_name, LinkOwnership::ClaimedExisting);
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
            } else {
                Self::set_tc_link_ownership(attached, prog_name, LinkOwnership::AttachedNow);
            }
        }
    }

    fn claim_existing_tc_links(&self, attached: &mut AttachedLinks) {
        for prog_name in ["tc_egress", "tc_ingress"] {
            let link_pin = self.tc_link_pin_path(prog_name);
            if std::path::Path::new(&link_pin).exists() {
                Self::set_tc_link_ownership(attached, prog_name, LinkOwnership::ClaimedExisting);
            }
        }
    }

    fn set_tc_link_ownership(attached: &mut AttachedLinks, prog_name: &str, ownership: LinkOwnership) {
        match prog_name {
            "tc_egress" => attached.tc_egress = ownership,
            "tc_ingress" => attached.tc_ingress = ownership,
            _ => {}
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

    /// Attach XDP from the already pinned shared runtime without loading a new eBPF object.
    fn attach_xdp_from_pin(&self, prog_pin: &str, xdp_link_pin: &str) -> Result<(), String> {
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
