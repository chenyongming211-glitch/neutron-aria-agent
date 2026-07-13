use aria_core::ebpf_ops::{critical_network_map_names, TraceMapMode, NETWORK_MAP_NAMES};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// Represents a single tap interface with its attached XDP firewall instance.
/// On kernel 5.7+, the XDP link is pinned to bpffs so it survives agent crashes.
/// On older kernels, XDP is attached via netlink and will detach when agent exits.
pub struct FirewallInstance {
    pub iface: String,
    pub pin_path: PathBuf,
    pub state_path: PathBuf,
    pub shared_runtime: bool,
    trace_map_mode: TraceMapMode,
    /// Whether FQ qdisc (EDT) was successfully configured.
    /// If false, QoS shaping is unavailable — only policing works.
    pub edt_available: bool,
}

const RUNTIME_METADATA_SCHEMA_VERSION: u32 = 2;
const PERSISTED_LIVE_IFACES_SCHEMA_VERSION: u32 = 2;
const FQ_QDISC_MARKER: &str = ".fq-root-qdisc-owned";

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct RuntimePinState {
    pub created_shared_runtime: bool,
    pub reused_existing_runtime: bool,
    pub preexisting_live_links: bool,
    pub preexisting_xdp_link: bool,
    pub preexisting_tc_ingress_link: bool,
    pub preexisting_tc_egress_link: bool,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TcAclLinkHealth {
    pub ingress: bool,
    pub egress: bool,
    pub xdp: bool,
}

impl TcAclLinkHealth {
    pub fn new(ingress: bool, egress: bool, xdp: bool) -> Self {
        Self {
            ingress,
            egress,
            xdp,
        }
    }

    pub fn acl_ready(self) -> bool {
        self.ingress && self.egress
    }

    pub fn xdp_ready(self) -> bool {
        self.xdp
    }

    pub fn missing_tc(self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if !self.ingress {
            missing.push("tc_ingress");
        }
        if !self.egress {
            missing.push("tc_egress");
        }
        missing
    }
}

fn tcx_query_contains_expected_program(
    expected_program_id: u32,
    attached_program_ids: &[u32],
) -> bool {
    attached_program_ids.contains(&expected_program_id)
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

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum LinkRollbackAction {
    RemoveXdpAttachment,
    RemoveTcLinkPin(&'static str),
    RemoveRuntimePinPath,
}

fn rollback_link_cleanup_plan(
    attached: &AttachedLinks,
    remove_pin_path: bool,
) -> Vec<LinkRollbackAction> {
    let mut plan = Vec::new();
    if attached.xdp == LinkOwnership::AttachedNow {
        plan.push(LinkRollbackAction::RemoveXdpAttachment);
    }
    if attached.tc_egress == LinkOwnership::AttachedNow {
        plan.push(LinkRollbackAction::RemoveTcLinkPin("tc_egress"));
    }
    if attached.tc_ingress == LinkOwnership::AttachedNow {
        plan.push(LinkRollbackAction::RemoveTcLinkPin("tc_ingress"));
    }
    let has_claimed_existing = attached.xdp == LinkOwnership::ClaimedExisting
        || attached.tc_egress == LinkOwnership::ClaimedExisting
        || attached.tc_ingress == LinkOwnership::ClaimedExisting;
    if remove_pin_path && !has_claimed_existing {
        plan.push(LinkRollbackAction::RemoveRuntimePinPath);
    }
    plan
}

fn execute_rollback_cleanup_plan<F>(
    plan: &[LinkRollbackAction],
    mut cleanup: F,
) -> Result<(), String>
where
    F: FnMut(LinkRollbackAction) -> Result<(), String>,
{
    let mut errors = Vec::new();
    for action in plan {
        if let Err(error) = cleanup(*action) {
            errors.push(format!("{:?}: {}", action, error));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn checked_xdp_detach_output(
    iface: &str,
    output: std::io::Result<std::process::Output>,
) -> Result<(), String> {
    let output = output
        .map_err(|error| format!("[{}] failed to spawn XDP detach command: {}", iface, error))?;
    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let detail = if stderr.is_empty() {
        "no stderr".to_string()
    } else {
        stderr
    };
    Err(format!(
        "[{}] XDP detach command failed with status {}: {}",
        iface, output.status, detail
    ))
}

#[derive(Debug, Eq, PartialEq)]
struct XdpAttachFailure {
    message: String,
    attachment_may_remain: bool,
}

impl XdpAttachFailure {
    fn safe(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            attachment_may_remain: false,
        }
    }

    fn attachment_may_remain(&self) -> bool {
        self.attachment_may_remain
    }
}

impl std::fmt::Display for XdpAttachFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

fn recover_unpinned_xdp_attachment<F>(
    pin_error: impl Into<String>,
    detach: F,
) -> Result<(), XdpAttachFailure>
where
    F: FnOnce() -> Result<(), String>,
{
    let pin_error = pin_error.into();
    match detach() {
        Ok(()) => Err(XdpAttachFailure::safe(format!(
            "XDP link pin failed: {}; newly attached XDP program detached",
            pin_error
        ))),
        Err(detach_error) => Err(XdpAttachFailure {
            message: format!(
                "XDP link pin failed: {}; immediate XDP detach failed: {}",
                pin_error, detach_error
            ),
            attachment_may_remain: true,
        }),
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedLiveIface {
    iface: String,
    ifindex: u32,
    #[serde(default = "default_persisted_live_iface_active")]
    active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedLiveIfaces {
    schema_version: u32,
    ifaces: Vec<PersistedLiveIface>,
}

#[derive(Debug, Clone)]
enum RuntimeInventoryStatus {
    Healthy,
    StaleOrIncomplete(String),
}

fn default_persisted_live_iface_active() -> bool {
    true
}

fn tc_acl_links_complete(ingress: bool, egress: bool) -> bool {
    ingress && egress
}

impl FirewallInstance {
    fn fq_qdisc_marker_path(&self) -> PathBuf {
        self.state_path.join(FQ_QDISC_MARKER)
    }

    fn mark_owned_fq_qdisc(&self) {
        let marker_path = self.fq_qdisc_marker_path();
        if let Err(e) = std::fs::write(&marker_path, b"owned\n") {
            warn!(
                instance = %self.iface,
                path = %marker_path.display(),
                error = %e,
                "failed to persist FQ qdisc ownership marker"
            );
        }
    }

    fn cleanup_owned_fq_qdisc(&self) -> Result<(), String> {
        let marker_path = self.fq_qdisc_marker_path();
        if !marker_path.exists() {
            return Ok(());
        }

        let iface_sys_path = Path::new("/sys/class/net").join(&self.iface);
        if !iface_sys_path.exists() {
            std::fs::remove_file(&marker_path).map_err(|e| {
                format!(
                    "[{}] Failed to remove FQ marker for gone device {}: {}",
                    self.iface,
                    marker_path.display(),
                    e
                )
            })?;
            return Ok(());
        }

        aria_core::ebpf_ops::cleanup_root_qdisc(&self.iface)
            .map_err(|e| format!("[{}] Failed to remove owned root qdisc: {}", self.iface, e))?;
        std::fs::remove_file(&marker_path).map_err(|e| {
            format!(
                "[{}] Failed to remove FQ qdisc ownership marker {}: {}",
                self.iface,
                marker_path.display(),
                e
            )
        })?;
        Ok(())
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
            format!(
                "{}/{}_{}_link",
                self.pin_path.display(),
                self.iface,
                prog_name
            )
        } else {
            format!("{}/{}_link", self.pin_path.display(), prog_name)
        }
    }

    pub fn require_tc_acl_links(&self) -> Result<(), String> {
        let health = self.tc_acl_link_health();
        if health.acl_ready() {
            return Ok(());
        }

        Err(format!(
            "missing pinned TC ACL links: {}",
            health.missing_tc().join(", ")
        ))
    }

    pub fn require_tc_acl_runtime(&self) -> Result<(), String> {
        let mut missing = Vec::new();
        for prog_name in ["tc_ingress", "tc_egress"] {
            if !Path::new(&self.tc_link_pin_path(prog_name)).exists() {
                missing.push(format!("{} link", prog_name));
            }
            if !self.pin_path.join(prog_name).exists() {
                missing.push(format!("{} program", prog_name));
            }
        }
        if missing.is_empty() {
            return Ok(());
        }

        Err(format!(
            "missing pinned TC ACL runtime: {}",
            missing.join(", ")
        ))
    }

    fn tcx_attachment_is_live(
        &self,
        prog_name: &str,
        attach_type: aya::programs::tc::TcAttachType,
    ) -> bool {
        let Ok(program) =
            aya::programs::SchedClassifier::from_pin(self.tc_prog_pin_path(prog_name))
        else {
            return false;
        };
        let Ok(program_info) = program.info() else {
            return false;
        };
        let Ok(pinned_link) =
            aya::programs::links::PinnedLink::from_pin(self.tc_link_pin_path(prog_name))
        else {
            return false;
        };
        let fd_link: aya::programs::links::FdLink = pinned_link.into();
        let Ok(_tcx_link): Result<aya::programs::tc::SchedClassifierLink, _> = fd_link.try_into()
        else {
            return false;
        };
        let Ok((_revision, attached_programs)) =
            aya::programs::SchedClassifier::query_tcx(&self.iface, attach_type)
        else {
            return false;
        };
        let attached_program_ids: Vec<u32> = attached_programs
            .iter()
            .map(|attached| attached.id())
            .collect();
        tcx_query_contains_expected_program(program_info.id(), &attached_program_ids)
    }

    pub fn xdp_link_health(&self) -> bool {
        Path::new(&self.xdp_link_pin_path()).exists()
    }

    pub fn tc_acl_link_health(&self) -> TcAclLinkHealth {
        TcAclLinkHealth::new(
            self.tcx_attachment_is_live(
                "tc_ingress",
                aya::programs::tc::TcAttachType::Ingress,
            ),
            self.tcx_attachment_is_live(
                "tc_egress",
                aya::programs::tc::TcAttachType::Egress,
            ),
            self.xdp_link_health(),
        )
    }

    fn pin_runtime_maps(&self, bpf: &mut aya::Ebpf, pin_path: &str) -> Result<(), String> {
        let critical_map_names = critical_network_map_names(self.trace_map_mode);
        for name in NETWORK_MAP_NAMES {
            if let Some(map) = bpf.map_mut(name) {
                let target = format!("{}/{}", pin_path, name);
                if std::path::Path::new(&target).exists() {
                    continue;
                }
                if let Err(e) = map.pin(target) {
                    if critical_map_names.contains(name) {
                        return Err(format!("failed to pin critical map {}: {}", name, e));
                    }
                    warn!(instance = %self.iface, map = %name, error = %e, "failed to pin runtime map");
                }
            } else if critical_map_names.contains(name) {
                return Err(format!("critical map {} not found", name));
            }
        }
        Ok(())
    }

    pub fn new(
        iface: &str,
        pin_path: PathBuf,
        state_path: PathBuf,
        shared_runtime: bool,
        trace_map_mode: TraceMapMode,
    ) -> Self {
        Self {
            iface: iface.to_string(),
            pin_path,
            state_path,
            shared_runtime,
            trace_map_mode,
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

    fn persisted_live_ifaces_path(&self) -> PathBuf {
        let state_root = self
            .state_path
            .parent()
            .unwrap_or(self.state_path.as_path());
        state_root.join(format!(".{}.live-ifaces.json", self.runtime_namespace()))
    }

    fn required_program_pins() -> Vec<String> {
        vec!["xdp_firewall".to_string()]
    }

    fn optional_program_pins() -> Vec<String> {
        vec!["tc_egress".to_string(), "tc_ingress".to_string()]
    }

    fn expected_critical_map_pins(&self) -> Vec<String> {
        critical_network_map_names(self.trace_map_mode)
            .iter()
            .map(|name| (*name).to_string())
            .collect()
    }

    fn compute_ebpf_sha256(&self, ebpf_path: &str) -> Result<String, String> {
        let bytes = std::fs::read(ebpf_path).map_err(|e| format!("read ebpf for hash: {}", e))?;
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
            critical_map_pins: self.expected_critical_map_pins(),
        })
    }

    fn load_runtime_metadata(&self) -> Result<RuntimeMetadata, String> {
        let path = self.runtime_metadata_path();
        let raw = std::fs::read_to_string(&path)
            .map_err(|e| format!("read runtime metadata {}: {}", path.display(), e))?;
        serde_json::from_str(&raw)
            .map_err(|e| format!("parse runtime metadata {}: {}", path.display(), e))
    }

    fn load_persisted_live_ifaces(&self) -> Result<PersistedLiveIfaces, String> {
        let path = self.persisted_live_ifaces_path();
        if !path.exists() {
            return Ok(PersistedLiveIfaces {
                schema_version: PERSISTED_LIVE_IFACES_SCHEMA_VERSION,
                ifaces: Vec::new(),
            });
        }

        let raw = std::fs::read_to_string(&path)
            .map_err(|e| format!("read persisted live ifaces {}: {}", path.display(), e))?;
        let mut state: PersistedLiveIfaces = serde_json::from_str(&raw)
            .map_err(|e| format!("parse persisted live ifaces {}: {}", path.display(), e))?;
        let original_schema_version = state.schema_version;
        if original_schema_version != 1
            && original_schema_version != PERSISTED_LIVE_IFACES_SCHEMA_VERSION
        {
            return Err(format!(
                "persisted live ifaces schema {} is unsupported (expected 1 or {})",
                original_schema_version, PERSISTED_LIVE_IFACES_SCHEMA_VERSION,
            ));
        }
        if original_schema_version == 1 {
            for entry in &mut state.ifaces {
                entry.active = false;
            }
        }
        state.schema_version = PERSISTED_LIVE_IFACES_SCHEMA_VERSION;
        if original_schema_version == 1 {
            self.store_persisted_live_ifaces_atomically(&state)?;
        }
        Ok(state)
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

    fn store_persisted_live_ifaces_atomically(
        &self,
        state: &PersistedLiveIfaces,
    ) -> Result<(), String> {
        let path = self.persisted_live_ifaces_path();
        let tmp_path = path.with_extension("tmp");
        let json = serde_json::to_string_pretty(state)
            .map_err(|e| format!("serialize persisted live ifaces: {}", e))?;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                format!(
                    "create persisted live ifaces dir {}: {}",
                    parent.display(),
                    e
                )
            })?;
        }

        std::fs::write(&tmp_path, json).map_err(|e| {
            format!(
                "write persisted live ifaces tmp {}: {}",
                tmp_path.display(),
                e
            )
        })?;
        std::fs::rename(&tmp_path, &path)
            .map_err(|e| format!("rename persisted live ifaces {}: {}", path.display(), e))?;
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

    fn current_ifindex(&self) -> Result<u32, String> {
        let path = format!("/sys/class/net/{}/ifindex", self.iface);
        let raw = std::fs::read_to_string(&path)
            .map_err(|e| format!("read ifindex for {}: {}", self.iface, e))?;
        raw.trim()
            .parse::<u32>()
            .map_err(|e| format!("parse ifindex for {}: {}", self.iface, e))
    }

    fn existing_ifaces_by_ifindex(&self) -> Result<HashMap<u32, String>, String> {
        let mut ifaces = HashMap::new();
        let entries = std::fs::read_dir("/sys/class/net")
            .map_err(|e| format!("read /sys/class/net: {}", e))?;
        for entry in entries {
            let entry = entry.map_err(|e| format!("read /sys/class/net entry: {}", e))?;
            let file_type = entry
                .file_type()
                .map_err(|e| format!("read /sys/class/net entry type: {}", e))?;
            // Sysfs may expose helper files like bonding_masters alongside real
            // interfaces. Only interface directories/symlinks carry ifindex.
            if !file_type.is_dir() && !file_type.is_symlink() {
                continue;
            }
            let iface = entry.file_name().to_string_lossy().to_string();
            let ifindex_path = entry.path().join("ifindex");
            let raw = match std::fs::read_to_string(&ifindex_path) {
                Ok(raw) => raw,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(format!("read ifindex for {}: {}", iface, e)),
            };
            let ifindex = raw
                .trim()
                .parse::<u32>()
                .map_err(|e| format!("parse ifindex for {}: {}", iface, e))?;
            ifaces.insert(ifindex, iface);
        }
        Ok(ifaces)
    }

    pub fn reserve_persisted_live_iface(&self) -> Result<(), String> {
        if !self.shared_runtime {
            return Ok(());
        }

        let mut state = self.load_persisted_live_ifaces()?;
        state.ifaces.retain(|entry| entry.iface != self.iface);
        state.ifaces.push(PersistedLiveIface {
            iface: self.iface.clone(),
            ifindex: self.current_ifindex()?,
            active: false,
        });
        self.store_persisted_live_ifaces_atomically(&state)
    }

    pub fn activate_persisted_live_iface(&self) -> Result<(), String> {
        if !self.shared_runtime {
            return Ok(());
        }

        let mut state = self.load_persisted_live_ifaces()?;
        let ifindex = self.current_ifindex()?;
        let mut found = false;
        for entry in &mut state.ifaces {
            if entry.iface != self.iface {
                continue;
            }
            entry.ifindex = ifindex;
            entry.active = true;
            found = true;
            break;
        }

        if !found {
            return Err(format!(
                "persisted live runtime reservation for {} missing before activation",
                self.iface
            ));
        }

        self.store_persisted_live_ifaces_atomically(&state)
    }

    pub fn release_persisted_live_iface(&self) -> Result<(), String> {
        if !self.shared_runtime {
            return Ok(());
        }

        let path = self.persisted_live_ifaces_path();
        let mut state = self.load_persisted_live_ifaces()?;
        state.ifaces.retain(|entry| entry.iface != self.iface);
        if state.ifaces.is_empty() {
            if path.exists() {
                std::fs::remove_file(&path).map_err(|e| {
                    format!("remove persisted live ifaces {}: {}", path.display(), e)
                })?;
            }
            return Ok(());
        }
        self.store_persisted_live_ifaces_atomically(&state)
    }

    pub fn cleanup_stale_shared_runtime_reservations(&self) -> Result<Vec<String>, String> {
        if !self.shared_runtime {
            return Ok(Vec::new());
        }
        if self.pin_path.exists() {
            return Ok(Vec::new());
        }

        let path = self.persisted_live_ifaces_path();
        let state = self.reconcile_persisted_live_ifaces()?;
        if state.ifaces.is_empty() {
            self.clear_runtime_metadata();
            return Ok(Vec::new());
        }

        let state_root = self
            .state_path
            .parent()
            .unwrap_or(self.state_path.as_path())
            .to_path_buf();
        let mut cleaned = Vec::new();
        let mut errors = Vec::new();

        for entry in state.ifaces {
            let stale = FirewallInstance::new(
                &entry.iface,
                self.pin_path.clone(),
                state_root.join(&entry.iface),
                true,
                self.trace_map_mode,
            );
            match stale.detach_with_cleanup(false) {
                Ok(()) => cleaned.push(entry.iface),
                Err(e) => errors.push(format!("{}:{}", entry.iface, e)),
            }
        }

        if !errors.is_empty() {
            return Err(errors.join("; "));
        }

        if path.exists() {
            std::fs::remove_file(&path).map_err(|e| {
                format!(
                    "remove stale persisted live ifaces {}: {}",
                    path.display(),
                    e
                )
            })?;
        }
        self.clear_runtime_metadata();
        Ok(cleaned)
    }

    fn reconcile_persisted_live_ifaces(&self) -> Result<PersistedLiveIfaces, String> {
        let path = self.persisted_live_ifaces_path();
        let state = self.load_persisted_live_ifaces()?;
        if state.ifaces.is_empty() {
            return Ok(state);
        }

        let existing_ifaces = self.existing_ifaces_by_ifindex()?;
        let mut seen_ifindices = HashSet::new();
        let mut changed = false;
        let mut retained = Vec::new();

        for entry in state.ifaces {
            if let Some(current_iface) = existing_ifaces.get(&entry.ifindex) {
                if !seen_ifindices.insert(entry.ifindex) {
                    changed = true;
                    continue;
                }
                if entry.iface != *current_iface {
                    changed = true;
                }
                retained.push(PersistedLiveIface {
                    iface: current_iface.clone(),
                    ifindex: entry.ifindex,
                    active: entry.active,
                });
            } else {
                changed = true;
                info!(
                    instance = %self.iface,
                    stale_iface = %entry.iface,
                    stale_ifindex = entry.ifindex,
                    "dropping stale persisted live runtime reservation"
                );
            }
        }

        if !changed {
            return Ok(PersistedLiveIfaces {
                schema_version: PERSISTED_LIVE_IFACES_SCHEMA_VERSION,
                ifaces: retained,
            });
        }

        let reconciled = PersistedLiveIfaces {
            schema_version: PERSISTED_LIVE_IFACES_SCHEMA_VERSION,
            ifaces: retained,
        };
        if reconciled.ifaces.is_empty() {
            if path.exists() {
                std::fs::remove_file(&path).map_err(|e| {
                    format!("remove persisted live ifaces {}: {}", path.display(), e)
                })?;
            }
        } else {
            self.store_persisted_live_ifaces_atomically(&reconciled)?;
        }
        Ok(reconciled)
    }

    fn persisted_live_ifaces_active(&self) -> Result<bool, String> {
        Ok(self
            .reconcile_persisted_live_ifaces()?
            .ifaces
            .iter()
            .any(|entry| entry.active))
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

    fn validate_runtime_inventory(&self, expected: &RuntimeMetadata) -> RuntimeInventoryStatus {
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

    fn load_and_pin_runtime(
        &self,
        ebpf_path: &str,
        expected_metadata: &RuntimeMetadata,
    ) -> Result<(), String> {
        let pin_path_str = self
            .pin_path
            .to_str()
            .ok_or_else(|| format!("non-UTF-8 pin path: {}", self.pin_path.display()))?;

        std::fs::create_dir_all(&self.pin_path)
            .map_err(|e| format!("Failed to create pin directory {:?}: {}", self.pin_path, e))?;
        std::fs::create_dir_all(&self.state_path).map_err(|e| {
            format!(
                "Failed to create state directory {:?}: {}",
                self.state_path, e
            )
        })?;

        info!(instance = %self.iface, ebpf_path = %ebpf_path, "loading eBPF");
        let bpf_bytes = std::fs::read(ebpf_path).map_err(|e| format!("read ebpf: {}", e))?;
        let mut bpf = aya::EbpfLoader::new()
            .map_pin_path(pin_path_str)
            .load(&bpf_bytes)
            .map_err(|e| format!("[{}] load error: {:?}", self.iface, e))?;

        let loaded_optional_programs = self.load_runtime_programs(&mut bpf)?;
        self.pin_runtime_maps(&mut bpf, pin_path_str)
            .map_err(|e| format!("pin runtime maps failed: {}", e))?;
        let present_program_pins =
            self.pin_runtime_programs(&mut bpf, pin_path_str, &loaded_optional_programs)?;
        let mut metadata = expected_metadata.clone();
        metadata.present_program_pins = present_program_pins;
        self.store_runtime_metadata_atomically(&metadata)?;

        Ok(())
    }

    fn repair_missing_optional_program_pins(&self, ebpf_path: &str) -> Result<Vec<String>, String> {
        let mut metadata = self.load_runtime_metadata()?;
        let missing: Vec<String> = Self::optional_program_pins()
            .into_iter()
            .filter(|name| !self.pin_path.join(name).exists())
            .collect();
        if missing.is_empty() {
            return Ok(Vec::new());
        }

        let pin_path_str = self
            .pin_path
            .to_str()
            .ok_or_else(|| format!("non-UTF-8 pin path: {}", self.pin_path.display()))?;

        info!(
            instance = %self.iface,
            missing_programs = ?missing,
            "repairing missing optional runtime program pins"
        );
        let bpf_bytes = std::fs::read(ebpf_path).map_err(|e| format!("read ebpf: {}", e))?;
        let mut bpf = aya::EbpfLoader::new()
            .map_pin_path(pin_path_str)
            .load(&bpf_bytes)
            .map_err(|e| format!("[{}] load for optional program repair: {:?}", self.iface, e))?;

        let mut repaired = Vec::new();
        for prog_name in missing {
            if let Err(e) = self.load_tc_program(&mut bpf, &prog_name) {
                warn!(instance = %self.iface, program = %prog_name, error = %e, "optional TC program repair load failed");
                continue;
            }

            let Some(program) = bpf.program_mut(prog_name.as_str()) else {
                warn!(instance = %self.iface, program = %prog_name, "optional TC program missing after repair load");
                continue;
            };
            let target = format!("{}/{}", pin_path_str, prog_name);
            if let Err(e) = program.pin(&target) {
                warn!(instance = %self.iface, program = %prog_name, target = %target, error = ?e, "optional TC program repair pin failed");
                continue;
            }
            repaired.push(prog_name);
        }

        if !repaired.is_empty() {
            let mut present: BTreeSet<String> =
                metadata.present_program_pins.iter().cloned().collect();
            for prog_name in &repaired {
                present.insert(prog_name.clone());
            }
            metadata.present_program_pins = present.into_iter().collect();
            self.store_runtime_metadata_atomically(&metadata)?;
        }

        Ok(repaired)
    }

    fn rebuild_shared_runtime(
        &self,
        ebpf_path: &str,
        metadata: &RuntimeMetadata,
    ) -> Result<(), String> {
        info!(instance = %self.iface, path = %self.pin_path.display(), "rebuilding dormant shared runtime");

        if self.pin_path.exists() {
            std::fs::remove_dir_all(&self.pin_path).map_err(|e| {
                format!(
                    "remove stale shared pin dir {}: {}",
                    self.pin_path.display(),
                    e
                )
            })?;
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
        let preexisting_tc_ingress_link =
            Path::new(&self.tc_link_pin_path("tc_ingress")).exists();
        let preexisting_tc_egress_link =
            Path::new(&self.tc_link_pin_path("tc_egress")).exists();
        let preexisting_live_links = preexisting_xdp_link
            || preexisting_tc_ingress_link
            || preexisting_tc_egress_link;
        let expected_metadata = self.expected_runtime_metadata(ebpf_path)?;
        let mut persisted_live_runtime = self.persisted_live_ifaces_active()?;
        let pinned_live_runtime = if pin_path_preexisted {
            self.shared_runtime_has_pinned_live_links()?
        } else {
            false
        };
        if !pin_path_preexisted
            && !known_live_runtime
            && !pinned_live_runtime
            && persisted_live_runtime
        {
            let cleaned = self.cleanup_stale_shared_runtime_reservations()?;
            if !cleaned.is_empty() {
                info!(
                    instance = %self.iface,
                    cleaned_ifaces = ?cleaned,
                    "cleared stale shared runtime reservations before rebuilding missing pin directory"
                );
            }
            persisted_live_runtime = false;
        }
        let live_runtime = known_live_runtime || pinned_live_runtime || persisted_live_runtime;

        if !pin_path_preexisted {
            if live_runtime {
                return Err(
                    "shared runtime appears live but the pinned runtime directory is missing; detach managed taps and reattach to rebuild safely"
                        .to_string(),
                );
            }
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
                preexisting_live_links: false,
                preexisting_xdp_link: false,
                preexisting_tc_ingress_link: false,
                preexisting_tc_egress_link: false,
            });
        }
        match self.validate_runtime_inventory(&expected_metadata) {
            RuntimeInventoryStatus::Healthy => {
                let repaired_optional_pins =
                    self.repair_missing_optional_program_pins(ebpf_path)?;
                if !repaired_optional_pins.is_empty() {
                    info!(
                        instance = %self.iface,
                        repaired_programs = ?repaired_optional_pins,
                        "repaired shared runtime optional program pins"
                    );
                }
                info!(instance = %self.iface, preexisting_live_links, preexisting_xdp_link, preexisting_tc_ingress_link, preexisting_tc_egress_link, live_runtime, "reusing healthy shared runtime");
                Ok(RuntimePinState {
                    created_shared_runtime: false,
                    reused_existing_runtime: true,
                    preexisting_live_links,
                    preexisting_xdp_link,
                    preexisting_tc_ingress_link,
                    preexisting_tc_egress_link,
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
                    preexisting_live_links: false,
                    preexisting_xdp_link: false,
                    preexisting_tc_ingress_link: false,
                    preexisting_tc_egress_link: false,
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
        let pin_path_str = self
            .pin_path
            .to_str()
            .ok_or_else(|| format!("non-UTF-8 pin path: {}", self.pin_path.display()))?;

        self.ensure_tc_runtime(&mut attached);

        let xdp_prog_pin = format!("{}/xdp_firewall", pin_path_str);
        if pin_state.preexisting_xdp_link {
            attached.xdp = LinkOwnership::ClaimedExisting;
        } else if !std::path::Path::new(&xdp_prog_pin).exists() {
            warn!(instance = %self.iface, prog_pin = %xdp_prog_pin, "pinned XDP DDoS program missing; TC ACL remains independent");
        } else {
            match self.attach_xdp_from_pin(&xdp_prog_pin, &xdp_link_pin) {
                Ok(()) => attached.xdp = LinkOwnership::AttachedNow,
                Err(error) if error.attachment_may_remain() => {
                    attached.xdp = LinkOwnership::AttachedNow;
                    let rollback_error = self.rollback_attached_links(&attached, false).err();
                    return Err(match rollback_error {
                        Some(rollback_error) => format!(
                            "XDP attachment may remain after pin failure: {}; rollback failed: {}",
                            error, rollback_error
                        ),
                        None => format!(
                            "XDP attachment pin failed and required transaction rollback: {}",
                            error
                        ),
                    });
                }
                Err(error) => {
                    warn!(instance = %self.iface, error = %error, "XDP DDoS hook unavailable; TC ACL remains independent");
                }
            }
        }

        if let Err(e) = self.activate_persisted_live_iface() {
            if let Err(rollback_err) = self.rollback_attached_links(&attached, false) {
                warn!(instance = %self.iface, error = %rollback_err, "failed to roll back links after persisted live activation failure");
            }
            return Err(e);
        }

        self.ensure_fq_runtime();

        let health = self.tc_acl_link_health();
        info!(instance = %self.iface, tc_ingress = health.ingress, tc_egress = health.egress, xdp = health.xdp, edt_available = self.edt_available, "interface links attached from pinned runtime");
        Ok(attached)
    }

    pub fn rollback_attached_links(
        &self,
        attached: &AttachedLinks,
        remove_pin_path: bool,
    ) -> Result<(), String> {
        let plan = rollback_link_cleanup_plan(attached, remove_pin_path);
        execute_rollback_cleanup_plan(&plan, |action| match action {
            LinkRollbackAction::RemoveXdpAttachment => {
                let xdp_link_pin = self.xdp_link_pin_path();
                if std::path::Path::new(&xdp_link_pin).exists() {
                    std::fs::remove_file(&xdp_link_pin).map_err(|e| {
                        format!("[{}] Failed to remove pinned XDP link: {}", self.iface, e)
                    })?;
                } else {
                    self.detach_xdp_with_ip()?;
                }
                info!(instance = %self.iface, "rolled back newly attached XDP link");
                Ok(())
            }
            LinkRollbackAction::RemoveTcLinkPin(prog_name) => {
                let link_pin = self.tc_link_pin_path(prog_name);
                if std::path::Path::new(&link_pin).exists() {
                    std::fs::remove_file(&link_pin).map_err(|e| {
                        format!(
                            "[{}] Failed to remove pinned {} link: {}",
                            self.iface, prog_name, e
                        )
                    })?;
                }
                info!(instance = %self.iface, program = %prog_name, "rolled back newly attached TC link");
                Ok(())
            }
            LinkRollbackAction::RemoveRuntimePinPath => {
                if self.pin_path.exists() {
                    std::fs::remove_dir_all(&self.pin_path).map_err(|e| {
                        format!("[{}] Failed to remove pin directory: {}", self.iface, e)
                    })?;
                    info!(instance = %self.iface, "runtime pin directory cleaned after rollback");
                }
                Ok(())
            }
        })
    }

    fn load_runtime_programs(&self, bpf: &mut aya::Ebpf) -> Result<Vec<String>, String> {
        {
            let xdp_program = bpf
                .program_mut("xdp_firewall")
                .ok_or_else(|| format!("[{}] XDP program not found", self.iface))?;

            let xdp: &mut aya::programs::Xdp =
                xdp_program
                    .try_into()
                    .map_err(|e: aya::programs::ProgramError| {
                        format!("[{}] xdp try_into error: {:?}", self.iface, e)
                    })?;

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
        let tc_program = bpf
            .program_mut(prog_name)
            .ok_or_else(|| format!("{} program not found", prog_name))?;

        let tc: &mut aya::programs::SchedClassifier = tc_program
            .try_into()
            .map_err(|e: aya::programs::ProgramError| format!("{} try_into: {:?}", prog_name, e))?;

        tc.load()
            .map_err(|e| format!("{} load: {:?}", prog_name, e))
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
            required_program_ref.pin(required_target).map_err(|e| {
                format!(
                    "failed to pin required runtime program {}: {:?}",
                    required_program, e
                )
            })?;
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
        let xdp_link = xdp
            .take_link(link_id)
            .map_err(|e| format!("take_link: {:?}", e))?;
        let fd_link: aya::programs::links::FdLink = xdp_link
            .try_into()
            .map_err(|e: aya::programs::links::LinkError| format!("FdLink convert: {:?}", e))?;
        fd_link.pin(pin_path).map_err(|e| format!("pin: {:?}", e))?;
        Ok(())
    }

    fn tc_prog_pin_path(&self, prog_name: &str) -> String {
        format!("{}/{}", self.pin_path.display(), prog_name)
    }

    fn ensure_tc_runtime(&self, attached: &mut AttachedLinks) {
        let tc_programs = [
            (
                "tc_egress",
                aya::programs::tc::TcAttachType::Egress,
                "Egress control",
            ),
            (
                "tc_ingress",
                aya::programs::tc::TcAttachType::Ingress,
                "Ingress mirror",
            ),
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

    fn set_tc_link_ownership(
        attached: &mut AttachedLinks,
        prog_name: &str,
        ownership: LinkOwnership,
    ) {
        match prog_name {
            "tc_egress" => attached.tc_egress = ownership,
            "tc_ingress" => attached.tc_ingress = ownership,
            _ => {}
        }
    }

    fn ensure_fq_runtime(&mut self) {
        let Some(state_path_str) = self.state_path.to_str() else {
            warn!(
                instance = %self.iface,
                state_path = %self.state_path.display(),
                "non-UTF-8 state path; skipping persisted QoS shaping check"
            );
            self.edt_available = aria_core::ebpf_ops::check_fq_qdisc(&self.iface);
            return;
        };
        let state = aria_core::wal::load_with_wal(state_path_str);
        let requires_shaping = state.qos_rules.iter().any(|rule| rule.mode == 1);

        if requires_shaping {
            match aria_core::ebpf_ops::ensure_fq_qdisc(&self.iface) {
                Ok(aria_core::ebpf_ops::FqQdiscState::InstalledNow) => {
                    self.edt_available = true;
                    self.mark_owned_fq_qdisc();
                }
                Ok(aria_core::ebpf_ops::FqQdiscState::AlreadyPresent) => {
                    self.edt_available = true;
                }
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
    fn attach_xdp_from_pin(
        &self,
        prog_pin: &str,
        xdp_link_pin: &str,
    ) -> Result<(), XdpAttachFailure> {
        let mut xdp =
            aya::programs::Xdp::from_pin(prog_pin, aya_obj::programs::XdpAttachType::Interface)
                .map_err(|e| {
                    XdpAttachFailure::safe(format!(
                        "[{}] XDP from_pin during recovery: {:?}",
                        self.iface, e
                    ))
                })?;

        let link_id = xdp
            .attach(&self.iface, aya::programs::XdpFlags::default())
            .map_err(|e| {
                XdpAttachFailure::safe(format!(
                    "[{}] xdp.attach during recovery: {:?}",
                    self.iface, e
                ))
            })?;

        if let Err(pin_error) = self.try_pin_xdp_link(&mut xdp, link_id, xdp_link_pin) {
            return recover_unpinned_xdp_attachment(pin_error, || self.detach_xdp_with_ip());
        }
        info!(instance = %self.iface, "recovered XDP link pin");
        Ok(())
    }

    fn detach_xdp_with_ip(&self) -> Result<(), String> {
        checked_xdp_detach_output(
            &self.iface,
            std::process::Command::new("ip")
                .args(["link", "set", "dev", &self.iface, "xdp", "off"])
                .output(),
        )
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

        let link_id = tc
            .attach(&self.iface, attach_type)
            .map_err(|e| format!("{} attach from pin: {:?}", prog_name, e))?;

        let tc_link = tc
            .take_link(link_id)
            .map_err(|e| format!("take_link: {:?}", e))?;
        let fd_link: aya::programs::links::FdLink = tc_link
            .try_into()
            .map_err(|e: aya::programs::links::LinkError| format!("FdLink: {:?}", e))?;
        let link_pin = self.tc_link_pin_path(prog_name);
        fd_link.pin(&link_pin).map_err(|e| format!("pin: {:?}", e))?;
        info!(instance = %self.iface, direction = %dir_str, "TC program reattached from pinned runtime");

        Ok(())
    }

    fn detach_with_cleanup(&self, remove_pin_path: bool) -> Result<(), String> {
        let xdp_link_pin = self.xdp_link_pin_path();
        let mut errors = Vec::new();

        if std::path::Path::new(&xdp_link_pin).exists() {
            match std::fs::remove_file(&xdp_link_pin) {
                Ok(()) => info!(instance = %self.iface, "XDP link unpinned"),
                Err(error) => errors.push(format!(
                    "[{}] Failed to remove pinned XDP link: {}",
                    self.iface, error
                )),
            }
        }

        for prog_name in ["tc_egress", "tc_ingress"] {
            let link_pin = self.tc_link_pin_path(prog_name);
            if std::path::Path::new(&link_pin).exists() {
                match std::fs::remove_file(&link_pin) {
                    Ok(()) => info!(instance = %self.iface, program = %prog_name, "TC link unpinned"),
                    Err(error) => errors.push(format!(
                        "[{}] Failed to remove pinned {} link: {}",
                        self.iface, prog_name, error
                    )),
                }
            }
        }

        if let Err(error) = self.cleanup_owned_fq_qdisc() {
            errors.push(error);
        }

        // Clean up pinned runtime dir only for non-shared runtimes or explicit rollback.
        if remove_pin_path && self.pin_path.exists() {
            match std::fs::remove_dir_all(&self.pin_path) {
                Ok(()) => info!(instance = %self.iface, "pin directory cleaned"),
                Err(error) => errors.push(format!(
                    "[{}] Failed to remove pin directory: {}",
                    self.iface, error
                )),
            }
        }

        if !errors.is_empty() {
            return Err(errors.join("; "));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tc_acl_link_health_requires_both_directions_but_not_xdp() {
        assert!(TcAclLinkHealth::new(true, true, false).acl_ready());
        assert!(!TcAclLinkHealth::new(true, false, true).acl_ready());
        assert!(!TcAclLinkHealth::new(false, true, true).acl_ready());
        assert!(TcAclLinkHealth::new(true, true, true).xdp_ready());
        assert!(!TcAclLinkHealth::new(true, true, false).xdp_ready());
    }

    #[test]
    fn tcx_attachment_query_requires_the_expected_program_id() {
        assert!(tcx_query_contains_expected_program(42, &[7, 42, 99]));
        assert!(!tcx_query_contains_expected_program(42, &[]));
        assert!(!tcx_query_contains_expected_program(42, &[7, 41, 99]));
    }

    #[test]
    fn standalone_review_program_pin_completeness_requires_links_and_programs() {
        let pin_path = std::env::temp_dir().join(format!(
            "aria-standalone-runtime-health-{}",
            std::process::id()
        ));
        if pin_path.exists() {
            std::fs::remove_dir_all(&pin_path).unwrap();
        }
        std::fs::create_dir_all(&pin_path).unwrap();
        let state_path = pin_path.join("state");
        std::fs::create_dir_all(&state_path).unwrap();

        let instance = FirewallInstance::new(
            "standalone-review",
            pin_path.clone(),
            state_path,
            false,
            TraceMapMode::Legacy,
        );
        std::fs::write(pin_path.join("tc_ingress_link"), b"link").unwrap();
        std::fs::write(pin_path.join("tc_egress_link"), b"link").unwrap();

        let missing_programs = instance.require_tc_acl_runtime().unwrap_err();
        assert!(missing_programs.contains("tc_ingress program"));
        assert!(missing_programs.contains("tc_egress program"));

        std::fs::write(pin_path.join("tc_ingress"), b"program").unwrap();
        std::fs::write(pin_path.join("tc_egress"), b"program").unwrap();
        instance.require_tc_acl_runtime().unwrap();

        std::fs::remove_file(pin_path.join("tc_ingress_link")).unwrap();
        assert!(instance
            .require_tc_acl_runtime()
            .unwrap_err()
            .contains("tc_ingress link"));

        std::fs::remove_dir_all(pin_path).unwrap();
    }

    #[test]
    fn neutron_tc_acl_requires_both_direction_links() {
        assert!(tc_acl_links_complete(true, true));
        assert!(!tc_acl_links_complete(true, false));
        assert!(!tc_acl_links_complete(false, true));
        assert!(!tc_acl_links_complete(false, false));
    }

    #[test]
    fn managed_failure_path_cleanup_plan_preserves_claimed_direction() {
        let mixed = AttachedLinks {
            xdp: LinkOwnership::ClaimedExisting,
            tc_egress: LinkOwnership::ClaimedExisting,
            tc_ingress: LinkOwnership::AttachedNow,
        };

        assert_eq!(
            rollback_link_cleanup_plan(&mixed, true),
            vec![LinkRollbackAction::RemoveTcLinkPin("tc_ingress")]
        );

        let reversed = AttachedLinks {
            xdp: LinkOwnership::Absent,
            tc_egress: LinkOwnership::AttachedNow,
            tc_ingress: LinkOwnership::ClaimedExisting,
        };
        assert_eq!(
            rollback_link_cleanup_plan(&reversed, false),
            vec![LinkRollbackAction::RemoveTcLinkPin("tc_egress")]
        );
    }

    #[test]
    fn managed_failure_path_cleanup_continues_after_error() {
        let plan = vec![
            LinkRollbackAction::RemoveXdpAttachment,
            LinkRollbackAction::RemoveTcLinkPin("tc_egress"),
            LinkRollbackAction::RemoveTcLinkPin("tc_ingress"),
            LinkRollbackAction::RemoveRuntimePinPath,
        ];
        let mut attempted = Vec::new();

        let error = execute_rollback_cleanup_plan(&plan, |action| {
            attempted.push(action);
            if action == LinkRollbackAction::RemoveXdpAttachment {
                Err("forced xdp cleanup failure".to_string())
            } else {
                Ok(())
            }
        })
        .unwrap_err();

        assert_eq!(attempted, plan);
        assert!(error.contains("forced xdp cleanup failure"));
    }

    #[test]
    fn managed_failure_path_xdp_pin_failure_is_never_acknowledged() {
        let detach_calls = std::cell::Cell::new(0);
        let error = recover_unpinned_xdp_attachment("forced pin failure", || {
            detach_calls.set(detach_calls.get() + 1);
            Ok(())
        })
        .unwrap_err();

        assert_eq!(detach_calls.get(), 1);
        assert!(!error.attachment_may_remain());
        assert!(error.to_string().contains("forced pin failure"));
        assert!(error.to_string().contains("detached"));

        let error = recover_unpinned_xdp_attachment("forced pin failure", || {
            Err("forced detach failure".to_string())
        })
        .unwrap_err();
        assert!(error.attachment_may_remain());
        assert!(error.to_string().contains("forced pin failure"));
        assert!(error.to_string().contains("forced detach failure"));
    }

    #[test]
    fn managed_failure_path_xdp_detach_command_failure_propagates() {
        let spawn_error = checked_xdp_detach_output(
            "tap-failure",
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "forced spawn failure",
            )),
        )
        .unwrap_err();
        assert!(spawn_error.contains("forced spawn failure"));

        let nonzero = std::process::Command::new("sh")
            .args([
                "-c",
                "printf 'forced detach stderr' >&2; exit 23",
            ])
            .output();
        let status_error = checked_xdp_detach_output("tap-failure", nonzero).unwrap_err();
        assert!(status_error.contains("forced detach stderr"));
        assert!(status_error.contains("23"));
    }
}
