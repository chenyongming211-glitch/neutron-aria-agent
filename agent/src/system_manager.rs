use crate::control_plane::ControlPlane;
use crate::instance::{
    classify_legacy_tc_cleanup, configure_fragment_context_capacity,
    finalize_fragment_recovery_with_tc_fallback, FirewallInstance, TcAclLinkHealth,
};
use crate::xdp_link_health::{
    existing_xdp_pin_disposition, ExistingXdpPinDisposition,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{info, warn};

use aria_core::common::TapMapRuntime;
use aria_core::ebpf_ops::{
    cleanup_root_qdisc, critical_network_map_names, ensure_fq_qdisc,
    replay_standalone_state_to_pinned_maps_from_snapshot, replay_state_from_snapshot,
    scrub_standalone_runtime_state, FqQdiscState, TraceMapMode, NETWORK_MAP_NAMES,
};

const FQ_QDISC_MARKER: &str = ".fq-root-qdisc-owned";

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum SystemAclActivation {
    Restore { conntrack: bool, acl: bool },
    StayDisabled,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum ClsactOwnership {
    Absent,
    Preexisting,
    Created,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum SystemTcDirection {
    Ingress,
    Egress,
}

impl SystemTcDirection {
    fn program_name(self) -> &'static str {
        match self {
            Self::Ingress => "tc_ingress",
            Self::Egress => "tc_egress",
        }
    }

    fn attach_type(self) -> aya::programs::tc::TcAttachType {
        match self {
            Self::Ingress => aya::programs::tc::TcAttachType::Ingress,
            Self::Egress => aya::programs::tc::TcAttachType::Egress,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum SystemTcAttachOutcome {
    Pinned,
    Legacy { priority: u16, handle: u32 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SystemStartOwnership {
    xdp_link: bool,
    tc_egress_link: bool,
    tc_ingress_link: bool,
    clsact: ClsactOwnership,
    owned_map_pins: Vec<PathBuf>,
    owned_program_pins: Vec<PathBuf>,
    owned_link_pins: Vec<PathBuf>,
    owned_legacy_tc: Vec<SystemTcDirection>,
    owned_runtime_dirs: Vec<PathBuf>,
    fq_root_qdisc: bool,
}

impl SystemStartOwnership {
    fn new() -> Self {
        Self {
            xdp_link: false,
            tc_egress_link: false,
            tc_ingress_link: false,
            clsact: ClsactOwnership::Absent,
            owned_map_pins: Vec::new(),
            owned_program_pins: Vec::new(),
            owned_link_pins: Vec::new(),
            owned_legacy_tc: Vec::new(),
            owned_runtime_dirs: Vec::new(),
            fq_root_qdisc: false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum SystemCleanupAction {
    DetachOwnedLegacyTc(SystemTcDirection),
    RemoveOwnedPin(PathBuf),
    RemoveOwnedClsact,
    RemoveOwnedRuntimeDirectory(PathBuf),
}

fn failed_start_cleanup_plan(ownership: &SystemStartOwnership) -> Vec<SystemCleanupAction> {
    let mut plan = Vec::new();
    for direction in ownership.owned_legacy_tc.iter().rev() {
        plan.push(SystemCleanupAction::DetachOwnedLegacyTc(*direction));
    }
    for path in ownership
        .owned_link_pins
        .iter()
        .chain(ownership.owned_program_pins.iter())
        .chain(ownership.owned_map_pins.iter())
    {
        plan.push(SystemCleanupAction::RemoveOwnedPin(path.clone()));
    }
    if ownership.clsact == ClsactOwnership::Created {
        plan.push(SystemCleanupAction::RemoveOwnedClsact);
    }
    for path in ownership.owned_runtime_dirs.iter().rev() {
        plan.push(SystemCleanupAction::RemoveOwnedRuntimeDirectory(path.clone()));
    }
    plan
}

fn preexisting_system_tc_runtime_is_healthy(
    enforcement_required: bool,
    preexisting_live_runtime: bool,
    live_health: TcAclLinkHealth,
) -> Result<bool, String> {
    if !preexisting_live_runtime {
        return Ok(false);
    }
    if enforcement_required && !live_health.acl_ready() {
        return Err(format!(
            "preexisting standalone ACL/CT runtime is incomplete: {}",
            live_health.missing_tc().join(", ")
        ));
    }
    Ok(true)
}

fn owned_program_pin(
    ownership: &SystemStartOwnership,
    program: &str,
) -> Option<SystemCleanupAction> {
    ownership
        .owned_program_pins
        .iter()
        .find(|path| path.file_name().and_then(|name| name.to_str()) == Some(program))
        .cloned()
        .map(SystemCleanupAction::RemoveOwnedPin)
}

fn owned_link_pin(
    ownership: &SystemStartOwnership,
    link: &str,
) -> Option<SystemCleanupAction> {
    ownership
        .owned_link_pins
        .iter()
        .find(|path| path.file_name().and_then(|name| name.to_str()) == Some(link))
        .cloned()
        .map(SystemCleanupAction::RemoveOwnedPin)
}

fn unbacked_program_link_cleanup_plan(
    ownership: &SystemStartOwnership,
    program_health: TcAclLinkHealth,
) -> Vec<SystemCleanupAction> {
    let mut plan = Vec::new();
    if ownership.xdp_link && !program_health.xdp {
        if let Some(action) = owned_link_pin(ownership, "xdp_link") {
            plan.push(action);
        }
    }
    if ownership.tc_egress_link && !program_health.egress {
        if let Some(action) = owned_link_pin(ownership, "tc_egress_link") {
            plan.push(action);
        }
    } else if !ownership.tc_egress_link && program_health.egress {
        if let Some(action) = owned_program_pin(ownership, "tc_egress") {
            plan.push(action);
        }
    }
    if ownership.tc_ingress_link && !program_health.ingress {
        if let Some(action) = owned_link_pin(ownership, "tc_ingress_link") {
            plan.push(action);
        }
    } else if !ownership.tc_ingress_link && program_health.ingress {
        if let Some(action) = owned_program_pin(ownership, "tc_ingress") {
            plan.push(action);
        }
    }
    plan
}

fn execute_system_cleanup_plan<F>(
    plan: &[SystemCleanupAction],
    mut cleanup: F,
) -> Result<(), String>
where
    F: FnMut(SystemCleanupAction) -> Result<(), String>,
{
    let mut errors = Vec::new();
    for action in plan {
        if let Err(error) = cleanup(action.clone()) {
            errors.push(error);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn missing_runtime_directories(path: &Path) -> Vec<PathBuf> {
    let mut missing = Vec::new();
    let mut cursor = Some(path);
    while let Some(current) = cursor {
        if current.exists() {
            break;
        }
        missing.push(current.to_path_buf());
        cursor = current.parent();
    }
    missing.reverse();
    missing
}

fn cleanup_empty_runtime_directories(paths: &[PathBuf]) -> Result<(), String> {
    let mut errors = Vec::new();
    for path in paths.iter().rev() {
        if !path.exists() {
            continue;
        }
        if let Err(error) = fs::remove_dir(path) {
            errors.push(format!(
                "failed to remove transaction-created runtime directory {}: {}",
                path.display(),
                error
            ));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn create_runtime_pin_directories_with<F>(
    path: &Path,
    create: F,
) -> Result<Vec<PathBuf>, String>
where
    F: FnOnce(&Path) -> std::io::Result<()>,
{
    let owned_directories = missing_runtime_directories(path);
    match create(path) {
        Ok(()) => Ok(owned_directories),
        Err(error) => match cleanup_empty_runtime_directories(&owned_directories) {
            Ok(()) => Err(format!("Failed to create pin directory: {}", error)),
            Err(cleanup_error) => Err(format!(
                "Failed to create pin directory: {}; partial directory cleanup failed: {}",
                error, cleanup_error
            )),
        },
    }
}

fn create_runtime_pin_directories(path: &Path) -> Result<Vec<PathBuf>, String> {
    create_runtime_pin_directories_with(path, |candidate| fs::create_dir_all(candidate))
}

fn system_acl_activation(
    desired_conntrack: bool,
    desired_acl: bool,
    health: TcAclLinkHealth,
) -> Result<SystemAclActivation, String> {
    if !desired_conntrack && !desired_acl {
        return Ok(SystemAclActivation::StayDisabled);
    }
    if !health.acl_ready() {
        return Err(format!(
            "standalone ACL/CT requires healthy dual TC attachments: {}",
            health.missing_tc().join(", ")
        ));
    }
    Ok(SystemAclActivation::Restore {
        conntrack: desired_conntrack,
        acl: desired_acl,
    })
}

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

    let iface_sys_path = Path::new("/sys/class/net").join(iface);
    if !iface_sys_path.exists() {
        fs::remove_file(&marker_path).map_err(|e| {
            format!(
                "failed to remove FQ qdisc ownership marker for gone device {}: {}",
                marker_path.display(),
                e
            )
        })?;
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

fn remove_pin_file_if_present(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    fs::remove_file(path).map_err(|e| format!("failed to remove {}: {}", path.display(), e))
}

fn checked_tc_output(iface: &str, args: &[&str], operation: &str) -> Result<Vec<u8>, String> {
    let output = std::process::Command::new("tc")
        .args(args)
        .output()
        .map_err(|e| format!("{} on {} could not start: {}", operation, iface, e))?;
    if output.status.success() {
        return Ok(output.stdout);
    }
    Err(format!(
        "{} on {} failed ({}): {}",
        operation,
        iface,
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

fn remove_owned_clsact(iface: &str) -> Result<(), String> {
    for direction in ["ingress", "egress"] {
        let output = checked_tc_output(
            iface,
            &["filter", "show", "dev", iface, direction],
            "inspect clsact filters",
        )?;
        if !String::from_utf8_lossy(&output).trim().is_empty() {
            return Err(format!(
                "preserving transaction-created clsact on {} because unrelated {} filters remain",
                iface, direction
            ));
        }
    }
    checked_tc_output(
        iface,
        &["qdisc", "del", "dev", iface, "clsact"],
        "remove owned clsact",
    )?;
    Ok(())
}

fn execute_system_cleanup_action(
    action: SystemCleanupAction,
    iface: &str,
    _pin_path: &str,
) -> Result<(), String> {
    match action {
        SystemCleanupAction::DetachOwnedLegacyTc(direction) => {
            classify_legacy_tc_cleanup(
                aya::programs::tc::qdisc_detach_program(
                    iface,
                    direction.attach_type(),
                    direction.program_name(),
                ),
                direction.program_name(),
            )
            .map(|_| ())
        }
        SystemCleanupAction::RemoveOwnedPin(path) => remove_pin_file_if_present(&path),
        SystemCleanupAction::RemoveOwnedClsact => remove_owned_clsact(iface),
        SystemCleanupAction::RemoveOwnedRuntimeDirectory(path) => {
            if path.exists() {
                fs::remove_dir(&path).map_err(|e| {
                    format!(
                        "failed to remove owned runtime directory {}: {}",
                        path.display(),
                        e
                    )
                })?;
            }
            Ok(())
        }
    }
}

fn cleanup_failed_start(
    iface: &str,
    pin_path: &str,
    state_path: &str,
    ownership: &SystemStartOwnership,
) -> Result<(), String> {
    let mut errors = Vec::new();
    let plan = failed_start_cleanup_plan(ownership);
    if let Err(error) = execute_system_cleanup_plan(&plan, |action| {
        execute_system_cleanup_action(action, iface, pin_path)
    }) {
        errors.push(error);
    }
    if ownership.fq_root_qdisc {
        if let Err(error) = cleanup_owned_root_qdisc(iface, state_path) {
            errors.push(error);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn start_error_with_cleanup(
    error: impl Into<String>,
    iface: &str,
    pin_path: &str,
    state_path: &str,
    ownership: &SystemStartOwnership,
) -> String {
    let error = error.into();
    match cleanup_failed_start(iface, pin_path, state_path, ownership) {
        Ok(()) => error,
        Err(cleanup_error) => format!("{}; standalone cleanup failed: {}", error, cleanup_error),
    }
}

fn ensure_clsact(iface: &str) -> Result<ClsactOwnership, String> {
    match aya::programs::tc::qdisc_add_clsact(iface) {
        Ok(()) => Ok(ClsactOwnership::Created),
        Err(error) => {
            let error = format!("{:?}", error);
            if error.contains("File exists") {
                Ok(ClsactOwnership::Preexisting)
            } else {
                Err(format!("qdisc_add_clsact: {}", error))
            }
        }
    }
}

fn pin_runtime_maps(
    bpf: &mut aya::Ebpf,
    pin_path: &str,
    trace_map_mode: TraceMapMode,
    ownership: &mut SystemStartOwnership,
) -> Result<(), String> {
    let critical_map_names = critical_network_map_names(trace_map_mode);
    for name in NETWORK_MAP_NAMES {
        if let Some(map) = bpf.map_mut(name) {
            let target = Path::new(pin_path).join(name);
            let target_preexisting = target.exists();
            if target_preexisting {
                continue;
            }
            if let Err(e) = map.pin(&target) {
                if critical_map_names.contains(name) {
                    return Err(format!("failed to pin critical map {}: {}", name, e));
                }
                warn!(map = %name, error = %e, "failed to pin runtime map");
            } else {
                ownership.owned_map_pins.push(target);
            }
        } else if critical_map_names.contains(name) {
            return Err(format!("critical map {} not found", name));
        }
    }
    Ok(())
}

fn pin_runtime_programs(
    bpf: &mut aya::Ebpf,
    pin_path: &str,
    require_tc_acl: bool,
    claimed_health: TcAclLinkHealth,
    ownership: &mut SystemStartOwnership,
) -> TcAclLinkHealth {
    let mut ingress = false;
    let mut egress = false;
    let mut xdp = false;
    for name in &["xdp_firewall", "tc_egress", "tc_ingress"] {
        let target = Path::new(pin_path).join(name);
        let target_preexisting = target.exists();
        let claimed = match *name {
            "xdp_firewall" => claimed_health.xdp,
            "tc_ingress" => claimed_health.ingress,
            "tc_egress" => claimed_health.egress,
            _ => false,
        };
        let result = if claimed {
            Ok(())
        } else {
            match bpf.program_mut(name) {
                Some(program) => program
                    .pin(&target)
                    .map_err(|e| format!("Failed to pin program {}: {:?}", name, e)),
                None => Err(format!("Program {} not found", name)),
            }
        };
        if result.is_ok() && !claimed && !target_preexisting {
            ownership.owned_program_pins.push(target);
        }
        match (*name, result) {
            ("xdp_firewall", Ok(())) => xdp = true,
            ("tc_ingress", Ok(())) => ingress = true,
            ("tc_egress", Ok(())) => egress = true,
            ("xdp_firewall", Err(error)) => {
                warn!(error = %error, "XDP program pin unavailable; XDP health degraded");
            }
            (tc_name, Err(error)) if require_tc_acl => {
                warn!(program = %tc_name, error = %error, "required TC ACL program pin unavailable");
            }
            (tc_name, Err(error)) => {
                warn!(program = %tc_name, error = %error, "optional TC runtime program pin unavailable");
            }
            _ => {}
        }
    }
    TcAclLinkHealth::new(ingress, egress, xdp)
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
    (|| -> Result<(), String> {
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
    })()?;
    info!(iface = %iface, "XDP link pinned");

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
    let _lifecycle_guard = control_plane.lock_runtime_lifecycle().await;
    let mut ownership = SystemStartOwnership::new();
    ownership.owned_runtime_dirs = create_runtime_pin_directories(Path::new(pin_path))?;
    if let Err(error) = fs::create_dir_all(state_path) {
        return Err(start_error_with_cleanup(
            format!("Failed to create state directory: {}", error),
            iface,
            pin_path,
            state_path,
            &ownership,
        ));
    }

    // Set max_port_policies
    let sm = aria_core::state::StateManager::new(state_path);
    if let Err(e) = sm.set_max_port_policies(max_port_policies) {
        warn!(iface = %iface, error = %e, "failed to persist max_port_policies");
    }

    let desired = aria_core::wal::load_with_wal(state_path);
    let desired_conntrack = desired.conntrack_enabled;
    let desired_acl = desired.acl_enabled;
    let fragment_tracking = control_plane.fragment_tracking_settings();

    info!(iface = %iface, ebpf_path = %ebpf_path, "loading eBPF for system instance");
    let bpf_bytes = std::fs::read(ebpf_path).map_err(|error| {
        start_error_with_cleanup(
            format!("read ebpf: {}", error),
            iface,
            pin_path,
            state_path,
            &ownership,
        )
    })?;
    let mut loader = aya::EbpfLoader::new();
    configure_fragment_context_capacity(&mut loader, fragment_tracking.max_entries).map_err(
        |error| start_error_with_cleanup(error, iface, pin_path, state_path, &ownership),
    )?;
    let mut bpf = loader
        .map_pin_path(pin_path)
        .load(&bpf_bytes)
        .map_err(|error| {
            start_error_with_cleanup(
                format!("load error: {:?}", error),
                iface,
                pin_path,
                state_path,
                &ownership,
            )
        })?;
    let trace_map_mode = control_plane.trace_map_mode();

    // Pin all maps before attaching any programs so replay can rebuild runtime state
    // before packets hit the dataplane.
    if let Err(e) = pin_runtime_maps(&mut bpf, pin_path, trace_map_mode, &mut ownership) {
        return Err(start_error_with_cleanup(
            e,
            iface,
            pin_path,
            state_path,
            &ownership,
        ));
    }

    let preexisting_xdp_link = Path::new(pin_path).join("xdp_link").exists();
    let preexisting_tc_ingress_link = Path::new(pin_path).join("tc_ingress_link").exists();
    let preexisting_tc_egress_link = Path::new(pin_path).join("tc_egress_link").exists();
    let preexisting_instance = FirewallInstance::new(
        iface,
        pin_path.to_string().into(),
        state_path.to_string().into(),
        false,
        trace_map_mode,
    );
    let preexisting_health = preexisting_instance.tc_acl_link_health();
    let preexisting_live_runtime = preexisting_xdp_link
        || preexisting_tc_ingress_link
        || preexisting_tc_egress_link
        || preexisting_health.ingress
        || preexisting_health.egress;

    if preexisting_live_runtime {
        if let Err(e) = aria_core::ebpf_ops::update_firewall_config(
            TapMapRuntime::new(pin_path, aria_core::common::TAP_ID_UNASSIGNED),
            Some(false),
            None,
            Some(false),
            None,
            None,
            None,
            None,
        ) {
            return Err(start_error_with_cleanup(
                format!("failed to quiesce preexisting standalone ACL/CT runtime: {}", e),
                iface,
                pin_path,
                state_path,
                &ownership,
            ));
        }
    }

    if let Err(e) = preexisting_system_tc_runtime_is_healthy(
        desired_conntrack || desired_acl,
        preexisting_live_runtime,
        preexisting_health,
    ) {
        return Err(start_error_with_cleanup(
            format!("standalone pinned runtime validation failed after quiesce: {}", e),
            iface,
            pin_path,
            state_path,
            &ownership,
        ));
    }
    let fragment_recovery = aria_core::ebpf_ops::recover_fragment_runtime_configured_strict(
        pin_path,
        fragment_tracking
            .runtime_config(aria_core::common::FRAGMENT_RUNTIME_MODE_STANDALONE)
            .map_err(|error| {
                start_error_with_cleanup(error, iface, pin_path, state_path, &ownership)
            })?,
        fragment_tracking.max_entries,
    );
    if let Err(e) = finalize_fragment_recovery_with_tc_fallback(fragment_recovery, || {
        preexisting_instance.detach_fragment_tc_links_strict()
    }) {
        return Err(start_error_with_cleanup(
            format!("failed to recover standalone fragment runtime: {}", e),
            iface,
            pin_path,
            state_path,
            &ownership,
        ));
    }
    let reuse_preexisting_tc = preexisting_live_runtime && preexisting_health.acl_ready();

    let sm = aria_core::state::StateManager::new(state_path);
    match sm.get_tap_id() {
        Ok(tap_id) if tap_id != aria_core::common::TAP_ID_UNASSIGNED => {
            sm.set_tap_id(aria_core::common::TAP_ID_UNASSIGNED)
                .map_err(|e| {
                    start_error_with_cleanup(
                        format!("failed to reset system tap_id before replay: {}", e),
                        iface,
                        pin_path,
                        state_path,
                        &ownership,
                    )
                })?;
            info!(iface = %iface, stale_tap_id = tap_id, "reset stale system tap_id before replay");
        }
        Ok(_) => {}
        Err(e) => {
            return Err(start_error_with_cleanup(
                format!("failed to read system tap_id before replay: {}", e),
                iface,
                pin_path,
                state_path,
                &ownership,
            ));
        }
    }

    if let Err(e) = scrub_standalone_runtime_state(pin_path) {
        return Err(start_error_with_cleanup(
            format!("failed to scrub standalone runtime state before replay: {}", e),
            iface,
            pin_path,
            state_path,
            &ownership,
        ));
    }
    // Replay desired maps while keeping the live ACL/CT gate quiesced.
    let mut quiesced_desired = desired.clone();
    quiesced_desired.conntrack_enabled = false;
    quiesced_desired.acl_enabled = false;
    let replay_result = if reuse_preexisting_tc {
        replay_standalone_state_to_pinned_maps_from_snapshot(
            pin_path,
            state_path,
            &quiesced_desired,
        )
    } else {
        replay_state_from_snapshot(&mut bpf, state_path, &quiesced_desired)
    };
    if let Err(e) = replay_result {
        return Err(start_error_with_cleanup(
            format!("failed to replay state: {}", e),
            iface,
            pin_path,
            state_path,
            &ownership,
        ));
    }

    match ensure_fq_qdisc(iface) {
        Ok(FqQdiscState::InstalledNow) => {
            if let Err(e) = mark_owned_root_qdisc(state_path) {
                if let Err(cleanup_err) = cleanup_root_qdisc(iface) {
                    warn!(iface = %iface, error = %cleanup_err, "failed to roll back root qdisc after marker write failure");
                }
                return Err(start_error_with_cleanup(
                    e,
                    iface,
                    pin_path,
                    state_path,
                    &ownership,
                ));
            }
            ownership.fq_root_qdisc = true;
        }
        Ok(FqQdiscState::AlreadyPresent) => {}
        Err(e) => {
            warn!(iface = %iface, error = %e, "FQ qdisc setup failed; QoS EDT disabled");
        }
    }

    let xdp_link_pin = Path::new(pin_path).join("xdp_link");
    let xdp_link_preexisting = xdp_link_pin.exists();
    match existing_xdp_pin_disposition(
        xdp_link_preexisting,
        preexisting_health.xdp_ready(),
    ) {
        ExistingXdpPinDisposition::Claim => {
            ownership.xdp_link = true;
            info!(iface = %iface, "claimed exact preexisting XDP DDoS hook");
        }
        ExistingXdpPinDisposition::PreserveDegraded => {
            warn!(
                iface = %iface,
                reason = "identity_unverified",
                "preexisting XDP link identity is not verified; preserving pin without claiming or replacing it"
            );
        }
        ExistingXdpPinDisposition::Attach => {
            match attach_xdp_program(&mut bpf, iface, pin_path) {
                Ok(()) => {
                    ownership.xdp_link = true;
                    ownership.owned_link_pins.push(xdp_link_pin);
                }
                Err(error) => {
                    warn!(iface = %iface, error = %error, "XDP DDoS hook unavailable; continuing with TC ACL");
                }
            }
        }
    }

    match ensure_clsact(iface) {
        Ok(clsact) => ownership.clsact = clsact,
        Err(error) => {
            warn!(iface = %iface, error = %error, "TC clsact unavailable; TC ACL disabled");
        }
    }
    if ownership.clsact != ClsactOwnership::Absent {
        if reuse_preexisting_tc {
            ownership.tc_ingress_link = true;
            ownership.tc_egress_link = true;
            info!(iface = %iface, "claimed exact preexisting dual-TC ACL runtime");
        } else {
            let tc_egress_link_pin = Path::new(pin_path).join("tc_egress_link");
            let tc_egress_link_preexisting = tc_egress_link_pin.exists();
            match attach_tc_program(
                &mut bpf,
                SystemTcDirection::Egress,
                iface,
                pin_path,
            ) {
                Ok(SystemTcAttachOutcome::Pinned) => {
                    ownership.tc_egress_link = true;
                    if !tc_egress_link_preexisting {
                        ownership.owned_link_pins.push(tc_egress_link_pin);
                    }
                }
                Ok(SystemTcAttachOutcome::Legacy { priority, handle }) => {
                    ownership.tc_egress_link = true;
                    ownership.owned_legacy_tc.push(SystemTcDirection::Egress);
                    info!(iface = %iface, direction = "egress", priority, handle, "TC program attached with legacy netlink filter");
                }
                Err(error) => {
                    warn!(iface = %iface, error = %error, "TC egress attach failed; egress control disabled");
                }
            }

            let tc_ingress_link_pin = Path::new(pin_path).join("tc_ingress_link");
            let tc_ingress_link_preexisting = tc_ingress_link_pin.exists();
            match attach_tc_program(
                &mut bpf,
                SystemTcDirection::Ingress,
                iface,
                pin_path,
            ) {
                Ok(SystemTcAttachOutcome::Pinned) => {
                    ownership.tc_ingress_link = true;
                    if !tc_ingress_link_preexisting {
                        ownership.owned_link_pins.push(tc_ingress_link_pin);
                    }
                }
                Ok(SystemTcAttachOutcome::Legacy { priority, handle }) => {
                    ownership.tc_ingress_link = true;
                    ownership.owned_legacy_tc.push(SystemTcDirection::Ingress);
                    info!(iface = %iface, direction = "ingress", priority, handle, "TC program attached with legacy netlink filter");
                }
                Err(error) => {
                    warn!(iface = %iface, error = %error, "TC ingress attach failed; ingress mirror disabled");
                }
            }
        }
    }

    let claimed_health = TcAclLinkHealth::new(
        reuse_preexisting_tc,
        reuse_preexisting_tc,
        xdp_link_preexisting && preexisting_health.xdp_ready(),
    );
    let program_health = pin_runtime_programs(
        &mut bpf,
        pin_path,
        desired_conntrack || desired_acl,
        claimed_health,
        &mut ownership,
    );
    let split_cleanup = unbacked_program_link_cleanup_plan(&ownership, program_health);
    if let Err(error) = execute_system_cleanup_plan(&split_cleanup, |action| {
        execute_system_cleanup_action(action, iface, pin_path)
    }) {
        return Err(start_error_with_cleanup(
            format!("failed to roll back link without matching program pin: {}", error),
            iface,
            pin_path,
            state_path,
            &ownership,
        ));
    }
    if !program_health.xdp {
        ownership.xdp_link = false;
    }
    if !program_health.egress {
        ownership.tc_egress_link = false;
    }
    if !program_health.ingress {
        ownership.tc_ingress_link = false;
    }
    let health = FirewallInstance::new(
        iface,
        pin_path.to_string().into(),
        state_path.to_string().into(),
        false,
        trace_map_mode,
    )
    .tc_acl_link_health();
    ownership.tc_ingress_link = health.ingress;
    ownership.tc_egress_link = health.egress;
    ownership.xdp_link = health.xdp;
    if let Err(error) = system_acl_activation(desired_conntrack, desired_acl, health) {
        return Err(start_error_with_cleanup(
            error,
            iface,
            pin_path,
            state_path,
            &ownership,
        ));
    }
    if ownership.clsact == ClsactOwnership::Created
        && !ownership.tc_ingress_link
        && !ownership.tc_egress_link
    {
        if let Err(error) = execute_system_cleanup_action(
            SystemCleanupAction::RemoveOwnedClsact,
            iface,
            pin_path,
        ) {
            return Err(start_error_with_cleanup(
                error,
                iface,
                pin_path,
                state_path,
                &ownership,
            ));
        }
        ownership.clsact = ClsactOwnership::Absent;
    }

    if let Err(e) = sm.set_attached_iface(iface) {
        warn!(iface = %iface, error = %e, "failed to record attached interface");
    }

    // Register with control plane
    if let Err(e) = control_plane
        .register_system_instance(pin_path, state_path, desired, iface)
        .await
    {
        if let Err(clear_err) = sm.clear_attached_iface() {
            warn!(iface = %iface, error = %clear_err, "failed to clear attached interface record after register failure");
        }
        return Err(start_error_with_cleanup(
            format!("control-plane register failed: {}", e),
            iface,
            pin_path,
            state_path,
            &ownership,
        ));
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
    let _lifecycle_guard = control_plane.lock_runtime_lifecycle().await;
    let sm = aria_core::state::StateManager::new(state_path);
    let mut errors = Vec::new();
    match sm.get_attached_iface() {
        Ok(Some(iface)) => {
            let instance = FirewallInstance::new(
                &iface,
                pin_path.to_string().into(),
                state_path.to_string().into(),
                false,
                control_plane.trace_map_mode(),
            );
            for direction in [SystemTcDirection::Egress, SystemTcDirection::Ingress] {
                let link_pin = Path::new(pin_path)
                    .join(format!("{}_link", direction.program_name()));
                let program_pin = Path::new(pin_path).join(direction.program_name());
                if !link_pin.exists() && program_pin.exists() {
                    if let Err(error) = instance.detach_owned_legacy_tc_program(
                        direction.program_name(),
                        direction.attach_type(),
                    ) {
                        errors.push(error);
                    }
                }
            }
            let plan = ["xdp_link", "tc_egress_link", "tc_ingress_link"]
                .into_iter()
                .map(|name| SystemCleanupAction::RemoveOwnedPin(Path::new(pin_path).join(name)))
                .collect::<Vec<_>>();
            if let Err(error) = execute_system_cleanup_plan(&plan, |action| {
                execute_system_cleanup_action(action, &iface, pin_path)
            }) {
                errors.push(error);
            }
            if let Err(error) = cleanup_owned_root_qdisc(&iface, state_path) {
                errors.push(error);
            }

            if let Err(error) = sm.clear_attached_iface() {
                errors.push(format!("failed to clear attached interface record: {}", error));
            }
        }
        Ok(None) => {
            info!("no attached interface recorded; skipping XDP/TC detach");
        }
        Err(e) => {
            errors.push(format!("failed to read system attached interface: {}", e));
        }
    }

    let runtime_pin_plan = [
        "xdp_link",
        "tc_egress_link",
        "tc_ingress_link",
        "xdp_firewall",
        "tc_egress",
        "tc_ingress",
    ]
        .into_iter()
        .chain(NETWORK_MAP_NAMES.iter().copied())
        .map(|name| SystemCleanupAction::RemoveOwnedPin(Path::new(pin_path).join(name)))
        .collect::<Vec<_>>();
    if let Err(error) = execute_system_cleanup_plan(&runtime_pin_plan, |action| {
        execute_system_cleanup_action(action, "system", pin_path)
    }) {
        errors.push(error);
    }

    if Path::new(pin_path).exists() {
        match fs::read_dir(pin_path) {
            Ok(mut entries) => {
                if entries.next().is_none() {
                    if let Err(error) = fs::remove_dir(pin_path) {
                        errors.push(format!("failed to remove empty pin directory: {}", error));
                    }
                } else {
                    info!(pin_path = %pin_path, "preserving non-empty runtime pin directory after exact pin cleanup");
                }
            }
            Err(error) => {
                errors.push(format!("failed to inspect pin directory: {}", error));
            }
        }
    }

    // Always publish the stop attempt, while returning any detach/degraded error.
    control_plane.unregister_instance("system").await;

    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    info!("system firewall stopped");
    Ok(())
}

/// Attach a TC program with optional link pinning (graceful fallback for older kernels).
fn attach_tc_program(
    bpf: &mut aya::Ebpf,
    direction: SystemTcDirection,
    iface: &str,
    pin_path: &str,
) -> Result<SystemTcAttachOutcome, String> {
    let prog_name = direction.program_name();
    let attach_type = direction.attach_type();
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

    let tc_link = tc
        .take_link(link_id)
        .map_err(|e| format!("take_link: {:?}", e))?;
    let fd_backed = match <&aya::programs::links::FdLink>::try_from(&tc_link) {
        Ok(_) => true,
        Err(aya::programs::links::LinkError::InvalidLink) => false,
        Err(error) => return Err(format!("{} inspect TC link type: {:?}", prog_name, error)),
    };

    if fd_backed {
        let fd_link: aya::programs::links::FdLink = tc_link
            .try_into()
            .map_err(|e: aya::programs::links::LinkError| format!("FdLink: {:?}", e))?;
        let link_pin = format!("{}/{}_link", pin_path, prog_name);
        fd_link
            .pin(&link_pin)
            .map_err(|e| format!("pin: {:?}", e))?;
        info!(iface = %iface, direction = %dir_str, "TC program attached with pinned link");
        Ok(SystemTcAttachOutcome::Pinned)
    } else {
        let priority = tc_link
            .priority()
            .map_err(|e| format!("{} legacy priority: {:?}", prog_name, e))?;
        let handle = tc_link
            .handle()
            .map_err(|e| format!("{} legacy handle: {:?}", prog_name, e))?;
        std::mem::forget(tc_link);
        Ok(SystemTcAttachOutcome::Legacy { priority, handle })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standalone_acl_activation_requires_both_tc_links() {
        assert_eq!(
            system_acl_activation(true, true, TcAclLinkHealth::new(true, true, false)).unwrap(),
            SystemAclActivation::Restore {
                conntrack: true,
                acl: true,
            }
        );
        assert!(
            system_acl_activation(true, false, TcAclLinkHealth::new(true, false, true)).is_err()
        );
        assert!(
            system_acl_activation(false, true, TcAclLinkHealth::new(false, true, true)).is_err()
        );
        assert_eq!(
            system_acl_activation(false, false, TcAclLinkHealth::new(false, false, false)).unwrap(),
            SystemAclActivation::StayDisabled
        );
    }

    #[test]
    fn standalone_review_preexisting_legacy_tc_requires_both_directions() {
        assert!(preexisting_system_tc_runtime_is_healthy(
            true,
            true,
            TcAclLinkHealth::new(true, true, false),
        )
        .unwrap());
        assert!(preexisting_system_tc_runtime_is_healthy(
            true,
            true,
            TcAclLinkHealth::new(true, false, false),
        )
        .is_err());
        assert!(!preexisting_system_tc_runtime_is_healthy(
            true,
            false,
            TcAclLinkHealth::new(false, false, false),
        )
        .unwrap());
    }

    #[test]
    fn standalone_review_failed_start_detaches_owned_legacy_tc_before_pins() {
        let program_pin = PathBuf::from("/review/tc_ingress");
        let mut ownership = SystemStartOwnership::new();
        ownership.owned_legacy_tc.push(SystemTcDirection::Ingress);
        ownership.owned_program_pins.push(program_pin.clone());

        assert_eq!(
            failed_start_cleanup_plan(&ownership),
            vec![
                SystemCleanupAction::DetachOwnedLegacyTc(SystemTcDirection::Ingress),
                SystemCleanupAction::RemoveOwnedPin(program_pin),
            ]
        );
    }

    #[test]
    fn standalone_review_cleanup_plan_preserves_preexisting_clsact() {
        let xdp = PathBuf::from("/review/xdp_link");
        let ingress = PathBuf::from("/review/tc_ingress_link");
        let mut ownership = SystemStartOwnership::new();
        ownership.xdp_link = true;
        ownership.tc_ingress_link = true;
        ownership.clsact = ClsactOwnership::Preexisting;
        ownership.owned_link_pins = vec![xdp.clone(), ingress.clone()];

        assert_eq!(
            failed_start_cleanup_plan(&ownership),
            vec![
                SystemCleanupAction::RemoveOwnedPin(xdp),
                SystemCleanupAction::RemoveOwnedPin(ingress),
            ]
        );

        let runtime_dir = PathBuf::from("/review/runtime");
        let mut created = SystemStartOwnership::new();
        created.clsact = ClsactOwnership::Created;
        created.owned_runtime_dirs.push(runtime_dir.clone());
        assert_eq!(
            failed_start_cleanup_plan(&created),
            vec![
                SystemCleanupAction::RemoveOwnedClsact,
                SystemCleanupAction::RemoveOwnedRuntimeDirectory(runtime_dir),
            ]
        );
    }

    #[test]
    fn standalone_review_cleanup_attempts_every_owned_resource() {
        let plan = vec![
            SystemCleanupAction::RemoveOwnedPin(PathBuf::from("/review/xdp_link")),
            SystemCleanupAction::RemoveOwnedPin(PathBuf::from("/review/tc_egress_link")),
            SystemCleanupAction::RemoveOwnedPin(PathBuf::from("/review/tc_ingress_link")),
            SystemCleanupAction::RemoveOwnedClsact,
            SystemCleanupAction::RemoveOwnedRuntimeDirectory(PathBuf::from("/review/runtime")),
        ];
        let mut attempted = Vec::new();

        let error = execute_system_cleanup_plan(&plan, |action| {
            attempted.push(action.clone());
            if action == SystemCleanupAction::RemoveOwnedPin(PathBuf::from("/review/xdp_link")) {
                Err("forced XDP cleanup failure".to_string())
            } else {
                Ok(())
            }
        })
        .unwrap_err();

        assert_eq!(attempted, plan);
        assert!(error.contains("forced XDP cleanup failure"));
    }

    #[test]
    fn standalone_review_partial_tc_cleanup_removes_only_owned_pins() {
        let pin_path = std::env::temp_dir().join(format!(
            "aria-standalone-owned-cleanup-{}",
            std::process::id()
        ));
        if pin_path.exists() {
            std::fs::remove_dir_all(&pin_path).unwrap();
        }
        std::fs::create_dir_all(&pin_path).unwrap();
        for name in [
            "xdp_link",
            "tc_ingress_link",
            "tc_egress_link",
            "unrelated_link",
        ] {
            std::fs::write(pin_path.join(name), b"pin").unwrap();
        }
        let mut ownership = SystemStartOwnership::new();
        ownership.xdp_link = true;
        ownership.tc_ingress_link = true;
        ownership.clsact = ClsactOwnership::Preexisting;
        ownership.owned_link_pins =
            vec![pin_path.join("xdp_link"), pin_path.join("tc_ingress_link")];
        let pin_path_string = pin_path.to_string_lossy().into_owned();

        execute_system_cleanup_plan(&failed_start_cleanup_plan(&ownership), |action| {
            execute_system_cleanup_action(action, "unused-review-iface", &pin_path_string)
        })
        .unwrap();

        assert!(!pin_path.join("xdp_link").exists());
        assert!(!pin_path.join("tc_ingress_link").exists());
        assert!(pin_path.join("tc_egress_link").exists());
        assert!(pin_path.join("unrelated_link").exists());
        std::fs::remove_dir_all(pin_path).unwrap();
    }

    #[test]
    fn standalone_review_xdp_program_pin_failure_rolls_back_owned_link() {
        let xdp_link = PathBuf::from("/review/xdp_link");
        let mut ownership = SystemStartOwnership::new();
        ownership.xdp_link = true;
        ownership.tc_egress_link = true;
        ownership.tc_ingress_link = true;
        ownership.clsact = ClsactOwnership::Preexisting;
        ownership.owned_link_pins.push(xdp_link.clone());

        assert_eq!(
            unbacked_program_link_cleanup_plan(
                &ownership,
                TcAclLinkHealth::new(true, true, false),
            ),
            vec![SystemCleanupAction::RemoveOwnedPin(xdp_link)]
        );
    }

    #[test]
    fn standalone_review_start_replays_exact_approved_snapshot() {
        let source = include_str!("system_manager.rs");
        let start = source
            .split("pub async fn system_start(")
            .nth(1)
            .unwrap()
            .split("pub async fn system_stop(")
            .next()
            .unwrap();

        assert_eq!(
            start.matches("aria_core::wal::load_with_wal(state_path)").count(),
            1,
            "standalone startup must approve exactly one durable snapshot"
        );
        assert!(start.contains("let mut quiesced_desired = desired.clone();"));
        assert!(start.contains("quiesced_desired.conntrack_enabled = false;"));
        assert!(start.contains("quiesced_desired.acl_enabled = false;"));
        assert!(start.contains(
            "replay_state_from_snapshot(&mut bpf, state_path, &quiesced_desired)"
        ));
        assert!(start.contains(
            "replay_standalone_state_to_pinned_maps_from_snapshot"
        ));
        assert!(start.contains(
            ".register_system_instance(pin_path, state_path, desired, iface)"
        ));
        assert!(!start.contains("replay_state(&mut bpf, state_path)"));
    }

    #[test]
    fn standalone_start_clears_recovery_only_after_replay_and_registration() {
        let source = include_str!("system_manager.rs");
        let start = source
            .split("pub async fn system_start(")
            .nth(1)
            .unwrap()
            .split("pub async fn system_stop(")
            .next()
            .unwrap();
        let replay = start
            .find("let replay_result = if reuse_preexisting_tc")
            .unwrap();
        let register = start.find("register_system_instance").unwrap();

        assert!(replay < register);
        assert!(!start[..register].contains("clear_local_projection_recoveries"));
    }

    #[test]
    fn standalone_review_preexisting_pin_dir_cleans_only_transaction_pins() {
        let pin_path = std::env::temp_dir().join(format!(
            "aria-standalone-individual-pin-cleanup-{}",
            std::process::id()
        ));
        if pin_path.exists() {
            std::fs::remove_dir_all(&pin_path).unwrap();
        }
        std::fs::create_dir_all(&pin_path).unwrap();
        let preexisting_map = pin_path.join("preexisting_map");
        let owned_map = pin_path.join("owned_map");
        let owned_program = pin_path.join("xdp_firewall");
        for path in [&preexisting_map, &owned_map, &owned_program] {
            std::fs::write(path, b"pin").unwrap();
        }

        let mut ownership = SystemStartOwnership::new();
        ownership.owned_map_pins.push(owned_map.clone());
        ownership.owned_program_pins.push(owned_program.clone());
        let pin_path_string = pin_path.to_string_lossy().into_owned();
        execute_system_cleanup_plan(&failed_start_cleanup_plan(&ownership), |action| {
            execute_system_cleanup_action(action, "unused-review-iface", &pin_path_string)
        })
        .unwrap();

        assert!(!owned_map.exists());
        assert!(!owned_program.exists());
        assert!(preexisting_map.exists());
        assert!(pin_path.exists());
        std::fs::remove_dir_all(pin_path).unwrap();
    }

    #[test]
    fn standalone_review_program_pin_without_link_is_cleaned_for_retry() {
        let pin_path = std::env::temp_dir().join(format!(
            "aria-standalone-program-pin-retry-{}",
            std::process::id()
        ));
        if pin_path.exists() {
            std::fs::remove_dir_all(&pin_path).unwrap();
        }
        std::fs::create_dir_all(&pin_path).unwrap();
        let program_pin = pin_path.join("tc_ingress");
        std::fs::write(&program_pin, b"pin").unwrap();

        let mut ownership = SystemStartOwnership::new();
        ownership.owned_program_pins.push(program_pin.clone());
        let plan = unbacked_program_link_cleanup_plan(
            &ownership,
            TcAclLinkHealth::new(true, false, true),
        );
        assert_eq!(
            plan,
            vec![SystemCleanupAction::RemoveOwnedPin(program_pin.clone())]
        );
        let pin_path_string = pin_path.to_string_lossy().into_owned();
        execute_system_cleanup_plan(&plan, |action| {
            execute_system_cleanup_action(action, "unused-review-iface", &pin_path_string)
        })
        .unwrap();

        assert!(!program_pin.exists());
        std::fs::write(&program_pin, b"retry-pin").unwrap();
        assert!(program_pin.exists(), "retry must not be blocked by a stale pin");
        std::fs::remove_dir_all(pin_path).unwrap();
    }

    #[test]
    fn standalone_review_partial_runtime_dir_creation_is_rolled_back() {
        let root = std::env::temp_dir().join(format!(
            "aria-standalone-partial-dir-{}",
            std::process::id()
        ));
        if root.exists() {
            std::fs::remove_dir_all(&root).unwrap();
        }
        std::fs::create_dir_all(&root).unwrap();
        let first_created = root.join("runtime");
        let requested = first_created.join("system");

        let error = create_runtime_pin_directories_with(&requested, |_| {
            std::fs::create_dir(&first_created)?;
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "forced create_dir_all failure",
            ))
        })
        .unwrap_err();

        assert!(error.contains("forced create_dir_all failure"));
        assert!(!first_created.exists());
        assert!(root.exists());
        std::fs::remove_dir_all(root).unwrap();
    }
}
