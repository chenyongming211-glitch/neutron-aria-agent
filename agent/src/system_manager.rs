use crate::control_plane::ControlPlane;
use crate::instance::TcAclLinkHealth;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{info, warn};

use aria_core::common::TapMapRuntime;
use aria_core::ebpf_ops::{
    cleanup_root_qdisc, critical_network_map_names, ensure_fq_qdisc, replay_state,
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
struct SystemStartOwnership {
    xdp_link: bool,
    tc_egress_link: bool,
    tc_ingress_link: bool,
    clsact: ClsactOwnership,
    pin_path_created: bool,
    fq_root_qdisc: bool,
}

impl SystemStartOwnership {
    fn new(pin_path_created: bool) -> Self {
        Self {
            xdp_link: false,
            tc_egress_link: false,
            tc_ingress_link: false,
            clsact: ClsactOwnership::Absent,
            pin_path_created,
            fq_root_qdisc: false,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum SystemCleanupAction {
    RemoveXdpLink,
    RemoveTcLink(&'static str),
    RemoveOwnedClsact,
    RemoveRuntimePinPath,
}

fn failed_start_cleanup_plan(ownership: &SystemStartOwnership) -> Vec<SystemCleanupAction> {
    let mut plan = Vec::new();
    if ownership.xdp_link {
        plan.push(SystemCleanupAction::RemoveXdpLink);
    }
    if ownership.tc_egress_link {
        plan.push(SystemCleanupAction::RemoveTcLink("tc_egress"));
    }
    if ownership.tc_ingress_link {
        plan.push(SystemCleanupAction::RemoveTcLink("tc_ingress"));
    }
    if ownership.clsact == ClsactOwnership::Created {
        plan.push(SystemCleanupAction::RemoveOwnedClsact);
    }
    if ownership.pin_path_created {
        plan.push(SystemCleanupAction::RemoveRuntimePinPath);
    }
    plan
}

fn unbacked_program_link_cleanup_plan(
    ownership: &SystemStartOwnership,
    program_health: TcAclLinkHealth,
) -> Vec<SystemCleanupAction> {
    let mut plan = Vec::new();
    if ownership.xdp_link && !program_health.xdp {
        plan.push(SystemCleanupAction::RemoveXdpLink);
    }
    if ownership.tc_egress_link && !program_health.egress {
        plan.push(SystemCleanupAction::RemoveTcLink("tc_egress"));
    }
    if ownership.tc_ingress_link && !program_health.ingress {
        plan.push(SystemCleanupAction::RemoveTcLink("tc_ingress"));
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
        if let Err(error) = cleanup(*action) {
            errors.push(error);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
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
            "standalone ACL/CT requires pinned TC links: {}",
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
    pin_path: &str,
) -> Result<(), String> {
    match action {
        SystemCleanupAction::RemoveXdpLink => {
            remove_pin_file_if_present(&Path::new(pin_path).join("xdp_link"))
        }
        SystemCleanupAction::RemoveTcLink(program) => {
            remove_pin_file_if_present(&Path::new(pin_path).join(format!("{}_link", program)))
        }
        SystemCleanupAction::RemoveOwnedClsact => remove_owned_clsact(iface),
        SystemCleanupAction::RemoveRuntimePinPath => {
            if Path::new(pin_path).exists() {
                fs::remove_dir_all(pin_path)
                    .map_err(|e| format!("failed to remove owned runtime pin path: {}", e))?;
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

fn pin_runtime_programs(
    bpf: &mut aya::Ebpf,
    pin_path: &str,
    require_tc_acl: bool,
) -> TcAclLinkHealth {
    let mut ingress = false;
    let mut egress = false;
    let mut xdp = false;
    for name in &["xdp_firewall", "tc_egress", "tc_ingress"] {
        let result = match bpf.program_mut(name) {
            Some(program) => program
                .pin(format!("{}/{}", pin_path, name))
                .map_err(|e| format!("Failed to pin program {}: {:?}", name, e)),
            None => Err(format!("Program {} not found", name)),
        };
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
    let mut ownership = SystemStartOwnership::new(!Path::new(pin_path).exists());
    fs::create_dir_all(pin_path).map_err(|e| format!("Failed to create pin directory: {}", e))?;
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
    let mut bpf = aya::EbpfLoader::new()
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
    if let Err(e) = pin_runtime_maps(&mut bpf, pin_path, trace_map_mode) {
        return Err(start_error_with_cleanup(
            e,
            iface,
            pin_path,
            state_path,
            &ownership,
        ));
    }

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

    let desired = aria_core::wal::load_with_wal(state_path);
    let desired_conntrack = desired.conntrack_enabled;
    let desired_acl = desired.acl_enabled;

    // Replay state
    if let Err(e) = replay_state(&mut bpf, state_path) {
        return Err(start_error_with_cleanup(
            format!("failed to replay state: {}", e),
            iface,
            pin_path,
            state_path,
            &ownership,
        ));
    }

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
            format!("failed to quiesce standalone ACL/CT before attach: {}", e),
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

    match attach_xdp_program(&mut bpf, iface, pin_path) {
        Ok(()) => ownership.xdp_link = true,
        Err(error) => {
            warn!(iface = %iface, error = %error, "XDP DDoS hook unavailable; continuing with TC ACL");
        }
    }

    match ensure_clsact(iface) {
        Ok(clsact) => ownership.clsact = clsact,
        Err(error) => {
            warn!(iface = %iface, error = %error, "TC clsact unavailable; TC ACL disabled");
        }
    }
    if ownership.clsact != ClsactOwnership::Absent {
        match attach_tc_program(
            &mut bpf,
            "tc_egress",
            iface,
            aya::programs::tc::TcAttachType::Egress,
            pin_path,
        ) {
            Ok(()) => ownership.tc_egress_link = true,
            Err(error) => {
                warn!(iface = %iface, error = %error, "TC egress attach failed; egress control disabled");
            }
        }

        match attach_tc_program(
            &mut bpf,
            "tc_ingress",
            iface,
            aya::programs::tc::TcAttachType::Ingress,
            pin_path,
        ) {
            Ok(()) => ownership.tc_ingress_link = true,
            Err(error) => {
                warn!(iface = %iface, error = %error, "TC ingress attach failed; ingress mirror disabled");
            }
        }
    }

    let program_health =
        pin_runtime_programs(&mut bpf, pin_path, desired_conntrack || desired_acl);
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
    let health = TcAclLinkHealth::new(
        ownership.tc_ingress_link,
        ownership.tc_egress_link,
        ownership.xdp_link,
    );
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
            let plan = [
                SystemCleanupAction::RemoveXdpLink,
                SystemCleanupAction::RemoveTcLink("tc_egress"),
                SystemCleanupAction::RemoveTcLink("tc_ingress"),
            ];
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

    if Path::new(pin_path).exists() {
        if let Err(error) = fs::remove_dir_all(pin_path) {
            errors.push(format!("failed to remove pin directory: {}", error));
        }
        info!(pin_path = %pin_path, "removed pinned maps and programs");
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
    prog_name: &str,
    iface: &str,
    attach_type: aya::programs::tc::TcAttachType,
    pin_path: &str,
) -> Result<(), String> {
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

    (|| -> Result<(), String> {
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
    })()?;
    info!(iface = %iface, direction = %dir_str, "TC program attached with pinned link");

    Ok(())
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
    fn standalone_review_cleanup_plan_preserves_preexisting_clsact() {
        let ownership = SystemStartOwnership {
            xdp_link: true,
            tc_egress_link: false,
            tc_ingress_link: true,
            clsact: ClsactOwnership::Preexisting,
            pin_path_created: false,
            fq_root_qdisc: false,
        };

        assert_eq!(
            failed_start_cleanup_plan(&ownership),
            vec![
                SystemCleanupAction::RemoveXdpLink,
                SystemCleanupAction::RemoveTcLink("tc_ingress"),
            ]
        );

        let created = SystemStartOwnership {
            xdp_link: false,
            tc_egress_link: false,
            tc_ingress_link: false,
            clsact: ClsactOwnership::Created,
            pin_path_created: true,
            fq_root_qdisc: false,
        };
        assert_eq!(
            failed_start_cleanup_plan(&created),
            vec![
                SystemCleanupAction::RemoveOwnedClsact,
                SystemCleanupAction::RemoveRuntimePinPath,
            ]
        );
    }

    #[test]
    fn standalone_review_cleanup_attempts_every_owned_resource() {
        let plan = vec![
            SystemCleanupAction::RemoveXdpLink,
            SystemCleanupAction::RemoveTcLink("tc_egress"),
            SystemCleanupAction::RemoveTcLink("tc_ingress"),
            SystemCleanupAction::RemoveOwnedClsact,
            SystemCleanupAction::RemoveRuntimePinPath,
        ];
        let mut attempted = Vec::new();

        let error = execute_system_cleanup_plan(&plan, |action| {
            attempted.push(action);
            if action == SystemCleanupAction::RemoveXdpLink {
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
    fn standalone_review_xdp_program_pin_failure_rolls_back_owned_link() {
        let ownership = SystemStartOwnership {
            xdp_link: true,
            tc_egress_link: true,
            tc_ingress_link: true,
            clsact: ClsactOwnership::Preexisting,
            pin_path_created: false,
            fq_root_qdisc: false,
        };

        assert_eq!(
            unbacked_program_link_cleanup_plan(
                &ownership,
                TcAclLinkHealth::new(true, true, false),
            ),
            vec![SystemCleanupAction::RemoveXdpLink]
        );
    }
}
