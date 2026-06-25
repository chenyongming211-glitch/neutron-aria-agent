use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, put},
    Json, Router,
};
use aria_api::{
    action_from_string, direction_from_string, proto_from_string, ManagedNeutronPort,
    NeutronAclRuleSnapshot, NeutronAclSnapshot, NeutronCapabilitiesResponse, NeutronDeleteResponse,
    NeutronPortApplyResult, NeutronPortSnapshot, NeutronSnapshotRequest, NeutronSnapshotResponse,
    NeutronStatusResponse,
};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::{error, warn};

use crate::control_plane::ControlPlane;
use crate::tap_registry::TapRegistry;

#[derive(Clone)]
pub(crate) struct NeutronApiState {
    registry: Arc<TapRegistry>,
    control_plane: Arc<ControlPlane>,
    ovs_bridge: String,
    runtime: Arc<RwLock<NeutronRuntimeState>>,
    apply_lock: Arc<Mutex<()>>,
}

#[derive(Default)]
struct NeutronRuntimeState {
    generation: u64,
    ports: BTreeMap<String, ManagedNeutronPort>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SnapshotPlan {
    attach: Vec<NeutronPortSnapshot>,
    update: Vec<NeutronPortSnapshot>,
    detach: Vec<ManagedNeutronPort>,
    ignored: Vec<NeutronPortApplyResult>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AclGroupPlan {
    name: String,
    cidrs: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct AclPolicyPlan {
    src_group: String,
    dst_group: String,
    proto: u8,
    action: u8,
    direction: u8,
    ports: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct AclApplyPlan {
    groups: Vec<AclGroupPlan>,
    policies: Vec<AclPolicyPlan>,
}

impl NeutronApiState {
    fn new(registry: Arc<TapRegistry>, control_plane: Arc<ControlPlane>, ovs_bridge: String) -> Self {
        Self {
            registry,
            control_plane,
            ovs_bridge,
            runtime: Arc::new(RwLock::new(NeutronRuntimeState::default())),
            apply_lock: Arc::new(Mutex::new(())),
        }
    }
}

pub(crate) fn build_router(
    registry: Arc<TapRegistry>,
    control_plane: Arc<ControlPlane>,
    ovs_bridge: String,
) -> Router {
    Router::new()
        .route(
            "/api/v1/neutron/capabilities",
            get(get_neutron_capabilities),
        )
        .route("/api/v1/neutron/status", get(get_neutron_status))
        .route("/api/v1/neutron/snapshot", put(put_neutron_snapshot))
        .route(
            "/api/v1/neutron/ports/{port_id}",
            delete(delete_neutron_port),
        )
        .with_state(NeutronApiState::new(registry, control_plane, ovs_bridge))
}

async fn get_neutron_capabilities() -> impl IntoResponse {
    Json(NeutronCapabilitiesResponse::current())
}

async fn get_neutron_status(State(state): State<NeutronApiState>) -> impl IntoResponse {
    let runtime = state.runtime.read().await;
    let managed_ports = runtime.ports.values().cloned().collect();
    let generation = runtime.generation;
    drop(runtime);

    Json(NeutronStatusResponse {
        generation,
        managed_ports,
        active_instances: state.registry.list().await,
    })
}

async fn put_neutron_snapshot(
    State(state): State<NeutronApiState>,
    Json(snapshot): Json<NeutronSnapshotRequest>,
) -> impl IntoResponse {
    // Keep mutating snapshot apply alive even if the UDS client times out or disconnects.
    let handle = tokio::spawn(apply_neutron_snapshot(state, snapshot));
    match handle.await {
        Ok(response) => Json(response).into_response(),
        Err(e) => {
            error!(error = %e, "Neutron snapshot apply task failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "snapshot_apply_task_failed",
                    "details": e.to_string(),
                })),
            )
                .into_response()
        }
    }
}

async fn apply_neutron_snapshot(
    state: NeutronApiState,
    snapshot: NeutronSnapshotRequest,
) -> NeutronSnapshotResponse {
    let _guard = state.apply_lock.lock().await;
    let current_ports = state.runtime.read().await.ports.clone();
    let local_inventory = LocalInterfaceInventory::load(&state.ovs_bridge);
    let plan = build_snapshot_plan(&current_ports, &snapshot, &local_inventory);

    let mut next_ports = current_ports;
    let mut results = plan.ignored;

    for port in plan.detach {
        if let Err(e) = purge_neutron_acl(&state, &port.ifname, &port.port_id).await {
            warn!(
                port_id = %port.port_id,
                ifname = %port.ifname,
                error = %e,
                "failed to purge Neutron ACL before detach"
            );
        }
        match state.registry.detach(&port.ifname).await {
            Ok(()) => {
                next_ports.remove(&port.port_id);
                state
                    .control_plane
                    .clear_neutron_port_authority(&port.ifname)
                    .await;
                results.push(NeutronPortApplyResult {
                    port_id: port.port_id,
                    ifname: port.ifname,
                    action: "detach".to_string(),
                    status: "ok".to_string(),
                    reason: None,
                });
            }
            Err(e) => {
                results.push(NeutronPortApplyResult {
                    port_id: port.port_id,
                    ifname: port.ifname,
                    action: "detach".to_string(),
                    status: "error".to_string(),
                    reason: Some(e),
                });
            }
        }
    }

    for port in plan.update {
        let managed = managed_port_from_snapshot(&port);
        match reconcile_neutron_acl(&state, &port).await {
            Ok(()) => {
                state
                    .control_plane
                    .mark_neutron_port_authority(
                        &managed.ifname,
                        &managed.port_id,
                        &managed.managed_domains,
                        snapshot.generation,
                    )
                    .await;
                next_ports.insert(managed.port_id.clone(), managed.clone());
                results.push(NeutronPortApplyResult {
                    port_id: managed.port_id,
                    ifname: managed.ifname,
                    action: "update".to_string(),
                    status: "ok".to_string(),
                    reason: None,
                });
            }
            Err(e) => {
                results.push(NeutronPortApplyResult {
                    port_id: managed.port_id,
                    ifname: managed.ifname,
                    action: "update".to_string(),
                    status: "error".to_string(),
                    reason: Some(format!("acl_apply_failed:{}", e)),
                });
            }
        }
    }

    for port in plan.attach {
        match state.registry.attach(&port.ifname).await {
            Ok(()) => {
                let managed = managed_port_from_snapshot(&port);
                match reconcile_neutron_acl(&state, &port).await {
                    Ok(()) => {
                        state
                            .control_plane
                            .mark_neutron_port_authority(
                                &managed.ifname,
                                &managed.port_id,
                                &managed.managed_domains,
                                snapshot.generation,
                            )
                            .await;
                        next_ports.insert(managed.port_id.clone(), managed.clone());
                        results.push(NeutronPortApplyResult {
                            port_id: managed.port_id,
                            ifname: managed.ifname,
                            action: "attach".to_string(),
                            status: "ok".to_string(),
                            reason: None,
                        });
                    }
                    Err(e) => {
                        if let Err(detach_err) = state.registry.detach(&port.ifname).await {
                            warn!(
                                port_id = %port.port_id,
                                ifname = %port.ifname,
                                error = %detach_err,
                                "failed to detach after Neutron ACL apply failure"
                            );
                        }
                        state
                            .control_plane
                            .clear_neutron_port_authority(&port.ifname)
                            .await;
                        results.push(NeutronPortApplyResult {
                            port_id: managed.port_id,
                            ifname: managed.ifname,
                            action: "attach".to_string(),
                            status: "error".to_string(),
                            reason: Some(format!("acl_apply_failed:{}", e)),
                        });
                    }
                }
            }
            Err(e) => {
                results.push(NeutronPortApplyResult {
                    port_id: port.port_id,
                    ifname: port.ifname,
                    action: "attach".to_string(),
                    status: "error".to_string(),
                    reason: Some(e),
                });
            }
        }
    }

    {
        let mut runtime = state.runtime.write().await;
        runtime.generation = snapshot.generation;
        runtime.ports = next_ports;
    }

    NeutronSnapshotResponse {
        generation: snapshot.generation,
        results,
        active_instances: state.registry.list().await,
    }
}

async fn delete_neutron_port(
    State(state): State<NeutronApiState>,
    Path(port_id): Path<String>,
) -> impl IntoResponse {
    let error_port_id = port_id.clone();
    // Keep mutating delete alive even if the UDS client times out or disconnects.
    let handle = tokio::spawn(apply_delete_neutron_port(state, port_id));
    match handle.await {
        Ok((status, response)) => (status, Json(response)).into_response(),
        Err(e) => {
            error!(error = %e, "Neutron port delete task failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(NeutronDeleteResponse {
                    port_id: error_port_id,
                    ifname: None,
                    detached: false,
                    status: "error".to_string(),
                    error: Some(format!("delete_task_failed:{}", e)),
                }),
            )
                .into_response()
        }
    }
}

async fn apply_delete_neutron_port(
    state: NeutronApiState,
    port_id: String,
) -> (StatusCode, NeutronDeleteResponse) {
    let _guard = state.apply_lock.lock().await;
    let port = {
        let runtime = state.runtime.read().await;
        runtime.ports.get(&port_id).cloned()
    };

    let Some(port) = port else {
        return (
            StatusCode::OK,
            NeutronDeleteResponse {
                port_id,
                ifname: None,
                detached: false,
                status: "not_found".to_string(),
                error: None,
            },
        );
    };

    if let Err(e) = purge_neutron_acl(&state, &port.ifname, &port.port_id).await {
        warn!(
            port_id = %port.port_id,
            ifname = %port.ifname,
            error = %e,
            "failed to purge Neutron ACL during port delete"
        );
    }

    match state.registry.detach(&port.ifname).await {
        Ok(()) => {
            {
                let mut runtime = state.runtime.write().await;
                runtime.ports.remove(&port_id);
            }
            state
                .control_plane
                .clear_neutron_port_authority(&port.ifname)
                .await;
            (
                StatusCode::OK,
                NeutronDeleteResponse {
                    port_id: port.port_id,
                    ifname: Some(port.ifname),
                    detached: true,
                    status: "ok".to_string(),
                    error: None,
                },
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            NeutronDeleteResponse {
                port_id: port.port_id,
                ifname: Some(port.ifname),
                detached: false,
                status: "error".to_string(),
                error: Some(e),
            },
        ),
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct LocalOvsInterface {
    name: String,
    ifindex: Option<u32>,
    bridge: Option<String>,
    iface_id: Option<String>,
}

#[derive(Clone, Debug, Default)]
struct LocalInterfaceInventory {
    ovs_bridge: String,
    ovs_error: Option<String>,
    by_iface_id: BTreeMap<String, LocalOvsInterface>,
    by_name: BTreeMap<String, LocalOvsInterface>,
}

impl LocalInterfaceInventory {
    fn load(ovs_bridge: &str) -> Self {
        match Self::try_load(ovs_bridge) {
            Ok(inventory) => inventory,
            Err(error) => Self {
                ovs_bridge: ovs_bridge.to_string(),
                ovs_error: Some(error),
                by_iface_id: BTreeMap::new(),
                by_name: BTreeMap::new(),
            },
        }
    }

    fn try_load(ovs_bridge: &str) -> Result<Self, String> {
        let bridge_ports = Self::list_bridge_ports(ovs_bridge)?;
        let output = Command::new("ovs-vsctl")
            .args([
                "--format=json",
                "--columns=name,external_ids",
                "list",
                "Interface",
            ])
            .output()
            .map_err(|e| format!("run ovs-vsctl list Interface: {}", e))?;
        if !output.status.success() {
            return Err(format!(
                "ovs-vsctl list Interface failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let payload = String::from_utf8_lossy(&output.stdout);
        Self::from_ovs_json(ovs_bridge, &bridge_ports, &payload)
    }

    fn list_bridge_ports(ovs_bridge: &str) -> Result<BTreeSet<String>, String> {
        let output = Command::new("ovs-vsctl")
            .args(["list-ports", ovs_bridge])
            .output()
            .map_err(|e| format!("run ovs-vsctl list-ports {}: {}", ovs_bridge, e))?;
        if !output.status.success() {
            return Err(format!(
                "ovs-vsctl list-ports {} failed: {}",
                ovs_bridge,
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout)
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(ToOwned::to_owned)
            .collect())
    }

    fn from_ovs_json(
        ovs_bridge: &str,
        bridge_ports: &BTreeSet<String>,
        payload: &str,
    ) -> Result<Self, String> {
        let document: Value =
            serde_json::from_str(payload).map_err(|e| format!("parse ovs-vsctl json: {}", e))?;
        let headings = document
            .get("headings")
            .and_then(Value::as_array)
            .ok_or_else(|| "ovs json missing headings".to_string())?;
        let data = document
            .get("data")
            .and_then(Value::as_array)
            .ok_or_else(|| "ovs json missing data".to_string())?;

        let mut name_index = None;
        let mut external_ids_index = None;
        for (index, heading) in headings.iter().enumerate() {
            match heading.as_str() {
                Some("name") => name_index = Some(index),
                Some("external_ids") => external_ids_index = Some(index),
                _ => {}
            }
        }
        let name_index = name_index.ok_or_else(|| "ovs json missing name heading".to_string())?;
        let external_ids_index = external_ids_index
            .ok_or_else(|| "ovs json missing external_ids heading".to_string())?;

        let mut inventory = Self {
            ovs_bridge: ovs_bridge.to_string(),
            ovs_error: None,
            by_iface_id: BTreeMap::new(),
            by_name: BTreeMap::new(),
        };

        for row in data {
            let Some(values) = row.as_array() else {
                continue;
            };
            let Some(name) = values.get(name_index).and_then(Value::as_str) else {
                continue;
            };
            let external_ids = values
                .get(external_ids_index)
                .map(parse_ovs_external_ids)
                .unwrap_or_default();
            let iface_id = external_ids.get("iface-id").cloned();
            let interface = LocalOvsInterface {
                name: name.to_string(),
                ifindex: read_ifindex(name),
                bridge: bridge_ports
                    .contains(name)
                    .then(|| ovs_bridge.to_string()),
                iface_id: iface_id.clone(),
            };
            if let Some(iface_id) = iface_id {
                inventory
                    .by_iface_id
                    .insert(iface_id, interface.clone());
            }
            inventory.by_name.insert(name.to_string(), interface);
        }

        Ok(inventory)
    }

    fn is_authoritative(&self) -> bool {
        self.ovs_error.is_none()
    }
}

fn parse_ovs_external_ids(value: &Value) -> BTreeMap<String, String> {
    let mut result = BTreeMap::new();
    let Some(items) = value.as_array() else {
        return result;
    };
    if items.len() != 2 || items.first().and_then(Value::as_str) != Some("map") {
        return result;
    }
    let Some(entries) = items.get(1).and_then(Value::as_array) else {
        return result;
    };
    for entry in entries {
        let Some(pair) = entry.as_array() else {
            continue;
        };
        if pair.len() != 2 {
            continue;
        }
        if let (Some(key), Some(value)) = (pair[0].as_str(), pair[1].as_str()) {
            result.insert(key.to_string(), value.to_string());
        }
    }
    result
}

fn guess_tap_name(port_id: &str) -> String {
    if port_id.is_empty() {
        return String::new();
    }
    let prefix: String = port_id.chars().take(11).collect();
    format!("tap{}", prefix)
}

fn read_ifindex(ifname: &str) -> Option<u32> {
    let path = format!("/sys/class/net/{}/ifindex", ifname);
    std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| raw.trim().parse::<u32>().ok())
        .filter(|ifindex| *ifindex != 0)
}

fn is_compute_owner(device_owner: Option<&str>) -> bool {
    device_owner
        .map(|owner| owner.is_empty() || owner.starts_with("compute:"))
        .unwrap_or(true)
}

fn is_ovs_vif(vif_type: Option<&str>) -> bool {
    matches!(vif_type, None | Some("") | Some("ovs"))
}

fn is_normal_vnic(vnic_type: Option<&str>) -> bool {
    matches!(vnic_type, None | Some("") | Some("normal"))
}

fn ineligible_port(port: &NeutronPortSnapshot, reason: String) -> NeutronPortSnapshot {
    let mut resolved = port.clone();
    resolved.eligible = false;
    resolved.disposition = Some(reason);
    resolved.managed_domains.clear();
    resolved
}

fn resolve_local_neutron_port(
    port: &NeutronPortSnapshot,
    inventory: &LocalInterfaceInventory,
) -> NeutronPortSnapshot {
    if !port.eligible {
        return ineligible_port(
            port,
            port.disposition
                .clone()
                .unwrap_or_else(|| "not eligible".to_string()),
        );
    }

    if !is_compute_owner(port.device_owner.as_deref()) {
        return ineligible_port(
            port,
            format!(
                "not_applicable_device_owner:{}",
                port.device_owner.as_deref().unwrap_or("")
            ),
        );
    }
    if !is_ovs_vif(port.vif_type.as_deref()) {
        return ineligible_port(
            port,
            format!("unsupported_vif_type:{}", port.vif_type.as_deref().unwrap_or("")),
        );
    }
    if !is_normal_vnic(port.vnic_type.as_deref()) {
        return ineligible_port(
            port,
            format!(
                "unsupported_vnic_type:{}",
                port.vnic_type.as_deref().unwrap_or("")
            ),
        );
    }

    if let Some(error) = &inventory.ovs_error {
        return ineligible_port(port, format!("ovsdb_unavailable:{}", error));
    }

    let by_iface_id = inventory.by_iface_id.get(&port.port_id);
    let requested_name = port.ifname.trim();
    let by_name = (!requested_name.is_empty())
        .then(|| inventory.by_name.get(requested_name))
        .flatten();
    let interface = by_iface_id.or(by_name);

    let Some(interface) = interface else {
        let guessed = if requested_name.is_empty() {
            guess_tap_name(&port.port_id)
        } else {
            requested_name.to_string()
        };
        let mut missing = port.clone();
        missing.ifname = guessed;
        return ineligible_port(&missing, "ovs_iface_id_not_found".to_string());
    };

    if interface.bridge.as_deref() != Some(inventory.ovs_bridge.as_str()) {
        let mut bridge_mismatch = port.clone();
        bridge_mismatch.ifname = interface.name.clone();
        bridge_mismatch.ovs_iface_id = interface.iface_id.clone();
        return ineligible_port(
            &bridge_mismatch,
            format!("not_on_ovs_bridge:{}", inventory.ovs_bridge),
        );
    }

    if interface.iface_id.as_deref() != Some(port.port_id.as_str()) {
        let mut mismatch = port.clone();
        mismatch.ifname = interface.name.clone();
        mismatch.ovs_iface_id = interface.iface_id.clone();
        return ineligible_port(&mismatch, "ovs_iface_id_mismatch".to_string());
    }

    let ifindex = interface.ifindex.or_else(|| read_ifindex(&interface.name));
    if ifindex.is_none() {
        let mut not_ready = port.clone();
        not_ready.ifname = interface.name.clone();
        not_ready.ovs_iface_id = interface.iface_id.clone();
        return ineligible_port(&not_ready, "ifindex_not_ready".to_string());
    }

    let mut resolved = port.clone();
    resolved.ifname = interface.name.clone();
    resolved.ifindex = ifindex;
    resolved.eligible = true;
    resolved.disposition = Some("eligible_ovs_tap".to_string());
    resolved.network_backend = Some("openvswitch".to_string());
    resolved.ovs_iface_id = interface.iface_id.clone();
    resolved
}

fn normalize_managed_domains(domains: &[String]) -> Vec<String> {
    ControlPlane::normalize_neutron_managed_domains(domains)
        .into_iter()
        .collect()
}

fn managed_port_from_snapshot(port: &NeutronPortSnapshot) -> ManagedNeutronPort {
    ManagedNeutronPort {
        port_id: port.port_id.clone(),
        ifname: port.ifname.clone(),
        ifindex: port.ifindex,
        managed_domains: normalize_managed_domains(&port.managed_domains),
    }
}

fn port_manages_acl(port: &NeutronPortSnapshot) -> bool {
    normalize_managed_domains(&port.managed_domains)
        .iter()
        .any(|domain| domain == "acl")
}

fn neutron_acl_prefix(port_id: &str) -> String {
    format!("neutron:{}:", port_id)
}

fn is_neutron_acl_group(port_id: &str, group_name: &str) -> bool {
    group_name.starts_with(&neutron_acl_prefix(port_id))
}

fn acl_rule_id(rule: &NeutronAclRuleSnapshot, index: usize) -> String {
    rule.id
        .as_deref()
        .filter(|id| !id.trim().is_empty())
        .map(|id| {
            id.chars()
                .map(|ch| {
                    if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                        ch
                    } else {
                        '_'
                    }
                })
                .collect::<String>()
        })
        .unwrap_or_else(|| format!("rule{}", index))
}

fn normalize_default_action(action: &str) -> String {
    let normalized = action.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        "allow".to_string()
    } else {
        normalized
    }
}

fn neutron_acl_to_datapath_directions(direction: u8) -> Vec<u8> {
    match direction {
        // Neutron ACL direction is VM-port centric. On a Linux tap, traffic
        // entering the VM is observed by the host-side TC egress hook.
        0 => vec![1],
        // Traffic leaving the VM is observed by the host-side TC ingress hook.
        1 => vec![0],
        2 => vec![1, 0],
        other => vec![other],
    }
}

fn ensure_ipv4_cidrs(cidrs: &[String], rule_id: &str) -> Result<(), String> {
    for cidr in cidrs {
        if cidr.contains(':') {
            return Err(format!("rule {} uses IPv6 CIDR {}; unsupported", rule_id, cidr));
        }
    }
    Ok(())
}

fn acl_ports(rule: &NeutronAclRuleSnapshot, proto: u8, rule_id: &str) -> Result<Option<String>, String> {
    if rule.src_port_min.is_some() || rule.src_port_max.is_some() {
        return Err(format!(
            "rule {} uses source port matching; unsupported by current datapath translator",
            rule_id
        ));
    }

    let min = rule.dst_port_min.or(rule.dst_port_max);
    let max = rule.dst_port_max.or(rule.dst_port_min);
    let (Some(min), Some(max)) = (min, max) else {
        return Ok(None);
    };

    if proto != 6 && proto != 17 {
        return Err(format!(
            "rule {} uses L4 ports with protocol {}; only tcp/udp are supported",
            rule_id, proto
        ));
    }
    if min > max {
        return Err(format!(
            "rule {} has invalid destination port range {}-{}",
            rule_id, min, max
        ));
    }
    if min == max {
        Ok(Some(min.to_string()))
    } else {
        Ok(Some(format!("{}-{}", min, max)))
    }
}

fn cidr_group(
    port_id: &str,
    rule_id: &str,
    side: &str,
    cidrs: &[String],
    groups: &mut Vec<AclGroupPlan>,
) -> String {
    if cidrs.is_empty() {
        return "any".to_string();
    }
    let name = format!("{}{}:{}", neutron_acl_prefix(port_id), side, rule_id);
    groups.push(AclGroupPlan {
        name: name.clone(),
        cidrs: cidrs.to_vec(),
    });
    name
}

fn translate_neutron_acl(port_id: &str, acl: &NeutronAclSnapshot) -> Result<AclApplyPlan, String> {
    if !acl.enabled
        || !acl.status.eq_ignore_ascii_case("ready")
        || !acl.effective_action.eq_ignore_ascii_case("enforce")
    {
        return Ok(AclApplyPlan::default());
    }

    let default_action = normalize_default_action(&acl.default_action);
    if !matches!(default_action.as_str(), "allow" | "accept" | "pass") {
        return Err(format!(
            "default_action {} is unsupported in the minimal Neutron ACL translator",
            acl.default_action
        ));
    }

    let mut groups = Vec::new();
    let mut policies = Vec::new();
    let mut seen = BTreeSet::new();
    for (index, rule) in acl.rules.iter().enumerate() {
        let rule_id = acl_rule_id(rule, index);
        if rule
            .ethertype
            .as_deref()
            .map(|ethertype| ethertype.eq_ignore_ascii_case("IPv6"))
            .unwrap_or(false)
        {
            return Err(format!("rule {} uses IPv6 ethertype; unsupported", rule_id));
        }
        ensure_ipv4_cidrs(&rule.src_cidrs, &rule_id)?;
        ensure_ipv4_cidrs(&rule.dst_cidrs, &rule_id)?;

        let proto = proto_from_string(rule.protocol.as_deref().unwrap_or("any"))
            .map_err(|e| format!("rule {} protocol: {}", rule_id, e))?;
        let action = action_from_string(rule.action.as_deref().unwrap_or("allow"))
            .map_err(|e| format!("rule {} action: {}", rule_id, e))?;
        let direction = direction_from_string(rule.direction.as_deref().unwrap_or("ingress"))
            .map_err(|e| format!("rule {} direction: {}", rule_id, e))?;
        let ports = acl_ports(rule, proto, &rule_id)?;
        let src_group = cidr_group(port_id, &rule_id, "src", &rule.src_cidrs, &mut groups);
        let dst_group = cidr_group(port_id, &rule_id, "dst", &rule.dst_cidrs, &mut groups);

        for direction in neutron_acl_to_datapath_directions(direction) {
            let key = (src_group.clone(), dst_group.clone(), proto, direction);
            if !seen.insert(key.clone()) {
                return Err(format!(
                    "duplicate effective ACL key src={} dst={} proto={} direction={}",
                    key.0, key.1, key.2, key.3
                ));
            }
            policies.push(AclPolicyPlan {
                src_group: key.0,
                dst_group: key.1,
                proto,
                action,
                direction,
                ports: ports.clone(),
            });
        }
    }

    Ok(AclApplyPlan { groups, policies })
}

async fn purge_neutron_acl(
    state: &NeutronApiState,
    ifname: &str,
    port_id: &str,
) -> Result<(), String> {
    let (rules, groups_by_name) = match state.control_plane.list_policies(ifname).await {
        Ok(result) => result,
        Err(e) => return Err(e.to_string()),
    };
    let group_names_by_id: BTreeMap<u32, String> = groups_by_name
        .values()
        .map(|group| (group.id, group.name.clone()))
        .collect();

    for rule in rules {
        let src_group = if rule.src_group_id == 0 {
            "any".to_string()
        } else {
            group_names_by_id
                .get(&rule.src_group_id)
                .cloned()
                .unwrap_or_else(|| format!("id:{}", rule.src_group_id))
        };
        let dst_group = if rule.dst_group_id == 0 {
            "any".to_string()
        } else {
            group_names_by_id
                .get(&rule.dst_group_id)
                .cloned()
                .unwrap_or_else(|| format!("id:{}", rule.dst_group_id))
        };
        if is_neutron_acl_group(port_id, &src_group) || is_neutron_acl_group(port_id, &dst_group) {
            state
                .control_plane
                .delete_policy(ifname, &src_group, &dst_group, rule.proto, rule.direction)
                .await
                .map_err(|e| e.to_string())?;
        }
    }

    let groups = state
        .control_plane
        .list_groups(ifname)
        .await
        .map_err(|e| e.to_string())?;
    for group in groups {
        if is_neutron_acl_group(port_id, &group.name) {
            state
                .control_plane
                .delete_group(ifname, &group.name)
                .await
                .map_err(|e| e.to_string())?;
        }
    }

    Ok(())
}

async fn flush_neutron_acl_conntrack(
    state: &NeutronApiState,
    ifname: &str,
    port_id: &str,
) -> Result<(), String> {
    let flushed = state
        .control_plane
        .flush_conntrack(ifname)
        .await
        .map_err(|e| e.to_string())?;
    if flushed > 0 {
        warn!(
            port_id = %port_id,
            ifname = %ifname,
            flushed,
            "flushed conntrack after Neutron ACL reconcile"
        );
    }
    Ok(())
}

async fn reconcile_neutron_acl(
    state: &NeutronApiState,
    port: &NeutronPortSnapshot,
) -> Result<(), String> {
    if !port_manages_acl(port) {
        return Ok(());
    }

    purge_neutron_acl(state, &port.ifname, &port.port_id).await?;

    let Some(acl) = &port.acl else {
        flush_neutron_acl_conntrack(state, &port.ifname, &port.port_id).await?;
        state
            .control_plane
            .update_config(&port.ifname, None, None, Some(false), None, None, None, None)
            .await
            .map_err(|e| e.to_string())?;
        return Ok(());
    };

    let plan = translate_neutron_acl(&port.port_id, acl)?;
    if plan.policies.is_empty() {
        flush_neutron_acl_conntrack(state, &port.ifname, &port.port_id).await?;
        state
            .control_plane
            .update_config(&port.ifname, None, None, Some(false), None, None, None, None)
            .await
            .map_err(|e| e.to_string())?;
        return Ok(());
    }

    for group in &plan.groups {
        for cidr in &group.cidrs {
            if let Err(e) = state.control_plane.add_group(&port.ifname, &group.name, cidr).await {
                let _ = purge_neutron_acl(state, &port.ifname, &port.port_id).await;
                let _ = state
                    .control_plane
                    .update_config(&port.ifname, None, None, Some(false), None, None, None, None)
                    .await;
                return Err(e.to_string());
            }
        }
    }

    for policy in &plan.policies {
        if let Err(e) = state
            .control_plane
            .add_policy(
                &port.ifname,
                &policy.src_group,
                &policy.dst_group,
                policy.proto,
                policy.action,
                policy.direction,
                policy.ports.as_deref(),
            )
            .await
        {
            let _ = purge_neutron_acl(state, &port.ifname, &port.port_id).await;
            let _ = state
                .control_plane
                .update_config(&port.ifname, None, None, Some(false), None, None, None, None)
                .await;
            return Err(e.to_string());
        }
    }

    flush_neutron_acl_conntrack(state, &port.ifname, &port.port_id).await?;
    state
        .control_plane
        .update_config(&port.ifname, None, None, Some(true), None, None, None, None)
        .await
        .map_err(|e| e.to_string())
}

fn build_snapshot_plan(
    current: &BTreeMap<String, ManagedNeutronPort>,
    snapshot: &NeutronSnapshotRequest,
    inventory: &LocalInterfaceInventory,
) -> SnapshotPlan {
    let mut desired = BTreeMap::new();
    let mut ignored = Vec::new();

    for port in &snapshot.ports {
        if port.port_id.trim().is_empty() {
            ignored.push(NeutronPortApplyResult {
                port_id: port.port_id.clone(),
                ifname: port.ifname.clone(),
                action: "ignore".to_string(),
                status: "ignored".to_string(),
                reason: Some("missing port_id".to_string()),
            });
            continue;
        }

        let resolved_port = resolve_local_neutron_port(port, inventory);

        if !resolved_port.eligible {
            ignored.push(NeutronPortApplyResult {
                port_id: resolved_port.port_id.clone(),
                ifname: resolved_port.ifname.clone(),
                action: "ignore".to_string(),
                status: "ignored".to_string(),
                reason: Some(
                    resolved_port
                        .disposition
                        .clone()
                        .unwrap_or_else(|| "not eligible".to_string()),
                ),
            });
            continue;
        }

        if resolved_port.ifname.trim().is_empty() {
            ignored.push(NeutronPortApplyResult {
                port_id: resolved_port.port_id.clone(),
                ifname: resolved_port.ifname.clone(),
                action: "ignore".to_string(),
                status: "ignored".to_string(),
                reason: Some("missing ifname".to_string()),
            });
            continue;
        }

        desired.insert(resolved_port.port_id.clone(), resolved_port);
    }

    let desired_ids: BTreeSet<String> = desired.keys().cloned().collect();
    let mut detach = Vec::new();

    if inventory.is_authoritative() {
        for (port_id, managed) in current {
            match desired.get(port_id) {
                Some(port) if port.ifname == managed.ifname => {}
                _ => detach.push(managed.clone()),
            }
        }
    }

    let mut attach = Vec::new();
    let mut update = Vec::new();
    for (port_id, port) in desired {
        match current.get(&port_id) {
            Some(managed) if managed.ifname == port.ifname => {
                update.push(port);
            }
            _ if desired_ids.contains(&port_id) => {
                attach.push(port);
            }
            _ => {}
        }
    }

    SnapshotPlan {
        attach,
        update,
        detach,
        ignored,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn managed(port_id: &str, ifname: &str) -> ManagedNeutronPort {
        ManagedNeutronPort {
            port_id: port_id.to_string(),
            ifname: ifname.to_string(),
            ifindex: None,
            managed_domains: Vec::new(),
        }
    }

    fn port(port_id: &str, ifname: &str, eligible: bool) -> NeutronPortSnapshot {
        NeutronPortSnapshot {
            port_id: port_id.to_string(),
            ifname: ifname.to_string(),
            ifindex: None,
            eligible,
            disposition: None,
            device_owner: None,
            vif_type: None,
            vnic_type: None,
            network_backend: None,
            ovs_iface_id: None,
            managed_domains: Vec::new(),
            acl: None,
        }
    }

    fn iface(
        name: &str,
        port_id: &str,
        ifindex: Option<u32>,
        bridge: Option<&str>,
    ) -> LocalOvsInterface {
        LocalOvsInterface {
            name: name.to_string(),
            ifindex,
            bridge: bridge.map(ToOwned::to_owned),
            iface_id: Some(port_id.to_string()),
        }
    }

    fn inventory(interfaces: Vec<LocalOvsInterface>) -> LocalInterfaceInventory {
        let mut by_iface_id = BTreeMap::new();
        let mut by_name = BTreeMap::new();
        for interface in interfaces {
            if let Some(iface_id) = interface.iface_id.clone() {
                by_iface_id.insert(iface_id, interface.clone());
            }
            by_name.insert(interface.name.clone(), interface);
        }
        LocalInterfaceInventory {
            ovs_bridge: "br-int".to_string(),
            ovs_error: None,
            by_iface_id,
            by_name,
        }
    }

    #[test]
    fn neutron_snapshot_plan_attaches_only_eligible_ports() {
        let current = BTreeMap::new();
        let local = inventory(vec![iface("tap111", "vm-port", Some(11), Some("br-int"))]);
        let snapshot = NeutronSnapshotRequest {
            generation: 1,
            host: None,
            ports: vec![
                port("vm-port", "tap111", true),
                NeutronPortSnapshot {
                    disposition: Some("service port".to_string()),
                    ..port("dhcp-port", "tap222", false)
                },
            ],
        };

        let plan = build_snapshot_plan(&current, &snapshot, &local);

        let mut expected = port("vm-port", "tap111", true);
        expected.ifindex = Some(11);
        expected.disposition = Some("eligible_ovs_tap".to_string());
        expected.network_backend = Some("openvswitch".to_string());
        expected.ovs_iface_id = Some("vm-port".to_string());
        assert_eq!(plan.attach, vec![expected]);
        assert!(plan.update.is_empty());
        assert!(plan.detach.is_empty());
        assert_eq!(plan.ignored.len(), 1);
        assert_eq!(plan.ignored[0].port_id, "dhcp-port");
    }

    #[test]
    fn neutron_snapshot_plan_detaches_removed_ports() {
        let mut current = BTreeMap::new();
        current.insert("old-port".to_string(), managed("old-port", "tap-old"));
        current.insert("kept-port".to_string(), managed("kept-port", "tap-kept"));
        let local = inventory(vec![iface("tap-kept", "kept-port", Some(12), Some("br-int"))]);
        let snapshot = NeutronSnapshotRequest {
            generation: 2,
            host: None,
            ports: vec![port("kept-port", "tap-kept", true)],
        };

        let plan = build_snapshot_plan(&current, &snapshot, &local);

        assert!(plan.attach.is_empty());
        assert_eq!(plan.update.len(), 1);
        assert_eq!(plan.update[0].port_id, "kept-port");
        assert_eq!(plan.update[0].ifname, "tap-kept");
        assert_eq!(plan.update[0].ifindex, Some(12));
        assert_eq!(plan.detach, vec![managed("old-port", "tap-old")]);
        assert!(plan.ignored.is_empty());
    }

    #[test]
    fn neutron_snapshot_plan_reattaches_when_ifname_changes() {
        let mut current = BTreeMap::new();
        current.insert("vm-port".to_string(), managed("vm-port", "tap-old"));
        let local = inventory(vec![iface("tap-new", "vm-port", Some(13), Some("br-int"))]);
        let snapshot = NeutronSnapshotRequest {
            generation: 3,
            host: None,
            ports: vec![port("vm-port", "tap-new", true)],
        };

        let plan = build_snapshot_plan(&current, &snapshot, &local);

        assert_eq!(plan.detach, vec![managed("vm-port", "tap-old")]);
        assert_eq!(plan.attach.len(), 1);
        assert_eq!(plan.attach[0].ifname, "tap-new");
        assert!(plan.update.is_empty());
        assert!(plan.ignored.is_empty());
    }

    #[test]
    fn neutron_snapshot_plan_detaches_previously_managed_ineligible_port() {
        let mut current = BTreeMap::new();
        current.insert("dhcp-port".to_string(), managed("dhcp-port", "tap-dhcp"));
        let local = inventory(vec![iface("tap-dhcp", "dhcp-port", Some(14), Some("br-int"))]);
        let snapshot = NeutronSnapshotRequest {
            generation: 4,
            host: None,
            ports: vec![NeutronPortSnapshot {
                disposition: Some("device_owner network:dhcp".to_string()),
                ..port("dhcp-port", "tap-dhcp", false)
            }],
        };

        let plan = build_snapshot_plan(&current, &snapshot, &local);

        assert_eq!(plan.detach, vec![managed("dhcp-port", "tap-dhcp")]);
        assert!(plan.attach.is_empty());
        assert!(plan.update.is_empty());
        assert_eq!(plan.ignored[0].reason.as_deref(), Some("device_owner network:dhcp"));
    }

    #[test]
    fn neutron_snapshot_plan_updates_existing_port_domains_without_reattach() {
        let mut current = BTreeMap::new();
        current.insert(
            "vm-port".to_string(),
            ManagedNeutronPort {
                managed_domains: vec!["acl".to_string()],
                ..managed("vm-port", "tap-vm")
            },
        );
        let local = inventory(vec![iface("tap-vm", "vm-port", Some(15), Some("br-int"))]);
        let snapshot = NeutronSnapshotRequest {
            generation: 5,
            host: None,
            ports: vec![NeutronPortSnapshot {
                managed_domains: vec!["acl".to_string(), "qos".to_string()],
                ..port("vm-port", "tap-vm", true)
            }],
        };

        let plan = build_snapshot_plan(&current, &snapshot, &local);

        assert!(plan.attach.is_empty());
        assert!(plan.detach.is_empty());
        assert_eq!(plan.update.len(), 1);
        assert_eq!(
            normalize_managed_domains(&plan.update[0].managed_domains),
            vec!["acl".to_string(), "qos".to_string()]
        );
    }

    #[test]
    fn neutron_snapshot_plan_resolves_candidate_by_ovs_iface_id() {
        let current = BTreeMap::new();
        let local = inventory(vec![iface(
            "tape607e86b-9e",
            "e607e86b-9e5f-4c63-a5df-3dc8986a1b0f",
            Some(27),
            Some("br-int"),
        )]);
        let mut candidate = port("e607e86b-9e5f-4c63-a5df-3dc8986a1b0f", "", true);
        candidate.disposition = Some("pending_local_validation".to_string());
        candidate.managed_domains = vec!["acl".to_string()];
        let snapshot = NeutronSnapshotRequest {
            generation: 6,
            host: None,
            ports: vec![candidate],
        };

        let plan = build_snapshot_plan(&current, &snapshot, &local);

        assert_eq!(plan.attach.len(), 1);
        assert_eq!(plan.attach[0].ifname, "tape607e86b-9e");
        assert_eq!(plan.attach[0].ifindex, Some(27));
        assert_eq!(
            plan.attach[0].disposition.as_deref(),
            Some("eligible_ovs_tap")
        );
        assert!(plan.ignored.is_empty());
    }

    #[test]
    fn neutron_snapshot_plan_does_not_detach_when_ovsdb_unavailable() {
        let mut current = BTreeMap::new();
        current.insert("vm-port".to_string(), managed("vm-port", "tap-vm"));
        let local = LocalInterfaceInventory {
            ovs_bridge: "br-int".to_string(),
            ovs_error: Some("permission denied".to_string()),
            by_iface_id: BTreeMap::new(),
            by_name: BTreeMap::new(),
        };
        let snapshot = NeutronSnapshotRequest {
            generation: 7,
            host: None,
            ports: vec![port("vm-port", "", true)],
        };

        let plan = build_snapshot_plan(&current, &snapshot, &local);

        assert!(plan.attach.is_empty());
        assert!(plan.update.is_empty());
        assert!(plan.detach.is_empty());
        assert_eq!(plan.ignored.len(), 1);
        assert_eq!(
            plan.ignored[0].reason.as_deref(),
            Some("ovsdb_unavailable:permission denied")
        );
    }

    #[test]
    fn neutron_acl_translator_builds_drop_icmp_policy() {
        let acl = NeutronAclSnapshot {
            enabled: true,
            status: "ready".to_string(),
            reason: "ready".to_string(),
            effective_action: "enforce".to_string(),
            policy_id: Some("acl-policy".to_string()),
            policy_name: Some("smoke".to_string()),
            binding_id: Some("acl-binding".to_string()),
            source: Some("port".to_string()),
            default_action: "allow".to_string(),
            stateful: true,
            revision: 1,
            rules: vec![NeutronAclRuleSnapshot {
                id: Some("drop-icmp".to_string()),
                direction: Some("ingress".to_string()),
                priority: 100,
                action: Some("drop".to_string()),
                ethertype: Some("IPv4".to_string()),
                protocol: Some("icmp".to_string()),
                src_cidrs: vec!["10.58.159.2/32".to_string()],
                dst_cidrs: Vec::new(),
                src_port_min: None,
                src_port_max: None,
                dst_port_min: None,
                dst_port_max: None,
            }],
        };

        let plan = translate_neutron_acl("port-1", &acl).expect("ACL should translate");

        assert_eq!(
            plan.groups,
            vec![AclGroupPlan {
                name: "neutron:port-1:src:drop-icmp".to_string(),
                cidrs: vec!["10.58.159.2/32".to_string()],
            }]
        );
        assert_eq!(
            plan.policies,
            vec![AclPolicyPlan {
                src_group: "neutron:port-1:src:drop-icmp".to_string(),
                dst_group: "any".to_string(),
                proto: 1,
                action: 1,
                direction: 1,
                ports: None,
            }]
        );
    }

    #[test]
    fn neutron_acl_translator_rejects_default_deny_until_owned_defaults_exist() {
        let acl = NeutronAclSnapshot {
            enabled: true,
            status: "ready".to_string(),
            reason: "ready".to_string(),
            effective_action: "enforce".to_string(),
            policy_id: Some("acl-policy".to_string()),
            policy_name: None,
            binding_id: None,
            source: Some("port".to_string()),
            default_action: "deny".to_string(),
            stateful: true,
            revision: 1,
            rules: Vec::new(),
        };

        let error = translate_neutron_acl("port-1", &acl).expect_err("default deny is guarded");

        assert!(error.contains("default_action deny is unsupported"));
    }
}
