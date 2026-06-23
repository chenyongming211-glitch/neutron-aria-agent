use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

use crate::control_plane::ControlPlane;
use crate::tap_registry::TapRegistry;

#[derive(Clone)]
pub(crate) struct NeutronApiState {
    registry: Arc<TapRegistry>,
    control_plane: Arc<ControlPlane>,
    runtime: Arc<RwLock<NeutronRuntimeState>>,
    apply_lock: Arc<Mutex<()>>,
}

#[derive(Default)]
struct NeutronRuntimeState {
    generation: u64,
    ports: BTreeMap<String, ManagedNeutronPort>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct NeutronSnapshotRequest {
    #[serde(default)]
    pub generation: u64,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub ports: Vec<NeutronPortSnapshot>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct NeutronPortSnapshot {
    pub port_id: String,
    #[serde(default)]
    pub ifname: String,
    #[serde(default)]
    pub ifindex: Option<u32>,
    #[serde(default)]
    pub eligible: bool,
    #[serde(default)]
    pub disposition: Option<String>,
    #[serde(default)]
    pub device_owner: Option<String>,
    #[serde(default)]
    pub vif_type: Option<String>,
    #[serde(default)]
    pub vnic_type: Option<String>,
    #[serde(default)]
    pub network_backend: Option<String>,
    #[serde(default)]
    pub ovs_iface_id: Option<String>,
    #[serde(default)]
    pub managed_domains: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct ManagedNeutronPort {
    pub port_id: String,
    pub ifname: String,
    pub ifindex: Option<u32>,
    pub managed_domains: Vec<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct NeutronCapabilitiesResponse {
    api_version: &'static str,
    attach_authority: &'static str,
    supports_full_snapshot: bool,
    supports_port_delete: bool,
    supported_domains: Vec<&'static str>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct NeutronStatusResponse {
    generation: u64,
    managed_ports: Vec<ManagedNeutronPort>,
    active_instances: Vec<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct NeutronSnapshotResponse {
    generation: u64,
    results: Vec<NeutronPortApplyResult>,
    active_instances: Vec<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct NeutronDeleteResponse {
    port_id: String,
    ifname: Option<String>,
    detached: bool,
    status: String,
    error: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct NeutronPortApplyResult {
    port_id: String,
    ifname: String,
    action: String,
    status: String,
    reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SnapshotPlan {
    attach: Vec<NeutronPortSnapshot>,
    update: Vec<NeutronPortSnapshot>,
    detach: Vec<ManagedNeutronPort>,
    ignored: Vec<NeutronPortApplyResult>,
}

impl NeutronApiState {
    fn new(registry: Arc<TapRegistry>, control_plane: Arc<ControlPlane>) -> Self {
        Self {
            registry,
            control_plane,
            runtime: Arc::new(RwLock::new(NeutronRuntimeState::default())),
            apply_lock: Arc::new(Mutex::new(())),
        }
    }
}

pub(crate) fn build_router(registry: Arc<TapRegistry>, control_plane: Arc<ControlPlane>) -> Router {
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
        .with_state(NeutronApiState::new(registry, control_plane))
}

async fn get_neutron_capabilities() -> impl IntoResponse {
    Json(NeutronCapabilitiesResponse {
        api_version: "v1",
        attach_authority: "neutron_snapshot",
        supports_full_snapshot: true,
        supports_port_delete: true,
        supported_domains: vec![
            "attach",
            "acl",
            "qos",
            "mirror",
            "config",
            "conntrack",
            "tcprt",
            "trace",
            "drops",
            "ssl",
        ],
    })
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
    let _guard = state.apply_lock.lock().await;
    let current_ports = state.runtime.read().await.ports.clone();
    let plan = build_snapshot_plan(&current_ports, &snapshot);

    let mut next_ports = current_ports;
    let mut results = plan.ignored;

    for port in plan.detach {
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

    for port in plan.attach {
        match state.registry.attach(&port.ifname).await {
            Ok(()) => {
                let managed = managed_port_from_snapshot(&port);
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

    Json(NeutronSnapshotResponse {
        generation: snapshot.generation,
        results,
        active_instances: state.registry.list().await,
    })
}

async fn delete_neutron_port(
    State(state): State<NeutronApiState>,
    Path(port_id): Path<String>,
) -> impl IntoResponse {
    let _guard = state.apply_lock.lock().await;
    let port = {
        let runtime = state.runtime.read().await;
        runtime.ports.get(&port_id).cloned()
    };

    let Some(port) = port else {
        return (
            StatusCode::OK,
            Json(NeutronDeleteResponse {
                port_id,
                ifname: None,
                detached: false,
                status: "not_found".to_string(),
                error: None,
            }),
        );
    };

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
                Json(NeutronDeleteResponse {
                    port_id: port.port_id,
                    ifname: Some(port.ifname),
                    detached: true,
                    status: "ok".to_string(),
                    error: None,
                }),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(NeutronDeleteResponse {
                port_id: port.port_id,
                ifname: Some(port.ifname),
                detached: false,
                status: "error".to_string(),
                error: Some(e),
            }),
        ),
    }
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

fn build_snapshot_plan(
    current: &BTreeMap<String, ManagedNeutronPort>,
    snapshot: &NeutronSnapshotRequest,
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

        if port.ifname.trim().is_empty() {
            ignored.push(NeutronPortApplyResult {
                port_id: port.port_id.clone(),
                ifname: port.ifname.clone(),
                action: "ignore".to_string(),
                status: "ignored".to_string(),
                reason: Some("missing ifname".to_string()),
            });
            continue;
        }

        if !port.eligible {
            ignored.push(NeutronPortApplyResult {
                port_id: port.port_id.clone(),
                ifname: port.ifname.clone(),
                action: "ignore".to_string(),
                status: "ignored".to_string(),
                reason: Some(
                    port.disposition
                        .clone()
                        .unwrap_or_else(|| "not eligible".to_string()),
                ),
            });
            continue;
        }

        desired.insert(port.port_id.clone(), port.clone());
    }

    let desired_ids: BTreeSet<String> = desired.keys().cloned().collect();
    let mut detach = Vec::new();

    for (port_id, managed) in current {
        match desired.get(port_id) {
            Some(port) if port.ifname == managed.ifname => {}
            _ => detach.push(managed.clone()),
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
        }
    }

    #[test]
    fn neutron_snapshot_plan_attaches_only_eligible_ports() {
        let current = BTreeMap::new();
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

        let plan = build_snapshot_plan(&current, &snapshot);

        assert_eq!(plan.attach, vec![port("vm-port", "tap111", true)]);
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
        let snapshot = NeutronSnapshotRequest {
            generation: 2,
            host: None,
            ports: vec![port("kept-port", "tap-kept", true)],
        };

        let plan = build_snapshot_plan(&current, &snapshot);

        assert!(plan.attach.is_empty());
        assert_eq!(plan.update, vec![port("kept-port", "tap-kept", true)]);
        assert_eq!(plan.detach, vec![managed("old-port", "tap-old")]);
        assert!(plan.ignored.is_empty());
    }

    #[test]
    fn neutron_snapshot_plan_reattaches_when_ifname_changes() {
        let mut current = BTreeMap::new();
        current.insert("vm-port".to_string(), managed("vm-port", "tap-old"));
        let snapshot = NeutronSnapshotRequest {
            generation: 3,
            host: None,
            ports: vec![port("vm-port", "tap-new", true)],
        };

        let plan = build_snapshot_plan(&current, &snapshot);

        assert_eq!(plan.detach, vec![managed("vm-port", "tap-old")]);
        assert_eq!(plan.attach, vec![port("vm-port", "tap-new", true)]);
        assert!(plan.update.is_empty());
        assert!(plan.ignored.is_empty());
    }

    #[test]
    fn neutron_snapshot_plan_detaches_previously_managed_ineligible_port() {
        let mut current = BTreeMap::new();
        current.insert("dhcp-port".to_string(), managed("dhcp-port", "tap-dhcp"));
        let snapshot = NeutronSnapshotRequest {
            generation: 4,
            host: None,
            ports: vec![NeutronPortSnapshot {
                disposition: Some("device_owner network:dhcp".to_string()),
                ..port("dhcp-port", "tap-dhcp", false)
            }],
        };

        let plan = build_snapshot_plan(&current, &snapshot);

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
        let snapshot = NeutronSnapshotRequest {
            generation: 5,
            host: None,
            ports: vec![NeutronPortSnapshot {
                managed_domains: vec!["acl".to_string(), "qos".to_string()],
                ..port("vm-port", "tap-vm", true)
            }],
        };

        let plan = build_snapshot_plan(&current, &snapshot);

        assert!(plan.attach.is_empty());
        assert!(plan.detach.is_empty());
        assert_eq!(plan.update.len(), 1);
        assert_eq!(
            normalize_managed_domains(&plan.update[0].managed_domains),
            vec!["acl".to_string(), "qos".to_string()]
        );
    }
}
