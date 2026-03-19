use std::sync::Arc;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;

use aria_api::*;
use crate::control_plane::{ControlPlane, ControlPlaneError};

type AppState = Arc<ControlPlane>;

fn err_response(e: ControlPlaneError) -> impl IntoResponse {
    let code = e.status_code();
    let status = StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (status, Json(ApiError { code, error: e.to_string() }))
}

// ── Health ──

pub async fn health(State(cp): State<AppState>) -> impl IntoResponse {
    let instances = cp.list_instances().await;
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        instances: instances.len(),
    })
}

// ── Instances ──

pub async fn list_instances(State(cp): State<AppState>) -> impl IntoResponse {
    let names = cp.list_instances().await;
    Json(InstancesResponse {
        instances: names.into_iter().map(|name| InstanceInfo {
            name,
            active: true,
        }).collect(),
    })
}

// ── System Start/Stop ──

pub async fn system_start(
    State(cp): State<AppState>,
    Json(req): Json<SystemStartRequest>,
) -> impl IntoResponse {
    let pin_path = format!("{}/system", cp.base_pin_path);
    let state_path = format!("{}/system", cp.base_state_path);

    match crate::system_manager::system_start(
        &req.iface, &cp.ebpf_path, &pin_path, &state_path,
        req.max_port_policies, cp.clone(),
    ).await {
        Ok(()) => (StatusCode::OK, Json(MessageResponse {
            message: format!("System firewall started on {}", req.iface),
        })).into_response(),
        Err(e) => {
            let status = StatusCode::INTERNAL_SERVER_ERROR;
            (status, Json(ApiError { code: 500, error: e })).into_response()
        }
    }
}

pub async fn system_stop(State(cp): State<AppState>) -> impl IntoResponse {
    let pin_path = format!("{}/system", cp.base_pin_path);
    let state_path = format!("{}/system", cp.base_state_path);

    match crate::system_manager::system_stop(&pin_path, &state_path, cp.clone()).await {
        Ok(()) => (StatusCode::OK, Json(MessageResponse {
            message: "System firewall stopped".to_string(),
        })).into_response(),
        Err(e) => {
            let status = StatusCode::INTERNAL_SERVER_ERROR;
            (status, Json(ApiError { code: 500, error: e })).into_response()
        }
    }
}

// ── Groups ──

pub async fn list_groups(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.list_groups(&instance).await {
        Ok(groups) => Ok(Json(GroupsResponse {
            groups: groups.into_iter().map(|g| GroupEntry {
                id: g.id,
                name: g.name,
                cidrs: g.cidrs,
            }).collect(),
        })),
        Err(e) => Err(err_response(e)),
    }
}

pub async fn add_group(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
    Json(req): Json<AddGroupRequest>,
) -> impl IntoResponse {
    match cp.add_group(&instance, &req.name, &req.cidr).await {
        Ok(id) => Ok((StatusCode::CREATED, Json(AddGroupResponse {
            id,
            name: req.name,
        }))),
        Err(e) => Err(err_response(e)),
    }
}

pub async fn delete_group(
    State(cp): State<AppState>,
    Path((instance, name)): Path<(String, String)>,
) -> impl IntoResponse {
    match cp.delete_group(&instance, &name).await {
        Ok(()) => Ok(Json(MessageResponse {
            message: format!("Deleted group '{}'", name),
        })),
        Err(e) => Err(err_response(e)),
    }
}

// ── Policies ──

pub async fn list_policies(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.list_policies(&instance).await {
        Ok((rules, groups)) => {
            let find_name = |id: u32| -> String {
                if id == 0 { return "any".to_string(); }
                groups.values()
                    .find(|g| g.id == id)
                    .map(|g| g.name.clone())
                    .unwrap_or_else(|| format!("id:{}", id))
            };
            let policies = rules.into_iter().map(|r| {
                PolicyEntry {
                    src_group: find_name(r.src_group_id),
                    src_group_id: r.src_group_id,
                    dst_group: find_name(r.dst_group_id),
                    dst_group_id: r.dst_group_id,
                    proto: proto_to_string(r.proto),
                    action: action_to_string(r.action),
                    direction: direction_to_string(r.direction),
                    ports: r.ports,
                    bitmap_idx: r.bitmap_idx,
                }
            }).collect();
            Ok(Json(PoliciesResponse { policies }))
        }
        Err(e) => Err(err_response(e)),
    }
}

pub async fn add_policy(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
    Json(req): Json<AddPolicyRequest>,
) -> impl IntoResponse {
    let proto = match proto_from_string(&req.proto) {
        Ok(p) => p,
        Err(e) => return Err(err_response(ControlPlaneError::ValidationError(e))),
    };
    let action = match action_from_string(&req.action) {
        Ok(a) => a,
        Err(e) => return Err(err_response(ControlPlaneError::ValidationError(e))),
    };
    let direction = match direction_from_string(&req.direction) {
        Ok(d) => d,
        Err(e) => return Err(err_response(ControlPlaneError::ValidationError(e))),
    };

    match cp.add_policy(&instance, &req.src_group, &req.dst_group, proto, action, direction, req.ports.as_deref()).await {
        Ok(()) => Ok((StatusCode::CREATED, Json(MessageResponse {
            message: format!("Added policy: {} -> {} ({})", req.src_group, req.dst_group, req.direction),
        }))),
        Err(e) => Err(err_response(e)),
    }
}

pub async fn delete_policy(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
    Json(req): Json<DeletePolicyRequest>,
) -> impl IntoResponse {
    let proto = match proto_from_string(&req.proto) {
        Ok(p) => p,
        Err(e) => return Err(err_response(ControlPlaneError::ValidationError(e))),
    };
    let direction = match direction_from_string(&req.direction) {
        Ok(d) => d,
        Err(e) => return Err(err_response(ControlPlaneError::ValidationError(e))),
    };

    match cp.delete_policy(&instance, &req.src_group, &req.dst_group, proto, direction).await {
        Ok(()) => Ok(Json(MessageResponse {
            message: format!("Deleted policy: {} -> {}", req.src_group, req.dst_group),
        })),
        Err(e) => Err(err_response(e)),
    }
}

pub async fn batch_add_policies(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
    Json(req): Json<BatchAddPoliciesRequest>,
) -> impl IntoResponse {
    let mut added = 0;
    let mut errors = Vec::new();

    for policy in &req.policies {
        let proto = match proto_from_string(&policy.proto) {
            Ok(p) => p,
            Err(e) => { errors.push(e); continue; }
        };
        let action = match action_from_string(&policy.action) {
            Ok(a) => a,
            Err(e) => { errors.push(e); continue; }
        };
        let direction = match direction_from_string(&policy.direction) {
            Ok(d) => d,
            Err(e) => { errors.push(e); continue; }
        };

        match cp.add_policy(&instance, &policy.src_group, &policy.dst_group, proto, action, direction, policy.ports.as_deref()).await {
            Ok(()) => added += 1,
            Err(e) => errors.push(e.to_string()),
        }
    }

    let status = if errors.is_empty() { StatusCode::CREATED } else { StatusCode::OK };
    (status, Json(BatchPoliciesResponse { added, errors }))
}

// ── QoS ──

pub async fn list_qos(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.list_qos(&instance).await {
        Ok(rules) => Ok(Json(QosListResponse {
            rules: rules.into_iter().map(|r| QosEntry {
                group: r.group_name,
                group_id: r.group_id,
                direction: direction_to_string(r.direction),
                rate_bps: r.rate_bps,
                burst_bytes: r.burst_bytes,
                priority: r.priority,
                mode: if r.mode == 1 { "shaping".to_string() } else { "policing".to_string() },
            }).collect(),
        })),
        Err(e) => Err(err_response(e)),
    }
}

pub async fn add_qos(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
    Json(req): Json<AddQosRequest>,
) -> impl IntoResponse {
    let direction = match direction_from_string(&req.direction) {
        Ok(d) => d,
        Err(e) => return Err(err_response(ControlPlaneError::ValidationError(e))),
    };
    let rate_bps = match aria_core::qos_ops::parse_rate(&req.rate) {
        Ok(r) => r,
        Err(e) => return Err(err_response(ControlPlaneError::ValidationError(e))),
    };
    let burst_bytes = if req.burst.is_empty() || req.burst == "0" {
        aria_core::qos_ops::compute_default_burst(rate_bps)
    } else {
        match aria_core::qos_ops::parse_burst(&req.burst) {
            Ok(b) => b,
            Err(e) => return Err(err_response(ControlPlaneError::ValidationError(e))),
        }
    };
    let mode: u8 = match req.mode.to_lowercase().as_str() {
        "policing" | "" => 0,
        "shaping" => 1,
        other => return Err(err_response(ControlPlaneError::ValidationError(
            format!("Invalid mode '{}': must be 'policing' or 'shaping'", other)
        ))),
    };

    // direction=2 means "both": apply to ingress and egress
    let directions: Vec<u8> = if direction == 2 { vec![0, 1] } else { vec![direction] };

    for dir in &directions {
        // Ingress does not support shaping mode
        let effective_mode = if *dir == 0 && mode == 1 { 0 } else { mode };
        if let Err(e) = cp.add_qos(&instance, &req.group, *dir, rate_bps, burst_bytes, req.priority, effective_mode).await {
            return Err(err_response(e));
        }
    }

    let dir_label = if direction == 2 { "both" } else { &req.direction };
    Ok((StatusCode::CREATED, Json(MessageResponse {
        message: format!("Added QoS rule for group '{}' ({})", req.group, dir_label),
    })))
}

pub async fn delete_qos(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
    Json(req): Json<DeleteQosRequest>,
) -> impl IntoResponse {
    let direction = match direction_from_string(&req.direction) {
        Ok(d) => d,
        Err(e) => return Err(err_response(ControlPlaneError::ValidationError(e))),
    };

    // direction=2 means "both": delete ingress and egress
    let directions: Vec<u8> = if direction == 2 { vec![0, 1] } else { vec![direction] };

    for dir in &directions {
        if let Err(e) = cp.delete_qos(&instance, &req.group, *dir).await {
            return Err(err_response(e));
        }
    }

    let dir_label = if direction == 2 { "both" } else { &req.direction };
    Ok(Json(MessageResponse {
        message: format!("Deleted QoS rule for group '{}' ({})", req.group, dir_label),
    }))
}

// ── Conntrack ──

pub async fn list_conntrack(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.list_conntrack(&instance).await {
        Ok(entries) => {
            let total = entries.len();
            let connections: Vec<ConntrackEntry> = entries.into_iter().map(|e| ConntrackEntry {
                src_ip: e.src_ip,
                dst_ip: e.dst_ip,
                src_port: e.src_port,
                dst_port: e.dst_port,
                proto: proto_to_string(e.proto),
                state: match e.state {
                    1 => "NEW".to_string(),
                    2 => "ESTABLISHED".to_string(),
                    _ => "UNKNOWN".to_string(),
                },
                packets: e.pkt_count,
                bytes: e.byte_count,
            }).collect();
            Ok(Json(ConntrackResponse { connections, total }))
        }
        Err(e) => Err(err_response(e)),
    }
}

pub async fn flush_conntrack(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.flush_conntrack(&instance).await {
        Ok(count) => Ok(Json(ConntrackFlushResponse { flushed: count })),
        Err(e) => Err(err_response(e)),
    }
}

// ── Config ──

pub async fn get_config(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.get_config(&instance).await {
        Ok(cfg) => Ok(Json(ConfigResponse {
            conntrack: cfg.conntrack_enabled != 0,
            monitoring: cfg.monitoring_enabled != 0,
            acl: cfg.acl_enabled != 0,
            qos: cfg.qos_enabled != 0,
            mirror: cfg.mirror_enabled != 0,
            tcprt: cfg.tcprt_enabled != 0,
            num_cpus: cfg.num_cpus,
        })),
        Err(e) => Err(err_response(e)),
    }
}

pub async fn update_config(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
    Json(req): Json<UpdateConfigRequest>,
) -> impl IntoResponse {
    match cp.update_config(&instance, req.conntrack, req.monitoring, req.acl, req.qos, req.mirror, req.tcprt).await {
        Ok(()) => Ok(Json(MessageResponse {
            message: "Configuration updated".to_string(),
        })),
        Err(e) => Err(err_response(e)),
    }
}

// ── Stats ──

pub async fn stats_overview(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.get_stats_overview(&instance).await {
        Ok((groups, policies, qos_rules, mirror_rules, ct_v4, ct_v6)) => Ok(Json(StatsOverview {
            groups,
            policies,
            qos_rules,
            mirror_rules,
            conntrack_v4: ct_v4,
            conntrack_v6: ct_v6,
        })),
        Err(e) => Err(err_response(e)),
    }
}

pub async fn stats_rules(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.get_rule_stats(&instance).await {
        Ok((entries, groups)) => {
            let find_name = |id: u32| -> String {
                if id == 0 { return "any".to_string(); }
                groups.values()
                    .find(|g| g.id == id)
                    .map(|g| g.name.clone())
                    .unwrap_or_else(|| format!("id:{}", id))
            };
            Ok(Json(RuleStatsResponse {
                rules: entries.into_iter().map(|e| aria_api::RuleStatsEntry {
                    src_group: find_name(e.key.src_id),
                    src_id: e.key.src_id,
                    dst_group: find_name(e.key.dst_id),
                    dst_id: e.key.dst_id,
                    proto: proto_to_string(e.key.proto),
                    direction: direction_to_string(e.key.direction),
                    packets: e.packets,
                    bytes: e.bytes,
                }).collect(),
            }))
        }
        Err(e) => Err(err_response(e)),
    }
}

#[derive(Deserialize)]
pub struct TopQuery {
    #[serde(default = "default_top")]
    pub top: usize,
}

fn default_top() -> usize { 20 }

pub async fn stats_flows(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
    Query(query): Query<TopQuery>,
) -> impl IntoResponse {
    match cp.get_top_flows(&instance, query.top).await {
        Ok((v4, v6)) => {
            let mut flows: Vec<FlowEntry> = Vec::new();
            for e in v4 {
                flows.push(FlowEntry {
                    src_ip: e.src_ip.to_string(),
                    dst_ip: e.dst_ip.to_string(),
                    src_port: e.src_port,
                    dst_port: e.dst_port,
                    proto: proto_to_string(e.proto),
                    packets: e.packets,
                    bytes: e.bytes,
                });
            }
            for e in v6 {
                flows.push(FlowEntry {
                    src_ip: e.src_ip.to_string(),
                    dst_ip: e.dst_ip.to_string(),
                    src_port: e.src_port,
                    dst_port: e.dst_port,
                    proto: proto_to_string(e.proto),
                    packets: e.packets,
                    bytes: e.bytes,
                });
            }
            Ok(Json(FlowStatsResponse { flows }))
        }
        Err(e) => Err(err_response(e)),
    }
}

pub async fn stats_qos(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.get_qos_stats(&instance).await {
        Ok((entries, groups)) => {
            let find_name = |id: u32| -> String {
                if id == 0 { return "any".to_string(); }
                groups.values()
                    .find(|g| g.id == id)
                    .map(|g| g.name.clone())
                    .unwrap_or_else(|| format!("id:{}", id))
            };
            Ok(Json(QosStatsResponse {
                rules: entries.into_iter().map(|e| aria_api::QosStatsEntry {
                    group: find_name(e.key.group_id),
                    group_id: e.key.group_id,
                    direction: direction_to_string(e.key.direction),
                    passed_packets: e.passed_packets,
                    passed_bytes: e.passed_bytes,
                    dropped_packets: e.dropped_packets,
                    dropped_bytes: e.dropped_bytes,
                    shaped_packets: e.shaped_packets,
                    shaped_bytes: e.shaped_bytes,
                }).collect(),
            }))
        }
        Err(e) => Err(err_response(e)),
    }
}

pub async fn stats_groups(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.get_group_stats(&instance).await {
        Ok((entries, groups)) => {
            let find_name = |id: u32| -> String {
                if id == 0 { return "any".to_string(); }
                groups.values()
                    .find(|g| g.id == id)
                    .map(|g| g.name.clone())
                    .unwrap_or_else(|| format!("id:{}", id))
            };
            Ok(Json(GroupStatsResponse {
                groups: entries.into_iter().map(|e| aria_api::GroupStatsEntry {
                    group: find_name(e.key.group_id),
                    group_id: e.key.group_id,
                    direction: direction_to_string(e.key.direction),
                    packets: e.packets,
                    bytes: e.bytes,
                }).collect(),
            }))
        }
        Err(e) => Err(err_response(e)),
    }
}

// ── Mirror ──

pub async fn list_mirror(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.list_mirror(&instance).await {
        Ok(rules) => Ok(Json(MirrorListResponse {
            rules: rules.into_iter().map(|r| MirrorEntry {
                src_group: r.src_group_name,
                src_group_id: r.src_group_id,
                dst_group: r.dst_group_name,
                dst_group_id: r.dst_group_id,
                proto: proto_to_string(r.proto),
                direction: direction_to_string(r.direction),
                target_iface: r.target_iface,
                target_ifindex: r.target_ifindex,
                is_global: r.is_global,
            }).collect(),
        })),
        Err(e) => Err(err_response(e)),
    }
}

pub async fn add_mirror(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
    Json(req): Json<AddMirrorRequest>,
) -> impl IntoResponse {
    let proto = match proto_from_string(&req.proto) {
        Ok(p) => p,
        Err(e) => return Err(err_response(ControlPlaneError::ValidationError(e))),
    };
    let direction = match direction_from_string(&req.direction) {
        Ok(d) => d,
        Err(e) => return Err(err_response(ControlPlaneError::ValidationError(e))),
    };

    // direction=2 means "both": apply to ingress and egress
    let directions: Vec<u8> = if direction == 2 { vec![0, 1] } else { vec![direction] };

    for dir in &directions {
        if let Err(e) = cp.add_mirror(&instance, &req.src_group, &req.dst_group, proto, *dir, &req.target).await {
            return Err(err_response(e));
        }
    }

    let dir_label = if direction == 2 { "both" } else { &req.direction };
    Ok((StatusCode::CREATED, Json(MessageResponse {
        message: format!("Added mirror rule ({}) -> target '{}'", dir_label, req.target),
    })))
}

pub async fn delete_mirror(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
    Json(req): Json<DeleteMirrorRequest>,
) -> impl IntoResponse {
    let proto = match proto_from_string(&req.proto) {
        Ok(p) => p,
        Err(e) => return Err(err_response(ControlPlaneError::ValidationError(e))),
    };
    let direction = match direction_from_string(&req.direction) {
        Ok(d) => d,
        Err(e) => return Err(err_response(ControlPlaneError::ValidationError(e))),
    };

    let directions: Vec<u8> = if direction == 2 { vec![0, 1] } else { vec![direction] };

    for dir in &directions {
        if let Err(e) = cp.delete_mirror(&instance, &req.src_group, &req.dst_group, proto, *dir).await {
            return Err(err_response(e));
        }
    }

    let dir_label = if direction == 2 { "both" } else { &req.direction };
    Ok(Json(MessageResponse {
        message: format!("Deleted mirror rule ({})", dir_label),
    }))
}

pub async fn stats_mirror(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.get_mirror_stats(&instance).await {
        Ok((entries, groups)) => {
            let find_name = |id: u32| -> String {
                if id == 0 { return "any".to_string(); }
                groups.values()
                    .find(|g| g.id == id)
                    .map(|g| g.name.clone())
                    .unwrap_or_else(|| format!("id:{}", id))
            };
            Ok(Json(MirrorStatsResponse {
                rules: entries.into_iter().map(|e| aria_api::MirrorStatsEntry {
                    src_group: find_name(e.src_id),
                    src_id: e.src_id,
                    dst_group: find_name(e.dst_id),
                    dst_id: e.dst_id,
                    proto: proto_to_string(e.proto),
                    direction: direction_to_string(e.direction),
                    mirrored_packets: e.mirrored_packets,
                    mirrored_bytes: e.mirrored_bytes,
                    errors: e.errors,
                    is_global: e.is_global,
                }).collect(),
            }))
        }
        Err(e) => Err(err_response(e)),
    }
}

// ── TCP-RT ──

pub async fn list_tcprt(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
    Query(query): Query<TopQuery>,
) -> impl IntoResponse {
    match cp.list_tcprt(&instance, query.top).await {
        Ok(entries) => {
            let flows = entries.into_iter().map(|e| aria_api::TcpRtEntry {
                src_ip: e.src_ip,
                dst_ip: e.dst_ip,
                src_port: e.src_port,
                dst_port: e.dst_port,
                handshake_us: e.handshake_us,
                rtt_client_us: e.rtt_client_us,
                rtt_server_us: e.rtt_server_us,
                art_us: e.art_us,
                retrans_req: e.retrans_req,
                retrans_resp: e.retrans_resp,
                request_count: e.request_count,
                state: e.state,
            }).collect();
            Ok(Json(aria_api::TcpRtResponse { flows }))
        }
        Err(e) => Err(err_response(e)),
    }
}

pub async fn flush_tcprt(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.flush_tcprt(&instance).await {
        Ok(count) => Ok(Json(aria_api::TcpRtFlushResponse { flushed: count })),
        Err(e) => Err(err_response(e)),
    }
}

pub async fn batch_query_tcprt(
    State(cp): State<AppState>,
    Json(req): Json<aria_api::TcpRtBatchQueryRequest>,
) -> impl IntoResponse {
    let tuples: Vec<(String, String, u16, u16)> = req.tuples.into_iter()
        .map(|t| (t.src_ip, t.dst_ip, t.src_port, t.dst_port))
        .collect();
    match cp.batch_query_tcprt(&tuples).await {
        Ok(entries) => {
            let results = entries.into_iter().map(|(instance, e)| aria_api::TcpRtInstanceEntry {
                instance,
                entry: aria_api::TcpRtEntry {
                    src_ip: e.src_ip,
                    dst_ip: e.dst_ip,
                    src_port: e.src_port,
                    dst_port: e.dst_port,
                    handshake_us: e.handshake_us,
                    rtt_client_us: e.rtt_client_us,
                    rtt_server_us: e.rtt_server_us,
                    art_us: e.art_us,
                    retrans_req: e.retrans_req,
                    retrans_resp: e.retrans_resp,
                    request_count: e.request_count,
                    state: e.state,
                },
            }).collect();
            Ok(Json(aria_api::TcpRtBatchQueryResponse { results }))
        }
        Err(e) => Err(err_response(e)),
    }
}

// ── Drop Reason Profiler ──

pub async fn list_drops(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.get_drop_stats(&instance).await {
        Ok((entries, groups)) => {
            let find_name = |id: u32| -> String {
                if id == 0 { return "any".to_string(); }
                groups.values()
                    .find(|g| g.id == id)
                    .map(|g| g.name.clone())
                    .unwrap_or_else(|| format!("id:{}", id))
            };
            Ok(Json(aria_api::DropStatsResponse {
                drops: entries.into_iter().map(|e| aria_api::DropStatsEntry {
                    reason: aria_core::trace_ops::drop_reason_name(e.reason),
                    direction: direction_to_string(e.direction),
                    proto: proto_to_string(e.proto),
                    src_group: find_name(e.src_id),
                    src_id: e.src_id,
                    dst_group: find_name(e.dst_id),
                    dst_id: e.dst_id,
                    packets: e.packets,
                    bytes: e.bytes,
                }).collect(),
            }))
        }
        Err(e) => Err(err_response(e)),
    }
}

pub async fn flush_drops(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.flush_drop_stats(&instance).await {
        Ok(count) => Ok(Json(aria_api::DropFlushResponse { flushed: count })),
        Err(e) => Err(err_response(e)),
    }
}

// ── Packet Trace ──

pub async fn start_trace(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
    Json(req): Json<aria_api::TraceStartRequest>,
) -> impl IntoResponse {
    let src_ip: u32 = if req.src_ip.is_empty() {
        0
    } else {
        match req.src_ip.parse::<std::net::Ipv4Addr>() {
            Ok(ip) => u32::from(ip),
            Err(_) => return Err(err_response(ControlPlaneError::ValidationError(
                format!("Invalid src_ip: {}", req.src_ip)
            ))),
        }
    };
    let dst_ip: u32 = if req.dst_ip.is_empty() {
        0
    } else {
        match req.dst_ip.parse::<std::net::Ipv4Addr>() {
            Ok(ip) => u32::from(ip),
            Err(_) => return Err(err_response(ControlPlaneError::ValidationError(
                format!("Invalid dst_ip: {}", req.dst_ip)
            ))),
        }
    };
    let proto: u8 = if req.proto.is_empty() {
        0
    } else {
        match proto_from_string(&req.proto) {
            Ok(p) => p,
            Err(e) => return Err(err_response(ControlPlaneError::ValidationError(e))),
        }
    };

    match cp.start_trace(&instance, src_ip, dst_ip, req.src_port, req.dst_port, proto).await {
        Ok(()) => Ok((StatusCode::OK, Json(MessageResponse {
            message: "Trace started".to_string(),
        }))),
        Err(e) => Err(err_response(e)),
    }
}

pub async fn stop_trace(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.stop_trace(&instance).await {
        Ok(()) => Ok(Json(MessageResponse {
            message: "Trace stopped".to_string(),
        })),
        Err(e) => Err(err_response(e)),
    }
}

pub async fn list_trace(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
    Query(query): Query<TopQuery>,
) -> impl IntoResponse {
    match cp.get_trace_events(&instance, query.top).await {
        Ok((entries, groups)) => {
            let find_name = |id: u32| -> String {
                if id == 0 { return "any".to_string(); }
                groups.values()
                    .find(|g| g.id == id)
                    .map(|g| g.name.clone())
                    .unwrap_or_else(|| format!("id:{}", id))
            };
            Ok(Json(aria_api::TraceResponse {
                events: entries.into_iter().map(|e| aria_api::TraceEventEntry {
                    seq: e.seq,
                    timestamp: e.timestamp,
                    src_ip: e.src_ip,
                    dst_ip: e.dst_ip,
                    src_port: e.src_port,
                    dst_port: e.dst_port,
                    proto: proto_to_string(e.proto),
                    hook: e.hook,
                    result: e.result,
                    direction: e.direction,
                    src_group: find_name(e.src_id),
                    src_id: e.src_id,
                    dst_group: find_name(e.dst_id),
                    dst_id: e.dst_id,
                    pkt_len: e.pkt_len,
                    ct_state: e.ct_state,
                    drop_reason: e.drop_reason,
                }).collect(),
            }))
        }
        Err(e) => Err(err_response(e)),
    }
}

pub async fn flush_trace(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.flush_trace(&instance).await {
        Ok(count) => Ok(Json(aria_api::TraceFlushResponse { flushed: count })),
        Err(e) => Err(err_response(e)),
    }
}
