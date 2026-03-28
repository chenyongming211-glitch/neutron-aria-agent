use async_stream::stream;
use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::IntoResponse,
    Json,
};
use bytes::Bytes;
use serde::Deserialize;
use std::fmt::Write;
use std::sync::Arc;
use tracing::warn;

use crate::control_plane::{ControlPlane, ControlPlaneError};
use crate::kernel_drop_manager::KernelDropMode;
use aria_core::ebpf_ops::TraceMapMode;
use aria_api::*;

type AppState = Arc<ControlPlane>;

fn err_response(e: ControlPlaneError) -> impl IntoResponse {
    let code = e.status_code();
    let status = StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (
        status,
        Json(ApiError {
            code,
            error: e.to_string(),
        }),
    )
}

fn legacy_drop_headers(instance: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("deprecation"),
        HeaderValue::from_static("true"),
    );
    headers.insert(
        HeaderName::from_static("sunset"),
        HeaderValue::from_static("Tue, 30 Jun 2026 00:00:00 GMT"),
    );
    if let Ok(value) = HeaderValue::from_str(&format!(
        "</api/v1/stats/kernel_drops?instance={}>; rel=\"successor-version\"",
        instance
    )) {
        headers.insert(header::LINK, value);
    }
    headers
}

fn kernel_drop_mode_name(mode: KernelDropMode) -> &'static str {
    match mode {
        KernelDropMode::Disabled => "disabled",
        KernelDropMode::ScaffoldOnly => "scaffold_only",
        KernelDropMode::KfreeSkbLegacy => "kfree_skb_legacy",
        KernelDropMode::KfreeSkbReasonful => "kfree_skb_reasonful",
    }
}

fn trace_map_mode_name(mode: TraceMapMode) -> &'static str {
    match mode {
        TraceMapMode::Legacy => "legacy",
        TraceMapMode::Stream => "stream",
    }
}

// ── Health ──

pub async fn health(State(cp): State<AppState>) -> impl IntoResponse {
    let instances = cp.list_instances().await;
    let kernel_drop = cp.get_kernel_drop_status().await;
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        instances: instances.len(),
        kernel_drop_available: kernel_drop.loaded,
        kernel_drop_mode: Some(kernel_drop_mode_name(kernel_drop.mode).to_string()),
        kernel_drop_managed_ifaces: kernel_drop.managed_ifaces,
        kernel_drop_last_error: kernel_drop.last_error,
    })
}

// ── Instances ──

pub async fn list_instances(State(cp): State<AppState>) -> impl IntoResponse {
    let names = cp.list_instances().await;
    Json(InstancesResponse {
        instances: names
            .into_iter()
            .map(|name| InstanceInfo { name, active: true })
            .collect(),
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
        &req.iface,
        &cp.ebpf_path,
        &pin_path,
        &state_path,
        req.max_port_policies,
        cp.clone(),
    )
    .await
    {
        Ok(()) => (
            StatusCode::OK,
            Json(MessageResponse {
                message: format!("System firewall started on {}", req.iface),
            }),
        )
            .into_response(),
        Err(e) => {
            let status = StatusCode::INTERNAL_SERVER_ERROR;
            (
                status,
                Json(ApiError {
                    code: 500,
                    error: e,
                }),
            )
                .into_response()
        }
    }
}

pub async fn system_stop(State(cp): State<AppState>) -> impl IntoResponse {
    let pin_path = format!("{}/system", cp.base_pin_path);
    let state_path = format!("{}/system", cp.base_state_path);

    match crate::system_manager::system_stop(&pin_path, &state_path, cp.clone()).await {
        Ok(()) => (
            StatusCode::OK,
            Json(MessageResponse {
                message: "System firewall stopped".to_string(),
            }),
        )
            .into_response(),
        Err(e) => {
            let status = StatusCode::INTERNAL_SERVER_ERROR;
            (
                status,
                Json(ApiError {
                    code: 500,
                    error: e,
                }),
            )
                .into_response()
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
            groups: groups
                .into_iter()
                .map(|g| GroupEntry {
                    id: g.id,
                    name: g.name,
                    cidrs: g.cidrs,
                })
                .collect(),
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
        Ok(id) => Ok((
            StatusCode::CREATED,
            Json(AddGroupResponse { id, name: req.name }),
        )),
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

pub async fn list_groups_with_stats(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.list_groups_with_stats(&instance).await {
        Ok((groups, stats)) => {
            // Build stats map for O(1) lookup: (group_id, direction) -> stats
            let mut stats_map: std::collections::HashMap<
                (u32, u8),
                aria_core::monitoring::GroupStatsEntry,
            > = stats
                .into_iter()
                .map(|s| ((s.key.group_id, s.key.direction), s))
                .collect();

            let groups_with_stats = groups
                .into_iter()
                .map(|g| {
                    let ingress_key = (g.id, 0u8); // direction=0 for ingress
                    let egress_key = (g.id, 1u8); // direction=1 for egress
                    let ingress_stats = stats_map.remove(&ingress_key);
                    let egress_stats = stats_map.remove(&egress_key);
                    GroupWithStatsEntry {
                        id: g.id,
                        name: g.name,
                        cidrs: g.cidrs,
                        ingress_packets: ingress_stats.as_ref().map(|s| s.packets).unwrap_or(0),
                        ingress_bytes: ingress_stats.as_ref().map(|s| s.bytes).unwrap_or(0),
                        egress_packets: egress_stats.as_ref().map(|s| s.packets).unwrap_or(0),
                        egress_bytes: egress_stats.as_ref().map(|s| s.bytes).unwrap_or(0),
                    }
                })
                .collect();
            Ok(Json(GroupsWithStatsResponse {
                groups: groups_with_stats,
            }))
        }
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
                if id == 0 {
                    return "any".to_string();
                }
                groups
                    .values()
                    .find(|g| g.id == id)
                    .map(|g| g.name.clone())
                    .unwrap_or_else(|| format!("id:{}", id))
            };
            let policies = rules
                .into_iter()
                .map(|r| PolicyEntry {
                    src_group: find_name(r.src_group_id),
                    src_group_id: r.src_group_id,
                    dst_group: find_name(r.dst_group_id),
                    dst_group_id: r.dst_group_id,
                    proto: proto_to_string(r.proto),
                    action: action_to_string(r.action),
                    direction: direction_to_string(r.direction),
                    ports: r.ports,
                    bitmap_idx: r.bitmap_idx,
                })
                .collect();
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

    let directions: Vec<u8> = if direction == 2 {
        vec![0, 1]
    } else {
        vec![direction]
    };
    let mut applied: Vec<u8> = Vec::new();

    for dir in &directions {
        if let Err(e) = cp
            .add_policy(
                &instance,
                &req.src_group,
                &req.dst_group,
                proto,
                action,
                *dir,
                req.ports.as_deref(),
            )
            .await
        {
            for prev_dir in &applied {
                let _ = cp
                    .delete_policy(&instance, &req.src_group, &req.dst_group, proto, *prev_dir)
                    .await;
            }
            return Err(err_response(e));
        }
        applied.push(*dir);
    }

    let dir_label = if direction == 2 {
        "both"
    } else {
        &req.direction
    };
    Ok((
        StatusCode::CREATED,
        Json(MessageResponse {
            message: format!(
                "Added policy: {} -> {} ({})",
                req.src_group, req.dst_group, dir_label
            ),
        }),
    ))
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

    if let Err(e) = cp
        .delete_policy(&instance, &req.src_group, &req.dst_group, proto, direction)
        .await
    {
        return Err(err_response(e));
    }

    let dir_label = if direction == 2 {
        "both"
    } else {
        &req.direction
    };
    Ok(Json(MessageResponse {
        message: format!(
            "Deleted policy: {} -> {} ({})",
            req.src_group, req.dst_group, dir_label
        ),
    }))
}

pub async fn list_policies_with_stats(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.list_policies(&instance).await {
        Ok((rules, groups)) => {
            match cp.get_rule_stats(&instance).await {
                Ok((stats, _stats_groups)) => {
                    let find_name = |id: u32| -> String {
                        if id == 0 {
                            return "any".to_string();
                        }
                        groups
                            .values()
                            .find(|g| g.id == id)
                            .map(|g| g.name.clone())
                            .unwrap_or_else(|| format!("id:{}", id))
                    };

                    // Build stats map for O(1) lookup
                    let mut stats_map: std::collections::HashMap<
                        (u32, u32, u8, u8),
                        aria_core::monitoring::RuleStatsEntry,
                    > = stats
                        .into_iter()
                        .map(|s| {
                            (
                                (s.key.src_id, s.key.dst_id, s.key.proto, s.key.direction),
                                s,
                            )
                        })
                        .collect();

                    let policies = rules
                        .into_iter()
                        .map(|r| {
                            let key = (r.src_group_id, r.dst_group_id, r.proto, r.direction);
                            let stat = stats_map.remove(&key);
                            PolicyWithStatsEntry {
                                src_group: find_name(r.src_group_id),
                                src_group_id: r.src_group_id,
                                dst_group: find_name(r.dst_group_id),
                                dst_group_id: r.dst_group_id,
                                proto: proto_to_string(r.proto),
                                action: action_to_string(r.action),
                                direction: direction_to_string(r.direction),
                                ports: r.ports,
                                bitmap_idx: r.bitmap_idx,
                                packets: stat.as_ref().map(|s| s.packets).unwrap_or(0),
                                bytes: stat.as_ref().map(|s| s.bytes).unwrap_or(0),
                                dropped_packets: stat
                                    .as_ref()
                                    .map(|s| s.dropped_packets)
                                    .unwrap_or(0),
                                dropped_bytes: stat.as_ref().map(|s| s.dropped_bytes).unwrap_or(0),
                            }
                        })
                        .collect();
                    Ok(Json(PoliciesWithStatsResponse { policies }))
                }
                Err(e) => Err(err_response(e)),
            }
        }
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
            Err(e) => {
                errors.push(e);
                continue;
            }
        };
        let action = match action_from_string(&policy.action) {
            Ok(a) => a,
            Err(e) => {
                errors.push(e);
                continue;
            }
        };
        let direction = match direction_from_string(&policy.direction) {
            Ok(d) => d,
            Err(e) => {
                errors.push(e);
                continue;
            }
        };

        let directions: Vec<u8> = if direction == 2 {
            vec![0, 1]
        } else {
            vec![direction]
        };
        let mut applied: Vec<u8> = Vec::new();
        let mut add_error: Option<String> = None;

        for dir in &directions {
            if let Err(e) = cp
                .add_policy(
                    &instance,
                    &policy.src_group,
                    &policy.dst_group,
                    proto,
                    action,
                    *dir,
                    policy.ports.as_deref(),
                )
                .await
            {
                add_error = Some(e.to_string());
                break;
            }
            applied.push(*dir);
        }

        if let Some(err) = add_error {
            for prev_dir in &applied {
                let _ = cp
                    .delete_policy(
                        &instance,
                        &policy.src_group,
                        &policy.dst_group,
                        proto,
                        *prev_dir,
                    )
                    .await;
            }
            errors.push(err);
        } else {
            added += 1;
        }
    }

    let status = if errors.is_empty() {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    (status, Json(BatchPoliciesResponse { added, errors }))
}

// ── QoS ──

pub async fn list_qos(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.list_qos(&instance).await {
        Ok(rules) => Ok(Json(QosListResponse {
            rules: rules
                .into_iter()
                .map(|r| QosEntry {
                    group: r.group_name,
                    group_id: r.group_id,
                    direction: direction_to_string(r.direction),
                    rate_bps: r.rate_bps,
                    burst_bytes: r.burst_bytes,
                    priority: r.priority,
                    mode: if r.mode == 1 {
                        "shaping".to_string()
                    } else {
                        "policing".to_string()
                    },
                })
                .collect(),
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
        other => {
            return Err(err_response(ControlPlaneError::ValidationError(format!(
                "Invalid mode '{}': must be 'policing' or 'shaping'",
                other
            ))))
        }
    };

    // direction=2 means "both": apply to ingress and egress
    let directions: Vec<u8> = if direction == 2 {
        vec![0, 1]
    } else {
        vec![direction]
    };
    let mut applied: Vec<u8> = Vec::new();
    let mut shaping_downgraded = false;

    for dir in &directions {
        // Ingress does not support shaping mode, downgrade to policing
        let effective_mode = if *dir == 0 && mode == 1 {
            shaping_downgraded = true;
            0
        } else {
            mode
        };
        if let Err(e) = cp
            .add_qos(
                &instance,
                &req.group,
                *dir,
                rate_bps,
                burst_bytes,
                req.priority,
                effective_mode,
            )
            .await
        {
            // Rollback previously applied directions
            for prev_dir in &applied {
                let _ = cp.delete_qos(&instance, &req.group, *prev_dir).await;
            }
            return Err(err_response(e));
        }
        applied.push(*dir);
    }

    let dir_label = if direction == 2 {
        "both"
    } else {
        &req.direction
    };
    let mut msg = format!("Added QoS rule for group '{}' ({})", req.group, dir_label);
    if shaping_downgraded {
        msg.push_str(". Warning: ingress shaping is not supported, downgraded to policing");
    }
    Ok((StatusCode::CREATED, Json(MessageResponse { message: msg })))
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

    if let Err(e) = cp.delete_qos(&instance, &req.group, direction).await {
        return Err(err_response(e));
    }

    let dir_label = if direction == 2 {
        "both"
    } else {
        &req.direction
    };
    Ok(Json(MessageResponse {
        message: format!("Deleted QoS rule for group '{}' ({})", req.group, dir_label),
    }))
}

pub async fn list_qos_with_stats(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.list_qos(&instance).await {
        Ok(rules) => {
            match cp.get_qos_stats(&instance).await {
                Ok((stats, _)) => {
                    // Build stats map for O(1) lookup
                    let mut stats_map: std::collections::HashMap<
                        (u32, u8),
                        aria_core::monitoring::QosStatsEntry,
                    > = stats
                        .into_iter()
                        .map(|s| ((s.key.group_id, s.key.direction), s))
                        .collect();

                    let rules_with_stats = rules
                        .into_iter()
                        .map(|r| {
                            let key = (r.group_id, r.direction);
                            let stat = stats_map.remove(&key);
                            QosWithStatsEntry {
                                group: r.group_name,
                                group_id: r.group_id,
                                direction: direction_to_string(r.direction),
                                rate_bps: r.rate_bps,
                                burst_bytes: r.burst_bytes,
                                priority: r.priority,
                                mode: if r.mode == 1 {
                                    "shaping".to_string()
                                } else {
                                    "policing".to_string()
                                },
                                passed_packets: stat
                                    .as_ref()
                                    .map(|s| s.passed_packets)
                                    .unwrap_or(0),
                                passed_bytes: stat.as_ref().map(|s| s.passed_bytes).unwrap_or(0),
                                dropped_packets: stat
                                    .as_ref()
                                    .map(|s| s.dropped_packets)
                                    .unwrap_or(0),
                                dropped_bytes: stat.as_ref().map(|s| s.dropped_bytes).unwrap_or(0),
                                shaped_packets: stat
                                    .as_ref()
                                    .map(|s| s.shaped_packets)
                                    .unwrap_or(0),
                                shaped_bytes: stat.as_ref().map(|s| s.shaped_bytes).unwrap_or(0),
                            }
                        })
                        .collect();
                    Ok(Json(QosWithStatsResponse {
                        rules: rules_with_stats,
                    }))
                }
                Err(e) => Err(err_response(e)),
            }
        }
        Err(e) => Err(err_response(e)),
    }
}

// ── Conntrack ──

pub async fn list_conntrack(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.list_conntrack(&instance).await {
        Ok(entries) => {
            let total = entries.len();
            let connections: Vec<ConntrackEntry> = entries
                .into_iter()
                .map(|e| ConntrackEntry {
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
                })
                .collect();
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
            ssl: cfg.ssl_enabled != 0,
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
    match cp
        .update_config(
            &instance,
            req.conntrack,
            req.monitoring,
            req.acl,
            req.qos,
            req.mirror,
            req.tcprt,
            req.ssl,
        )
        .await
    {
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
                if id == 0 {
                    return "any".to_string();
                }
                groups
                    .values()
                    .find(|g| g.id == id)
                    .map(|g| g.name.clone())
                    .unwrap_or_else(|| format!("id:{}", id))
            };
            Ok(Json(RuleStatsResponse {
                rules: entries
                    .into_iter()
                    .map(|e| aria_api::RuleStatsEntry {
                        src_group: find_name(e.key.src_id),
                        src_id: e.key.src_id,
                        dst_group: find_name(e.key.dst_id),
                        dst_id: e.key.dst_id,
                        proto: proto_to_string(e.key.proto),
                        direction: direction_to_string(e.key.direction),
                        packets: e.packets,
                        bytes: e.bytes,
                        dropped_packets: e.dropped_packets,
                        dropped_bytes: e.dropped_bytes,
                    })
                    .collect(),
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

fn default_top() -> usize {
    20
}

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
                if id == 0 {
                    return "any".to_string();
                }
                groups
                    .values()
                    .find(|g| g.id == id)
                    .map(|g| g.name.clone())
                    .unwrap_or_else(|| format!("id:{}", id))
            };
            Ok(Json(QosStatsResponse {
                rules: entries
                    .into_iter()
                    .map(|e| aria_api::QosStatsEntry {
                        group: find_name(e.key.group_id),
                        group_id: e.key.group_id,
                        direction: direction_to_string(e.key.direction),
                        passed_packets: e.passed_packets,
                        passed_bytes: e.passed_bytes,
                        dropped_packets: e.dropped_packets,
                        dropped_bytes: e.dropped_bytes,
                        shaped_packets: e.shaped_packets,
                        shaped_bytes: e.shaped_bytes,
                    })
                    .collect(),
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
                if id == 0 {
                    return "any".to_string();
                }
                groups
                    .values()
                    .find(|g| g.id == id)
                    .map(|g| g.name.clone())
                    .unwrap_or_else(|| format!("id:{}", id))
            };
            Ok(Json(GroupStatsResponse {
                groups: entries
                    .into_iter()
                    .map(|e| aria_api::GroupStatsEntry {
                        group: find_name(e.key.group_id),
                        group_id: e.key.group_id,
                        direction: direction_to_string(e.key.direction),
                        packets: e.packets,
                        bytes: e.bytes,
                    })
                    .collect(),
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
            rules: rules
                .into_iter()
                .map(|r| MirrorEntry {
                    src_group: r.src_group_name,
                    src_group_id: r.src_group_id,
                    dst_group: r.dst_group_name,
                    dst_group_id: r.dst_group_id,
                    proto: proto_to_string(r.proto),
                    direction: direction_to_string(r.direction),
                    target_iface: r.target_iface,
                    target_ifindex: r.target_ifindex,
                    is_global: r.is_global,
                })
                .collect(),
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
    let directions: Vec<u8> = if direction == 2 {
        vec![0, 1]
    } else {
        vec![direction]
    };
    let mut applied: Vec<u8> = Vec::new();

    for dir in &directions {
        if let Err(e) = cp
            .add_mirror(
                &instance,
                &req.src_group,
                &req.dst_group,
                proto,
                *dir,
                &req.target,
            )
            .await
        {
            // Rollback previously applied directions
            for prev_dir in &applied {
                let _ = cp
                    .delete_mirror(&instance, &req.src_group, &req.dst_group, proto, *prev_dir)
                    .await;
            }
            return Err(err_response(e));
        }
        applied.push(*dir);
    }

    let dir_label = if direction == 2 {
        "both"
    } else {
        &req.direction
    };
    Ok((
        StatusCode::CREATED,
        Json(MessageResponse {
            message: format!(
                "Added mirror rule ({}) -> target '{}'",
                dir_label, req.target
            ),
        }),
    ))
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

    if let Err(e) = cp
        .delete_mirror(&instance, &req.src_group, &req.dst_group, proto, direction)
        .await
    {
        return Err(err_response(e));
    }

    let dir_label = if direction == 2 {
        "both"
    } else {
        &req.direction
    };
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
                if id == 0 {
                    return "any".to_string();
                }
                groups
                    .values()
                    .find(|g| g.id == id)
                    .map(|g| g.name.clone())
                    .unwrap_or_else(|| format!("id:{}", id))
            };
            Ok(Json(MirrorStatsResponse {
                rules: entries
                    .into_iter()
                    .map(|e| aria_api::MirrorStatsEntry {
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
                    })
                    .collect(),
            }))
        }
        Err(e) => Err(err_response(e)),
    }
}

pub async fn list_mirror_with_stats(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.list_mirror(&instance).await {
        Ok(rules) => {
            match cp.get_mirror_stats(&instance).await {
                Ok((stats, _)) => {
                    // Build stats map for O(1) lookup
                    let mut stats_map: std::collections::HashMap<
                        (u32, u32, u8, u8, bool),
                        aria_core::monitoring::MirrorStatsEntry,
                    > = stats
                        .into_iter()
                        .map(|s| ((s.src_id, s.dst_id, s.proto, s.direction, s.is_global), s))
                        .collect();

                    let rules_with_stats = rules
                        .into_iter()
                        .map(|r| {
                            let key = (
                                r.src_group_id,
                                r.dst_group_id,
                                r.proto,
                                r.direction,
                                r.is_global,
                            );
                            let stat = stats_map.remove(&key);
                            MirrorWithStatsEntry {
                                src_group: r.src_group_name,
                                src_group_id: r.src_group_id,
                                dst_group: r.dst_group_name,
                                dst_group_id: r.dst_group_id,
                                proto: proto_to_string(r.proto),
                                direction: direction_to_string(r.direction),
                                target_iface: r.target_iface,
                                target_ifindex: r.target_ifindex,
                                is_global: r.is_global,
                                mirrored_packets: stat
                                    .as_ref()
                                    .map(|s| s.mirrored_packets)
                                    .unwrap_or(0),
                                mirrored_bytes: stat
                                    .as_ref()
                                    .map(|s| s.mirrored_bytes)
                                    .unwrap_or(0),
                                errors: stat.as_ref().map(|s| s.errors).unwrap_or(0),
                            }
                        })
                        .collect();
                    Ok(Json(MirrorWithStatsResponse {
                        rules: rules_with_stats,
                    }))
                }
                Err(e) => Err(err_response(e)),
            }
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
            let flows = entries
                .into_iter()
                .map(|e| aria_api::TcpRtEntry {
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
                    forward_platform_us: e.forward_platform_us,
                    server_network_us: e.server_network_us,
                    reverse_platform_us: e.reverse_platform_us,
                    fin_us: e.fin_us,
                    rst_us: e.rst_us,
                    close_us: e.close_us,
                    nqa_score: e.nqa_score,
                })
                .collect();
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

// ── SSL ──

fn map_ssl_connections(
    entries: Vec<aria_core::ssl_ops::SslConnEntry>,
) -> aria_api::SslListResponse {
    let connections = entries
        .into_iter()
        .map(|e| aria_api::SslConnEntry {
            seq: e.seq,
            pid: e.pid,
            tid: e.tid,
            handshake_us: e.handshake_us,
            timestamp: e.timestamp,
            sni: e.sni,
        })
        .collect();
    aria_api::SslListResponse { connections }
}

fn map_ssl_http_events(
    entries: Vec<aria_core::ssl_ops::SslHttpEntry>,
) -> aria_api::SslHttpListResponse {
    let events = entries
        .into_iter()
        .map(|e| aria_api::SslHttpEntry {
            seq: e.seq,
            pid: e.pid,
            tid: e.tid,
            method: e.method,
            path: e.path,
            host: e.host,
            status_code: e.status_code,
            latency_us: e.latency_us,
            request_ts: e.request_ts,
            response_ts: e.response_ts,
        })
        .collect();
    aria_api::SslHttpListResponse { events }
}

pub async fn list_ssl_global(
    State(cp): State<AppState>,
    Query(query): Query<TopQuery>,
) -> impl IntoResponse {
    match cp.list_ssl_global(query.top).await {
        Ok(entries) => Ok(Json(map_ssl_connections(entries))),
        Err(e) => Err(err_response(e)),
    }
}

pub async fn flush_ssl_global(State(cp): State<AppState>) -> impl IntoResponse {
    match cp.flush_ssl_global().await {
        Ok(count) => Ok(Json(aria_api::SslFlushResponse { flushed: count })),
        Err(e) => Err(err_response(e)),
    }
}

pub async fn list_ssl(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
    Query(query): Query<TopQuery>,
) -> impl IntoResponse {
    match cp.list_ssl(&instance, query.top).await {
        Ok(entries) => Ok(Json(map_ssl_connections(entries))),
        Err(e) => Err(err_response(e)),
    }
}

pub async fn flush_ssl(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.flush_ssl(&instance).await {
        Ok(count) => Ok(Json(aria_api::SslFlushResponse { flushed: count })),
        Err(e) => Err(err_response(e)),
    }
}

// ── SSL HTTP ──

pub async fn list_ssl_http_global(
    State(cp): State<AppState>,
    Query(query): Query<TopQuery>,
) -> impl IntoResponse {
    match cp.list_ssl_http_global(query.top).await {
        Ok(entries) => Ok(Json(map_ssl_http_events(entries))),
        Err(e) => Err(err_response(e)),
    }
}

pub async fn flush_ssl_http_global(State(cp): State<AppState>) -> impl IntoResponse {
    match cp.flush_ssl_http_global().await {
        Ok(count) => Ok(Json(aria_api::SslHttpFlushResponse { flushed: count })),
        Err(e) => Err(err_response(e)),
    }
}

pub async fn list_ssl_http(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
    Query(query): Query<TopQuery>,
) -> impl IntoResponse {
    match cp.list_ssl_http(&instance, query.top).await {
        Ok(entries) => Ok(Json(map_ssl_http_events(entries))),
        Err(e) => Err(err_response(e)),
    }
}

pub async fn flush_ssl_http(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.flush_ssl_http(&instance).await {
        Ok(count) => Ok(Json(aria_api::SslHttpFlushResponse { flushed: count })),
        Err(e) => Err(err_response(e)),
    }
}

// ── Global SSL Observability Config ──
// SSL uprobe is process-level, not tied to any network interface

pub async fn get_ssl_config(State(cp): State<AppState>) -> impl IntoResponse {
    match cp.get_ssl_global_config().await {
        Ok(enabled) => Ok(Json(aria_api::SslGlobalConfigResponse { enabled })),
        Err(e) => Err(err_response(e)),
    }
}

pub async fn update_ssl_config(
    State(cp): State<AppState>,
    Json(req): Json<aria_api::UpdateSslGlobalConfigRequest>,
) -> impl IntoResponse {
    match cp.set_ssl_global_config(req.enabled).await {
        Ok(()) => Ok(Json(aria_api::MessageResponse {
            message: format!(
                "SSL observability {}",
                if req.enabled { "enabled" } else { "disabled" }
            ),
        })),
        Err(e) => Err(err_response(e)),
    }
}

pub async fn list_ssl_errors(State(cp): State<AppState>) -> impl IntoResponse {
    match cp.get_ssl_errors().await {
        Ok(entries) => {
            let errors = entries
                .into_iter()
                .map(|e| aria_api::SslErrorEntry {
                    seq: e.seq,
                    pid: e.pid,
                    tid: e.tid,
                    timestamp: e.timestamp,
                    syscall: e.syscall,
                    ret_code: e.ret_code,
                    error_hint: e.error_hint,
                })
                .collect();
            Ok(Json(aria_api::SslErrorListResponse { errors }))
        }
        Err(e) => Err(err_response(e)),
    }
}

pub async fn flush_ssl_errors(State(cp): State<AppState>) -> impl IntoResponse {
    match cp.flush_ssl_errors().await {
        Ok(count) => Ok(Json(aria_api::SslErrorFlushResponse { flushed: count })),
        Err(e) => Err(err_response(e)),
    }
}

pub async fn batch_query_tcprt(
    State(cp): State<AppState>,
    Json(req): Json<aria_api::TcpRtBatchQueryRequest>,
) -> impl IntoResponse {
    let tuples: Vec<(String, String, u16, u16)> = req
        .tuples
        .into_iter()
        .map(|t| (t.src_ip, t.dst_ip, t.src_port, t.dst_port))
        .collect();
    match cp.batch_query_tcprt(&tuples).await {
        Ok(entries) => {
            let results = entries
                .into_iter()
                .map(|(instance, e)| aria_api::TcpRtInstanceEntry {
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
                        forward_platform_us: e.forward_platform_us,
                        server_network_us: e.server_network_us,
                        reverse_platform_us: e.reverse_platform_us,
                        fin_us: e.fin_us,
                        rst_us: e.rst_us,
                        close_us: e.close_us,
                        nqa_score: e.nqa_score,
                    },
                })
                .collect();
            Ok(Json(aria_api::TcpRtBatchQueryResponse { results }))
        }
        Err(e) => Err(err_response(e)),
    }
}

pub async fn filter_tcprt(
    State(cp): State<AppState>,
    Json(req): Json<aria_api::TcpRtFilterRequest>,
) -> impl IntoResponse {
    match cp.filter_tcprt(&req.dst_ip, req.dst_port).await {
        Ok(instance_entries) => {
            let instances: Vec<aria_api::TcpRtAggregatedEntry> = instance_entries
                .into_iter()
                .map(|(name, entries)| {
                    let count = entries.len() as u32;
                    let fc = count as f64;
                    aria_api::TcpRtAggregatedEntry {
                        instance: name,
                        flow_count: count,
                        avg_rtt_client_us: entries.iter().map(|e| e.rtt_client_us).sum::<f64>()
                            / fc,
                        avg_rtt_server_us: entries.iter().map(|e| e.rtt_server_us).sum::<f64>()
                            / fc,
                        avg_art_us: entries.iter().map(|e| e.art_us).sum::<f64>() / fc,
                        avg_handshake_us: entries.iter().map(|e| e.handshake_us).sum::<f64>() / fc,
                        total_retrans_req: entries.iter().map(|e| e.retrans_req).sum(),
                        total_retrans_resp: entries.iter().map(|e| e.retrans_resp).sum(),
                        avg_forward_platform_us: entries
                            .iter()
                            .map(|e| e.forward_platform_us)
                            .sum::<f64>()
                            / fc,
                        avg_server_network_us: entries
                            .iter()
                            .map(|e| e.server_network_us)
                            .sum::<f64>()
                            / fc,
                        avg_reverse_platform_us: entries
                            .iter()
                            .map(|e| e.reverse_platform_us)
                            .sum::<f64>()
                            / fc,
                        avg_nqa_score: entries.iter().map(|e| e.nqa_score as f64).sum::<f64>() / fc,
                    }
                })
                .collect();
            Ok(Json(aria_api::TcpRtFilterResponse {
                dst_ip: req.dst_ip,
                dst_port: req.dst_port,
                instances,
            }))
        }
        Err(e) => Err(err_response(e)),
    }
}

pub async fn tcprt_histogram(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.list_tcprt(&instance, 100000).await {
        Ok(entries) => {
            let bucket_boundaries: Vec<f64> = vec![
                1_000.0,
                5_000.0,
                10_000.0,
                50_000.0,
                100_000.0,
                500_000.0,
                1_000_000.0,
                5_000_000.0,
                10_000_000.0,
            ];
            let mut counts = vec![0u64; bucket_boundaries.len()];
            let mut total = 0u64;
            let mut sum_us = 0.0f64;
            let mut art_values: Vec<f64> = Vec::new();

            for e in &entries {
                if e.art_us > 0.0 {
                    total += 1;
                    sum_us += e.art_us;
                    art_values.push(e.art_us);
                    for (i, &boundary) in bucket_boundaries.iter().enumerate() {
                        if e.art_us <= boundary {
                            counts[i] += 1;
                        }
                    }
                }
            }

            art_values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
            let percentile = |p: f64| -> f64 {
                if art_values.is_empty() {
                    return 0.0;
                }
                let idx = ((p / 100.0) * art_values.len() as f64).ceil() as usize;
                art_values[idx.min(art_values.len()).saturating_sub(1)]
            };

            let buckets = bucket_boundaries
                .iter()
                .enumerate()
                .map(|(i, &le_us)| aria_api::TcpRtHistogramBucket {
                    le_us,
                    count: counts[i],
                })
                .collect();

            Ok(Json(aria_api::TcpRtHistogramResponse {
                buckets,
                total,
                sum_us,
                p50_us: percentile(50.0),
                p95_us: percentile(95.0),
                p99_us: percentile(99.0),
            }))
        }
        Err(e) => Err(err_response(e)),
    }
}

pub async fn tcprt_states(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.list_tcprt(&instance, 100000).await {
        Ok(entries) => {
            let mut state_counts: Vec<(String, u64)> = Vec::new();
            let total_flows = entries.len() as u64;

            for e in &entries {
                if let Some(sc) = state_counts.iter_mut().find(|(s, _)| s == &e.state) {
                    sc.1 += 1;
                } else {
                    state_counts.push((e.state.clone(), 1));
                }
            }

            let mut anomalies: Vec<String> = Vec::new();
            if total_flows > 0 {
                for (state, count) in &state_counts {
                    let pct = *count as f64 / total_flows as f64 * 100.0;
                    if state == "close_wait" && pct > 10.0 {
                        anomalies.push(format!(
                            "CLOSE_WAIT is {:.1}% (>10%) - possible connection leak",
                            pct
                        ));
                    }
                    if state == "rst" && pct > 20.0 {
                        anomalies.push(format!(
                            "RST is {:.1}% (>20%) - possible network issue",
                            pct
                        ));
                    }
                }
            }

            let states = state_counts
                .into_iter()
                .map(|(state, count)| aria_api::TcpRtStateCount { state, count })
                .collect();

            Ok(Json(aria_api::TcpRtStatesResponse {
                states,
                total_flows,
                anomalies,
            }))
        }
        Err(e) => Err(err_response(e)),
    }
}

// ── Service Chains ──

pub async fn list_chains(State(cp): State<AppState>) -> impl IntoResponse {
    let chains = cp.list_chains().await;
    Json(aria_api::ServiceChainListResponse {
        chains: chains
            .into_iter()
            .map(|c| aria_api::ServiceChainEntry {
                name: c.name,
                description: c.description,
                hops: c
                    .hops
                    .into_iter()
                    .map(|h| aria_api::ServiceHopEntry {
                        name: h.name,
                        hop_type: format!("{:?}", h.hop_type).to_lowercase(),
                        taps: h
                            .taps
                            .into_iter()
                            .map(|t| aria_api::TapBindingEntry {
                                tap: t.tap,
                                role: format!("{:?}", t.role).to_lowercase(),
                            })
                            .collect(),
                    })
                    .collect(),
            })
            .collect(),
    })
}

pub async fn create_chain(
    State(cp): State<AppState>,
    Json(req): Json<aria_api::CreateServiceChainRequest>,
) -> impl IntoResponse {
    use crate::service_chain::{HopType, ServiceChain, ServiceHop, TapBinding, TapRole};

    let hops: Result<Vec<ServiceHop>, String> = req
        .hops
        .into_iter()
        .map(|h| {
            let hop_type = match h.hop_type.to_lowercase().as_str() {
                "bridge" => Ok(HopType::Bridge),
                "proxy" => Ok(HopType::Proxy),
                other => Err(format!(
                    "Invalid hop_type '{}': must be 'bridge' or 'proxy'",
                    other
                )),
            }?;
            let taps: Result<Vec<TapBinding>, String> = h
                .taps
                .into_iter()
                .map(|t| {
                    let role = match t.role.to_lowercase().as_str() {
                        "in" => Ok(TapRole::In),
                        "out" => Ok(TapRole::Out),
                        "bidirectional" | "bidi" => Ok(TapRole::Bidirectional),
                        other => Err(format!(
                            "Invalid tap role '{}': must be 'in', 'out', or 'bidirectional'",
                            other
                        )),
                    }?;
                    Ok(TapBinding { tap: t.tap, role })
                })
                .collect();
            Ok(ServiceHop {
                name: h.name,
                hop_type,
                taps: taps?,
            })
        })
        .collect();

    let hops = match hops {
        Ok(h) => h,
        Err(e) => return Err(err_response(ControlPlaneError::ValidationError(e))),
    };

    let chain = ServiceChain {
        name: req.name.clone(),
        description: req.description,
        hops,
    };

    match cp.create_chain(chain).await {
        Ok(()) => Ok((
            StatusCode::CREATED,
            Json(MessageResponse {
                message: format!("Service chain '{}' created", req.name),
            }),
        )),
        Err(e) => Err(err_response(e)),
    }
}

pub async fn get_chain(State(cp): State<AppState>, Path(name): Path<String>) -> impl IntoResponse {
    match cp.get_chain(&name).await {
        Ok(c) => Ok(Json(aria_api::ServiceChainEntry {
            name: c.name,
            description: c.description,
            hops: c
                .hops
                .into_iter()
                .map(|h| aria_api::ServiceHopEntry {
                    name: h.name,
                    hop_type: format!("{:?}", h.hop_type).to_lowercase(),
                    taps: h
                        .taps
                        .into_iter()
                        .map(|t| aria_api::TapBindingEntry {
                            tap: t.tap,
                            role: format!("{:?}", t.role).to_lowercase(),
                        })
                        .collect(),
                })
                .collect(),
        })),
        Err(e) => Err(err_response(e)),
    }
}

pub async fn delete_chain(
    State(cp): State<AppState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    match cp.delete_chain(&name).await {
        Ok(()) => Ok(Json(MessageResponse {
            message: format!("Deleted service chain '{}'", name),
        })),
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
                if id == 0 {
                    return "any".to_string();
                }
                groups
                    .values()
                    .find(|g| g.id == id)
                    .map(|g| g.name.clone())
                    .unwrap_or_else(|| format!("id:{}", id))
            };
            Ok((
                legacy_drop_headers(&instance),
                Json(aria_api::DropStatsResponse {
                    drops: entries
                        .into_iter()
                        .map(|e| aria_api::DropStatsEntry {
                            reason: aria_core::trace_ops::drop_reason_name(e.reason),
                            direction: direction_to_string(e.direction),
                            proto: proto_to_string(e.proto),
                            src_group: find_name(e.src_id),
                            src_id: e.src_id,
                            dst_group: find_name(e.dst_id),
                            dst_id: e.dst_id,
                            packets: e.packets,
                            bytes: e.bytes,
                        })
                        .collect(),
                }),
            ))
        }
        Err(e) => Err(err_response(e)),
    }
}

pub async fn flush_drops(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.flush_drop_stats(&instance).await {
        Ok(count) => Ok((
            legacy_drop_headers(&instance),
            Json(aria_api::DropFlushResponse { flushed: count }),
        )),
        Err(e) => Err(err_response(e)),
    }
}

pub async fn list_kernel_drops(
    State(cp): State<AppState>,
    Query(query): Query<aria_api::KernelDropQuery>,
) -> impl IntoResponse {
    match cp.get_kernel_drop_stats(&query).await {
        Ok(drops) => Ok(Json(aria_api::KernelDropStatsResponse { drops })),
        Err(e) => Err(err_response(e)),
    }
}

pub async fn flush_kernel_drops(
    State(cp): State<AppState>,
    Query(query): Query<aria_api::KernelDropQuery>,
) -> impl IntoResponse {
    match cp.flush_kernel_drop_stats(&query).await {
        Ok(flushed) => Ok(Json(aria_api::KernelDropFlushResponse { flushed })),
        Err(e) => Err(err_response(e)),
    }
}

// ── Packet Trace ──

pub async fn start_trace(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
    Json(req): Json<aria_api::TraceStartRequest>,
) -> impl IntoResponse {
    let mut src_ip: u32 = 0;
    let mut dst_ip: u32 = 0;
    let mut src_ip_v6: [u8; 16] = [0u8; 16];
    let mut dst_ip_v6: [u8; 16] = [0u8; 16];
    let mut is_ipv6: u8 = 0; // 0=IPv4, 1=IPv6, 2=both
    let mut src_is_v6 = false;
    let mut dst_is_v6 = false;

    if !req.src_ip.is_empty() {
        if let Ok(ip) = req.src_ip.parse::<std::net::Ipv4Addr>() {
            src_ip = u32::from(ip);
        } else if let Ok(ip) = req.src_ip.parse::<std::net::Ipv6Addr>() {
            src_ip_v6 = ip.octets();
            src_is_v6 = true;
        } else {
            return Err(err_response(ControlPlaneError::ValidationError(format!(
                "Invalid src_ip: {}",
                req.src_ip
            ))));
        }
    }
    if !req.dst_ip.is_empty() {
        if let Ok(ip) = req.dst_ip.parse::<std::net::Ipv4Addr>() {
            dst_ip = u32::from(ip);
        } else if let Ok(ip) = req.dst_ip.parse::<std::net::Ipv6Addr>() {
            dst_ip_v6 = ip.octets();
            dst_is_v6 = true;
        } else {
            return Err(err_response(ControlPlaneError::ValidationError(format!(
                "Invalid dst_ip: {}",
                req.dst_ip
            ))));
        }
    }

    // Reject mixed address families
    if (src_is_v6 && !req.dst_ip.is_empty() && !dst_is_v6)
        || (dst_is_v6 && !req.src_ip.is_empty() && !src_is_v6)
    {
        return Err(err_response(ControlPlaneError::ValidationError(
            "Cannot mix IPv4 and IPv6 addresses in trace filter".to_string(),
        )));
    }

    // Determine address family
    if src_is_v6 || dst_is_v6 {
        is_ipv6 = 1;
    } else if req.src_ip.is_empty() && req.dst_ip.is_empty() {
        is_ipv6 = 2; // match both
    }
    // else: is_ipv6 = 0 (IPv4 only, default)

    let proto: u8 = if req.proto.is_empty() {
        0
    } else {
        match proto_from_string(&req.proto) {
            Ok(p) => p,
            Err(e) => return Err(err_response(ControlPlaneError::ValidationError(e))),
        }
    };

    match cp
        .start_trace(
            &instance,
            src_ip,
            dst_ip,
            src_ip_v6,
            dst_ip_v6,
            req.src_port,
            req.dst_port,
            proto,
            is_ipv6,
        )
        .await
    {
        Ok(()) => Ok((
            StatusCode::OK,
            Json(MessageResponse {
                message: "Trace started".to_string(),
            }),
        )),
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
                if id == 0 {
                    return "any".to_string();
                }
                groups
                    .values()
                    .find(|g| g.id == id)
                    .map(|g| g.name.clone())
                    .unwrap_or_else(|| format!("id:{}", id))
            };
            Ok(Json(aria_api::TraceResponse {
                events: entries
                    .into_iter()
                    .map(|e| aria_api::TraceEventEntry {
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
                    })
                    .collect(),
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

// ── Prometheus Metrics ──

const METRICS_CHUNK_SIZE: usize = 16 * 1024;
const LATENCY_BUCKET_LABELS: [&str; 9] = [
    "0.001", "0.005", "0.01", "0.05", "0.1", "0.5", "1", "5", "10",
];

fn prom_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn ct_contract_hook_to_string(hook: u8) -> &'static str {
    match hook {
        aria_core::common::CT_CONTRACT_HOOK_TC_INGRESS => "tc_ingress",
        _ => "unknown",
    }
}

fn ct_contract_family_to_string(family: u8) -> &'static str {
    match family {
        aria_core::common::CT_CONTRACT_FAMILY_IPV4 => "ipv4",
        aria_core::common::CT_CONTRACT_FAMILY_IPV6 => "ipv6",
        _ => "unknown",
    }
}

fn ct_contract_reason_to_string(reason: u8) -> &'static str {
    match reason {
        aria_core::common::CT_CONTRACT_REASON_CT_MISS => "ct_miss",
        aria_core::common::CT_CONTRACT_REASON_CT_DISABLED => "ct_disabled",
        _ => "unknown",
    }
}

fn flush_metrics_chunk(buf: &mut String, force: bool) -> Option<Bytes> {
    if buf.is_empty() || (!force && buf.len() < METRICS_CHUNK_SIZE) {
        return None;
    }

    let chunk = Bytes::copy_from_slice(buf.as_bytes());
    buf.clear();
    Some(chunk)
}

fn write_latency_histogram(
    out: &mut String,
    metric_name: &str,
    instance: &str,
    bucket_counts: &[u64; 9],
    sum_seconds: f64,
    count: u64,
) {
    for (idx, le) in LATENCY_BUCKET_LABELS.iter().enumerate() {
        let _ = writeln!(
            out,
            "{metric_name}_bucket{{instance=\"{instance}\",le=\"{le}\"}} {}",
            bucket_counts[idx]
        );
    }
    let _ = writeln!(
        out,
        "{metric_name}_bucket{{instance=\"{instance}\",le=\"+Inf\"}} {count}"
    );
    let _ = writeln!(
        out,
        "{metric_name}_sum{{instance=\"{instance}\"}} {sum_seconds}"
    );
    let _ = writeln!(
        out,
        "{metric_name}_count{{instance=\"{instance}\"}} {count}"
    );
}

fn write_tcprt_summary_metrics(
    out: &mut String,
    instance: &str,
    summary: &aria_core::monitoring::TcprtMetricsSummary,
) {
    let _ = writeln!(
        out,
        "aria_tcprt_flows_total{{instance=\"{instance}\"}} {}",
        summary.flows
    );
    let _ = writeln!(
        out,
        "aria_tcprt_retrans_req_total{{instance=\"{instance}\"}} {}",
        summary.retrans_req
    );
    let _ = writeln!(
        out,
        "aria_tcprt_retrans_resp_total{{instance=\"{instance}\"}} {}",
        summary.retrans_resp
    );
    let _ = writeln!(
        out,
        "aria_tcprt_requests_total{{instance=\"{instance}\"}} {}",
        summary.requests
    );
    let _ = writeln!(
        out,
        "aria_tcprt_handshake_us_sum{{instance=\"{instance}\"}} {}",
        summary.handshake_sum_us
    );
    let _ = writeln!(
        out,
        "aria_tcprt_art_us_sum{{instance=\"{instance}\"}} {}",
        summary.art_sum_us
    );
    let _ = writeln!(
        out,
        "aria_tcprt_rtt_client_us_sum{{instance=\"{instance}\"}} {}",
        summary.rtt_client_sum_us
    );
    let _ = writeln!(
        out,
        "aria_tcprt_rtt_server_us_sum{{instance=\"{instance}\"}} {}",
        summary.rtt_server_sum_us
    );
    write_latency_histogram(
        out,
        "aria_tcprt_art_seconds",
        instance,
        &summary.art_bucket_counts,
        summary.art_sum_seconds,
        summary.art_count,
    );
    let avg_nqa = if summary.flows > 0 {
        summary.nqa_sum / summary.flows as f64
    } else {
        0.0
    };
    let _ = writeln!(
        out,
        "aria_tcprt_nqa_score_avg{{instance=\"{instance}\"}} {avg_nqa:.1}"
    );
}

fn write_ssl_summary_metrics(
    out: &mut String,
    instance: &str,
    summary: &aria_core::ssl_ops::SslMetricsSummary,
) {
    let _ = writeln!(
        out,
        "aria_ssl_handshakes_total{{instance=\"{instance}\"}} {}",
        summary.total
    );
    write_latency_histogram(
        out,
        "aria_ssl_handshake_seconds",
        instance,
        &summary.bucket_counts,
        summary.sum_seconds,
        summary.count,
    );
}

fn write_ssl_http_summary_metrics(
    out: &mut String,
    instance: &str,
    summary: &aria_core::ssl_ops::SslHttpMetricsSummary,
) {
    let _ = writeln!(
        out,
        "aria_ssl_http_requests_total{{instance=\"{instance}\"}} {}",
        summary.total
    );
    write_latency_histogram(
        out,
        "aria_ssl_http_latency_seconds",
        instance,
        &summary.bucket_counts,
        summary.sum_seconds,
        summary.count,
    );
    let _ = writeln!(
        out,
        "aria_ssl_http_status_2xx_total{{instance=\"{instance}\"}} {}",
        summary.status_2xx
    );
    let _ = writeln!(
        out,
        "aria_ssl_http_status_4xx_total{{instance=\"{instance}\"}} {}",
        summary.status_4xx
    );
    let _ = writeln!(
        out,
        "aria_ssl_http_status_5xx_total{{instance=\"{instance}\"}} {}",
        summary.status_5xx
    );
}

pub async fn metrics(State(cp): State<AppState>) -> impl IntoResponse {
    let instances = cp.list_instances().await;
    let kernel_drop = cp.get_kernel_drop_status().await;
    let trace_backend = prom_escape(cp.trace_backend_name());
    let trace_mode = prom_escape(trace_map_mode_name(cp.trace_map_mode()));
    let mut trace_runtime: Vec<_> = cp.get_trace_runtime_status().await.into_iter().collect();
    trace_runtime.sort_by(|a, b| a.0.cmp(&b.0));

    let stream = stream! {
        let mut out = String::with_capacity(METRICS_CHUNK_SIZE * 2);

        // ── Kernel drop observability status ──
        let _ = writeln!(out, "# HELP aria_kernel_drop_observability_up Whether kernel drop observability is available");
        let _ = writeln!(out, "# TYPE aria_kernel_drop_observability_up gauge");
        let _ = writeln!(out, "# HELP aria_kernel_drop_managed_ifaces Number of interfaces tracked by kernel drop observability");
        let _ = writeln!(out, "# TYPE aria_kernel_drop_managed_ifaces gauge");
        let _ = writeln!(out, "# HELP aria_kernel_drop_mode_info Kernel drop observability mode");
        let _ = writeln!(out, "# TYPE aria_kernel_drop_mode_info gauge");
        let _ = writeln!(out, "# HELP aria_kernel_drop_last_error Kernel drop observability last error indicator");
        let _ = writeln!(out, "# TYPE aria_kernel_drop_last_error gauge");
        let mode = prom_escape(kernel_drop_mode_name(kernel_drop.mode));
        let _ = writeln!(
            out,
            "aria_kernel_drop_observability_up {}",
            if kernel_drop.loaded { 1 } else { 0 }
        );
        let _ = writeln!(
            out,
            "aria_kernel_drop_managed_ifaces {}",
            kernel_drop.managed_ifaces
        );
        let _ = writeln!(
            out,
            "aria_kernel_drop_mode_info{{mode=\"{mode}\"}} 1"
        );
        let _ = writeln!(
            out,
            "aria_kernel_drop_last_error {}",
            if kernel_drop.last_error.is_some() { 1 } else { 0 }
        );
        if let Some(chunk) = flush_metrics_chunk(&mut out, true) {
            yield Ok::<_, std::convert::Infallible>(chunk);
        }

        // ── Kernel drop counters ──
        let _ = writeln!(out, "# HELP aria_kernel_drop_packets_total Kernel drop packets by reason");
        let _ = writeln!(out, "# TYPE aria_kernel_drop_packets_total counter");
        let _ = writeln!(out, "# HELP aria_kernel_drop_bytes_total Kernel drop bytes by reason");
        let _ = writeln!(out, "# TYPE aria_kernel_drop_bytes_total counter");

        if kernel_drop.loaded {
            match cp.get_kernel_drop_stats(&KernelDropQuery {
                include_unattributed: true,
                ..Default::default()
            }).await {
                Ok(entries) => {
                    for entry in &entries {
                        let instance = prom_escape(entry.instance.as_deref().unwrap_or(""));
                        let iface = prom_escape(entry.iface.as_deref().unwrap_or(""));
                        let reason = prom_escape(&entry.reason);
                        let proto = prom_escape(&entry.proto);
                        let source = prom_escape(&entry.source);
                        let _ = writeln!(
                            out,
                            "aria_kernel_drop_packets_total{{instance=\"{instance}\",iface=\"{iface}\",ifindex=\"{}\",reason=\"{reason}\",proto=\"{proto}\",source=\"{source}\"}} {}",
                            entry.ifindex,
                            entry.packets
                        );
                        let _ = writeln!(
                            out,
                            "aria_kernel_drop_bytes_total{{instance=\"{instance}\",iface=\"{iface}\",ifindex=\"{}\",reason=\"{reason}\",proto=\"{proto}\",source=\"{source}\"}} {}",
                            entry.ifindex,
                            entry.bytes
                        );
                        if let Some(chunk) = flush_metrics_chunk(&mut out, false) {
                            yield Ok::<_, std::convert::Infallible>(chunk);
                        }
                    }
                }
                Err(e) => warn!("Failed to collect kernel drop metrics: {}", e),
            }
        }
        if let Some(chunk) = flush_metrics_chunk(&mut out, true) {
            yield Ok::<_, std::convert::Infallible>(chunk);
        }

        // ── Trace backend runtime status ──
        let _ = writeln!(out, "# HELP aria_trace_backend_info Trace backend selection");
        let _ = writeln!(out, "# TYPE aria_trace_backend_info gauge");
        let _ = writeln!(out, "# HELP aria_trace_runtime_registered_taps Number of taps registered to each trace runtime");
        let _ = writeln!(out, "# TYPE aria_trace_runtime_registered_taps gauge");
        let _ = writeln!(out, "# HELP aria_trace_runtime_active_consumers Number of active userspace stream consumers per runtime");
        let _ = writeln!(out, "# TYPE aria_trace_runtime_active_consumers gauge");
        let _ = writeln!(out, "# HELP aria_trace_runtime_lost_events_total Trace stream events reported lost by the backend");
        let _ = writeln!(out, "# TYPE aria_trace_runtime_lost_events_total counter");
        let _ = writeln!(out, "# HELP aria_trace_runtime_cache_evictions_total Trace stream events evicted from the userspace cache");
        let _ = writeln!(out, "# TYPE aria_trace_runtime_cache_evictions_total counter");
        let _ = writeln!(out, "# HELP aria_trace_runtime_consumer_failures_total Trace stream consumer failures");
        let _ = writeln!(out, "# TYPE aria_trace_runtime_consumer_failures_total counter");
        let _ = writeln!(out, "# HELP aria_trace_runtime_consumer_restarts_total Trace stream consumer restarts");
        let _ = writeln!(out, "# TYPE aria_trace_runtime_consumer_restarts_total counter");
        let _ = writeln!(out, "# HELP aria_trace_runtime_last_error Whether the trace runtime has a recorded last error");
        let _ = writeln!(out, "# TYPE aria_trace_runtime_last_error gauge");
        let _ = writeln!(
            out,
            "aria_trace_backend_info{{backend=\"{trace_backend}\",mode=\"{trace_mode}\"}} 1"
        );

        for (pin_path, status) in &trace_runtime {
            let pin_path = prom_escape(pin_path);
            let _ = writeln!(
                out,
                "aria_trace_runtime_registered_taps{{pin_path=\"{pin_path}\"}} {}",
                status.registered_taps
            );
            let _ = writeln!(
                out,
                "aria_trace_runtime_active_consumers{{pin_path=\"{pin_path}\"}} {}",
                status.active_consumers
            );
            let _ = writeln!(
                out,
                "aria_trace_runtime_lost_events_total{{pin_path=\"{pin_path}\"}} {}",
                status.lost_events
            );
            let _ = writeln!(
                out,
                "aria_trace_runtime_cache_evictions_total{{pin_path=\"{pin_path}\"}} {}",
                status.cache_evictions
            );
            let _ = writeln!(
                out,
                "aria_trace_runtime_consumer_failures_total{{pin_path=\"{pin_path}\"}} {}",
                status.consumer_failures
            );
            let _ = writeln!(
                out,
                "aria_trace_runtime_consumer_restarts_total{{pin_path=\"{pin_path}\"}} {}",
                status.consumer_restarts
            );
            let _ = writeln!(
                out,
                "aria_trace_runtime_last_error{{pin_path=\"{pin_path}\"}} {}",
                if status.last_error.is_some() { 1 } else { 0 }
            );
            if let Some(chunk) = flush_metrics_chunk(&mut out, false) {
                yield Ok::<_, std::convert::Infallible>(chunk);
            }
        }
        if let Some(chunk) = flush_metrics_chunk(&mut out, true) {
            yield Ok::<_, std::convert::Infallible>(chunk);
        }

        // ── Overview gauges ──
        let _ = writeln!(out, "# HELP aria_groups_total Number of IP groups configured");
        let _ = writeln!(out, "# TYPE aria_groups_total gauge");
        let _ = writeln!(out, "# HELP aria_policies_total Number of ACL policies configured");
        let _ = writeln!(out, "# TYPE aria_policies_total gauge");
        let _ = writeln!(out, "# HELP aria_qos_rules_total Number of QoS rules configured");
        let _ = writeln!(out, "# TYPE aria_qos_rules_total gauge");
        let _ = writeln!(out, "# HELP aria_mirror_rules_total Number of mirror rules configured");
        let _ = writeln!(out, "# TYPE aria_mirror_rules_total gauge");
        let _ = writeln!(out, "# HELP aria_conntrack_total Number of conntrack entries");
        let _ = writeln!(out, "# TYPE aria_conntrack_total gauge");

        for inst in &instances {
            let i = prom_escape(inst);
            if let Ok((groups, policies, qos_rules, mirror_rules, ct_v4, ct_v6)) = cp.get_stats_overview(inst).await {
                let _ = writeln!(out, "aria_groups_total{{instance=\"{i}\"}} {groups}");
                let _ = writeln!(out, "aria_policies_total{{instance=\"{i}\"}} {policies}");
                let _ = writeln!(out, "aria_qos_rules_total{{instance=\"{i}\"}} {qos_rules}");
                let _ = writeln!(out, "aria_mirror_rules_total{{instance=\"{i}\"}} {mirror_rules}");
                let _ = writeln!(out, "aria_conntrack_total{{instance=\"{i}\",family=\"ipv4\"}} {ct_v4}");
                let _ = writeln!(out, "aria_conntrack_total{{instance=\"{i}\",family=\"ipv6\"}} {ct_v6}");
            }
            if let Some(chunk) = flush_metrics_chunk(&mut out, false) {
                yield Ok::<_, std::convert::Infallible>(chunk);
            }
        }
        if let Some(chunk) = flush_metrics_chunk(&mut out, true) {
            yield Ok::<_, std::convert::Infallible>(chunk);
        }

        // ── CT contract fallback counters ──
        let _ = writeln!(out, "# HELP aria_ct_contract_packets_total Packets handled through conntrack-contract fallback");
        let _ = writeln!(out, "# TYPE aria_ct_contract_packets_total counter");
        let _ = writeln!(out, "# HELP aria_ct_contract_bytes_total Bytes handled through conntrack-contract fallback");
        let _ = writeln!(out, "# TYPE aria_ct_contract_bytes_total counter");

        for inst in &instances {
            let i = prom_escape(inst);
            if let Ok(entries) = cp.get_ct_contract_stats(inst).await {
                for e in &entries {
                    let hook = prom_escape(ct_contract_hook_to_string(e.hook));
                    let family = prom_escape(ct_contract_family_to_string(e.family));
                    let reason = prom_escape(ct_contract_reason_to_string(e.reason));
                    let _ = writeln!(out, "aria_ct_contract_packets_total{{instance=\"{i}\",hook=\"{hook}\",family=\"{family}\",reason=\"{reason}\"}} {}", e.packets);
                    let _ = writeln!(out, "aria_ct_contract_bytes_total{{instance=\"{i}\",hook=\"{hook}\",family=\"{family}\",reason=\"{reason}\"}} {}", e.bytes);
                    if let Some(chunk) = flush_metrics_chunk(&mut out, false) {
                        yield Ok::<_, std::convert::Infallible>(chunk);
                    }
                }
            }
        }
        if let Some(chunk) = flush_metrics_chunk(&mut out, true) {
            yield Ok::<_, std::convert::Infallible>(chunk);
        }

        // ── Drop counters ──
        let _ = writeln!(out, "# HELP aria_drop_packets_total Dropped packets by reason");
        let _ = writeln!(out, "# TYPE aria_drop_packets_total counter");
        let _ = writeln!(out, "# HELP aria_drop_bytes_total Dropped bytes by reason");
        let _ = writeln!(out, "# TYPE aria_drop_bytes_total counter");

        for inst in &instances {
            let i = prom_escape(inst);
            if let Ok((entries, groups)) = cp.get_drop_stats(inst).await {
                let find_name = |id: u32| -> String {
                    if id == 0 {
                        return "any".to_string();
                    }
                    groups.values().find(|g| g.id == id).map(|g| g.name.clone()).unwrap_or_else(|| format!("id:{}", id))
                };
                for e in &entries {
                    let reason = prom_escape(&aria_core::trace_ops::drop_reason_name(e.reason));
                    let dir = prom_escape(&direction_to_string(e.direction));
                    let proto = prom_escape(&proto_to_string(e.proto));
                    let sg = prom_escape(&find_name(e.src_id));
                    let dg = prom_escape(&find_name(e.dst_id));
                    let _ = writeln!(out, "aria_drop_packets_total{{instance=\"{i}\",reason=\"{reason}\",direction=\"{dir}\",proto=\"{proto}\",src_group=\"{sg}\",dst_group=\"{dg}\"}} {}", e.packets);
                    let _ = writeln!(out, "aria_drop_bytes_total{{instance=\"{i}\",reason=\"{reason}\",direction=\"{dir}\",proto=\"{proto}\",src_group=\"{sg}\",dst_group=\"{dg}\"}} {}", e.bytes);
                    if let Some(chunk) = flush_metrics_chunk(&mut out, false) {
                        yield Ok::<_, std::convert::Infallible>(chunk);
                    }
                }
            }
        }
        if let Some(chunk) = flush_metrics_chunk(&mut out, true) {
            yield Ok::<_, std::convert::Infallible>(chunk);
        }

        // ── ACL rule counters ──
        let _ = writeln!(out, "# HELP aria_rule_packets_total ACL rule matched packets");
        let _ = writeln!(out, "# TYPE aria_rule_packets_total counter");
        let _ = writeln!(out, "# HELP aria_rule_bytes_total ACL rule matched bytes");
        let _ = writeln!(out, "# TYPE aria_rule_bytes_total counter");
        let _ = writeln!(out, "# HELP aria_rule_dropped_packets_total ACL rule dropped packets");
        let _ = writeln!(out, "# TYPE aria_rule_dropped_packets_total counter");
        let _ = writeln!(out, "# HELP aria_rule_dropped_bytes_total ACL rule dropped bytes");
        let _ = writeln!(out, "# TYPE aria_rule_dropped_bytes_total counter");

        for inst in &instances {
            let i = prom_escape(inst);
            if let Ok((entries, groups)) = cp.get_rule_stats(inst).await {
                let find_name = |id: u32| -> String {
                    if id == 0 {
                        return "any".to_string();
                    }
                    groups.values().find(|g| g.id == id).map(|g| g.name.clone()).unwrap_or_else(|| format!("id:{}", id))
                };
                for e in &entries {
                    let sg = prom_escape(&find_name(e.key.src_id));
                    let dg = prom_escape(&find_name(e.key.dst_id));
                    let proto = prom_escape(&proto_to_string(e.key.proto));
                    let dir = prom_escape(&direction_to_string(e.key.direction));
                    let _ = writeln!(out, "aria_rule_packets_total{{instance=\"{i}\",src_group=\"{sg}\",dst_group=\"{dg}\",proto=\"{proto}\",direction=\"{dir}\"}} {}", e.packets);
                    let _ = writeln!(out, "aria_rule_bytes_total{{instance=\"{i}\",src_group=\"{sg}\",dst_group=\"{dg}\",proto=\"{proto}\",direction=\"{dir}\"}} {}", e.bytes);
                    let _ = writeln!(out, "aria_rule_dropped_packets_total{{instance=\"{i}\",src_group=\"{sg}\",dst_group=\"{dg}\",proto=\"{proto}\",direction=\"{dir}\"}} {}", e.dropped_packets);
                    let _ = writeln!(out, "aria_rule_dropped_bytes_total{{instance=\"{i}\",src_group=\"{sg}\",dst_group=\"{dg}\",proto=\"{proto}\",direction=\"{dir}\"}} {}", e.dropped_bytes);
                    if let Some(chunk) = flush_metrics_chunk(&mut out, false) {
                        yield Ok::<_, std::convert::Infallible>(chunk);
                    }
                }
            }
        }
        if let Some(chunk) = flush_metrics_chunk(&mut out, true) {
            yield Ok::<_, std::convert::Infallible>(chunk);
        }

        // ── QoS counters ──
        let _ = writeln!(out, "# HELP aria_qos_passed_packets_total QoS passed packets");
        let _ = writeln!(out, "# TYPE aria_qos_passed_packets_total counter");
        let _ = writeln!(out, "# HELP aria_qos_passed_bytes_total QoS passed bytes");
        let _ = writeln!(out, "# TYPE aria_qos_passed_bytes_total counter");
        let _ = writeln!(out, "# HELP aria_qos_dropped_packets_total QoS dropped packets");
        let _ = writeln!(out, "# TYPE aria_qos_dropped_packets_total counter");
        let _ = writeln!(out, "# HELP aria_qos_dropped_bytes_total QoS dropped bytes");
        let _ = writeln!(out, "# TYPE aria_qos_dropped_bytes_total counter");
        let _ = writeln!(out, "# HELP aria_qos_shaped_packets_total QoS shaped packets");
        let _ = writeln!(out, "# TYPE aria_qos_shaped_packets_total counter");
        let _ = writeln!(out, "# HELP aria_qos_shaped_bytes_total QoS shaped bytes");
        let _ = writeln!(out, "# TYPE aria_qos_shaped_bytes_total counter");

        for inst in &instances {
            let i = prom_escape(inst);
            if let Ok((entries, groups)) = cp.get_qos_stats(inst).await {
                let find_name = |id: u32| -> String {
                    if id == 0 {
                        return "any".to_string();
                    }
                    groups.values().find(|g| g.id == id).map(|g| g.name.clone()).unwrap_or_else(|| format!("id:{}", id))
                };
                for e in &entries {
                    let g = prom_escape(&find_name(e.key.group_id));
                    let dir = prom_escape(&direction_to_string(e.key.direction));
                    let _ = writeln!(out, "aria_qos_passed_packets_total{{instance=\"{i}\",group=\"{g}\",direction=\"{dir}\"}} {}", e.passed_packets);
                    let _ = writeln!(out, "aria_qos_passed_bytes_total{{instance=\"{i}\",group=\"{g}\",direction=\"{dir}\"}} {}", e.passed_bytes);
                    let _ = writeln!(out, "aria_qos_dropped_packets_total{{instance=\"{i}\",group=\"{g}\",direction=\"{dir}\"}} {}", e.dropped_packets);
                    let _ = writeln!(out, "aria_qos_dropped_bytes_total{{instance=\"{i}\",group=\"{g}\",direction=\"{dir}\"}} {}", e.dropped_bytes);
                    let _ = writeln!(out, "aria_qos_shaped_packets_total{{instance=\"{i}\",group=\"{g}\",direction=\"{dir}\"}} {}", e.shaped_packets);
                    let _ = writeln!(out, "aria_qos_shaped_bytes_total{{instance=\"{i}\",group=\"{g}\",direction=\"{dir}\"}} {}", e.shaped_bytes);
                    if let Some(chunk) = flush_metrics_chunk(&mut out, false) {
                        yield Ok::<_, std::convert::Infallible>(chunk);
                    }
                }
            }
        }
        if let Some(chunk) = flush_metrics_chunk(&mut out, true) {
            yield Ok::<_, std::convert::Infallible>(chunk);
        }

        // ── Group traffic counters ──
        let _ = writeln!(out, "# HELP aria_group_packets_total Group traffic packets");
        let _ = writeln!(out, "# TYPE aria_group_packets_total counter");
        let _ = writeln!(out, "# HELP aria_group_bytes_total Group traffic bytes");
        let _ = writeln!(out, "# TYPE aria_group_bytes_total counter");

        for inst in &instances {
            let i = prom_escape(inst);
            if let Ok((entries, groups)) = cp.get_group_stats(inst).await {
                let find_name = |id: u32| -> String {
                    if id == 0 {
                        return "any".to_string();
                    }
                    groups.values().find(|g| g.id == id).map(|g| g.name.clone()).unwrap_or_else(|| format!("id:{}", id))
                };
                for e in &entries {
                    let g = prom_escape(&find_name(e.key.group_id));
                    let dir = prom_escape(&direction_to_string(e.key.direction));
                    let _ = writeln!(out, "aria_group_packets_total{{instance=\"{i}\",group=\"{g}\",direction=\"{dir}\"}} {}", e.packets);
                    let _ = writeln!(out, "aria_group_bytes_total{{instance=\"{i}\",group=\"{g}\",direction=\"{dir}\"}} {}", e.bytes);
                    if let Some(chunk) = flush_metrics_chunk(&mut out, false) {
                        yield Ok::<_, std::convert::Infallible>(chunk);
                    }
                }
            }
        }
        if let Some(chunk) = flush_metrics_chunk(&mut out, true) {
            yield Ok::<_, std::convert::Infallible>(chunk);
        }

        // ── Mirror counters ──
        let _ = writeln!(out, "# HELP aria_mirror_packets_total Mirrored packets");
        let _ = writeln!(out, "# TYPE aria_mirror_packets_total counter");
        let _ = writeln!(out, "# HELP aria_mirror_bytes_total Mirrored bytes");
        let _ = writeln!(out, "# TYPE aria_mirror_bytes_total counter");
        let _ = writeln!(out, "# HELP aria_mirror_errors_total Mirror errors");
        let _ = writeln!(out, "# TYPE aria_mirror_errors_total counter");

        for inst in &instances {
            let i = prom_escape(inst);
            if let Ok((entries, groups)) = cp.get_mirror_stats(inst).await {
                let find_name = |id: u32| -> String {
                    if id == 0 {
                        return "any".to_string();
                    }
                    groups.values().find(|g| g.id == id).map(|g| g.name.clone()).unwrap_or_else(|| format!("id:{}", id))
                };
                for e in &entries {
                    let sg = prom_escape(&find_name(e.src_id));
                    let dg = prom_escape(&find_name(e.dst_id));
                    let proto = prom_escape(&proto_to_string(e.proto));
                    let dir = prom_escape(&direction_to_string(e.direction));
                    let _ = writeln!(out, "aria_mirror_packets_total{{instance=\"{i}\",src_group=\"{sg}\",dst_group=\"{dg}\",proto=\"{proto}\",direction=\"{dir}\"}} {}", e.mirrored_packets);
                    let _ = writeln!(out, "aria_mirror_bytes_total{{instance=\"{i}\",src_group=\"{sg}\",dst_group=\"{dg}\",proto=\"{proto}\",direction=\"{dir}\"}} {}", e.mirrored_bytes);
                    let _ = writeln!(out, "aria_mirror_errors_total{{instance=\"{i}\",src_group=\"{sg}\",dst_group=\"{dg}\",proto=\"{proto}\",direction=\"{dir}\"}} {}", e.errors);
                    if let Some(chunk) = flush_metrics_chunk(&mut out, false) {
                        yield Ok::<_, std::convert::Infallible>(chunk);
                    }
                }
            }
        }
        if let Some(chunk) = flush_metrics_chunk(&mut out, true) {
            yield Ok::<_, std::convert::Infallible>(chunk);
        }

        // ── TCP-RT aggregated ──
        let _ = writeln!(out, "# HELP aria_tcprt_flows_total Number of retained TCP-RT flows");
        let _ = writeln!(out, "# TYPE aria_tcprt_flows_total gauge");
        let _ = writeln!(out, "# HELP aria_tcprt_retrans_req_total Total request retransmissions");
        let _ = writeln!(out, "# TYPE aria_tcprt_retrans_req_total counter");
        let _ = writeln!(out, "# HELP aria_tcprt_retrans_resp_total Total response retransmissions");
        let _ = writeln!(out, "# TYPE aria_tcprt_retrans_resp_total counter");
        let _ = writeln!(out, "# HELP aria_tcprt_requests_total Total request count");
        let _ = writeln!(out, "# TYPE aria_tcprt_requests_total counter");
        let _ = writeln!(out, "# HELP aria_tcprt_handshake_us_sum Sum of handshake latency in microseconds");
        let _ = writeln!(out, "# TYPE aria_tcprt_handshake_us_sum gauge");
        let _ = writeln!(out, "# HELP aria_tcprt_art_us_sum Sum of application response time in microseconds");
        let _ = writeln!(out, "# TYPE aria_tcprt_art_us_sum gauge");
        let _ = writeln!(out, "# HELP aria_tcprt_rtt_client_us_sum Sum of client RTT in microseconds");
        let _ = writeln!(out, "# TYPE aria_tcprt_rtt_client_us_sum gauge");
        let _ = writeln!(out, "# HELP aria_tcprt_rtt_server_us_sum Sum of server RTT in microseconds");
        let _ = writeln!(out, "# TYPE aria_tcprt_rtt_server_us_sum gauge");
        let _ = writeln!(out, "# HELP aria_tcprt_art_seconds ART latency distribution histogram");
        let _ = writeln!(out, "# TYPE aria_tcprt_art_seconds histogram");
        let _ = writeln!(out, "# HELP aria_tcprt_nqa_score_avg Average NQA network quality score (0-100)");
        let _ = writeln!(out, "# TYPE aria_tcprt_nqa_score_avg gauge");

        for inst in &instances {
            let i = prom_escape(inst);
            match cp.get_tcprt_metrics_summary(inst).await {
                Ok(Some(summary)) => write_tcprt_summary_metrics(&mut out, &i, &summary),
                Ok(None) => {}
                Err(e) => warn!("Failed to collect TCP-RT metrics for {}: {}", inst, e),
            }
            if let Some(chunk) = flush_metrics_chunk(&mut out, false) {
                yield Ok::<_, std::convert::Infallible>(chunk);
            }
        }
        if let Some(chunk) = flush_metrics_chunk(&mut out, true) {
            yield Ok::<_, std::convert::Infallible>(chunk);
        }

        // ── SSL handshake metrics ──
        let _ = writeln!(out, "# HELP aria_ssl_handshakes_total Number of SSL handshakes observed");
        let _ = writeln!(out, "# TYPE aria_ssl_handshakes_total gauge");
        let _ = writeln!(out, "# HELP aria_ssl_handshake_seconds SSL handshake latency distribution");
        let _ = writeln!(out, "# TYPE aria_ssl_handshake_seconds histogram");

        let ssl_instance = prom_escape("ssl-global");
        match cp.get_ssl_metrics_summary().await {
            Ok(Some(summary)) => write_ssl_summary_metrics(&mut out, &ssl_instance, &summary),
            Ok(None) => {}
            Err(e) => warn!("Failed to collect SSL handshake metrics: {}", e),
        }
        if let Some(chunk) = flush_metrics_chunk(&mut out, true) {
            yield Ok::<_, std::convert::Infallible>(chunk);
        }

        // ── SSL HTTP metrics ──
        let _ = writeln!(out, "# HELP aria_ssl_http_requests_total Number of HTTP requests observed via SSL");
        let _ = writeln!(out, "# TYPE aria_ssl_http_requests_total gauge");
        let _ = writeln!(out, "# HELP aria_ssl_http_latency_seconds HTTP request latency distribution via SSL");
        let _ = writeln!(out, "# TYPE aria_ssl_http_latency_seconds histogram");

        match cp.get_ssl_http_metrics_summary().await {
            Ok(Some(summary)) => write_ssl_http_summary_metrics(&mut out, &ssl_instance, &summary),
            Ok(None) => {}
            Err(e) => warn!("Failed to collect SSL HTTP metrics: {}", e),
        }
        if let Some(chunk) = flush_metrics_chunk(&mut out, true) {
            yield Ok::<_, std::convert::Infallible>(chunk);
        }
    };

    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        Body::from_stream(stream),
    )
}
