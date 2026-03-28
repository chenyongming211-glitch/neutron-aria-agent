mod common;
mod config;
mod conntrack;
mod drops;
mod groups;
mod health;
mod metrics;
mod mirror;
mod ssl;
mod stats;
mod system;
mod tcprt;
mod trace;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;

use crate::control_plane::ControlPlaneError;
use aria_api::*;
use self::common::{err_response, AppState};
pub use self::config::{get_config, update_config};
pub use self::conntrack::{flush_conntrack, list_conntrack};
pub use self::drops::{flush_drops, flush_kernel_drops, list_drops, list_kernel_drops};
pub use self::groups::{add_group, delete_group, list_groups, list_groups_with_stats};
pub use self::health::health;
pub use self::metrics::metrics;
pub use self::mirror::{
    add_mirror, delete_mirror, list_mirror, list_mirror_with_stats, stats_mirror,
};
pub use self::ssl::{
    flush_ssl, flush_ssl_errors, flush_ssl_global, flush_ssl_http, flush_ssl_http_global,
    get_ssl_config, list_ssl, list_ssl_errors, list_ssl_global, list_ssl_http,
    list_ssl_http_global, update_ssl_config,
};
pub use self::stats::{stats_flows, stats_groups, stats_overview, stats_qos, stats_rules};
pub use self::system::{list_instances, system_start, system_stop};
pub use self::tcprt::{
    batch_query_tcprt, filter_tcprt, flush_tcprt, list_tcprt, tcprt_histogram, tcprt_states,
};
pub use self::trace::{flush_trace, list_trace, start_trace, stop_trace};

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

#[derive(Deserialize)]
pub struct TopQuery {
    #[serde(default = "default_top")]
    pub top: usize,
}

fn default_top() -> usize {
    20
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
