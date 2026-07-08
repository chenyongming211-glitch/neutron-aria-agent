use std::collections::HashMap;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};

use super::common::{err_response, AppState};
use crate::control_plane::{ControlPlaneError, LocalWriteDomain};
use aria_api::*;

#[utoipa::path(
    get,
    path = "/api/v1/{instance}/qos",
    tag = "qos",
    summary = "List QoS rules for an instance",
    operation_id = "listQosRules",
    params(
        ("instance" = String, Path, description = "Managed instance name")
    ),
    responses(
        (status = 200, description = "Configured QoS rules", body = QosListResponse),
        (status = 404, description = "Instance not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError)
    )
)]
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

#[utoipa::path(
    post,
    path = "/api/v1/{instance}/qos",
    tag = "qos",
    summary = "Add or update a QoS rule",
    operation_id = "addOrUpdateQosRule",
    params(
        ("instance" = String, Path, description = "Managed instance name")
    ),
    request_body = AddQosRequest,
    responses(
        (status = 201, description = "QoS rule created or updated", body = MessageResponse),
        (status = 400, description = "Validation error", body = ApiError),
        (status = 404, description = "Instance or group not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError)
    )
)]
pub async fn add_qos(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
    Json(req): Json<AddQosRequest>,
) -> impl IntoResponse {
    if let Err(e) = cp
        .ensure_local_write_allowed(&instance, LocalWriteDomain::Qos)
        .await
    {
        return Err(err_response(e));
    }

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
            ))));
        }
    };

    let directions: Vec<u8> = if direction == 2 {
        vec![0, 1]
    } else {
        vec![direction]
    };
    let mut applied: Vec<u8> = Vec::new();
    let mut shaping_downgraded = false;

    for dir in &directions {
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

#[utoipa::path(
    delete,
    path = "/api/v1/{instance}/qos",
    tag = "qos",
    summary = "Delete a QoS rule",
    operation_id = "deleteQosRule",
    params(
        ("instance" = String, Path, description = "Managed instance name")
    ),
    request_body = DeleteQosRequest,
    responses(
        (status = 200, description = "QoS rule deleted", body = MessageResponse),
        (status = 400, description = "Validation error", body = ApiError),
        (status = 404, description = "Instance or group not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError)
    )
)]
pub async fn delete_qos(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
    Json(req): Json<DeleteQosRequest>,
) -> impl IntoResponse {
    if let Err(e) = cp
        .ensure_local_write_allowed(&instance, LocalWriteDomain::Qos)
        .await
    {
        return Err(err_response(e));
    }

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

#[utoipa::path(
    get,
    path = "/api/v1/{instance}/qos/with_stats",
    tag = "qos",
    summary = "List QoS rules with aggregated statistics",
    operation_id = "listQosRulesWithStats",
    params(
        ("instance" = String, Path, description = "Managed instance name")
    ),
    responses(
        (status = 200, description = "QoS rules with statistics", body = QosWithStatsResponse),
        (status = 404, description = "Instance not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError)
    )
)]
pub async fn list_qos_with_stats(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.list_qos(&instance).await {
        Ok(rules) => match cp.get_qos_stats(&instance).await {
            Ok((stats, _)) => {
                let mut stats_map: HashMap<(u32, u8), aria_core::monitoring::QosStatsEntry> = stats
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
                            passed_packets: stat.as_ref().map(|s| s.passed_packets).unwrap_or(0),
                            passed_bytes: stat.as_ref().map(|s| s.passed_bytes).unwrap_or(0),
                            dropped_packets: stat.as_ref().map(|s| s.dropped_packets).unwrap_or(0),
                            dropped_bytes: stat.as_ref().map(|s| s.dropped_bytes).unwrap_or(0),
                            shaped_packets: stat.as_ref().map(|s| s.shaped_packets).unwrap_or(0),
                            shaped_bytes: stat.as_ref().map(|s| s.shaped_bytes).unwrap_or(0),
                        }
                    })
                    .collect();
                Ok(Json(QosWithStatsResponse {
                    rules: rules_with_stats,
                }))
            }
            Err(e) => Err(err_response(e)),
        },
        Err(e) => Err(err_response(e)),
    }
}
