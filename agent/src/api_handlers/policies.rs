use std::collections::HashMap;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};

use super::common::{err_response, AppState};
use crate::control_plane::ControlPlaneError;
use aria_api::*;

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
        Ok((rules, groups)) => match cp.get_rule_stats(&instance).await {
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

                let mut stats_map: HashMap<(u32, u32, u8, u8), aria_core::monitoring::RuleStatsEntry> =
                    stats
                        .into_iter()
                        .map(|s| ((s.key.src_id, s.key.dst_id, s.key.proto, s.key.direction), s))
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
        },
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
