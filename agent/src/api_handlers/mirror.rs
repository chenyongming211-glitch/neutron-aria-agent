use std::collections::HashMap;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};

use super::common::{err_response, AppState};
use crate::control_plane::ControlPlaneError;
use aria_api::{
    direction_from_string, direction_to_string, proto_from_string, proto_to_string,
    AddMirrorRequest, DeleteMirrorRequest, MessageResponse, MirrorEntry, MirrorListResponse,
    MirrorStatsResponse, MirrorWithStatsEntry, MirrorWithStatsResponse,
};

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
        Ok(rules) => match cp.get_mirror_stats(&instance).await {
            Ok((stats, _)) => {
                let mut stats_map: HashMap<
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
        },
        Err(e) => Err(err_response(e)),
    }
}
