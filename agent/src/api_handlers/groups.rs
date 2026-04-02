use std::collections::HashMap;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};

use super::common::{err_response, AppState};
use aria_api::{
    AddGroupRequest, AddGroupResponse, GroupEntry, GroupWithStatsEntry, GroupsResponse,
    GroupsWithStatsResponse, MessageResponse,
};

#[utoipa::path(
    get,
    path = "/api/v1/{instance}/groups",
    tag = "groups",
    summary = "List groups for an instance",
    params(
        ("instance" = String, Path, description = "Managed instance name")
    ),
    responses(
        (status = 200, description = "Configured groups", body = GroupsResponse),
        (status = 404, description = "Instance not found", body = aria_api::ApiError),
        (status = 500, description = "Internal server error", body = aria_api::ApiError)
    )
)]
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

#[utoipa::path(
    post,
    path = "/api/v1/{instance}/groups",
    tag = "groups",
    summary = "Create or extend a group",
    params(
        ("instance" = String, Path, description = "Managed instance name")
    ),
    request_body = AddGroupRequest,
    responses(
        (status = 201, description = "Group created or updated", body = AddGroupResponse),
        (status = 400, description = "Validation error", body = aria_api::ApiError),
        (status = 404, description = "Instance not found", body = aria_api::ApiError),
        (status = 500, description = "Internal server error", body = aria_api::ApiError)
    )
)]
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

#[utoipa::path(
    delete,
    path = "/api/v1/{instance}/groups/{name}",
    tag = "groups",
    summary = "Delete a group",
    params(
        ("instance" = String, Path, description = "Managed instance name"),
        ("name" = String, Path, description = "Group name")
    ),
    responses(
        (status = 200, description = "Group deleted", body = MessageResponse),
        (status = 404, description = "Instance or group not found", body = aria_api::ApiError),
        (status = 500, description = "Internal server error", body = aria_api::ApiError)
    )
)]
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

#[utoipa::path(
    get,
    path = "/api/v1/{instance}/groups/with_stats",
    tag = "groups",
    summary = "List groups with aggregated statistics",
    params(
        ("instance" = String, Path, description = "Managed instance name")
    ),
    responses(
        (status = 200, description = "Groups with statistics", body = GroupsWithStatsResponse),
        (status = 404, description = "Instance not found", body = aria_api::ApiError),
        (status = 500, description = "Internal server error", body = aria_api::ApiError)
    )
)]
pub async fn list_groups_with_stats(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.list_groups_with_stats(&instance).await {
        Ok((groups, stats)) => {
            let mut stats_map: HashMap<(u32, u8), aria_core::monitoring::GroupStatsEntry> = stats
                .into_iter()
                .map(|s| ((s.key.group_id, s.key.direction), s))
                .collect();

            let groups_with_stats = groups
                .into_iter()
                .map(|g| {
                    let ingress_key = (g.id, 0u8);
                    let egress_key = (g.id, 1u8);
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
