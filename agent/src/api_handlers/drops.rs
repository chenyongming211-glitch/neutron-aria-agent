use axum::{
    extract::{Path, Query, State},
    response::IntoResponse,
    Json,
};

use super::common::{err_response, legacy_drop_headers, AppState};
use aria_api::{direction_to_string, proto_to_string};

#[utoipa::path(
    get,
    path = "/api/v1/{instance}/stats/drops",
    tag = "drops",
    summary = "List legacy drop statistics for an instance",
    description = "Deprecated legacy drop statistics endpoint. Prefer /api/v1/stats/kernel_drops for kernel-attributed drops.",
    params(
        ("instance" = String, Path, description = "Managed instance name")
    ),
    responses(
        (status = 200, description = "Legacy drop statistics", body = aria_api::DropStatsResponse),
        (status = 404, description = "Instance not found", body = aria_api::ApiError),
        (status = 500, description = "Internal server error", body = aria_api::ApiError)
    )
)]
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

#[utoipa::path(
    delete,
    path = "/api/v1/{instance}/stats/drops",
    tag = "drops",
    summary = "Flush legacy drop statistics for an instance",
    description = "Deprecated legacy drop statistics endpoint. Prefer /api/v1/stats/kernel_drops for kernel-attributed drops.",
    params(
        ("instance" = String, Path, description = "Managed instance name")
    ),
    responses(
        (status = 200, description = "Flushed legacy drop statistics count", body = aria_api::DropFlushResponse),
        (status = 404, description = "Instance not found", body = aria_api::ApiError),
        (status = 500, description = "Internal server error", body = aria_api::ApiError)
    )
)]
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

#[utoipa::path(
    get,
    path = "/api/v1/stats/kernel_drops",
    tag = "drops",
    summary = "List kernel-attributed drop statistics",
    params(
        ("instance" = Option<String>, Query, description = "Filter by managed instance name"),
        ("iface" = Option<String>, Query, description = "Filter by interface name"),
        ("ifindex" = Option<u32>, Query, description = "Filter by interface index"),
        ("reason" = Option<u16>, Query, description = "Filter by kernel drop reason code"),
        ("top" = Option<usize>, Query, description = "Maximum number of drop records to return"),
        ("include_unattributed" = Option<bool>, Query, description = "Include drops that cannot be mapped to a managed instance")
    ),
    responses(
        (status = 200, description = "Kernel-attributed drop statistics", body = aria_api::KernelDropStatsResponse),
        (status = 400, description = "Validation error", body = aria_api::ApiError),
        (status = 500, description = "Internal server error", body = aria_api::ApiError)
    )
)]
pub async fn list_kernel_drops(
    State(cp): State<AppState>,
    Query(query): Query<aria_api::KernelDropQuery>,
) -> impl IntoResponse {
    match cp.get_kernel_drop_stats(&query).await {
        Ok(drops) => Ok(Json(aria_api::KernelDropStatsResponse { drops })),
        Err(e) => Err(err_response(e)),
    }
}

#[utoipa::path(
    delete,
    path = "/api/v1/stats/kernel_drops",
    tag = "drops",
    summary = "Flush kernel-attributed drop statistics",
    params(
        ("instance" = Option<String>, Query, description = "Filter by managed instance name"),
        ("iface" = Option<String>, Query, description = "Filter by interface name"),
        ("ifindex" = Option<u32>, Query, description = "Filter by interface index"),
        ("reason" = Option<u16>, Query, description = "Filter by kernel drop reason code"),
        ("top" = Option<usize>, Query, description = "Maximum number of drop records to target"),
        ("include_unattributed" = Option<bool>, Query, description = "Include drops that cannot be mapped to a managed instance")
    ),
    responses(
        (status = 200, description = "Flushed kernel drop statistics count", body = aria_api::KernelDropFlushResponse),
        (status = 400, description = "Validation error", body = aria_api::ApiError),
        (status = 500, description = "Internal server error", body = aria_api::ApiError)
    )
)]
pub async fn flush_kernel_drops(
    State(cp): State<AppState>,
    Query(query): Query<aria_api::KernelDropQuery>,
) -> impl IntoResponse {
    match cp.flush_kernel_drop_stats(&query).await {
        Ok(flushed) => Ok(Json(aria_api::KernelDropFlushResponse { flushed })),
        Err(e) => Err(err_response(e)),
    }
}
