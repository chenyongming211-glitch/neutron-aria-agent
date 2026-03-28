use axum::{
    extract::{Path, Query, State},
    response::IntoResponse,
    Json,
};

use super::common::{err_response, legacy_drop_headers, AppState};
use aria_api::{direction_to_string, proto_to_string};

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
