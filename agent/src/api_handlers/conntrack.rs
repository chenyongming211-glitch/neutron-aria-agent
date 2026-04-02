use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Json,
};

use super::common::{err_response, AppState};
use aria_api::{proto_to_string, ConntrackEntry, ConntrackFlushResponse, ConntrackResponse};

#[utoipa::path(
    get,
    path = "/api/v1/{instance}/conntrack",
    tag = "conntrack",
    summary = "List conntrack entries for an instance",
    operation_id = "listConntrackEntries",
    params(
        ("instance" = String, Path, description = "Managed instance name")
    ),
    responses(
        (status = 200, description = "Conntrack table contents", body = ConntrackResponse),
        (status = 404, description = "Instance not found", body = aria_api::ApiError),
        (status = 500, description = "Internal server error", body = aria_api::ApiError)
    )
)]
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

#[utoipa::path(
    delete,
    path = "/api/v1/{instance}/conntrack",
    tag = "conntrack",
    summary = "Flush conntrack entries for an instance",
    operation_id = "flushConntrackEntries",
    params(
        ("instance" = String, Path, description = "Managed instance name")
    ),
    responses(
        (status = 200, description = "Flushed conntrack entry count", body = ConntrackFlushResponse),
        (status = 404, description = "Instance not found", body = aria_api::ApiError),
        (status = 500, description = "Internal server error", body = aria_api::ApiError)
    )
)]
pub async fn flush_conntrack(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.flush_conntrack(&instance).await {
        Ok(count) => Ok(Json(ConntrackFlushResponse { flushed: count })),
        Err(e) => Err(err_response(e)),
    }
}
