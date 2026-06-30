use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
};

use super::{
    TopQuery,
    common::{AppState, err_response},
};
use crate::control_plane::{ControlPlaneError, LocalWriteDomain};
use aria_api::{MessageResponse, proto_from_string, proto_to_string};

#[utoipa::path(
    post,
    path = "/api/v1/{instance}/trace",
    tag = "trace",
    summary = "Start packet tracing for an instance",
    operation_id = "startPacketTrace",
    params(
        ("instance" = String, Path, description = "Managed instance name")
    ),
    request_body = aria_api::TraceStartRequest,
    responses(
        (status = 200, description = "Trace started", body = MessageResponse),
        (status = 400, description = "Validation error", body = aria_api::ApiError),
        (status = 404, description = "Instance not found", body = aria_api::ApiError),
        (status = 500, description = "Internal server error", body = aria_api::ApiError)
    )
)]
pub async fn start_trace(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
    Json(req): Json<aria_api::TraceStartRequest>,
) -> impl IntoResponse {
    if let Err(e) = cp
        .ensure_local_write_allowed(&instance, LocalWriteDomain::Trace)
        .await
    {
        return Err(err_response(e));
    }

    let mut src_ip: u32 = 0;
    let mut dst_ip: u32 = 0;
    let mut src_ip_v6: [u8; 16] = [0u8; 16];
    let mut dst_ip_v6: [u8; 16] = [0u8; 16];
    let mut is_ipv6: u8 = 0;
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

    if (src_is_v6 && !req.dst_ip.is_empty() && !dst_is_v6)
        || (dst_is_v6 && !req.src_ip.is_empty() && !src_is_v6)
    {
        return Err(err_response(ControlPlaneError::ValidationError(
            "Cannot mix IPv4 and IPv6 addresses in trace filter".to_string(),
        )));
    }

    if src_is_v6 || dst_is_v6 {
        is_ipv6 = 1;
    } else if req.src_ip.is_empty() && req.dst_ip.is_empty() {
        is_ipv6 = 2;
    }

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

#[utoipa::path(
    delete,
    path = "/api/v1/{instance}/trace",
    tag = "trace",
    summary = "Stop packet tracing for an instance",
    operation_id = "stopPacketTrace",
    params(
        ("instance" = String, Path, description = "Managed instance name")
    ),
    responses(
        (status = 200, description = "Trace stopped", body = MessageResponse),
        (status = 404, description = "Instance not found", body = aria_api::ApiError),
        (status = 500, description = "Internal server error", body = aria_api::ApiError)
    )
)]
pub async fn stop_trace(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = cp
        .ensure_local_write_allowed(&instance, LocalWriteDomain::Trace)
        .await
    {
        return Err(err_response(e));
    }

    match cp.stop_trace(&instance).await {
        Ok(()) => Ok(Json(MessageResponse {
            message: "Trace stopped".to_string(),
        })),
        Err(e) => Err(err_response(e)),
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/{instance}/trace",
    tag = "trace",
    summary = "List packet trace events for an instance",
    operation_id = "listPacketTraceEvents",
    params(
        ("instance" = String, Path, description = "Managed instance name"),
        ("top" = Option<usize>, Query, description = "Maximum number of trace events to return")
    ),
    responses(
        (status = 200, description = "Trace events", body = aria_api::TraceResponse),
        (status = 404, description = "Instance not found", body = aria_api::ApiError),
        (status = 500, description = "Internal server error", body = aria_api::ApiError)
    )
)]
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

#[utoipa::path(
    delete,
    path = "/api/v1/{instance}/trace/flush",
    tag = "trace",
    summary = "Flush packet trace events for an instance",
    operation_id = "flushPacketTraceEvents",
    params(
        ("instance" = String, Path, description = "Managed instance name")
    ),
    responses(
        (status = 200, description = "Flushed trace event count", body = aria_api::TraceFlushResponse),
        (status = 404, description = "Instance not found", body = aria_api::ApiError),
        (status = 500, description = "Internal server error", body = aria_api::ApiError)
    )
)]
pub async fn flush_trace(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = cp
        .ensure_local_write_allowed(&instance, LocalWriteDomain::Trace)
        .await
    {
        return Err(err_response(e));
    }

    match cp.flush_trace(&instance).await {
        Ok(count) => Ok(Json(aria_api::TraceFlushResponse { flushed: count })),
        Err(e) => Err(err_response(e)),
    }
}
