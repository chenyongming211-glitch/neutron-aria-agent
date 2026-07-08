use axum::{
    extract::{Path, Query, State},
    response::IntoResponse,
    Json,
};

use super::{
    common::{err_response, AppState},
    TopQuery,
};
use crate::control_plane::LocalWriteDomain;

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

#[utoipa::path(
    get,
    path = "/api/v1/ssl",
    tag = "ssl",
    summary = "List global SSL connection observations",
    operation_id = "listGlobalSslConnections",
    params(
        ("top" = Option<usize>, Query, description = "Maximum number of SSL connections to return")
    ),
    responses(
        (status = 200, description = "Global SSL connection observations", body = aria_api::SslListResponse),
        (status = 500, description = "Internal server error", body = aria_api::ApiError)
    )
)]
pub async fn list_ssl_global(
    State(cp): State<AppState>,
    Query(query): Query<TopQuery>,
) -> impl IntoResponse {
    match cp.list_ssl_global(query.top).await {
        Ok(entries) => Ok(Json(map_ssl_connections(entries))),
        Err(e) => Err(err_response(e)),
    }
}

#[utoipa::path(
    delete,
    path = "/api/v1/ssl",
    tag = "ssl",
    summary = "Flush global SSL connection observations",
    operation_id = "flushGlobalSslConnections",
    responses(
        (status = 200, description = "Flushed SSL connection count", body = aria_api::SslFlushResponse),
        (status = 500, description = "Internal server error", body = aria_api::ApiError)
    )
)]
pub async fn flush_ssl_global(State(cp): State<AppState>) -> impl IntoResponse {
    match cp.flush_ssl_global().await {
        Ok(count) => Ok(Json(aria_api::SslFlushResponse { flushed: count })),
        Err(e) => Err(err_response(e)),
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/{instance}/ssl",
    tag = "ssl",
    summary = "List SSL connection observations for an instance",
    operation_id = "listInstanceSslConnections",
    params(
        ("instance" = String, Path, description = "Managed instance name"),
        ("top" = Option<usize>, Query, description = "Maximum number of SSL connections to return")
    ),
    responses(
        (status = 200, description = "SSL connection observations", body = aria_api::SslListResponse),
        (status = 404, description = "Instance not found", body = aria_api::ApiError),
        (status = 500, description = "Internal server error", body = aria_api::ApiError)
    )
)]
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

#[utoipa::path(
    delete,
    path = "/api/v1/{instance}/ssl",
    tag = "ssl",
    summary = "Flush SSL connection observations for an instance",
    operation_id = "flushInstanceSslConnections",
    params(
        ("instance" = String, Path, description = "Managed instance name")
    ),
    responses(
        (status = 200, description = "Flushed SSL connection count", body = aria_api::SslFlushResponse),
        (status = 404, description = "Instance not found", body = aria_api::ApiError),
        (status = 500, description = "Internal server error", body = aria_api::ApiError)
    )
)]
pub async fn flush_ssl(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = cp
        .ensure_local_write_allowed(&instance, LocalWriteDomain::Ssl)
        .await
    {
        return Err(err_response(e));
    }

    match cp.flush_ssl(&instance).await {
        Ok(count) => Ok(Json(aria_api::SslFlushResponse { flushed: count })),
        Err(e) => Err(err_response(e)),
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/ssl/http",
    tag = "ssl",
    summary = "List global SSL HTTP observations",
    operation_id = "listGlobalSslHttpEvents",
    params(
        ("top" = Option<usize>, Query, description = "Maximum number of SSL HTTP events to return")
    ),
    responses(
        (status = 200, description = "Global SSL HTTP observations", body = aria_api::SslHttpListResponse),
        (status = 500, description = "Internal server error", body = aria_api::ApiError)
    )
)]
pub async fn list_ssl_http_global(
    State(cp): State<AppState>,
    Query(query): Query<TopQuery>,
) -> impl IntoResponse {
    match cp.list_ssl_http_global(query.top).await {
        Ok(entries) => Ok(Json(map_ssl_http_events(entries))),
        Err(e) => Err(err_response(e)),
    }
}

#[utoipa::path(
    delete,
    path = "/api/v1/ssl/http",
    tag = "ssl",
    summary = "Flush global SSL HTTP observations",
    operation_id = "flushGlobalSslHttpEvents",
    responses(
        (status = 200, description = "Flushed SSL HTTP event count", body = aria_api::SslHttpFlushResponse),
        (status = 500, description = "Internal server error", body = aria_api::ApiError)
    )
)]
pub async fn flush_ssl_http_global(State(cp): State<AppState>) -> impl IntoResponse {
    match cp.flush_ssl_http_global().await {
        Ok(count) => Ok(Json(aria_api::SslHttpFlushResponse { flushed: count })),
        Err(e) => Err(err_response(e)),
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/{instance}/ssl/http",
    tag = "ssl",
    summary = "List SSL HTTP observations for an instance",
    operation_id = "listInstanceSslHttpEvents",
    params(
        ("instance" = String, Path, description = "Managed instance name"),
        ("top" = Option<usize>, Query, description = "Maximum number of SSL HTTP events to return")
    ),
    responses(
        (status = 200, description = "SSL HTTP observations", body = aria_api::SslHttpListResponse),
        (status = 404, description = "Instance not found", body = aria_api::ApiError),
        (status = 500, description = "Internal server error", body = aria_api::ApiError)
    )
)]
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

#[utoipa::path(
    delete,
    path = "/api/v1/{instance}/ssl/http",
    tag = "ssl",
    summary = "Flush SSL HTTP observations for an instance",
    operation_id = "flushInstanceSslHttpEvents",
    params(
        ("instance" = String, Path, description = "Managed instance name")
    ),
    responses(
        (status = 200, description = "Flushed SSL HTTP event count", body = aria_api::SslHttpFlushResponse),
        (status = 404, description = "Instance not found", body = aria_api::ApiError),
        (status = 500, description = "Internal server error", body = aria_api::ApiError)
    )
)]
pub async fn flush_ssl_http(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    if let Err(e) = cp
        .ensure_local_write_allowed(&instance, LocalWriteDomain::Ssl)
        .await
    {
        return Err(err_response(e));
    }

    match cp.flush_ssl_http(&instance).await {
        Ok(count) => Ok(Json(aria_api::SslHttpFlushResponse { flushed: count })),
        Err(e) => Err(err_response(e)),
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/ssl/config",
    tag = "ssl",
    summary = "Get global SSL observability configuration",
    operation_id = "getGlobalSslConfig",
    responses(
        (status = 200, description = "Global SSL observability configuration", body = aria_api::SslGlobalConfigResponse),
        (status = 500, description = "Internal server error", body = aria_api::ApiError)
    )
)]
pub async fn get_ssl_config(State(cp): State<AppState>) -> impl IntoResponse {
    match cp.get_ssl_global_config().await {
        Ok(enabled) => Ok(Json(aria_api::SslGlobalConfigResponse { enabled })),
        Err(e) => Err(err_response(e)),
    }
}

#[utoipa::path(
    put,
    path = "/api/v1/ssl/config",
    tag = "ssl",
    summary = "Update global SSL observability configuration",
    operation_id = "updateGlobalSslConfig",
    request_body = aria_api::UpdateSslGlobalConfigRequest,
    responses(
        (status = 200, description = "SSL observability configuration updated", body = aria_api::MessageResponse),
        (status = 400, description = "Validation error", body = aria_api::ApiError),
        (status = 500, description = "Internal server error", body = aria_api::ApiError)
    )
)]
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

#[utoipa::path(
    get,
    path = "/api/v1/ssl/errors",
    tag = "ssl",
    summary = "List SSL error observations",
    operation_id = "listSslErrors",
    responses(
        (status = 200, description = "SSL error observations", body = aria_api::SslErrorListResponse),
        (status = 500, description = "Internal server error", body = aria_api::ApiError)
    )
)]
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

#[utoipa::path(
    delete,
    path = "/api/v1/ssl/errors",
    tag = "ssl",
    summary = "Flush SSL error observations",
    operation_id = "flushSslErrors",
    responses(
        (status = 200, description = "Flushed SSL error count", body = aria_api::SslErrorFlushResponse),
        (status = 500, description = "Internal server error", body = aria_api::ApiError)
    )
)]
pub async fn flush_ssl_errors(State(cp): State<AppState>) -> impl IntoResponse {
    match cp.flush_ssl_errors().await {
        Ok(count) => Ok(Json(aria_api::SslErrorFlushResponse { flushed: count })),
        Err(e) => Err(err_response(e)),
    }
}
