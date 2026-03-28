use axum::{
    extract::{Path, Query, State},
    response::IntoResponse,
    Json,
};

use super::{
    common::{err_response, AppState},
    TopQuery,
};

fn map_ssl_connections(entries: Vec<aria_core::ssl_ops::SslConnEntry>) -> aria_api::SslListResponse {
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

pub async fn list_ssl_global(
    State(cp): State<AppState>,
    Query(query): Query<TopQuery>,
) -> impl IntoResponse {
    match cp.list_ssl_global(query.top).await {
        Ok(entries) => Ok(Json(map_ssl_connections(entries))),
        Err(e) => Err(err_response(e)),
    }
}

pub async fn flush_ssl_global(State(cp): State<AppState>) -> impl IntoResponse {
    match cp.flush_ssl_global().await {
        Ok(count) => Ok(Json(aria_api::SslFlushResponse { flushed: count })),
        Err(e) => Err(err_response(e)),
    }
}

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

pub async fn flush_ssl(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.flush_ssl(&instance).await {
        Ok(count) => Ok(Json(aria_api::SslFlushResponse { flushed: count })),
        Err(e) => Err(err_response(e)),
    }
}

pub async fn list_ssl_http_global(
    State(cp): State<AppState>,
    Query(query): Query<TopQuery>,
) -> impl IntoResponse {
    match cp.list_ssl_http_global(query.top).await {
        Ok(entries) => Ok(Json(map_ssl_http_events(entries))),
        Err(e) => Err(err_response(e)),
    }
}

pub async fn flush_ssl_http_global(State(cp): State<AppState>) -> impl IntoResponse {
    match cp.flush_ssl_http_global().await {
        Ok(count) => Ok(Json(aria_api::SslHttpFlushResponse { flushed: count })),
        Err(e) => Err(err_response(e)),
    }
}

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

pub async fn flush_ssl_http(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.flush_ssl_http(&instance).await {
        Ok(count) => Ok(Json(aria_api::SslHttpFlushResponse { flushed: count })),
        Err(e) => Err(err_response(e)),
    }
}

pub async fn get_ssl_config(State(cp): State<AppState>) -> impl IntoResponse {
    match cp.get_ssl_global_config().await {
        Ok(enabled) => Ok(Json(aria_api::SslGlobalConfigResponse { enabled })),
        Err(e) => Err(err_response(e)),
    }
}

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

pub async fn flush_ssl_errors(State(cp): State<AppState>) -> impl IntoResponse {
    match cp.flush_ssl_errors().await {
        Ok(count) => Ok(Json(aria_api::SslErrorFlushResponse { flushed: count })),
        Err(e) => Err(err_response(e)),
    }
}
