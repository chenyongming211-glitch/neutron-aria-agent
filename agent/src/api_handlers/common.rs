use std::sync::Arc;

use axum::{
    http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::IntoResponse,
    Json,
};

use crate::control_plane::{ControlPlane, ControlPlaneError};
use crate::kernel_drop_manager::KernelDropMode;
use aria_api::ApiError;
use aria_core::ebpf_ops::TraceMapMode;

pub(crate) type AppState = Arc<ControlPlane>;

pub(crate) fn err_response(e: ControlPlaneError) -> impl IntoResponse {
    let code = e.status_code();
    let status = StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (
        status,
        Json(ApiError {
            code,
            error: e.to_string(),
        }),
    )
}

pub(crate) fn legacy_drop_headers(instance: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        HeaderName::from_static("deprecation"),
        HeaderValue::from_static("true"),
    );
    headers.insert(
        HeaderName::from_static("sunset"),
        HeaderValue::from_static("Tue, 30 Jun 2026 00:00:00 GMT"),
    );
    if let Ok(value) = HeaderValue::from_str(&format!(
        "</api/v1/stats/kernel_drops?instance={}>; rel=\"successor-version\"",
        instance
    )) {
        headers.insert(header::LINK, value);
    }
    headers
}

pub(crate) fn kernel_drop_mode_name(mode: KernelDropMode) -> &'static str {
    match mode {
        KernelDropMode::Disabled => "disabled",
        KernelDropMode::ScaffoldOnly => "scaffold_only",
        KernelDropMode::KfreeSkbLegacy => "kfree_skb_legacy",
        KernelDropMode::KfreeSkbReasonful => "kfree_skb_reasonful",
    }
}

pub(crate) fn trace_map_mode_name(mode: TraceMapMode) -> &'static str {
    match mode {
        TraceMapMode::Legacy => "legacy",
        TraceMapMode::Stream => "stream",
    }
}
