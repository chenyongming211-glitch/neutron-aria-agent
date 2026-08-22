use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};

use super::common::{kernel_drop_mode_name, AppState};
use aria_api::HealthResponse;

/// Bounded process/API liveness response. Deliberately does not inspect
/// instances, ACL state, ports, or OVS.
pub async fn liveness() -> StatusCode {
    StatusCode::OK
}

#[utoipa::path(
    get,
    path = "/api/v1/health",
    tag = "health",
    summary = "Get agent health status",
    operation_id = "healthCheck",
    responses(
        (status = 200, description = "Health status and runtime capabilities", body = HealthResponse)
    )
)]
pub async fn health(State(cp): State<AppState>) -> impl IntoResponse {
    let instances = cp.list_instances().await;
    let kernel_drop = cp.get_kernel_drop_status().await;
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        instances: instances.len(),
        wal_replay_failures: aria_core::wal::last_wal_replay_failures(),
        kernel_drop_available: kernel_drop.loaded,
        kernel_drop_mode: Some(kernel_drop_mode_name(kernel_drop.mode).to_string()),
        kernel_drop_managed_ifaces: kernel_drop.managed_ifaces,
        kernel_drop_last_error: kernel_drop.last_error,
    })
}
