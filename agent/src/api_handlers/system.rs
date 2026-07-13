use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};

use super::common::AppState;
use aria_api::{ApiError, InstanceInfo, InstancesResponse, MessageResponse, SystemStartRequest};

#[utoipa::path(
    get,
    path = "/api/v1/instances",
    tag = "system",
    summary = "List managed instances",
    operation_id = "listInstances",
    responses(
        (status = 200, description = "Currently managed firewall instances", body = InstancesResponse)
    )
)]
pub async fn list_instances(State(cp): State<AppState>) -> impl IntoResponse {
    let snapshots = cp.list_instance_runtime_health().await;
    Json(InstancesResponse {
        instances: snapshots
            .into_iter()
            .map(|snapshot| InstanceInfo {
                name: snapshot.name,
                active: snapshot.active,
                acl_ready: snapshot.acl_ready,
                xdp_ready: snapshot.xdp_ready,
                readiness_reason: snapshot.readiness_reason,
            })
            .collect(),
    })
}

#[utoipa::path(
    post,
    path = "/api/v1/system/start",
    tag = "system",
    summary = "Start the standalone system firewall",
    operation_id = "startSystemFirewall",
    request_body = SystemStartRequest,
    responses(
        (status = 200, description = "System firewall started", body = MessageResponse),
        (status = 500, description = "System start failed", body = ApiError)
    )
)]
pub async fn system_start(
    State(cp): State<AppState>,
    Json(req): Json<SystemStartRequest>,
) -> impl IntoResponse {
    let pin_path = format!("{}/system", cp.base_pin_path);
    let state_path = format!("{}/system", cp.base_state_path);

    match crate::system_manager::system_start(
        &req.iface,
        &cp.ebpf_path,
        &pin_path,
        &state_path,
        req.max_port_policies,
        cp.clone(),
    )
    .await
    {
        Ok(()) => (
            StatusCode::OK,
            Json(MessageResponse {
                message: format!("System firewall started on {}", req.iface),
            }),
        )
            .into_response(),
        Err(e) => {
            let status = StatusCode::INTERNAL_SERVER_ERROR;
            (
                status,
                Json(ApiError {
                    code: 500,
                    error: e,
                }),
            )
                .into_response()
        }
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/system/stop",
    tag = "system",
    summary = "Stop the standalone system firewall",
    operation_id = "stopSystemFirewall",
    responses(
        (status = 200, description = "System firewall stopped", body = MessageResponse),
        (status = 500, description = "System stop failed", body = ApiError)
    )
)]
pub async fn system_stop(State(cp): State<AppState>) -> impl IntoResponse {
    let pin_path = format!("{}/system", cp.base_pin_path);
    let state_path = format!("{}/system", cp.base_state_path);

    match crate::system_manager::system_stop(&pin_path, &state_path, cp.clone()).await {
        Ok(()) => (
            StatusCode::OK,
            Json(MessageResponse {
                message: "System firewall stopped".to_string(),
            }),
        )
            .into_response(),
        Err(e) => {
            let status = StatusCode::INTERNAL_SERVER_ERROR;
            (
                status,
                Json(ApiError {
                    code: 500,
                    error: e,
                }),
            )
                .into_response()
        }
    }
}
