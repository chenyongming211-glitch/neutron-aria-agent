use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};

use super::common::AppState;
use aria_api::{ApiError, InstanceInfo, InstancesResponse, MessageResponse, SystemStartRequest};

pub async fn list_instances(State(cp): State<AppState>) -> impl IntoResponse {
    let names = cp.list_instances().await;
    Json(InstancesResponse {
        instances: names
            .into_iter()
            .map(|name| InstanceInfo { name, active: true })
            .collect(),
    })
}

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
