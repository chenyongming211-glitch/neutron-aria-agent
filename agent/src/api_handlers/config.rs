use axum::{
    Json,
    extract::{Path, State},
    response::IntoResponse,
};

use super::common::{AppState, err_response};
use crate::control_plane::LocalWriteDomain;
use aria_api::{ConfigResponse, MessageResponse, UpdateConfigRequest};

#[utoipa::path(
    get,
    path = "/api/v1/{instance}/config",
    tag = "config",
    summary = "Get instance feature configuration",
    operation_id = "getInstanceConfig",
    params(
        ("instance" = String, Path, description = "Managed instance name")
    ),
    responses(
        (status = 200, description = "Current instance configuration", body = ConfigResponse),
        (status = 404, description = "Instance not found", body = aria_api::ApiError),
        (status = 500, description = "Internal server error", body = aria_api::ApiError)
    )
)]
pub async fn get_config(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.get_config(&instance).await {
        Ok(cfg) => Ok(Json(ConfigResponse {
            conntrack: cfg.conntrack_enabled != 0,
            monitoring: cfg.monitoring_enabled != 0,
            acl: cfg.acl_enabled != 0,
            qos: cfg.qos_enabled != 0,
            mirror: cfg.mirror_enabled != 0,
            tcprt: cfg.tcprt_enabled != 0,
            ssl: cfg.ssl_enabled != 0,
            num_cpus: cfg.num_cpus,
        })),
        Err(e) => Err(err_response(e)),
    }
}

#[utoipa::path(
    put,
    path = "/api/v1/{instance}/config",
    tag = "config",
    summary = "Update instance feature configuration",
    operation_id = "updateInstanceConfig",
    params(
        ("instance" = String, Path, description = "Managed instance name")
    ),
    request_body = UpdateConfigRequest,
    responses(
        (status = 200, description = "Configuration updated", body = MessageResponse),
        (status = 400, description = "Validation error", body = aria_api::ApiError),
        (status = 404, description = "Instance not found", body = aria_api::ApiError),
        (status = 500, description = "Internal server error", body = aria_api::ApiError)
    )
)]
pub async fn update_config(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
    Json(req): Json<UpdateConfigRequest>,
) -> impl IntoResponse {
    if req.conntrack.is_some() {
        if let Err(e) = cp
            .ensure_local_write_allowed(&instance, LocalWriteDomain::Conntrack)
            .await
        {
            return Err(err_response(e));
        }
    }
    if req.monitoring.is_some() {
        if let Err(e) = cp
            .ensure_local_write_allowed(&instance, LocalWriteDomain::Config)
            .await
        {
            return Err(err_response(e));
        }
    }
    if req.acl.is_some() {
        if let Err(e) = cp
            .ensure_local_write_allowed(&instance, LocalWriteDomain::Acl)
            .await
        {
            return Err(err_response(e));
        }
    }
    if req.qos.is_some() {
        if let Err(e) = cp
            .ensure_local_write_allowed(&instance, LocalWriteDomain::Qos)
            .await
        {
            return Err(err_response(e));
        }
    }
    if req.mirror.is_some() {
        if let Err(e) = cp
            .ensure_local_write_allowed(&instance, LocalWriteDomain::Mirror)
            .await
        {
            return Err(err_response(e));
        }
    }
    if req.tcprt.is_some() {
        if let Err(e) = cp
            .ensure_local_write_allowed(&instance, LocalWriteDomain::Tcprt)
            .await
        {
            return Err(err_response(e));
        }
    }
    if req.ssl.is_some() {
        if let Err(e) = cp
            .ensure_local_write_allowed(&instance, LocalWriteDomain::Ssl)
            .await
        {
            return Err(err_response(e));
        }
    }

    match cp
        .update_config(
            &instance,
            req.conntrack,
            req.monitoring,
            req.acl,
            req.qos,
            req.mirror,
            req.tcprt,
            req.ssl,
        )
        .await
    {
        Ok(()) => Ok(Json(MessageResponse {
            message: "Configuration updated".to_string(),
        })),
        Err(e) => Err(err_response(e)),
    }
}
