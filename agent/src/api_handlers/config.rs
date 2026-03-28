use axum::{
    extract::{Path, State},
    response::IntoResponse,
    Json,
};

use super::common::{err_response, AppState};
use aria_api::{ConfigResponse, MessageResponse, UpdateConfigRequest};

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

pub async fn update_config(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
    Json(req): Json<UpdateConfigRequest>,
) -> impl IntoResponse {
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
