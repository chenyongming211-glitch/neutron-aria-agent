use std::sync::Arc;
#[allow(unused_imports)]
use axum::{
    Router,
    routing::{get, post, put, delete},
};

use crate::control_plane::ControlPlane;
use crate::api_handlers;

pub fn build_router(control_plane: Arc<ControlPlane>) -> Router {
    Router::new()
        // Health & instances
        .route("/api/v1/health", get(api_handlers::health))
        .route("/api/v1/instances", get(api_handlers::list_instances))
        // System start/stop
        .route("/api/v1/system/start", post(api_handlers::system_start))
        .route("/api/v1/system/stop", post(api_handlers::system_stop))
        // Per-instance routes
        .route("/api/v1/{instance}/groups", get(api_handlers::list_groups).post(api_handlers::add_group))
        .route("/api/v1/{instance}/groups/{name}", delete(api_handlers::delete_group))
        .route("/api/v1/{instance}/policies", get(api_handlers::list_policies).post(api_handlers::add_policy).delete(api_handlers::delete_policy))
        .route("/api/v1/{instance}/policies/batch", post(api_handlers::batch_add_policies))
        .route("/api/v1/{instance}/qos", get(api_handlers::list_qos).post(api_handlers::add_qos).delete(api_handlers::delete_qos))
        .route("/api/v1/{instance}/conntrack", get(api_handlers::list_conntrack).delete(api_handlers::flush_conntrack))
        .route("/api/v1/{instance}/config", get(api_handlers::get_config).put(api_handlers::update_config))
        .route("/api/v1/{instance}/stats", get(api_handlers::stats_overview))
        .route("/api/v1/{instance}/stats/rules", get(api_handlers::stats_rules))
        .route("/api/v1/{instance}/stats/flows", get(api_handlers::stats_flows))
        .route("/api/v1/{instance}/stats/qos", get(api_handlers::stats_qos))
        .route("/api/v1/{instance}/stats/groups", get(api_handlers::stats_groups))
        .with_state(control_plane)
}
