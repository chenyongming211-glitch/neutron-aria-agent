#[allow(unused_imports)]
use axum::{
    extract::{Request, State},
    http::Method,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, post, put},
    Router,
};
use std::sync::Arc;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::api_handlers;
use crate::control_plane::ControlPlane;
use crate::neutron_maintenance::{MaintenanceCoordinator, MaintenanceWriter};

pub(crate) fn is_maintenance_mutation_method(method: &Method) -> bool {
    method == Method::POST
        || method == Method::PUT
        || method == Method::PATCH
        || method == Method::DELETE
}

async fn maintenance_writer_fence(
    State(maintenance): State<Arc<MaintenanceCoordinator>>,
    request: Request,
    next: Next,
) -> Response {
    if !is_maintenance_mutation_method(request.method()) {
        return next.run(request).await;
    }
    let lease = match maintenance
        .acquire_writer(MaintenanceWriter::Direct, None)
        .await
    {
        Ok(lease) => lease,
        Err(error) => {
            return (
                axum::http::StatusCode::CONFLICT,
                axum::Json(serde_json::json!({
                    "error": error.code,
                    "details": error.details,
                })),
            )
                .into_response();
        }
    };
    let response = next.run(request).await;
    drop(lease);
    response
}

pub fn build_router(
    control_plane: Arc<ControlPlane>,
    maintenance: Arc<MaintenanceCoordinator>,
) -> Router {
    Router::new()
        .merge(SwaggerUi::new("/docs").url("/openapi.json", crate::openapi::ApiDoc::openapi()))
        // Health & instances
        .route("/metrics", get(api_handlers::metrics))
        .route("/api/v1/health", get(api_handlers::health))
        .route("/api/v1/instances", get(api_handlers::list_instances))
        // System start/stop
        .route("/api/v1/system/start", post(api_handlers::system_start))
        .route("/api/v1/system/stop", post(api_handlers::system_stop))
        // Batch query (no instance path param)
        .route("/api/v1/tcprt/query", post(api_handlers::batch_query_tcprt))
        // TCP-RT filter by service address (no instance path param)
        .route("/api/v1/tcprt/filter", post(api_handlers::filter_tcprt))
        // Service chains (no instance path param)
        .route(
            "/api/v1/chains",
            get(api_handlers::list_chains).post(api_handlers::create_chain),
        )
        .route(
            "/api/v1/chains/{name}",
            get(api_handlers::get_chain).delete(api_handlers::delete_chain),
        )
        // Global SSL observability config (no instance path param)
        .route(
            "/api/v1/ssl",
            get(api_handlers::list_ssl_global).delete(api_handlers::flush_ssl_global),
        )
        .route(
            "/api/v1/ssl/http",
            get(api_handlers::list_ssl_http_global).delete(api_handlers::flush_ssl_http_global),
        )
        .route(
            "/api/v1/ssl/config",
            get(api_handlers::get_ssl_config).put(api_handlers::update_ssl_config),
        )
        .route(
            "/api/v1/ssl/errors",
            get(api_handlers::list_ssl_errors).delete(api_handlers::flush_ssl_errors),
        )
        .route(
            "/api/v1/stats/kernel_drops",
            get(api_handlers::list_kernel_drops).delete(api_handlers::flush_kernel_drops),
        )
        // Per-instance routes
        .route(
            "/api/v1/{instance}/groups",
            get(api_handlers::list_groups).post(api_handlers::add_group),
        )
        .route(
            "/api/v1/{instance}/groups/{name}",
            delete(api_handlers::delete_group),
        )
        .route(
            "/api/v1/{instance}/groups/with_stats",
            get(api_handlers::list_groups_with_stats),
        )
        .route(
            "/api/v1/{instance}/policies",
            get(api_handlers::list_policies)
                .post(api_handlers::add_policy)
                .delete(api_handlers::delete_policy),
        )
        .route(
            "/api/v1/{instance}/policies/batch",
            post(api_handlers::batch_add_policies),
        )
        .route(
            "/api/v1/{instance}/policies/with_stats",
            get(api_handlers::list_policies_with_stats),
        )
        .route(
            "/api/v1/{instance}/qos",
            get(api_handlers::list_qos)
                .post(api_handlers::add_qos)
                .delete(api_handlers::delete_qos),
        )
        .route(
            "/api/v1/{instance}/qos/with_stats",
            get(api_handlers::list_qos_with_stats),
        )
        .route(
            "/api/v1/{instance}/mirror",
            get(api_handlers::list_mirror)
                .post(api_handlers::add_mirror)
                .delete(api_handlers::delete_mirror),
        )
        .route(
            "/api/v1/{instance}/mirror/with_stats",
            get(api_handlers::list_mirror_with_stats),
        )
        .route(
            "/api/v1/{instance}/conntrack",
            get(api_handlers::list_conntrack).delete(api_handlers::flush_conntrack),
        )
        .route(
            "/api/v1/{instance}/config",
            get(api_handlers::get_config).put(api_handlers::update_config),
        )
        .route(
            "/api/v1/{instance}/stats",
            get(api_handlers::stats_overview),
        )
        .route(
            "/api/v1/{instance}/stats/rules",
            get(api_handlers::stats_rules),
        )
        .route(
            "/api/v1/{instance}/stats/flows",
            get(api_handlers::stats_flows),
        )
        .route("/api/v1/{instance}/stats/qos", get(api_handlers::stats_qos))
        .route(
            "/api/v1/{instance}/stats/groups",
            get(api_handlers::stats_groups),
        )
        .route(
            "/api/v1/{instance}/stats/mirror",
            get(api_handlers::stats_mirror),
        )
        .route(
            "/api/v1/{instance}/tcprt",
            get(api_handlers::list_tcprt).delete(api_handlers::flush_tcprt),
        )
        .route(
            "/api/v1/{instance}/tcprt/histogram",
            get(api_handlers::tcprt_histogram),
        )
        .route(
            "/api/v1/{instance}/tcprt/states",
            get(api_handlers::tcprt_states),
        )
        .route(
            "/api/v1/{instance}/ssl",
            get(api_handlers::list_ssl).delete(api_handlers::flush_ssl),
        )
        .route(
            "/api/v1/{instance}/ssl/http",
            get(api_handlers::list_ssl_http).delete(api_handlers::flush_ssl_http),
        )
        .route(
            "/api/v1/{instance}/stats/drops",
            get(api_handlers::list_drops).delete(api_handlers::flush_drops),
        )
        .route(
            "/api/v1/{instance}/trace",
            get(api_handlers::list_trace)
                .post(api_handlers::start_trace)
                .delete(api_handlers::stop_trace),
        )
        .route(
            "/api/v1/{instance}/trace/flush",
            delete(api_handlers::flush_trace),
        )
        .with_state(control_plane)
        .route_layer(middleware::from_fn_with_state(
            maintenance,
            maintenance_writer_fence,
        ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Method;

    #[test]
    fn neutron_maintenance_tcp_mutation_methods_are_exhaustively_classified() {
        for method in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
            assert!(is_maintenance_mutation_method(&method));
        }
        for method in [Method::GET, Method::HEAD, Method::OPTIONS] {
            assert!(!is_maintenance_mutation_method(&method));
        }
    }
}
