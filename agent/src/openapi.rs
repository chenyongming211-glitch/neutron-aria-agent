use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::api_handlers::health::health,
        crate::api_handlers::system::list_instances,
        crate::api_handlers::system::system_start,
        crate::api_handlers::system::system_stop,
        crate::api_handlers::chains::list_chains,
        crate::api_handlers::chains::create_chain,
        crate::api_handlers::chains::get_chain,
        crate::api_handlers::chains::delete_chain,
        crate::api_handlers::config::get_config,
        crate::api_handlers::config::update_config,
        crate::api_handlers::conntrack::list_conntrack,
        crate::api_handlers::conntrack::flush_conntrack,
        crate::api_handlers::drops::list_drops,
        crate::api_handlers::drops::flush_drops,
        crate::api_handlers::drops::list_kernel_drops,
        crate::api_handlers::drops::flush_kernel_drops,
        crate::api_handlers::groups::list_groups,
        crate::api_handlers::groups::add_group,
        crate::api_handlers::groups::delete_group,
        crate::api_handlers::groups::list_groups_with_stats,
        crate::api_handlers::mirror::list_mirror,
        crate::api_handlers::mirror::add_mirror,
        crate::api_handlers::mirror::delete_mirror,
        crate::api_handlers::mirror::stats_mirror,
        crate::api_handlers::mirror::list_mirror_with_stats,
        crate::api_handlers::policies::list_policies,
        crate::api_handlers::policies::add_policy,
        crate::api_handlers::policies::delete_policy,
        crate::api_handlers::policies::list_policies_with_stats,
        crate::api_handlers::policies::batch_add_policies,
        crate::api_handlers::qos::list_qos,
        crate::api_handlers::qos::add_qos,
        crate::api_handlers::qos::delete_qos,
        crate::api_handlers::qos::list_qos_with_stats,
        crate::api_handlers::ssl::list_ssl_global,
        crate::api_handlers::ssl::flush_ssl_global,
        crate::api_handlers::ssl::list_ssl,
        crate::api_handlers::ssl::flush_ssl,
        crate::api_handlers::ssl::list_ssl_http_global,
        crate::api_handlers::ssl::flush_ssl_http_global,
        crate::api_handlers::ssl::list_ssl_http,
        crate::api_handlers::ssl::flush_ssl_http,
        crate::api_handlers::ssl::get_ssl_config,
        crate::api_handlers::ssl::update_ssl_config,
        crate::api_handlers::ssl::list_ssl_errors,
        crate::api_handlers::ssl::flush_ssl_errors,
        crate::api_handlers::stats::stats_overview,
        crate::api_handlers::stats::stats_rules,
        crate::api_handlers::stats::stats_flows,
        crate::api_handlers::stats::stats_qos,
        crate::api_handlers::stats::stats_groups,
        crate::api_handlers::tcprt::list_tcprt,
        crate::api_handlers::tcprt::flush_tcprt,
        crate::api_handlers::tcprt::batch_query_tcprt,
        crate::api_handlers::tcprt::filter_tcprt,
        crate::api_handlers::tcprt::tcprt_histogram,
        crate::api_handlers::tcprt::tcprt_states,
        crate::api_handlers::trace::start_trace,
        crate::api_handlers::trace::stop_trace,
        crate::api_handlers::trace::list_trace,
        crate::api_handlers::trace::flush_trace
    ),
    components(
        schemas(
            aria_api::ApiError,
            aria_api::HealthResponse,
            aria_api::InstanceInfo,
            aria_api::InstancesResponse,
            aria_api::SystemStartRequest,
            aria_api::MessageResponse,
            aria_api::BitmapCleanupPendingResponse,
            aria_api::PolicyMutationResponse,
            aria_api::GroupEntry,
            aria_api::GroupsResponse,
            aria_api::AddGroupRequest,
            aria_api::AddGroupResponse,
            aria_api::GroupWithStatsEntry,
            aria_api::GroupsWithStatsResponse,
            aria_api::PolicyEntry,
            aria_api::PoliciesResponse,
            aria_api::AddPolicyRequest,
            aria_api::DeletePolicyRequest,
            aria_api::BatchAddPoliciesRequest,
            aria_api::BatchPoliciesResponse,
            aria_api::PolicyWithStatsEntry,
            aria_api::PoliciesWithStatsResponse,
            aria_api::ConntrackEntry,
            aria_api::ConntrackResponse,
            aria_api::ConntrackFlushResponse,
            aria_api::ConfigResponse,
            aria_api::UpdateConfigRequest,
            aria_api::QosEntry,
            aria_api::QosListResponse,
            aria_api::AddQosRequest,
            aria_api::DeleteQosRequest,
            aria_api::StatsOverview,
            aria_api::RuleStatsEntry,
            aria_api::RuleStatsResponse,
            aria_api::FlowEntry,
            aria_api::FlowStatsResponse,
            aria_api::QosStatsEntry,
            aria_api::QosStatsResponse,
            aria_api::QosWithStatsEntry,
            aria_api::QosWithStatsResponse,
            aria_api::GroupStatsEntry,
            aria_api::GroupStatsResponse,
            aria_api::MirrorEntry,
            aria_api::MirrorListResponse,
            aria_api::AddMirrorRequest,
            aria_api::DeleteMirrorRequest,
            aria_api::MirrorStatsEntry,
            aria_api::MirrorStatsResponse,
            aria_api::MirrorWithStatsEntry,
            aria_api::MirrorWithStatsResponse,
            aria_api::TcpRtEntry,
            aria_api::TcpRtResponse,
            aria_api::TcpRtFlushResponse,
            aria_api::TcpRtQueryTuple,
            aria_api::TcpRtBatchQueryRequest,
            aria_api::TcpRtInstanceEntry,
            aria_api::TcpRtBatchQueryResponse,
            aria_api::TcpRtFilterRequest,
            aria_api::TcpRtAggregatedEntry,
            aria_api::TcpRtFilterResponse,
            aria_api::TcpRtHistogramBucket,
            aria_api::TcpRtHistogramResponse,
            aria_api::TcpRtStateCount,
            aria_api::TcpRtStatesResponse,
            aria_api::TapBindingEntry,
            aria_api::ServiceHopEntry,
            aria_api::ServiceChainEntry,
            aria_api::ServiceChainListResponse,
            aria_api::CreateServiceChainRequest,
            aria_api::DropStatsEntry,
            aria_api::DropStatsResponse,
            aria_api::DropFlushResponse,
            aria_api::KernelDropQuery,
            aria_api::KernelDropStatsEntry,
            aria_api::KernelDropStatsResponse,
            aria_api::KernelDropFlushResponse,
            aria_api::TraceStartRequest,
            aria_api::TraceEventEntry,
            aria_api::TraceResponse,
            aria_api::TraceFlushResponse,
            aria_api::SslConnEntry,
            aria_api::SslListResponse,
            aria_api::SslFlushResponse,
            aria_api::SslHttpEntry,
            aria_api::SslHttpListResponse,
            aria_api::SslHttpFlushResponse,
            aria_api::SslGlobalConfigResponse,
            aria_api::UpdateSslGlobalConfigRequest,
            aria_api::SslErrorEntry,
            aria_api::SslErrorListResponse,
            aria_api::SslErrorFlushResponse
        )
    ),
    tags(
        (name = "health", description = "Health and runtime capability endpoints"),
        (name = "system", description = "System firewall lifecycle and instance discovery"),
        (name = "chains", description = "Service chain management"),
        (name = "config", description = "Per-instance feature configuration"),
        (name = "conntrack", description = "Conntrack observability"),
        (name = "drops", description = "Drop observability endpoints"),
        (name = "groups", description = "CIDR group management"),
        (name = "mirror", description = "Traffic mirroring rules and statistics"),
        (name = "policies", description = "ACL policy management"),
        (name = "qos", description = "QoS rule management"),
        (name = "ssl", description = "SSL and HTTPS observability"),
        (name = "stats", description = "Per-instance statistics"),
        (name = "tcprt", description = "TCP round-trip observability"),
        (name = "trace", description = "Packet tracing controls and events")
    )
)]
pub struct ApiDoc;

#[cfg(test)]
mod tests {
    use super::ApiDoc;
    use utoipa::OpenApi;

    #[test]
    fn openapi_contains_core_paths_and_components() {
        let doc = serde_json::to_value(ApiDoc::openapi()).expect("openapi should serialize");

        assert!(doc.pointer("/paths/~1api~1v1~1health").is_some());
        assert!(doc.pointer("/paths/~1api~1v1~1instances").is_some());
        assert!(doc.pointer("/paths/~1api~1v1~1system~1start").is_some());
        assert!(doc.pointer("/paths/~1api~1v1~1chains").is_some());
        assert!(doc.pointer("/paths/~1api~1v1~1chains~1{name}").is_some());
        assert!(doc
            .pointer("/paths/~1api~1v1~1{instance}~1config")
            .is_some());
        assert!(doc
            .pointer("/paths/~1api~1v1~1{instance}~1conntrack")
            .is_some());
        assert!(doc
            .pointer("/paths/~1api~1v1~1{instance}~1groups")
            .is_some());
        assert!(doc
            .pointer("/paths/~1api~1v1~1{instance}~1mirror")
            .is_some());
        assert!(doc
            .pointer("/paths/~1api~1v1~1{instance}~1policies")
            .is_some());
        assert!(doc.pointer("/paths/~1api~1v1~1{instance}~1qos").is_some());
        assert!(doc.pointer("/paths/~1api~1v1~1{instance}~1stats").is_some());
        assert!(doc.pointer("/paths/~1api~1v1~1{instance}~1tcprt").is_some());
        assert!(doc.pointer("/paths/~1api~1v1~1tcprt~1query").is_some());
        assert!(doc.pointer("/paths/~1api~1v1~1ssl").is_some());
        assert!(doc.pointer("/paths/~1api~1v1~1ssl~1config").is_some());
        assert!(doc.pointer("/paths/~1api~1v1~1{instance}~1trace").is_some());
        assert!(doc
            .pointer("/paths/~1api~1v1~1stats~1kernel_drops")
            .is_some());

        assert!(doc.pointer("/components/schemas/ApiError").is_some());
        assert!(doc.pointer("/components/schemas/HealthResponse").is_some());
        assert!(doc
            .pointer("/components/schemas/BatchAddPoliciesRequest")
            .is_some());
        assert!(doc.pointer("/components/schemas/AddQosRequest").is_some());
        assert!(doc
            .pointer("/components/schemas/AddMirrorRequest")
            .is_some());
        assert!(doc
            .pointer("/components/schemas/TcpRtBatchQueryRequest")
            .is_some());
        assert!(doc
            .pointer("/components/schemas/TraceStartRequest")
            .is_some());
        assert!(doc
            .pointer("/components/schemas/SslGlobalConfigResponse")
            .is_some());

        assert_eq!(
            doc.pointer("/paths/~1api~1v1~1health/get/operationId")
                .and_then(|value| value.as_str()),
            Some("healthCheck")
        );
        assert_eq!(
            doc.pointer("/paths/~1api~1v1~1{instance}~1policies/get/operationId")
                .and_then(|value| value.as_str()),
            Some("listPolicies")
        );
        assert_eq!(
            doc.pointer("/paths/~1api~1v1~1tcprt~1query/post/operationId")
                .and_then(|value| value.as_str()),
            Some("batchQueryTcpRt")
        );
        assert_eq!(
            doc.pointer("/paths/~1api~1v1~1ssl~1config/put/operationId")
                .and_then(|value| value.as_str()),
            Some("updateGlobalSslConfig")
        );

        assert_eq!(
            doc.pointer("/components/schemas/SystemStartRequest/example/iface")
                .and_then(|value| value.as_str()),
            Some("eth0")
        );
        assert_eq!(
            doc.pointer("/components/schemas/AddPolicyRequest/example/src_group")
                .and_then(|value| value.as_str()),
            Some("web")
        );
        assert_eq!(
            doc.pointer("/components/schemas/AddQosRequest/properties/rate/description")
                .and_then(|value| value.as_str()),
            Some("Human-readable rate value such as `100mbit` or `10gbit`.")
        );
        assert_eq!(
            doc.pointer(
                "/components/schemas/KernelDropQuery/properties/include_unattributed/description"
            )
            .and_then(|value| value.as_str()),
            Some("Include drop entries that could not be mapped back to a managed instance.")
        );
    }

    #[test]
    fn openapi_does_not_expose_neutron_uds_paths() {
        let doc = serde_json::to_value(ApiDoc::openapi()).expect("openapi should serialize");

        assert!(doc
            .pointer("/paths/~1api~1v1~1neutron~1capabilities")
            .is_none());
        assert!(doc.pointer("/paths/~1api~1v1~1neutron~1status").is_none());
        assert!(doc.pointer("/paths/~1api~1v1~1neutron~1snapshot").is_none());
        assert!(doc
            .pointer("/paths/~1api~1v1~1neutron~1ports~1{port_id}~1snapshot")
            .is_none());
        assert!(doc
            .pointer("/paths/~1api~1v1~1neutron~1ports~1{port_id}")
            .is_none());
    }
}
