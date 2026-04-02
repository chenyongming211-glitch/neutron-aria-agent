use utoipa::OpenApi;

#[derive(OpenApi)]
#[openapi(
    paths(
        crate::api_handlers::health::health,
        crate::api_handlers::system::list_instances,
        crate::api_handlers::system::system_start,
        crate::api_handlers::system::system_stop,
        crate::api_handlers::groups::list_groups,
        crate::api_handlers::groups::add_group,
        crate::api_handlers::groups::delete_group,
        crate::api_handlers::groups::list_groups_with_stats,
        crate::api_handlers::policies::list_policies,
        crate::api_handlers::policies::add_policy,
        crate::api_handlers::policies::delete_policy,
        crate::api_handlers::policies::list_policies_with_stats,
        crate::api_handlers::policies::batch_add_policies,
        crate::api_handlers::qos::list_qos,
        crate::api_handlers::qos::add_qos,
        crate::api_handlers::qos::delete_qos,
        crate::api_handlers::qos::list_qos_with_stats
    ),
    components(
        schemas(
            aria_api::ApiError,
            aria_api::HealthResponse,
            aria_api::InstanceInfo,
            aria_api::InstancesResponse,
            aria_api::SystemStartRequest,
            aria_api::MessageResponse,
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
            aria_api::QosEntry,
            aria_api::QosListResponse,
            aria_api::AddQosRequest,
            aria_api::DeleteQosRequest,
            aria_api::QosWithStatsEntry,
            aria_api::QosWithStatsResponse
        )
    ),
    tags(
        (name = "health", description = "Health and runtime capability endpoints"),
        (name = "system", description = "System firewall lifecycle and instance discovery"),
        (name = "groups", description = "CIDR group management"),
        (name = "policies", description = "ACL policy management"),
        (name = "qos", description = "QoS rule management")
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
        assert!(doc.pointer("/paths/~1api~1v1~1{instance}~1groups").is_some());
        assert!(doc.pointer("/paths/~1api~1v1~1{instance}~1policies").is_some());
        assert!(doc.pointer("/paths/~1api~1v1~1{instance}~1qos").is_some());

        assert!(doc.pointer("/components/schemas/ApiError").is_some());
        assert!(doc.pointer("/components/schemas/HealthResponse").is_some());
        assert!(doc.pointer("/components/schemas/BatchAddPoliciesRequest").is_some());
        assert!(doc.pointer("/components/schemas/AddQosRequest").is_some());
    }
}
