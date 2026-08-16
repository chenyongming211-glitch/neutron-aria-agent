use std::collections::HashMap;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};

use super::common::{err_response, AppState};
use crate::control_plane::{
    standalone_policy_family_protocols, ControlPlaneError, LocalWriteDomain,
    StandaloneAclBatchItem, StandaloneAclMutation,
};
use aria_api::*;

fn cleanup_pending_response(
    pending: Vec<crate::control_plane::StandaloneCleanupPending>,
) -> Vec<BitmapCleanupPendingResponse> {
    pending
        .into_iter()
        .map(|pending| BitmapCleanupPendingResponse {
            bitmap_idx: pending.bitmap_idx,
            ports_normalized: pending.ports_normalized,
            error: pending.error,
        })
        .collect()
}

#[utoipa::path(
    get,
    path = "/api/v1/{instance}/policies",
    tag = "policies",
    summary = "List policies for an instance",
    operation_id = "listPolicies",
    params(
        ("instance" = String, Path, description = "Managed instance name")
    ),
    responses(
        (status = 200, description = "Configured policies", body = PoliciesResponse),
        (status = 404, description = "Instance not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError)
    )
)]
pub async fn list_policies(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.list_policies(&instance).await {
        Ok((rules, groups)) => {
            let find_name = |id: u32| -> String {
                if id == 0 {
                    return "any".to_string();
                }
                groups
                    .values()
                    .find(|g| g.id == id)
                    .map(|g| g.name.clone())
                    .unwrap_or_else(|| format!("id:{}", id))
            };
            let policies = rules
                .into_iter()
                .map(|r| PolicyEntry {
                    ethertype: if r.ip_family == 6 {
                        "IPv6".to_string()
                    } else {
                        "IPv4".to_string()
                    },
                    src_group: find_name(r.src_group_id),
                    src_group_id: r.src_group_id,
                    dst_group: find_name(r.dst_group_id),
                    dst_group_id: r.dst_group_id,
                    proto: proto_to_string(r.proto),
                    action: action_to_string(r.action),
                    direction: direction_to_string(r.direction),
                    ports: r.ports,
                    bitmap_idx: r.bitmap_idx,
                })
                .collect();
            Ok(Json(PoliciesResponse { policies }))
        }
        Err(e) => Err(err_response(e)),
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/{instance}/policies",
    tag = "policies",
    summary = "Add a policy",
    operation_id = "addPolicy",
    params(
        ("instance" = String, Path, description = "Managed instance name")
    ),
    request_body = AddPolicyRequest,
    responses(
        (status = 201, description = "Policy created", body = PolicyMutationResponse),
        (status = 202, description = "Policy committed with bitmap cleanup pending", body = PolicyMutationResponse),
        (status = 400, description = "Validation error", body = ApiError),
        (status = 404, description = "Instance or group not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError)
    )
)]
pub async fn add_policy(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
    Json(req): Json<AddPolicyRequest>,
) -> impl IntoResponse {
    if let Err(e) = cp
        .ensure_local_write_allowed(&instance, LocalWriteDomain::Acl)
        .await
    {
        return Err(err_response(e));
    }

    let action = match action_from_string(&req.action) {
        Ok(a) => a,
        Err(e) => return Err(err_response(ControlPlaneError::ValidationError(e))),
    };
    let direction = match direction_from_string(&req.direction) {
        Ok(d) => d,
        Err(e) => return Err(err_response(ControlPlaneError::ValidationError(e))),
    };
    let family_protocols = match standalone_policy_family_protocols(
        req.ethertype.as_deref(),
        &req.proto,
    ) {
        Ok(value) => value,
        Err(error) => return Err(err_response(ControlPlaneError::ValidationError(error))),
    };

    let cleanup_pending = match cp
        .add_policy_family_protocols(
            &instance,
            &req.src_group,
            &req.dst_group,
            action,
            direction,
            req.ports.as_deref(),
            &family_protocols,
        )
        .await
    {
        Ok(cleanup_pending) => cleanup_pending_response(cleanup_pending),
        Err(error) => return Err(err_response(error)),
    };

    let dir_label = if direction == 2 {
        "both"
    } else {
        &req.direction
    };
    let status = if cleanup_pending.is_empty() {
        StatusCode::CREATED
    } else {
        StatusCode::ACCEPTED
    };
    Ok((
        status,
        Json(PolicyMutationResponse {
            message: format!(
                "Added policy: {} -> {} ({})",
                req.src_group, req.dst_group, dir_label
            ),
            committed: true,
            cleanup_pending,
        }),
    ))
}

#[utoipa::path(
    delete,
    path = "/api/v1/{instance}/policies",
    tag = "policies",
    summary = "Delete a policy",
    operation_id = "deletePolicy",
    params(
        ("instance" = String, Path, description = "Managed instance name")
    ),
    request_body = DeletePolicyRequest,
    responses(
        (status = 200, description = "Policy deleted", body = PolicyMutationResponse),
        (status = 202, description = "Policy committed with bitmap cleanup pending", body = PolicyMutationResponse),
        (status = 400, description = "Validation error", body = ApiError),
        (status = 404, description = "Instance or policy not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError)
    )
)]
pub async fn delete_policy(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
    Json(req): Json<DeletePolicyRequest>,
) -> impl IntoResponse {
    if let Err(e) = cp
        .ensure_local_write_allowed(&instance, LocalWriteDomain::Acl)
        .await
    {
        return Err(err_response(e));
    }

    let direction = match direction_from_string(&req.direction) {
        Ok(d) => d,
        Err(e) => return Err(err_response(ControlPlaneError::ValidationError(e))),
    };
    let family_protocols = match standalone_policy_family_protocols(
        req.ethertype.as_deref(),
        &req.proto,
    ) {
        Ok(value) => value,
        Err(error) => return Err(err_response(ControlPlaneError::ValidationError(error))),
    };

    let cleanup_pending = match cp
        .delete_policy_family_protocols(
            &instance,
            &req.src_group,
            &req.dst_group,
            direction,
            &family_protocols,
        )
        .await
    {
        Ok(cleanup_pending) => cleanup_pending_response(cleanup_pending),
        Err(error) => return Err(err_response(error)),
    };

    let dir_label = if direction == 2 {
        "both"
    } else {
        &req.direction
    };
    let status = if cleanup_pending.is_empty() {
        StatusCode::OK
    } else {
        StatusCode::ACCEPTED
    };
    Ok((
        status,
        Json(PolicyMutationResponse {
            message: format!(
                "Deleted policy: {} -> {} ({})",
                req.src_group, req.dst_group, dir_label
            ),
            committed: true,
            cleanup_pending,
        }),
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/{instance}/policies/with_stats",
    tag = "policies",
    summary = "List policies with aggregated statistics",
    operation_id = "listPoliciesWithStats",
    params(
        ("instance" = String, Path, description = "Managed instance name")
    ),
    responses(
        (status = 200, description = "Policies with statistics", body = PoliciesWithStatsResponse),
        (status = 404, description = "Instance not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError)
    )
)]
pub async fn list_policies_with_stats(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.list_policies(&instance).await {
        Ok((rules, groups)) => match cp.get_rule_stats(&instance).await {
            Ok((stats, _stats_groups)) => {
                let find_name = |id: u32| -> String {
                    if id == 0 {
                        return "any".to_string();
                    }
                    groups
                        .values()
                        .find(|g| g.id == id)
                        .map(|g| g.name.clone())
                        .unwrap_or_else(|| format!("id:{}", id))
                };

                let mut stats_map: HashMap<
                    (u32, u32, u8, u8, u8),
                    aria_core::monitoring::RuleStatsEntry,
                > = stats
                    .into_iter()
                    .map(|s| {
                        (
                            (
                                s.key.src_id,
                                s.key.dst_id,
                                s.key.proto,
                                s.key.direction,
                                s.key.ip_family,
                            ),
                            s,
                        )
                    })
                    .collect();

                let policies = rules
                    .into_iter()
                    .map(|r| {
                        let key = (
                            r.src_group_id,
                            r.dst_group_id,
                            r.proto,
                            r.direction,
                            r.ip_family,
                        );
                        let stat = stats_map.remove(&key);
                        PolicyWithStatsEntry {
                            ethertype: if r.ip_family == 6 {
                                "IPv6".to_string()
                            } else {
                                "IPv4".to_string()
                            },
                            src_group: find_name(r.src_group_id),
                            src_group_id: r.src_group_id,
                            dst_group: find_name(r.dst_group_id),
                            dst_group_id: r.dst_group_id,
                            proto: proto_to_string(r.proto),
                            action: action_to_string(r.action),
                            direction: direction_to_string(r.direction),
                            ports: r.ports,
                            bitmap_idx: r.bitmap_idx,
                            packets: stat.as_ref().map(|s| s.packets).unwrap_or(0),
                            bytes: stat.as_ref().map(|s| s.bytes).unwrap_or(0),
                            dropped_packets: stat.as_ref().map(|s| s.dropped_packets).unwrap_or(0),
                            dropped_bytes: stat.as_ref().map(|s| s.dropped_bytes).unwrap_or(0),
                        }
                    })
                    .collect();
                Ok(Json(PoliciesWithStatsResponse { policies }))
            }
            Err(e) => Err(err_response(e)),
        },
        Err(e) => Err(err_response(e)),
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/{instance}/policies/batch",
    tag = "policies",
    summary = "Batch add policies",
    operation_id = "batchAddPolicies",
    params(
        ("instance" = String, Path, description = "Managed instance name")
    ),
    request_body = BatchAddPoliciesRequest,
    responses(
        (status = 201, description = "All policies were created", body = BatchPoliciesResponse),
        (status = 200, description = "Request processed with partial failures", body = BatchPoliciesResponse),
        (status = 202, description = "Accepted policies committed with bitmap cleanup pending", body = BatchPoliciesResponse),
        (status = 404, description = "Instance not found", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError)
    )
)]
pub async fn batch_add_policies(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
    Json(req): Json<BatchAddPoliciesRequest>,
) -> impl IntoResponse {
    if let Err(e) = cp
        .ensure_local_write_allowed(&instance, LocalWriteDomain::Acl)
        .await
    {
        return Err(err_response(e));
    }

    let mut items = Vec::with_capacity(req.policies.len());
    for (request_index, policy) in req.policies.into_iter().enumerate() {
        let action = match action_from_string(&policy.action) {
            Ok(a) => a,
            Err(e) => {
                items.push(StandaloneAclBatchItem::Rejected {
                    request_index,
                    error: e,
                });
                continue;
            }
        };
        let direction = match direction_from_string(&policy.direction) {
            Ok(d) => d,
            Err(e) => {
                items.push(StandaloneAclBatchItem::Rejected {
                    request_index,
                    error: e,
                });
                continue;
            }
        };
        let family_protocols = match standalone_policy_family_protocols(
            policy.ethertype.as_deref(),
            &policy.proto,
        ) {
            Ok(value) => value,
            Err(error) => {
                items.push(StandaloneAclBatchItem::Rejected { request_index, error });
                continue;
            }
        };
        items.push(StandaloneAclBatchItem::Parsed {
            request_index,
            mutation: StandaloneAclMutation::UpsertPolicyFamilyProtocols {
                src_group: policy.src_group,
                dst_group: policy.dst_group,
                action,
                direction,
                ports: policy.ports,
                family_protocols,
            },
        });
    }

    let (added, errors, cleanup_pending) = match cp.batch_add_policies(&instance, items).await {
        Ok(result) => result,
        Err(error) => return Err(err_response(error)),
    };
    let cleanup_pending = cleanup_pending_response(cleanup_pending);

    let status = if !cleanup_pending.is_empty() {
        StatusCode::ACCEPTED
    } else if errors.is_empty() {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((
        status,
        Json(BatchPoliciesResponse {
            added,
            errors,
            committed: true,
            cleanup_pending,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::standalone_policy_family_protocols;
    use aria_core::common::{IP_FAMILY_V4, IP_FAMILY_V6};

    #[test]
    fn standalone_acl_family_aware_protocols_expand_any_and_reject_conflicts() {
        assert_eq!(
            standalone_policy_family_protocols(Some("any"), "icmp").unwrap(),
            vec![(IP_FAMILY_V4, 1), (IP_FAMILY_V6, 58)]
        );
        assert_eq!(
            standalone_policy_family_protocols(Some("IPv4"), "icmp").unwrap(),
            vec![(IP_FAMILY_V4, 1)]
        );
        assert_eq!(
            standalone_policy_family_protocols(Some("IPv6"), "ipv6-icmp").unwrap(),
            vec![(IP_FAMILY_V6, 58)]
        );
        assert_eq!(
            standalone_policy_family_protocols(Some("any"), "tcp").unwrap(),
            vec![(IP_FAMILY_V4, 6), (IP_FAMILY_V6, 6)]
        );
        assert!(standalone_policy_family_protocols(Some("IPv6"), "icmp").is_err());
        assert!(standalone_policy_family_protocols(Some("IPv4"), "icmpv6").is_err());
    }
}
