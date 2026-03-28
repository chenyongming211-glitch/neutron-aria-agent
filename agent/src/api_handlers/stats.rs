use axum::{
    extract::{Path, Query, State},
    response::IntoResponse,
    Json,
};

use super::{
    common::{err_response, AppState},
    TopQuery,
};
use aria_api::{
    direction_to_string, proto_to_string, FlowEntry, FlowStatsResponse, GroupStatsResponse,
    QosStatsResponse, RuleStatsResponse, StatsOverview,
};

pub async fn stats_overview(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.get_stats_overview(&instance).await {
        Ok((groups, policies, qos_rules, mirror_rules, ct_v4, ct_v6)) => Ok(Json(StatsOverview {
            groups,
            policies,
            qos_rules,
            mirror_rules,
            conntrack_v4: ct_v4,
            conntrack_v6: ct_v6,
        })),
        Err(e) => Err(err_response(e)),
    }
}

pub async fn stats_rules(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.get_rule_stats(&instance).await {
        Ok((entries, groups)) => {
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
            Ok(Json(RuleStatsResponse {
                rules: entries
                    .into_iter()
                    .map(|e| aria_api::RuleStatsEntry {
                        src_group: find_name(e.key.src_id),
                        src_id: e.key.src_id,
                        dst_group: find_name(e.key.dst_id),
                        dst_id: e.key.dst_id,
                        proto: proto_to_string(e.key.proto),
                        direction: direction_to_string(e.key.direction),
                        packets: e.packets,
                        bytes: e.bytes,
                        dropped_packets: e.dropped_packets,
                        dropped_bytes: e.dropped_bytes,
                    })
                    .collect(),
            }))
        }
        Err(e) => Err(err_response(e)),
    }
}

pub async fn stats_flows(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
    Query(query): Query<TopQuery>,
) -> impl IntoResponse {
    match cp.get_top_flows(&instance, query.top).await {
        Ok((v4, v6)) => {
            let mut flows: Vec<FlowEntry> = Vec::new();
            for e in v4 {
                flows.push(FlowEntry {
                    src_ip: e.src_ip.to_string(),
                    dst_ip: e.dst_ip.to_string(),
                    src_port: e.src_port,
                    dst_port: e.dst_port,
                    proto: proto_to_string(e.proto),
                    packets: e.packets,
                    bytes: e.bytes,
                });
            }
            for e in v6 {
                flows.push(FlowEntry {
                    src_ip: e.src_ip.to_string(),
                    dst_ip: e.dst_ip.to_string(),
                    src_port: e.src_port,
                    dst_port: e.dst_port,
                    proto: proto_to_string(e.proto),
                    packets: e.packets,
                    bytes: e.bytes,
                });
            }
            Ok(Json(FlowStatsResponse { flows }))
        }
        Err(e) => Err(err_response(e)),
    }
}

pub async fn stats_qos(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.get_qos_stats(&instance).await {
        Ok((entries, groups)) => {
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
            Ok(Json(QosStatsResponse {
                rules: entries
                    .into_iter()
                    .map(|e| aria_api::QosStatsEntry {
                        group: find_name(e.key.group_id),
                        group_id: e.key.group_id,
                        direction: direction_to_string(e.key.direction),
                        passed_packets: e.passed_packets,
                        passed_bytes: e.passed_bytes,
                        dropped_packets: e.dropped_packets,
                        dropped_bytes: e.dropped_bytes,
                        shaped_packets: e.shaped_packets,
                        shaped_bytes: e.shaped_bytes,
                    })
                    .collect(),
            }))
        }
        Err(e) => Err(err_response(e)),
    }
}

pub async fn stats_groups(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.get_group_stats(&instance).await {
        Ok((entries, groups)) => {
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
            Ok(Json(GroupStatsResponse {
                groups: entries
                    .into_iter()
                    .map(|e| aria_api::GroupStatsEntry {
                        group: find_name(e.key.group_id),
                        group_id: e.key.group_id,
                        direction: direction_to_string(e.key.direction),
                        packets: e.packets,
                        bytes: e.bytes,
                    })
                    .collect(),
            }))
        }
        Err(e) => Err(err_response(e)),
    }
}
