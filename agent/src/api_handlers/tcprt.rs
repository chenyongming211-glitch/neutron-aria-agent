use std::cmp::Ordering;

use axum::{
    extract::{Path, Query, State},
    response::IntoResponse,
    Json,
};

use super::{
    common::{err_response, AppState},
    TopQuery,
};

fn map_tcprt_entry(e: aria_core::tcprt_ops::TcpRtEntry) -> aria_api::TcpRtEntry {
    aria_api::TcpRtEntry {
        src_ip: e.src_ip,
        dst_ip: e.dst_ip,
        src_port: e.src_port,
        dst_port: e.dst_port,
        handshake_us: e.handshake_us,
        rtt_client_us: e.rtt_client_us,
        rtt_server_us: e.rtt_server_us,
        art_us: e.art_us,
        retrans_req: e.retrans_req,
        retrans_resp: e.retrans_resp,
        request_count: e.request_count,
        state: e.state,
        forward_platform_us: e.forward_platform_us,
        server_network_us: e.server_network_us,
        reverse_platform_us: e.reverse_platform_us,
        fin_us: e.fin_us,
        rst_us: e.rst_us,
        close_us: e.close_us,
        nqa_score: e.nqa_score,
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/{instance}/tcprt",
    tag = "tcprt",
    summary = "List TCP-RT flow records for an instance",
    operation_id = "listTcpRtFlows",
    params(
        ("instance" = String, Path, description = "Managed instance name"),
        ("top" = Option<usize>, Query, description = "Maximum number of TCP-RT flows to return")
    ),
    responses(
        (status = 200, description = "TCP-RT flow records", body = aria_api::TcpRtResponse),
        (status = 404, description = "Instance not found", body = aria_api::ApiError),
        (status = 500, description = "Internal server error", body = aria_api::ApiError)
    )
)]
pub async fn list_tcprt(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
    Query(query): Query<TopQuery>,
) -> impl IntoResponse {
    match cp.list_tcprt(&instance, query.top).await {
        Ok(entries) => {
            let flows = entries.into_iter().map(map_tcprt_entry).collect();
            Ok(Json(aria_api::TcpRtResponse { flows }))
        }
        Err(e) => Err(err_response(e)),
    }
}

#[utoipa::path(
    delete,
    path = "/api/v1/{instance}/tcprt",
    tag = "tcprt",
    summary = "Flush TCP-RT flow records for an instance",
    operation_id = "flushTcpRtFlows",
    params(
        ("instance" = String, Path, description = "Managed instance name")
    ),
    responses(
        (status = 200, description = "Flushed TCP-RT record count", body = aria_api::TcpRtFlushResponse),
        (status = 404, description = "Instance not found", body = aria_api::ApiError),
        (status = 500, description = "Internal server error", body = aria_api::ApiError)
    )
)]
pub async fn flush_tcprt(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.flush_tcprt(&instance).await {
        Ok(count) => Ok(Json(aria_api::TcpRtFlushResponse { flushed: count })),
        Err(e) => Err(err_response(e)),
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/tcprt/query",
    tag = "tcprt",
    summary = "Batch query TCP-RT tuples across instances",
    operation_id = "batchQueryTcpRt",
    request_body = aria_api::TcpRtBatchQueryRequest,
    responses(
        (status = 200, description = "TCP-RT entries matched across instances", body = aria_api::TcpRtBatchQueryResponse),
        (status = 400, description = "Validation error", body = aria_api::ApiError),
        (status = 500, description = "Internal server error", body = aria_api::ApiError)
    )
)]
pub async fn batch_query_tcprt(
    State(cp): State<AppState>,
    Json(req): Json<aria_api::TcpRtBatchQueryRequest>,
) -> impl IntoResponse {
    let tuples: Vec<(String, String, u16, u16)> = req
        .tuples
        .into_iter()
        .map(|t| (t.src_ip, t.dst_ip, t.src_port, t.dst_port))
        .collect();
    match cp.batch_query_tcprt(&tuples).await {
        Ok(entries) => {
            let results = entries
                .into_iter()
                .map(|(instance, e)| aria_api::TcpRtInstanceEntry {
                    instance,
                    entry: map_tcprt_entry(e),
                })
                .collect();
            Ok(Json(aria_api::TcpRtBatchQueryResponse { results }))
        }
        Err(e) => Err(err_response(e)),
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/tcprt/filter",
    tag = "tcprt",
    summary = "Aggregate TCP-RT metrics by service address",
    operation_id = "filterTcpRtByService",
    request_body = aria_api::TcpRtFilterRequest,
    responses(
        (status = 200, description = "Aggregated TCP-RT metrics by instance", body = aria_api::TcpRtFilterResponse),
        (status = 400, description = "Validation error", body = aria_api::ApiError),
        (status = 500, description = "Internal server error", body = aria_api::ApiError)
    )
)]
pub async fn filter_tcprt(
    State(cp): State<AppState>,
    Json(req): Json<aria_api::TcpRtFilterRequest>,
) -> impl IntoResponse {
    match cp.filter_tcprt(&req.dst_ip, req.dst_port).await {
        Ok(instance_entries) => {
            let instances: Vec<aria_api::TcpRtAggregatedEntry> = instance_entries
                .into_iter()
                .map(|(name, entries)| {
                    let count = entries.len() as u32;
                    let fc = count as f64;
                    aria_api::TcpRtAggregatedEntry {
                        instance: name,
                        flow_count: count,
                        avg_rtt_client_us: entries.iter().map(|e| e.rtt_client_us).sum::<f64>()
                            / fc,
                        avg_rtt_server_us: entries.iter().map(|e| e.rtt_server_us).sum::<f64>()
                            / fc,
                        avg_art_us: entries.iter().map(|e| e.art_us).sum::<f64>() / fc,
                        avg_handshake_us: entries.iter().map(|e| e.handshake_us).sum::<f64>() / fc,
                        total_retrans_req: entries.iter().map(|e| e.retrans_req).sum(),
                        total_retrans_resp: entries.iter().map(|e| e.retrans_resp).sum(),
                        avg_forward_platform_us: entries
                            .iter()
                            .map(|e| e.forward_platform_us)
                            .sum::<f64>()
                            / fc,
                        avg_server_network_us: entries
                            .iter()
                            .map(|e| e.server_network_us)
                            .sum::<f64>()
                            / fc,
                        avg_reverse_platform_us: entries
                            .iter()
                            .map(|e| e.reverse_platform_us)
                            .sum::<f64>()
                            / fc,
                        avg_nqa_score: entries.iter().map(|e| e.nqa_score as f64).sum::<f64>() / fc,
                    }
                })
                .collect();
            Ok(Json(aria_api::TcpRtFilterResponse {
                dst_ip: req.dst_ip,
                dst_port: req.dst_port,
                instances,
            }))
        }
        Err(e) => Err(err_response(e)),
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/{instance}/tcprt/histogram",
    tag = "tcprt",
    summary = "Get TCP-RT ART histogram for an instance",
    operation_id = "getTcpRtHistogram",
    params(
        ("instance" = String, Path, description = "Managed instance name")
    ),
    responses(
        (status = 200, description = "TCP-RT ART histogram", body = aria_api::TcpRtHistogramResponse),
        (status = 404, description = "Instance not found", body = aria_api::ApiError),
        (status = 500, description = "Internal server error", body = aria_api::ApiError)
    )
)]
pub async fn tcprt_histogram(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.list_tcprt(&instance, 100000).await {
        Ok(entries) => {
            let bucket_boundaries: Vec<f64> = vec![
                1_000.0,
                5_000.0,
                10_000.0,
                50_000.0,
                100_000.0,
                500_000.0,
                1_000_000.0,
                5_000_000.0,
                10_000_000.0,
            ];
            let mut counts = vec![0u64; bucket_boundaries.len()];
            let mut total = 0u64;
            let mut sum_us = 0.0f64;
            let mut art_values: Vec<f64> = Vec::new();

            for e in &entries {
                if e.art_us > 0.0 {
                    total += 1;
                    sum_us += e.art_us;
                    art_values.push(e.art_us);
                    for (i, &boundary) in bucket_boundaries.iter().enumerate() {
                        if e.art_us <= boundary {
                            counts[i] += 1;
                        }
                    }
                }
            }

            art_values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
            let percentile = |p: f64| -> f64 {
                if art_values.is_empty() {
                    return 0.0;
                }
                let idx = ((p / 100.0) * art_values.len() as f64).ceil() as usize;
                art_values[idx.min(art_values.len()).saturating_sub(1)]
            };

            let buckets = bucket_boundaries
                .iter()
                .enumerate()
                .map(|(i, &le_us)| aria_api::TcpRtHistogramBucket {
                    le_us,
                    count: counts[i],
                })
                .collect();

            Ok(Json(aria_api::TcpRtHistogramResponse {
                buckets,
                total,
                sum_us,
                p50_us: percentile(50.0),
                p95_us: percentile(95.0),
                p99_us: percentile(99.0),
            }))
        }
        Err(e) => Err(err_response(e)),
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/{instance}/tcprt/states",
    tag = "tcprt",
    summary = "Get TCP-RT state distribution for an instance",
    operation_id = "getTcpRtStates",
    params(
        ("instance" = String, Path, description = "Managed instance name")
    ),
    responses(
        (status = 200, description = "TCP-RT state distribution", body = aria_api::TcpRtStatesResponse),
        (status = 404, description = "Instance not found", body = aria_api::ApiError),
        (status = 500, description = "Internal server error", body = aria_api::ApiError)
    )
)]
pub async fn tcprt_states(
    State(cp): State<AppState>,
    Path(instance): Path<String>,
) -> impl IntoResponse {
    match cp.list_tcprt(&instance, 100000).await {
        Ok(entries) => {
            let mut state_counts: Vec<(String, u64)> = Vec::new();
            let total_flows = entries.len() as u64;

            for e in &entries {
                if let Some(sc) = state_counts.iter_mut().find(|(s, _)| s == &e.state) {
                    sc.1 += 1;
                } else {
                    state_counts.push((e.state.clone(), 1));
                }
            }

            let mut anomalies: Vec<String> = Vec::new();
            if total_flows > 0 {
                for (state, count) in &state_counts {
                    let pct = *count as f64 / total_flows as f64 * 100.0;
                    if state == "close_wait" && pct > 10.0 {
                        anomalies.push(format!(
                            "CLOSE_WAIT is {:.1}% (>10%) - possible connection leak",
                            pct
                        ));
                    }
                    if state == "rst" && pct > 20.0 {
                        anomalies.push(format!(
                            "RST is {:.1}% (>20%) - possible network issue",
                            pct
                        ));
                    }
                }
            }

            let states = state_counts
                .into_iter()
                .map(|(state, count)| aria_api::TcpRtStateCount { state, count })
                .collect();

            Ok(Json(aria_api::TcpRtStatesResponse {
                states,
                total_flows,
                anomalies,
            }))
        }
        Err(e) => Err(err_response(e)),
    }
}
