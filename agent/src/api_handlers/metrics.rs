use std::fmt::Write;

use async_stream::stream;
use axum::{
    body::Body,
    extract::State,
    http::{StatusCode, header},
    response::IntoResponse,
};
use bytes::Bytes;
use tracing::warn;

use super::common::{AppState, kernel_drop_mode_name, trace_map_mode_name};
use aria_api::*;

const METRICS_CHUNK_SIZE: usize = 16 * 1024;
const LATENCY_BUCKET_LABELS: [&str; 9] = [
    "0.001", "0.005", "0.01", "0.05", "0.1", "0.5", "1", "5", "10",
];

fn prom_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn ct_contract_hook_to_string(hook: u8) -> &'static str {
    match hook {
        aria_core::common::CT_CONTRACT_HOOK_TC_INGRESS => "tc_ingress",
        _ => "unknown",
    }
}

fn ct_contract_family_to_string(family: u8) -> &'static str {
    match family {
        aria_core::common::CT_CONTRACT_FAMILY_IPV4 => "ipv4",
        aria_core::common::CT_CONTRACT_FAMILY_IPV6 => "ipv6",
        _ => "unknown",
    }
}

fn ct_contract_reason_to_string(reason: u8) -> &'static str {
    match reason {
        aria_core::common::CT_CONTRACT_REASON_CT_MISS => "ct_miss",
        aria_core::common::CT_CONTRACT_REASON_CT_DISABLED => "ct_disabled",
        _ => "unknown",
    }
}

fn flush_metrics_chunk(buf: &mut String, force: bool) -> Option<Bytes> {
    if buf.is_empty() || (!force && buf.len() < METRICS_CHUNK_SIZE) {
        return None;
    }

    let chunk = Bytes::copy_from_slice(buf.as_bytes());
    buf.clear();
    Some(chunk)
}

fn write_latency_histogram(
    out: &mut String,
    metric_name: &str,
    instance: &str,
    bucket_counts: &[u64; 9],
    sum_seconds: f64,
    count: u64,
) {
    for (idx, le) in LATENCY_BUCKET_LABELS.iter().enumerate() {
        let _ = writeln!(
            out,
            "{metric_name}_bucket{{instance=\"{instance}\",le=\"{le}\"}} {}",
            bucket_counts[idx]
        );
    }
    let _ = writeln!(
        out,
        "{metric_name}_bucket{{instance=\"{instance}\",le=\"+Inf\"}} {count}"
    );
    let _ = writeln!(
        out,
        "{metric_name}_sum{{instance=\"{instance}\"}} {sum_seconds}"
    );
    let _ = writeln!(
        out,
        "{metric_name}_count{{instance=\"{instance}\"}} {count}"
    );
}

fn write_tcprt_summary_metrics(
    out: &mut String,
    instance: &str,
    summary: &aria_core::monitoring::TcprtMetricsSummary,
) {
    let _ = writeln!(
        out,
        "aria_tcprt_flows_total{{instance=\"{instance}\"}} {}",
        summary.flows
    );
    let _ = writeln!(
        out,
        "aria_tcprt_retrans_req_total{{instance=\"{instance}\"}} {}",
        summary.retrans_req
    );
    let _ = writeln!(
        out,
        "aria_tcprt_retrans_resp_total{{instance=\"{instance}\"}} {}",
        summary.retrans_resp
    );
    let _ = writeln!(
        out,
        "aria_tcprt_requests_total{{instance=\"{instance}\"}} {}",
        summary.requests
    );
    let _ = writeln!(
        out,
        "aria_tcprt_handshake_us_sum{{instance=\"{instance}\"}} {}",
        summary.handshake_sum_us
    );
    let _ = writeln!(
        out,
        "aria_tcprt_art_us_sum{{instance=\"{instance}\"}} {}",
        summary.art_sum_us
    );
    let _ = writeln!(
        out,
        "aria_tcprt_rtt_client_us_sum{{instance=\"{instance}\"}} {}",
        summary.rtt_client_sum_us
    );
    let _ = writeln!(
        out,
        "aria_tcprt_rtt_server_us_sum{{instance=\"{instance}\"}} {}",
        summary.rtt_server_sum_us
    );
    write_latency_histogram(
        out,
        "aria_tcprt_art_seconds",
        instance,
        &summary.art_bucket_counts,
        summary.art_sum_seconds,
        summary.art_count,
    );
    let avg_nqa = if summary.flows > 0 {
        summary.nqa_sum / summary.flows as f64
    } else {
        0.0
    };
    let _ = writeln!(
        out,
        "aria_tcprt_nqa_score_avg{{instance=\"{instance}\"}} {avg_nqa:.1}"
    );
}

fn write_ssl_summary_metrics(
    out: &mut String,
    instance: &str,
    summary: &aria_core::ssl_ops::SslMetricsSummary,
) {
    let _ = writeln!(
        out,
        "aria_ssl_handshakes_total{{instance=\"{instance}\"}} {}",
        summary.total
    );
    write_latency_histogram(
        out,
        "aria_ssl_handshake_seconds",
        instance,
        &summary.bucket_counts,
        summary.sum_seconds,
        summary.count,
    );
}

fn write_ssl_http_summary_metrics(
    out: &mut String,
    instance: &str,
    summary: &aria_core::ssl_ops::SslHttpMetricsSummary,
) {
    let _ = writeln!(
        out,
        "aria_ssl_http_requests_total{{instance=\"{instance}\"}} {}",
        summary.total
    );
    write_latency_histogram(
        out,
        "aria_ssl_http_latency_seconds",
        instance,
        &summary.bucket_counts,
        summary.sum_seconds,
        summary.count,
    );
    let _ = writeln!(
        out,
        "aria_ssl_http_status_2xx_total{{instance=\"{instance}\"}} {}",
        summary.status_2xx
    );
    let _ = writeln!(
        out,
        "aria_ssl_http_status_4xx_total{{instance=\"{instance}\"}} {}",
        summary.status_4xx
    );
    let _ = writeln!(
        out,
        "aria_ssl_http_status_5xx_total{{instance=\"{instance}\"}} {}",
        summary.status_5xx
    );
}

pub async fn metrics(State(cp): State<AppState>) -> impl IntoResponse {
    let instances = cp.list_instances().await;
    let kernel_drop = cp.get_kernel_drop_status().await;
    let trace_backend = prom_escape(cp.trace_backend_name());
    let trace_mode = prom_escape(trace_map_mode_name(cp.trace_map_mode()));
    let mut trace_runtime: Vec<_> = cp.get_trace_runtime_status().await.into_iter().collect();
    trace_runtime.sort_by(|a, b| a.0.cmp(&b.0));

    let stream = stream! {
        let mut out = String::with_capacity(METRICS_CHUNK_SIZE * 2);

        let _ = writeln!(out, "# HELP aria_kernel_drop_observability_up Whether kernel drop observability is available");
        let _ = writeln!(out, "# TYPE aria_kernel_drop_observability_up gauge");
        let _ = writeln!(out, "# HELP aria_kernel_drop_managed_ifaces Number of interfaces tracked by kernel drop observability");
        let _ = writeln!(out, "# TYPE aria_kernel_drop_managed_ifaces gauge");
        let _ = writeln!(out, "# HELP aria_kernel_drop_mode_info Kernel drop observability mode");
        let _ = writeln!(out, "# TYPE aria_kernel_drop_mode_info gauge");
        let _ = writeln!(out, "# HELP aria_kernel_drop_last_error Kernel drop observability last error indicator");
        let _ = writeln!(out, "# TYPE aria_kernel_drop_last_error gauge");
        let mode = prom_escape(kernel_drop_mode_name(kernel_drop.mode));
        let _ = writeln!(
            out,
            "aria_kernel_drop_observability_up {}",
            if kernel_drop.loaded { 1 } else { 0 }
        );
        let _ = writeln!(
            out,
            "aria_kernel_drop_managed_ifaces {}",
            kernel_drop.managed_ifaces
        );
        let _ = writeln!(
            out,
            "aria_kernel_drop_mode_info{{mode=\"{mode}\"}} 1"
        );
        let _ = writeln!(
            out,
            "aria_kernel_drop_last_error {}",
            if kernel_drop.last_error.is_some() { 1 } else { 0 }
        );
        if let Some(chunk) = flush_metrics_chunk(&mut out, true) {
            yield Ok::<_, std::convert::Infallible>(chunk);
        }

        let _ = writeln!(out, "# HELP aria_kernel_drop_packets_total Kernel drop packets by reason");
        let _ = writeln!(out, "# TYPE aria_kernel_drop_packets_total counter");
        let _ = writeln!(out, "# HELP aria_kernel_drop_bytes_total Kernel drop bytes by reason");
        let _ = writeln!(out, "# TYPE aria_kernel_drop_bytes_total counter");

        if kernel_drop.loaded {
            match cp.get_kernel_drop_stats(&KernelDropQuery {
                include_unattributed: true,
                ..Default::default()
            }).await {
                Ok(entries) => {
                    for entry in &entries {
                        let instance = prom_escape(entry.instance.as_deref().unwrap_or(""));
                        let iface = prom_escape(entry.iface.as_deref().unwrap_or(""));
                        let reason = prom_escape(&entry.reason);
                        let proto = prom_escape(&entry.proto);
                        let source = prom_escape(&entry.source);
                        let _ = writeln!(
                            out,
                            "aria_kernel_drop_packets_total{{instance=\"{instance}\",iface=\"{iface}\",ifindex=\"{}\",reason=\"{reason}\",proto=\"{proto}\",source=\"{source}\"}} {}",
                            entry.ifindex,
                            entry.packets
                        );
                        let _ = writeln!(
                            out,
                            "aria_kernel_drop_bytes_total{{instance=\"{instance}\",iface=\"{iface}\",ifindex=\"{}\",reason=\"{reason}\",proto=\"{proto}\",source=\"{source}\"}} {}",
                            entry.ifindex,
                            entry.bytes
                        );
                        if let Some(chunk) = flush_metrics_chunk(&mut out, false) {
                            yield Ok::<_, std::convert::Infallible>(chunk);
                        }
                    }
                }
                Err(e) => warn!("Failed to collect kernel drop metrics: {}", e),
            }
        }
        if let Some(chunk) = flush_metrics_chunk(&mut out, true) {
            yield Ok::<_, std::convert::Infallible>(chunk);
        }

        let _ = writeln!(out, "# HELP aria_trace_backend_info Trace backend selection");
        let _ = writeln!(out, "# TYPE aria_trace_backend_info gauge");
        let _ = writeln!(out, "# HELP aria_trace_runtime_registered_taps Number of taps registered to each trace runtime");
        let _ = writeln!(out, "# TYPE aria_trace_runtime_registered_taps gauge");
        let _ = writeln!(out, "# HELP aria_trace_runtime_active_consumers Number of active userspace stream consumers per runtime");
        let _ = writeln!(out, "# TYPE aria_trace_runtime_active_consumers gauge");
        let _ = writeln!(out, "# HELP aria_trace_runtime_lost_events_total Trace stream events reported lost by the backend");
        let _ = writeln!(out, "# TYPE aria_trace_runtime_lost_events_total counter");
        let _ = writeln!(out, "# HELP aria_trace_runtime_cache_evictions_total Trace stream events evicted from the userspace cache");
        let _ = writeln!(out, "# TYPE aria_trace_runtime_cache_evictions_total counter");
        let _ = writeln!(out, "# HELP aria_trace_runtime_consumer_failures_total Trace stream consumer failures");
        let _ = writeln!(out, "# TYPE aria_trace_runtime_consumer_failures_total counter");
        let _ = writeln!(out, "# HELP aria_trace_runtime_consumer_restarts_total Trace stream consumer restarts");
        let _ = writeln!(out, "# TYPE aria_trace_runtime_consumer_restarts_total counter");
        let _ = writeln!(out, "# HELP aria_trace_runtime_last_error Whether the trace runtime has a recorded last error");
        let _ = writeln!(out, "# TYPE aria_trace_runtime_last_error gauge");
        let _ = writeln!(
            out,
            "aria_trace_backend_info{{backend=\"{trace_backend}\",mode=\"{trace_mode}\"}} 1"
        );

        for (pin_path, status) in &trace_runtime {
            let pin_path = prom_escape(pin_path);
            let _ = writeln!(
                out,
                "aria_trace_runtime_registered_taps{{pin_path=\"{pin_path}\"}} {}",
                status.registered_taps
            );
            let _ = writeln!(
                out,
                "aria_trace_runtime_active_consumers{{pin_path=\"{pin_path}\"}} {}",
                status.active_consumers
            );
            let _ = writeln!(
                out,
                "aria_trace_runtime_lost_events_total{{pin_path=\"{pin_path}\"}} {}",
                status.lost_events
            );
            let _ = writeln!(
                out,
                "aria_trace_runtime_cache_evictions_total{{pin_path=\"{pin_path}\"}} {}",
                status.cache_evictions
            );
            let _ = writeln!(
                out,
                "aria_trace_runtime_consumer_failures_total{{pin_path=\"{pin_path}\"}} {}",
                status.consumer_failures
            );
            let _ = writeln!(
                out,
                "aria_trace_runtime_consumer_restarts_total{{pin_path=\"{pin_path}\"}} {}",
                status.consumer_restarts
            );
            let _ = writeln!(
                out,
                "aria_trace_runtime_last_error{{pin_path=\"{pin_path}\"}} {}",
                if status.last_error.is_some() { 1 } else { 0 }
            );
            if let Some(chunk) = flush_metrics_chunk(&mut out, false) {
                yield Ok::<_, std::convert::Infallible>(chunk);
            }
        }
        if let Some(chunk) = flush_metrics_chunk(&mut out, true) {
            yield Ok::<_, std::convert::Infallible>(chunk);
        }

        let _ = writeln!(out, "# HELP aria_groups_total Number of IP groups configured");
        let _ = writeln!(out, "# TYPE aria_groups_total gauge");
        let _ = writeln!(out, "# HELP aria_policies_total Number of ACL policies configured");
        let _ = writeln!(out, "# TYPE aria_policies_total gauge");
        let _ = writeln!(out, "# HELP aria_qos_rules_total Number of QoS rules configured");
        let _ = writeln!(out, "# TYPE aria_qos_rules_total gauge");
        let _ = writeln!(out, "# HELP aria_mirror_rules_total Number of mirror rules configured");
        let _ = writeln!(out, "# TYPE aria_mirror_rules_total gauge");
        let _ = writeln!(out, "# HELP aria_conntrack_total Number of conntrack entries");
        let _ = writeln!(out, "# TYPE aria_conntrack_total gauge");

        for inst in &instances {
            let i = prom_escape(inst);
            if let Ok((groups, policies, qos_rules, mirror_rules, ct_v4, ct_v6)) =
                cp.get_stats_overview(inst).await
            {
                let _ = writeln!(out, "aria_groups_total{{instance=\"{i}\"}} {groups}");
                let _ = writeln!(out, "aria_policies_total{{instance=\"{i}\"}} {policies}");
                let _ = writeln!(out, "aria_qos_rules_total{{instance=\"{i}\"}} {qos_rules}");
                let _ = writeln!(out, "aria_mirror_rules_total{{instance=\"{i}\"}} {mirror_rules}");
                let _ = writeln!(out, "aria_conntrack_total{{instance=\"{i}\",family=\"ipv4\"}} {ct_v4}");
                let _ = writeln!(out, "aria_conntrack_total{{instance=\"{i}\",family=\"ipv6\"}} {ct_v6}");
            }
            if let Some(chunk) = flush_metrics_chunk(&mut out, false) {
                yield Ok::<_, std::convert::Infallible>(chunk);
            }
        }
        if let Some(chunk) = flush_metrics_chunk(&mut out, true) {
            yield Ok::<_, std::convert::Infallible>(chunk);
        }

        let _ = writeln!(out, "# HELP aria_ct_contract_packets_total Packets handled through conntrack-contract fallback");
        let _ = writeln!(out, "# TYPE aria_ct_contract_packets_total counter");
        let _ = writeln!(out, "# HELP aria_ct_contract_bytes_total Bytes handled through conntrack-contract fallback");
        let _ = writeln!(out, "# TYPE aria_ct_contract_bytes_total counter");

        for inst in &instances {
            let i = prom_escape(inst);
            if let Ok(entries) = cp.get_ct_contract_stats(inst).await {
                for e in &entries {
                    let hook = prom_escape(ct_contract_hook_to_string(e.hook));
                    let family = prom_escape(ct_contract_family_to_string(e.family));
                    let reason = prom_escape(ct_contract_reason_to_string(e.reason));
                    let _ = writeln!(out, "aria_ct_contract_packets_total{{instance=\"{i}\",hook=\"{hook}\",family=\"{family}\",reason=\"{reason}\"}} {}", e.packets);
                    let _ = writeln!(out, "aria_ct_contract_bytes_total{{instance=\"{i}\",hook=\"{hook}\",family=\"{family}\",reason=\"{reason}\"}} {}", e.bytes);
                    if let Some(chunk) = flush_metrics_chunk(&mut out, false) {
                        yield Ok::<_, std::convert::Infallible>(chunk);
                    }
                }
            }
        }
        if let Some(chunk) = flush_metrics_chunk(&mut out, true) {
            yield Ok::<_, std::convert::Infallible>(chunk);
        }

        let _ = writeln!(out, "# HELP aria_drop_packets_total Dropped packets by reason");
        let _ = writeln!(out, "# TYPE aria_drop_packets_total counter");
        let _ = writeln!(out, "# HELP aria_drop_bytes_total Dropped bytes by reason");
        let _ = writeln!(out, "# TYPE aria_drop_bytes_total counter");

        for inst in &instances {
            let i = prom_escape(inst);
            if let Ok((entries, groups)) = cp.get_drop_stats(inst).await {
                let find_name = |id: u32| -> String {
                    if id == 0 {
                        return "any".to_string();
                    }
                    groups.values().find(|g| g.id == id).map(|g| g.name.clone()).unwrap_or_else(|| format!("id:{}", id))
                };
                for e in &entries {
                    let reason = prom_escape(&aria_core::trace_ops::drop_reason_name(e.reason));
                    let dir = prom_escape(&direction_to_string(e.direction));
                    let proto = prom_escape(&proto_to_string(e.proto));
                    let sg = prom_escape(&find_name(e.src_id));
                    let dg = prom_escape(&find_name(e.dst_id));
                    let _ = writeln!(out, "aria_drop_packets_total{{instance=\"{i}\",reason=\"{reason}\",direction=\"{dir}\",proto=\"{proto}\",src_group=\"{sg}\",dst_group=\"{dg}\"}} {}", e.packets);
                    let _ = writeln!(out, "aria_drop_bytes_total{{instance=\"{i}\",reason=\"{reason}\",direction=\"{dir}\",proto=\"{proto}\",src_group=\"{sg}\",dst_group=\"{dg}\"}} {}", e.bytes);
                    if let Some(chunk) = flush_metrics_chunk(&mut out, false) {
                        yield Ok::<_, std::convert::Infallible>(chunk);
                    }
                }
            }
        }
        if let Some(chunk) = flush_metrics_chunk(&mut out, true) {
            yield Ok::<_, std::convert::Infallible>(chunk);
        }

        let _ = writeln!(out, "# HELP aria_rule_packets_total ACL rule matched packets");
        let _ = writeln!(out, "# TYPE aria_rule_packets_total counter");
        let _ = writeln!(out, "# HELP aria_rule_bytes_total ACL rule matched bytes");
        let _ = writeln!(out, "# TYPE aria_rule_bytes_total counter");
        let _ = writeln!(out, "# HELP aria_rule_dropped_packets_total ACL rule dropped packets");
        let _ = writeln!(out, "# TYPE aria_rule_dropped_packets_total counter");
        let _ = writeln!(out, "# HELP aria_rule_dropped_bytes_total ACL rule dropped bytes");
        let _ = writeln!(out, "# TYPE aria_rule_dropped_bytes_total counter");

        for inst in &instances {
            let i = prom_escape(inst);
            if let Ok((entries, groups)) = cp.get_rule_stats(inst).await {
                let find_name = |id: u32| -> String {
                    if id == 0 {
                        return "any".to_string();
                    }
                    groups.values().find(|g| g.id == id).map(|g| g.name.clone()).unwrap_or_else(|| format!("id:{}", id))
                };
                for e in &entries {
                    let sg = prom_escape(&find_name(e.key.src_id));
                    let dg = prom_escape(&find_name(e.key.dst_id));
                    let proto = prom_escape(&proto_to_string(e.key.proto));
                    let dir = prom_escape(&direction_to_string(e.key.direction));
                    let _ = writeln!(out, "aria_rule_packets_total{{instance=\"{i}\",src_group=\"{sg}\",dst_group=\"{dg}\",proto=\"{proto}\",direction=\"{dir}\"}} {}", e.packets);
                    let _ = writeln!(out, "aria_rule_bytes_total{{instance=\"{i}\",src_group=\"{sg}\",dst_group=\"{dg}\",proto=\"{proto}\",direction=\"{dir}\"}} {}", e.bytes);
                    let _ = writeln!(out, "aria_rule_dropped_packets_total{{instance=\"{i}\",src_group=\"{sg}\",dst_group=\"{dg}\",proto=\"{proto}\",direction=\"{dir}\"}} {}", e.dropped_packets);
                    let _ = writeln!(out, "aria_rule_dropped_bytes_total{{instance=\"{i}\",src_group=\"{sg}\",dst_group=\"{dg}\",proto=\"{proto}\",direction=\"{dir}\"}} {}", e.dropped_bytes);
                    if let Some(chunk) = flush_metrics_chunk(&mut out, false) {
                        yield Ok::<_, std::convert::Infallible>(chunk);
                    }
                }
            }
        }
        if let Some(chunk) = flush_metrics_chunk(&mut out, true) {
            yield Ok::<_, std::convert::Infallible>(chunk);
        }

        let _ = writeln!(out, "# HELP aria_qos_passed_packets_total QoS passed packets");
        let _ = writeln!(out, "# TYPE aria_qos_passed_packets_total counter");
        let _ = writeln!(out, "# HELP aria_qos_passed_bytes_total QoS passed bytes");
        let _ = writeln!(out, "# TYPE aria_qos_passed_bytes_total counter");
        let _ = writeln!(out, "# HELP aria_qos_dropped_packets_total QoS dropped packets");
        let _ = writeln!(out, "# TYPE aria_qos_dropped_packets_total counter");
        let _ = writeln!(out, "# HELP aria_qos_dropped_bytes_total QoS dropped bytes");
        let _ = writeln!(out, "# TYPE aria_qos_dropped_bytes_total counter");
        let _ = writeln!(out, "# HELP aria_qos_shaped_packets_total QoS shaped packets");
        let _ = writeln!(out, "# TYPE aria_qos_shaped_packets_total counter");
        let _ = writeln!(out, "# HELP aria_qos_shaped_bytes_total QoS shaped bytes");
        let _ = writeln!(out, "# TYPE aria_qos_shaped_bytes_total counter");

        for inst in &instances {
            let i = prom_escape(inst);
            if let Ok((entries, groups)) = cp.get_qos_stats(inst).await {
                let find_name = |id: u32| -> String {
                    if id == 0 {
                        return "any".to_string();
                    }
                    groups.values().find(|g| g.id == id).map(|g| g.name.clone()).unwrap_or_else(|| format!("id:{}", id))
                };
                for e in &entries {
                    let g = prom_escape(&find_name(e.key.group_id));
                    let dir = prom_escape(&direction_to_string(e.key.direction));
                    let _ = writeln!(out, "aria_qos_passed_packets_total{{instance=\"{i}\",group=\"{g}\",direction=\"{dir}\"}} {}", e.passed_packets);
                    let _ = writeln!(out, "aria_qos_passed_bytes_total{{instance=\"{i}\",group=\"{g}\",direction=\"{dir}\"}} {}", e.passed_bytes);
                    let _ = writeln!(out, "aria_qos_dropped_packets_total{{instance=\"{i}\",group=\"{g}\",direction=\"{dir}\"}} {}", e.dropped_packets);
                    let _ = writeln!(out, "aria_qos_dropped_bytes_total{{instance=\"{i}\",group=\"{g}\",direction=\"{dir}\"}} {}", e.dropped_bytes);
                    let _ = writeln!(out, "aria_qos_shaped_packets_total{{instance=\"{i}\",group=\"{g}\",direction=\"{dir}\"}} {}", e.shaped_packets);
                    let _ = writeln!(out, "aria_qos_shaped_bytes_total{{instance=\"{i}\",group=\"{g}\",direction=\"{dir}\"}} {}", e.shaped_bytes);
                    if let Some(chunk) = flush_metrics_chunk(&mut out, false) {
                        yield Ok::<_, std::convert::Infallible>(chunk);
                    }
                }
            }
        }
        if let Some(chunk) = flush_metrics_chunk(&mut out, true) {
            yield Ok::<_, std::convert::Infallible>(chunk);
        }

        let _ = writeln!(out, "# HELP aria_group_packets_total Group traffic packets");
        let _ = writeln!(out, "# TYPE aria_group_packets_total counter");
        let _ = writeln!(out, "# HELP aria_group_bytes_total Group traffic bytes");
        let _ = writeln!(out, "# TYPE aria_group_bytes_total counter");

        for inst in &instances {
            let i = prom_escape(inst);
            if let Ok((entries, groups)) = cp.get_group_stats(inst).await {
                let find_name = |id: u32| -> String {
                    if id == 0 {
                        return "any".to_string();
                    }
                    groups.values().find(|g| g.id == id).map(|g| g.name.clone()).unwrap_or_else(|| format!("id:{}", id))
                };
                for e in &entries {
                    let g = prom_escape(&find_name(e.key.group_id));
                    let dir = prom_escape(&direction_to_string(e.key.direction));
                    let _ = writeln!(out, "aria_group_packets_total{{instance=\"{i}\",group=\"{g}\",direction=\"{dir}\"}} {}", e.packets);
                    let _ = writeln!(out, "aria_group_bytes_total{{instance=\"{i}\",group=\"{g}\",direction=\"{dir}\"}} {}", e.bytes);
                    if let Some(chunk) = flush_metrics_chunk(&mut out, false) {
                        yield Ok::<_, std::convert::Infallible>(chunk);
                    }
                }
            }
        }
        if let Some(chunk) = flush_metrics_chunk(&mut out, true) {
            yield Ok::<_, std::convert::Infallible>(chunk);
        }

        let _ = writeln!(out, "# HELP aria_mirror_packets_total Mirrored packets");
        let _ = writeln!(out, "# TYPE aria_mirror_packets_total counter");
        let _ = writeln!(out, "# HELP aria_mirror_bytes_total Mirrored bytes");
        let _ = writeln!(out, "# TYPE aria_mirror_bytes_total counter");
        let _ = writeln!(out, "# HELP aria_mirror_errors_total Mirror errors");
        let _ = writeln!(out, "# TYPE aria_mirror_errors_total counter");

        for inst in &instances {
            let i = prom_escape(inst);
            if let Ok((entries, groups)) = cp.get_mirror_stats(inst).await {
                let find_name = |id: u32| -> String {
                    if id == 0 {
                        return "any".to_string();
                    }
                    groups.values().find(|g| g.id == id).map(|g| g.name.clone()).unwrap_or_else(|| format!("id:{}", id))
                };
                for e in &entries {
                    let sg = prom_escape(&find_name(e.src_id));
                    let dg = prom_escape(&find_name(e.dst_id));
                    let proto = prom_escape(&proto_to_string(e.proto));
                    let dir = prom_escape(&direction_to_string(e.direction));
                    let _ = writeln!(out, "aria_mirror_packets_total{{instance=\"{i}\",src_group=\"{sg}\",dst_group=\"{dg}\",proto=\"{proto}\",direction=\"{dir}\"}} {}", e.mirrored_packets);
                    let _ = writeln!(out, "aria_mirror_bytes_total{{instance=\"{i}\",src_group=\"{sg}\",dst_group=\"{dg}\",proto=\"{proto}\",direction=\"{dir}\"}} {}", e.mirrored_bytes);
                    let _ = writeln!(out, "aria_mirror_errors_total{{instance=\"{i}\",src_group=\"{sg}\",dst_group=\"{dg}\",proto=\"{proto}\",direction=\"{dir}\"}} {}", e.errors);
                    if let Some(chunk) = flush_metrics_chunk(&mut out, false) {
                        yield Ok::<_, std::convert::Infallible>(chunk);
                    }
                }
            }
        }
        if let Some(chunk) = flush_metrics_chunk(&mut out, true) {
            yield Ok::<_, std::convert::Infallible>(chunk);
        }

        let _ = writeln!(out, "# HELP aria_tcprt_flows_total Number of retained TCP-RT flows");
        let _ = writeln!(out, "# TYPE aria_tcprt_flows_total gauge");
        let _ = writeln!(out, "# HELP aria_tcprt_retrans_req_total Total request retransmissions");
        let _ = writeln!(out, "# TYPE aria_tcprt_retrans_req_total counter");
        let _ = writeln!(out, "# HELP aria_tcprt_retrans_resp_total Total response retransmissions");
        let _ = writeln!(out, "# TYPE aria_tcprt_retrans_resp_total counter");
        let _ = writeln!(out, "# HELP aria_tcprt_requests_total Total request count");
        let _ = writeln!(out, "# TYPE aria_tcprt_requests_total counter");
        let _ = writeln!(out, "# HELP aria_tcprt_handshake_us_sum Sum of handshake latency in microseconds");
        let _ = writeln!(out, "# TYPE aria_tcprt_handshake_us_sum gauge");
        let _ = writeln!(out, "# HELP aria_tcprt_art_us_sum Sum of application response time in microseconds");
        let _ = writeln!(out, "# TYPE aria_tcprt_art_us_sum gauge");
        let _ = writeln!(out, "# HELP aria_tcprt_rtt_client_us_sum Sum of client RTT in microseconds");
        let _ = writeln!(out, "# TYPE aria_tcprt_rtt_client_us_sum gauge");
        let _ = writeln!(out, "# HELP aria_tcprt_rtt_server_us_sum Sum of server RTT in microseconds");
        let _ = writeln!(out, "# TYPE aria_tcprt_rtt_server_us_sum gauge");
        let _ = writeln!(out, "# HELP aria_tcprt_art_seconds ART latency distribution histogram");
        let _ = writeln!(out, "# TYPE aria_tcprt_art_seconds histogram");
        let _ = writeln!(out, "# HELP aria_tcprt_nqa_score_avg Average NQA network quality score (0-100)");
        let _ = writeln!(out, "# TYPE aria_tcprt_nqa_score_avg gauge");

        for inst in &instances {
            let i = prom_escape(inst);
            match cp.get_tcprt_metrics_summary(inst).await {
                Ok(Some(summary)) => write_tcprt_summary_metrics(&mut out, &i, &summary),
                Ok(None) => {}
                Err(e) => warn!("Failed to collect TCP-RT metrics for {}: {}", inst, e),
            }
            if let Some(chunk) = flush_metrics_chunk(&mut out, false) {
                yield Ok::<_, std::convert::Infallible>(chunk);
            }
        }
        if let Some(chunk) = flush_metrics_chunk(&mut out, true) {
            yield Ok::<_, std::convert::Infallible>(chunk);
        }

        let _ = writeln!(out, "# HELP aria_ssl_handshakes_total Number of SSL handshakes observed");
        let _ = writeln!(out, "# TYPE aria_ssl_handshakes_total gauge");
        let _ = writeln!(out, "# HELP aria_ssl_handshake_seconds SSL handshake latency distribution");
        let _ = writeln!(out, "# TYPE aria_ssl_handshake_seconds histogram");

        let ssl_instance = prom_escape("ssl-global");
        match cp.get_ssl_metrics_summary().await {
            Ok(Some(summary)) => write_ssl_summary_metrics(&mut out, &ssl_instance, &summary),
            Ok(None) => {}
            Err(e) => warn!("Failed to collect SSL handshake metrics: {}", e),
        }
        if let Some(chunk) = flush_metrics_chunk(&mut out, true) {
            yield Ok::<_, std::convert::Infallible>(chunk);
        }

        let _ = writeln!(out, "# HELP aria_ssl_http_requests_total Number of HTTP requests observed via SSL");
        let _ = writeln!(out, "# TYPE aria_ssl_http_requests_total gauge");
        let _ = writeln!(out, "# HELP aria_ssl_http_latency_seconds HTTP request latency distribution via SSL");
        let _ = writeln!(out, "# TYPE aria_ssl_http_latency_seconds histogram");

        match cp.get_ssl_http_metrics_summary().await {
            Ok(Some(summary)) => write_ssl_http_summary_metrics(&mut out, &ssl_instance, &summary),
            Ok(None) => {}
            Err(e) => warn!("Failed to collect SSL HTTP metrics: {}", e),
        }
        if let Some(chunk) = flush_metrics_chunk(&mut out, true) {
            yield Ok::<_, std::convert::Infallible>(chunk);
        }
    };

    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        Body::from_stream(stream),
    )
}
