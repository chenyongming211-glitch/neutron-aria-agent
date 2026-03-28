use crate::api_client;

pub(crate) async fn handle(
    client: &api_client::ApiClient,
    instance: &str,
    dst: &str,
    dport: u16,
    _chain: Option<&str>,
) -> Result<(), String> {
    println!("=== Aria Diagnostic Report ===");
    println!("Target: {}:{}\n", dst, dport);

    println!("--- L4: TCP ---");
    let tcprt_resp = client
        .filter_tcprt(&aria_api::TcpRtFilterRequest {
            dst_ip: dst.to_string(),
            dst_port: dport,
        })
        .await;

    match tcprt_resp {
        Ok(resp) if !resp.instances.is_empty() => {
            let total_flows: u32 = resp.instances.iter().map(|i| i.flow_count).sum();
            let fc = resp.instances.len() as f64;
            let avg_hs: f64 = resp
                .instances
                .iter()
                .map(|i| i.avg_handshake_us)
                .sum::<f64>()
                / fc;
            let avg_crtt: f64 = resp
                .instances
                .iter()
                .map(|i| i.avg_rtt_client_us)
                .sum::<f64>()
                / fc;
            let avg_srtt: f64 = resp
                .instances
                .iter()
                .map(|i| i.avg_rtt_server_us)
                .sum::<f64>()
                / fc;
            let total_retrans_req: u32 = resp.instances.iter().map(|i| i.total_retrans_req).sum();
            let total_retrans_resp: u32 =
                resp.instances.iter().map(|i| i.total_retrans_resp).sum();
            let avg_nqa: f64 = resp.instances.iter().map(|i| i.avg_nqa_score).sum::<f64>() / fc;

            println!(
                "  Flows: {}    Avg HS: {:.1}us    Avg cRTT: {:.1}us    Avg sRTT: {:.1}us",
                total_flows, avg_hs, avg_crtt, avg_srtt
            );
            println!(
                "  Retrans: {} req / {} resp    NQA: {:.0}",
                total_retrans_req, total_retrans_resp, avg_nqa
            );
        }
        _ => {
            println!("  (no TCP-RT data)");
        }
    }

    println!("\n--- L5: SSL/TLS ---");
    match client.list_ssl(instance, 10000).await {
        Ok(resp) => {
            if resp.connections.is_empty() {
                println!("  (no SSL data)");
            } else {
                let total = resp.connections.len();
                let avg_hs: f64 =
                    resp.connections.iter().map(|c| c.handshake_us).sum::<f64>() / total as f64;

                let mut sni_counts: Vec<(String, usize)> = Vec::new();
                for c in &resp.connections {
                    if c.sni.is_empty() {
                        continue;
                    }
                    if let Some(entry) = sni_counts.iter_mut().find(|(s, _)| s == &c.sni) {
                        entry.1 += 1;
                    } else {
                        sni_counts.push((c.sni.clone(), 1));
                    }
                }
                sni_counts.sort_by(|a, b| b.1.cmp(&a.1));

                println!("  Handshakes: {}    Avg: {:.1}ms", total, avg_hs / 1000.0);
                for (sni, count) in sni_counts.iter().take(5) {
                    println!("  SNI: {} ({})", sni, count);
                }
            }
        }
        Err(_) => {
            println!("  (SSL data unavailable)");
        }
    }

    println!("\n--- L7: HTTP ---");
    match client.list_ssl_http(instance, 10000).await {
        Ok(resp) => {
            if resp.events.is_empty() {
                println!("  (no HTTP data)");
            } else {
                let total = resp.events.len();
                let avg_latency: f64 =
                    resp.events.iter().map(|e| e.latency_us).sum::<f64>() / total as f64;

                let mut status_counts: Vec<(u16, usize)> = Vec::new();
                for e in &resp.events {
                    if let Some(entry) = status_counts.iter_mut().find(|(s, _)| *s == e.status_code)
                    {
                        entry.1 += 1;
                    } else {
                        status_counts.push((e.status_code, 1));
                    }
                }
                status_counts.sort_by(|a, b| b.1.cmp(&a.1));

                println!(
                    "  Requests: {}    Avg Latency: {:.1}ms",
                    total,
                    avg_latency / 1000.0
                );
                let status_str: Vec<String> = status_counts
                    .iter()
                    .take(5)
                    .map(|(s, c)| format!("{}({})", s, c))
                    .collect();
                println!("  Status: {}", status_str.join(" "));

                let mut sorted = resp.events.clone();
                sorted.sort_by(|a, b| {
                    b.latency_us
                        .partial_cmp(&a.latency_us)
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
                println!("  Slowest:");
                for e in sorted.iter().take(5) {
                    println!(
                        "    {:<6} {:<30} {:.1}ms",
                        e.method,
                        e.path,
                        e.latency_us / 1000.0
                    );
                }
            }
        }
        Err(_) => {
            println!("  (HTTP data unavailable)");
        }
    }

    println!("\n--- Drops ---");
    match client
        .list_kernel_drops(&aria_api::KernelDropQuery {
            instance: Some(instance.to_string()),
            iface: None,
            ifindex: None,
            reason: None,
            top: None,
            include_unattributed: false,
        })
        .await
    {
        Ok(resp) => {
            if resp.drops.is_empty() {
                println!("  (none)");
            } else {
                for d in &resp.drops {
                    println!(
                        "  {}: {} pkts ({} bytes) - iface={} proto={}",
                        d.reason,
                        d.packets,
                        d.bytes,
                        d.iface.as_deref().unwrap_or("-"),
                        d.proto
                    );
                }
            }
        }
        Err(_) => {
            println!("  (drop data unavailable)");
        }
    }

    let mut verdict = "HEALTHY";
    let mut reasons: Vec<String> = Vec::new();

    if let Ok(resp) = client
        .filter_tcprt(&aria_api::TcpRtFilterRequest {
            dst_ip: dst.to_string(),
            dst_port: dport,
        })
        .await
    {
        for inst in &resp.instances {
            if inst.avg_nqa_score < 50.0 {
                verdict = "UNHEALTHY";
                reasons.push(format!("NQA={:.0} (<50)", inst.avg_nqa_score));
            } else if inst.avg_nqa_score < 80.0 && verdict != "UNHEALTHY" {
                verdict = "DEGRADED";
                reasons.push(format!("NQA={:.0} (<80)", inst.avg_nqa_score));
            }
        }
    }

    if let Ok(resp) = client.list_ssl_http(instance, 10000).await {
        if !resp.events.is_empty() {
            let total = resp.events.len() as f64;
            let count_5xx = resp
                .events
                .iter()
                .filter(|e| e.status_code >= 500 && e.status_code < 600)
                .count() as f64;
            let pct = count_5xx / total * 100.0;
            if pct > 10.0 {
                verdict = "UNHEALTHY";
                reasons.push(format!("5xx={:.1}% (>10%)", pct));
            }
        }
    }

    if let Ok(resp) = client
        .list_kernel_drops(&aria_api::KernelDropQuery {
            instance: Some(instance.to_string()),
            iface: None,
            ifindex: None,
            reason: None,
            top: None,
            include_unattributed: false,
        })
        .await
    {
        let total_drops: u64 = resp.drops.iter().map(|d| d.packets).sum();
        if total_drops > 0 {
            verdict = "UNHEALTHY";
            reasons.push(format!("drops={}", total_drops));
        }
    }

    println!("\n--- Verdict: {} ---", verdict);
    if !reasons.is_empty() {
        println!("  Reasons: {}", reasons.join(", "));
    }

    Ok(())
}
