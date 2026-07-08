use crate::{api_client, cli::TcprtCommands};

/// 5-tuple flow key for cross-instance matching.
#[derive(Hash, Eq, PartialEq, Clone)]
struct FlowKey {
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
}

struct InstanceFlows {
    name: String,
    flows: std::collections::HashMap<FlowKey, aria_api::TcpRtEntry>,
}

/// Fetch TCP-RT data from all active instances, return instance/flow pairs.
async fn fetch_all_instance_flows(
    client: &api_client::ApiClient,
) -> Result<Vec<InstanceFlows>, String> {
    let instances_resp = client.list_instances().await?;
    let active: Vec<String> = instances_resp
        .instances
        .iter()
        .filter(|i| i.active)
        .map(|i| i.name.clone())
        .collect();

    let mut all = Vec::new();
    for inst_name in &active {
        let resp = match client.list_tcprt(inst_name, 65536).await {
            Ok(r) => r,
            Err(_) => continue,
        };
        let mut flows = std::collections::HashMap::new();
        for f in resp.flows {
            let key = FlowKey {
                src_ip: f.src_ip.clone(),
                dst_ip: f.dst_ip.clone(),
                src_port: f.src_port,
                dst_port: f.dst_port,
            };
            flows.insert(key, f);
        }
        all.push(InstanceFlows {
            name: inst_name.clone(),
            flows,
        });
    }
    Ok(all)
}

/// Sort key extractor for a given dimension name.
fn sort_value(entry: &aria_api::TcpRtEntry, dim: &str) -> f64 {
    match dim {
        "crtt" => entry.rtt_client_us,
        "srtt" => entry.rtt_server_us,
        "hs" => entry.handshake_us,
        "retrans" => (entry.retrans_req + entry.retrans_resp) as f64,
        "nqa" => -(entry.nqa_score as f64),
        _ => entry.art_us,
    }
}

async fn handle_top(
    client: &api_client::ApiClient,
    by: &str,
    top: usize,
    watch: bool,
    interval: u64,
) -> Result<(), String> {
    if watch {
        loop {
            print!("\x1B[2J\x1B[H");
            if let Err(e) = run_tcprt_top(client, by, top).await {
                eprintln!("Error: {}", e);
            }
            tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
        }
    } else {
        run_tcprt_top(client, by, top).await
    }
}

async fn handle_flow(
    client: &api_client::ApiClient,
    dst: &str,
    dport: u16,
    chain: Option<&str>,
) -> Result<(), String> {
    run_tcprt_flow(client, dst, dport, chain).await
}

async fn handle_histogram(client: &api_client::ApiClient, instance: &str) -> Result<(), String> {
    match client.tcprt_histogram(instance).await {
        Ok(resp) => {
            if resp.total == 0 {
                println!("No ART data collected yet");
            } else {
                println!("=== ART Latency Distribution ===\n");
                let max_count = resp.buckets.iter().map(|b| b.count).max().unwrap_or(1);
                let bar_width = 40;
                for b in &resp.buckets {
                    let label = if b.le_us >= 1_000_000.0 {
                        format!("{:.0}s", b.le_us / 1_000_000.0)
                    } else if b.le_us >= 1_000.0 {
                        format!("{:.0}ms", b.le_us / 1_000.0)
                    } else {
                        format!("{:.0}us", b.le_us)
                    };
                    let filled = if max_count > 0 {
                        (b.count as usize * bar_width) / max_count as usize
                    } else {
                        0
                    };
                    let bar: String = "\u{2588}".repeat(filled);
                    println!("  <= {:<8} {:>8} |{}", label, b.count, bar);
                }
                println!();
                println!("  Total: {}  Sum: {:.1} us", resp.total, resp.sum_us);
                println!(
                    "  p50: {:.1} us  p95: {:.1} us  p99: {:.1} us",
                    resp.p50_us, resp.p95_us, resp.p99_us
                );
            }
            Ok(())
        }
        Err(e) => Err(e),
    }
}

async fn handle_states(client: &api_client::ApiClient, instance: &str) -> Result<(), String> {
    match client.tcprt_states(instance).await {
        Ok(resp) => {
            if resp.total_flows == 0 {
                println!("No TCP-RT flows found");
            } else {
                println!(
                    "=== TCP State Distribution ({} flows) ===\n",
                    resp.total_flows
                );
                println!("  {:<15} {:>8} {:>8}", "State", "Count", "Percent");
                println!("  {:<15} {:>8} {:>8}", "───────────", "──────", "───────");
                for s in &resp.states {
                    let pct = s.count as f64 / resp.total_flows as f64 * 100.0;
                    println!("  {:<15} {:>8} {:>7.1}%", s.state, s.count, pct);
                }
                if !resp.anomalies.is_empty() {
                    println!();
                    println!("  Anomalies:");
                    for a in &resp.anomalies {
                        println!("    ! {}", a);
                    }
                }
            }
            Ok(())
        }
        Err(e) => Err(e),
    }
}

async fn handle_flush(client: &api_client::ApiClient, instance: &str) -> Result<(), String> {
    match client.flush_tcprt(instance).await {
        Ok(resp) => {
            println!("Flushed {} TCP-RT entries", resp.flushed);
            Ok(())
        }
        Err(e) => Err(e),
    }
}

pub(crate) async fn handle_action(
    client: &api_client::ApiClient,
    instance: &str,
    action: TcprtCommands,
) -> Result<(), String> {
    match action {
        TcprtCommands::Top {
            by,
            top,
            watch,
            interval,
        } => handle_top(client, &by, top, watch, interval).await,
        TcprtCommands::Flow { dst, dport, chain } => {
            handle_flow(client, &dst, dport, chain.as_deref()).await
        }
        TcprtCommands::Histogram => handle_histogram(client, instance).await,
        TcprtCommands::States => handle_states(client, instance).await,
        TcprtCommands::Flush => handle_flush(client, instance).await,
    }
}

async fn run_tcprt_top(client: &api_client::ApiClient, by: &str, top: usize) -> Result<(), String> {
    let all_instances = fetch_all_instance_flows(client).await?;
    if all_instances.is_empty() {
        println!("No active instances found");
        return Ok(());
    }

    let mut unique_keys: Vec<FlowKey> = Vec::new();
    for inst in &all_instances {
        for key in inst.flows.keys() {
            if !unique_keys.contains(key) {
                unique_keys.push(key.clone());
            }
        }
    }

    if unique_keys.is_empty() {
        println!("No TCP-RT data collected yet");
        return Ok(());
    }

    unique_keys.sort_by(|a, b| {
        let val_a: f64 = all_instances
            .iter()
            .filter_map(|inst| inst.flows.get(a).map(|f| sort_value(f, by)))
            .fold(0.0f64, f64::max);
        let val_b: f64 = all_instances
            .iter()
            .filter_map(|inst| inst.flows.get(b).map(|f| sort_value(f, by)))
            .fold(0.0f64, f64::max);
        val_b
            .partial_cmp(&val_a)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    unique_keys.truncate(top);

    struct Row {
        src_ip: String,
        dst_ip: String,
        src_port: u16,
        dst_port: u16,
        instance: String,
        art: f64,
        crtt: f64,
        srtt: f64,
        hs: f64,
        req_rt: u32,
        rsp_rt: u32,
        state: String,
        nqa: u8,
    }

    let mut rows: Vec<Row> = Vec::new();
    for key in &unique_keys {
        let mut points: Vec<(&str, &aria_api::TcpRtEntry)> = all_instances
            .iter()
            .filter_map(|i| i.flows.get(key).map(|f| (i.name.as_str(), f)))
            .collect();
        points.sort_by(|a, b| {
            b.1.rtt_server_us
                .partial_cmp(&a.1.rtt_server_us)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        for (inst_name, entry) in points {
            rows.push(Row {
                src_ip: key.src_ip.clone(),
                dst_ip: key.dst_ip.clone(),
                src_port: key.src_port,
                dst_port: key.dst_port,
                instance: inst_name.to_string(),
                art: entry.art_us,
                crtt: entry.rtt_client_us,
                srtt: entry.rtt_server_us,
                hs: entry.handshake_us,
                req_rt: entry.retrans_req,
                rsp_rt: entry.retrans_resp,
                state: entry.state.clone(),
                nqa: entry.nqa_score,
            });
        }
    }

    println!(
        "{:<20} {:<20} {:<7} {:<7} {:<12} {:<10} {:<10} {:<10} {:<10} {:<7} {:<7} {:<5} {}",
        "Source",
        "Destination",
        "SPort",
        "DPort",
        "Instance",
        "ART (us)",
        "cRTT",
        "sRTT",
        "HS",
        "ReqRT",
        "RspRT",
        "NQA",
        "State"
    );
    for r in &rows {
        let art_str = if r.art == 0.0 {
            "-".to_string()
        } else {
            format!("{:.1}", r.art)
        };
        println!(
            "{:<20} {:<20} {:<7} {:<7} {:<12} {:<10} {:<10.1} {:<10.1} {:<10.1} {:<7} {:<7} {:<5} {}",
            r.src_ip,
            r.dst_ip,
            r.src_port,
            r.dst_port,
            r.instance,
            art_str,
            r.crtt,
            r.srtt,
            r.hs,
            r.req_rt,
            r.rsp_rt,
            r.nqa,
            r.state
        );
    }

    Ok(())
}

async fn run_tcprt_flow(
    client: &api_client::ApiClient,
    dst: &str,
    dport: u16,
    chain: Option<&str>,
) -> Result<(), String> {
    let resp = client
        .filter_tcprt(&aria_api::TcpRtFilterRequest {
            dst_ip: dst.to_string(),
            dst_port: dport,
        })
        .await?;

    if resp.instances.is_empty() {
        println!("No flows found for {}:{}", dst, dport);
        return Ok(());
    }

    let total_flows: u32 = resp.instances.iter().map(|i| i.flow_count).sum();

    if let Some(chain_name) = chain {
        run_tcprt_flow_with_chain(client, dst, dport, chain_name, &resp, total_flows).await
    } else {
        run_tcprt_flow_coarse(dst, dport, &resp, total_flows)
    }
}

/// Latency breakdown using dual-observation (bond1 XDP+TC).
/// For multi-instance without dual-observation, suggest --chain.
fn run_tcprt_flow_coarse(
    dst: &str,
    dport: u16,
    resp: &aria_api::TcpRtFilterResponse,
    total_flows: u32,
) -> Result<(), String> {
    println!("Service: {}:{}  ({} flows)\n", dst, dport, total_flows);

    let dual_inst = resp
        .instances
        .iter()
        .find(|i| i.instance == "system" && i.avg_forward_platform_us > 0.0)
        .or_else(|| {
            resp.instances
                .iter()
                .find(|i| i.avg_forward_platform_us > 0.0)
        });

    if let Some(inst) = dual_inst {
        let client_net = inst.avg_rtt_client_us;
        let fwd_platform = inst.avg_forward_platform_us;
        let server_net = inst.avg_server_network_us;
        let rev_platform = inst.avg_reverse_platform_us;
        let server_proc = (inst.avg_art_us - server_net).max(0.0);

        struct Segment {
            label: &'static str,
            value: f64,
        }
        let segments = [
            Segment {
                label: "Client Network",
                value: client_net,
            },
            Segment {
                label: "Platform (forward)",
                value: fwd_platform,
            },
            Segment {
                label: "Server Network",
                value: server_net,
            },
            Segment {
                label: "Platform (reverse)",
                value: rev_platform,
            },
            Segment {
                label: "Server Processing",
                value: server_proc,
            },
        ];
        let max_val = segments.iter().map(|s| s.value).fold(0.0f64, f64::max);

        println!("  Latency Breakdown (avg)");
        println!("  ─────────────────────────  ────────────");
        for seg in &segments {
            let marker = if seg.value >= max_val && max_val > 0.0 {
                "  <- bottleneck"
            } else {
                ""
            };
            println!("  {:<25} {:>8.1} us{}", seg.label, seg.value, marker);
        }

        println!();
        println!("  Retransmissions (total)");
        println!("  ─────────────────────────  ─────────  ─────────");
        println!("  {:<25} {:<10} {}", "", "Req", "Resp");
        println!(
            "  {:<25} {:<10} {}",
            "Total", inst.total_retrans_req, inst.total_retrans_resp
        );

        println!();
        println!("  NQA Score (avg): {:.0}", inst.avg_nqa_score);
        println!();
        return Ok(());
    }

    println!(
        "  {:<15} {:>10} {:>10} {:>10} {:>10} {:>8} {:>8} {:>5}",
        "Instance", "cRTT", "sRTT", "ART", "HS", "ReqRT", "RspRT", "NQA"
    );
    println!(
        "  {:<15} {:>10} {:>10} {:>10} {:>10} {:>8} {:>8} {:>5}",
        "───────────", "────────", "────────", "────────", "────────", "──────", "──────", "─────"
    );
    for inst in &resp.instances {
        println!(
            "  {:<15} {:>8.1}us {:>8.1}us {:>8.1}us {:>8.1}us {:>8} {:>8} {:>5.0}",
            inst.instance,
            inst.avg_rtt_client_us,
            inst.avg_rtt_server_us,
            inst.avg_art_us,
            inst.avg_handshake_us,
            inst.total_retrans_req,
            inst.total_retrans_resp,
            inst.avg_nqa_score
        );
    }
    if resp.instances.len() > 1 {
        println!("\n  Tip: use --chain <name> for per-hop latency breakdown");
    }
    println!();

    Ok(())
}

/// Per-hop fine-grained breakdown using service chain topology.
async fn run_tcprt_flow_with_chain(
    client: &api_client::ApiClient,
    dst: &str,
    dport: u16,
    chain_name: &str,
    resp: &aria_api::TcpRtFilterResponse,
    total_flows: u32,
) -> Result<(), String> {
    let chain = client.get_chain(chain_name).await?;

    println!(
        "Service: {}:{}  (chain: {}, {} flows)\n",
        dst, dport, chain_name, total_flows
    );

    let mut tap_to_hop: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (idx, hop) in chain.hops.iter().enumerate() {
        for tap in &hop.taps {
            tap_to_hop.insert(tap.tap.clone(), idx);
        }
    }

    let mut hop_data: Vec<Option<aria_api::TcpRtAggregatedEntry>> = vec![None; chain.hops.len()];
    let mut hop_counts: Vec<u32> = vec![0; chain.hops.len()];

    for inst in &resp.instances {
        if let Some(&hop_idx) = tap_to_hop.get(&inst.instance) {
            if let Some(ref mut existing) = hop_data[hop_idx] {
                existing.avg_rtt_client_us += inst.avg_rtt_client_us;
                existing.avg_rtt_server_us += inst.avg_rtt_server_us;
                existing.avg_art_us += inst.avg_art_us;
                existing.avg_handshake_us += inst.avg_handshake_us;
                existing.total_retrans_req += inst.total_retrans_req;
                existing.total_retrans_resp += inst.total_retrans_resp;
                existing.flow_count += inst.flow_count;
                existing.avg_forward_platform_us += inst.avg_forward_platform_us;
                existing.avg_server_network_us += inst.avg_server_network_us;
                existing.avg_reverse_platform_us += inst.avg_reverse_platform_us;
                existing.avg_nqa_score += inst.avg_nqa_score;
                hop_counts[hop_idx] += 1;
            } else {
                hop_data[hop_idx] = Some(aria_api::TcpRtAggregatedEntry {
                    instance: inst.instance.clone(),
                    flow_count: inst.flow_count,
                    avg_rtt_client_us: inst.avg_rtt_client_us,
                    avg_rtt_server_us: inst.avg_rtt_server_us,
                    avg_art_us: inst.avg_art_us,
                    avg_handshake_us: inst.avg_handshake_us,
                    total_retrans_req: inst.total_retrans_req,
                    total_retrans_resp: inst.total_retrans_resp,
                    avg_forward_platform_us: inst.avg_forward_platform_us,
                    avg_server_network_us: inst.avg_server_network_us,
                    avg_reverse_platform_us: inst.avg_reverse_platform_us,
                    avg_nqa_score: inst.avg_nqa_score,
                });
                hop_counts[hop_idx] = 1;
            }
        }
    }

    for (idx, data) in hop_data.iter_mut().enumerate() {
        if let Some(ref mut d) = data {
            let c = hop_counts[idx] as f64;
            if c > 1.0 {
                d.avg_rtt_client_us /= c;
                d.avg_rtt_server_us /= c;
                d.avg_art_us /= c;
                d.avg_handshake_us /= c;
                d.avg_forward_platform_us /= c;
                d.avg_server_network_us /= c;
                d.avg_reverse_platform_us /= c;
                d.avg_nqa_score /= c;
            }
        }
    }

    struct HopPoint {
        name: String,
        data: aria_api::TcpRtAggregatedEntry,
    }
    let points: Vec<HopPoint> = chain
        .hops
        .iter()
        .enumerate()
        .filter_map(|(idx, hop)| {
            hop_data[idx].take().map(|d| HopPoint {
                name: hop.name.clone(),
                data: d,
            })
        })
        .collect();

    if points.is_empty() {
        println!("  No matching data found for chain hops");
        return Ok(());
    }

    if points.len() < 2 {
        let p = &points[0];
        println!("  Only one hop has data: {}", p.name);
        println!(
            "  Avg cRTT: {:.1} us, Avg sRTT: {:.1} us, Avg ART: {:.1} us",
            p.data.avg_rtt_client_us, p.data.avg_rtt_server_us, p.data.avg_art_us
        );
        return Ok(());
    }

    struct Segment {
        label: String,
        value: f64,
    }
    let mut segments: Vec<Segment> = Vec::new();

    segments.push(Segment {
        label: "Client Network".to_string(),
        value: points[0].data.avg_rtt_client_us,
    });

    for i in 0..points.len() - 1 {
        let diff =
            (points[i].data.avg_rtt_server_us - points[i + 1].data.avg_rtt_server_us).max(0.0);
        segments.push(Segment {
            label: format!("{} → {}", points[i].name, points[i + 1].name),
            value: diff,
        });
    }

    let last = &points[points.len() - 1];
    segments.push(Segment {
        label: format!("{} → server", last.name),
        value: (last.data.avg_art_us - last.data.avg_rtt_server_us).max(0.0),
    });

    let max_val = segments.iter().map(|s| s.value).fold(0.0f64, f64::max);

    println!("  Latency Breakdown (avg)");
    println!("  ─────────────────────  ────────────");
    for seg in &segments {
        let marker = if seg.value >= max_val && max_val > 0.0 {
            "  ← bottleneck"
        } else {
            ""
        };
        println!("  {:<23} {:.1} us{}", seg.label, seg.value, marker);
    }

    println!();
    println!("  Packet Loss (total)");
    println!("  ─────────────────────  ─────────  ─────────");
    println!("  {:<23} {:<10} {}", "", "Req Loss", "Rsp Loss");
    for i in 0..points.len() - 1 {
        let req_loss = (points[i].data.total_retrans_req as i64
            - points[i + 1].data.total_retrans_req as i64)
            .max(0);
        let rsp_loss = (points[i].data.total_retrans_resp as i64
            - points[i + 1].data.total_retrans_resp as i64)
            .max(0);
        let label = format!("{} → {}", points[i].name, points[i + 1].name);
        println!("  {:<23} {:<10} {}", label, req_loss, rsp_loss);
    }
    let last = &points[points.len() - 1];
    let label = format!("{} → server", last.name);
    println!(
        "  {:<23} {:<10} {}",
        label, last.data.total_retrans_req, last.data.total_retrans_resp
    );
    println!();

    Ok(())
}
