use crate::{api_client, cli::TraceCommands};

/// Collect trace events from all taps, keyed by instance name.
async fn collect_trace_events(
    client: &api_client::ApiClient,
    taps: &[String],
) -> Result<std::collections::HashMap<String, Vec<aria_api::TraceEventEntry>>, String> {
    let mut all = std::collections::HashMap::new();
    for tap in taps {
        match client.list_trace(tap, 65536).await {
            Ok(resp) => {
                all.insert(tap.clone(), resp.events);
            }
            Err(_) => {
                all.insert(tap.clone(), Vec::new());
            }
        }
    }
    Ok(all)
}

/// Display the live summary table (no detail section).
fn display_trace_live(
    src: &str,
    dst: &str,
    events: &std::collections::HashMap<String, Vec<aria_api::TraceEventEntry>>,
    taps: &[String],
) {
    let src_label = if src.is_empty() { "*" } else { src };
    let dst_label = if dst.is_empty() { "*" } else { dst };
    println!(
        "Trace: {} → {}  (live, Ctrl+C to stop)\n",
        src_label, dst_label
    );
    println!(
        "  {:<20} {:<10} {:<10} {}",
        "Instance", "In", "Out", "Verdict"
    );
    println!(
        "  {:<20} {:<10} {:<10} {}",
        "────────────────", "────────", "────────", "──────────────"
    );
    for tap in taps {
        let evts = events
            .get(tap.as_str())
            .map(|v| v.as_slice())
            .unwrap_or(&[]);
        print_instance_summary(tap, evts);
    }
}

/// Display the final summary with detail section for instances that have drops.
fn display_trace_summary(
    src: &str,
    dst: &str,
    events: &std::collections::HashMap<String, Vec<aria_api::TraceEventEntry>>,
    taps: &[String],
) {
    let src_label = if src.is_empty() { "*" } else { src };
    let dst_label = if dst.is_empty() { "*" } else { dst };
    println!("Trace: {} → {}\n", src_label, dst_label);
    println!(
        "  {:<20} {:<10} {:<10} {}",
        "Instance", "In", "Out", "Verdict"
    );
    println!(
        "  {:<20} {:<10} {:<10} {}",
        "────────────────", "────────", "────────", "──────────────"
    );
    for tap in taps {
        let evts = events
            .get(tap.as_str())
            .map(|v| v.as_slice())
            .unwrap_or(&[]);
        print_instance_summary(tap, evts);
    }

    for tap in taps {
        let evts = events
            .get(tap.as_str())
            .map(|v| v.as_slice())
            .unwrap_or(&[]);
        let drops: Vec<&aria_api::TraceEventEntry> =
            evts.iter().filter(|e| e.result.contains("drop")).collect();
        if drops.is_empty() {
            continue;
        }
        println!("\n  Detail ({}):", tap);
        println!(
            "  {:<6} {:<16} {:<16} {:<6} {:<10} {:<14} {}",
            "Seq", "Source", "Destination", "Proto", "Result", "Drop Reason", "Hook"
        );
        for e in &drops {
            println!(
                "  {:<6} {:<16} {:<16} {:<6} {:<10} {:<14} {}",
                e.seq, e.src_ip, e.dst_ip, e.proto, e.result, e.drop_reason, e.hook
            );
        }
    }
}

fn print_instance_summary(tap: &str, evts: &[aria_api::TraceEventEntry]) {
    if evts.is_empty() {
        println!(
            "  {:<20} {:<10} {:<10} {}",
            tap, "0 pkts", "0 pkts", "no data"
        );
        return;
    }
    let ingress = evts.iter().filter(|e| e.direction == "ingress").count();
    let egress = evts.iter().filter(|e| e.direction == "egress").count();
    let has_drop = evts.iter().any(|e| e.result.contains("drop"));
    let verdict = if has_drop {
        let reason = evts
            .iter()
            .find(|e| e.result.contains("drop"))
            .map(|e| e.drop_reason.as_str())
            .unwrap_or("unknown");
        format!("← drop:{}", reason)
    } else {
        "pass".to_string()
    };
    println!(
        "  {:<20} {:<10} {:<10} {}",
        tap,
        format!("{} pkts", ingress),
        format!("{} pkts", egress),
        verdict
    );
}

/// Represents a hop in the chain trace display, with its taps and aggregated event data.
struct ChainHopTrace {
    name: String,
    taps: Vec<(String, String)>,
}

/// Build chain hop trace structure from a chain definition.
fn build_chain_hops(chain: &aria_api::ServiceChainEntry) -> Vec<ChainHopTrace> {
    chain
        .hops
        .iter()
        .map(|hop| ChainHopTrace {
            name: hop.name.clone(),
            taps: hop
                .taps
                .iter()
                .map(|t| (t.tap.clone(), t.role.clone()))
                .collect(),
        })
        .collect()
}

/// Count ingress/egress packets for a set of events.
fn count_in_out(evts: &[aria_api::TraceEventEntry]) -> (usize, usize) {
    let ingress = evts.iter().filter(|e| e.direction == "ingress").count();
    let egress = evts.iter().filter(|e| e.direction == "egress").count();
    (ingress, egress)
}

/// Build a compact drop summary string grouped by drop reason.
fn format_drop_summary(evts: &[aria_api::TraceEventEntry]) -> String {
    let drops: Vec<&aria_api::TraceEventEntry> =
        evts.iter().filter(|e| e.result.contains("drop")).collect();
    if drops.is_empty() {
        return "-".to_string();
    }

    let mut reason_counts: Vec<(String, usize)> = Vec::new();
    for d in &drops {
        let reason = if d.drop_reason.is_empty() {
            "unknown"
        } else {
            &d.drop_reason
        };
        if let Some(entry) = reason_counts.iter_mut().find(|(r, _)| r == reason) {
            entry.1 += 1;
        } else {
            reason_counts.push((reason.to_string(), 1));
        }
    }
    reason_counts.sort_by(|a, b| b.1.cmp(&a.1));
    let parts: Vec<String> = reason_counts
        .iter()
        .map(|(r, c)| format!("{} {}", c, r))
        .collect();
    format!("\u{2717} {}", parts.join(", "))
}

/// Per-hop aggregated data for drop attribution.
struct HopAgg {
    total_in: usize,
    total_out: usize,
    drop_groups: Vec<(String, String, usize)>,
}

/// Collect per-hop aggregated data from events.
fn collect_hop_aggs(
    hops: &[ChainHopTrace],
    events: &std::collections::HashMap<String, Vec<aria_api::TraceEventEntry>>,
) -> Vec<HopAgg> {
    let mut hop_aggs = Vec::new();
    for hop in hops {
        let mut hop_in = 0usize;
        let mut hop_out = 0usize;
        let mut drop_groups: Vec<(String, String, usize)> = Vec::new();

        for (tap_name, _role) in &hop.taps {
            let evts = events.get(tap_name).map(|v| v.as_slice()).unwrap_or(&[]);
            let (in_cnt, out_cnt) = count_in_out(evts);
            hop_in += in_cnt;
            hop_out += out_cnt;

            for e in evts.iter().filter(|e| e.result.contains("drop")) {
                let dir = e.direction.clone();
                let reason = if e.drop_reason.is_empty() {
                    "unknown".to_string()
                } else {
                    e.drop_reason.clone()
                };
                if let Some(entry) = drop_groups
                    .iter_mut()
                    .find(|(d, r, _)| d == &dir && r == &reason)
                {
                    entry.2 += 1;
                } else {
                    drop_groups.push((dir, reason, 1));
                }
            }
        }
        drop_groups.sort_by(|a, b| b.2.cmp(&a.2));
        hop_aggs.push(HopAgg {
            total_in: hop_in,
            total_out: hop_out,
            drop_groups,
        });
    }
    hop_aggs
}

/// Print the table rows for each hop/tap.
fn print_chain_table_rows(
    hops: &[ChainHopTrace],
    events: &std::collections::HashMap<String, Vec<aria_api::TraceEventEntry>>,
) {
    for hop in hops {
        for (tap_name, role) in &hop.taps {
            let evts = events.get(tap_name).map(|v| v.as_slice()).unwrap_or(&[]);
            let (in_cnt, out_cnt) = count_in_out(evts);
            let drop_str = format_drop_summary(evts);

            let in_str = if in_cnt > 0 || role == "in" || role == "bidi" {
                format!("{} pkts", in_cnt)
            } else {
                "-".to_string()
            };
            let out_str = if out_cnt > 0 || role == "out" || role == "bidi" {
                format!("{} pkts", out_cnt)
            } else {
                "-".to_string()
            };

            println!(
                "  {:<15} {:<12} {:<8} {:<12} {:<12} {}",
                hop.name, tap_name, role, in_str, out_str, drop_str
            );
        }
    }
}

/// Print drop attribution annotations.
fn print_drop_annotations(hops: &[ChainHopTrace], hop_aggs: &[HopAgg]) {
    let mut has_annotation = false;
    for i in 0..hop_aggs.len() {
        if hop_aggs[i].total_in > hop_aggs[i].total_out {
            let lost = hop_aggs[i].total_in - hop_aggs[i].total_out;
            if !has_annotation {
                println!();
                has_annotation = true;
            }
            println!(
                "  \u{2605} dropped {}/{} inside {}",
                lost, hop_aggs[i].total_in, hops[i].name
            );

            if hop_aggs[i].drop_groups.is_empty() {
                println!("    \u{2514}\u{2500} no drop reason captured (device internal block)");
            } else {
                let total_groups = hop_aggs[i].drop_groups.len();
                for (j, (dir, reason, cnt)) in hop_aggs[i].drop_groups.iter().enumerate() {
                    let connector = if j + 1 < total_groups {
                        "\u{251c}\u{2500}"
                    } else {
                        "\u{2514}\u{2500}"
                    };
                    println!("    {} {}: {} ({})", connector, dir, cnt, reason);
                }
            }
        }

        if i + 1 < hop_aggs.len() && hop_aggs[i].total_out > 0 {
            let next_in = hop_aggs[i + 1].total_in;
            if hop_aggs[i].total_out > next_in {
                let lost = hop_aggs[i].total_out - next_in;
                if !has_annotation {
                    println!();
                    has_annotation = true;
                }
                println!(
                    "  \u{2193} {} pkts lost between {} and {}",
                    lost,
                    hops[i].name,
                    hops[i + 1].name
                );
            }
        }
    }
}

/// Display chain-aware trace summary (timed mode).
fn display_trace_chain_summary(
    src: &str,
    dst: &str,
    chain_name: &str,
    events: &std::collections::HashMap<String, Vec<aria_api::TraceEventEntry>>,
    hops: &[ChainHopTrace],
) {
    let src_label = if src.is_empty() { "*" } else { src };
    let dst_label = if dst.is_empty() { "*" } else { dst };
    println!(
        "Chain: {}    Filter: {} \u{2192} {}\n",
        chain_name, src_label, dst_label
    );

    println!(
        "  {:<15} {:<12} {:<8} {:<12} {:<12} {}",
        "Hop", "Tap", "Role", "In", "Out", "Drops"
    );
    println!(
        "  {:<15} {:<12} {:<8} {:<12} {:<12} {}",
        "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
        "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
        "\u{2500}\u{2500}\u{2500}\u{2500}",
        "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
        "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
        "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}"
    );

    print_chain_table_rows(hops, events);
    let hop_aggs = collect_hop_aggs(hops, events);
    print_drop_annotations(hops, &hop_aggs);

    for hop in hops {
        for (tap_name, _role) in &hop.taps {
            let evts = events.get(tap_name).map(|v| v.as_slice()).unwrap_or(&[]);
            let drops: Vec<&aria_api::TraceEventEntry> =
                evts.iter().filter(|e| e.result.contains("drop")).collect();
            if drops.is_empty() {
                continue;
            }
            println!("\n  Detail ({} / {}):", hop.name, tap_name);
            println!(
                "  {:<6} {:<16} {:<16} {:<6} {:<10} {:<14} {}",
                "Seq", "Source", "Destination", "Proto", "Result", "Drop Reason", "Hook"
            );
            for e in &drops {
                println!(
                    "  {:<6} {:<16} {:<16} {:<6} {:<10} {:<14} {}",
                    e.seq, e.src_ip, e.dst_ip, e.proto, e.result, e.drop_reason, e.hook
                );
            }
        }
    }
}

/// Display chain-aware trace live view (continuous mode).
fn display_trace_chain_live(
    src: &str,
    dst: &str,
    chain_name: &str,
    events: &std::collections::HashMap<String, Vec<aria_api::TraceEventEntry>>,
    hops: &[ChainHopTrace],
) {
    let src_label = if src.is_empty() { "*" } else { src };
    let dst_label = if dst.is_empty() { "*" } else { dst };
    println!(
        "Chain: {}    Filter: {} \u{2192} {}  (live, Ctrl+C to stop)\n",
        chain_name, src_label, dst_label
    );

    println!(
        "  {:<15} {:<12} {:<8} {:<12} {:<12} {}",
        "Hop", "Tap", "Role", "In", "Out", "Drops"
    );
    println!(
        "  {:<15} {:<12} {:<8} {:<12} {:<12} {}",
        "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
        "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
        "\u{2500}\u{2500}\u{2500}\u{2500}",
        "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
        "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}",
        "\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}\u{2500}"
    );

    print_chain_table_rows(hops, events);
    let hop_aggs = collect_hop_aggs(hops, events);
    print_drop_annotations(hops, &hop_aggs);
}

async fn run_trace_with_chain(
    client: &api_client::ApiClient,
    chain_name: &str,
    src: &str,
    dst: &str,
    sport: u16,
    dport: u16,
    proto: &str,
    wait: Option<u64>,
) -> Result<(), String> {
    let chain = client.get_chain(chain_name).await?;
    let hops = build_chain_hops(&chain);

    let taps: Vec<String> = hops
        .iter()
        .flat_map(|h| h.taps.iter().map(|(t, _)| t.clone()))
        .collect();

    if taps.is_empty() {
        return Err("Chain has no taps configured".to_string());
    }

    let req = aria_api::TraceStartRequest {
        src_ip: src.to_string(),
        dst_ip: dst.to_string(),
        src_port: sport,
        dst_port: dport,
        proto: proto.to_string(),
    };

    for tap in &taps {
        let _ = client.flush_trace(tap).await;
        client
            .start_trace(tap, &req)
            .await
            .map_err(|e| format!("Failed to start trace on {}: {}", tap, e))?;
    }

    let tap_list = taps.join(", ");
    println!("Tracing chain '{}' on [{}] ...", chain_name, tap_list);

    let result = match wait {
        Some(secs) => {
            tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
            let events = collect_trace_events(client, &taps).await?;
            display_trace_chain_summary(src, dst, chain_name, &events, &hops);
            Ok(())
        }
        None => {
            let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
            let r = running.clone();
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                r.store(false, std::sync::atomic::Ordering::SeqCst);
            });

            while running.load(std::sync::atomic::Ordering::SeqCst) {
                let events = collect_trace_events(client, &taps).await?;
                print!("\x1B[2J\x1B[H");
                display_trace_chain_live(src, dst, chain_name, &events, &hops);
                for _ in 0..20 {
                    if !running.load(std::sync::atomic::Ordering::SeqCst) {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }

            println!();
            let events = collect_trace_events(client, &taps).await?;
            display_trace_chain_summary(src, dst, chain_name, &events, &hops);
            Ok(())
        }
    };

    for tap in &taps {
        let _ = client.stop_trace(tap).await;
    }

    result
}

async fn run_trace(
    client: &api_client::ApiClient,
    taps: &[String],
    src: &str,
    dst: &str,
    sport: u16,
    dport: u16,
    proto: &str,
    wait: Option<u64>,
) -> Result<(), String> {
    let req = aria_api::TraceStartRequest {
        src_ip: src.to_string(),
        dst_ip: dst.to_string(),
        src_port: sport,
        dst_port: dport,
        proto: proto.to_string(),
    };

    for tap in taps {
        let _ = client.flush_trace(tap).await;
        client
            .start_trace(tap, &req)
            .await
            .map_err(|e| format!("Failed to start trace on {}: {}", tap, e))?;
    }

    let tap_list = taps.join(", ");
    println!("Tracing on [{}] ...", tap_list);

    let result = match wait {
        Some(secs) => {
            tokio::time::sleep(std::time::Duration::from_secs(secs)).await;
            let events = collect_trace_events(client, taps).await?;
            display_trace_summary(src, dst, &events, taps);
            Ok(())
        }
        None => {
            let running = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
            let r = running.clone();
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                r.store(false, std::sync::atomic::Ordering::SeqCst);
            });

            while running.load(std::sync::atomic::Ordering::SeqCst) {
                let events = collect_trace_events(client, taps).await?;
                print!("\x1B[2J\x1B[H");
                display_trace_live(src, dst, &events, taps);
                for _ in 0..20 {
                    if !running.load(std::sync::atomic::Ordering::SeqCst) {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }

            println!();
            let events = collect_trace_events(client, taps).await?;
            display_trace_summary(src, dst, &events, taps);
            Ok(())
        }
    };

    for tap in taps {
        let _ = client.stop_trace(tap).await;
    }

    result
}

pub(crate) async fn handle_trace_start(
    client: &api_client::ApiClient,
    tap: Option<String>,
    src: String,
    dst: String,
    sport: u16,
    dport: u16,
    proto: String,
    wait: Option<u64>,
    chain: Option<String>,
) -> Result<(), String> {
    if let Some(chain_name) = chain {
        run_trace_with_chain(client, &chain_name, &src, &dst, sport, dport, &proto, wait).await
    } else {
        let taps = if let Some(t) = tap {
            vec![t]
        } else {
            match client.list_instances().await {
                Ok(resp) => resp
                    .instances
                    .iter()
                    .filter(|i| i.active)
                    .map(|i| i.name.clone())
                    .collect(),
                Err(e) => {
                    eprintln!("Error: Failed to list instances: {}", e);
                    std::process::exit(1);
                }
            }
        };
        if taps.is_empty() {
            Err("No active instances found".to_string())
        } else {
            run_trace(client, &taps, &src, &dst, sport, dport, &proto, wait).await
        }
    }
}

pub(crate) async fn handle_action(
    client: &api_client::ApiClient,
    action: TraceCommands,
) -> Result<(), String> {
    match action {
        TraceCommands::Start {
            tap,
            src,
            dst,
            sport,
            dport,
            proto,
            wait,
            chain,
        } => handle_trace_start(client, tap, src, dst, sport, dport, proto, wait, chain).await,
    }
}
